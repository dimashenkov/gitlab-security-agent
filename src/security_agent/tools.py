"""The agent's tool surface.

Everything the agent can do is here, and all of it is read-only: list, read,
search, inspect history, and record findings. There is deliberately no shell
tool and no write tool — the agent reviews code that an untrusted contributor
may have authored, and a general-purpose exec tool in a job that holds a GitLab
API token is an escalation path, not a convenience.

Tool results are the agent's only view of the repository, so each one is written
to be honest about its own limits: when output is trimmed or a search is capped,
the result says so, because an agent that thinks it saw everything will stop
looking.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from . import generated
from .evidence import (
    EvidenceProblem,
    attribution,
    evidence_span,
    excerpt,
    locate_evidence,
)
from .models import Candidate, Finding, RejectedClaim, StageMetrics, ToolCallRecord
from .workspace import Workspace, WorkspaceError

log = logging.getLogger(__name__)

REPORT_FINDING = "report_finding"

# The review says it is over. Not the process exiting, not the model falling
# silent — a deliberate call.
#
# With the Messages API "the model stopped asking for tools" is a real signal:
# `end_turn` is the model choosing to stop. A provider that owns its own loop
# gives no such signal — its process exits zero whether the review finished or
# the harness gave up, and this project's one unbreakable rule is that those two
# must never render the same. So completion becomes something the reviewer
# states, in the same channel as everything else it states, and both runners
# read the same statement.
#
# It also fixes something on the API path. The final summary used to be
# whatever text happened to be in the last response, which is presentation:
# a sentence written to be read, arriving through a channel with no schema and
# no minimum. Through here it is an argument, and it is journalled as submitted.
FINISH_REVIEW = "finish_review"

# Below this a summary is a sign-off, not a summary. Chosen to be short enough
# that one honest sentence passes.
MIN_SUMMARY_CHARS = 40

# What `get_diff` shows the model. Named because `Workspace.MAX_DIFF_BYTES` is
# derived from it: the read ceiling exists to stop a hostile change exhausting
# memory, and its right size is "enough to produce this, and no more".
MAX_DIFF_CHARS = 120_000

# The verifier's counterpart to `finish_review`: submitting the one vote it is
# allowed to cast is also how it says it is done.
#
# On the Messages API path the verdict already arrives reliably — a
# schema-constrained final message is a guarantee, not a hope. A provider that
# owns its loop offers no such guarantee, and "the verifier stopped" would
# otherwise be indistinguishable from "the verifier voted". Both channels are
# accepted and the vote records which one it came through, because a verdict
# that arrived as loose prose and one that arrived as a validated argument are
# not equally trustworthy and the artifact should not pretend otherwise.
SUBMIT_VERDICT = "submit_verdict"

# How many times one claim may fail the citation check before it is dropped for
# good. One retry is a typo in a path or a quote reconstructed from memory; a
# second failure on the same claim means the code is not there.
MAX_CITATION_ATTEMPTS = 2


@dataclass
class Session:
    """Mutable state accumulated across the agent's turns."""

    candidates: List[Candidate] = field(default_factory=list)
    rejected: List[RejectedClaim] = field(default_factory=list)
    tool_calls: List[ToolCallRecord] = field(default_factory=list)
    files_examined: List[str] = field(default_factory=list)
    # (path, channel) for every file whose bytes reached the model.
    exposures: List[tuple] = field(default_factory=list)
    duplicates_dropped: int = 0
    turn: int = 0
    metrics: StageMetrics = field(default_factory=StageMetrics)
    # Set only by `finish_review`. The one place a runner-independent answer to
    # "did this review end, or was it ended" is written down.
    finished: bool = False
    final_summary: str = ""
    unresolved: List[str] = field(default_factory=list)
    # Set only by `submit_verdict`, and only in a verifier's session. One
    # session, one candidate, one vote — a second submission is refused rather
    # than allowed to overwrite the first.
    verdict: Optional[Dict[str, Any]] = None
    # The whole-change diff was cut off at its ceiling while this session ran.
    # Recorded here because on the CLI path `get_diff` runs in a child process
    # against a different `Workspace`, so the parent's own flag is always False
    # — the fact has to travel with the session or the gate never learns that
    # the reviewer saw the first part of a change and no more.
    diff_truncated: bool = False
    _attempts: Dict[str, int] = field(default_factory=dict)

    def note_file(self, path: str) -> None:
        if path and path not in self.files_examined:
            self.files_examined.append(path)

    def note_exposure(self, path: str, channel: str) -> None:
        """Record that this file's bytes reached the model, and how.

        Distinct from `files_examined`, which is what the agent chose to
        *open*. A whole-change `get_diff` puts every changed file's contents in
        the conversation without any of them being opened, and `search_code`
        returns matching lines from files nobody asked for by name. Reading
        "was the payload seen" off `files_examined` would answer no while the
        text sat in the context window — which is the difference between a
        verifier that resisted and one that was never tried.
        """
        if not path:
            return
        key = (path, channel)
        if key not in self.exposures:
            self.exposures.append(key)

    def attempt(self, key: str) -> int:
        self._attempts[key] = self._attempts.get(key, 0) + 1
        return self._attempts[key]


@dataclass
class ToolResult:
    content: str
    summary: str
    is_error: bool = False


Handler = Callable[[Workspace, Session, Dict[str, Any]], ToolResult]


# --------------------------------------------------------------------- schemas


def load_finding_schema(prompt_dir: Path) -> Dict[str, Any]:
    """Derive the `report_finding` input schema from the report schema.

    ``prompts/findings.schema.json`` describes the whole report; one finding is
    exactly ``properties.findings.items``. Deriving it keeps a single definition
    of what a finding is — the artifact written at the end and the tool the model
    calls cannot drift apart.
    """
    schema_path = prompt_dir / "findings.schema.json"
    try:
        raw = json.loads(schema_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise WorkspaceError(
            "findings schema not found at {}".format(schema_path)) from exc
    except json.JSONDecodeError as exc:
        raise WorkspaceError(
            "{} is not valid JSON: {}".format(schema_path, exc)) from exc

    try:
        item = raw["properties"]["findings"]["items"]
    except (KeyError, TypeError) as exc:
        raise WorkspaceError(
            "{}: expected properties.findings.items to describe a single "
            "finding".format(schema_path)
        ) from exc
    if item.get("type") != "object" or "properties" not in item:
        raise WorkspaceError(
            "{}: properties.findings.items must be an object schema".format(schema_path)
        )
    return item


def tool_definitions(finding_schema: Dict[str, Any], diff_available: bool) -> List[Dict[str, Any]]:
    """Build the tool list sent with every request.

    The order is fixed and the content is derived only from the schema file and
    the run mode, never from anything per-run. Tools are rendered before the
    system prompt in the cache prefix, so a tool list that varied between turns
    would invalidate the cache on every call.
    """
    tools: List[Dict[str, Any]] = []

    if diff_available:
        tools.append({
            "name": "list_changed_files",
            "description": (
                "List every file changed in the merge request under review, with "
                "its change type. Start here: it tells you the shape of the "
                "change before you spend a call reading anything."
            ),
            "input_schema": {"type": "object", "properties": {}},
        })
        tools.append({
            "name": "get_diff",
            "description": (
                "Get the unified diff for the merge request. Omit `path` for the "
                "whole change, or pass one file's path to see just that file with "
                "more surrounding context. Line numbers on the '+' side of a hunk "
                "header are the post-change line numbers to cite in findings."
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Repository-relative path, or omit for all files.",
                    },
                    "context_lines": {
                        "type": "integer",
                        "description": "Lines of context around each hunk, 0-100. Default 12.",
                    },
                },
            },
        })

    tools.append({
        "name": "list_directory",
        "description": (
            "List tracked files and subdirectories under a path. Use it to orient "
            "yourself in an unfamiliar repository — to find where routes, "
            "middleware, models, or config live."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Repository-relative directory, or omit for the root.",
                },
                "depth": {
                    "type": "integer",
                    "description": "How many levels to expand, 1-6. Default 1.",
                },
            },
        },
    })

    tools.append({
        "name": "read_file",
        "description": (
            "Read a tracked file with line numbers. Read the whole file when it is "
            "small; pass start_line and end_line to window into a large one. This "
            "is how you confirm what a diff only hints at — the validation that "
            "runs before a sink, the decorator on a route, the default in a config."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Repository-relative file path."},
                "start_line": {"type": "integer", "description": "First line, 1-based. Default 1."},
                "end_line": {
                    "type": "integer",
                    "description": "Last line inclusive; omit or 0 for end of file.",
                },
            },
            "required": ["path"],
        },
    })

    tools.append({
        "name": "search_code",
        "description": (
            "Search tracked files with a POSIX extended regular expression, "
            "returning file:line:match. This is your main instrument for tracing "
            "data flow: find a function's callers, find every use of a sink, find "
            "where a value is validated, or find whether a pattern you just saw "
            "repeats elsewhere in the codebase."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "pattern": {
                    "type": "string",
                    "description": "POSIX extended regex, e.g. 'execute\\(.*%s' or 'def (login|authenticate)'.",
                },
                "path_glob": {
                    "type": "string",
                    "description": "Restrict to matching paths, e.g. 'src/**/*.py'.",
                },
                "case_sensitive": {
                    "type": "boolean",
                    "description": "Default false.",
                },
                "context_lines": {
                    "type": "integer",
                    "description": "Lines of context around each match, 0-10. Default 0.",
                },
                "max_results": {
                    "type": "integer",
                    "description": "Cap on returned matches, 1-300. Default 80.",
                },
            },
            "required": ["pattern"],
        },
    })

    tools.append({
        "name": "git_log",
        "description": (
            "Recent commit subjects for the repository or one file. Useful for "
            "telling deliberate security work from an accident, and for seeing "
            "whether a suspicious construct predates this change."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Repository-relative path, or omit for all."},
                "max_count": {"type": "integer", "description": "Commits to return, 1-50. Default 15."},
            },
        },
    })

    tools.append({
        "name": REPORT_FINDING,
        "description": (
            "Record one confirmed security finding. Call this once per distinct "
            "weakness, at the point where you have traced the exploit path and can "
            "state it concretely — not as a placeholder for something you still "
            "intend to check. Reporting the same weakness twice is de-duplicated, "
            "and reporting one you cannot substantiate is worse than reporting "
            "nothing, because it blocks a merge."
        ),
        "strict": True,
        "input_schema": finding_schema,
    })

    tools.append({
        "name": FINISH_REVIEW,
        "description": (
            "End the review. Call this exactly once, when you have finished "
            "looking — after every finding is reported, or after concluding "
            "there is nothing to report. This is the only way to say the "
            "review is complete: a review that stops without it is recorded as "
            "having been cut short, because from the outside 'finished' and "
            "'was interrupted' look identical.\n\n"
            "Do not call it to bail out of something you have not checked. If "
            "you ran out of room or could not settle a question, still call it "
            "— and say so in `unresolved`. A named gap is useful; a silent one "
            "is the failure this tool exists to prevent."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "summary": {
                    "type": "string",
                    "description": (
                        "What you reviewed and what you concluded, in the "
                        "reviewer's own words. This is what a person reads "
                        "first. State what you looked at, not only what you "
                        "found — 'no findings' after reading three files and "
                        "'no findings' after reading thirty are different "
                        "statements."
                    ),
                },
                "unresolved": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": (
                        "Questions you could not settle, one per entry. A "
                        "control you could not locate, a caller you could not "
                        "trace, a file you could not read. Leave empty only if "
                        "there genuinely are none — 'I could not tell' is a "
                        "real answer here and a better one than a guess."
                    ),
                },
            },
            "required": ["summary"],
        },
    })

    return tools


def read_only_tool_definitions(diff_available: bool) -> List[Dict[str, Any]]:
    """The investigation tools without `report_finding` or `finish_review`.

    Used by the verifier, which must be able to check a claim as thoroughly as
    the agent that made it, but has no business creating findings of its own —
    its only output is a verdict on the one claim it was given. It has no
    review to end either: its answer is a JSON verdict, and giving it a way to
    declare a review complete would let one vote on one claim close the review
    that produced the claim.
    """
    return [
        tool for tool in tool_definitions(_MINIMAL_FINDING_SCHEMA, diff_available)
        if tool["name"] not in (REPORT_FINDING, FINISH_REVIEW)
    ]


def verifier_tool_definitions(
    verdict_schema: Dict[str, Any], diff_available: bool
) -> List[Dict[str, Any]]:
    """The read-only set plus the one way a verifier may answer.

    The schema is passed in rather than defined here because it belongs to the
    verification layer, and duplicating it would put two definitions of a
    verdict in the codebase — the shape of drift this project has already been
    bitten by twice.
    """
    return [*read_only_tool_definitions(diff_available), {
        "name": SUBMIT_VERDICT,
        "description": (
            "Submit your verdict on the one finding you were given. Call this "
            "exactly once, when you have finished checking — it is both your "
            "answer and your statement that you are done. A verifier that "
            "stops without calling it has not voted, and a claim with no vote "
            "behind it is not verified.\n\n"
            "You may not submit twice. If you are unsure, that is what "
            "`uncertain` is for: a steady 'I could not establish this' is "
            "worth more than a guess that differs between readings."
        ),
        "input_schema": verdict_schema,
    }]


# `tool_definitions` needs a finding schema to build the reporting tool, which
# the verifier list then discards. This placeholder keeps the caller from having
# to load the real schema just to throw the result away.
_MINIMAL_FINDING_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": [],
    "properties": {},
}


# -------------------------------------------------------------------- handlers


def _handle_list_changed_files(ws: Workspace, session: Session, args: Dict[str, Any]) -> ToolResult:
    changed = ws.changed_files()
    if not changed:
        return ToolResult(
            "The diff for this merge request contains no reviewable files "
            "(the change may be limited to excluded paths such as lockfiles).",
            "no changed files",
        )
    # Generated files are labelled here rather than removed. A diff carrying
    # ten thousand lines of regenerated protobuf pushes the hand-written code
    # out of the reviewer's attention and costs input tokens for it — but
    # generated CI configuration decides what runs and as whom, a compromised
    # generator produces real vulnerabilities in real output, and an attacker
    # can type the banner into a file they wrote themselves. So the path stays
    # visible with its reason, and the file stays readable.
    lines = []
    labelled = 0
    for path, kind in changed:
        # The raw blob, not `read_file`: that one returns line-numbered text
        # for the model to cite, and a numbered line does not start with `//`,
        # so every anchored banner pattern would silently miss. The anchors are
        # load-bearing — they are what stops a marker in a string literal from
        # reclassifying hand-written code.
        try:
            head = ws.blob_text(path)
        except WorkspaceError:
            head = ""
        reason = generated.classify(path, head)
        if reason:
            labelled += 1
            lines.append("{} ({}) — generated: {}. Look at {} instead, unless "
                         "the output itself carries the weakness."
                         .format(path, kind, reason, generated.source_of(path)))
        else:
            lines.append("{} ({})".format(path, kind))

    note = ""
    if labelled:
        note = ("\n\n{} of these are generated. They are still readable, and "
                "worth opening when the generator or its input also changed — "
                "output that moved with no identifiable source input is the "
                "interesting case.".format(labelled))
    return ToolResult(
        "{} changed file(s):\n{}{}".format(len(changed), "\n".join(lines), note),
        "{} changed file(s), {} generated".format(len(changed), labelled),
    )


def _handle_get_diff(ws: Workspace, session: Session, args: Dict[str, Any]) -> ToolResult:
    path = str(args.get("path") or "")
    context_lines = _as_int(args.get("context_lines"), 12)
    body = ws.diff(path=path, context_lines=context_lines)
    # Only a *whole-change* diff can hide part of the change. A truncated
    # single-file diff means that file was not fully shown, which the trim
    # notice below already says to the model — it is the unqualified one that
    # decides whether the review saw the change it is answerable for.
    if not path and ws.diff_truncated:
        session.diff_truncated = True
    if not body.strip():
        return ToolResult(
            "Empty diff for {}.".format(path or "this merge request"),
            "empty diff",
        )
    trimmed = False
    if len(body) > MAX_DIFF_CHARS:
        body = body[:MAX_DIFF_CHARS]
        trimmed = True
    if path:
        session.note_file(ws.repo_path(path))
    # Every file the body actually carries. A whole-change diff names none of
    # them in the arguments and contains all of them.
    for touched in _paths_in_diff(body):
        session.note_exposure(touched, "get_diff")
    note = (
        "\n\n[Diff trimmed at 120000 characters. Request individual files with "
        "`path` to see the rest.]" if trimmed else ""
    )
    return ToolResult(
        body + note,
        "diff for {} ({} chars{})".format(
            path or "all files", len(body), ", trimmed" if trimmed else ""
        ),
    )


def _handle_list_directory(ws: Workspace, session: Session, args: Dict[str, Any]) -> ToolResult:
    path = str(args.get("path") or "")
    depth = _as_int(args.get("depth"), 1)
    body = ws.list_directory(path=path, depth=depth)
    return ToolResult(body, "listed {}".format(path or "."))


def _handle_read_file(ws: Workspace, session: Session, args: Dict[str, Any]) -> ToolResult:
    path = str(args.get("path") or "")
    start = _as_int(args.get("start_line"), 1)
    end = _as_int(args.get("end_line"), 0)
    body, trimmed = ws.read_file(path, start_line=start, end_line=end)
    session.note_file(ws.repo_path(path))
    session.note_exposure(ws.repo_path(path), "read_file")
    if trimmed:
        body += (
            "\n\n[Output trimmed. Re-read with a narrower start_line/end_line "
            "window to see the rest.]"
        )
    return ToolResult(body, "read {}".format(path))


def _handle_search_code(ws: Workspace, session: Session, args: Dict[str, Any]) -> ToolResult:
    pattern = str(args.get("pattern") or "")
    body, count = ws.search(
        pattern=pattern,
        path_glob=str(args.get("path_glob") or ""),
        max_results=_as_int(args.get("max_results"), 80),
        case_sensitive=bool(args.get("case_sensitive", False)),
        context_lines=_as_int(args.get("context_lines"), 0),
    )
    # The files the matches came from. Nobody asked for these by name, and
    # their lines are now in the conversation.
    for touched in _paths_in_search(body):
        session.note_exposure(touched, "search_code")
    return ToolResult(body, "search {!r}: {} match(es)".format(pattern, count))


def _handle_git_log(ws: Workspace, session: Session, args: Dict[str, Any]) -> ToolResult:
    max_count = max(1, min(_as_int(args.get("max_count"), 15), 50))
    path = str(args.get("path") or "")
    cmd = ["log", "--no-color", "--date=short", "--format=%h %ad %an: %s", "-n", str(max_count)]
    if path:
        cmd += ["--", ws.repo_path(path)]
    body = ws.git(*cmd, check=False).strip()
    return ToolResult(body or "(no commits)", "git log {}".format(path or "."))


def _handle_finish_review(ws: Workspace, session: Session, args: Dict[str, Any]) -> ToolResult:
    """Record that the reviewer says it is done, and what it concluded.

    Rejections here are returned rather than raised, like every other tool, so
    a reviewer that signs off with two words gets told and can answer properly.
    The one thing this must never do is refuse in a way that leaves the review
    running with no way to end it — so a second call is accepted quietly rather
    than treated as an error.
    """
    summary = str(args.get("summary") or "").strip()
    if len(summary) < MIN_SUMMARY_CHARS:
        return ToolResult(
            "The review is not recorded as finished: `summary` is {} characters "
            "and must be at least {}. Say what you examined and what you "
            "concluded — a person reads this before anything else.".format(
                len(summary), MIN_SUMMARY_CHARS),
            "summary too short",
            is_error=True,
        )

    raw = args.get("unresolved") or []
    if isinstance(raw, str):
        # One string where a list was asked for. Wrapping it keeps a real
        # answer rather than discarding it on a shape complaint.
        raw = [raw]
    unresolved = [str(item).strip() for item in raw if str(item).strip()]

    if session.finished:
        # Already signed off. Keep the first sign-off: a second one arriving
        # after more work is not more authoritative, and letting a later call
        # overwrite the summary would let a truncated retry blank it.
        return ToolResult(
            "The review is already recorded as finished. Stop here.",
            "finish_review (repeat, ignored)",
        )

    session.finished = True
    session.final_summary = summary
    session.unresolved = unresolved
    return ToolResult(
        "Review recorded as finished. Stop now — no further tool calls are "
        "needed.",
        "finish_review: {} unresolved".format(len(unresolved)),
    )


def _handle_submit_verdict(ws: Workspace, session: Session, args: Dict[str, Any]) -> ToolResult:
    """Record the verifier's one vote. Shape only — the meaning is checked above.

    Deliberately shallow: whether a confirmation names what it searched for,
    and what the panel does with three votes, are decisions for the
    verification layer. Duplicating any of that here would put two definitions
    of a valid verdict in the codebase, and the one in this file would be the
    one nobody remembered to update.
    """
    verdict = str(args.get("verdict") or "").strip()
    if not verdict:
        return ToolResult(
            "No verdict recorded: `verdict` is required.",
            "verdict missing", is_error=True)

    if session.verdict is not None:
        # One session, one candidate, one vote. A second call is refused rather
        # than allowed to overwrite: a later answer is not a better one, and
        # letting it through would let a truncated retry replace a real verdict.
        return ToolResult(
            "You have already submitted a verdict on this finding and may not "
            "submit another. Stop here.",
            "submit_verdict (repeat, refused)", is_error=True)

    session.verdict = dict(args)
    return ToolResult(
        "Verdict recorded. Stop now — no further tool calls are needed.",
        "submit_verdict: {}".format(verdict))


def _handle_report_finding(ws: Workspace, session: Session, args: Dict[str, Any]) -> ToolResult:
    """Record a finding — after checking that the code it cites is really there.

    This is the deterministic half of the hallucination check. The agent must
    quote the vulnerable code verbatim; that quote is matched against the file
    on disk before anything is recorded. A quote that is not in the file means
    the finding describes code that does not exist, and a blocking gate has no
    business emitting one.
    """
    try:
        finding = Finding.from_dict(args)
    except (KeyError, TypeError, ValueError) as exc:
        return ToolResult(
            "Could not record the finding: {}. Every field in the schema is "
            "required.".format(exc),
            "malformed finding",
            is_error=True,
        )

    claim_key = "{}|{}".format(finding.file, finding.title.strip().lower())
    attempt = session.attempt(claim_key)
    final_attempt = attempt >= MAX_CITATION_ATTEMPTS

    # --- does the file exist? ---
    try:
        # Existence is decided by the revision under review, not by the disk —
        # the same authority the quoted evidence is matched against.
        rel_path = ws.repo_path(finding.file)
        file_text = ws.raw_text(finding.file)
    except WorkspaceError as exc:
        if final_attempt:
            session.rejected.append(RejectedClaim(
                title=finding.title, file=finding.file,
                reason="unknown-path", detail=str(exc)))
            return ToolResult(
                "Dropped: {!r} still does not resolve to a readable file. Do not "
                "report this finding again.".format(finding.file),
                "dropped: unknown path {}".format(finding.file),
                is_error=True,
            )
        session.metrics.citations_rejected_unknown_path += 1
        return ToolResult(
            "Not recorded — no readable file {!r} in this repository ({}).{} "
            "Findings must cite a real repository-relative path. Check the path "
            "with list_directory or search_code, then report again.".format(
                finding.file, exc, _suggest_paths(ws, finding.file)),
            "rejected: unknown path {}".format(finding.file),
            is_error=True,
        )

    # --- is the quoted code actually in that file, at one identifiable place? ---
    try:
        located = locate_evidence(file_text, finding.evidence, finding.line)
        problem = ""
    except EvidenceProblem as exc:
        located, problem = None, str(exc)
    if located is None:
        if final_attempt:
            session.rejected.append(RejectedClaim(
                title=finding.title, file=rel_path,
                reason="evidence-not-found",
                detail="quoted code does not appear in the file"))
            return ToolResult(
                "Dropped: {} in {}. A finding whose evidence cannot be tied to "
                "one place in the file cannot be reported. Move on."
                .format(problem, rel_path),
                "dropped: {}".format(problem[:60]),
                is_error=True,
            )
        session.metrics.note_citation_rejection(problem)
        window, start, stop = excerpt(file_text, finding.line, radius=20)
        return ToolResult(
            "Not recorded — {} in {}. Evidence must be copied verbatim from the "
            "file, with no diff markers, ellipses, or paraphrasing, and must "
            "identify one place.\n\nWhat is actually at lines {}-{}:\n{}\n\n"
            "Re-read the file, then either report again quoting the real code, "
            "or drop the finding if the code you had in mind is not there."
            .format(problem, rel_path, start, stop, window),
            "rejected: {}".format(problem[:60]),
            is_error=True,
        )

    # --- accept, correcting the line number to where the code really is ---
    span = evidence_span(finding.evidence)
    corrected_from = finding.line if finding.line != located else None
    changed = ws.changed_line_map()
    attributed = attribution(rel_path, located, span, changed)

    duplicate = next(
        (c for c in session.candidates if c.fingerprint == finding.fingerprint), None
    )
    if duplicate is not None:
        session.duplicates_dropped += 1
        return ToolResult(
            "Already recorded as {} ({}). Not added again — move on to the next "
            "concern.".format(duplicate.fingerprint, duplicate.finding.title),
            "duplicate of {}".format(duplicate.fingerprint),
        )

    session.metrics.citations_accepted += 1
    if corrected_from is not None:
        session.metrics.lines_corrected += 1
    candidate = Candidate(
        finding=finding,
        evidence_located_line=located,
        line_corrected_from=corrected_from,
        in_changed_lines=bool(attributed) if changed else True,
        attributed_by=attributed if changed else "added",
        path_verified=True,
    )
    session.candidates.append(candidate)
    session.note_file(rel_path)

    notes = []
    if corrected_from is not None:
        notes.append("line corrected from {} to {}".format(corrected_from, located))
    if changed and not attributed:
        notes.append(
            "this code is not part of the diff, so it will be reported as "
            "pre-existing rather than introduced by this change"
        )
    suffix = " ({})".format("; ".join(notes)) if notes else ""

    return ToolResult(
        "Recorded {} — {} {} at {}:{}{}. Evidence verified against the file."
        .format(finding.fingerprint, finding.severity, finding.category,
                rel_path, located, suffix),
        "recorded {} {} at {}:{}".format(
            finding.severity, finding.category, rel_path, located),
    )


HANDLERS: Dict[str, Handler] = {
    "list_changed_files": _handle_list_changed_files,
    "get_diff": _handle_get_diff,
    "list_directory": _handle_list_directory,
    "read_file": _handle_read_file,
    "search_code": _handle_search_code,
    "git_log": _handle_git_log,
    REPORT_FINDING: _handle_report_finding,
    FINISH_REVIEW: _handle_finish_review,
    SUBMIT_VERDICT: _handle_submit_verdict,
}


# Both sides of a file header. `+++ b/...` names the file as it is after the
# change and is what an addition or an edit carries; a deletion writes
# `+++ /dev/null` and names the file only on the `--- a/...` line, so reading
# the `+++` side alone recorded no exposure for it.
#
# The bytes of a deleted file are in the diff either way — every removed line
# of it — so a review of a deletion had the code in front of it and the record
# said nothing had reached the model. That mattered once the gate began reading
# this to tell a review that stopped early from one nothing reached: a
# deletion-only change, partial, was about to be called an absent review.
_DIFF_PATH = re.compile(r"^(?:\+\+\+ b|--- a)/(.+)$", re.M)


def _paths_in_diff(body: str) -> List[str]:
    """The files a unified diff actually carries content for.

    Deduplicated, because an ordinary edit names the same file on both header
    lines and an exposure is a fact about a file rather than a count of
    mentions.
    """
    return list(dict.fromkeys(
        line for line in _DIFF_PATH.findall(body or "") if line != "/dev/null"))


_SEARCH_PATH = re.compile(r"^([^\s:][^:]*):\d+:", re.M)


def _paths_in_search(body: str) -> List[str]:
    """The files a search result quoted lines from."""
    return list(dict.fromkeys(_SEARCH_PATH.findall(body or "")))


def dispatch(ws: Workspace, session: Session, name: str, args: Dict[str, Any]) -> ToolResult:
    """Run one tool call, converting every failure into a usable tool result.

    A raised exception here would end the run; a returned error lets the agent
    correct a bad argument and continue, which is almost always what a wrong path
    or an invalid regex deserves.
    """
    handler = HANDLERS.get(name)
    if handler is None:
        return ToolResult(
            "No tool named {!r}. Available: {}.".format(name, ", ".join(sorted(HANDLERS))),
            "unknown tool {}".format(name),
            is_error=True,
        )
    if not isinstance(args, dict):
        return ToolResult(
            "Tool input must be a JSON object.", "malformed input", is_error=True
        )
    try:
        return handler(ws, session, args)
    except WorkspaceError as exc:
        return ToolResult(str(exc), "error: {}".format(exc), is_error=True)
    except Exception as exc:  # last line of defence — never kill the run
        log.exception("tool %s raised", name)
        return ToolResult(
            "{} failed unexpectedly: {}: {}".format(name, type(exc).__name__, exc),
            "error: {}".format(type(exc).__name__),
            is_error=True,
        )


def _as_int(value: Any, default: int) -> int:
    if value is None or isinstance(value, bool):
        return default
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _suggest_paths(ws: Workspace, wanted: str, limit: int = 5) -> str:
    """Offer tracked paths sharing the basename, to fix an obvious path slip."""
    basename = wanted.rsplit("/", 1)[-1]
    if not basename:
        return ""
    matches = [p for p in ws.tracked_files() if p.rsplit("/", 1)[-1] == basename][:limit]
    if not matches:
        return ""
    return " Tracked files with that name: {}.".format(", ".join(matches))
