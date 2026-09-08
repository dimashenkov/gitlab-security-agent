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
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from . import generated
from .context_budget import ContextBudget
from .evidence import (
    EvidenceProblem,
    attribution,
    evidence_span,
    excerpt,
    locate_evidence,
    unquote_path,
)
from .models import Candidate, Finding, RejectedClaim, StageMetrics, ToolCallRecord
from .workspace import (
    CUT_BY_DEADLINE,
    MAX_OUTPUT_CHARS,
    FileNotAtRevision,
    FileTooLarge,
    Workspace,
    WorkspaceError,
)

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
    # How much of the conversation the review has spent. Unbounded by default,
    # so switching it on is a decision: a budget that appeared silently would
    # change every existing run without anyone choosing it.
    context: ContextBudget = field(default_factory=ContextBudget)
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
    # The entire text of the change was put in front of the model at least once,
    # whole and uncut. See `ToolResult.whole_diff` for why this one fact is the
    # completeness rule and line-by-line accounting is not.
    whole_diff_delivered: bool = False
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
    """What a tool produced, and what it means for the session *if delivered*.

    The last three fields are deliberately deferred. They were once written
    straight onto the session inside the handler, which was correct while every
    result was delivered and became wrong the moment the context budget could
    refuse one: a read whose bytes never reached the model was still recorded as
    an exposure, and `gate._reviewed_nothing` reads exposures to tell a review
    that stopped early from one that never started. A run refused everything it
    asked for would have claimed the change had been seen.

    So a handler now *describes* what delivering its result would mean, and
    `_budgeted` applies it only when the content actually goes to the model.
    """

    content: str
    summary: str
    is_error: bool = False
    # Files the agent opened by name. `Session.files_examined`.
    examined: Tuple[str, ...] = ()
    # (path, channel) for every file whose bytes this result carries.
    exposures: Tuple[Tuple[str, str], ...] = ()
    # This result is a whole-change diff that the workspace cut at its ceiling.
    diff_truncated: bool = False
    # This result carried the entire change, whole and uncut.
    #
    # The completeness question — did the reviewer read what it is answerable
    # for — was twice attempted as a per-file boolean and twice wrong: files
    # *opened by name* answers "none" for a review that read the whole diff, and
    # files whose bytes arrived counts one search hit as having seen a file.
    # Line-level accounting was the third attempt, and Codex refused it for a
    # reason worth keeping: "'the model saw an overview and chose what to open'
    # cannot be both cheaper and no more lenient" — an overview the
    # model selects from is cheaper *because* something went unread, and no
    # arithmetic over delivered lines makes that not so.
    #
    # What is left is the one fact that is both cheap and honest: the whole text
    # of the change reached the model once, entire. Everything after that is
    # navigation. It is false when the diff was cut at either ceiling, when only
    # one file was asked for, and when the context budget refused the result —
    # `apply` runs on delivery and on nothing else.
    whole_diff: bool = False

    def apply(self, session: "Session") -> None:
        """Record what this result means, now that it is going to the model."""
        for path in self.examined:
            session.note_file(path)
        for path, channel in self.exposures:
            session.note_exposure(path, channel)
        if self.diff_truncated:
            session.diff_truncated = True
        if self.whole_diff:
            session.whole_diff_delivered = True


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
        # **A change can be real and have nothing to open.** A deletion is not
        # in `changed_files` — the file is gone and cannot be read — so this
        # used to answer "no reviewable files" to a change that removed an
        # authorisation check, and the reviewer stopped there. Codex, on the
        # gate pass for the `_run` repair: the control flow was fixed to reach
        # the model and the model was then told there was nothing to look at.
        #
        # The deletions are named, and the reviewer is pointed at the diff,
        # which is where the removed lines are.
        deleted = [obj.path for obj in ws.changed_objects()
                   if obj.status == "deleted"]
        if deleted:
            return ToolResult(
                "No files in this change can be opened, because the change "
                "removes them. {} file(s) deleted:\n{}\n\nRead the diff: it "
                "carries every removed line. A deleted authorisation check, "
                "validation routine or other control is a security-relevant "
                "change and is what this listing cannot show you.".format(
                    len(deleted), "\n".join("- " + p for p in deleted)),
                "{} deleted file(s)".format(len(deleted)),
            )
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
        #
        # And the head, not the whole file: reading it whole went through the
        # context ceiling, so every file over 292 KB raised, the error was
        # swallowed into `head = ""`, and `classify("")` answered None. The
        # classifier was blind on exactly the file class it exists for —
        # generated files are the large ones. Measured on a 658 KB protobuf:
        # the real head classifies as "Go generator banner", the empty string
        # as nothing.
        try:
            head = ws.head_text(path)
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


@dataclass(frozen=True)
class DiffCut:
    """Where an oversized diff was cut, and not merely that it was.

    The two cuts below are different facts for the reader, so they are two
    fields and not one boolean. A boundary cut leaves whole files and drops
    later ones; a mid-file cut leaves one file stopping part-way through, and
    the remedy for it is a different tool call. Returning `True` for both is
    what let the note say "the files above are whole" over half a file.
    """

    body: str
    trimmed: bool
    # True only when the surviving text stops inside a file's hunks.
    mid_file: bool = False
    # The file the cut landed inside, when it could be named from the headers
    # that survived. `None` with `mid_file` set means the cut came before those
    # headers were reached — still a mid-file cut, just an unnamed one. Reading
    # "no name" as "not mid-file" is the same absence-as-agreement mistake this
    # whole function exists to undo.
    inside_file: Optional[str] = None


def _trim_diff(body: str) -> DiffCut:
    """Cut an oversized diff where a file ends, never mid-line.

    The first version sliced at exactly 120,000 characters. That can land in
    the middle of a hunk header, of a line number, or of the expression that
    makes the change dangerous — and the file was still recorded as exposed,
    because `_paths_in_diff` had already seen its header. A reviewer shown two
    thirds of a function has been shown something worse than nothing: it looks
    complete.

    So the cut is made at the last `diff --git` boundary inside the ceiling.
    What survives is whole files; what is missing is missing entirely, which is
    a state the model can act on and the accounting can see. A single file
    larger than the whole ceiling has no boundary to cut at, and falls back to
    the last complete line rather than to nothing.

    That fallback is the case this return value exists for. Measured on a
    304,070-character diff whose first file is a 9,000-line rewrite: none of
    the 9,000 added lines were delivered, the second changed file was absent,
    and the note the model reads announced the delivered files as whole. The
    caller could not have said otherwise — it was handed one boolean for two
    cuts. So the shape of the cut travels with the body.
    """
    if len(body) <= MAX_DIFF_CHARS:
        return DiffCut(body, False)
    head = body[:MAX_DIFF_CHARS]
    boundary = head.rfind("\ndiff --git ")
    if boundary > 0:
        return DiffCut(head[:boundary], True)
    line_end = head.rfind("\n")
    kept = head[:line_end] if line_end > 0 else head
    # A ceiling that falls exactly where the next file's header begins cut at a
    # boundary after all — there was no boundary *inside* the ceiling to find,
    # which is a fact about the search and not about the diff. Calling it
    # mid-file would name a file that is in fact whole, and send the reader to
    # re-read something it already has.
    if body[len(kept):].startswith("\ndiff --git "):
        return DiffCut(kept, True)
    # The same parser the exposure records use, so a quoted or escaped path is
    # named here the way it is named everywhere else. With no boundary inside
    # the ceiling there is at most one file in `kept`, so the last name it
    # carries is the file being cut.
    carried = _paths_in_diff(kept)
    return DiffCut(kept, True, mid_file=True,
                   inside_file=carried[-1] if carried else None)


def _read_cut_note(ws: Workspace) -> str:
    """What to tell the model when the *read* was cut, not the rendering.

    Two things stop `Workspace._bounded` and their remedies point in opposite
    directions. Raising `SECURITY_SCAN_DIFF_CEILING_BYTES` repairs a byte cut;
    for a deadline cut it lets more output accumulate before the clock kills it
    anyway, so naming it there is worse than saying nothing. The cause is
    carried out of `_bounded` for exactly this. Codex, tenth gate round,
    2026-09-08.

    Empty when nothing was cut, so callers can append it unconditionally.
    """
    if not ws.last_diff_truncated:
        return ""
    if ws.last_diff_cause == CUT_BY_DEADLINE:
        return (
            # **It says which limit stopped the read, and nothing about the
            # size of the change.** It said "this is a slow read and not a
            # large change", which the deadline establishes nothing about —
            # and `_bounded`'s own marker says the opposite, correctly, one
            # layer down. Two messages about one cut, disagreeing. Codex,
            # eleventh gate round.
            "\n\n[Reading this diff hit the git deadline and stopped, so its "
            "end is missing; the change may be any size. Raising "
            "SECURITY_SCAN_DIFF_CEILING_BYTES does not help with this cut and "
            "lets more output pile up before the same clock stops it. {} This "
            "review is recorded as incomplete.]".format(
                # **Not "ask for one file at a time" when one file is what was
                # asked for.** `_handle_get_diff` calls this for a scoped
                # request too, and advice the reader has already taken sends
                # it round the same timeout again. Codex, twelfth gate round.
                #
                # And the tool argument is not the test. A run started with
                # `--path huge.py` sets `Workspace.scope`, so a plain
                # `get_diff {}` is already one file — while a scope covering a
                # directory is several, where narrowing still helps. The
                # resolved count is the fact, and `diff()` is where it is
                # known. Codex, thirteenth gate round, 2026-09-08.
                "Narrowing further is not possible: this request was already "
                "for one file. Its diff cannot be retrieved within the "
                "deadline, so the change to it has to be split, or git here "
                "has to be made faster." if ws.last_diff_paths == 1 else
                "Ask for one file at a time with `path`.")
        )
    return (
        "\n\n[Diff cut while it was being read, at the workspace byte "
        "ceiling: the end of this diff is missing. Raising "
        "SECURITY_SCAN_DIFF_CEILING_BYTES is the remedy for this cut, up to "
        "the separate fixed limit on how much can be shown at all. This "
        "review is recorded as incomplete.]"
    )


def _handle_get_diff(ws: Workspace, session: Session, args: Dict[str, Any]) -> ToolResult:
    path = str(args.get("path") or "")
    # The model's explicit choice wins; the operator's setting is the
    # default it falls back to. `search_code` keeps its own 0 — a different
    # tool, and the setting names the diff.
    context_lines = _as_int(args.get("context_lines"),
                            ws.default_context_lines)
    body = ws.diff(path=path, context_lines=context_lines)
    # `ws.last_diff_truncated` and not `ws.diff_truncated`: the first is this
    # call's truth and the second stays set once anything in the run has been
    # cut, so reading the run's flag here let an earlier single-file trim decide
    # what a later whole-change diff is.
    #
    # Any cut, in any scope. The rule used to be "only a whole-change diff can
    # hide part of the change", and it left a hole a measurement found rather
    # than an argument: a 247,000-character diff sits under the workspace's
    # 512 KiB ceiling and over this module's 120,000-character one, so it was
    # cut in half by `_trim_diff`, `ws.diff_truncated` stayed False, and the run
    # was reported complete over the first half of a change. That is the exact
    # sentence this product exists to prevent.
    #
    # A single-file diff cut short is the same fact in a smaller frame — the
    # reviewer asked for something and was handed part of it — and treating it
    # as harmless is what made the two runners disagree about identical
    # reviews. Both cuts, both scopes, one flag.
    if not body.strip():
        return ToolResult(
            # The cut note goes here too. `_bounded` appends its own marker, so
            # a cut body is not empty on any path found today — but "empty" and
            # "cut so early there is nothing left" read identically to the
            # model, and the difference is the whole subject of this module.
            # Hardened rather than argued away: the branch is cheap and the
            # reasoning that says it is unreachable is exactly the kind that
            # stops being true one refactor later. Codex, tenth gate round.
            "Empty diff for {}.".format(path or "this merge request")
            + _read_cut_note(ws),
            "empty diff",
            diff_truncated=ws.last_diff_truncated,
            # A whole change with no diff body is a change with no text in it —
            # binary files, a rename, a mode bit. There is nothing being kept
            # from the reviewer, and calling that "the change was never shown"
            # would report every binary-only merge request as unread. The
            # inventory already names those files and why they cannot be read.
            whole_diff=bool(not path and not ws.last_diff_truncated),
        )
    cut = _trim_diff(body)
    body, trimmed = cut.body, cut.trimmed
    truncated_change = bool(trimmed or ws.last_diff_truncated)
    # The note is the only thing the model has to act on, so it says which of
    # the two cuts happened. The boundary one has a remedy — ask for the
    # missing files. **The mid-file one has none, and the note has to say so.**
    #
    # It first said "read it in windows with `read_file` instead", which Codex
    # rejected on the gate for this change: `read_file` returns the file's text
    # at the reviewed revision, which is the state *after* the change and not
    # the change. It cannot show a deleted line, and it cannot tell an added
    # line from one that was always there. Naming it as the remedy replaced a
    # remedy that loops with one that answers a different question — and a
    # reviewer that believes it has recovered the change stops looking, which
    # is worse than one that knows it cannot.
    #
    # So this names what the tools can still establish, and then says plainly
    # that the missing hunks are not among them. The run is already recorded
    # incomplete (`diff_truncated` reaches `gate._partial`); the note must not
    # imply otherwise.
    # **The two notes are composed, not chosen between.** `trimmed` is this
    # module's character limit; `ws.last_diff_cause` is the workspace's, and
    # they are not alternatives — a byte cut at the default 512 KiB ceiling
    # returns far more than `MAX_DIFF_CHARS`, so both fire on the same call.
    # The first version used the read-cut note only when `trimmed` was false,
    # which meant the cause was reported in exactly the configuration where it
    # never happens and discarded in the ordinary one. Codex, eleventh gate
    # round, 2026-09-08; the tests before it exercised only cuts that exclude
    # each other, which is how it read as covered.
    if not trimmed:
        note = ""
    elif cut.mid_file:
        note = (
            "\n\n[Diff trimmed at {} characters, in the middle of {}. Its "
            "hunks stop part-way through: the rest of that file's changes are "
            "not here.{} Those hunks cannot be retrieved: asking for that file "
            "with `path` is cut in the same place, and `read_file` returns its "
            "text at the reviewed revision — the state after the change, not "
            "the change, so a removed line is not in it and an added line is "
            "indistinguishable from one that was always there. This review is "
            "recorded as incomplete.]".format(
                MAX_DIFF_CHARS,
                "`{}`".format(cut.inside_file) if cut.inside_file
                # No header survived the cut, so the file cannot be named. The
                # reader still needs to know the text stops mid-file; the name
                # is one `list_changed_files` away, the false "this is whole"
                # is not recoverable.
                else "a file whose header did not survive the cut, so it "
                     "cannot be named here",
                # Only a whole-change diff has files after the cut one. Saying
                # so for a single-file request would send the reader looking
                # for files this call was never going to carry.
                # And `path` is qualified, because a dropped later file can be
                # over the ceiling on its own and comes back cut in exactly the
                # same way. An unqualified "request them with `path`" is the
                # same defect as the one this whole note exists to fix, one
                # file further down.
                " No file changed after it is here either; "
                "`list_changed_files` names them, and each can be requested "
                "with `path` unless its own diff is over the ceiling too, in "
                "which case that one is cut the same way." if not path else "",
            )
        )
    else:
        note = (
            "\n\n[Diff trimmed at {} characters, at a file boundary. The files "
            "above are whole; the ones after the cut are not here at all. "
            "Request them individually with `path` — except any whose own diff "
            "is over the ceiling, which comes back cut the same way.]".format(
                MAX_DIFF_CHARS)
        )
    return ToolResult(
        # Both notes, whichever fired. Two cuts on one call are two facts and
        # the reader needs both: the character trim says what is missing from
        # the end of this result, the read cut says the body it trimmed was
        # already short of the change.
        body + note + _read_cut_note(ws),
        # The summary is what the transcript and the accounting keep, and a
        # mid-file cut recorded as plain "trimmed" is the same loss one layer
        # up: nothing later could tell that a file was delivered in half.
        "diff for {} ({} chars{})".format(
            path or "all files", len(body),
            ", trimmed mid-file{}".format(
                " in " + cut.inside_file if cut.inside_file else ""
            ) if cut.mid_file else (", trimmed" if trimmed else "")
        ),
        examined=(ws.repo_path(path),) if path else (),
        # Every file the body actually carries. A whole-change diff names none
        # of them in the arguments and contains all of them.
        exposures=tuple((touched, "get_diff") for touched in _paths_in_diff(body)),
        diff_truncated=truncated_change,
        # The same two cuts, asked of the whole change rather than of this
        # result: a body that is missing files, or a body that is missing the
        # rest of one file, is not the change shown entire.
        whole_diff=bool(not path and not truncated_change),
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
    try:
        body, trimmed = ws.read_file(path, start_line=start, end_line=end)
    except FileNotAtRevision as absent:
        # **The last link that assumed a reviewed file.** Codex, 2026-09-06,
        # tracing the whole deletion path: for a file larger than the
        # verifier's context the brief supplies a window and tells it to read
        # more with the tools — and this handler read the reviewed revision,
        # where a deleted file is not. The verifier was invited to investigate
        # and then refused the file.
        #
        # `FileNotAtRevision` and not `WorkspaceError`: catching the base class
        # took *every* failure as evidence of a deletion, so a file that was
        # merely over the ceiling entered this branch and was refused here for
        # an unrelated second reason. `read_removed_file` refuses any path this
        # change did not delete, so this is not a way of reading the base
        # generally.
        try:
            body, trimmed = ws.read_removed_file(path, start_line=start, end_line=end)
        except FileTooLarge:
            # Named before the base class, or the fix below swallows it: a
            # large *deleted* file would be re-raised as "not at this
            # revision", losing the distinction this change exists to make.
            # Codex caught it in the gate for the change that introduced it.
            raise
        except WorkspaceError:
            # The path is absent and this change did not delete it, which is a
            # path that never existed. Raising the deletion guard's message
            # here would answer `read_file` with *"read it with read_file"* —
            # circular advice, and the reason it gives is not the reason.
            raise absent from None
        body = ("`{}` was deleted by this change; the lines below are from the "
                "**base revision**, before the removal.\n\n{}".format(path, body))
    if trimmed:
        # **The remedy has to exist.** Two different cuts set `trimmed`, and
        # the advice below fitted only one of them. When the body stopped
        # because later *lines* did not fit, a narrower window does reach them.
        # When it stopped inside a single line, it does not: one line is
        # already the narrowest window, so following the advice returns the
        # identical bytes, and a reviewer that trusts it loops. Measured: a
        # 140,016-character line delivers `MAX_OUTPUT_CHARS` of itself and the
        # rest is unreachable through this tool at any argument, while the
        # message invites the reader to try again.
        #
        # The same defect was repaired once already, one level up: the ceiling
        # moved from the blob to the rendered window, and the sentence pointing
        # at the window stayed behind it. So this names the tool that does
        # terminate. `search_code` returns a window centred on the match rather
        # than the head of the line, which is the only way to see the inside of
        # a line this long.
        clip = ws.last_read_clip
        if clip is None:
            body += (
                "\n\n[Output trimmed. Re-read with a narrower start_line/"
                "end_line window to see the rest.]"
            )
        else:
            body += (
                "\n\n[Output trimmed inside line {}: that line is {} "
                "characters and only the first {} are above. A narrower "
                "start_line/end_line window returns these same bytes — one "
                "line is the narrowest window there is. To see further into "
                "it, search for a pattern with `search_code`: its result is a "
                "window centred on the match.{}]".format(
                    clip.number, clip.chars, MAX_OUTPUT_CHARS,
                    " Lines after {} were selected and are not here; a window "
                    "starting after it returns them.".format(clip.number)
                    if clip.more_after else "",
                )
            )
    return ToolResult(
        body,
        "read {}".format(path),
        examined=(ws.repo_path(path),),
        exposures=((ws.repo_path(path), "read_file"),),
    )


def _handle_search_code(ws: Workspace, session: Session, args: Dict[str, Any]) -> ToolResult:
    pattern = str(args.get("pattern") or "")
    body, count = ws.search(
        pattern=pattern,
        path_glob=str(args.get("path_glob") or ""),
        max_results=_as_int(args.get("max_results"), 80),
        case_sensitive=bool(args.get("case_sensitive", False)),
        context_lines=_as_int(args.get("context_lines"), 0),
    )
    # The summary must not assert what the body qualifies. A search whose scan
    # stopped early counted what it reached, and printing that as an exact
    # total put two disagreeing statements about one result into one artifact.
    counted = ("at least {} match(es)".format(count)
               if ws.last_search_truncated else "{} match(es)".format(count))
    return ToolResult(
        body,
        "search {!r}: {}".format(pattern, counted),
        # The files the matches came from. Nobody asked for these by name, and
        # their lines are now in the conversation.
        exposures=tuple((touched, "search_code")
                        for touched in _paths_in_search(body)),
    )


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


def _file_is_attributable(path: str, changed) -> bool:
    """Can the changed-line map say anything about this file at all?

    Distinct from "is the map non-empty". A map that knows about other files
    and nothing about this one cannot place a line in it, and reading that
    silence as "the line was already there" is what let one line of
    `.gitattributes` file a critical finding as pre-existing — where the gate
    skips it. Measured end to end on 2026-09-07.

    Absent means unknown, and unknown fails towards the finding counting.
    """
    if not changed:
        return False
    return bool(changed.added.get(path)) or bool(changed.removed_at.get(path))


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
    # Carried out of the read, because only the read knows it. `attribution`
    # works from the diff's line map, and `changed_line_map` leaves `current`
    # empty for `+++ /dev/null` — a wholly deleted file has no line in the
    # reviewed revision to attribute anything to. So the map says nothing, and
    # a finding about a removed authorisation check came out as "pre-existing,
    # not introduced here": accepted, and then excluded from the gate by the
    # rule for code this change did not touch. Codex, 2026-09-06, asked
    # directly whether the attribution survived the repair.
    from_a_deleted_file = False
    try:
        # Existence is decided by the revision under review, not by the disk —
        # the same authority the quoted evidence is matched against.
        rel_path = ws.repo_path(finding.file)
        try:
            file_text = ws.raw_text(finding.file)
        except FileNotAtRevision as absent:
            # **A file this change deleted is read at the base.** It is not at
            # the reviewed revision — that is what deleting it means — so every
            # finding quoting a removed authorisation check was dropped as
            # `unknown-path`. The diff could inspire the finding and nothing
            # could record it. Codex, 2026-09-06, on the gate pass for the
            # deletion repair: fixing the control flow without this leaves the
            # reviewer able to see the removal and unable to report it.
            #
            # `FileNotAtRevision` and not `WorkspaceError`. Catching the base
            # class meant "over the ceiling" also entered this branch, where
            # `removed_text` refused it a second time for an unrelated reason —
            # and *that* message became the artifact's detail: `unknown-path`,
            # *"is not a file this change deleted; read it with read_file"*,
            # advising the tool that had already refused it. Measured on
            # 2026-09-07, not reasoned about.
            try:
                file_text = ws.removed_text(finding.file)
            except FileTooLarge:
                raise
            except WorkspaceError:
                # Absent at head and not deleted by this change, which is a
                # path that never existed. The deletion guard's own message —
                # *"read it with read_file"* — would become the artifact's
                # detail for a claim the reviewer made about a path it
                # invented, advising a tool that refuses it too. The reason
                # recorded is the one that is true: not at this revision.
                raise absent from None
            from_a_deleted_file = True
    except FileTooLarge as exc:
        # A file too large to scan is a different answer from a path that does
        # not exist, and until now it was recorded as the second. It is still a
        # dropped claim — nothing can confirm the quote — but the reason is the
        # one that is true, and it names its own limit rather than a path.
        session.metrics.citations_rejected_too_large += 1
        if final_attempt:
            session.rejected.append(RejectedClaim(
                title=finding.title, file=finding.file,
                reason="file-too-large", detail=str(exc)))
            return ToolResult(
                "Dropped: {} Nothing can confirm a quotation from it, so the "
                "finding cannot be recorded. Do not report it again."
                .format(exc),
                "dropped: file too large {}".format(finding.file),
                is_error=True,
            )
        return ToolResult(
            "Not recorded — {} The path is real; the file is too large for the "
            "citation check to open. If the weakness is also visible in a "
            "smaller file, report it there instead.".format(exc),
            "rejected: file too large {}".format(finding.file),
            is_error=True,
        )
    except WorkspaceError as exc:
        # Counted on both paths: the drop is a rejection too, and the loudest
        # one. Incrementing only on the retry path made a claim abandoned after
        # MAX_CITATION_ATTEMPTS look in the artifact like a claim that was
        # nudged once and then never came back — every dropped claim
        # undercounted by exactly one.
        session.metrics.citations_rejected_unknown_path += 1
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
        # Same undercount as the path branch above: a claim dropped after
        # MAX_CITATION_ATTEMPTS never reached the counter, so the `citations`
        # block scored the final failure as if it had not happened.
        session.metrics.note_citation_rejection(problem)
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
        # The same ceiling every other tool result honours. The radius bounds
        # lines and a file that is one long line has one line, so without this
        # a rejected citation could return the whole file as "lines 1-1".
        window, start, stop = excerpt(file_text, finding.line, radius=20,
                                      limit=MAX_OUTPUT_CHARS)
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
    #
    # And the path, for the same reason. `repo_path` deliberately accepts
    # `/src/app.py` and `./src/app.py` for `src/app.py` — its docstring says
    # the model writes them — so both spellings reached here and produced the
    # same candidate with a *different* fingerprint, because the digest was
    # taken from `finding.file` raw. Four spellings, four identities for one
    # weakness. Measured, on this code: they came back as four distinct
    # digests.
    #
    # What that cost is the whole point of anchoring identity on code rather
    # than on prose: an accepted-risk entry stops matching the next time the
    # model spells the path differently, two reports of one weakness are not
    # deduplicated, and a `path:` suppression rule silently fails to apply.
    # The fingerprint moved off the title for exactly this reason and kept
    # half of the problem.
    if finding.file != rel_path:
        finding = replace(finding, file=rel_path)
    span = evidence_span(finding.evidence)
    corrected_from = finding.line if finding.line != located else None
    changed = ws.changed_line_map()
    attributed = ("deleted" if from_a_deleted_file
                  else attribution(rel_path, located, span, changed))

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
        # A deletion is a change to this merge request whatever the line map
        # can say about it: the file is gone *because of this change*.
        #
        # **"The map places no line in this file" is not "this line is old".**
        # The second layer of the `.gitattributes` repair, and the one that
        # closes the class rather than one route into it. `bool(attributed)`
        # answered False for both of these, and they are different facts:
        #
        #   the map holds lines for this file, and not this one
        #       -> the line really is pre-existing
        #   the map holds no lines for this file at all
        #       -> nothing could attribute it, and a finding filed as
        #          pre-existing is a finding the gate skips
        #
        # One line of `.gitattributes` saying `*.py -diff` produced the second
        # while the map stayed non-empty, because `.gitattributes` was in it.
        # `--attr-source` stops that route; this stops the reading that made it
        # work, so the next way of emptying one file's entry — a diff git
        # cannot parse, a rename it resolves differently, a form nobody has
        # thought of — fails towards blocking instead of towards silence.
        # Codex asked for both layers, 2026-09-07.
        in_changed_lines=(True if from_a_deleted_file
                          else bool(attributed) if _file_is_attributable(
                              rel_path, changed) else True),
        attributed_by=attributed if (changed or from_a_deleted_file)
        else "added",
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


def _header_path(line: str) -> str:
    """The file named by a `--- a/...` or `+++ b/...` header, decoded.

    Git puts the prefix inside the quotes — `"b/src/caf\\303\\251.py"` — so the
    unquoting happens first and the `a/`/`b/` strip second. The single tab git
    appends when a path contains a space is removed, and nothing else is: a
    trailing space is a legal name on Linux, and `.strip()` here would produce a
    key that nothing ever looks up.
    """
    body = line[4:]
    if body.endswith("\t"):
        body = body[:-1]
    path = unquote_path(body)
    if path.startswith("a/") or path.startswith("b/"):
        return path[2:]
    return path


def _paths_in_diff(body: str) -> List[str]:
    """The files a unified diff actually carries content for.

    Read structurally, one line at a time, rather than by scanning the whole
    body for anything shaped like a header. The scanning version matched
    `^(?:\\+\\+\\+ b|--- a)/(.+)$` anywhere, and every line of added content in a
    diff begins with `+` — so a merge request that adds the literal line

        +++ b/payments/authorise.py

    to any file wrote an exposure record for a file the reviewer never opened.
    The record is read by `gate._reviewed_nothing` to tell a review that
    stopped early from one that never started, so the forgery pointed the wrong
    way: it made a thinner review look like a fuller one. The same class of
    defect, and the same fix, as `evidence.changed_lines` — parse the format,
    do not pattern-match the text.

    A header only counts before the first `@@` of its file section. After that,
    everything until the next `diff --git` is content the author wrote.

    Both sides are read. `+++ b/...` names the file as it is after the change
    and is what an addition or an edit carries; a deletion writes
    `+++ /dev/null` and names the file only on `--- a/...`. The bytes of a
    deleted file are in the diff either way — every removed line of it — so a
    review of a deletion had the code in front of it, and reading the `+++`
    side alone recorded nothing.

    Paths are decoded with the same function the evidence layer uses: git
    escapes quotes, backslashes and control characters whatever
    `core.quotePath` says, and a path recorded in its escaped form is a path
    nothing will ever match.

    Deduplicated, because an ordinary edit names the same file on both header
    lines and an exposure is a fact about a file rather than a count of
    mentions.
    """
    found: List[str] = []
    in_hunk = False
    for line in (body or "").splitlines():
        if line.startswith("diff --git "):
            in_hunk = False
            continue
        if line.startswith("@@"):
            in_hunk = True
            continue
        if in_hunk:
            continue
        if line.startswith("--- ") or line.startswith("+++ "):
            path = _header_path(line)
            if path and path != "/dev/null":
                found.append(path)
    return list(dict.fromkeys(found))


_SEARCH_PATH = re.compile(r"^([^\s:][^:]*):\d+:", re.M)


def _paths_in_search(body: str) -> List[str]:
    """The files a search result quoted lines from."""
    return list(dict.fromkeys(_SEARCH_PATH.findall(body or "")))


def dispatch(ws: Workspace, session: Session, name: str, args: Dict[str, Any]) -> ToolResult:
    """Run one tool call, converting every failure into a usable tool result.

    A raised exception here would end the run; a returned error lets the agent
    correct a bad argument and continue, which is almost always what a wrong path
    or an invalid regex deserves.

    Every exit goes through `_budgeted`, including the error ones. They are not
    refused — an error result always reaches the model — but they are text in
    the conversation and were once the four ways out of this function that the
    estimate never saw.
    """
    handler = HANDLERS.get(name)
    if handler is None:
        return _budgeted(session, name, ToolResult(
            "No tool named {!r}. Available: {}.".format(name, ", ".join(sorted(HANDLERS))),
            "unknown tool {}".format(name),
            is_error=True,
        ))
    if not isinstance(args, dict):
        return _budgeted(session, name, ToolResult(
            "Tool input must be a JSON object.", "malformed input", is_error=True
        ))
    try:
        result = handler(ws, session, args)
    except WorkspaceError as exc:
        return _budgeted(session, name, ToolResult(
            str(exc), "error: {}".format(exc), is_error=True))
    except Exception as exc:  # last line of defence — never kill the run
        log.exception("tool %s raised", name)
        return _budgeted(session, name, ToolResult(
            "{} failed unexpectedly: {}: {}".format(name, type(exc).__name__, exc),
            "error: {}".format(type(exc).__name__),
            is_error=True,
        ))
    return _budgeted(session, name, result)


# Tools whose result is a decision, not a payload. They are tiny, and their
# handlers write to the session before the result is weighed — `finish_review`
# sets `finished`, `report_finding` appends a candidate. Refusing one for space
# would leave the session recording something the model was told did not happen.
# They are counted like everything else; they are simply never kept out.
ALWAYS_ADMITTED = frozenset({REPORT_FINDING, FINISH_REVIEW, SUBMIT_VERDICT})


def _budgeted(session: Session, name: str, result: ToolResult) -> ToolResult:
    """Count what this result costs, or keep it out if there is no room.

    The check is made *before* the content enters the conversation. Asking
    afterwards is the "one last huge tool call" problem: a 20k result admitted
    at 105k against a 110k ceiling does not stop at 110k, it lands at 125k, and
    the ceiling measured nothing.

    An error result is admitted whatever the budget says. It is small, and
    refusing the message that explains a bad argument would leave the model
    guessing at the very moment it needs to narrow its request. That does mean
    the estimate can pass `hard`: this is a ceiling on what is *fetched*, not a
    guarantee about the conversation, and the alternative — a review that cannot
    be told why its argument was wrong — is worse.

    A refused result records nothing on the session. `exposures` is how
    `gate._reviewed_nothing` tells a review that stopped early from one that
    never started, and content that was kept out of the conversation was not
    seen. Recording it here would have let a run refused everything it asked
    for claim the change had been read.
    """
    budget = session.context
    if not budget.bounded or result.is_error or name in ALWAYS_ADMITTED:
        budget.admit(name, result.content)
        result.apply(session)
        return result

    if not budget.enforcing:
        # Observing. The question "would this have been refused" is asked of an
        # imagined enforcing run rather than of this one, because this one
        # never refuses and so sails past the limit and stays there — after
        # which every later result reads as refused. The result itself goes to
        # the model unchanged, which is what makes the number worth having: it
        # is measured on a review the measurement did not alter.
        budget.shadow(result.content)
        budget.admit(name, result.content)
        result.apply(session)
        return result

    if budget.would_exceed(result.content):
        cost = budget.refuse(name, result.content, "would cross the hard limit")
        left = budget.remaining or 0
        # The refusal is a tool result rather than an exception so the model can
        # act on it, and it says what to do rather than only what happened.
        #
        # What it must not say is "finish with what you have". The first draft
        # did, and that is an instruction to conclude on less than the change —
        # from the one component whose whole purpose is to stop that happening
        # silently. It narrows, or it says the review is short.
        refusal = ToolResult(
            "This result is about {:,} estimated tokens and only about {:,} "
            "remain in the review's context budget, so it was not returned and "
            "none of it was seen. Narrow the request — a line range, a single "
            "file, a tighter pattern — and read it. Anything left unread makes "
            "this review incomplete, and it will be reported as incomplete."
            .format(cost, left),
            "{}: refused, {:,} tokens over budget".format(name, cost - left),
            is_error=True,
        )
        # The refusal itself is text in the conversation. Not counting it let a
        # run of repeated refusals grow the real context while the estimate
        # stood still.
        budget.admit(name + ":refusal", refusal.content)
        return refusal

    budget.admit(name, result.content)
    result.apply(session)
    hint = budget.hint()
    if hint:
        budget.admit(name + ":hint", hint)
        return ToolResult(result.content + hint, result.summary, result.is_error)
    return result


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
