"""Driving a review with the `claude` CLI, on the developer's own subscription.

Every review costs money on the Messages API, and this project's own rule
forbids paying for a small reason — so the mechanism for reviewing real changes
sat unused for days because no change was ever quite worth a bill. This runner
removes the bill for local work. CI stays on the API.

It is deliberately thin. The CLI is not a second provider with equal standing;
it is the tool the developer already installed, run as themselves, and the
artifact says `claude-cli` in plain sight so nothing is ever mistaken for a
review CI produced.

## Where the seam is

`SecurityAgent.run()` is not a wrapper around a model call. It owns the turn
ceiling, the wall clock, the truncation replay, the cache breakpoint, and the
allowlist that turns an unnamed stop reason into `error` rather than
`completed`. The CLI brings its own loop and exposes none of that, so this
replaces `run()` rather than slotting into it.

That is survivable because of one property: **everything that decides anything
accumulates in `Session`, through `dispatch()`, because every capability is a
tool.** The message history is not where the decision lives; the tool log is.
So the CLI drives the loop, our MCP server answers every tool call through the
same `dispatch()`, and the `Session` that comes back is the same object the API
path would have built. What the runner supplies on top is only the part that is
genuinely the provider's: how it stopped, and what it cost.

## The reviewed repository is not a place to run a client in

The CLI skips its workspace-trust dialog in non-interactive mode. Running it
inside the checkout would put `.claude/settings.json`, `CLAUDE.md`, hooks,
skills and plugins — all files the author of the change under review can edit —
into the session as a second instruction channel, underneath our prompt
contract and invisible to it. The whole product rests on repository content
being data rather than instruction, and that would break it before the first
token.

So the CLI runs in an empty temporary directory and never sees the repository
at all. The repository is read only by the MCP server, a different process,
pointed at it explicitly. This is not a setting that can be misconfigured; it
is the absence of a path.
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
import shutil
import signal
import subprocess
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from .agent import _provenance
from .budget import STOPPED_TOOL_CALLS, Allowance, RunBudget
from .config import Config
from .crash_journal import read_trace, render_trace
from .models import (
    STOP_BUDGET,
    STOP_COMPLETED,
    STOP_ERROR,
    STOP_TIME_LIMIT,
    STOP_TRANSPORT,
    Revision,
    ScanOutcome,
)
from .session_document import SessionDocumentError, read_session
from .tools import Session
from .workspace import Workspace

log = logging.getLogger(__name__)

PROVIDER = "claude-cli"

# The MCP server's name in the config we write. It prefixes every tool name the
# CLI sees, which is how `--allowedTools` can name ours and only ours.
SERVER_KEY = "security_agent"
TOOL_PREFIX = "mcp__{}__".format(SERVER_KEY)

# Every built-in the CLI ships that could read, write or run anything. Named
# rather than relying on `--allowedTools` alone: an allowlist says what is
# permitted and a denylist says what is refused, and the two disagree exactly
# when a new built-in appears that nobody added to either. Refusing by name
# means a tool added upstream is not silently available; refusing by omission
# means it is.
DENIED_TOOLS: Tuple[str, ...] = (
    "Bash", "Edit", "Write", "NotebookEdit", "Read", "Glob", "Grep",
    "WebFetch", "WebSearch", "Task", "TodoWrite", "KillShell", "BashOutput",
    "SlashCommand", "ExitPlanMode",
)

# What the CLI's terminal JSON can say, and what each means to us. An allowlist
# with `error` as the default, for the reason the API path has one: a response
# whose ending nobody named was once treated as a completed review, and a
# provider that owns its own loop will invent new endings without asking.
_SUBTYPES = {
    "success": STOP_COMPLETED,
    "error_max_turns": STOP_ERROR,
    "error_during_execution": STOP_ERROR,
}


class RunnerError(Exception):
    """The runner could not produce a review. Never a verdict about the code."""


def cli_available(executable: str = "claude") -> Optional[str]:
    """The path to the CLI, or `None`. Never raises, never guesses."""
    return shutil.which(executable)


def build_command(
    *,
    executable: str,
    system_prompt: str,
    mcp_config: Path,
    model: str = "",
) -> List[str]:
    """The exact argument list, built where a test can read it.

    Separate from launching so the confinement can be asserted without a
    subprocess. Every flag here is load-bearing:

    * `--print` with `--output-format json` — one terminal object to parse
      instead of a transcript to scrape.
    * `--mcp-config` **and** `--strict-mcp-config` — ours are loaded and every
      other MCP server configured on this machine is ignored. Without the
      second flag the developer's own servers join the session, which is a set
      of tools our prompt never described.
    * `--allowedTools` naming only our prefix, and `--disallowedTools` naming
      every built-in. Two statements of one intention, because they fail
      differently: a built-in added upstream is outside the allowlist and would
      also be outside a denylist nobody updated — the allowlist is what catches
      it, and the denylist is what makes the intention legible.
    * `--system-prompt` replaces rather than appends, which also removes the
      dynamic sections the CLI would otherwise add — memory paths among them.
      `--append-system-prompt` would leave the default contract underneath ours
      and put two sets of instructions in front of the model.
    * `--no-session-persistence` — a security review is not a conversation to
      resume, and a transcript of one on disk is a copy of the reviewed code
      nobody asked for.
    """
    command = [
        executable,
        "--print",
        "--output-format", "json",
        "--mcp-config", str(mcp_config),
        "--strict-mcp-config",
        "--allowedTools", TOOL_PREFIX + "*",
        "--disallowedTools", *DENIED_TOOLS,
        "--permission-mode", "manual",
        "--system-prompt", system_prompt,
        "--no-session-persistence",
    ]
    if model:
        command += ["--model", model]
    return command


def build_mcp_config(
    *,
    repo: Path,
    base_sha: str,
    head_sha: str,
    tool_set: str,
    allowance: Allowance,
    handoff: "Handoff",
    scope: Sequence[str] = (),
    python: str = "",
) -> Dict[str, Any]:
    """The MCP config the CLI is handed: one server, ours, with its budget."""
    arguments = [
        "-m", "security_agent.mcp_server",
        "--repo", str(repo),
        "--head", head_sha,
        "--tools", tool_set,
        "--max-tool-calls", str(allowance.ceiling),
        "--run-id", handoff.run_id,
        "--session-document", str(handoff.session_document),
        "--crash-journal", str(handoff.crash_journal),
        "--spend-report", str(handoff.spend_report),
        "--base-sha", base_sha,
        "--head-sha", head_sha,
        "--config-digest", handoff.config_digest,
    ]
    if base_sha:
        arguments += ["--base", base_sha]
    for pattern in scope:
        arguments += ["--path", pattern]

    return {
        "mcpServers": {
            SERVER_KEY: {
                "command": python or _python(),
                "args": arguments,
                # The child imports this package, and the CLI's cwd is an empty
                # directory that has never heard of it.
                "env": {"PYTHONPATH": _package_root(), **_inherited_env()},
            }
        }
    }


class Handoff:
    """The files one review uses to get its state out of the child process.

    All of them live in a directory this process makes and owns. Not in the
    repository: the reviewed tree is writable by whoever opened the change, and
    a document the review reads back must not be a document the review's subject
    could have written.
    """

    def __init__(self, root: Path, run_id: str, config_digest: str) -> None:
        self.root = Path(root)
        self.run_id = run_id
        self.config_digest = config_digest
        self.session_document = self.root / "session.json"
        self.crash_journal = self.root / "crash.jsonl"
        self.spend_report = self.root / "spend.json"
        self.mcp_config = self.root / "mcp.json"
        # Where the CLI itself runs. Empty, and outside the checkout, so no
        # `.claude` directory, `CLAUDE.md`, hook or plugin belonging to the
        # reviewed repository is ever in scope.
        self.cwd = self.root / "cwd"
        self.cwd.mkdir(parents=True, exist_ok=True)

    def spend(self) -> Dict[str, Any]:
        """What the child reported spending, or `{}` if it never said.

        The whole record, not one key. Reading only `spent` left
        `refused_for_budget` on the floor — the child computed that its review
        had been cut short, wrote it down, exited 2 about it, and the parent
        looked past all three. A run that hit its ceiling then rendered as a
        completed review with no findings.
        """
        try:
            payload = json.loads(self.spend_report.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}
        return payload if isinstance(payload, dict) else {}

    def spent_tool_calls(self) -> Optional[int]:
        report = self.spend()
        try:
            return int(report["spent"])
        except (KeyError, TypeError, ValueError):
            return None

    def refused_for_budget(self) -> bool:
        return self.spend().get("refused_for_budget") is True


class ClaudeCodeRunner:
    """One review, driven by the CLI, answered by our tools."""

    def __init__(
        self,
        cfg: Config,
        workspace: Workspace,
        budget: RunBudget,
        *,
        executable: str = "claude",
        config_digest: str = "",
    ) -> None:
        self.cfg = cfg
        self.ws = workspace
        self.budget = budget
        self.executable = executable
        self.config_digest = config_digest
        self.run_id = uuid.uuid4().hex[:16]
        # Set only when a run leaves no session document. Held here rather than
        # returned alongside the stop reason because it is not part of "how did
        # this end" — it is a document for a person, and the report renders it
        # knowingly instead of guessing what kind of string it has.
        self.trace_markdown = ""

    # ------------------------------------------------------------------ run

    def run(self, mode: str, briefing: str, revision: Revision) -> ScanOutcome:
        """Drive one review to an outcome. Never raises for a review that failed.

        A failure to *review* is an outcome with a stop reason, because that is
        what the gate knows how to refuse. A failure to *start* is an exception,
        because there is nothing to report about code nobody looked at.
        """
        path = cli_available(self.executable)
        if path is None:
            raise RunnerError(
                "the `{}` command is not on PATH. This runner exists to use the "
                "CLI you already have; it will not fall back to the paid API, "
                "because which account is charged is not a decision to make on "
                "somebody's behalf.".format(self.executable))

        root = Path(tempfile.mkdtemp(prefix="security-review-"))
        handoff = Handoff(root, self.run_id, self.config_digest)
        try:
            return self._run_in(handoff, path, mode, briefing, revision)
        finally:
            # The crash trace has already been read into the outcome by now.
            shutil.rmtree(root, ignore_errors=True)

    def _run_in(
        self,
        handoff: Handoff,
        executable: str,
        mode: str,
        briefing: str,
        revision: Revision,
    ) -> ScanOutcome:
        handoff.mcp_config.write_text(json.dumps(build_mcp_config(
            repo=self.ws.root,
            base_sha=revision.base_sha,
            # Not `or "HEAD"`. The child stamps the document with what it is
            # given and the parent checks the document against `revision`, so a
            # substitution here makes the two disagree by construction: the
            # document says `HEAD` and the check is given `""`, and every such
            # review is refused as describing different code. The child already
            # defaults its own `--head`.
            head_sha=revision.head_sha,
            tool_set="reviewer",
            allowance=self.budget.review,
            handoff=handoff,
            scope=self.cfg.scope,
        ), indent=2), encoding="utf-8")

        command = build_command(
            executable=executable,
            system_prompt=(self.cfg.resolved_prompt_dir() / "system.md").read_text(
                encoding="utf-8"),
            mcp_config=handoff.mcp_config,
            model=self.cfg.model,
        )

        outcome = ScanOutcome(mode=mode, model=self.cfg.model)
        outcome.revision = revision
        # What produced this verdict. Left unset, every CLI artifact recorded an
        # empty provenance — and `identity` is computed from it, so the key
        # `--reuse` matches on and the key `baseline.py` refuses a comparison
        # across were both blank. Two runs of different prompts against
        # different code would have shared an identity.
        outcome.provenance = _provenance(self.cfg)
        outcome.provenance.note_served(self.cfg.model)
        started = time.monotonic()
        result = self._launch(command, briefing, handoff)

        session, stop_reason, stop_detail = self._collect(handoff, result, revision)
        if session is not None:
            _apply_session(outcome, session)

        outcome.stop_reason = stop_reason
        outcome.stop_detail = stop_detail
        outcome.trace_markdown = self.trace_markdown
        log.info("claude-cli finished in %.0fs: %s", time.monotonic() - started,
                 stop_reason)
        return outcome

    # -------------------------------------------------------------- process

    def _launch(self, command: List[str], briefing: str,
                handoff: "Handoff") -> "CliResult":
        """Run the CLI, bounded by the run's own clock.

        The wall clock is enforced here because this process holds the handle
        and the CLI has no ceiling of its own — there is no `--max-turns`. The
        other ceiling, tool calls, is enforced in the child, which is the only
        place that can see them.
        """
        remaining = max(1.0, self.budget.profile.runtime_seconds - self.budget.elapsed)
        return launch(command, stdin=briefing, cwd=handoff.cwd,
                      timeout=remaining,
                      limit_seconds=self.budget.profile.runtime_seconds)

    def _collect(
        self, handoff: Handoff, result: "CliResult", revision: Revision
    ) -> Tuple[Optional[Session], str, str]:
        """The session, and how the run ended, from two independent statements.

        The CLI's own ending is not sufficient on its own. Its process exits
        zero whether the review finished or the harness gave up, so a run counts
        as complete only when the CLI ended cleanly **and** our session document
        exists and says the reviewer signed off. Either half missing is exit 2.
        """
        spent = handoff.spent_tool_calls()
        if spent is not None:
            for _ in range(spent):
                self.budget.review.note_tool_call()

        # No grace period after a kill. The wait is for a rename already in
        # flight from a process that is shutting down cleanly; a process this
        # parent has just signalled is not writing anything, and waiting on it
        # would only make a failed review slow as well as failed.
        grace = 0.0 if result.killed else DOCUMENT_GRACE_SECONDS
        if not _wait_for(handoff.session_document, grace):
            # Nothing authoritative. Whatever the CLI said about itself, the
            # child never reached the end — so the crash journal is the whole
            # story, and it is diagnostics rather than findings.
            detail, trace = _crash_detail(handoff, result)
            self.trace_markdown = trace
            return None, _killed_reason(result), detail

        try:
            session = read_session(
                handoff.session_document,
                run_id=self.run_id,
                revision=revision,
                config_digest=self.config_digest,
            )
        except SessionDocumentError as exc:
            # A document that exists and cannot be trusted is worse than none:
            # it is the shape of an answer. Refused, and named.
            return None, STOP_ERROR, (
                "the review wrote a session document this run cannot accept: "
                "{}".format(exc))

        if result.killed or result.failed:
            # The document is there and the process still did not end cleanly.
            # The findings in it are real, and the review is not finished.
            #
            # The trace comes too, now that the child hands over as it goes: the
            # document says what was established and the journal says what was
            # in flight when the kill landed — a call that started and never
            # reported back is visible in one and invisible in the other.
            trace = read_trace(handoff.crash_journal)
            if trace.present:
                self.trace_markdown = render_trace(trace)
            return session, _killed_reason(result), result.detail

        if result.returncode != 0:
            # It said success and exited non-zero. Believing the JSON over the
            # exit code is the permissive reading of a contradiction, which is
            # the one that ships.
            return session, STOP_ERROR, (
                "the CLI reported {!r} and exited {}. A process that failed and "
                "still printed a success object has not agreed with itself, and "
                "this runner does not choose the reassuring half.".format(
                    result.subtype or "(no subtype)", result.returncode))

        stop = _SUBTYPES.get(result.subtype, STOP_ERROR)
        if stop != STOP_COMPLETED:
            return session, stop, result.detail or _unnamed(result.subtype)

        # The CLI says it finished. Two of our own statements can still say the
        # review did not, and both were being ignored.
        #
        # The child refused a tool call for budget. It recorded that, wrote it
        # to the spend report, and exited 2 about it — and the parent read one
        # key from that file and none of the rest. A hostile change large enough
        # to burn the allowance before the reviewer reaches the vulnerable code
        # then rendered as a completed review with no findings, which is the
        # exact outcome `budget.py` says three times must never happen.
        if handoff.refused_for_budget():
            self.budget.stopped_by = STOPPED_TOOL_CALLS
            return session, STOP_BUDGET, (
                "the review ran out of tool calls ({} allowed) before it "
                "finished looking. Raise the profile for a complete review — "
                "this is not a statement about the code.".format(
                    self.budget.review.ceiling))

        # And the reviewer never signed off. On the Messages API path this is
        # recorded and not gated, because `end_turn` is the model choosing to
        # stop and is a real signal. Here there is no `end_turn`: the process
        # exits zero whether the review finished or the harness gave up, so
        # `finish_review` is the only statement that exists. A session with no
        # sign-off — no tool calls made at all, an `--allowedTools` pattern that
        # matched nothing, a handshake the child lost — wrote an empty document
        # and came out as a green tick.
        if not session.finished:
            return session, STOP_ERROR, (
                "the review never called `finish_review`, so nothing states "
                "that it finished rather than stopped. On this runner that is "
                "the only signal there is: the process exits zero either way.")

        return session, STOP_COMPLETED, ""


def launch(
    command: List[str],
    *,
    stdin: str,
    cwd: Path,
    timeout: float,
    limit_seconds: int,
) -> "CliResult":
    """Run the CLI to completion, or kill its whole process tree.

    A process group, not `subprocess.run(timeout=...)`. That kills the `claude`
    process and nothing it started — and what it started is our MCP server,
    which holds the hostile checkout open and goes on running `git` against it
    after the parent has moved on, races the parent for the session and spend
    files, and can still be writing into the handoff directory while the parent
    deletes it. The wall clock is the one ceiling this runner can actually
    enforce; enforcing it on the parent alone enforces nothing.

    Shared by the reviewer and the verifier because they differed only in the
    wording of two messages, and a launch that killed a tree in one place and a
    process in the other would be the kind of divergence nobody looks for.
    """
    try:
        process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=str(cwd),
            env=_child_env(),
            # Its own process group, so one signal reaches every descendant.
            start_new_session=True,
        )
    except OSError as exc:
        return CliResult(failed=True, stop=STOP_TRANSPORT, detail=(
            "the CLI could not be run: {}".format(exc)))

    try:
        out, err = process.communicate(stdin, timeout=timeout)
    except subprocess.TimeoutExpired:
        _kill_tree(process)
        # Drained after the kill so the pipes close and nothing is left
        # blocking on a full buffer. Whatever arrived is diagnostics only.
        with contextlib.suppress(subprocess.TimeoutExpired, ValueError, OSError):
            process.communicate(timeout=10)
        return CliResult(killed=True, stop=STOP_TIME_LIMIT, detail=(
            "the review was stopped after {}s (the profile's time limit)"
            .format(limit_seconds)))

    return _parse_terminal(process.returncode, out, err)


def _kill_tree(process: "subprocess.Popen") -> None:
    """Signal the whole group, then make sure the direct child is gone.

    `killpg` can fail — the group may already be empty, or the platform may not
    have it — and a failure there must not leave the parent believing it killed
    something it did not. So the direct child is killed either way.
    """
    try:
        os.killpg(os.getpgid(process.pid), signal.SIGKILL)
    except (OSError, AttributeError):
        log.warning("could not signal the process group; killing the child only")
    with contextlib.suppress(OSError):
        process.kill()



class CliResult:
    """What the CLI said about its own ending, before we judge it."""

    def __init__(
        self,
        subtype: str = "",
        detail: str = "",
        killed: bool = False,
        failed: bool = False,
        stop: str = "",
        returncode: int = 0,
        usage: Optional[Dict[str, Any]] = None,
        payload: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.subtype = subtype
        self.detail = detail
        self.killed = killed
        self.failed = failed
        # The named ending this result already implies, decided where the
        # failure was observed. Deriving it later from `killed`/`failed` meant
        # one flag covering two different endings — a process that could not be
        # started and a process that answered unusably — and the caller then had
        # to guess which. It guessed wrong.
        self.stop = stop
        # Kept, because it was being thrown away. `_parse_terminal` consulted
        # the exit code only when the output was empty or unparseable, so a
        # process that failed and still printed a well-formed `"success"`
        # object was believed — and with a session document present, that is a
        # completed review. The provider's two statements about itself have to
        # agree before either is taken at face value.
        self.returncode = returncode
        self.usage = usage or {}
        # Kept whole for the artifact's telemetry half. Never read to decide.
        self.payload = payload or {}


def _parse_terminal(returncode: int, stdout: str, stderr: str) -> CliResult:
    """Read the CLI's terminal JSON, refusing to guess at anything.

    Three separate failures wear the same face on this transport — a crash, a
    malformed document, and a review that found nothing — so each gets its own
    named ending rather than falling through to the last branch.
    """
    text = (stdout or "").strip()
    if not text:
        return CliResult(failed=True, stop=STOP_TRANSPORT, detail=(
            "the CLI produced no output (exit {}){}".format(
                returncode, _tail(stderr))))

    try:
        payload = json.loads(text)
    except ValueError:
        # Deliberately not "search the output for a JSON object". Making the
        # input less parseable must never make the result more permissive, and
        # scavenging a fragment out of a corrupted stream is exactly that.
        return CliResult(failed=True, stop=STOP_ERROR, detail=(
            "the CLI's output was not the JSON document `--output-format json` "
            "promises (exit {}){}".format(returncode, _tail(stderr))))

    if not isinstance(payload, dict):
        return CliResult(failed=True, stop=STOP_ERROR, detail=(
            "the CLI's output was a {}, not an object".format(
                type(payload).__name__)))

    subtype = str(payload.get("subtype") or "")
    if payload.get("is_error") is True and subtype in _SUBTYPES:
        # It said `success` and also said it errored. Believe the error: the
        # permissive reading of a contradiction is the one that ships.
        subtype = ""

    return CliResult(
        subtype=subtype,
        returncode=returncode,
        detail=str(payload.get("result") or "") if payload.get("is_error") else "",
        usage=payload.get("usage") if isinstance(payload.get("usage"), dict) else {},
        payload=payload,
    )


# How long the parent waits for the child's document after the CLI has exited.
#
# The child writes it when its own stdin closes, which happens as the CLI shuts
# down — so the parent asking the instant `claude` exits asks a moment too
# early. That race made every run report "ended without writing its session
# document" over a review that had made twenty-one tool calls and claimed two
# findings: the work was done, the handoff was not, and the artifact said the
# process had died.
#
# Bounded, and short. Waiting is for a write already in flight; a child that
# genuinely died will never write, and turning that into a long pause would
# make a failed review slow as well as failed.
DOCUMENT_GRACE_SECONDS = 10.0


def _wait_for(path: Path, seconds: float = DOCUMENT_GRACE_SECONDS) -> bool:
    """Is the document there, allowing for a write that has not landed yet?

    `write_session` renames into place, so the file appears whole or not at
    all — there is no half-written state to observe, and polling for existence
    is enough.
    """
    deadline = time.monotonic() + seconds
    while True:
        if path.exists():
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.1)


def _killed_reason(result: CliResult) -> str:
    return result.stop or STOP_ERROR


def _unnamed(subtype: str) -> str:
    if subtype in _SUBTYPES:
        return ""
    return (
        "the CLI ended with subtype {!r}, which this runner does not recognise. "
        "Treated as a failure rather than a completed review — an ending nobody "
        "named is not an ending anybody checked.".format(subtype or "(absent)"))


def _crash_detail(handoff: Handoff, result: CliResult) -> Tuple[str, str]:
    """(the sentence, the rendered trace) for a run that left no document.

    Two values rather than one string, because the report has to treat them
    differently: the sentence is prose from a provider and is escaped, the
    trace is a document this project rendered and is not. Returning them joined
    made the report decide which it was holding by counting newlines.
    """
    # Returned raw. It is a `stop_detail`, and the report escapes every one of
    # those — which is the right place, because that rule then holds for both
    # runners rather than for whichever one remembered.
    lead = result.detail or (
        "the review process ended without writing its session document")
    trace = read_trace(handoff.crash_journal)
    if not trace.present:
        return (lead + ". No crash journal was written either, so nothing is "
                       "known about how far it got."), ""
    return lead + ".", render_trace(trace)


def _apply_session(outcome: ScanOutcome, session: Session) -> None:
    """Fold the child's session into the outcome, exactly as the API path does."""
    outcome.reported = list(session.candidates)
    outcome.rejected_claims = list(session.rejected)
    outcome.tool_calls = list(session.tool_calls)
    outcome.files_examined = list(session.files_examined)
    outcome.coverage.examined = list(session.files_examined)
    outcome.metrics = session.metrics
    outcome.duplicates_dropped = session.duplicates_dropped
    outcome.turns = session.turn
    outcome.finished_explicitly = session.finished
    outcome.unresolved = list(session.unresolved)
    outcome.summary = session.final_summary


# --------------------------------------------------------------- environment


def _package_root() -> str:
    """Where `security_agent` lives, so the child can import it."""
    return str(Path(__file__).resolve().parents[1])


def _python() -> str:
    import sys

    return sys.executable


def _inherited_env() -> Dict[str, str]:
    """The few variables a child genuinely needs, and nothing else.

    An allowlist because the child runs `git`, and passing the whole environment
    would carry credentials, tokens and CI variables into a process that has no
    use for any of them.
    """
    keep = ("PATH", "HOME", "LANG", "LC_ALL", "TMPDIR", "SYSTEMROOT")
    return {name: os.environ[name] for name in keep if name in os.environ}


def _child_env() -> Dict[str, str]:
    """The environment the CLI itself runs in.

    Deliberately not stripped down to nothing: the CLI needs its own
    configuration and credentials to run as the developer at all, and taking
    those away would be the "custom login" this design refuses to build. What
    is removed is the API key, so a session that could not authenticate as the
    subscription cannot quietly bill an account instead.
    """
    env = dict(os.environ)
    for name in ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN"):
        env.pop(name, None)
    return env


def _tail(stderr: str, limit: int = 400) -> str:
    text = (stderr or "").strip()
    if not text:
        return ""
    if len(text) > limit:
        text = "…" + text[-limit:]
    return ". Its error output ended: {}".format(text)
