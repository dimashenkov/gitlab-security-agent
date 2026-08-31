"""Driving a review with the `claude` CLI, under the login it already has.

Every review costs money on the Messages API, and this project's own rule
forbids paying for a small reason — so the mechanism for reviewing real changes
sat unused for days because no change was ever quite worth a bill. This runner
moves local work off the API key and onto the CLI the developer already has.
What that costs them depends on how that CLI is authenticated, which is asked
and recorded rather than assumed. CI stays on the API.

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
from dataclasses import dataclass
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
    STOP_INCONCLUSIVE,
    STOP_TIME_LIMIT,
    STOP_TRANSPORT,
    Revision,
    ScanOutcome,
    Usage,
)
from .session_document import SessionDocumentError, read_session
from .tools import Session
from .workspace import Workspace, inventory_notes

log = logging.getLogger(__name__)

PROVIDER = "claude-cli"

# The MCP server's name in the config we write. It prefixes every tool name the
# CLI sees, which is how `--allowedTools` can name ours and only ours.
SERVER_KEY = "security_agent"
TOOL_PREFIX = "mcp__{}__".format(SERVER_KEY)

# What `--tools` is given so the CLI ships no built-in tools into the session.
# Its own help: "Use \"\" to disable all tools, \"default\" to use all tools, or
# specify tool names". Named rather than written inline so that a test can
# assert on the same value the runner passes, and so that changing it is a
# visible edit rather than a deleted pair of quotation marks.
NO_BUILTIN_TOOLS = ""

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


# How long `claude auth status` may take before the answer is "cannot tell".
# It is a local read of stored credentials, so a second is generous; the point
# of the ceiling is that a preflight which hangs turns "is this authenticated"
# into "this review never starts", which is a worse failure than the one it
# came to prevent.
AUTH_TIMEOUT = 10.0

AUTH_OK = "authenticated"
AUTH_MISSING = "not-authenticated"
AUTH_UNKNOWN = "unknown"


@dataclass(frozen=True)
class Authentication:
    """What `claude auth status` said, reduced to what may be acted on.

    Four fields and no more. The command also returns the account's email
    address and its organisation id, and neither is anything this program needs
    to decide whether to run — so neither is read, kept, logged or written into
    an artifact. A field that is never held cannot leak from a report.
    """

    state: str = AUTH_UNKNOWN
    # `claude.ai` for a subscription login, `api-key`/`console` for a billed
    # one. Empty when the CLI did not say.
    method: str = ""
    # `max`, `pro`, and empty when there is none — which is the case that
    # distinguishes a subscription from an account billed per request.
    subscription: str = ""
    detail: str = ""

    @property
    def subscription_backed(self) -> bool:
        """Established, rather than inferred from the absence of an API key.

        Stripping `ANTHROPIC_API_KEY` from the child proves the child cannot
        reach for the parent's key. It proves nothing about how the CLI's own
        stored login is billed, and the difference is the whole of what this
        program is allowed to claim about cost.
        """
        return self.method == "claude.ai" and bool(self.subscription)


def authentication(executable: str = "claude",
                   timeout: float = AUTH_TIMEOUT) -> Authentication:
    """Ask the CLI whether it is logged in, before a review is started.

    Three answers, not two, and the third is the point: an older CLI without
    this subcommand, output that will not parse, or a call that timed out are
    all `unknown`. Refusing to run on `unknown` would make a working
    installation unusable on the strength of a guess about its version, and
    treating `unknown` as authenticated would make the check decoration. It is
    reported as what it is and the run continues.

    Never raises. A preflight that can throw is a new way for a review to fail.
    """
    if cli_available(executable) is None:
        return Authentication(state=AUTH_MISSING,
                              detail="`{}` is not on PATH".format(executable))
    try:
        proc = subprocess.run(
            [executable, "auth", "status"],
            capture_output=True, text=True, timeout=timeout, check=False,
            # The parent's key must not decide the answer: with it set, a CLI
            # that would otherwise report a subscription can report an API
            # login, and this program would then refuse the very run it exists
            # to make free.
            env=_child_env(),
        )
    except subprocess.TimeoutExpired:
        return Authentication(
            state=AUTH_UNKNOWN,
            detail="`{} auth status` did not answer within {:.0f}s".format(
                executable, timeout))
    except OSError as exc:
        return Authentication(state=AUTH_UNKNOWN,
                              detail="could not run `{} auth status`: {}".format(
                                  executable, exc))

    try:
        payload = json.loads(proc.stdout or "")
    except json.JSONDecodeError:
        # An older CLI prints prose here, or nothing. Not a failure to
        # authenticate — a failure to ask, which is a different sentence.
        return Authentication(
            state=AUTH_UNKNOWN,
            detail="`{} auth status` did not answer in JSON".format(executable))
    if not isinstance(payload, dict):
        return Authentication(
            state=AUTH_UNKNOWN,
            detail="`{} auth status` answered with {}".format(
                executable, type(payload).__name__))

    if "loggedIn" not in payload:
        # A JSON object of some other shape — an older CLI, or a newer one that
        # renamed the field. Not a logout: the question was never answered.
        # Reading a missing key as `False` is the absent-versus-zero confusion
        # this project refuses everywhere else, and here it would refuse to run
        # on a machine that is perfectly well logged in.
        return Authentication(
            state=AUTH_UNKNOWN,
            detail="`{} auth status` did not say whether it is logged "
                   "in".format(executable))
    if payload["loggedIn"] is not True:
        return Authentication(state=AUTH_MISSING,
                              detail="`{} auth status` reports no login".format(
                                  executable))
    return Authentication(
        state=AUTH_OK,
        method=str(payload.get("authMethod") or ""),
        subscription=str(payload.get("subscriptionType") or ""),
    )


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
    * `--tools ""` — the built-in set is not present at all. This is the
      boundary; the two lists below are defence in depth. An allowlist says
      what may be used and a denylist says what may not, and both leave the
      tool existing and reachable by anything that can get past a permission
      check. `--tools ""` is documented by the CLI itself as disabling all
      tools, and it selects from the *built-in* set only, so ours survive: a
      one-tool MCP server returning a nonce the model cannot invent answered
      with that nonce both with the flag and without it, on 2026-08-28. It was
      checked rather than reasoned about because being wrong means every
      review runs with no tools at all and reports nothing found — a clean
      sheet produced by a review that could not look.

      It is placed so the token after it begins with `-`. The option is
      variadic, so it consumes arguments until the next flag, and putting a
      bare value after it would hand that value to `--tools` instead.

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
        # The next element must begin with `-`. See the docstring: `--tools` is
        # variadic and would otherwise eat it.
        "--tools", NO_BUILTIN_TOOLS,
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
    context_lines: int = 12,
    max_context_tokens: int = 0,
    max_context_soft_tokens: int = 0,
    max_context_mode: str = "observe",
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
        # Passed rather than left to the inherited environment. The child
        # would read the same variable, and a setting that works on one
        # path because of an env var and on the other because of an
        # argument is a setting that will one day work on neither.
        "--context-lines", str(context_lines),
        # The same reasoning, and the more important case: the tool results land
        # in the child, so the child is the only process that can refuse one.
        # A budget configured on the parent and not passed here would be a
        # setting that reads as enforced and enforces nothing.
        "--max-context", str(max_context_tokens),
        "--max-context-soft", str(max_context_soft_tokens),
        "--max-context-mode", max_context_mode,
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
            context_lines=self.ws.default_context_lines,
            max_context_tokens=self.cfg.max_context_tokens,
            max_context_soft_tokens=self.cfg.max_context_soft_tokens,
            max_context_mode=self.cfg.max_context_mode,
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
        outcome.provenance.provider = PROVIDER
        # What the CLI said about its own login, so the report can state the
        # billing that was established rather than the one that was assumed.
        # Asked once here rather than per verifier session: it is the same
        # answer for every process this run starts, and a preflight repeated
        # per session is a preflight that costs more than it checks.
        #
        # And acted on. `cli.py` asks the same question earlier and refuses a
        # definite no, but this class is also constructed directly — by the
        # corpus runner and by tests — and a login that ended between the two
        # calls is a launch nobody would have wanted. Reading the answer for
        # the report and not for the decision is the shape of a check that
        # exists and does nothing.
        auth = authentication(self.executable)
        if auth.state == AUTH_MISSING:
            raise RunnerError(
                "the `claude` CLI is not logged in ({}). Run `claude auth "
                "login`. This runner will not fall back to the paid API, "
                "because which account is charged is not a decision to make "
                "on somebody's behalf.".format(auth.detail))
        outcome.provenance.auth_method = auth.method
        outcome.provenance.auth_subscription = auth.subscription
        outcome.provenance.note_served(self.cfg.model)
        started = time.monotonic()
        result = self._launch(command, briefing, handoff)

        # What the CLI priced the run at, recorded and not interpreted. The
        # terminal object carries `total_cost_usd` on a subscription too — a
        # two-token reply on a Max plan came back as $0.29 — so it is what the
        # run *would* have cost, and reading it as a bill would mark every
        # subscription run as billed. The billed question is the auth method's.
        cost = result.payload.get("total_cost_usd")
        if isinstance(cost, (int, float)):
            outcome.provenance.reported_cost_usd = float(cost)

        # What it says it used. Parsed for a fortnight and read by nobody, so
        # every run through this runner wrote five zeros where the truth was
        # "this runner reported nothing" — the project's own absent-is-not-zero
        # rule broken inside the record that rule is about.
        #
        # Assigned rather than merged: this is the review stage's usage, and it
        # arrives once, whole, at the end of the run. `total_usage` still notes
        # a gap for any stage that ran without reporting, so a block the CLI
        # did not send, or sent in a shape `from_provider` will not read, ends
        # up as an admitted absence rather than a zero.
        outcome.usage = result.reported_usage

        session, stop_reason, stop_detail = self._collect(handoff, result, revision)
        if session is not None:
            _apply_session(outcome, session)

        # What the change contained is the parent's own knowledge — it holds
        # the workspace — and it is filled whether or not a session came back,
        # because a killed run still has a change it was asked about. Without
        # it the report could not say how much of the change had been opened,
        # on the one runner whose reviews are the ones being read.
        if mode == "diff" and self.ws.diff_base:
            outcome.coverage.changed = [p for p, _ in self.ws.changed_files()]
            (outcome.coverage.unreadable,
             outcome.coverage.deleted) = inventory_notes(self.ws)
            if self.ws.scope:
                outcome.coverage.out_of_scope = self.ws.out_of_scope(
                    [p for p, _ in self.ws.all_changed_files()])

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

        if not self.budget.profile.conclusive:
            # The last thing checked, and it overrides everything above it. The
            # review may have run perfectly, signed off and found nothing — and
            # this profile is still not allowed to say so, because it was sized
            # to stop early and usually does. `conclusive` was a flag nothing
            # read; it is a stop reason now, so the gate cannot miss it.
            return session, STOP_INCONCLUSIVE, (
                "the `{}` profile is not allowed to conclude a review. It ran "
                "to the end and what it reports are leads; run a profile that "
                "can conclude before treating this as an answer."
                .format(self.budget.profile.name))

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
        # Parsed off the terminal object and read by nobody. This is why every
        # one of the 38 member runs in `measurements/cli-batch-*.json` recorded
        # five zeros for `usage`: nothing here ever reaches `ScanOutcome.usage`,
        # and the Messages API path — which does, since the first commit — is
        # the only reason the field ever holds a figure. (Those runs are
        # attributed to this runner by their filenames and by the commits that
        # added them; only four of the 38 carry `provenance.provider`, which
        # postdates the rest, so the artifacts alone do not establish it.)
        #
        # Now wired, on evidence rather than on a guess. The names were read
        # off this binary's own session transcripts under
        # `~/.claude/projects/` — 1729 usage blocks, all of them the Messages
        # API spelling, not the camelCase of the neighbouring `modelUsage`.
        #
        # `Usage.from_provider` still takes all four or none. What the
        # transcripts establish is what the CLI writes *there*; the terminal
        # object this parses is a different document by the same program, and
        # "very probably the same shape" is not the same as read. If it is not,
        # the block fails the check and the artifact says "not reported" —
        # which is what it said before this change, so the worst case here is
        # the status quo and never an understated figure.
        self.usage = usage or {}
        self.reported_usage = Usage.from_provider(usage)
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
    # What actually reached the model, which is what the gate reads to
    # tell a review that stopped early from one that never started.
    outcome.exposures = list(session.exposures)
    outcome.coverage.examined = list(session.files_examined)
    outcome.metrics = session.metrics
    outcome.duplicates_dropped = session.duplicates_dropped
    outcome.turns = session.turn
    outcome.finished_explicitly = session.finished
    outcome.unresolved = list(session.unresolved)
    outcome.summary = session.final_summary
    # The coverage accounting, which was entirely empty on this runner: the
    # report's "N of M changed file(s) opened" line simply did not render, and
    # the gate never learned that a change had been shown to the reviewer only
    # in part.
    #
    # `diff_truncated` has to travel with the session because `get_diff` runs
    # in the child, against a different `Workspace` — the parent's own flag is
    # always False here. The other two are the parent's own knowledge and are
    # filled by the caller, which holds the workspace.
    outcome.coverage.diff_truncated = session.diff_truncated
    # The same reasoning, and the same journey: a result the budget kept out was
    # kept out in the child, and this is the only record of it that survives.
    outcome.coverage.context_refusals = session.context.refused_results
    outcome.coverage.context_would_refuse = session.context.would_refuse_results
    # And the same again for the one fact the completeness rule will rest on.
    # The child is where `get_diff` ran and where the budget decided whether its
    # result was delivered; nothing in the parent can know it.
    outcome.coverage.whole_diff_delivered = session.whole_diff_delivered


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
    is removed is the API key, so a session that could not reach the CLI's own
    login cannot quietly bill an account instead.

    And the two variables that name the checkout. The design's claim is that
    the CLI is never given a path into the repository — it runs in an empty
    directory and the repository reaches only the MCP server, a different
    process. `PWD` and `OLDPWD` were carrying that path in anyway, which made
    the claim true of the argument list and false of the environment. The
    process is given its working directory explicitly by `cwd=`, so neither is
    needed for it to run.
    """
    env = dict(os.environ)
    for name in ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "PWD", "OLDPWD"):
        env.pop(name, None)
    return env


def _tail(stderr: str, limit: int = 400) -> str:
    text = (stderr or "").strip()
    if not text:
        return ""
    if len(text) > limit:
        text = "…" + text[-limit:]
    return ". Its error output ended: {}".format(text)
