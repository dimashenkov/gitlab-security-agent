"""This project's tools, offered over MCP to a runner that owns its own loop.

The `claude` CLI can drive a review, and it is cheaper to let it than to
reimplement its loop. What must not travel with the loop are the tools. The
citation check in `report_finding`, the exposure journal in `Session`, the
containment and no-ext-diff rules in `Workspace`, the reading of blobs at the
reviewed revision rather than off a disk an untrusted contributor wrote — those
are the parts that make a verdict mean anything. A review driven with the CLI's
own file-reading tools would look identical from the outside and would have none
of them.

So this module is a bridge and deliberately nothing more. Every call lands in
`dispatch()`, the single entry point the Messages API path already goes through,
and no tool is reimplemented here. What this layer adds is only what the
transport makes possible: an offered set the caller may not step outside of, a
budget the caller cannot spend past, and a stdout that carries protocol and
nothing else.

The failure mode this file is written against is the quiet one. On this
transport a crash, a stray `print`, and a tool that found nothing all reach the
client as the same silence or the same unusable line — so every path here ends
in an answer, and the answer says which of those happened.

The same boundary is why this process writes two files. The `Session` that holds
the findings, the rejections, the coverage and the sign-off accumulates *here*,
in a child the parent cannot reach into, and dies with the process. So when the
client disconnects — the normal end — the whole session is written once,
atomically, as the authoritative document the parent reads. And while the run
goes on, each domain event is appended to a crash journal, which is worth
nothing when the document exists and is the only thing left when the process was
killed before it could write one. The two are not alternatives: one says what
was found, the other says how far it got, and only the first ever gates
anything.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import logging
import os
import sys
from contextlib import redirect_stdout
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, TextIO

from . import __version__
from .budget import Allowance
from .config import Config, ConfigError
from .context_budget import ContextBudget
from .crash_journal import CrashJournal, CrashJournalError
from .gate import EXIT_ERROR, EXIT_OK
from .models import Revision, ToolCallRecord
from .session_document import SessionDocumentError, write_session
from .tools import (
    Session,
    ToolResult,
    dispatch,
    load_finding_schema,
    tool_definitions,
)
from .workspace import Workspace, WorkspaceError

log = logging.getLogger(__name__)

# The revision this file was written against, and the one named on `initialize`
# when the client asks for something outside the list below: the spec's own
# answer to a version we do not speak is to state the one we do and let the
# client decide, and guessing at a dialect we have not implemented would fail
# later and less clearly.
PROTOCOL_VERSION = "2025-06-18"

# The revisions this server's shapes are genuinely valid under, and the reason
# the version is negotiated rather than stated. `initialize`, `tools/list` and a
# `tools/call` result of text content beside `isError` are spelled identically
# in all three; everything that separates them — elicitation, roots, structured
# content, batching — this server either does not use or already refuses, so
# answering with the client's own version claims nothing we do not do.
#
# Stating ours unconditionally was safe only while clients were forgiving. The
# spec permits a client that does not recognise the version the server names to
# disconnect, and a disconnected client is a session with no tools — the failure
# Claude Code 2.1.236 has already produced here by another route, where the
# reviewer invented `<invoke name="get_diff">` and its result rather than say it
# had nothing. That same client negotiates 2025-11-25 and was being answered
# with 2025-06-18 on the hope that it would accept it. It does today. The list
# is what stops the next move in the client's version being a silent one.
SUPPORTED_PROTOCOL_VERSIONS = ("2025-11-25", "2025-06-18", "2025-03-26")

SERVER_NAME = "gitlab-security-agent"

# JSON-RPC 2.0 error codes. Named because a bare -32602 in a response is not
# readable, and these are what a client's own error text is built from.
PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603


class StdoutUnavailable(Exception):
    """File descriptor 1 could not be claimed for the protocol."""


REVIEWER = "reviewer"
VERIFIER = "verifier"
TOOL_SETS = (REVIEWER, VERIFIER)


def mcp_tool(tool: Dict[str, Any]) -> Dict[str, Any]:
    """Render one of our tool definitions in MCP's shape.

    Three keys, and only three. Our definitions carry `input_schema` and
    sometimes `strict`, which are the Messages API's spelling and the Messages
    API's flag; forwarding either would put a field in a protocol message that
    no client is required to understand, and a client that validates strictly
    would reject the whole list over it. Converting here rather than keeping a
    second copy of the definitions keeps one description of each tool — the
    drift this project has already been bitten by twice.
    """
    return {
        "name": tool["name"],
        "description": tool.get("description", ""),
        "inputSchema": tool.get("input_schema", {"type": "object", "properties": {}}),
    }


def build_tool_set(
    tool_set: str, diff_available: bool, prompt_dir: Optional[Path] = None
) -> List[Dict[str, Any]]:
    """The definitions for one role, taken from `tools.py` rather than restated.

    `verify` is imported inside the function because importing it pulls in the
    Anthropic SDK, and this server never talks to the API — it is the half of
    the run that does not cost anything. Paying for that import on every start
    would make the cheapest path in the system depend on the most expensive
    dependency in it.
    """
    if tool_set == VERIFIER:
        from .tools import verifier_tool_definitions
        from .verify import VERDICT_SCHEMA

        return verifier_tool_definitions(VERDICT_SCHEMA, diff_available)
    if tool_set != REVIEWER:
        raise ValueError("unknown tool set {!r}; choose one of {}".format(
            tool_set, ", ".join(TOOL_SETS)))
    directory = prompt_dir or Config().resolved_prompt_dir()
    return tool_definitions(load_finding_schema(directory), diff_available)


class MCPServer:
    """One stdio session: one workspace, one offered set, one allowance.

    Nothing here is shared with another session, for the same reason
    `budget.py` hands out allowances instead of keeping a counter — verifiers
    run as separate processes under this runner, and anything they read from
    each other while spending would put a race inside the security decision.
    """

    def __init__(
        self,
        workspace: Workspace,
        tools: Sequence[Dict[str, Any]],
        allowance: Allowance,
        session: Optional[Session] = None,
        server_name: str = SERVER_NAME,
        journal: Optional[CrashJournal] = None,
    ) -> None:
        self.ws = workspace
        self.tools = list(tools)
        # Enforcement of the promise made in `tools/list`. `dispatch()` will run
        # any tool in `HANDLERS`, which is correct for it — it serves both roles
        # — and wrong here: a verifier that could call `report_finding` could
        # create the finding it was convened to judge.
        #
        # Not a second layer, though the first draft of this comment said so.
        # This set and the list the client is shown are the same value, so a
        # construction that wrongly included `report_finding` would be believed
        # by both. The genuinely independent layer is outside this process — the
        # CLI's own `--allowedTools` / `--disallowedTools`, which the runner
        # sets and which does not consult `self.tools` at all.
        self.offered = {tool["name"] for tool in self.tools}
        self.allowance = allowance
        self.session = Session() if session is None else session
        self.server_name = server_name
        # What `initialize` settled on, and the version every later message is
        # answered under. Held per session rather than read off the module
        # constant because two of this server's processes serve one review and a
        # client is free to negotiate differently with each.
        self.protocol_version = PROTOCOL_VERSION
        # Optional, never authoritative, and deliberately held *here* rather
        # than inside the tool handlers. Journalling from `tools.py` would put a
        # file write in every handler and tie the tool layer — which the API
        # runner shares, and which has no child process to survive — to a file
        # only this transport needs. This layer already sees every call and
        # every change the call made, which is all the journal records.
        self.journal = journal
        self.initialized = False
        # Set when a call was actually turned away for budget — not when the
        # last permitted call was spent. A session that used its ceiling exactly
        # and then stopped got everything it asked for; one that was refused did
        # not, and only the second is a review that was cut short.
        self.refused_for_budget = False
        # How to hand the session over. Set by `main` when the parent asked
        # for a document, and called after every state change rather than at
        # exit — see `_call_tool`.
        self.handover: Optional[Callable[[], None]] = None

    # ------------------------------------------------------------ the loop

    def serve(self, stdin: TextIO, stdout: TextIO) -> None:
        """Read newline-delimited JSON-RPC until the input ends.

        `readline` rather than iterating the file: iteration reads ahead into a
        buffer, and a client that waits for each reply before sending the next
        request would then be waiting for bytes we are holding — a deadlock
        that looks exactly like a hung review.

        `sys.stdout` is redirected to stderr for the duration and the protocol
        goes to the handle passed in. That is the Python half of keeping the
        stream clean, and it is only the Python half: it does nothing about a
        write to file descriptor 1 from C, or from a subprocess that inherited
        it. `claim_stdout` is the half that covers those, and `main` uses it —
        this stays because the two are cheap and cover different things.

        The rule is worth enforcing twice. One `print` left in a tool handler
        corrupts the stream, and what the client reports is a protocol error:
        indistinguishable from the tool having failed, and pointing at the
        wrong file.
        """
        with redirect_stdout(sys.stderr):
            while True:
                line = stdin.readline()
                if not line:
                    return
                reply = self.handle_line(line)
                if reply is None:
                    continue
                stdout.write(reply + "\n")
                stdout.flush()

    def handle_line(self, line: str) -> Optional[str]:
        """One line in, one line of JSON out — or `None` for nothing to say.

        Returns rather than writes, so the loop above owns the only handle that
        reaches the client.
        """
        text = line.strip()
        if not text:
            # A blank line between messages is framing, not a message. Answering
            # it with a parse error would make an idle client look broken.
            return None

        try:
            message = json.loads(text)
        except ValueError as exc:
            # The id is unknowable — the bytes that carried it did not parse —
            # so it is null, and the loop keeps reading. Unparseable input must
            # never be the quietest kind of failure: a client that garbles one
            # request and gets silence will wait forever, and a review that
            # hangs reads as a review that is still working.
            log.warning("could not parse a line as JSON: %s", exc)
            return self._error(None, PARSE_ERROR, "invalid JSON: {}".format(exc))

        if isinstance(message, list):
            # Batching was removed in this revision of MCP. Accepting it would
            # mean implementing a shape no client is allowed to send.
            return self._error(
                None, INVALID_REQUEST,
                "JSON-RPC batches are not part of MCP {}; send one request per "
                "line".format(self.protocol_version))
        if not isinstance(message, dict):
            return self._error(
                None, INVALID_REQUEST, "a JSON-RPC message must be an object")

        method = message.get("method")
        request_id = message.get("id")
        if not isinstance(method, str) or not method:
            return self._error(request_id, INVALID_REQUEST, "no method named")

        if request_id is None:
            # A notification. The protocol forbids answering one at all, so an
            # unknown notification is dropped rather than turned into an error
            # nobody is listening for.
            if method == "notifications/initialized":
                self.initialized = True
            else:
                log.debug("ignoring notification %s", method)
            return None

        params = message.get("params")
        if params is None:
            params = {}
        if not isinstance(params, dict):
            return self._error(request_id, INVALID_PARAMS, "params must be an object")

        try:
            return self._handle_request(request_id, method, params)
        except Exception as exc:
            # Nothing below is expected to raise — `dispatch()` converts its own
            # failures, and the rest is dictionary building. This catches the
            # unexpected anyway: the alternative is a dead server, and a dead
            # server on this transport is a client blocked on a read with no
            # error to report.
            log.exception("%s raised", method)
            return self._error(
                request_id, INTERNAL_ERROR,
                "{} failed unexpectedly: {}: {}".format(
                    method, type(exc).__name__, exc))

    def _handle_request(
        self, request_id: Any, method: str, params: Dict[str, Any]
    ) -> str:
        if method == "initialize":
            return self._initialize(request_id, params)
        if method == "ping":
            return self._result(request_id, {})
        if method == "tools/list":
            return self._result(
                request_id, {"tools": [mcp_tool(t) for t in self.tools]})
        if method == "tools/call":
            return self._call_tool(request_id, params)
        return self._error(
            request_id, METHOD_NOT_FOUND,
            "this server implements initialize, notifications/initialized, "
            "tools/list, tools/call and ping; {!r} is not one of them".format(method))

    # --------------------------------------------------------------- methods

    def _initialize(self, request_id: Any, params: Dict[str, Any]) -> str:
        """Settle on a version, and say what this server can do.

        The client's own version is answered when it is one this server's shapes
        are valid under, and only then. A version outside that list is answered
        with ours, which is what the spec asks for and leaves the decision where
        it belongs — with the client, which knows whether it can speak it.

        The capabilities the client offers alongside its version are read and
        deliberately not acted on. 2.1.236 sends `roots` and `elicitation`; both
        are things a server may ask the *client* to do, this server asks for
        neither, and a capability nobody uses needs no handling. What it must not
        do is object to them: a handshake refused over a field we do not read is
        a session with no tools, and a session with no tools has already been
        seen to end in a reviewer inventing the calls it never made.
        """
        asked = params.get("protocolVersion")
        if isinstance(asked, str) and asked in SUPPORTED_PROTOCOL_VERSIONS:
            self.protocol_version = asked
        elif asked:
            log.warning("client asked for MCP %s, which this server does not "
                        "implement; answering with %s", asked, self.protocol_version)
        self.initialized = True
        return self._result(request_id, {
            "protocolVersion": self.protocol_version,
            # `listChanged` is false and says so. The set is fixed at
            # construction — that is the point of it — so a client that polls
            # for changes would be polling for something that cannot happen.
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": self.server_name, "version": __version__},
        })

    def _call_tool(self, request_id: Any, params: Dict[str, Any]) -> str:
        name = params.get("name")
        if not isinstance(name, str) or not name:
            return self._error(request_id, INVALID_PARAMS, "no tool name given")
        arguments = params.get("arguments")
        if arguments is None:
            arguments = {}

        # Counted before anything is checked, because `budget.py` documents one
        # rule for what an attempt is: it counts whether it succeeds, fails
        # validation, or is refused. Counting only the calls that reach a tool
        # would let a client loop on a misspelled name for free, and would make
        # the number in the usage report mean something different on this runner
        # than on the other one.
        if not self.allowance.note_tool_call():
            self.refused_for_budget = True
            return self._result(request_id, self._tool_result(ToolResult(
                "No tool calls left: this session's budget of {} was spent, and "
                "nothing further will run. Stop and report what you have "
                "established so far — do not present an unfinished search as a "
                "clean result.".format(self.allowance.ceiling),
                "budget exhausted", is_error=True)))

        if name not in self.offered:
            # `dispatch()` would run this one. That is exactly why the check is
            # here: the offered set is narrower than the handler table, and the
            # difference between them is what keeps a verifier from reporting
            # findings. An unknown tool is a protocol fault under MCP, so it is
            # answered as one rather than dressed up as tool output — a refusal
            # that arrives looking like successful content is the one shape
            # that could be read as the tool having run.
            log.warning("refused %s: not in the %s set", name, self.server_name)
            return self._error(
                request_id, INVALID_PARAMS,
                "no tool named {!r} is offered by this server; it offers "
                "{}".format(name, ", ".join(sorted(self.offered))))

        # Read before the call so the journal can be told what this one call
        # added. See `_journal_new_state` for why it is a comparison and not a
        # reading of the result text.
        before = self._session_state()

        call_id = ""
        if self.journal is not None:
            # Here, and not above the two checks. Neither a budget refusal nor
            # an unoffered name runs a tool, and a `tool_started` with no
            # `tool_finished` after it is rendered as "started, outcome
            # unknown" — true of a call the kill interrupted, false of a call
            # that was turned away before it began.
            call_id = self.journal.tool_started(
                name, arguments, turn=self.session.turn)

        try:
            result = dispatch(self.ws, self.session, name, arguments)
        except Exception as exc:
            # `dispatch()` already converts everything it can into a result, so
            # reaching here means the failure was in the conversion itself. It
            # still becomes a result: the client is a loop we do not own, and
            # killing this process ends its review with no explanation.
            log.exception("dispatch(%s) raised", name)
            result = ToolResult(
                "{} failed unexpectedly: {}: {}".format(
                    name, type(exc).__name__, exc),
                "error: {}".format(type(exc).__name__), is_error=True)

        # The audit trail, recorded where the API path records it — right after
        # the dispatch, with the name, the arguments and the summary all in
        # hand. Without this the artifact's account of what the review actually
        # did was blank on this runner: the report's coverage section, the
        # journal entry a person judges, and the conformance comparison against
        # the other runner all read zero tool calls for a review that made
        # dozens. The crash journal is not a substitute — it exists for a run
        # that died, and it is deliberately not gateable state.
        self.session.tool_calls.append(ToolCallRecord(
            turn=self.session.turn,
            name=name,
            arguments=arguments if isinstance(arguments, dict) else {},
            summary=result.summary,
            is_error=result.is_error,
        ))

        if self.journal is not None:
            self.journal.tool_finished(
                call_id, summary=result.summary, is_error=result.is_error)
            self._journal_new_state(before)

        # Handed over now, not at exit.
        #
        # The first design wrote the document once, when the client closed this
        # server's input — the normal end. Measured against the corpus, that end
        # does not arrive: the CLI takes its MCP servers down with it, so a
        # review that had made seventeen tool calls, found a critical remote
        # code execution and called `finish_review` handed over nothing, and the
        # parent correctly reported a process that died. The work was done every
        # time and the handoff was never reached.
        #
        # `write_session` renames a complete document into place, so rewriting
        # it after each call is safe: the parent sees the last complete one, and
        # never a partial one. A JSON dump per tool call is unmeasurable beside
        # a model turn.
        if self.handover is not None:
            self.handover()

        log.info("%-20s %s%s", name, result.summary,
                 " [rejected]" if result.is_error else "")
        return self._result(request_id, self._tool_result(result))

    # ------------------------------------------------------------- journalling

    def _session_state(self) -> Dict[str, Any]:
        """How much of the session already existed before a call ran."""
        return {
            "candidates": len(self.session.candidates),
            "rejected": len(self.session.rejected),
            "finished": self.session.finished,
            "verdict": self.session.verdict is not None,
        }

    def _journal_new_state(self, before: Dict[str, Any]) -> None:
        """Append whatever this call added, found by comparing the session to itself.

        Read off `Session` rather than off the tool's result. The result is
        prose written for the model to act on, and deciding from its wording
        whether a finding was accepted would put a second definition of
        "accepted" in this codebase, in the file least likely to be updated when
        the first one changes. What the citation check decided is in the
        session, exactly once.

        The two flags are the same idea for the two fields that are set once and
        never again. `finish_review` called twice keeps the first sign-off and
        leaves `finished` true through both calls, so journalling on the value
        rather than on the change would write a second `review_finished` and
        make one sign-off read as two — in the file whose only job is to say
        truthfully how far a killed run got.
        """
        journal = self.journal
        if journal is None:
            return
        session = self.session
        for candidate in session.candidates[before["candidates"]:]:
            journal.finding_accepted(
                title=candidate.finding.title,
                file=candidate.finding.file,
                # The located line, not the claimed one: the citation check
                # corrects the number, and the journal should name the place a
                # person can open.
                line=candidate.line,
                severity=candidate.severity,
                confidence=candidate.confidence,
                fingerprint=candidate.fingerprint,
            )
        for claim in session.rejected[before["rejected"]:]:
            journal.claim_rejected(
                title=claim.title, file=claim.file, reason=claim.reason,
                detail=claim.detail)
        if session.finished and not before["finished"]:
            journal.review_finished(
                summary=session.final_summary, unresolved=session.unresolved)
        if session.verdict is not None and not before["verdict"]:
            journal.verdict_submitted(
                verdict=str(session.verdict.get("verdict") or ""),
                reasoning=str(session.verdict.get("reasoning") or ""))

    # ---------------------------------------------------------------- shapes

    @staticmethod
    def _tool_result(result: ToolResult) -> Dict[str, Any]:
        """Our result in MCP's shape.

        `isError` is always present rather than omitted when false. A missing
        field and a false one are the same thing to a careful client and not to
        a careless one, and the careless reading here is the permissive one.
        """
        return {
            "content": [{"type": "text", "text": result.content or "(no output)"}],
            "isError": result.is_error,
        }

    @staticmethod
    def _result(request_id: Any, result: Dict[str, Any]) -> str:
        return json.dumps({"jsonrpc": "2.0", "id": request_id, "result": result})

    @staticmethod
    def _error(request_id: Any, code: int, message: str) -> str:
        return json.dumps({
            "jsonrpc": "2.0",
            "id": request_id,
            "error": {"code": code, "message": message},
        })


def build_server(
    root: Path,
    diff_base: str = "",
    diff_head: str = "HEAD",
    tool_set: str = REVIEWER,
    max_tool_calls: int = 100,
    excludes: Sequence[str] = (),
    prompt_dir: Optional[Path] = None,
    scope: Sequence[str] = (),
    crash_journal_path: Optional[Path] = None,
    run_id: str = "",
    revision: Optional[Revision] = None,
    default_context_lines: int = 12,
    max_context_tokens: int = 0,
    max_context_soft_tokens: int = 0,
    max_context_mode: str = "observe",
) -> MCPServer:
    """Assemble a session from the same parts the API path uses.

    `crash_journal_path` is optional and, when given, is not best-effort: see
    `main` for why a journal that was asked for and could not be opened stops
    the server from starting.
    """
    # Before the workspace, because an argument that could never work should be
    # refused whatever the repository turns out to be. Refused rather than
    # corrected: this is a command line, outside `Config.validate`, and a
    # ceiling that quietly relaxes is the defect this project keeps finding in
    # its own code.
    if max_context_tokens < 0 or max_context_soft_tokens < 0:
        raise ValueError("--max-context and --max-context-soft must not be "
                         "negative; 0 means unbounded")
    if max_context_soft_tokens > max_context_tokens > 0:
        raise ValueError(
            "--max-context-soft ({}) is above --max-context ({}), so it could "
            "never fire".format(max_context_soft_tokens, max_context_tokens))
    if max_context_mode not in ("observe", "enforce"):
        raise ValueError(
            "--max-context-mode must be observe|enforce, got {!r}".format(
                max_context_mode))

    workspace = Workspace(
        root=root, excludes=excludes, diff_base=diff_base, diff_head=diff_head,
        scope=scope, default_context_lines=default_context_lines)
    # `diff_available` follows the base, not a flag: without a base there is
    # nothing to diff, and offering `get_diff` anyway would spend a call to
    # learn that.
    tools = build_tool_set(tool_set, bool(diff_base), prompt_dir)
    if max_tool_calls < 1:
        # Refused rather than raised to one. This entry point is reached from a
        # command line, so it sits outside `Profile`'s constructor checks, and
        # a budget boundary that quietly becomes more permissive is the defect
        # this project keeps finding in its own code.
        raise ValueError(
            "--max-tool-calls must be at least 1; {} was asked for, and a "
            "session that may make no tool calls cannot review anything"
            .format(max_tool_calls))
    allowance = Allowance(tool_set, max_tool_calls)
    session = Session()
    session.context = ContextBudget.configured(
        max_context_tokens, max_context_soft_tokens,
        enforcing=max_context_mode == "enforce")

    journal = None
    if crash_journal_path is not None:
        # One journal per *process*, not per run, because a run is no longer
        # one process. Claude Code 2.1.236 starts this server twice for one
        # review: once to probe it with `server/discover`, which this server
        # does not implement and answers with a JSON-RPC error, and once for
        # the session. Both were handed the same path; the probe claimed it and
        # wrote its error record, and the session then refused to start at all.
        #
        # The reviewer was left with no tools. It wrote `<invoke name="get_diff">`
        # into its prose and invented the result — a review of a repository that
        # did not exist. The gate caught it, because nothing was ever recorded
        # as reached, but every paid review failed this way after the upgrade.
        #
        # The guarantee the single path was protecting — two runs must never
        # interleave into one trace — is kept by the name: a pid cannot be
        # shared, and `read_trace` is given whichever file has a review in it.
        path = Path(crash_journal_path)
        _refuse_another_run_s_journal(path, run_id)
        journal = CrashJournal(
            path.with_name("{}.{}{}".format(path.stem, os.getpid(), path.suffix)),
            run_id=run_id)
        # Written before anything else can be. A child killed during start-up
        # would otherwise leave an empty file, and an empty file cannot say
        # whether the run never began or the disk was never reachable.
        journal.run_started(mode=tool_set, revision=_revision_line(revision))
    return MCPServer(workspace, tools, allowance, session=session, journal=journal)


def _refuse_another_run_s_journal(path: Path, run_id: str) -> None:
    """Stop before writing beside a journal that belongs to somebody else.

    The rule being kept is the one the single-file design was for: a reader must
    never take an earlier run's progress for this one's and give a confident
    account of a death that happened last week. What changed is where journals
    live. Since one review became two processes they are written to
    `<name>.<pid><suffix>`, and `read_trace` — finding nothing at the plain name
    — reads whichever sibling has the most records in it. So a check on the
    plain name alone now guards a path that nothing writes to, while the files
    that would actually be misread sit beside it unexamined.

    The run id is what separates the two cases, and it has to, because one of
    them is normal. Claude Code starts this server twice for one review, so a
    sibling stamped with *our* run id is this run's probe process and must be
    tolerated — refusing it is exactly the failure this whole change was made
    for. A sibling stamped with another run id, or one whose first record cannot
    be read at all, is refused: an unattributable journal is the case where
    guessing produces the confident wrong answer.

    Without `--run-id` there is nothing to tell two runs apart by and this check
    can only pass. That is a real gap and not a silent one — both runners always
    pass a run id, because the session document's binding needs it too.
    """
    for candidate in [path, *sorted(path.parent.glob(
            "{}.*{}".format(path.stem, path.suffix)))]:
        owner = _journal_owner(candidate)
        if owner is None or owner == str(run_id):
            continue
        raise CrashJournalError(
            "{} already exists and has records in it, written by run {!r} "
            "rather than {!r}; this run's trace would be read as that one's "
            "progress".format(candidate, owner, str(run_id)))


def _journal_owner(path: Path) -> Optional[str]:
    """Which run wrote a journal, or `None` for a file with nothing in it.

    Only the first line is read. A journal is append-only and every record
    carries the same run, so the first record answers the question; the file
    itself can be a hundred kilobytes of a review that went badly.

    An empty file is nobody's — the probe process creates one and writes to it,
    and a file with no records has no trace to be confused with. A file with
    records whose first line does not parse, or carries no run, is reported as
    `""`, which belongs to no run that named itself and is therefore refused.
    """
    try:
        if path.stat().st_size == 0:
            return None
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            first = handle.readline()
    except OSError:
        return None
    try:
        record = json.loads(first)
    except ValueError:
        return ""
    if not isinstance(record, dict):
        return ""
    run = record.get("run")
    return run if isinstance(run, str) else ""


def _revision_line(revision: Optional[Revision]) -> str:
    """Which commits were being read, for a person reading a killed run's trace.

    Resolved SHAs when there are any, the symbolic names when there are not: a
    trace saying `main..HEAD` names different code every day, which is the same
    problem the document's binding exists to solve — but here it is a diagnostic
    string, so an approximate answer beats no answer.
    """
    if revision is None:
        return ""
    base = revision.base_sha or revision.base
    head = revision.head_sha or revision.head
    return "{}..{}".format(base[:12], head[:12])


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    # Every handler on stderr, set here rather than left to chance. The root
    # logger's fallback already writes there, but a library that calls
    # `basicConfig` first can point it anywhere, and "anywhere" includes the one
    # stream that must stay clean.
    logging.basicConfig(
        level=logging.INFO, stream=sys.stderr,
        format="%(levelname)s %(name)s: %(message)s")

    # What the document is an answer *about*. The resolved SHAs are separate
    # arguments from `--base`/`--head` because those are what the operator
    # configured — `main`, `HEAD`, a branch name — and none of them identifies a
    # commit a week later, which is exactly what a document read by another
    # process has to be bound to.
    revision = Revision(
        base=args.base or "", head=args.head or "HEAD",
        base_sha=args.base_sha or "", head_sha=args.head_sha or "")

    try:
        server = build_server(
            root=Path(args.repo or ".").resolve(),
            diff_base=args.base or "",
            diff_head=args.head or "HEAD",
            tool_set=args.tools,
            prompt_dir=Path(args.prompt_dir) if args.prompt_dir else None,
            max_tool_calls=args.max_tool_calls,
            scope=tuple(args.path or ()),
            crash_journal_path=(
                Path(args.crash_journal) if args.crash_journal else None),
            run_id=args.run_id or "",
            revision=revision,
            default_context_lines=args.context_lines,
            max_context_tokens=args.max_context,
            max_context_soft_tokens=args.max_context_soft,
            max_context_mode=args.max_context_mode,
        )
    except (WorkspaceError, ConfigError, ValueError) as exc:
        # A server that never came up must not exit zero. On this transport the
        # client sees a closed pipe either way, and the exit code is the only
        # place the difference between "no findings" and "never started" is
        # written down.
        log.error("%s", exc)
        return EXIT_ERROR
    except CrashJournalError as exc:
        # Fatal, and the only defensible answer. `CrashJournal` raises this when
        # the file is already there, which means either another child is writing
        # to that path right now or a previous run's journal was left behind —
        # and the stale file does not go away because we decided to carry on
        # without a journal. It stays, this run appends nothing to it, and if
        # this run is then killed the parent reads yesterday's progress as
        # today's. A confident wrong account of a death is worse than no
        # account, and worse still than not starting.
        #
        # Note this is the opposite trade from the one `CrashJournal` makes
        # *during* a run, where a failed write is swallowed. That is right too:
        # once the review is happening, losing it to keep its diagnostics honest
        # costs more than the diagnostics are worth. Here nothing has happened
        # yet, nothing has been spent, and the parent can fix the path.
        log.error("%s", exc)
        return EXIT_ERROR

    if args.session_document:
        # Attached before the first request, so a session that ends after one
        # tool call has still handed over what it learned. The same function is
        # called again below, on the ordinary end, when there is nothing left
        # to add — the last write wins and they are identical.
        document = Path(args.session_document)
        revision = Revision(base_sha=args.base_sha or "",
                            head_sha=args.head_sha or "")
        server.handover = lambda: _write_session_document(
            document, server.session, run_id=args.run_id or "",
            revision=revision, config_digest=args.config_digest or "")

    log.info("serving the %s tool set over MCP %s (%d tool calls)",
             args.tools, PROTOCOL_VERSION, server.allowance.ceiling)
    try:
        protocol = claim_stdout(required=True)
    except StdoutUnavailable as exc:
        log.error("%s", exc)
        return EXIT_ERROR
    try:
        server.serve(sys.stdin, protocol)
    finally:
        protocol.flush()
        if protocol is not sys.stdout:
            protocol.close()

    if args.spend_report:
        _write_spend_report(Path(args.spend_report), server)

    # `serve()` returned, so stdin closed: the client disconnected, which is how
    # a review that ran to the end ends. Everything this process learned is in
    # `server.session` and nowhere else.
    if args.session_document and not _write_session_document(
            Path(args.session_document), server.session,
            run_id=args.run_id or "", revision=revision,
            config_digest=args.config_digest or ""):
        return EXIT_ERROR

    if server.refused_for_budget:
        # The client got its answers and then hit the ceiling. Exiting zero
        # would put "the session was cut short" and "the session finished" in
        # the same channel, and the parent process has no other way to tell them
        # apart — the transcript it reads was written by the model that ran out.
        log.error("the session was refused a tool call: %d of %d spent",
                  server.allowance.spent, server.allowance.ceiling)
        return EXIT_ERROR
    return EXIT_OK


def claim_stdout(required: bool = False) -> TextIO:
    """Take file descriptor 1 for the protocol and point everything else away.

    Redirecting `sys.stdout` covers Python-level writes and nothing else. A
    library that writes to fd 1 from C, and — the one that will actually happen
    here — a subprocess that inherits it, both go straight onto the wire. This
    module runs `git` on nearly every tool call; one of those inheriting stdout
    would put diff text into the middle of a JSON-RPC frame.

    So the descriptor itself moves. Fd 1 is duplicated to a private one for the
    protocol, and stderr is dup'd onto fd 1 — after which everything that
    writes to "standard output", by any route, at any level, and in any child
    process, writes to stderr instead. The protocol handle is the only way back
    to the client, and this function is the only thing holding it.

    Line buffered, because the client is waiting for each reply before it sends
    the next request: a reply sitting in a buffer is indistinguishable from a
    review that has stopped responding.

    `required` decides what happens when there are no real descriptors — an
    embedded caller, a harness that replaced the streams with objects. The
    production command passes `True` and refuses to start: a server that came
    up with weaker containment than it was written to have is a server nobody
    will look at again, and this project's rule is that a thing which could not
    be done fails visibly rather than continuing in a reduced form.

    An embedded caller may pass `False` and get `sys.stdout` with a warning.
    That is only defensible because what the swap protects against is a
    *subprocess* inheriting the descriptor, and a caller with no descriptors has
    no subprocess to protect against.
    """
    try:
        stderr_fd = sys.stderr.fileno()
        sys.stdout.flush()
        protocol_fd = os.dup(1)
    except (AttributeError, OSError, ValueError) as exc:
        if required:
            raise StdoutUnavailable(
                "standard output could not be claimed at the descriptor level "
                "({}). This server cannot guarantee that only protocol reaches "
                "the client, and a bridge that might interleave `git` output "
                "with JSON-RPC frames is worse than one that does not "
                "start.".format(exc)) from exc
        log.warning(
            "standard output could not be claimed at the descriptor level (%s); "
            "protocol and any descriptor-level writes share one stream", exc)
        return sys.stdout
    os.dup2(stderr_fd, 1)
    return os.fdopen(protocol_fd, "w", encoding="utf-8", buffering=1)


def _write_spend_report(path: Path, server: "MCPServer") -> None:
    """What this session actually spent, for the parent to fold into the run.

    Written last, atomically, and never allowed to end the process: this file is
    accounting, and a review that completed must not be turned into a failure by
    a disk that was full when it tried to say how many searches it ran.

    The parent needs it because the allowance lives here. Tool-call accounting
    has to mean the same thing on both runners — it is part of what the two are
    compared on — and an exit code can only say whether the ceiling was hit, not
    where the run stopped short of it.

    A process that spent nothing will not overwrite a report that is already
    there, for the same reason `_write_session_document` will not overwrite a
    document. Both processes of one review are handed this same path, and the
    probe spends nothing; its `refused_for_budget: false` landing on top of the
    session's `true` would erase the one statement that says the review ran out
    of tool calls before it finished looking, and the runner reads that key to
    decide whether a review with no findings was a clean one.
    """
    payload = {
        "label": server.allowance.label,
        "ceiling": server.allowance.ceiling,
        "spent": server.allowance.spent,
        "refused_for_budget": server.refused_for_budget,
    }
    nothing_to_say = server.allowance.spent == 0 and not server.refused_for_budget
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        # Named for this process. A fixed neighbour is one more file two
        # processes of the same review would both claim, and two writers
        # interleaving into it would put a torn document where the rename then
        # makes it the report.
        temporary = path.with_name("{}.{}.partial".format(path.name, os.getpid()))
        temporary.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        if nothing_to_say:
            # Checking `path.exists()` and then renaming is two steps, and the
            # gap between them is a race the probe can win: it looks and finds
            # nothing, the session writes `refused_for_budget: true`, and the
            # probe's `false` lands on top — erasing the one statement that
            # turns a review which ran out of tool calls into an incomplete one
            # rather than a clean one.
            #
            # `os.link` is the same intent in a single step. It fails when the
            # name is taken, so a process with nothing to report can only ever
            # create the report, never replace one.
            with contextlib.suppress(FileExistsError):
                os.link(str(temporary), str(path))
            temporary.unlink()
            return
        temporary.replace(path)
    except OSError as exc:
        log.error("could not write the spend report to %s: %s", path, exc)


def _write_session_document(
    path: Path,
    session: Session,
    *,
    run_id: str,
    revision: Revision,
    config_digest: str,
) -> bool:
    """The review itself, out of this process and into the parent's hands.

    Returns whether it was written; `main` turns a `False` into exit 2. That is
    the opposite of what `_write_spend_report` does with the same kind of
    failure, and the difference is what is being lost. The spend report is
    accounting — without it the parent is missing a number, and a review that
    happened is still a review. This document *is* the review: the candidates,
    the rejections, what was examined, the sign-off. None of it exists anywhere
    else once this process ends.

    So the argument that a completed review must not be failed by a bad disk
    does not reach this case, because without the document there is no completed
    review left to protect — only a process that once had one. Exiting 0 here
    would say "checked" while handing over nothing that was checked, and the
    parent, finding no document, treats the run as killed and exits 2 anyway.
    The choice is between the two processes agreeing and this one's exit code
    being a lie; and of the two, a lie that says "clean" is the failure this
    whole project is built to prevent.

    `write_session` either renames a complete document into place or leaves the
    path alone, so a `False` here also means no half-document was left behind
    for the parent to find.

    One thing this will not do is hand over an emptiness on top of somebody
    else's work. Both processes of one review are given the same `--session-
    document`, and the probe — which is sent `server/discover`, answers that it
    does not implement it, and is closed — reaches this function at exit with a
    session that has no tool calls, no candidates and no sign-off in it. Whether
    that write lands before or after the session's last one is the client's
    scheduling and not ours; landing after, it replaces a review that found a
    critical vulnerability with a document saying the run examined nothing. That
    document passes every binding check — same run, same commits, same config —
    so nothing downstream could tell it from a review that genuinely did
    nothing.

    A process that did none of the work therefore writes only when no document
    exists yet, which keeps the other half of the guarantee: whichever of the
    two starts first, the parent still finds a document rather than the silence
    it reads as a child that never came up.
    """
    if _did_nothing(session):
        # A process that served no tool has nothing to hand over, and the only
        # question is whether the parent would otherwise find no document at
        # all. So it writes one *if there is not one already* — and the check
        # and the write must be one step, not two.
        #
        # Two steps is a race with a real loser: the probe looks and finds
        # nothing, the session writes the review, and the probe then replaces a
        # critical finding with a document saying nothing was examined. That
        # document carries this run's id, its commits and its config digest, so
        # every binding check in `read_session` passes and nothing downstream
        # can tell it from a review that genuinely did nothing.
        #
        # `os.link` is that one step: it fails if the name is taken, and the
        # process that did the reviewing is never the one that loses.
        temporary = path.with_name("{}.empty.{}".format(path.name, os.getpid()))
        try:
            write_session(temporary, session, run_id=run_id, revision=revision,
                          config_digest=config_digest)
            os.link(str(temporary), str(path))
        except FileExistsError:
            log.info("leaving the session document at %s alone: this process "
                     "made no tool calls and another one has handed over", path)
        except (SessionDocumentError, OSError) as exc:
            log.error("could not write an empty session document: %s", exc)
            return False
        finally:
            with contextlib.suppress(OSError):
                temporary.unlink()
        return True

    try:
        write_session(path, session, run_id=run_id, revision=revision,
                      config_digest=config_digest)
    except SessionDocumentError as exc:
        log.error(
            "the review completed and could not be handed over: %s. This run "
            "reports as incomplete, because nothing that was found can be read "
            "by anyone now.", exc)
        return False
    return True


def _did_nothing(session: Session) -> bool:
    """Whether this session holds any of the work a document is written to carry.

    Every one of these fields is reached only through a tool call, so an empty
    reading means this process served no tool — which is what the probe process
    is, and is also what a session whose handshake failed looks like. The test
    is deliberately over-inclusive: a session with so much as one recorded call
    counts as having something to say, because the alternative is a rule that
    has to decide which work is worth keeping.
    """
    return not (session.tool_calls or session.candidates or session.rejected
                or session.finished or session.verdict)


def _parse_args(argv: Optional[Sequence[str]]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="python -m security_agent.mcp_server",
        description=(
            "Serve this agent's read-only review tools to an MCP client over "
            "stdio. Speaks protocol only on stdout; logs go to stderr."
        ),
    )
    parser.add_argument("--repo", metavar="PATH", help="Repository to review (default: cwd).")
    parser.add_argument("--base", metavar="REV",
                        help="Diff base revision. Without it the diff tools are not offered.")
    parser.add_argument("--head", metavar="REV", default="HEAD", help="Diff head revision.")
    # Passed rather than inherited. `_inherited_env` is an allowlist —
    # `PATH`, `HOME`, `LANG`, `LC_ALL`, `TMPDIR`, `SYSTEMROOT` — so
    # `SECURITY_SCAN_PROMPT_DIR` never reached this process, and
    # `build_tool_set` fell back to `Config()`, the *default* constructor,
    # whose search finds the agent's own installed prompts. Measured: with the
    # operator pointing at a frozen copy, the parent hashed
    # `/private/tmp/frozen-prompts` into the artifact's provenance while this
    # process built `report_finding` from the checkout's own
    # `prompts/findings.schema.json`. The artifact named one schema and the
    # model was handed another.
    parser.add_argument("--prompt-dir", metavar="PATH",
                        help="Directory holding the prompts and the finding "
                             "schema. Must be the one the parent recorded.")
    parser.add_argument("--tools", choices=TOOL_SETS, default=REVIEWER,
                        help="Which set to offer; nothing outside it can be called.")
    parser.add_argument("--context-lines", type=int, default=12,
                        help="lines of diff context when the model does not "
                             "ask for a number; SECURITY_SCAN_CONTEXT_LINES "
                             "on the parent")
    parser.add_argument("--max-tool-calls", type=int, default=100,
                        help="Ceiling for this session (default: 100).")
    parser.add_argument("--max-context", type=int, default=0,
                        help="Estimated tokens of tool output this session may "
                             "accumulate before results stop being returned. "
                             "0 (default) is unbounded; "
                             "SECURITY_SCAN_MAX_CONTEXT on the parent.")
    parser.add_argument("--max-context-soft", type=int, default=0,
                        help="Where the session is told to start finishing "
                             "rather than stopped. 0 derives it from "
                             "--max-context.")
    parser.add_argument("--max-context-mode", choices=("observe", "enforce"),
                        default="observe",
                        help="observe (default) counts what the limit would "
                             "have kept out and keeps nothing out; enforce "
                             "refuses. Measure before cutting.")
    parser.add_argument(
        "--path", metavar="PATH", action="append", default=[],
        help="Narrow which changed files the review is answerable for. "
             "Repeatable. It does not narrow what may be read — the same rule "
             "as the CLI's own flag, and for the same reason.")
    parser.add_argument(
        "--spend-report", metavar="PATH",
        help="Where to write this session's tool-call count when the client "
             "disconnects. The parent has no other way to learn it: the child "
             "holds the allowance, and tool-call accounting has to mean the "
             "same thing on both runners or the two cannot be compared.")
    parser.add_argument(
        "--session-document", metavar="PATH",
        help="Where to write the whole session when the client disconnects: "
             "the findings, the rejected claims, the coverage and the sign-off. "
             "This is the review; it accumulates in this process and reaches "
             "the parent no other way. A path that cannot be written is "
             "reported as a run that did not complete.")
    parser.add_argument(
        "--crash-journal", metavar="PATH",
        help="Where to append one line per event as the run goes. Read only "
             "when this process was killed and wrote no session document; it "
             "says how far the run got, never what it found. The process id is "
             "put into the name, because one review is two processes; a journal "
             "beside it belonging to another run stops the start.")
    parser.add_argument(
        "--run-id", metavar="ID", default="",
        help="The run this session belongs to. Stamped into the session "
             "document and every journal record, so a document left over from "
             "an earlier run is refused rather than read as this one's.")
    parser.add_argument(
        "--base-sha", metavar="SHA", default="",
        help="The resolved base commit, for binding the session document. "
             "Distinct from --base, which is what the operator configured: "
             "`main` names different code on different days and cannot say "
             "which code a document describes.")
    parser.add_argument(
        "--head-sha", metavar="SHA", default="",
        help="The resolved head commit, for binding the session document.")
    parser.add_argument(
        "--config-digest", metavar="DIGEST", default="",
        help="Digest of the configuration this run was launched under. Bound "
             "into the session document: the same code under a different "
             "policy is a different review, and both documents parse.")
    return parser.parse_args(argv)


if __name__ == "__main__":
    sys.exit(main())
