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
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from contextlib import redirect_stdout
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, TextIO

from . import __version__
from .budget import Allowance
from .config import Config, ConfigError
from .gate import EXIT_ERROR, EXIT_OK
from .tools import (
    Session,
    ToolResult,
    dispatch,
    load_finding_schema,
    tool_definitions,
)
from .workspace import Workspace, WorkspaceError

log = logging.getLogger(__name__)

# The revision whose shapes this file implements. Sent back on `initialize`
# whatever the client asked for: the spec's own answer to a version we do not
# speak is to state the one we do and let the client decide, and guessing at a
# dialect we have not implemented would fail later and less clearly.
PROTOCOL_VERSION = "2025-06-18"

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
        self.initialized = False
        # Set when a call was actually turned away for budget — not when the
        # last permitted call was spent. A session that used its ceiling exactly
        # and then stopped got everything it asked for; one that was refused did
        # not, and only the second is a review that was cut short.
        self.refused_for_budget = False

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
                "line".format(PROTOCOL_VERSION))
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
        asked = params.get("protocolVersion")
        if asked and asked != PROTOCOL_VERSION:
            log.warning("client asked for MCP %s; answering with %s",
                        asked, PROTOCOL_VERSION)
        self.initialized = True
        return self._result(request_id, {
            "protocolVersion": PROTOCOL_VERSION,
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

        log.info("%-20s %s%s", name, result.summary,
                 " [rejected]" if result.is_error else "")
        return self._result(request_id, self._tool_result(result))

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
) -> MCPServer:
    """Assemble a session from the same parts the API path uses."""
    workspace = Workspace(
        root=root, excludes=excludes, diff_base=diff_base, diff_head=diff_head,
        scope=scope)
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
    return MCPServer(workspace, tools, allowance)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    # Every handler on stderr, set here rather than left to chance. The root
    # logger's fallback already writes there, but a library that calls
    # `basicConfig` first can point it anywhere, and "anywhere" includes the one
    # stream that must stay clean.
    logging.basicConfig(
        level=logging.INFO, stream=sys.stderr,
        format="%(levelname)s %(name)s: %(message)s")

    try:
        server = build_server(
            root=Path(args.repo or ".").resolve(),
            diff_base=args.base or "",
            diff_head=args.head or "HEAD",
            tool_set=args.tools,
            max_tool_calls=args.max_tool_calls,
            scope=tuple(args.path or ()),
        )
    except (WorkspaceError, ConfigError, ValueError) as exc:
        # A server that never came up must not exit zero. On this transport the
        # client sees a closed pipe either way, and the exit code is the only
        # place the difference between "no findings" and "never started" is
        # written down.
        log.error("%s", exc)
        return EXIT_ERROR

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
    """
    payload = {
        "label": server.allowance.label,
        "ceiling": server.allowance.ceiling,
        "spent": server.allowance.spent,
        "refused_for_budget": server.refused_for_budget,
    }
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_name(path.name + ".partial")
        temporary.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        temporary.replace(path)
    except OSError as exc:
        log.error("could not write the spend report to %s: %s", path, exc)


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
    parser.add_argument("--tools", choices=TOOL_SETS, default=REVIEWER,
                        help="Which set to offer; nothing outside it can be called.")
    parser.add_argument("--max-tool-calls", type=int, default=100,
                        help="Ceiling for this session (default: 100).")
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
    return parser.parse_args(argv)


if __name__ == "__main__":
    sys.exit(main())
