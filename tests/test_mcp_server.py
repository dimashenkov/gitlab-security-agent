"""Tests for the MCP bridge — driven as bytes, never as function calls.

Every test here writes JSON-RPC lines into the server's read loop and reads the
lines that come back out. Calling the handlers directly would pass while the
loop that feeds them is broken, and this project has already shipped that shape
of test once: 282 green tests around a control that never fired, because each
link was tested and the chain was not. The transport is the thing under test.
"""

import io
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from security_agent import mcp_server
from security_agent import tools as tools_module
from security_agent.mcp_server import (
    INVALID_PARAMS,
    METHOD_NOT_FOUND,
    PARSE_ERROR,
    PROTOCOL_VERSION,
    REVIEWER,
    VERIFIER,
    build_server,
)
from security_agent.tools import ToolResult

SRC = Path(__file__).resolve().parents[1] / "src"

READ_VIEWS = 'db.execute("SELECT * FROM users WHERE id = " + user_id)'


def line(request_id, method, **params):
    """One JSON-RPC request, as the bytes a client would send."""
    message = {"jsonrpc": "2.0", "id": request_id, "method": method}
    if params:
        message["params"] = params
    return json.dumps(message)


def transcript(server, *lines):
    """Feed lines through the real loop; return everything stdout received."""
    out = io.StringIO()
    server.serve(io.StringIO("".join(text + "\n" for text in lines)), out)
    return out.getvalue()


def drive(server, *lines):
    raw = transcript(server, *lines)
    return [json.loads(text) for text in raw.splitlines() if text.strip()]


def call(server, request_id, name, **arguments):
    return drive(server, line(request_id, "tools/call", name=name, arguments=arguments))


@pytest.fixture
def reviewer(git_repo):
    return build_server(root=git_repo, tool_set=REVIEWER, max_tool_calls=10)


class TestTheDescriptorItself:
    """The half `redirect_stdout` cannot do.

    Redirecting `sys.stdout` covers Python-level writes and nothing else. A
    write to file descriptor 1 from C, or from a subprocess that inherited it,
    goes straight onto the wire — and this server runs `git` on nearly every
    tool call, so an inherited descriptor is not a hypothetical. What the
    client would report is a protocol error pointing at the wrong file.

    Tested in a real subprocess because that is the only place descriptors are
    real. Under pytest's capture they are not, which is exactly why the bug
    survived a suite that drives every byte through the loop.
    """

    def test_a_raw_descriptor_write_lands_on_stderr(self, tmp_path):
        script = tmp_path / "leak.py"
        script.write_text(
            "import os, sys\n"
            "sys.path.insert(0, {!r})\n"
            "from security_agent.mcp_server import claim_stdout\n"
            "protocol = claim_stdout()\n"
            "os.write(1, b'LEAK FROM A DESCRIPTOR\\n')\n"
            "print('LEAK FROM PYTHON')\n"
            "protocol.write('PROTOCOL\\n')\n"
            "protocol.flush()\n".format(str(SRC)),
            encoding="utf-8")

        done = subprocess.run([sys.executable, str(script)],
                              capture_output=True, text=True, check=True)

        assert done.stdout == "PROTOCOL\n"
        assert "LEAK FROM A DESCRIPTOR" in done.stderr
        assert "LEAK FROM PYTHON" in done.stderr

    def test_the_server_answers_over_a_real_pipe(self, git_repo):
        """End to end through the entry point a `--mcp-config` would name."""
        request = line(1, "tools/call", name="git_log", arguments={})
        done = subprocess.run(
            [sys.executable, "-m", "security_agent.mcp_server",
             "--repo", str(git_repo), "--max-tool-calls", "5"],
            input=request + "\n", capture_output=True, text=True,
            env={**os.environ, "PYTHONPATH": str(SRC)}, check=False)

        replies = [json.loads(t) for t in done.stdout.splitlines() if t.strip()]
        assert len(replies) == 1
        assert replies[0]["result"]["isError"] is False
        # The startup log is on the other stream, where a client will not
        # mistake it for a frame.
        assert "serving the reviewer tool set" in done.stderr


class TestWhatTheParentNeedsBack:
    """The two things the bridge cannot leave behind in the child process.

    A scope the parent set and the child ignores would review more than the
    operator asked for, and a tool-call count only the child knows makes the two
    runners incomparable on a number they are compared on.
    """

    def test_a_scope_reaches_the_workspace(self, git_repo):
        """Passed through rather than dropped. A `--path` honoured by the API
        path and ignored here would make the same command mean two things."""
        server = build_server(root=git_repo, tool_set=REVIEWER,
                              max_tool_calls=10, scope=("app",))

        assert server.ws.scope == ("app",)
        assert server.ws.in_scope("app/views.py")
        assert not server.ws.in_scope("vendor/lib.py")

    def test_scope_does_not_reach_the_reading_tools(self, git_repo):
        """The rule the flag lives or dies by. A scope that fenced reads would
        turn every control it hid into a false positive."""
        server = build_server(root=git_repo, tool_set=REVIEWER,
                              max_tool_calls=10, scope=("nothing/matches",))
        replies = call(server, 1, "read_file", path="app/views.py")

        assert replies[0]["result"]["isError"] is False
        assert READ_VIEWS in replies[0]["result"]["content"][0]["text"]

    def test_the_spend_report_says_what_the_session_used(self, git_repo, tmp_path):
        server = build_server(root=git_repo, tool_set=REVIEWER, max_tool_calls=10)
        call(server, 1, "list_directory")
        call(server, 2, "git_log")

        target = tmp_path / "nested" / "spend.json"
        mcp_server._write_spend_report(target, server)

        assert json.loads(target.read_text()) == {
            "label": REVIEWER, "ceiling": 10, "spent": 2,
            "refused_for_budget": False,
        }

    def test_an_unwritable_spend_report_does_not_fail_the_review(self, git_repo,
                                                                tmp_path):
        """Accounting must not turn a completed review into a failure. The
        report says how many searches ran; the review already happened."""
        blocker = tmp_path / "blocker"
        blocker.write_text("not a directory")
        server = build_server(root=git_repo, tool_set=REVIEWER, max_tool_calls=10)

        mcp_server._write_spend_report(blocker / "spend.json", server)  # no raise


@pytest.fixture
def verifier(git_repo):
    return build_server(root=git_repo, tool_set=VERIFIER, max_tool_calls=10)


class TestHandshake:
    def test_initialize_declares_the_version_and_the_tools_capability(self, reviewer):
        """A handshake missing either field leaves the client with no tools.

        The CLI decides whether to ask for a tool list from what comes back
        here; a server that answers with an empty capability set is accepted
        and then never used, which looks like a review that found nothing.
        """
        (reply,) = drive(reviewer, line(1, "initialize", protocolVersion=PROTOCOL_VERSION))

        assert reply["id"] == 1
        assert reply["jsonrpc"] == "2.0"
        assert reply["result"]["protocolVersion"] == PROTOCOL_VERSION
        assert "tools" in reply["result"]["capabilities"]
        assert reply["result"]["serverInfo"]["name"]

    def test_a_client_asking_for_another_version_still_gets_ours(self, reviewer):
        """Answering with the client's version would claim a dialect we do not speak."""
        (reply,) = drive(reviewer, line(1, "initialize", protocolVersion="1999-01-01"))

        assert reply["result"]["protocolVersion"] == PROTOCOL_VERSION

    def test_the_initialized_notification_is_not_answered(self, reviewer):
        """Replying to a notification is a protocol violation, not a courtesy.

        A response carrying no id — or worse, a fabricated one — desynchronises
        a client that is matching replies to requests, and every later answer is
        read against the wrong request.
        """
        raw = transcript(
            reviewer,
            json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}),
            line(2, "ping"),
        )

        replies = [json.loads(text) for text in raw.splitlines() if text.strip()]
        assert [r["id"] for r in replies] == [2]

    def test_ping_is_answered(self, reviewer):
        """An unanswered keepalive makes a working server look dead mid-review."""
        (reply,) = drive(reviewer, line(7, "ping"))

        assert reply["result"] == {}


class TestToolList:
    def test_the_reviewer_set_can_report_and_finish(self, reviewer):
        """Without these two the CLI can investigate and never record anything."""
        (reply,) = drive(reviewer, line(1, "tools/list"))

        names = [tool["name"] for tool in reply["result"]["tools"]]
        assert "report_finding" in names
        assert "finish_review" in names
        assert "read_file" in names
        assert "submit_verdict" not in names

    def test_the_verifier_set_can_vote_and_cannot_report(self, verifier):
        """A verifier able to report findings could create the claim it judges.

        Its independence is the whole reason the panel exists; a set that leaks
        `report_finding` turns a second opinion into a second author.
        """
        (reply,) = drive(verifier, line(1, "tools/list"))

        names = [tool["name"] for tool in reply["result"]["tools"]]
        assert "submit_verdict" in names
        assert "report_finding" not in names
        assert "finish_review" not in names
        assert "search_code" in names

    def test_tools_are_rendered_in_mcp_shape(self, reviewer):
        """`input_schema` and `strict` are the Messages API's spelling.

        Forwarding them sends fields no MCP client is required to understand,
        and a client that validates the list strictly rejects all of it — every
        tool lost over a key nobody reads.
        """
        (reply,) = drive(reviewer, line(1, "tools/list"))

        for tool in reply["result"]["tools"]:
            assert set(tool) == {"name", "description", "inputSchema"}
            assert tool["inputSchema"]["type"] == "object"

    def test_the_diff_tools_appear_only_with_a_base(self, git_repo):
        """Offering `get_diff` with no base spends a call to learn there is none."""
        without = build_server(root=git_repo, tool_set=REVIEWER)
        with_base = build_server(root=git_repo, diff_base="HEAD", tool_set=REVIEWER)

        (bare,) = drive(without, line(1, "tools/list"))
        (ranged,) = drive(with_base, line(1, "tools/list"))

        assert "get_diff" not in [t["name"] for t in bare["result"]["tools"]]
        assert "get_diff" in [t["name"] for t in ranged["result"]["tools"]]


class TestToolCall:
    def test_read_file_returns_the_file_from_the_repository(self, reviewer):
        """The end of the chain: a client's bytes reach git and come back.

        Every other test here could pass with a server that never touched the
        workspace.
        """
        (reply,) = call(reviewer, 1, "read_file", path="app/views.py")

        result = reply["result"]
        assert result["isError"] is False
        assert READ_VIEWS in result["content"][0]["text"]
        assert result["content"][0]["type"] == "text"

    def test_the_call_is_recorded_in_our_own_session(self, reviewer):
        """The exposure journal must survive the change of runner.

        `Session` is what answers "were these bytes ever put in front of the
        model" — the difference between a review that resisted a payload and one
        that was never shown it. A bridge that built a fresh session per call
        would answer no to everything, and nothing else would look wrong.
        """
        call(reviewer, 1, "read_file", path="app/views.py")

        assert ("app/views.py", "read_file") in reviewer.session.exposures

    def test_a_tool_outside_the_offered_set_is_refused(self, verifier):
        """`dispatch()` would run this one. The offered set is what stops it.

        `report_finding` is in the handler table for the reviewer's sake, so a
        verifier session reaching `dispatch()` with that name would record a
        finding — the claim it was convened to judge, written by the judge.
        """
        assert "report_finding" in tools_module.HANDLERS

        (reply,) = call(verifier, 1, "report_finding", title="anything")

        assert reply["error"]["code"] == INVALID_PARAMS
        assert "report_finding" in reply["error"]["message"]
        assert verifier.session.candidates == []

    def test_a_tool_nobody_implements_is_refused(self, reviewer):
        (reply,) = call(reviewer, 1, "run_shell", command="id")

        assert reply["error"]["code"] == INVALID_PARAMS

    def test_a_call_with_no_arguments_still_runs(self, reviewer):
        """Omitting `arguments` entirely is legal MCP for a no-argument tool."""
        (reply,) = drive(reviewer, line(1, "tools/call", name="git_log"))

        assert reply["result"]["isError"] is False


class TestSurvival:
    def test_malformed_json_is_answered_and_the_next_line_still_works(self, reviewer):
        """Unparseable input must not be the quietest failure in the system.

        Silence would leave the client blocked on a read, which renders as a
        review still in progress; and a server that gave up on the bad line
        would drop the good request behind it. Making input less parseable can
        never be allowed to make the failure less visible.
        """
        replies = drive(
            reviewer,
            "{not json at all",
            line(2, "tools/call", name="read_file", arguments={"path": "app/views.py"}),
        )

        assert len(replies) == 2
        assert replies[0]["error"]["code"] == PARSE_ERROR
        assert replies[0]["id"] is None
        assert replies[1]["id"] == 2
        assert READ_VIEWS in replies[1]["result"]["content"][0]["text"]

    def test_a_blank_line_is_framing_and_not_an_error(self, reviewer):
        """An idle client sending newlines should not be reported as broken."""
        replies = drive(reviewer, "", "   ", line(3, "ping"))

        assert [r["id"] for r in replies] == [3]

    def test_a_handler_that_raises_becomes_an_error_result(self, reviewer, monkeypatch):
        """A raising tool must cost one call, not the whole review."""
        def explode(ws, session, args):
            raise RuntimeError("disk on fire")

        monkeypatch.setitem(tools_module.HANDLERS, "git_log", explode)

        replies = drive(
            reviewer,
            line(1, "tools/call", name="git_log", arguments={}),
            line(2, "ping"),
        )

        assert replies[0]["result"]["isError"] is True
        assert "disk on fire" in replies[0]["result"]["content"][0]["text"]
        assert replies[1]["id"] == 2

    def test_a_failure_above_dispatch_becomes_an_error_result(self, reviewer, monkeypatch):
        """`dispatch()` converts its own failures; this layer must convert the rest.

        Anything raised between the request and the handler — a bad conversion,
        a change in `dispatch`'s own contract — would otherwise kill the process
        and leave the client waiting on a pipe with nothing to report.
        """
        def explode(ws, session, name, args):
            raise ValueError("conversion broke")

        monkeypatch.setattr(mcp_server, "dispatch", explode)

        replies = drive(
            reviewer,
            line(1, "tools/call", name="read_file", arguments={"path": "app/views.py"}),
            line(2, "ping"),
        )

        assert replies[0]["result"]["isError"] is True
        assert "conversion broke" in replies[0]["result"]["content"][0]["text"]
        assert replies[1]["result"] == {}

    def test_an_unknown_method_is_a_method_not_found(self, reviewer):
        replies = drive(reviewer, line(1, "resources/list"), line(2, "ping"))

        assert replies[0]["error"]["code"] == METHOD_NOT_FOUND
        assert replies[1]["id"] == 2

    def test_a_batch_is_rejected_rather_than_half_understood(self, reviewer):
        """Batching left MCP in this revision; pretending to support it invents a shape."""
        (reply,) = drive(reviewer, json.dumps([{"jsonrpc": "2.0", "id": 1, "method": "ping"}]))

        assert reply["error"]["code"] == mcp_server.INVALID_REQUEST


class TestBudget:
    def test_exhaustion_is_an_error_result_that_says_so(self, git_repo):
        """Running out of budget must never read as a finished search.

        A crash here would end the client's loop with no explanation, and a
        silent empty result would be recorded as "nothing found" — the exact
        failure this project exists to prevent. The message has to name the
        budget so the transcript shows why the review stopped.
        """
        server = build_server(root=git_repo, tool_set=REVIEWER, max_tool_calls=1)

        first = call(server, 1, "read_file", path="app/views.py")[0]
        second = call(server, 2, "read_file", path="app/views.py")[0]

        assert first["result"]["isError"] is False
        assert second["result"]["isError"] is True
        text = second["result"]["content"][0]["text"].lower()
        assert "budget" in text
        assert "clean result" in text

    def test_the_server_keeps_answering_after_the_budget_is_gone(self, git_repo):
        """The client still has to be able to shut down cleanly."""
        server = build_server(root=git_repo, tool_set=REVIEWER, max_tool_calls=1)
        call(server, 1, "git_log")

        replies = drive(server, line(2, "ping"), line(3, "tools/list"))

        assert replies[0]["result"] == {}
        assert replies[1]["result"]["tools"]

    def test_the_process_exits_two_when_a_call_was_refused(self, git_repo,
                                                           monkeypatch, capfd):
        """A session that was cut short must not exit like one that finished.

        Driven through `main()` because the exit code is produced there, and
        with `capfd` rather than `capsys` because `main` now claims file
        descriptor 1 and refuses to start without real descriptors. `capsys`
        replaces the stream objects and leaves no descriptor behind, which is
        precisely the environment the production path is not allowed to run in.
        """
        request = line(1, "tools/call", name="git_log", arguments={})
        monkeypatch.setattr("sys.stdin", io.StringIO(request + "\n" + request + "\n"))

        code = mcp_server.main([
            "--repo", str(git_repo), "--tools", "verifier", "--max-tool-calls", "1"])

        assert code == 2
        assert '"isError": true' in capfd.readouterr().out

    def test_the_production_command_will_not_start_without_a_real_descriptor(
            self, git_repo, monkeypatch, caplog):
        """Fail closed, not degraded.

        A server that came up with weaker containment than it was written to
        have is a server nobody looks at again. `capsys` is the environment
        being simulated: streams that are objects with no `fileno`.
        """
        monkeypatch.setattr("sys.stdin", io.StringIO(""))
        monkeypatch.setattr("sys.stderr", io.StringIO())

        assert mcp_server.main(["--repo", str(git_repo)]) == 2
        assert "could not be claimed" in caplog.text

    def test_the_process_exits_zero_when_the_ceiling_was_merely_reached(
            self, git_repo, monkeypatch):
        """Spending the last permitted call is not being refused one.

        Exit 2 for a session that got everything it asked for would train the
        parent to ignore the signal, which is how a truncation gets through.
        """
        monkeypatch.setattr(
            "sys.stdin", io.StringIO(line(1, "tools/call", name="git_log", arguments={}) + "\n"))

        assert mcp_server.main([
            "--repo", str(git_repo), "--tools", "verifier", "--max-tool-calls", "1"]) == 0

    def test_a_refused_name_still_spends_a_call(self, verifier):
        """Otherwise a client can loop on a misspelled tool for free.

        `budget.py` documents one rule — an attempt counts whether it succeeds,
        fails validation, or is refused — and a runner that counted differently
        would put a different meaning behind the same number in the report.
        """
        call(verifier, 1, "report_finding", title="anything")

        assert verifier.allowance.spent == 1


class TestStdoutIsProtocolOnly:
    def test_a_tool_that_prints_does_not_corrupt_the_stream(self, reviewer, capsys):
        """One stray `print` in a tool turns every later reply into garbage.

        What the client reports is a protocol error, which is indistinguishable
        from the tool having failed and points the reader at the wrong file. So
        stdout is redirected while the loop runs, and the noise lands on stderr
        where it belongs.
        """
        def chatty(ws, session, args):
            print("noise on the protocol stream")
            return ToolResult("done", "chatty")

        original = tools_module.HANDLERS["git_log"]
        tools_module.HANDLERS["git_log"] = chatty
        try:
            raw = transcript(
                reviewer,
                line(1, "tools/call", name="git_log", arguments={}),
                line(2, "ping"),
            )
        finally:
            tools_module.HANDLERS["git_log"] = original

        assert "noise" not in raw
        replies = [json.loads(text) for text in raw.splitlines() if text.strip()]
        assert [r["id"] for r in replies] == [1, 2]
        assert replies[0]["result"]["content"][0]["text"] == "done"
        assert "noise on the protocol stream" in capsys.readouterr().err
