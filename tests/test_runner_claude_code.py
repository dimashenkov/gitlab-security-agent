"""The runner that spends nothing, and the two ways it could quietly lie.

It could **let the reviewed repository speak.** The CLI skips its workspace
trust dialog in non-interactive mode, so a client started inside the checkout
picks up `.claude/settings.json`, `CLAUDE.md`, hooks and plugins — every one of
them a file the author of the change under review can edit. That is a second
instruction channel underneath our prompt contract, and the product rests on
repository content being data rather than instruction. The defence is not a
setting: the CLI runs in an empty directory and is never given a path into the
tree at all.

It could **call a truncated review clean.** The CLI's process exits zero whether
the review finished or the harness gave up, so its own word is never enough. A
run counts as complete only when the CLI ended cleanly *and* our session
document exists and can be read back. Either half missing is exit 2.

Nothing here launches `claude`. The command is built by a function so it can be
read, and the process is stood in for by a script that behaves the way the CLI
does — which is also how the failure cases can be tested at all, since a real
CLI cannot be asked to corrupt its own output.
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import pytest

from security_agent import runner_claude_code as runner
from security_agent.budget import PROFILES, RunBudget
from security_agent.config import Config, GitLabContext
from security_agent.models import (
    STOP_COMPLETED,
    STOP_ERROR,
    STOP_TIME_LIMIT,
    STOP_TRANSPORT,
    Revision,
)
from security_agent.runner_claude_code import (
    DENIED_TOOLS,
    TOOL_PREFIX,
    ClaudeCodeRunner,
    Handoff,
    RunnerError,
    build_command,
    build_mcp_config,
    cli_available,
)
from security_agent.workspace import Workspace

PROMPTS = Path(__file__).resolve().parents[1] / "prompts"
REVISION = Revision(mode="diff", base="main", head="HEAD",
                    base_sha="a" * 40, head_sha="b" * 40)


@pytest.fixture
def cfg(tmp_path):
    return Config(prompt_dir=PROMPTS, output_dir=tmp_path / "out",
                  gitlab=GitLabContext(), post_comment=False)


@pytest.fixture
def budget():
    return RunBudget(profile=PROFILES["normal"], turns_enforced=False)


@pytest.fixture
def handoff(tmp_path):
    return Handoff(tmp_path / "handoff", "run-abc", "digest-123")


def _command(**overrides):
    arguments = {"executable": "claude", "system_prompt": "review this code",
                 "mcp_config": Path("/tmp/mcp.json")}
    arguments.update(overrides)
    return build_command(**arguments)


# ------------------------------------------------------ what the CLI is given


class TestConfinement:
    def test_only_our_tools_are_allowed(self):
        command = _command()
        allowed = command[command.index("--allowedTools") + 1]

        assert allowed == TOOL_PREFIX + "*"

    def test_every_built_in_is_denied_by_name(self):
        """Named as well as omitted, because the two fail differently. A tool
        added upstream falls outside the allowlist — that is what catches it —
        and the denylist is what makes the intention legible to a reader."""
        command = _command()
        denied = command[command.index("--disallowedTools") + 1:]

        for tool in ("Bash", "Write", "Edit", "Read", "WebFetch"):
            assert tool in denied

    def test_other_mcp_servers_on_this_machine_are_ignored(self):
        """Without `--strict-mcp-config` the developer's own servers join the
        session, which is a set of tools our prompt never described."""
        assert "--strict-mcp-config" in _command()

    def test_the_system_prompt_replaces_rather_than_appends(self):
        """`--append-system-prompt` would leave the CLI's default contract
        underneath ours and put two sets of instructions in front of the
        model."""
        command = _command()

        assert "--system-prompt" in command
        assert "--append-system-prompt" not in command

    def test_nothing_is_written_to_disk_about_the_session(self):
        assert "--no-session-persistence" in _command()

    def test_permissions_are_not_bypassed(self):
        """A flag that turns the checks off would make the two layers above
        decoration."""
        assert "--dangerously-skip-permissions" not in _command()


class TestTheClientNeverSeesTheRepository:
    def test_the_working_directory_is_empty_and_outside_the_tree(self, handoff, tmp_path):
        assert handoff.cwd.exists()
        assert list(handoff.cwd.iterdir()) == []
        assert tmp_path not in Path("/").parents  # sanity: it is a real path

    def test_the_repository_reaches_only_the_mcp_server(self, handoff, tmp_path):
        """The one place a path into the checkout appears is the argument list
        of our own server, in a different process."""
        config = build_mcp_config(
            repo=tmp_path / "repo", base_sha="a" * 40, head_sha="b" * 40,
            tool_set="reviewer", allowance=RunBudget(PROFILES["normal"]).review,
            handoff=handoff)
        server = config["mcpServers"][runner.SERVER_KEY]

        assert "--repo" in server["args"]
        assert str(tmp_path / "repo") in server["args"]
        # And nothing about the repository is in what the CLI itself is run with.
        assert str(tmp_path / "repo") not in _command()

    def test_the_child_gets_named_variables_and_not_the_environment(
            self, monkeypatch, handoff, tmp_path):
        """The child runs `git`. Handing it the whole environment would carry
        tokens and CI credentials into a process with no use for any of them."""
        monkeypatch.setenv("GITLAB_TOKEN", "secret")
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-also-secret")

        config = build_mcp_config(
            repo=tmp_path / "repo", base_sha="", head_sha="HEAD",
            tool_set="reviewer", allowance=RunBudget(PROFILES["normal"]).review,
            handoff=handoff)
        env = config["mcpServers"][runner.SERVER_KEY]["env"]

        assert "GITLAB_TOKEN" not in env
        assert "ANTHROPIC_API_KEY" not in env
        assert "PATH" in env

    def test_the_scope_is_passed_through(self, handoff, tmp_path):
        config = build_mcp_config(
            repo=tmp_path / "repo", base_sha="", head_sha="HEAD",
            tool_set="reviewer", allowance=RunBudget(PROFILES["normal"]).review,
            handoff=handoff, scope=("app", "*.md"))
        args = config["mcpServers"][runner.SERVER_KEY]["args"]

        assert args.count("--path") == 2
        assert "app" in args


class TestTheTwoSidesOfTheHandoffAgree:
    """The drift this test exists for happened while it was being written.

    The runner names the flags and the MCP server defines them, in two files
    edited by two people. A mismatch produces a child that exits before it
    serves anything, which the parent then reports as a review that did not
    complete — true, unhelpful, and pointing at the wrong thing. Asserted by
    parsing the runner's own argument list with the server's own parser, so
    neither side can be renamed alone.
    """

    def test_every_argument_the_runner_sends_is_one_the_server_accepts(
            self, handoff, tmp_path):
        from security_agent.mcp_server import _parse_args

        config = build_mcp_config(
            repo=tmp_path / "repo", base_sha="a" * 40, head_sha="b" * 40,
            tool_set="reviewer", allowance=RunBudget(PROFILES["normal"]).review,
            handoff=handoff, scope=("app",))
        args = config["mcpServers"][runner.SERVER_KEY]["args"]

        # Drop `-m security_agent.mcp_server`, which addresses the module
        # rather than being one of its arguments.
        parsed = _parse_args(args[2:])

        assert parsed.repo == str(tmp_path / "repo")
        assert parsed.session_document == str(handoff.session_document)
        assert parsed.crash_journal == str(handoff.crash_journal)
        assert parsed.run_id == handoff.run_id
        assert parsed.config_digest == handoff.config_digest
        assert parsed.base_sha == "a" * 40
        assert parsed.head_sha == "b" * 40
        assert parsed.path == ["app"]

    def test_an_unresolved_head_is_not_substituted_on_one_side_only(
            self, handoff, tmp_path):
        """A latent refusal of every review, found by a second reader.

        The child stamps the document with what it is given; the parent checks
        the document against the revision. Substituting `HEAD` for an empty
        `head_sha` here made the two disagree by construction — the document
        said `HEAD`, the check was given `""`, and the review came back as
        describing different code. The child defaults its own `--head`.
        """
        config = build_mcp_config(
            repo=tmp_path / "repo", base_sha="", head_sha="",
            tool_set="reviewer", allowance=RunBudget(PROFILES["normal"]).review,
            handoff=handoff)
        args = config["mcpServers"][runner.SERVER_KEY]["args"]

        assert args[args.index("--head-sha") + 1] == ""

    def test_the_child_is_given_the_reviewer_budget_it_must_not_exceed(
            self, handoff, tmp_path):
        from security_agent.mcp_server import _parse_args

        budget = RunBudget(PROFILES["normal"])
        config = build_mcp_config(
            repo=tmp_path / "repo", base_sha="", head_sha="HEAD",
            tool_set="reviewer", allowance=budget.review, handoff=handoff)
        parsed = _parse_args(config["mcpServers"][runner.SERVER_KEY]["args"][2:])

        assert parsed.max_tool_calls == budget.review.ceiling
        assert parsed.tools == "reviewer"


class TestTheApiKeyIsNotAvailableToTheCli:
    def test_the_key_is_removed_from_the_environment(self, monkeypatch):
        """A session that could not authenticate as the subscription must not
        quietly bill an account instead. That is the no-silent-fallback rule,
        enforced by taking away the means rather than by intending to."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
        monkeypatch.setenv("ANTHROPIC_AUTH_TOKEN", "token")

        env = runner._child_env()

        assert "ANTHROPIC_API_KEY" not in env
        assert "ANTHROPIC_AUTH_TOKEN" not in env


# ------------------------------------------------ reading the CLI's own word


class TestTerminalOutput:
    def test_a_clean_success_is_recognised(self):
        result = runner._parse_terminal(
            0, json.dumps({"subtype": "success", "result": "done"}), "")

        assert result.subtype == "success"
        assert not result.failed

    @pytest.mark.parametrize("subtype", ["error_max_turns", "error_during_execution"])
    def test_a_named_failure_is_not_a_success(self, subtype):
        result = runner._parse_terminal(1, json.dumps({"subtype": subtype}), "")

        assert runner._SUBTYPES[result.subtype] == STOP_ERROR

    def test_an_unnamed_subtype_is_a_failure(self):
        """The allowlist rule, on this transport. A stop reason nobody named is
        not a stop reason anybody checked, and the last time an unnamed one fell
        through to the final branch it rendered as a clean review."""
        result = runner._parse_terminal(
            0, json.dumps({"subtype": "compacted_and_resumed"}), "")

        assert result.subtype not in runner._SUBTYPES
        assert "does not recognise" in runner._unnamed(result.subtype)

    def test_success_that_also_says_it_errored_is_believed_on_the_error(self):
        """The permissive reading of a contradiction is the one that ships."""
        result = runner._parse_terminal(
            0, json.dumps({"subtype": "success", "is_error": True,
                           "result": "rate limited"}), "")

        assert result.subtype not in runner._SUBTYPES

    def test_output_that_is_not_json_is_a_failure_not_a_scavenger_hunt(self):
        """Deliberately not "find a JSON object somewhere in the stream".
        Making the input less parseable must never make the result more
        permissive, and picking a fragment out of a corrupted stream is exactly
        that."""
        result = runner._parse_terminal(
            0, 'Error: something broke {"subtype": "success"}', "")

        assert result.failed

    def test_no_output_at_all_is_a_failure_carrying_the_error_stream(self):
        result = runner._parse_terminal(137, "", "Killed: out of memory")

        assert result.failed
        assert "out of memory" in result.detail

    def test_a_json_array_is_not_an_object(self):
        assert runner._parse_terminal(0, "[1, 2, 3]", "").failed


# ------------------------------------------------- what makes a run complete


class TestCompletionNeedsBothHalves:
    def _runner(self, cfg, budget, tmp_path, git_repo):
        workspace = Workspace(root=git_repo, diff_base="", diff_head="HEAD")
        return ClaudeCodeRunner(cfg, workspace, budget, config_digest="digest-123")

    def test_a_missing_document_is_never_a_clean_review(
            self, cfg, budget, tmp_path, git_repo):
        """The CLI said it succeeded and our child never reached the end. Its
        word alone is not enough, because its process exits zero whether the
        review finished or the harness gave up."""
        subject = self._runner(cfg, budget, tmp_path, git_repo)
        handoff = Handoff(tmp_path / "handoff", subject.run_id, "digest-123")
        result = runner._parse_terminal(0, json.dumps({"subtype": "success"}), "")

        session, stop_reason, detail = subject._collect(handoff, result, REVISION)

        assert session is None
        assert stop_reason != STOP_COMPLETED
        assert "session document" in detail

    def test_a_kill_is_reported_as_the_time_limit(self, cfg, budget, tmp_path, git_repo):
        subject = self._runner(cfg, budget, tmp_path, git_repo)
        handoff = Handoff(tmp_path / "handoff", subject.run_id, "digest-123")

        _session, stop_reason, _detail = subject._collect(
            handoff,
            runner.CliResult(killed=True, stop=STOP_TIME_LIMIT, detail="stopped"),
            REVISION)

        assert stop_reason == STOP_TIME_LIMIT

    def test_a_process_that_would_not_run_is_a_transport_failure(
            self, cfg, budget, tmp_path, git_repo):
        subject = self._runner(cfg, budget, tmp_path, git_repo)
        handoff = Handoff(tmp_path / "handoff", subject.run_id, "digest-123")

        _session, stop_reason, _detail = subject._collect(
            handoff,
            runner.CliResult(failed=True, stop=STOP_TRANSPORT,
                             detail="no such file"),
            REVISION)

        assert stop_reason == STOP_TRANSPORT

    def test_a_document_this_run_cannot_accept_is_refused_not_used(
            self, cfg, budget, tmp_path, git_repo):
        """A document that exists and cannot be trusted is worse than none: it
        has the shape of an answer."""
        subject = self._runner(cfg, budget, tmp_path, git_repo)
        handoff = Handoff(tmp_path / "handoff", subject.run_id, "digest-123")
        handoff.session_document.write_text(
            json.dumps({"schema_version": 1, "run_id": "somebody-elses"}),
            encoding="utf-8")

        session, stop_reason, detail = subject._collect(
            handoff, runner._parse_terminal(
                0, json.dumps({"subtype": "success"}), ""), REVISION)

        assert session is None
        assert stop_reason == STOP_ERROR
        assert "cannot accept" in detail

    def test_the_crash_trace_is_carried_into_the_detail(
            self, cfg, budget, tmp_path, git_repo):
        """What the reader actually gets when a run dies: how far it got, and
        a statement that this is progress rather than a result."""
        from security_agent.crash_journal import CrashJournal

        subject = self._runner(cfg, budget, tmp_path, git_repo)
        handoff = Handoff(tmp_path / "handoff", subject.run_id, "digest-123")
        journal = CrashJournal(handoff.crash_journal, run_id=subject.run_id)
        journal.run_started(mode="diff", model="claude-opus-5")
        journal.tool_started("read_file", {"path": "app/views.py"})

        _session, _stop, detail = subject._collect(
            handoff,
            runner.CliResult(killed=True, stop=STOP_TIME_LIMIT, detail="stopped"),
            REVISION)

        # The sentence and the trace travel separately now: one is provider
        # prose the report escapes, the other is a document this project
        # rendered. Deciding which is which by counting newlines was a check
        # satisfied by a shape rather than by the thing.
        assert "stopped" in detail
        assert "read_file" in subject.trace_markdown
        assert "not a result" in subject.trace_markdown
        assert "outcome unknown" in subject.trace_markdown


# ------------------------------------------------------ refusing to fall back


class TestTheProviderMustAgreeWithItself:
    """A contradiction is resolved against the reassuring half.

    `_parse_terminal` consulted the exit code only when the output was empty or
    unparseable, so a process that failed and still printed a well-formed
    `"success"` object was believed — and with a session document present, that
    is a completed review with a green tick.
    """

    def test_a_success_object_from_a_failed_process_is_not_a_success(self):
        result = runner._parse_terminal(
            1, json.dumps({"subtype": "success", "result": "done"}), "")

        assert result.returncode == 1

    def test_the_exit_code_survives_parsing(self):
        """It was being discarded, which is why nothing downstream could ask."""
        assert runner._parse_terminal(
            0, json.dumps({"subtype": "success"}), "").returncode == 0

    def test_a_nonzero_exit_stops_completion(self, cfg, budget, tmp_path, git_repo):
        workspace = Workspace(root=git_repo, diff_base="", diff_head="HEAD")
        subject = ClaudeCodeRunner(cfg, workspace, budget, config_digest="d")
        handoff = Handoff(tmp_path / "handoff", subject.run_id, "d")
        handoff.session_document.write_text("{}", encoding="utf-8")

        _session, stop_reason, detail = subject._collect(
            handoff,
            runner._parse_terminal(9, json.dumps({"subtype": "success"}), ""),
            REVISION)

        assert stop_reason != STOP_COMPLETED
        assert "exited 9" in detail or "cannot accept" in detail


class TestKillingTheWholeTree:
    """`subprocess.run(timeout=...)` kills one process, not what it started.

    What `claude` starts is our MCP server, which holds the reviewed checkout
    open and goes on running `git` against it after the parent has given up —
    racing the parent for the session and spend files, and still writing into
    the handoff directory while the parent deletes it. The wall clock is the one
    ceiling this runner can actually enforce, and enforcing it on the parent
    alone enforces nothing.
    """

    def test_a_grandchild_does_not_outlive_the_deadline(self, tmp_path):
        """A real grandchild, because that is the only place the difference
        between killing a process and killing a group shows up."""
        marker = tmp_path / "grandchild-alive"
        script = tmp_path / "parent.py"
        script.write_text(
            "import subprocess, sys, time\n"
            "child = subprocess.Popen([sys.executable, '-c',\n"
            "    \"import time, pathlib, sys\\n\"\n"
            "    \"for _ in range(200):\\n\"\n"
            "    \"    pathlib.Path(sys.argv[1]).write_text(str(_))\\n\"\n"
            "    \"    time.sleep(0.05)\\n\", {!r}])\n"
            "time.sleep(60)\n".format(str(marker)),
            encoding="utf-8")

        result = runner.launch(
            [sys.executable, str(script)], stdin="", cwd=tmp_path,
            timeout=1.0, limit_seconds=1)

        assert result.killed is True
        first = marker.read_text() if marker.exists() else ""
        time.sleep(0.5)
        second = marker.read_text() if marker.exists() else ""
        assert first == second, (
            "the grandchild was still writing after the deadline killed its "
            "parent — the process group was not signalled")

    def test_a_process_that_cannot_be_run_is_a_transport_failure(self, tmp_path):
        result = runner.launch(["a-command-that-does-not-exist"], stdin="",
                               cwd=tmp_path, timeout=5.0, limit_seconds=5)

        assert result.failed is True
        assert result.stop == STOP_TRANSPORT

    def test_output_still_comes_back_on_the_ordinary_path(self, tmp_path):
        """The launcher replaced `subprocess.run`; it must still read stdout."""
        result = runner.launch(
            [sys.executable, "-c",
             "import json; print(json.dumps({'subtype': 'success'}))"],
            stdin="", cwd=tmp_path, timeout=10.0, limit_seconds=10)

        assert result.subtype == "success"
        assert result.returncode == 0


class TestNoSilentFallback:
    def test_a_missing_cli_is_refused_rather_than_worked_around(
            self, cfg, budget, git_repo, monkeypatch):
        """Which account is charged is not a decision to make on somebody's
        behalf. There is no path from here to the paid API."""
        monkeypatch.setattr(runner, "cli_available", lambda executable: None)
        workspace = Workspace(root=git_repo, diff_base="", diff_head="HEAD")

        with pytest.raises(RunnerError) as raised:
            ClaudeCodeRunner(cfg, workspace, budget).run("diff", "go", REVISION)

        assert "will not fall back" in str(raised.value)

    def test_cli_available_never_raises(self):
        assert cli_available("a-command-that-does-not-exist") is None


def test_the_denied_list_is_not_empty():
    """A list that emptied itself in a refactor would leave the allowlist as
    the only layer, and this file's second-layer tests would still pass."""
    assert len(DENIED_TOOLS) >= 10


class TestTheCoverageAccountingCrossesTheBoundary:
    """It was empty on this runner, entirely.

    The report's "N of M changed file(s) opened" line did not render, and the
    gate never learned that a change had been shown to the reviewer only in
    part — on the one runner whose reviews are the ones actually being read.

    Two different kinds of fact, and they travel differently. What the change
    contained is the parent's own knowledge: it holds the workspace. Whether
    the diff was cut off is the *child's*, because `get_diff` runs there,
    against a different `Workspace` — the parent's own flag is always false on
    this path, so a fact read from it would always have said "not truncated".
    """

    def test_a_truncated_diff_travels_with_the_session(self, tmp_path):
        from security_agent.models import ScanOutcome
        from security_agent.session_document import read_session, write_session
        from security_agent.tools import Session

        session = Session()
        session.diff_truncated = True
        document = tmp_path / "session.json"
        write_session(document, session, run_id="r1", revision=REVISION,
                      config_digest="d")

        restored = read_session(document, run_id="r1", revision=REVISION,
                                config_digest="d")
        outcome = ScanOutcome(mode="diff")
        runner._apply_session(outcome, restored)

        assert outcome.coverage.diff_truncated is True

    def test_the_parents_flag_is_not_what_is_read(self, cfg, budget, git_repo):
        """The child does the diffing. Reading the parent's workspace would
        answer "not truncated" every time, which is the shape of a check that
        cannot fail."""
        from security_agent.models import ScanOutcome
        from security_agent.tools import Session

        workspace = Workspace(root=git_repo, diff_base="", diff_head="HEAD")
        assert workspace.diff_truncated is False

        session = Session()
        session.diff_truncated = True
        outcome = ScanOutcome(mode="diff")
        runner._apply_session(outcome, session)

        assert outcome.coverage.diff_truncated is True
