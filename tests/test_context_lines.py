"""`SECURITY_SCAN_CONTEXT_LINES` was documented, read, stored, and ignored.

`Config.diff_context_lines` was set from the environment and read by nothing.
The number that reached git was a constant in `tools.py`, so an operator could
set the variable, see no warning, and believe the review had changed. That is
worse than an undocumented dead field: it is a control the documentation offers
and the code does not implement.

Found by `tools/unenforced.py`, which lists dataclass fields nothing outside
their declaring module reads — the same check that found `Profile.conclusive`
promising a profile could never conclude a review while nothing read it.

The chain is tested here, not the links. A test that only asserted
`Config.diff_context_lines == 40` would have passed throughout the defect.
"""
from __future__ import annotations

import pytest

from security_agent.config import Config
from security_agent.identity import review_identity
from security_agent.workspace import Workspace, WorkspaceError


@pytest.fixture
def changed(git_repo):
    """A second commit, so there is a diff whose context can be widened.

    The shared fixture stops at one commit, and `HEAD~1` against it produces an
    empty string — which two different settings agree on perfectly, so a test
    built on it would pass against the defect it exists to catch.
    """
    import subprocess

    env = {"GIT_AUTHOR_NAME": "Test", "GIT_AUTHOR_EMAIL": "t@example.com",
           "GIT_COMMITTER_NAME": "Test", "GIT_COMMITTER_EMAIL": "t@example.com",
           "PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": str(git_repo)}
    body = "\n".join("line {}".format(i) for i in range(60))
    (git_repo / "app" / "wide.py").write_text(body + "\n", encoding="utf-8")
    subprocess.run(("git", "-C", str(git_repo), "add", "-A"),
                   check=True, capture_output=True, env=env)
    subprocess.run(("git", "-C", str(git_repo), "commit", "-q", "-m", "one"),
                   check=True, capture_output=True, env=env)
    edited = body.replace("line 30", "line 30 changed")
    (git_repo / "app" / "wide.py").write_text(edited + "\n", encoding="utf-8")
    subprocess.run(("git", "-C", str(git_repo), "add", "-A"),
                   check=True, capture_output=True, env=env)
    subprocess.run(("git", "-C", str(git_repo), "commit", "-q", "-m", "two"),
                   check=True, capture_output=True, env=env)
    return git_repo


class TestTheSettingReachesGit:
    def test_the_configured_default_is_what_a_diff_carries(self, changed):
        """The whole point: change the setting, and git is asked for it.

        `--unified=` is what the number becomes, so asserting on the produced
        diff rather than on the stored field is what makes this a chain test.
        """
        wide = Workspace(root=changed, diff_base="HEAD~1",
                         default_context_lines=40)
        narrow = Workspace(root=changed, diff_base="HEAD~1",
                           default_context_lines=0)
        assert wide.diff() != narrow.diff()

    def test_an_explicit_request_still_wins(self, changed):
        """The model asked for a window on purpose; the setting is a default."""
        ws = Workspace(root=changed, diff_base="HEAD~1", default_context_lines=0)
        assert ws.diff(context_lines=40) != ws.diff()

    def test_omitting_the_argument_uses_the_configured_value(self, changed):
        ws = Workspace(root=changed, diff_base="HEAD~1", default_context_lines=40)
        assert ws.diff() == ws.diff(context_lines=40)

    def test_zero_is_a_real_value_and_not_a_missing_one(self, changed):
        """Hunks with no surrounding context is a coherent thing to ask for."""
        ws = Workspace(root=changed, diff_base="HEAD~1", default_context_lines=0)
        assert ws.diff() == ws.diff(context_lines=0)

    def test_a_negative_setting_is_refused_rather_than_clamped(self, git_repo):
        """It can only come from a typo, and reading it as 0 answers a question
        nobody asked."""
        with pytest.raises(WorkspaceError, match="cannot be negative"):
            Workspace(root=git_repo, default_context_lines=-1)


class TestItIsPartOfWhatTheReviewIs:
    """Two runs shown different amounts of code are not the same review.

    Without this an artifact produced at 12 could be reused for a run
    configured at 40, and the two could be compared as though the only
    difference were the code.
    """

    def test_the_identity_carries_it(self):
        identity = review_identity(Config(gitlab=None), None, None)
        assert "diff_context_lines" in identity["settings"]

    def test_two_settings_give_two_identities(self):
        twelve = review_identity(Config(gitlab=None, diff_context_lines=12), None, None)
        forty = review_identity(Config(gitlab=None, diff_context_lines=40), None, None)
        assert twelve != forty


class TestBothPathsGetIt:
    """A setting that works on one runner and not the other is worse than none.

    The Claude Code path runs its tools in a child process, so the value has to
    be passed rather than left to the inherited environment.
    """

    def test_the_child_is_told_the_number(self, tmp_path):
        from security_agent.budget import Allowance
        from security_agent.runner_claude_code import build_mcp_config

        class Handoff:
            run_id = "r"
            session_document = tmp_path / "doc.json"
            crash_journal = tmp_path / "j.jsonl"
            spend_report = tmp_path / "s.json"
            config_digest = "d"

        config = build_mcp_config(
            repo=tmp_path, base_sha="a" * 40, head_sha="b" * 40,
            tool_set="reviewer", allowance=Allowance("review", 10),
            handoff=Handoff(), context_lines=40)
        argv = next(iter(config["mcpServers"].values()))["args"]
        assert "--context-lines" in argv
        assert argv[argv.index("--context-lines") + 1] == "40"

    def test_the_child_parses_it(self):
        from security_agent.mcp_server import _parse_args
        assert _parse_args(["--repo", ".", "--context-lines", "40"]).context_lines == 40

    def test_the_child_defaults_to_twelve(self):
        from security_agent.mcp_server import _parse_args
        assert _parse_args(["--repo", "."]).context_lines == 12
