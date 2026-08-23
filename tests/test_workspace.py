"""Tests for the sandbox boundary.

The agent reads code an untrusted contributor may have written, in a job holding
an API key and a GitLab token. Containment is not a nicety here, so the escape
attempts are tested explicitly rather than assumed.
"""

import pytest

from security_agent.workspace import Workspace, WorkspaceError


@pytest.fixture
def ws(git_repo):
    return Workspace(root=git_repo, excludes=("package-lock.json",))


class TestPathContainment:
    def test_rejects_traversal(self, ws):
        with pytest.raises(WorkspaceError, match="outside the repository"):
            ws.resolve("../../etc/passwd")

    def test_rejects_traversal_hidden_mid_path(self, ws):
        with pytest.raises(WorkspaceError, match="outside the repository"):
            ws.resolve("app/../../../etc/passwd")

    def test_rejects_a_symlink_pointing_out_of_the_tree(self, ws, git_repo):
        # Containment is checked after symlink resolution; a prefix check on the
        # unresolved path would let this through.
        (git_repo / "escape").symlink_to("/etc")
        with pytest.raises(WorkspaceError, match="outside the repository"):
            ws.resolve("escape/passwd")

    def test_accepts_a_leading_slash_as_repo_relative(self, ws, git_repo):
        # Models routinely write "/app/views.py" for "app/views.py"; that is a
        # formatting habit, not an escape attempt.
        assert ws.resolve("/app/views.py") == git_repo / "app" / "views.py"

    def test_rejects_an_empty_path(self, ws):
        with pytest.raises(WorkspaceError, match="must not be empty"):
            ws.resolve("")

    def test_allows_a_normal_path(self, ws, git_repo):
        assert ws.resolve("app/views.py") == git_repo / "app" / "views.py"


class TestReading:
    def test_reads_a_file_with_line_numbers(self, ws):
        body, trimmed = ws.read_file("app/views.py")
        assert not trimmed
        assert "1 | def get_user" in body
        assert "lines 1-3 of 3" in body

    def test_reads_a_window(self, ws):
        body, _ = ws.read_file("app/views.py", start_line=2, end_line=2)
        assert "lines 2-2 of 3" in body
        assert "def get_user" not in body

    def test_rejects_a_start_line_past_the_end(self, ws):
        with pytest.raises(WorkspaceError, match="past the end"):
            ws.read_file("app/views.py", start_line=99)

    def test_rejects_a_missing_file(self, ws):
        with pytest.raises(WorkspaceError, match="not a tracked file"):
            ws.read_file("app/nope.py")

    def test_rejects_a_directory(self, ws):
        # A directory is not a blob, so the revision lookup rejects it for the
        # same reason it rejects anything untracked.
        with pytest.raises(WorkspaceError, match="not a tracked file"):
            ws.read_file("app")

    def test_raw_text_has_no_line_numbers(self, ws):
        assert ws.raw_text("app/views.py").startswith("def get_user")


class TestListing:
    def test_lists_tracked_files(self, ws):
        assert "app/" in ws.list_directory()
        assert "README.md" in ws.list_directory()

    def test_applies_excludes(self, ws):
        assert "package-lock.json" not in ws.list_directory()
        assert "package-lock.json" not in ws.tracked_files()

    def test_lists_a_subdirectory(self, ws):
        assert "views.py" in ws.list_directory("app")

    def test_rejects_an_unknown_directory(self, ws):
        with pytest.raises(WorkspaceError):
            ws.list_directory("nope")


class TestSearch:
    def test_finds_matches_with_line_numbers(self, ws):
        body, count = ws.search("SELECT")
        assert count == 1
        assert "app/views.py:3" in body

    def test_reports_no_matches_without_failing(self, ws):
        # git grep exits 1 for "no matches", which is an answer, not an error.
        body, count = ws.search("zzzznotpresent")
        assert count == 0
        assert "no matches" in body

    def test_is_case_insensitive_by_default(self, ws):
        _, count = ws.search("select")
        assert count == 1

    def test_honours_case_sensitivity(self, ws):
        _, count = ws.search("select", case_sensitive=True)
        assert count == 0

    def test_rejects_an_empty_pattern(self, ws):
        with pytest.raises(WorkspaceError, match="must not be empty"):
            ws.search("")

    def test_excluded_files_do_not_appear(self, ws):
        _, count = ws.search("lockfileVersion")
        assert count == 0


class TestRepositoryRequirement:
    def test_refuses_a_directory_that_is_not_a_repository(self, tmp_path):
        with pytest.raises(WorkspaceError, match="not a git repository"):
            Workspace(root=tmp_path)


class TestExcludes:
    def test_matches_a_bare_filename_pattern(self, git_repo):
        ws = Workspace(root=git_repo, excludes=("*.md",))
        assert ws.is_excluded("README.md")
        assert ws.is_excluded("docs/guide.md")

    def test_matches_a_directory_pattern_at_the_top_level(self, git_repo):
        ws = Workspace(root=git_repo, excludes=("*/vendor/*",))
        assert ws.is_excluded("vendor/lib.go")
        assert ws.is_excluded("src/vendor/lib.go")

    def test_leaves_other_paths_alone(self, git_repo):
        ws = Workspace(root=git_repo, excludes=("*.md",))
        assert not ws.is_excluded("app/views.py")


class TestGitEnvironment:
    """The environment git subprocesses run in.

    Both halves are load-bearing and they pull against each other: the config
    files must not be trusted, and the ownership check must still be waived. A
    CI run found that out the hard way — hardening the config away also removed
    the `safe.directory` that made a root-owned checkout readable, and the agent
    reported "cannot determine a diff base" for a commit that was right there.
    """

    def test_repository_controlled_config_is_not_read(self):
        from security_agent.workspace import _git_env

        env = _git_env()
        assert env["GIT_CONFIG_GLOBAL"] == "/dev/null"
        assert env["GIT_CONFIG_SYSTEM"] == "/dev/null"
        # HOME must not point into a repository, or a committed .gitconfig
        # becomes the agent's configuration.
        assert env["HOME"] == "/nonexistent"

    def test_ownership_check_is_waived_without_a_config_file(self):
        from security_agent.workspace import _git_env

        env = _git_env()
        assert env["GIT_CONFIG_COUNT"] == "1"
        assert env["GIT_CONFIG_KEY_0"] == "safe.directory"
        assert env["GIT_CONFIG_VALUE_0"] == "*"

    def test_git_still_works_through_this_environment(self, git_repo):
        # The settings above are only correct if git actually accepts them.
        ws = Workspace(root=git_repo, excludes=())
        assert ws.rev_exists("HEAD")
        assert "views.py" in ws.git("ls-files")

    def test_a_missing_revision_is_still_reported_as_missing(self, git_repo):
        ws = Workspace(root=git_repo, excludes=())
        assert not ws.rev_exists("0" * 40)
        assert not ws.rev_exists("")


class TestReadsTheRevisionNotTheDisk:
    """Files come from the object database, not from the working tree.

    The checkout is material an untrusted contributor controls, and what sits at
    a path on disk need not be what the commit says is there — a symlink, a file
    an earlier job step wrote, a filter driver. A finding has to describe the
    code actually proposed for merge.
    """

    def test_untracked_content_on_disk_is_not_readable(self, git_repo):
        ws = Workspace(root=git_repo, excludes=())
        (git_repo / "app" / "planted.py").write_text("SECRET = 'x'\n", encoding="utf-8")
        with pytest.raises(WorkspaceError, match="not a tracked file"):
            ws.read_file("app/planted.py")

    def test_a_modified_working_tree_does_not_change_what_is_read(self, git_repo):
        ws = Workspace(root=git_repo, excludes=())
        (git_repo / "app" / "views.py").write_text("# replaced after checkout\n",
                                                   encoding="utf-8")
        body, _ = ws.read_file("app/views.py")
        assert "replaced after checkout" not in body
        assert "SELECT * FROM users" in body

    def test_a_symlink_is_not_followed_to_its_target(self, git_repo):
        import subprocess

        env = {"PATH": "/usr/bin:/bin", "HOME": str(git_repo),
               "GIT_AUTHOR_NAME": "T", "GIT_AUTHOR_EMAIL": "t@e.com",
               "GIT_COMMITTER_NAME": "T", "GIT_COMMITTER_EMAIL": "t@e.com"}
        (git_repo / "link.py").symlink_to("/etc/hosts")
        subprocess.run(("git", "-C", str(git_repo), "add", "link.py"),
                       check=True, capture_output=True, env=env)
        subprocess.run(("git", "-C", str(git_repo), "commit", "-qm", "add link"),
                       check=True, capture_output=True, env=env)

        ws = Workspace(root=git_repo, excludes=())
        # git stores the link as its own blob — the target path — so what comes
        # back is the link text, never the contents of /etc/hosts.
        body, _ = ws.read_file("link.py")
        assert "/etc/hosts" in body
        assert "localhost" not in body

    def test_evidence_matching_uses_the_same_source(self, git_repo):
        ws = Workspace(root=git_repo, excludes=())
        (git_repo / "app" / "views.py").write_text("# replaced\n", encoding="utf-8")
        assert "SELECT * FROM users" in ws.raw_text("app/views.py")


class TestTreePathsAreCheckedLexically:
    """Naming a blob is a string operation, not a filesystem one.

    `resolve()` still guards filesystem access, but reads now address the git
    tree, where following a symlink to decide whether a path is allowed is both
    unnecessary and wrong — a committed symlink is an object we want to be able
    to look at.
    """

    def test_traversal_is_rejected(self, git_repo):
        ws = Workspace(root=git_repo, excludes=())
        for bad in ("../etc/passwd", "app/../../etc/passwd", "a/../../b"):
            with pytest.raises(WorkspaceError, match="outside the repository"):
                ws.repo_path(bad)

    def test_leading_slashes_and_dots_are_normalised(self, git_repo):
        ws = Workspace(root=git_repo, excludes=())
        assert ws.repo_path("/app/views.py") == "app/views.py"
        assert ws.repo_path("./app/./views.py") == "app/views.py"

    def test_empty_paths_are_rejected(self, git_repo):
        ws = Workspace(root=git_repo, excludes=())
        for bad in ("", "   ", "/", "./"):
            with pytest.raises(WorkspaceError, match="must not be empty"):
                ws.repo_path(bad)

    def test_it_does_not_touch_the_filesystem(self, git_repo):
        # A path that does not exist on disk still normalises; whether it is a
        # real blob is the revision's answer, given later and separately.
        ws = Workspace(root=git_repo, excludes=())
        assert ws.repo_path("does/not/exist.py") == "does/not/exist.py"
