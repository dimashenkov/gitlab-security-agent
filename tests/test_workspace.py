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
        with pytest.raises(WorkspaceError, match="does not exist"):
            ws.read_file("app/nope.py")

    def test_rejects_a_directory(self, ws):
        with pytest.raises(WorkspaceError, match="is a directory"):
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
