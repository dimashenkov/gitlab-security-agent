"""Tests for the sandbox boundary.

The agent reads code an untrusted contributor may have written, in a job holding
an API key and a GitLab token. Containment is not a nicety here, so the escape
attempts are tested explicitly rather than assumed.
"""

import pytest

from security_agent.tools import Session, dispatch
from security_agent.workspace import (
    MAX_READ_BYTES,
    FileNotAtRevision,
    FileTooLarge,
    Workspace,
    WorkspaceError,
)


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



def _injected(env):
    """The `GIT_CONFIG_*` settings, as a mapping.

    Every caller wants "is this setting pinned", and reading it off numbered
    keys by hand is how a test comes to assert the count instead.
    """
    count = int(env.get("GIT_CONFIG_COUNT", "0"))
    return {env["GIT_CONFIG_KEY_{}".format(i)]: env["GIT_CONFIG_VALUE_{}".format(i)]
            for i in range(count)}


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
        """Asserted as a setting that is present, not as a count.

        This read `GIT_CONFIG_COUNT == "1"` and broke the day a second setting
        was added for an unrelated reason. A test that fails when something is
        *added* teaches whoever adds it to edit the assertion, which is how the
        thing it was guarding stops being guarded.
        """
        from security_agent.workspace import _git_env

        assert _injected(_git_env())["safe.directory"] == "*"

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


class TestInputsNobodyHadTried:
    """Three shapes the audit found untested, each with a dead handler."""

    def test_a_binary_file_is_refused_with_a_reason(self, git_repo):
        """`workspace.py` raises "not UTF-8 text (binary file)" and no test
        had ever reached that line."""
        import subprocess

        env = {"GIT_AUTHOR_NAME": "T", "GIT_AUTHOR_EMAIL": "t@e.com",
               "GIT_COMMITTER_NAME": "T", "GIT_COMMITTER_EMAIL": "t@e.com",
               "PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": str(git_repo)}
        (git_repo / "logo.bin").write_bytes(bytes(range(256)) * 8)
        subprocess.run(("git", "-C", str(git_repo), "add", "-A"),
                       check=True, capture_output=True, env=env)
        subprocess.run(("git", "-C", str(git_repo), "commit", "-qm", "binary"),
                       check=True, capture_output=True, env=env)

        ws = Workspace(root=git_repo, excludes=())
        with pytest.raises(WorkspaceError) as caught:
            ws.read_file("logo.bin")
        assert "binary" in str(caught.value).lower()

    def test_a_git_timeout_becomes_a_named_failure_not_a_crash(self, git_repo, monkeypatch):
        """All three `TimeoutExpired` handlers were dead code to the suite. A
        crash here would exit 1 — "the code has blocking findings" — for a
        timeout."""
        import subprocess

        def slow(*args, **kwargs):
            raise subprocess.TimeoutExpired(cmd="git", timeout=1)

        monkeypatch.setattr(subprocess, "run", slow)
        ws = Workspace(root=git_repo, excludes=())
        with pytest.raises(WorkspaceError) as caught:
            ws.git("status")
        assert "timed out" in str(caught.value)

    def test_a_search_stops_at_the_ceiling_and_says_so(self, git_repo):
        """The streaming path exists so a huge result cannot be collected into
        memory whole — an OOM is a SIGKILL, and a killed process cannot report
        that the review did not complete."""
        import subprocess

        env = {"GIT_AUTHOR_NAME": "T", "GIT_AUTHOR_EMAIL": "t@e.com",
               "GIT_COMMITTER_NAME": "T", "GIT_COMMITTER_EMAIL": "t@e.com",
               "PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": str(git_repo)}
        (git_repo / "big.txt").write_text("needle here\n" * 40_000)
        subprocess.run(("git", "-C", str(git_repo), "add", "-A"),
                       check=True, capture_output=True, env=env)
        subprocess.run(("git", "-C", str(git_repo), "commit", "-qm", "big"),
                       check=True, capture_output=True, env=env)

        ws = Workspace(root=git_repo, excludes=())
        body, count = ws.search(pattern="needle", max_results=5)

        assert "at least" in body, body[:200]
        assert "the scan stopped here" in body
        # And it did not read forty thousand lines to say so.
        assert count < 40_000


class TestTheDiffIsBounded:
    """The one failure that defeats the exit-2 contract.

    `subprocess.run(capture_output=True)` reads the whole pipe before
    returning, and the size of a diff is chosen by whoever opened the merge
    request. An out-of-memory kill is a SIGKILL: `main`'s `except` never runs,
    no artifact is written, no comment is posted, and a previous run's green
    note stays on the merge request describing code that is no longer there.

    `search()` was hardened against exactly this and `diff()` was not — the
    reasoning was written down one function away and did not travel.
    """

    def _repo(self, tmp_path, blob):
        import subprocess as sp

        root = tmp_path / "repo"
        root.mkdir()
        sp.run(["git", "init", "-q", str(root)], check=True, capture_output=True)
        for key, value in (("user.email", "t@e.com"), ("user.name", "T")):
            sp.run(["git", "-C", str(root), "config", key, value], check=True,
                   capture_output=True)
        (root / "small.txt").write_text("one\n")
        sp.run(["git", "-C", str(root), "add", "-A"], check=True, capture_output=True)
        sp.run(["git", "-C", str(root), "commit", "-qm", "base"], check=True,
               capture_output=True)
        base = sp.run(["git", "-C", str(root), "rev-parse", "HEAD"],
                      capture_output=True, text=True, check=True).stdout.strip()
        (root / "big.txt").write_text(blob)
        sp.run(["git", "-C", str(root), "add", "-A"], check=True, capture_output=True)
        sp.run(["git", "-C", str(root), "commit", "-qm", "a large addition"],
               check=True, capture_output=True)
        return Workspace(root=root, diff_base=base, diff_head="HEAD")

    def test_a_large_diff_is_cut_off_and_says_so(self, tmp_path, monkeypatch):
        """Cut off, not merely trimmed after the fact — the ceiling is on what
        is ever resident, which is a different question from what the model is
        shown, with a different consequence."""
        monkeypatch.setattr(Workspace, "MAX_DIFF_BYTES", 50_000)
        ws = self._repo(tmp_path, "a line that repeats\n" * 40_000)

        body = ws.diff()

        # Bounded by the ceiling plus at most one read, not by the ceiling
        # exactly. Reading is chunked, so the check happens after a chunk has
        # arrived — stating the guarantee as "at most the ceiling" would be a
        # promise the code does not make and a test that fails on a chunk-size
        # change for no reason.
        assert len(body.encode("utf-8")) < 50_000 + 70_000
        assert len(body.encode("utf-8")) < len("a line that repeats\n") * 40_000
        assert "was cut off" in body
        assert "has not been fully reviewed" in body

    def test_an_ordinary_diff_is_returned_whole(self, tmp_path):
        """A ceiling that trimmed the ordinary case would make every review
        look truncated, and a warning on every run is a warning nobody reads."""
        ws = self._repo(tmp_path, "two\nthree\n")

        body = ws.diff()

        assert "big.txt" in body
        assert "was cut off" not in body

    def test_the_ceiling_is_derived_from_what_the_consumer_asks_for(self):
        """Not chosen for feeling roomy.

        The first version was eight megabytes, which is memory-safe and is
        unexplained work: `get_diff` trims to 120,000 characters before the
        model sees anything, so everything read past that has no review value.
        The ceiling is that number with room for worst-case multi-byte
        encoding, the diff's own headers, and one read of overshoot — and a
        genuine change that exceeds it is reported as a partial review, not as
        an abnormal change.
        """
        from security_agent.tools import MAX_DIFF_CHARS

        assert Workspace.MAX_DIFF_BYTES >= MAX_DIFF_CHARS * 4
        assert Workspace.MAX_DIFF_BYTES < MAX_DIFF_CHARS * 20

    def test_truncation_is_recorded_and_not_only_said(self, tmp_path, monkeypatch):
        """A sentence in the model's context is guidance, and an attacker can
        write the same sentence into a file. The flag is the accounting, and it
        is what the report and the artifact rely on."""
        monkeypatch.setattr(Workspace, "MAX_DIFF_BYTES", 50_000)
        ws = self._repo(tmp_path, "a line that repeats\n" * 40_000)

        assert ws.diff_truncated is False
        ws.diff()
        assert ws.diff_truncated is True


class TestTheReadCeilingSaysWhatItDoes:
    """`gpt-6-astra`, 2026-09-06. The refusal advised passing `start_line` and
    `end_line`, and `read_file` reached the file through `blob_text`, so the
    ceiling was on the whole blob and the window was refused identically — with
    the message repeating the suggestion that had just failed.

    Then the message was corrected to name no remedy, because there was none.
    Now there is one: the window is real, and these tests assert that instead.
    They were written against the defect and the defect is gone; what has to
    stay covered is that the advice a refusal gives *works*, which is the
    property both of the earlier versions broke in opposite directions.
    """

    def big_file(self, git_repo):
        import subprocess
        line = "# padding to push this file over the ceiling\n"
        (git_repo / "big.py").write_text(
            line * (MAX_READ_BYTES // len(line) + 40), encoding="utf-8")
        # Committed, because `blob_text` reads the revision and not the disk —
        # which is the point of that function and would otherwise make this
        # test refuse for the wrong reason.
        env = {"GIT_AUTHOR_NAME": "Test", "GIT_AUTHOR_EMAIL": "t@example.com",
               "GIT_COMMITTER_NAME": "Test",
               "GIT_COMMITTER_EMAIL": "t@example.com",
               "PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": str(git_repo)}
        for args in (("add", "big.py"), ("commit", "-qm", "big")):
            subprocess.run(("git", "-C", str(git_repo), *args), check=True,
                           capture_output=True, env=env)
        return "big.py"

    def test_the_whole_file_is_still_refused(self, ws, git_repo):
        """The ceiling on what is emitted has not moved."""
        path = self.big_file(git_repo)
        with pytest.raises(FileTooLarge) as caught:
            ws.read_file(path)
        assert "over the 292 KB limit" in str(caught.value)

    def test_the_window_the_message_advises_actually_works(self, ws, git_repo):
        """The defect, stated as the property it broke.

        The first version advised a window that was refused identically; the
        second advised nothing, because nothing worked. A refusal may only name
        a remedy it has checked is there — so the test takes the advice out of
        the message and follows it.
        """
        path = self.big_file(git_repo)
        with pytest.raises(FileTooLarge) as caught:
            ws.read_file(path)
        assert "start_line and end_line" in str(caught.value)

        body, _trimmed = ws.read_file(path, start_line=10, end_line=12)
        assert "lines 10-12" in body
        assert "    10 | # padding" in body

    def test_a_window_does_not_carry_the_rest_of_the_file(self, ws, git_repo):
        """Bounded by the window, not by the output cap after the fact.

        Slicing a file already in memory would answer this test the same way
        and would not have fixed anything, so the assertion is on the count of
        lines returned rather than on the size of the answer.
        """
        path = self.big_file(git_repo)
        body, trimmed = ws.read_file(path, start_line=100, end_line=104)
        assert not trimmed
        numbered = [ln for ln in body.splitlines() if "|" in ln]
        assert len(numbered) == 5
        assert "   100 |" in body and "   104 |" in body
        assert "    99 |" not in body and "   105 |" not in body

    def test_the_reported_total_is_measured_and_not_guessed(self, ws, git_repo):
        path = self.big_file(git_repo)
        body, _ = ws.read_file(path, start_line=1, end_line=2)
        line_count = MAX_READ_BYTES // len(
            "# padding to push this file over the ceiling\n") + 40
        assert "of {}".format(line_count) in body

    def test_a_window_past_the_end_is_a_refusal_and_not_an_empty_answer(
            self, ws, git_repo):
        """Absence is not agreement: no lines there is not "those lines are
        blank"."""
        path = self.big_file(git_repo)
        with pytest.raises(WorkspaceError, match="past the end"):
            ws.read_file(path, start_line=900_000, end_line=900_010)

    def test_a_backwards_window_is_refused(self, ws):
        with pytest.raises(WorkspaceError, match="before start_line"):
            ws.read_file("app/views.py", start_line=3, end_line=1)


class TestOneCeilingWasServingTwoPurposes:
    """Codex, 2026-09-07, on the design for windowed reading — and the
    measurements that answered it.

    `MAX_READ_BYTES` is a ceiling on what is *emitted to the model*; that is
    what its comment says it is for. Two readers of a blob emit none of it and
    were refused by it anyway, and one reader had no ceiling at all.
    """

    def env(self, root):
        return {"GIT_AUTHOR_NAME": "Test", "GIT_AUTHOR_EMAIL": "t@example.com",
                "GIT_COMMITTER_NAME": "Test",
                "GIT_COMMITTER_EMAIL": "t@example.com",
                "PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": str(root)}

    def git(self, root, *args):
        import subprocess
        return subprocess.run(("git", "-C", str(root), *args), check=True,
                              capture_output=True, text=True,
                              env=self.env(root)).stdout

    def a_large_deleted_file(self, git_repo, size=1_000_000):
        """A base holding a large file, and a change that removes it."""
        (git_repo / "vendor.py").write_text(
            "x = 1  # vendored padding\n" * (size // 25), encoding="utf-8")
        self.git(git_repo, "add", "-A")
        self.git(git_repo, "commit", "-qm", "vendor")
        base = self.git(git_repo, "rev-parse", "HEAD").strip()
        (git_repo / "vendor.py").unlink()
        self.git(git_repo, "add", "-A")
        self.git(git_repo, "commit", "-qm", "remove the vendored blob")
        head = self.git(git_repo, "rev-parse", "HEAD").strip()
        return Workspace(root=git_repo, diff_base=base, diff_head=head)

    def a_large_live_file(self, git_repo, size=700_000):
        (git_repo / "big.py").write_text(
            "y = 2  # padding\n" * (size // 17), encoding="utf-8")
        self.git(git_repo, "add", "-A")
        self.git(git_repo, "commit", "-qm", "big")
        head = self.git(git_repo, "rev-parse", "HEAD").strip()
        return Workspace(root=git_repo, diff_head=head)

    def test_the_deleted_file_reader_has_a_ceiling(self, git_repo,
                                                   monkeypatch):
        """It had none — measured, not argued.

        The same content was refused at 292 KB while it was live and returned
        whole once the change deleted it. The attacker chooses both the
        deletion and the size, and a merge request removing a large vendored
        blob looks ordinary. The ceiling is lowered here rather than a 9 MB
        file written, because what is under test is that a limit is consulted
        at all.
        """
        import security_agent.workspace as W
        ws = self.a_large_deleted_file(git_repo)
        monkeypatch.setattr(W, "MAX_LOCAL_SCAN_BYTES", 400_000)
        with pytest.raises(FileTooLarge) as caught:
            ws.removed_text("vendor.py")
        assert "over the 390 KB limit" in str(caught.value)

    def test_a_deleted_file_can_still_be_read_through_a_window(self, git_repo):
        """Bounded is not refused. The deletion is the finding, so the base
        content has to stay reachable."""
        ws = self.a_large_deleted_file(git_repo)
        body, _ = ws.read_removed_file("vendor.py", start_line=5, end_line=7)
        assert "at the base revision" in body
        assert "     5 | x = 1" in body
        assert "     8 |" not in body

    def test_the_citation_check_is_not_bounded_by_the_context_ceiling(
            self, git_repo):
        """`raw_text` emits nothing to the model and was refused by the
        ceiling on what is emitted.

        The consequence was a weakness that could be seen in the diff and not
        reported: the check could not open the file to confirm the quote, so
        the claim was dropped.
        """
        ws = self.a_large_live_file(git_repo)
        with pytest.raises(FileTooLarge):
            ws.read_file("big.py")          # still refused: this one is emitted
        assert len(ws.raw_text("big.py")) > MAX_READ_BYTES

    def test_the_local_ceiling_is_not_below_the_emitted_one(self):
        """Two constants that can drift, and the direction that would hurt.

        Lowering the local one below the emitted one would make the citation
        check stricter than reading — a file the reviewer can read and cannot
        cite, which is the defect this change removed, restored by an edit to
        a number.
        """
        from security_agent.workspace import MAX_LOCAL_SCAN_BYTES
        assert MAX_LOCAL_SCAN_BYTES >= MAX_READ_BYTES

    def test_a_head_read_sees_the_top_of_a_file_too_large_to_open(
            self, git_repo):
        """The generated-file classifier went blind on the file class it
        exists for: generated files are the large ones."""
        banner = "// Code generated by protoc-gen-go. DO NOT EDIT.\n"
        (git_repo / "pb.go").write_text(
            banner + "const X = 1  // padding\n" * 30_000, encoding="utf-8")
        self.git(git_repo, "add", "-A")
        self.git(git_repo, "commit", "-qm", "generated")
        head = self.git(git_repo, "rev-parse", "HEAD").strip()
        ws = Workspace(root=git_repo, diff_head=head)

        with pytest.raises(FileTooLarge):
            ws.read_file("pb.go")
        assert ws.head_text("pb.go").startswith(
            "// Code generated by protoc-gen-go")

    def test_a_binary_file_is_refused_by_the_window_too(self, git_repo):
        """The two readers must agree about what is text.

        Streaming with `errors="replace"` would hand a model a wall of
        replacement characters, which reads as a file it has seen.
        """
        (git_repo / "blob.bin").write_bytes(b"\x00\x01\x02\xff" * 4000)
        self.git(git_repo, "add", "-A")
        self.git(git_repo, "commit", "-qm", "binary")
        head = self.git(git_repo, "rev-parse", "HEAD").strip()
        ws = Workspace(root=git_repo, diff_head=head)
        with pytest.raises(WorkspaceError, match="binary file"):
            ws.read_file("blob.bin", start_line=1, end_line=2)

    def test_a_scan_stopped_at_the_ceiling_says_at_least(self, git_repo,
                                                          monkeypatch):
        """A total that was not measured is never printed as if it were."""
        import security_agent.workspace as W
        ws = self.a_large_live_file(git_repo)
        monkeypatch.setattr(W, "MAX_LOCAL_SCAN_BYTES", 50_000)
        body, _ = ws.read_file("big.py", start_line=2, end_line=4)
        assert "of at least" in body

    def test_reading_the_base_is_still_refused_for_a_live_file(self, git_repo):
        """The narrow guard survives the rewrite: this is not a general way of
        reading whatever the parent happened to contain."""
        ws = self.a_large_deleted_file(git_repo)
        with pytest.raises(WorkspaceError, match="not a file this change deleted"):
            ws.removed_text("app/views.py")
        with pytest.raises(WorkspaceError, match="not a file this change deleted"):
            ws.read_removed_file("app/views.py", start_line=1, end_line=2)


class TestTheGateOnTheGateFoundSeven:
    """Codex, 2026-09-07, on the diff that split the ceilings. Every one of
    these is a place where the new distinction was created and then lost, or a
    reader the new fetcher did not reach.
    """

    def env(self, root):
        return {"GIT_AUTHOR_NAME": "Test", "GIT_AUTHOR_EMAIL": "t@example.com",
                "GIT_COMMITTER_NAME": "Test",
                "GIT_COMMITTER_EMAIL": "t@example.com",
                "PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": str(root)}

    def git(self, root, *args):
        import subprocess
        return subprocess.run(("git", "-C", str(root), *args), check=True,
                              capture_output=True, text=True,
                              env=self.env(root)).stdout

    def commit(self, git_repo, message="x"):
        self.git(git_repo, "add", "-A")
        self.git(git_repo, "commit", "-qm", message)
        return self.git(git_repo, "rev-parse", "HEAD").strip()

    def test_the_prompt_baseline_reader_has_a_ceiling_too(self, git_repo,
                                                          monkeypatch):
        """`blob_bytes` bypassed the fetcher entirely.

        Its caller compares a prompt file against its baseline, and "the file
        we ship is small" is an assumption about a tree the change controls.
        """
        import security_agent.workspace as W
        (git_repo / "prompt.md").write_text("a\n" * 200_000, encoding="utf-8")
        head = self.commit(git_repo, "prompt")
        ws = Workspace(root=git_repo, diff_head=head)
        monkeypatch.setattr(W, "MAX_LOCAL_SCAN_BYTES", 100_000)
        with pytest.raises(FileTooLarge):
            ws.blob_bytes(head, "prompt.md")

    def test_an_absent_path_is_still_None_and_not_an_error(self, git_repo):
        """The other half of the same call: absent is an answer there.

        A prompt file this change *added* did not exist at the baseline, and
        that is a legitimate answer rather than a failure — so the new ceiling
        must not turn it into one.
        """
        head = self.git(git_repo, "rev-parse", "HEAD").strip()
        ws = Workspace(root=git_repo, diff_head=head)
        assert ws.blob_bytes(head, "never/written.md") is None

    def test_a_form_feed_does_not_shift_the_line_numbers(self, git_repo):
        """Lines are what git says they are: separated by LF.

        `str.splitlines()` also splits on form feed — an ordinary page break in
        older C and Lisp — so the window would be numbered differently from the
        file a finding cites.
        """
        (git_repo / "pager.c").write_text(
            "int one(void);\n\x0cint two(void);\nint three(void);\n",
            encoding="utf-8")
        head = self.commit(git_repo, "form feed")
        ws = Workspace(root=git_repo, diff_head=head)
        body, _ = ws.read_file("pager.c", start_line=2, end_line=2)
        assert "int two" in body
        assert "int three" not in body

    def test_a_windowed_read_of_a_deleted_file_says_it_is_not_there(
            self, git_repo):
        """The two paths must expose the same taxonomy.

        A failing windowed `git show` raised the base class, so `read_file`
        with a window on a deleted file never reached the fallback that reads
        the base — the deletion repair covered the whole-file path only.
        """
        (git_repo / "gone.py").write_text("def check():\n    pass\n",
                                          encoding="utf-8")
        base = self.commit(git_repo, "add")
        (git_repo / "gone.py").unlink()
        head = self.commit(git_repo, "delete")
        ws = Workspace(root=git_repo, diff_base=base, diff_head=head)
        with pytest.raises(FileNotAtRevision):
            ws.read_file("gone.py", start_line=1, end_line=2)

    def test_the_head_reader_reports_absence_the_same_way(self, git_repo):
        """A third caller of the window, and it had neither taxonomy.

        `head_text` goes straight to the primitive, so settling existence in
        `_render_window` would have left it raising the base class for a path
        that is not there — the same split the windowed and whole-file paths
        had. The check belongs in the primitive, where every caller reaches it.
        """
        head = self.git(git_repo, "rev-parse", "HEAD").strip()
        ws = Workspace(root=git_repo, diff_head=head)
        with pytest.raises(FileNotAtRevision):
            ws.head_text("app/never_written.py")

    def test_the_head_of_an_empty_file_is_empty_and_not_an_error(self,
                                                                 git_repo):
        (git_repo / "blank.py").write_text("", encoding="utf-8")
        head = self.commit(git_repo, "blank")
        ws = Workspace(root=git_repo, diff_head=head)
        assert ws.head_text("blank.py") == ""

    def test_an_empty_file_is_not_a_missing_file(self, git_repo):
        """Two distinct states in git, collapsed into the absence exception.

        A tracked empty file then fell through to the deleted-file fallback and
        was refused there as a path nothing deleted — two untrue things about a
        file that is simply blank.
        """
        (git_repo / "blank.py").write_text("", encoding="utf-8")
        head = self.commit(git_repo, "blank")
        ws = Workspace(root=git_repo, diff_head=head)
        body, trimmed = ws.read_file("blank.py")
        assert not trimmed
        assert "0 lines" in body


class TestADeletionIsPartOfTheChange:
    """`gpt-6-astra`, 2026-09-06, confirmed by building the tree: a change made
    entirely of deletions produced an empty `changed_files`, `_run` branched on
    that, and the review exited 0 without asking the model anything. Removing a
    whole file holding an authorisation check was reviewed as nothing.

    `changed_files` keeps its filter — a deleted file cannot be opened, and it
    is the list of files a reviewer is asked to open. What had to change is
    what decides there is nothing to review, and what the scoped diff is built
    from.
    """

    def deletion_only(self, git_repo):
        import subprocess
        env = {"GIT_AUTHOR_NAME": "Test", "GIT_AUTHOR_EMAIL": "t@example.com",
               "GIT_COMMITTER_NAME": "Test",
               "GIT_COMMITTER_EMAIL": "t@example.com",
               "PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": str(git_repo)}

        def git(*args):
            subprocess.run(("git", "-C", str(git_repo), *args), check=True,
                           capture_output=True, env=env)

        (git_repo / "auth.py").write_text(
            "def check(user):\n"
            "    if not user.is_admin:\n"
            "        raise Denied()\n", encoding="utf-8")
        git("add", "-A")
        git("commit", "-qm", "the guard")
        base = subprocess.run(("git", "-C", str(git_repo), "rev-parse", "HEAD"),
                              capture_output=True, text=True, check=True,
                              env=env).stdout.strip()
        (git_repo / "auth.py").unlink()
        git("add", "-A")
        git("commit", "-qm", "remove the guard")
        head = subprocess.run(("git", "-C", str(git_repo), "rev-parse", "HEAD"),
                              capture_output=True, text=True, check=True,
                              env=env).stdout.strip()
        return base, head

    def test_the_open_list_is_empty_and_the_inventory_is_not(self, git_repo):
        base, head = self.deletion_only(git_repo)
        ws = Workspace(root=git_repo, diff_base=base, diff_head=head)
        assert ws.changed_files() == []
        assert [(o.path, o.status) for o in ws.changed_objects()] == [
            ("auth.py", "deleted")]

    def test_the_diff_carries_the_removed_lines(self, git_repo):
        """The one place the removal exists, and what the reviewer reads."""
        base, head = self.deletion_only(git_repo)
        ws = Workspace(root=git_repo, diff_base=base, diff_head=head)
        body = ws.diff()
        assert "auth.py" in body
        assert "raise Denied()" in body

    def test_a_scoped_run_still_gets_the_deletion(self, git_repo):
        """The scoped diff built its pathspec from `changed_files`, which is
        empty here — so the removed lines vanished from the only place that
        carries them. Codex named this when adjudicating the repair."""
        base, head = self.deletion_only(git_repo)
        ws = Workspace(root=git_repo, diff_base=base, diff_head=head,
                       scope=("auth.py",))
        body = ws.diff()
        assert "raise Denied()" in body, body[:200]

    def test_a_deleted_file_is_readable_at_the_base(self, git_repo):
        """Citation validation reads the reviewed revision, where a deleted
        file is not — so every finding quoting a removed authorisation check
        was dropped as `unknown-path`. The diff could inspire the finding and
        nothing could record it. Codex named it on the gate pass."""
        base, head = self.deletion_only(git_repo)
        ws = Workspace(root=git_repo, diff_base=base, diff_head=head)
        with pytest.raises(WorkspaceError):
            ws.raw_text("auth.py")
        assert "raise Denied()" in ws.removed_text("auth.py")

    def test_it_refuses_a_path_the_change_did_not_delete(self, git_repo):
        """Narrow on purpose: the reason `blob_text` reads the reviewed commit
        rather than the working tree applies just as much to reading whatever
        the parent happened to contain."""
        base, head = self.deletion_only(git_repo)
        ws = Workspace(root=git_repo, diff_base=base, diff_head=head)
        with pytest.raises(WorkspaceError, match="not a file this change"):
            ws.removed_text("README.md")


class TestSearchReadsTheReviewedRevision:
    """`blob_text` says in its own docstring why the working tree must not be
    trusted — the checkout is material an untrusted contributor controls — and
    `search` ran `git grep` with no revision, which searches exactly that.

    Built as a real tree on 2026-09-06: a commit with no `require_admin` beside
    a working tree that has one gave "absent" from `read_file` and one match
    from `search`, so a verifier could refute a finding on a control that is
    not in the change. No attacker needed — a later commit on the branch, an
    earlier CI step, a checkout that is simply ahead.
    """

    def ahead_of_the_commit(self, git_repo):
        """A committed revision without the guard, a working tree with it."""
        import subprocess
        env = {"GIT_AUTHOR_NAME": "T", "GIT_AUTHOR_EMAIL": "t@e.com",
               "GIT_COMMITTER_NAME": "T", "GIT_COMMITTER_EMAIL": "t@e.com",
               "PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": str(git_repo)}

        def git(*args):
            return subprocess.run(("git", "-C", str(git_repo), *args),
                                  check=True, capture_output=True, text=True,
                                  env=env).stdout

        (git_repo / "app" / "auth.py").write_text(
            "def run(request):\n    return do(request)\n", encoding="utf-8")
        git("add", "-A")
        git("commit", "-qm", "the reviewed commit")
        head = git("rev-parse", "HEAD").strip()
        # The checkout moves on. Nothing commits it.
        (git_repo / "app" / "auth.py").write_text(
            "def run(request):\n    require_admin(request)\n"
            "    return do(request)\n", encoding="utf-8")
        return head

    def test_the_guard_in_the_working_tree_is_not_found(self, git_repo):
        head = self.ahead_of_the_commit(git_repo)
        ws = Workspace(root=git_repo, diff_head=head, excludes=())

        body, count = ws.search("require_admin")
        assert count == 0, body
        assert "require_admin" not in ws.read_file("app/auth.py")[0]

    def test_what_is_in_the_revision_is_still_found(self, git_repo):
        """The control. A search that found nothing at all would pass the test
        above for the wrong reason."""
        head = self.ahead_of_the_commit(git_repo)
        ws = Workspace(root=git_repo, diff_head=head, excludes=())

        body, count = ws.search("def run")
        assert count == 1, body

    def test_the_revision_prefix_never_reaches_the_reader(self, git_repo):
        """`git grep REV` returns `REV:path:line:text`, and three things take
        the first field as the path: the exclude check, the exposure record,
        and the model — which can only open a repository path."""
        head = self.ahead_of_the_commit(git_repo)
        ws = Workspace(root=git_repo, diff_head=head, excludes=())

        body, _ = ws.search("def run")
        assert head not in body, body
        assert "app/auth.py:" in body

    def test_an_excluded_path_is_still_excluded(self, git_repo):
        """The prefix broke this check by making every path look like the
        revision, so nothing matched an exclude and excluded files came back."""
        head = self.ahead_of_the_commit(git_repo)
        ws = Workspace(root=git_repo, diff_head=head, excludes=("*/auth.py",))

        _, count = ws.search("def run")
        assert count == 0

    def test_context_lines_carry_no_revision_either(self, git_repo):
        """`git grep` writes a match as `REV:path:line:text` and a context line
        as `REV-path-line-text`. A version that knew only the colon left the
        revision on every context line — which failed the exclude check, was
        recorded as an exposure under a path nobody can open, and was shown to
        the model as a path `read_file` refuses. Codex, 2026-09-07; the first
        version of this had no test with context at all.
        """
        head = self.ahead_of_the_commit(git_repo)
        ws = Workspace(root=git_repo, diff_head=head, excludes=())

        body, count = ws.search("return do", context_lines=2)
        # One match. The context line above it is shown and is checked below,
        # but it is not counted: it does not contain the pattern. This asserted
        # `2` while `count` was lines kept rather than matches, which is the
        # defect `TestALineOfContextIsNotAMatch` was written for.
        assert count == 1, body
        assert head not in body, body
        # The context line above the match is there, and addressable.
        assert "def run" in body
        # The first line is the "N match(es)" heading; the rest are results.
        for line in body.splitlines()[1:]:
            if line.strip() and not line.startswith("--"):
                assert line.startswith("app/auth.py"), line

    def test_an_excluded_file_is_excluded_with_context_too(self, git_repo):
        """The exclude check reads the first field. With the revision still on
        a context line, nothing matched the pattern and excluded content came
        back."""
        head = self.ahead_of_the_commit(git_repo)
        ws = Workspace(root=git_repo, diff_head=head, excludes=("*/auth.py",))

        _, count = ws.search("return do", context_lines=2)
        assert count == 0, "excluded content came back through a context line"

    def test_a_path_whose_name_looks_like_a_line_number(self, git_repo):
        """`app/case-12-data.py:7:match` was read as `app/case-12-data` by the
        heuristic that preceded `-z`, so an excluded file with a
        line-number-shaped name came back. Codex refused that parser;
        `git grep -z` puts a NUL after the path, which no path can contain."""
        import subprocess
        env = {"GIT_AUTHOR_NAME": "T", "GIT_AUTHOR_EMAIL": "t@e.com",
               "GIT_COMMITTER_NAME": "T", "GIT_COMMITTER_EMAIL": "t@e.com",
               "PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": str(git_repo)}

        def git(*args):
            return subprocess.run(("git", "-C", str(git_repo), *args),
                                  check=True, capture_output=True, text=True,
                                  env=env).stdout

        (git_repo / "app" / "case-12-data.py").write_text(
            "def run(request):\n    return do(request)\n", encoding="utf-8")
        git("add", "-A")
        git("commit", "-qm", "a name with separators and digits")
        head = git("rev-parse", "HEAD").strip()

        ws = Workspace(root=git_repo, diff_head=head, excludes=())
        body, _ = ws.search("return do")
        assert "app/case-12-data.py:2:" in body, body

        hidden = Workspace(root=git_repo, diff_head=head,
                           excludes=("*/case-12-data.py",))
        shown, count = hidden.search("return do")
        assert "case-12-data" not in shown, shown

    def test_a_hunk_separator_is_not_a_result(self, git_repo):
        """git writes `--` between context blocks. It carries no path, so it
        cannot be excluded — and counting it means a search whose every real
        line was excluded reports a nonzero result made of nothing else."""
        head = self.ahead_of_the_commit(git_repo)
        ws = Workspace(root=git_repo, diff_head=head, excludes=("*/auth.py",))

        # A pattern only the excluded file matches: every real line goes, and
        # what would be left is the separator between the hunks.
        body, count = ws.search("return do", context_lines=1)
        assert count == 0, body
        assert "--" not in body.replace("no matches", "")

    def test_a_path_containing_a_newline(self, git_repo):
        """`-z` makes the *delimiter* unambiguous and leaves the *framing*: the
        stream was still read line by line, and a path may legally contain a
        newline, so one record arrived as two malformed ones and the exclude
        check was handed a path that was never there. Measured on 2026-09-07
        against real git output; Codex named it on the gate pass for `-z`."""
        import subprocess
        env = {"GIT_AUTHOR_NAME": "T", "GIT_AUTHOR_EMAIL": "t@e.com",
               "GIT_COMMITTER_NAME": "T", "GIT_COMMITTER_EMAIL": "t@e.com",
               "PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": str(git_repo)}

        def git(*args):
            return subprocess.run(("git", "-C", str(git_repo), *args),
                                  check=True, capture_output=True, text=True,
                                  env=env).stdout

        odd = git_repo / "app" / "od\nd.py"
        odd.write_text("def run(request):\n    return do(request)\n",
                       encoding="utf-8")
        git("add", "-A")
        git("commit", "-qm", "a path with a newline in its name")
        head = git("rev-parse", "HEAD").strip()

        ws = Workspace(root=git_repo, diff_head=head, excludes=())
        body, count = ws.search("return do")
        assert count == 1, body
        assert head not in body, body

        hidden = Workspace(root=git_repo, diff_head=head,
                           excludes=("*/od\nd.py",))
        shown, count = hidden.search("return do")
        assert count == 0, shown


class TestTheHeaderNamesWhatTheBodyHolds:
    """Codex, 2026-09-07, second gate round on this change.

    The body was cut at `MAX_OUTPUT_CHARS` mid-character and the header was
    built from the range that had been *asked for*, so a three-line window of
    30,000-character lines answered `lines 1-3` with line 3 absent. A claim
    about what was delivered that nothing checked — the shape this tool exists
    to hunt, inside the tool.
    """

    def wide(self, git_repo, line_len=30_000, count=6):
        import subprocess
        env = {"GIT_AUTHOR_NAME": "Test", "GIT_AUTHOR_EMAIL": "t@example.com",
               "GIT_COMMITTER_NAME": "Test",
               "GIT_COMMITTER_EMAIL": "t@example.com",
               "PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": str(git_repo)}

        def git(*args):
            return subprocess.run(("git", "-C", str(git_repo), *args),
                                  check=True, capture_output=True, text=True,
                                  env=env).stdout

        (git_repo / "wide.js").write_text(
            "\n".join("var x{} = {!r};".format(n, "z" * line_len)
                      for n in range(1, count + 1)) + "\n",
            encoding="utf-8")
        git("add", "-A")
        git("commit", "-qm", "wide")
        head = git("rev-parse", "HEAD").strip()
        return Workspace(root=git_repo, diff_head=head, excludes=())

    def test_every_line_the_header_names_is_in_the_body(self, git_repo):
        ws = self.wide(git_repo)
        body, trimmed = ws.read_file("wide.js", start_line=1, end_line=6)
        assert trimmed
        header = body.splitlines()[0]
        import re
        first, last = re.search(r"lines (\d+)-(\d+)", header).groups()
        for n in range(int(first), int(last) + 1):
            assert "{:>6} |".format(n) in body, (n, header)

    def test_the_body_never_ends_mid_line(self, git_repo):
        """Cutting mid-character produced a fragment under a line number,
        which reads as the code at that line and is not."""
        ws = self.wide(git_repo)
        body, _ = ws.read_file("wide.js", start_line=1, end_line=6)
        last = body.splitlines()[-1]
        assert last.endswith("';") or last.endswith('";'), last[-40:]

    def test_one_line_too_long_is_still_answered(self, git_repo):
        """Dropping it would answer a different question from the one asked."""
        ws = self.wide(git_repo, line_len=200_000, count=2)
        body, trimmed = ws.read_file("wide.js", start_line=1, end_line=1)
        assert trimmed
        assert "     1 |" in body
        assert "lines 1-1" in body


class TestOneLongLineDoesNotBreakWhatSearchClaims:
    """Measured on 2026-09-07 with a bundled JS file: one minified line of
    about 320,000 characters, holding the only match in the repository.

    Three things in the answer were false, from two defects. The body ended
    mid-token, because `rsplit("\\n", 1)` on a slice with no newline returns
    the slice; and `truncated` was set by that single oversized record, so an
    exact count was presented as `at least 1` and the note said *"there are
    more"* when there were none — sending a model to narrow its pattern and
    search again for nothing.
    """

    def bundle(self, git_repo, chunks=20_000):
        import subprocess
        env = {"GIT_AUTHOR_NAME": "Test", "GIT_AUTHOR_EMAIL": "t@example.com",
               "GIT_COMMITTER_NAME": "Test",
               "GIT_COMMITTER_EMAIL": "t@example.com",
               "PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": str(git_repo)}

        def git(*args):
            return subprocess.run(("git", "-C", str(git_repo), *args),
                                  check=True, capture_output=True, text=True,
                                  env=env).stdout

        (git_repo / "bundle.js").write_text(
            "var a=1;" * chunks + "eval(userInput);" + "var b=2;" * chunks
            + "\n", encoding="utf-8")
        git("add", "-A")
        git("commit", "-qm", "bundle")
        head = git("rev-parse", "HEAD").strip()
        return Workspace(root=git_repo, diff_head=head, excludes=())

    # Two tests were removed here rather than kept. `search` returning a hit
    # at all, and a body containing any ellipsis, both hold against the code
    # this replaces — so they cost a run and establish nothing about it. Codex
    # named them on the gate, 2026-09-07. What they were reaching for is in
    # `test_what_was_searched_for_is_visible_in_the_answer` and
    # `test_both_omitted_sides_are_marked`, which do not.

    def test_the_count_is_exact_when_nothing_was_skipped(self, git_repo):
        """One match found, one match reported — not `at least 1`.

        The scan stopped because one record was larger than the budget, which
        says nothing about how many matches there are. Conflating that with
        "the scan stopped early" made an exact count read as a floor.
        """
        ws = self.bundle(git_repo)
        body, count = ws.search("eval")
        assert count == 1
        assert "at least" not in body, body[:200]

    def test_it_does_not_say_there_are_more(self, git_repo):
        ws = self.bundle(git_repo)
        body, _ = ws.search("eval")
        assert "there are more" not in body, body[:200]

    def test_the_body_does_not_end_inside_a_line(self, git_repo):
        """A fragment under `path:1:` reads as the code at that line."""
        ws = self.bundle(git_repo)
        body, _ = ws.search("eval")
        content = [ln for ln in body.splitlines()
                   if ln.startswith("bundle.js:")]
        assert content, body[:200]
        assert not content[0].endswith("var "), content[0][-40:]

    def test_both_omitted_sides_are_marked(self, git_repo):
        """The match is in the middle of the line, so both ends were dropped
        and both have to say so.

        Marking only the end would present the window as the start of the
        line, which is a different claim and a false one. This asserted the
        word "clipped" while the prefix design was still on the table; the
        design that survived says it with `…` on the side it happened, so the
        test asserts the property rather than the wording.
        """
        ws = self.bundle(git_repo)
        body, _ = ws.search("eval")
        line = [ln for ln in body.splitlines()
                if ln.startswith("bundle.js:")][0]
        after_prefix = line.split(":", 2)[2]
        assert after_prefix.startswith("… "), after_prefix[:60]
        assert after_prefix.endswith(" …"), after_prefix[-60:]

    def test_what_was_searched_for_is_visible_in_the_answer(self, git_repo):
        """The one the first set was missing, and the one that matters.

        Codex, 2026-09-07, on the design: a prefix clip returns a record that
        no longer demonstrates why it matched — worse than the fragment it
        replaces, because a fragment is at least honestly the start of the
        line. My tests asserted `count == 1` and never that `eval` survived,
        which is a test written to the fix rather than to the defect.
        """
        ws = self.bundle(git_repo)
        body, _ = ws.search("eval")
        assert "eval(userInput)" in body, body[:300]

    def test_a_match_after_multibyte_text_is_still_shown(self, git_repo):
        """The column git reports is a *byte* offset, measured: in a file
        whose match begins at character 22 it reports 35. Slicing a decoded
        string by that number lands in a different word, which is this
        project's recurring defect introduced by the fix for another one."""
        import subprocess
        env = {"GIT_AUTHOR_NAME": "Test", "GIT_AUTHOR_EMAIL": "t@example.com",
               "GIT_COMMITTER_NAME": "Test",
               "GIT_COMMITTER_EMAIL": "t@example.com",
               "PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": str(git_repo)}

        def git(*args):
            return subprocess.run(("git", "-C", str(git_repo), *args),
                                  check=True, capture_output=True, text=True,
                                  env=env).stdout

        (git_repo / "utf.js").write_text(
            "var s = '" + "ключ " * 8_000 + "'; eval(userInput);\n",
            encoding="utf-8")
        git("add", "-A")
        git("commit", "-qm", "utf")
        head = git("rev-parse", "HEAD").strip()
        ws = Workspace(root=git_repo, diff_head=head, excludes=())
        body, count = ws.search("eval")
        assert count == 1
        assert "eval(userInput)" in body, body[:300]
        assert "\ufffd" not in body, "a replacement character is not in the file"

    def test_many_ordinary_matches_still_report_more(self, git_repo):
        """The control. `truncated` must keep meaning what it says for the
        case it was written for, or this fix has traded one wrong claim for
        another."""
        import subprocess
        env = {"GIT_AUTHOR_NAME": "Test", "GIT_AUTHOR_EMAIL": "t@example.com",
               "GIT_COMMITTER_NAME": "Test",
               "GIT_COMMITTER_EMAIL": "t@example.com",
               "PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": str(git_repo)}

        def git(*args):
            return subprocess.run(("git", "-C", str(git_repo), *args),
                                  check=True, capture_output=True, text=True,
                                  env=env).stdout

        (git_repo / "many.py").write_text(
            "".join("eval(x)  # occurrence {}\n".format(n)
                    for n in range(30_000)), encoding="utf-8")
        git("add", "-A")
        git("commit", "-qm", "many")
        head = git("rev-parse", "HEAD").strip()
        ws = Workspace(root=git_repo, diff_head=head, excludes=())
        body, count = ws.search("eval", max_results=300)
        assert count > 0
        assert ("more match(es) not shown" in body
                or "the scan stopped here" in body), body[:300]


class TestAGeneratorStoppingIsNotAStreamEnding:
    """The regression the search rewrite introduced, and the shape of it.

    `_grep_records` returns when its `should_stop` fires, and a `for` loop
    cannot tell that from the stream running out — so a search killed by its
    own deadline came back as a search that found nothing. Exactly the defect
    `test_search_stopped_at_the_deadline_does_not_report_no_matches` was
    written for in September 2026, reintroduced by moving the deadline check
    into the parser.

    Absence read as agreement, one more time: the loop ending is not evidence
    that there was nothing more to read.
    """

    def test_the_parser_stopping_marks_the_search_as_stopped(self, git_repo,
                                                             monkeypatch):
        import security_agent.workspace as W
        ws = Workspace(root=git_repo, excludes=())
        body, count = ws.search("SELECT")
        assert count == 1 and "no matches" not in body

        monkeypatch.setattr(W, "GIT_TIMEOUT_SECONDS", -1)
        with pytest.raises(WorkspaceError, match="stopped at the"):
            ws.search("SELECT")

    def test_a_stop_partway_through_is_a_floor_and_says_so(self, git_repo,
                                                           monkeypatch):
        """Stopped after keeping some lines: the count is a floor, and both
        the head and the note have to say so. This is the case where
        `truncated` genuinely means what it says, and it must survive the fix
        that stopped it meaning that for one oversized record."""
        import subprocess

        import security_agent.workspace as W
        env = {"GIT_AUTHOR_NAME": "Test", "GIT_AUTHOR_EMAIL": "t@example.com",
               "GIT_COMMITTER_NAME": "Test",
               "GIT_COMMITTER_EMAIL": "t@example.com",
               "PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": str(git_repo)}

        def git(*args):
            return subprocess.run(("git", "-C", str(git_repo), *args),
                                  check=True, capture_output=True, text=True,
                                  env=env).stdout

        (git_repo / "many.py").write_text(
            "".join("eval(x)  # {}\n".format(n) for n in range(40_000)),
            encoding="utf-8")
        git("add", "-A")
        git("commit", "-qm", "many")
        head = git("rev-parse", "HEAD").strip()
        ws = Workspace(root=git_repo, diff_head=head, excludes=())
        monkeypatch.setattr(W, "MAX_SEARCH_HITS", 50)
        body, count = ws.search("eval", max_results=300)
        assert count > 0
        assert "at least" in body, body[:200]
        assert "the scan stopped here" in body, body[:200]

    def test_a_stopped_scan_still_accounts_for_what_it_withheld(
            self, git_repo, monkeypatch):
        """Two facts, and the stopped one used to silence the other.

        "The scan stopped" is about what was never read. "N more not shown" is
        about what *was* read and is being withheld. They were mutually
        exclusive branches with `truncated` first, so a broad search over this
        repository answered "at least 1471 match(es)", printed five lines, and
        accounted for none of the 1,466 it had in hand. Codex, sixth gate
        round, 2026-09-07, measured live before it was believed.
        """
        import re

        import security_agent.workspace as W
        env = {"GIT_AUTHOR_NAME": "Test", "GIT_AUTHOR_EMAIL": "t@example.com",
               "GIT_COMMITTER_NAME": "Test",
               "GIT_COMMITTER_EMAIL": "t@example.com",
               "PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": str(git_repo)}
        import subprocess

        def git(*args):
            return subprocess.run(("git", "-C", str(git_repo), *args),
                                  check=True, capture_output=True, text=True,
                                  env=env).stdout

        (git_repo / "many.py").write_text(
            "".join("eval(x)  # {}\n".format(n) for n in range(40_000)),
            encoding="utf-8")
        git("add", "-A")
        git("commit", "-qm", "many")
        head = git("rev-parse", "HEAD").strip()
        ws = Workspace(root=git_repo, diff_head=head, excludes=())
        monkeypatch.setattr(W, "MAX_SEARCH_HITS", 200)
        body, count = ws.search("eval", max_results=5)

        # The precondition: the scan really did stop *and* really is holding
        # back matches it read. Without both, this test measures nothing.
        assert "the scan stopped here" in body, body[:200]
        shown = len([ln for ln in body.splitlines() if ln.startswith("many.py:")])
        assert count > shown, (count, shown)

        withheld = re.search(r"(\d+) more match\(es\) not shown", body)
        assert withheld, (
            "the scan stopped and the matches it withheld went unmentioned:\n"
            + body[:400])
        assert shown + int(withheld.group(1)) == count, (
            "the answer does not account for the matches it reached:\n"
            + body[:400])


class TestTheParserAtEveryChunkBoundary:
    """Codex asked for this on the design gate: records split at every
    delimiter boundary.

    The parser reads fixed-size chunks and tracks the wanted window in
    *absolute* offsets across them, so an off-by-one at a chunk edge is a
    match silently moved or dropped — and a real stream only ever splits where
    the kernel happens to split it, which is not where the tests would.

    Driven directly rather than through git: the point is the arithmetic, and
    a real pipe cannot be made to break in a chosen place.
    """

    class Trickle:
        """A stream that hands back exactly `size` bytes at a time."""

        def __init__(self, data, size):
            self.data = data
            self.size = size
            self.at = 0

        def read(self, _n=None):
            chunk = self.data[self.at:self.at + self.size]
            self.at += len(chunk)
            return chunk

    def records(self, data, size):
        from security_agent.workspace import HUNK_SEPARATOR, _grep_records
        out = []
        for item in _grep_records(self.Trickle(data, size)):
            out.append("--" if item is HUNK_SEPARATOR else
                       (item.path, item.line, item.column, item.text,
                        item.offset, item.dropped_after))
        return out

    STREAM = (b"rev:app/a.py\x002\x008\x00x = eval(user)\n"
              b"rev:app/a.py\x003\x00after\n"
              b"--\n"
              b"rev:app/od\nd.py\x001\x005\x00y = eval(x)\n")

    def test_every_split_gives_the_same_records(self):
        whole = self.records(self.STREAM, len(self.STREAM))
        assert len(whole) == 4
        for size in range(1, len(self.STREAM) + 2):
            assert self.records(self.STREAM, size) == whole, size

    def test_a_path_with_a_newline_survives_every_split(self):
        for size in range(1, 40):
            got = self.records(self.STREAM, size)
            assert got[-1][0] == b"rev:app/od\nd.py", (size, got[-1][0])

    def test_a_context_line_gets_no_column(self):
        got = self.records(self.STREAM, 7)
        context = [r for r in got if r != "--" and r[2] is None]
        assert len(context) == 1
        assert context[0][3] == b"after"

    def test_a_context_line_whose_text_starts_with_digits(self):
        """The lookahead decides match-versus-context by digits-then-NUL. A
        context line beginning with digits must not be mistaken for one, and
        text can never contain a NUL, which is what makes the rule sound."""
        stream = b"rev:a.py\x004\x00123456 = total\n"
        for size in range(1, len(stream) + 2):
            got = self.records(stream, size)
            assert len(got) == 1, size
            assert got[0][2] is None, (size, got[0])
            assert got[0][3] == b"123456 = total", size

    def test_a_stream_ending_inside_the_lookahead(self):
        """Truncated mid-column: `path NUL line NUL 12` and then nothing.

        This asserted `len(got) <= 1` and "the column is None or digits",
        which every possible behaviour satisfies — a test that permits both
        answers establishes neither. Codex named it on the gate, 2026-09-07.

        The behaviour is pinned instead: the record is emitted as a *context*
        line whose text is `12`. That is the safe reading — a truncated column
        must never become a column, because a made-up byte offset would cut a
        window at a place the file does not have. The text is wrong by two
        characters and the path and line are right, so the reader sees a real
        location with a short line rather than a plausible fiction.
        """
        stream = b"rev:a.py\x004\x0012"
        got = self.records(stream, 3)
        assert len(got) == 1
        path, line, column, text, offset, dropped_after = got[0]
        assert path == b"rev:a.py"
        assert line == b"4"
        assert column is None, "a truncated column must not become a column"
        assert text == b"12"
        assert offset == 0 and not dropped_after

    def test_a_complete_column_at_the_very_end_is_still_a_column(self):
        """The control for the one above: the same shape, complete."""
        stream = b"rev:a.py\x004\x0012\x00x = eval(y)\n"
        for size in (1, 5, len(stream)):
            got = self.records(stream, size)
            assert len(got) == 1, size
            assert got[0][2] == b"12", (size, got[0][2])
            assert got[0][3] == b"x = eval(y)", size

    def test_the_window_is_taken_around_a_far_match(self):
        """The parser's half of the fix. A match late in a long line must be
        inside the retained bytes, which is what keeping the head did not do.
        """
        from security_agent.workspace import MAX_RECORD_BYTES
        lead = b"z" * 200_000
        stream = (b"rev:big.js\x001\x00" + str(len(lead) + 1).encode()
                  + b"\x00" + lead + b"eval(user)\n")
        for size in (1, 3, 4096, 65_536, 300_000):
            got = self.records(stream, size)
            assert len(got) == 1, size
            _p, _l, column, text, offset, _after = got[0]
            assert column == str(len(lead) + 1).encode()
            assert b"eval(user)" in text, (size, len(text))
            assert len(text) <= MAX_RECORD_BYTES, (size, len(text))
            assert offset > 0, size


class TestTheEdgeTrimDoesNotExcuseTheMiddle:
    """A window cut in bytes can begin or end inside a character; those two are
    artefacts of the cut. Anything invalid *inside* it is what the file holds.

    The first version of this drew the line with "the error is within four
    bytes of the end", after dropping up to four trailing bytes and retrying.
    Measured exhaustively rather than reasoned about: `b"abc\xffdef"` decoded
    to `"abc"`, silently — once enough trailing bytes are dropped, every
    interior error is within four of the new end, so the guard excuses all of
    them. A quoted line that is not the line, produced by the code that exists
    to stop exactly that.
    """

    CLEAN = "aбв€𝄞z"

    def test_no_cut_of_clean_text_is_refused_or_invented(self):
        """Every window of a clean line, declared as the cut it is."""
        from security_agent.workspace import _trimmed_decode
        raw = self.CLEAN.encode("utf-8")
        for begin in range(len(raw) + 1):
            for end in range(begin, len(raw) + 1):
                got = _trimmed_decode(raw[begin:end],
                                      cut_before=begin > 0,
                                      cut_after=end < len(raw))
                assert "\ufffd" not in got, (begin, end, got)
                assert got in self.CLEAN, (begin, end, got)

    def test_a_whole_line_is_not_forgiven_at_its_edges(self):
        """The second version's defect, and the reason the flags exist.

        An incremental decoder with `final=False` and an unconditional leading
        trim fixed the interior and left both edges forgiving: on a *complete*
        record, `b"\\x80abc"` gave `"abc"` and `b"abc\\xe2\\x82"` gave `"abc"`.
        Neither edge was cut, so both are corruption in the file, silently
        repaired by the code written to stop exactly that. Codex, 2026-09-07.
        """
        from security_agent.workspace import _trimmed_decode
        for payload in (b"\x80abc", b"abc\xe2\x82"):
            with pytest.raises(WorkspaceError, match="not UTF-8"):
                _trimmed_decode(payload, cut_before=False, cut_after=False)

    def test_the_same_bytes_are_forgiven_on_an_edge_that_was_cut(self):
        """The control. Declaring the cut has to change the answer, or the
        flags are decoration."""
        from security_agent.workspace import _trimmed_decode
        assert _trimmed_decode(b"\x80abc", cut_before=True) == "abc"
        assert _trimmed_decode(b"abc\xe2\x82", cut_after=True) == "abc"

    def test_invalid_bytes_inside_the_window_are_refused(self):
        from security_agent.workspace import _trimmed_decode
        for payload in (b"abc\xffdef",           # lone invalid byte
                        b"ab\xe2\x82cd",         # truncated 3-byte sequence
                        b"ab\xc0\xafcd",         # overlong encoding
                        b"ab\xed\xa0\x80cd"):    # surrogate
            # Refused even with both edges declared cut: the corruption is in
            # the middle, and forgiving an edge must not forgive that.
            with pytest.raises(WorkspaceError, match="not UTF-8"):
                _trimmed_decode(payload, cut_before=True, cut_after=True)

    def test_corruption_just_before_the_match_is_not_forgiven(self):
        """The prefix decode's own edge, which is not a cut one.

        `_window_around` measures where the match starts by decoding the bytes
        before it. That prefix ends at git's match start — a character boundary
        in the file — so nothing cut it, and an incomplete sequence sitting
        immediately before the match is corruption. Passing `cut_after=True`
        there trimmed it away silently. Codex, second gate round, 2026-09-07.

        Driven through `_window_around` directly: building a repository whose
        blob is invalid UTF-8 just before a match means fighting git's own
        binary detection, and the unit under test is the flag, not git.
        """
        from security_agent.workspace import GrepRecord, _trimmed_decode, _window_around

        # `ab` + a truncated three-byte sequence + the match. The column is
        # 1-based and points at the `e` of `eval`.
        text = b"ab\xe2\x82" + b"eval(x)"
        record = GrepRecord(path=b"a.js", line=b"1", column=b"5", text=text,
                            offset=0, dropped_after=False)
        with pytest.raises(WorkspaceError, match="not UTF-8"):
            _window_around(record, _trimmed_decode)

    def test_a_clean_prefix_before_the_match_still_works(self):
        """The control: the same shape, valid."""
        from security_agent.workspace import GrepRecord, _trimmed_decode, _window_around

        text = "aб".encode("utf-8") + b"eval(x)"
        record = GrepRecord(path=b"a.js", line=b"1",
                            column=str(len("aб".encode("utf-8")) + 1).encode(),
                            text=text, offset=0, dropped_after=False)
        assert _window_around(record, _trimmed_decode) == "aбeval(x)"

    def test_the_two_edge_artefacts_are_still_dropped(self):
        from security_agent.workspace import _trimmed_decode
        assert _trimmed_decode("abв".encode("utf-8")[:-1],
                               cut_after=True) == "ab"
        assert _trimmed_decode("абв".encode("utf-8")[1:],
                               cut_before=True) == "бв"


@pytest.fixture
def session():
    return Session()
class TestTheTruncationFlagIsNotSticky:
    """A qualifier left over from an earlier search is the same defect as a
    missing one: the summary says something about a search that did not
    happen.

    `search` returns early for "no matches", so a flag written only at the
    successful exit keeps the previous answer — and a clean no-match search
    following a stopped one reported "at least 0 match(es)". Found while
    checking my own fix for the third of Codex's four, 2026-09-07.
    """

    def repo(self, git_repo):
        import subprocess
        env = {"GIT_AUTHOR_NAME": "Test", "GIT_AUTHOR_EMAIL": "t@example.com",
               "GIT_COMMITTER_NAME": "Test",
               "GIT_COMMITTER_EMAIL": "t@example.com",
               "PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": str(git_repo)}

        def git(*args):
            return subprocess.run(("git", "-C", str(git_repo), *args),
                                  check=True, capture_output=True, text=True,
                                  env=env).stdout

        (git_repo / "many.py").write_text(
            "".join("eval(x)  # {}\n".format(n) for n in range(40_000)),
            encoding="utf-8")
        git("add", "-A")
        git("commit", "-qm", "many")
        head = git("rev-parse", "HEAD").strip()
        return Workspace(root=git_repo, diff_head=head, excludes=())

    def test_a_clean_search_after_a_stopped_one_is_not_marked(self, git_repo,
                                                              monkeypatch):
        import security_agent.workspace as W
        ws = self.repo(git_repo)
        monkeypatch.setattr(W, "MAX_SEARCH_HITS", 50)
        ws.search("eval")
        assert ws.last_search_truncated is True

        # A pattern that is in no file: the early "no matches" return.
        body, count = ws.search("zzzznotpresentanywhere")
        assert count == 0 and "no matches" in body
        assert ws.last_search_truncated is False, (
            "the previous search's qualifier survived into this one")

    def test_a_raising_search_does_not_leave_the_flag_set(self, git_repo,
                                                          monkeypatch):
        """Every exit, not only the two that return.

        Clearing on entry covers the early `no matches` return. It also has to
        cover the ones that raise — an empty pattern, an invalid regex, a
        search stopped before it read anything — or the summary of the *next*
        search inherits the qualifier. Checked at each exit rather than argued
        from where the assignment sits.
        """
        import security_agent.workspace as W
        ws = self.repo(git_repo)
        monkeypatch.setattr(W, "MAX_SEARCH_HITS", 50)
        ws.search("eval")
        assert ws.last_search_truncated is True

        monkeypatch.setattr(W, "MAX_SEARCH_HITS", 20_000)
        for pattern in ("", "(["):
            try:
                ws.search(pattern)
            except WorkspaceError:
                pass
            assert ws.last_search_truncated is False, pattern

    def test_the_note_still_tells_the_model_what_to_do(self, git_repo,
                                                       monkeypatch):
        """Saying less must not mean saying nothing actionable.

        The old note claimed "there are more", which was a fact it did not
        have; the new one has to keep the instruction that made the old one
        useful, or the honesty costs the reader the next step.
        """
        import security_agent.workspace as W
        ws = self.repo(git_repo)
        monkeypatch.setattr(W, "MAX_SEARCH_HITS", 50)
        body, _ = ws.search("eval")
        assert "the scan stopped here" in body
        assert "path_glob" in body
        assert "Narrow the pattern" in body

    def test_the_tool_summary_follows_it(self, git_repo, monkeypatch, session):
        import security_agent.workspace as W
        ws = self.repo(git_repo)
        monkeypatch.setattr(W, "MAX_SEARCH_HITS", 50)
        first = dispatch(ws, session, "search_code", {"pattern": "eval"})
        assert "at least" in first.summary, first.summary
        second = dispatch(ws, session, "search_code",
                          {"pattern": "zzzznotpresentanywhere"})
        assert "at least" not in second.summary, second.summary
        assert "0 match(es)" in second.summary, second.summary


class TestALineOfContextIsNotAMatch:
    """`context_lines` made the count and the allowance count the wrong thing.

    Measured on a built repository, 2026-09-07: one occurrence of a pattern
    with two lines of context on either side came back as **"5 match(es)"**,
    and with `max_results=1` the single line shown was the *first line of
    context* — text that does not contain the pattern — under a heading
    claiming five. The model plans with that number and quotes that line.

    Two separate wrong things from one confusion. The count treated every
    rendered line as a match, and the allowance was spent on rendered lines
    too, so leading context could displace the very line the search was for.

    Older than the change it was found in: `total = len(hits)` has counted
    context since context was added, and no test asked. Codex, third gate
    round on the record-bounding change.
    """

    def repo(self, git_repo):
        import subprocess
        env = {"GIT_AUTHOR_NAME": "Test", "GIT_AUTHOR_EMAIL": "t@example.com",
               "GIT_COMMITTER_NAME": "Test",
               "GIT_COMMITTER_EMAIL": "t@example.com",
               "PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": str(git_repo)}

        def git(*args):
            return subprocess.run(("git", "-C", str(git_repo), *args),
                                  check=True, capture_output=True, text=True,
                                  env=env).stdout

        # Two matches, far enough apart that each carries context of its own.
        (git_repo / "ctx.py").write_text(
            "alpha\nNEEDLE_XYZ one\nbeta\ngamma\nNEEDLE_XYZ two\ndelta\n",
            encoding="utf-8")
        git("add", "-A")
        git("commit", "-qm", "ctx")
        head = git("rev-parse", "HEAD").strip()
        return Workspace(root=git_repo, diff_head=head, excludes=())

    def test_the_count_is_matches_and_not_lines(self, git_repo):
        ws = self.repo(git_repo)
        body, count = ws.search("NEEDLE_XYZ", context_lines=2)
        assert count == 2, body
        assert body.startswith("2 match(es)"), body[:80]
        # And the context is still there — the fix must not be "drop context".
        assert "alpha" in body and "delta" in body, body

    def test_the_matching_line_is_never_the_one_dropped(self, git_repo):
        """`max_results=1` over a hit with context returned only the context.

        The line that justified the answer was the line the allowance spent
        itself getting to, so the result showed a file and a line number for
        text that does not contain the pattern.
        """
        ws = self.repo(git_repo)
        body, count = ws.search("NEEDLE_XYZ", context_lines=1, max_results=1)
        assert count == 2, body
        assert "NEEDLE_XYZ one" in body, body

    def test_the_withheld_number_counts_matches_too(self, git_repo):
        """The note must not subtract rendered lines from a count of matches.

        `total - len(shown)` mixes the two, and it reaches zero — the note
        disappearing entirely — while matches are still being withheld.
        """
        ws = self.repo(git_repo)
        body, _ = ws.search("NEEDLE_XYZ", context_lines=1, max_results=1)
        assert "1 more match(es) not shown" in body, body

    def test_the_summary_agrees_with_the_body(self, git_repo, session):
        ws = self.repo(git_repo)
        result = dispatch(ws, session, "search_code",
                          {"pattern": "NEEDLE_XYZ", "context_lines": 2})
        assert "2 match(es)" in result.summary, result.summary

    def test_a_search_without_context_is_unchanged(self, git_repo):
        """The control. Every record is a match when git emits no context, and
        the count must be the same number it always was."""
        ws = self.repo(git_repo)
        body, count = ws.search("NEEDLE_XYZ")
        quoted = [ln for ln in body.splitlines() if ln.startswith("ctx.py:")]
        assert count == 2 and len(quoted) == 2, body

    def wide(self, git_repo, monkeypatch):
        """A repository whose answer crosses the character ceiling, with two
        matches far enough apart that git gives them separate blocks."""
        import subprocess

        import security_agent.workspace as W
        env = {"GIT_AUTHOR_NAME": "Test", "GIT_AUTHOR_EMAIL": "t@example.com",
               "GIT_COMMITTER_NAME": "Test",
               "GIT_COMMITTER_EMAIL": "t@example.com",
               "PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": str(git_repo)}

        def git(*args):
            return subprocess.run(("git", "-C", str(git_repo), *args),
                                  check=True, capture_output=True, text=True,
                                  env=env).stdout

        filler = "pad pad pad pad pad pad pad\n"
        (git_repo / "wide.py").write_text(
            filler
            + "NEEDLE_A pad pad pad pad pad\n"
            + filler * 6
            + "NEEDLE_B pad pad pad pad pad\n"
            + filler,
            encoding="utf-8")
        git("add", "-A")
        git("commit", "-qm", "wide")
        head = git("rev-parse", "HEAD").strip()
        # Chosen by measurement, not by eye: the six rendered records end at
        # cumulative offsets 37/76/114/152/191/230, so a cut at 170 lands
        # *inside* the second matching line — the case that matters. A cut at
        # 200 lands after it and exercises nothing. Large enough, too, that
        # `_grep_stream`'s own ceiling (twice this, 340, against about 230 of
        # accounted size) is never reached, so `truncated` stays false and this
        # is the character cut alone.
        monkeypatch.setattr(W, "MAX_OUTPUT_CHARS", 170)
        return Workspace(root=git_repo, diff_head=head, excludes=())

    def test_the_character_ceiling_cannot_swallow_a_counted_match(
            self, git_repo, monkeypatch):
        """The cut was taken on the joined string, after the counting.

        Two blocks of context and a 60,000-character cut landing inside the
        second one: the matching line of that block went, its context stayed,
        the heading still counted the match, and no note said a match had been
        withheld — because the number of matches shown had been settled before
        the string was cut. Codex, fourth gate round, 2026-09-07.

        Asserted as a chain rather than as a shape: what the answer says it
        found must equal what it shows plus what it says it is withholding.
        """
        import re
        ws = self.wide(git_repo, monkeypatch)
        body, count = ws.search("NEEDLE_", context_lines=1)
        assert count == 2, body

        visible = len([ln for ln in body.splitlines()
                       if ln.startswith("wide.py:") and "NEEDLE_" in ln])
        # The precondition, asserted rather than assumed: if the fixture stops
        # crossing the ceiling this test passes trivially and measures nothing.
        assert visible < count, (
            "the ceiling did not cut anything, so nothing here is tested:\n"
            + body)
        withheld = re.search(r"(\d+) more match\(es\) not shown", body)
        assert visible + (int(withheld.group(1)) if withheld else 0) == count, (
            "the answer does not account for every match it counted:\n" + body)

    def test_the_answer_stays_within_the_character_ceiling(
            self, git_repo, monkeypatch):
        """The control for the same change: moving the cut into the record
        selection must still bound the answer."""
        import security_agent.workspace as W
        ws = self.wide(git_repo, monkeypatch)
        body, _ = ws.search("NEEDLE_", context_lines=1)
        quoted = "\n".join(ln for ln in body.splitlines()
                           if ln.startswith("wide.py:"))
        assert len(quoted) <= W.MAX_OUTPUT_CHARS, len(quoted)

    def test_context_dropped_by_the_ceiling_is_declared(
            self, git_repo, monkeypatch):
        """The ceiling landing *after* the last match, which says nothing.

        Both matches fit, so `total == kept` and neither the stopped note nor
        the withheld-matches note fires — and the trailing context line, which
        the caller asked for by passing `context_lines`, is gone without a
        word. An answer that claims an exact result must not also be quietly
        short of what was requested. Codex, fifth gate round, 2026-09-07.

        The ceiling is 200 rather than 170 for exactly this: at 170 the cut
        lands inside the second match and the other note covers it, so that
        fixture cannot reach this branch.
        """
        import security_agent.workspace as W
        ws = self.wide(git_repo, monkeypatch)
        monkeypatch.setattr(W, "MAX_OUTPUT_CHARS", 200)
        body, count = ws.search("NEEDLE_", context_lines=1)

        visible = len([ln for ln in body.splitlines()
                       if ln.startswith("wide.py:") and "NEEDLE_" in ln])
        assert count == 2 and visible == 2, body
        # The precondition: something really was dropped, or this is vacuous.
        quoted = [ln for ln in body.splitlines() if ln.startswith("wide.py:")]
        assert len(quoted) < 6, (
            "nothing was dropped, so this test measures nothing:\n" + body)
        assert "size limit" in body, (
            "context was dropped and the answer did not say so:\n" + body)


class TestAStrictDecodeMustNotLeaveGitWriting:
    """The search stopped reading and left the child blocked on a full pipe.

    `_window_around` decodes strictly and raises — deliberately, because a
    quoted line has to be the line. The raise left `_grep_stream` through
    `finally` with `truncated` false, so nothing terminated git: it blocked
    writing into a stdout pipe this loop would never read again, the cleanup
    blocked reading a stderr that could not reach EOF, and the search never
    returned at all. No deadline helps — nothing consults one from in there.

    Measured on 2026-09-07 before the fix: one bad byte on the first matched
    line and 6,000 matches after it, and the process printed "searching…" and
    nothing else for as long as it was left alone. A gate that never returns
    is worse than one that answers wrongly, and it is invisible to every test
    that drives the decoder directly. Codex, fifth gate round.

    Run on a thread with a join deadline, so a regression fails this test
    rather than wedging the suite.
    """

    def test_a_bad_byte_mid_stream_still_returns(self, git_repo):
        import subprocess
        import threading
        env = {"GIT_AUTHOR_NAME": "Test", "GIT_AUTHOR_EMAIL": "t@example.com",
               "GIT_COMMITTER_NAME": "Test",
               "GIT_COMMITTER_EMAIL": "t@example.com",
               "PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": str(git_repo)}

        def git(*args):
            return subprocess.run(("git", "-C", str(git_repo), *args),
                                  check=True, capture_output=True, text=True,
                                  env=env).stdout

        # Invalid UTF-8 on the first matched line, then far more output than a
        # 64 KiB pipe holds, so git is still writing when the decoder raises.
        # No NUL anywhere, or `-I` would skip the file as binary and the
        # matched line would never reach the decoder.
        (git_repo / "bad.py").write_bytes(
            b"eval(\xff) first\n"
            + b"".join(b"eval(x)  # occurrence %d\n" % n for n in range(6000)))
        git("add", "-A")
        git("commit", "-qm", "bad")
        head = git("rev-parse", "HEAD").strip()
        ws = Workspace(root=git_repo, diff_head=head, excludes=())

        outcome = []

        def run():
            try:
                outcome.append(("returned", ws.search("eval")))
            except BaseException as exc:      # noqa: BLE001 - recorded, not handled
                outcome.append(("raised", exc))

        worker = threading.Thread(target=run, daemon=True)
        worker.start()
        worker.join(timeout=60)
        assert not worker.is_alive(), (
            "search did not return: git is blocked writing into a pipe "
            "nobody is draining")
        assert outcome and outcome[0][0] == "raised", outcome
        assert isinstance(outcome[0][1], WorkspaceError), outcome[0][1]


class TestTheReviewedTreeDoesNotDescribeItself:
    """One line of `.gitattributes` disarmed the gate, and it needed nothing
    else — no configuration, no locale, no unusual file.

    A contributor adds `*.py -diff` in the same merge request as the weakness.
    `git diff --numstat` then prints `-` for both counts, the file is
    classified binary and drops out of the changed-line map — while the map
    stays non-empty, because `.gitattributes` itself is in it. `tools.py`
    reads the empty attribution as "this line was already there", the finding
    is filed pre-existing, and `gate.blocking_findings` skips it. Measured end
    to end on 2026-09-07: exit 1 became exit 0, the verdict line said "none at
    or above the high threshold" about a `critical`, and the finding was never
    verified because `_worth_verifying` skips pre-existing ones.

    `--no-ext-diff` and the pinned `GIT_CONFIG_*` already close the
    neighbouring route, because an external diff driver has to be *defined* in
    configuration. `-diff` is built into git and needs no configuration, which
    is how it walked through a guard written against the same idea.
    """

    def repo(self, tmp_path, attributes=""):
        import subprocess
        env = {"GIT_AUTHOR_NAME": "T", "GIT_AUTHOR_EMAIL": "t@e.com",
               "GIT_COMMITTER_NAME": "T", "GIT_COMMITTER_EMAIL": "t@e.com",
               "PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": str(tmp_path)}

        def git(*args):
            return subprocess.run(("git", "-C", str(tmp_path), *args),
                                  check=True, capture_output=True, text=True,
                                  env=env).stdout

        git("init", "-q")
        (tmp_path / "app.py").write_text("def h(r):\n    return ok()\n",
                                         encoding="utf-8")
        git("add", "-A")
        git("commit", "-qm", "base")
        base = git("rev-parse", "HEAD").strip()
        (tmp_path / "app.py").write_text(
            "def h(r):\n    return os.system(r.args['c'])\n", encoding="utf-8")
        if attributes:
            (tmp_path / ".gitattributes").write_text(attributes,
                                                     encoding="utf-8")
        git("add", "-A")
        git("commit", "-qm", "change")
        head = git("rev-parse", "HEAD").strip()
        return Workspace(root=tmp_path, diff_base=base, diff_head=head)

    def test_an_attributes_file_outside_the_tree_refuses_the_run(
            self, tmp_path):
        """The part that was not closed, named by Codex on 2026-09-07 and
        built 2026-09-09.

        `--attr-source` pins where git reads the *tree's* `.gitattributes`.
        `$GIT_DIR/info/attributes` is not in the tree, outranks it, and
        reproduces the whole effect from one line: every changed file looks
        binary, the diff becomes "Binary files … differ", searches return
        nothing, and the finding is filed pre-existing and never verified.

        Nothing a merge request pushes reaches that file — this is the
        runner's own state, and the refusal is a refusal to *claim*. It gives
        `WorkspaceError`, which the CLI turns into exit 2: the check did not
        run, which is a different answer from "nothing was found".
        """
        ws = self.repo(tmp_path)
        info = tmp_path / ".git" / "info"
        info.mkdir(parents=True, exist_ok=True)
        (info / "attributes").write_text("*.py -diff\n", encoding="utf-8")

        with pytest.raises(WorkspaceError) as caught:
            ws.refuse_untrusted_attributes()

        assert "outranks the pinned attribute source" in str(caught.value)
        assert "fresh git directory" in str(caught.value)

    def test_no_attributes_file_outside_the_tree_is_no_objection(
            self, tmp_path):
        """The control, or the check above passes on a workspace that refuses
        every repository."""
        self.repo(tmp_path).refuse_untrusted_attributes()

    def test_an_empty_attributes_file_is_no_objection(self, tmp_path):
        """A zero-byte file sets no attribute. A gate that fires on nothing is
        one somebody switches off, and then it guards nothing at all."""
        ws = self.repo(tmp_path)
        info = tmp_path / ".git" / "info"
        info.mkdir(parents=True, exist_ok=True)
        (info / "attributes").write_text("\n  \n", encoding="utf-8")

        ws.refuse_untrusted_attributes()

    @pytest.mark.parametrize("body", [
        "# a comment and nothing else\n",
        "*.tar export-ignore\n",
        "*.sh eol=lf\n",
        "# leading comment\n\n*.md linguist-documentation\n",
        "*.png filter=lfs merge=lfs\n",
        # Codex, 2026-09-09: `binary` is git's own macro and expands to
        # `-diff -text` **only when it is set**. These three do not invoke it
        # and hide nothing, and the first version of the parser reduced every
        # token to its name before testing it — so all three exited 2 on a
        # checkout nothing was wrong with.
        "*.py -binary\n",
        "*.py !binary\n",
        "*.py binary=maybe\n",
    ])
    def test_an_attributes_file_that_cannot_hide_a_diff_is_no_objection(
            self, tmp_path, body):
        """Codex, 2026-09-09, against the first version of this check.

        It refused any file with a non-blank line in it, so a comment — or an
        ordinary `export-ignore` — exited 2 on a repository nothing was wrong
        with, in a developer or CI checkout where such files are normal. That
        is the gate-that-fires-on-nothing this file's own comments warn about,
        written two paragraphs under one of them, and such a gate is deleted
        rather than obeyed — which costs the real route as well.
        """
        ws = self.repo(tmp_path)
        info = tmp_path / ".git" / "info"
        info.mkdir(parents=True, exist_ok=True)
        (info / "attributes").write_text(body, encoding="utf-8")

        ws.refuse_untrusted_attributes()

    @pytest.mark.parametrize("body, expected", [
        ("*.py -diff\n", "*.py -diff"),
        ("*.py !diff\n", "*.py !diff"),
        ("*.py diff=nothing\n", "*.py diff=nothing"),
        ("*.py binary\n", "*.py binary"),
        ("*.py text\n", "*.py text"),
        ("*.py -text\n", "*.py -text"),
        ("# a comment\n*.tar export-ignore\n*.py -diff\n", "*.py -diff"),
    ])
    def test_every_spelling_that_can_hide_a_diff_is_refused(
            self, tmp_path, body, expected):
        """`binary` is a macro for `-diff -text`, and `diff` may be set, unset,
        unspecified or pointed at a driver. Each changes what a review can
        read, so each is refused — and the refusal quotes the line, because a
        reader told only that "attributes are set" has to find it themselves.
        """
        ws = self.repo(tmp_path)
        info = tmp_path / ".git" / "info"
        info.mkdir(parents=True, exist_ok=True)
        (info / "attributes").write_text(body, encoding="utf-8")

        with pytest.raises(WorkspaceError) as caught:
            ws.refuse_untrusted_attributes()

        assert repr(expected) in str(caught.value)

    def test_a_git_failure_is_not_reported_as_a_missing_file(self, tmp_path):
        """Found 2026-09-09. `_blob_size` ran `cat-file` with `check=False` and
        turned every non-zero return into `None`, which `_blob_at` turns into
        `FileNotAtRevision` — so one unreadable object made a real `critical`
        get rejected as `unknown-path`, the reviewer was told "do not report
        this finding again", and the run exited 0.

        `terminal._dropped` prints one hard-coded reason for every rejection,
        so the only trace in the job log blamed the model for a git failure.

        The two are distinguishable and only in stderr, measured rather than
        assumed: a path that is not in the revision says "does not exist" or
        "exists on disk, but not in", and everything else is this tool failing
        to look.
        """
        ws = self.repo(tmp_path)

        # A revision git cannot resolve: not an answer about any file.
        with pytest.raises(WorkspaceError) as caught:
            ws._blob_size("nosuchrevision", "app.py")
        assert "could not say what" in str(caught.value)

    def test_a_path_absent_from_the_revision_is_still_an_answer(self, tmp_path):
        """The control, and the reason the refusal reads stderr rather than the
        return code: both cases exit 128, and only one of them is a failure."""
        ws = self.repo(tmp_path)

        assert ws._blob_size("HEAD", "never-existed.py") is None

    def test_a_linked_worktree_reads_the_shared_attributes_file(self, tmp_path):
        """Codex, 2026-09-09. `--absolute-git-dir` in a linked worktree is that
        worktree's own administrative directory, and git resolves shared paths
        such as `info/attributes` through the **common** directory — so the
        harmful file was still reaching git while this guard read a path that
        does not exist and returned quietly.

        `--git-path` asks git where it will look, which is the only question
        this check has.
        """
        import subprocess
        self.repo(tmp_path)
        linked = tmp_path.parent / (tmp_path.name + "-linked")
        subprocess.run(["git", "-C", str(tmp_path), "worktree", "add", "-q",
                        "-b", "side", str(linked)],
                       check=True, capture_output=True)
        info = tmp_path / ".git" / "info"
        info.mkdir(parents=True, exist_ok=True)
        (info / "attributes").write_text("*.py -diff\n", encoding="utf-8")

        ws = Workspace(root=linked, excludes=())

        with pytest.raises(WorkspaceError) as caught:
            ws.refuse_untrusted_attributes()
        assert "*.py -diff" in str(caught.value)

    def test_a_macro_defined_in_the_tree_and_used_outside_it_is_closed(
            self, tmp_path):
        """The shape the predicate lets through, and why that is right.

        `[attr]hidden -diff -text` in the tree's `.gitattributes` with
        `*.py hidden` in `$GIT_DIR/info/attributes` puts no dangerous token in
        the file `refuse_untrusted_attributes` reads. Measured 2026-09-09
        through the product's own reader: the pinned `--attr-source` leaves the
        macro undefined and the diff comes back readable, so there is nothing
        to refuse.

        The first attempt to establish this used a hand-rolled `git diff` with
        `check=False` and read only stdout — a git that refused the flag gave
        an empty string, and "the diff is hidden" was true for every case
        including the control. A measurement with no control is what let a gap
        be claimed and then withdrawn; this one carries its control below.
        """
        ws = self.repo(tmp_path, "[attr]hidden -diff -text\n")
        info = tmp_path / ".git" / "info"
        info.mkdir(parents=True, exist_ok=True)
        (info / "attributes").write_text("*.py hidden\n", encoding="utf-8")

        # Nothing to refuse: no line here names a diff attribute.
        ws.refuse_untrusted_attributes()
        # And git does not apply it, so the change is readable.
        assert "os.system" in ws.diff()

        # The control. The same macro *defined* in the untrusted file does
        # hide it, and is refused — the definition carries `-diff`.
        (info / "attributes").write_text(
            "[attr]hidden -diff -text\n*.py hidden\n", encoding="utf-8")
        with pytest.raises(WorkspaceError):
            ws.refuse_untrusted_attributes()
        assert "os.system" not in ws.diff()

    def test_a_file_marked_undiffable_is_still_attributed(self, tmp_path):
        """The defect. The changed line has to be attributable, or the finding
        on it is filed as code the change did not touch."""
        ws = self.repo(tmp_path, "*.py -diff\n")
        changed = ws.changed_line_map()
        assert "app.py" in changed.added, (
            "the attacker's own file decided this line was not changed: {}"
            .format(sorted(changed.added)))
        assert changed.added["app.py"]

    def test_the_control_without_the_attack(self, tmp_path):
        """The same repository, one line lighter. A control that answers the
        same way as the attack proves nothing about the attack."""
        ws = self.repo(tmp_path)
        changed = ws.changed_line_map()
        assert "app.py" in changed.added

    def test_it_is_not_reported_as_unreadable_either(self, tmp_path):
        """The second route to the same end: a file counted unreadable is
        subtracted from the readable change, and a change with nothing
        readable left exits 0 through the "reviewed nothing" branch."""
        ws = self.repo(tmp_path, "*.py -diff\n")
        unreadable = [o.path for o in ws.changed_objects()
                      if not o.has_reviewable_text]
        assert "app.py" not in unreadable, unreadable

    def test_marking_everything_undiffable_does_not_empty_the_change(
            self, tmp_path):
        """`* -diff` was the wider variant: every file reads binary, the map
        comes back empty, and `gate._readable_change` subtracts the unreadable
        set from the changed set and finds nothing left."""
        ws = self.repo(tmp_path, "* -diff\n")
        unreadable = [o.path for o in ws.changed_objects()
                      if not o.has_reviewable_text]
        assert unreadable == [], unreadable
        assert "app.py" in ws.changed_line_map().added

    def test_the_diff_the_model_reads_is_pinned_too(self, tmp_path):
        """`_bounded` builds its own `Popen` and did not carry the pin.

        The attribution map was protected while the primary diff — the thing
        the model actually reads — still let the reviewed tree decide what git
        would show. Codex found it on the gate for the first repair,
        2026-09-07: protecting the accounting and not the material is half a
        fix.
        """
        ws = self.repo(tmp_path, "*.py -diff\n")
        body = ws.diff()
        assert "Binary files" not in body, body[:200]
        assert "os.system" in body, body[:200]

    def test_search_is_pinned_too(self, tmp_path):
        """`git grep -I` skips what it considers binary, and `-diff` is how a
        contributor makes their own file considered binary. A search that
        cannot find the weakness is a verifier that cannot refute a claim
        about it."""
        ws = self.repo(tmp_path, "*.py -diff\n")
        body, count = ws.search("os.system")
        assert count == 1, body[:200]
        assert "app.py" in body, body[:200]

    def test_the_control_for_both(self, tmp_path):
        """Same repository, one line lighter. A control that answers the same
        way as the attack proves nothing about the attack."""
        ws = self.repo(tmp_path)
        assert "os.system" in ws.diff()
        assert ws.search("os.system")[1] == 1

    def test_a_genuinely_binary_file_is_still_binary(self, tmp_path):
        """The cost that must not be paid. Pinning the attribute source must
        not defeat git's own content detection, or the reviewer would be
        handed a PNG as text."""
        import subprocess
        env = {"GIT_AUTHOR_NAME": "T", "GIT_AUTHOR_EMAIL": "t@e.com",
               "GIT_COMMITTER_NAME": "T", "GIT_COMMITTER_EMAIL": "t@e.com",
               "PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": str(tmp_path)}

        def git(*args):
            return subprocess.run(("git", "-C", str(tmp_path), *args),
                                  check=True, capture_output=True, text=True,
                                  env=env).stdout

        git("init", "-q")
        (tmp_path / "logo.png").write_bytes(bytes(range(256)) * 4)
        git("add", "-A")
        git("commit", "-qm", "base")
        base = git("rev-parse", "HEAD").strip()
        (tmp_path / "logo.png").write_bytes(bytes(range(255, -1, -1)) * 4)
        git("add", "-A")
        git("commit", "-qm", "change")
        head = git("rev-parse", "HEAD").strip()
        ws = Workspace(root=tmp_path, diff_base=base, diff_head=head)
        unreadable = [(o.path, o.why_unreadable())
                      for o in ws.changed_objects()
                      if not o.has_reviewable_text]
        assert unreadable == [("logo.png", "binary")], unreadable

    def test_a_first_call_that_cannot_run_git_is_a_workspace_error(
            self, tmp_path, monkeypatch):
        """`_argv` resolves the pinned attribute source, which runs git on the
        first call of a workspace's life — inside paths that give a
        `WorkspaceError` for every other way git can fail.

        A raw `OSError` escaping from there is a crash where the rest of the
        class reports "I could not check", and those are different answers with
        different exit codes. Codex, second gate round, 2026-09-07.
        """
        import subprocess as sp

        import security_agent.workspace as W
        ws = self.repo(tmp_path)
        real = sp.run

        def refuse(cmd, **kwargs):
            if "hash-object" in cmd:
                raise OSError(2, "No such file or directory: 'git'")
            return real(cmd, **kwargs)

        monkeypatch.setattr(W.subprocess, "run", refuse)
        with pytest.raises(WorkspaceError, match="could not be run"):
            ws.diff()
        with pytest.raises(WorkspaceError, match="could not be run"):
            ws.search("os.system")

    def test_a_first_call_that_times_out_is_a_workspace_error(
            self, tmp_path, monkeypatch):
        import subprocess as sp

        import security_agent.workspace as W
        ws = self.repo(tmp_path)
        real = sp.run

        def stall(cmd, **kwargs):
            if "hash-object" in cmd:
                raise sp.TimeoutExpired(cmd, 1)
            return real(cmd, **kwargs)

        monkeypatch.setattr(W.subprocess, "run", stall)
        with pytest.raises(WorkspaceError, match="timed out"):
            ws.diff()
        with pytest.raises(WorkspaceError, match="timed out"):
            ws.search("os.system")

    def test_the_empty_tree_is_not_cached_across_repositories(self, tmp_path):
        """A cache keyed on nothing is a defect waiting to go quiet.

        The first version held it on the class, which is the same object id
        everywhere right up until it is not: a SHA-256 repository's empty tree
        is `6ef19b41...` where SHA-1's is `4b825dc6...`. Measured — git answers
        `fatal: bad --attr-source` and exits 128, so today it would be a loud
        failure. It is per instance now, so the question does not arise.
        """
        one, two = tmp_path / "one", tmp_path / "two"
        one.mkdir()
        two.mkdir()
        first = self.repo(one)
        second = self.repo(two)
        assert "_EMPTY_TREE" not in vars(type(first)), (
            "the empty tree is cached on the class and shared between "
            "repositories")
        assert first._empty_tree() == first._empty_tree()
        assert second._empty_tree()

    def test_the_empty_tree_is_asked_of_git(self, tmp_path):
        """Not hardcoded. `4b825dc...` is the SHA-1 empty tree and a SHA-256
        repository has a different one, so a constant would silently stop
        pinning anything there."""
        ws = self.repo(tmp_path)
        assert len(ws._empty_tree()) in (40, 64)
        assert all(c in "0123456789abcdef" for c in ws._empty_tree())
