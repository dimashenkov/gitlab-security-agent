"""Tests for the sandbox boundary.

The agent reads code an untrusted contributor may have written, in a job holding
an API key and a GitLab token. Containment is not a nicety here, so the escape
attempts are tested explicitly rather than assumed.
"""

import pytest

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
        assert "there are more" in body
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
        # `count` is lines kept, and context lines are kept too — the match
        # plus the one line of context above it in this two-line file.
        assert count == 2, body
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
