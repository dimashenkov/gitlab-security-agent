"""Reviewing less, without quietly checking less well.

`--path` exists so a review can be run on a change instead of on a repository,
which is what makes running one ten times a day possible. It is also the
easiest flag in this project to get wrong, in two directions:

**It must not fence the reading tools.** The whole design rests on following
code out of the hunk — the validation that makes a change safe and the caller
that makes it exploitable are almost never in the diff. A scope that also
narrowed reads would turn every control it hid into a false positive, and the
tool would get less trustworthy the more precisely it was aimed.

**It must not soften the gate.** Attribution decides whether a weakness was
introduced or was already there, and pre-existing findings are gated more
softly. Narrowing the changed-line map along with the scope would make a flag
whose purpose is to look at less also make the gate more forgiving about what
it did look at.

And a scoped run has to say so. "No findings" from a review of one file and
"no findings" from a review of the change are the same sentence.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from security_agent.config import Config, GitLabContext
from security_agent.identity import digest, review_identity
from security_agent.models import Revision, ScanOutcome
from security_agent.workspace import Workspace

PROMPTS = Path(__file__).resolve().parents[1] / "prompts"


@pytest.fixture
def repo(tmp_path):
    """Two directories and a base commit, so a real diff can be taken."""
    root = tmp_path / "repo"
    (root / "app").mkdir(parents=True)
    (root / "vendor").mkdir()

    def git(*args):
        subprocess.run(["git", "-C", str(root), *args], check=True,
                       capture_output=True)

    subprocess.run(["git", "init", "-q", str(root)], check=True,
                   capture_output=True)
    git("config", "user.email", "t@example.com")
    git("config", "user.name", "T")
    (root / "app" / "views.py").write_text("def get_user(uid):\n    return uid\n")
    (root / "vendor" / "lib.py").write_text("VALUE = 1\n")
    (root / "README.md").write_text("hello\n")
    git("add", "-A")
    git("commit", "-qm", "base")
    base = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"],
                          capture_output=True, text=True, check=True).stdout.strip()

    (root / "app" / "views.py").write_text(
        'def get_user(uid):\n    return db.execute("SELECT " + uid)\n')
    (root / "vendor" / "lib.py").write_text("VALUE = 2\n")
    (root / "README.md").write_text("hello there\n")
    git("add", "-A")
    git("commit", "-qm", "change")
    return root, base


def _ws(repo, scope=()):
    root, base = repo
    return Workspace(root=root, excludes=(), diff_base=base, diff_head="HEAD",
                     scope=scope)


# --------------------------------------------------------- what it narrows


def test_no_scope_reviews_every_changed_file(repo):
    """The only safe default for a gate."""
    paths = [p for p, _ in _ws(repo).changed_files()]

    assert set(paths) == {"app/views.py", "vendor/lib.py", "README.md"}


def test_a_deletion_a_rule_hid_is_still_in_the_unfiltered_list(repo, tmp_path):
    """Found 2026-09-09, hunting the shapes that reach the gate with nothing
    opened.

    `every_changed_file` exists so the report can say *which* filter emptied
    the review — the excludes or the `--path`. It kept `--diff-filter=ACMRT`,
    with a docstring arguing that a deleted file is "correctly absent rather
    than counted as something a rule hid". When a rule hides one, that is
    exactly what it is.

    A merge request whose only change was `git rm vendor/guard.php` — a path in
    `DEFAULT_EXCLUDES`, so with no operator configuration involved — emptied
    every list, so the report named no filter and said "This change adds or
    modifies no file". The same file *modified* correctly said every file was
    excluded: the deletion was reported strictly worse than the modification.
    """
    root, _base = repo
    subprocess.run(["git", "-C", str(root), "rm", "-q", "vendor/lib.py"],
                   check=True, capture_output=True)
    subprocess.run(["git", "-C", str(root), "commit", "-qm", "remove"],
                   check=True, capture_output=True)

    # The removal commit alone, so the change really is a deletion and nothing
    # else — the shape that emptied every list.
    ws = Workspace(root=root, excludes=("*/vendor/*", "vendor/*"),
                   diff_base="HEAD~1", diff_head="HEAD")

    assert ws.changed_files() == []
    every = dict(ws.every_changed_file())
    assert "vendor/lib.py" in every
    assert every["vendor/lib.py"] == "deleted"
    # And the filter is still off in the unfiltered list: the caller asks the
    # two predicates itself, one at a time.
    assert ws.is_excluded("vendor/lib.py")


def test_a_rename_out_of_the_reviewed_set_shows_both_ends(repo):
    """Codex, 2026-09-09, on my own repair — and on the test I wrote for it.

    Moving a guard from `app/` to `vendor/` empties the review exactly as
    deleting it does, because the new path is excluded. Reporting only the new
    path said "every file is excluded" and counted nothing as removed, so a
    guard moved out of review was described less clearly than one deleted —
    the same asymmetry, one step along.

    My first test for this used no excludes and asserted only that the old path
    was absent, which **passes with the old implementation restored**, because
    `changed_files` was already `-M`-aware. It proved nothing. This one names
    the case that separates the two.
    """
    root, _base = repo
    subprocess.run(["git", "-C", str(root), "mv", "app/views.py",
                    "vendor/views.py"], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(root), "commit", "-qm", "move"],
                   check=True, capture_output=True)

    ws = Workspace(root=root, excludes=("*/vendor/*", "vendor/*"),
                   diff_base="HEAD~1", diff_head="HEAD")

    assert ws.changed_files() == []
    every = dict(ws.every_changed_file())
    assert every == {"vendor/views.py": "renamed",
                     "app/views.py": "moved_from"}


class TestWhatARuleHidIsRecorded:
    """`Coverage.excluded` was declared, serialised, and assigned by nobody;
    `out_of_scope` was filled from `all_changed_files`, which is
    `--diff-filter=ACMRT`. So a *deletion* an exclude rule or a `--path` hid
    appeared in **no field of `Coverage` at all** — the run proceeded on its
    merits, exited 0 or 1, and nothing anywhere said a file had been removed.

    The argument is the one `out_of_scope`'s own docstring already makes: a
    scoped review reporting "no findings" without saying what it did not look
    at is the same sentence as a full review that found nothing. Recorded
    2026-09-09, built the same day.
    """

    def test_a_deleted_file_an_exclude_rule_hid_is_named(self, repo):
        root, _base = repo
        subprocess.run(["git", "-C", str(root), "rm", "-q", "vendor/lib.py"],
                       check=True, capture_output=True)
        subprocess.run(["git", "-C", str(root), "commit", "-qm", "remove"],
                       check=True, capture_output=True)

        ws = Workspace(root=root, excludes=("*/vendor/*", "vendor/*"),
                       diff_base="HEAD~1", diff_head="HEAD")
        excluded, out_of_scope = ws.hidden_by_rules()

        assert excluded == ["vendor/lib.py"]
        assert out_of_scope == []
        # And it is gone from every list the filters build, which is the
        # reason a separate reader is needed at all.
        assert ws.changed_files() == []
        assert [obj.path for obj in ws.changed_objects()] == []

    def test_a_deleted_file_the_scope_left_out_is_named_separately(self, repo):
        """The two rules are the operator's and they are set in different
        places. A report that mixes them costs a debugging session."""
        root, _base = repo
        subprocess.run(["git", "-C", str(root), "rm", "-q", "app/views.py"],
                       check=True, capture_output=True)
        subprocess.run(["git", "-C", str(root), "commit", "-qm", "remove"],
                       check=True, capture_output=True)

        ws = Workspace(root=root, excludes=(), diff_base="HEAD~1",
                       diff_head="HEAD", scope=("docs",))
        excluded, out_of_scope = ws.hidden_by_rules()

        assert excluded == []
        assert out_of_scope == ["app/views.py"]

    def test_a_path_both_rules_cover_is_reported_once(self, repo):
        """Two lists that overlap are counted twice by anybody who adds them.
        `is_excluded` is asked first, matching `changed_files`."""
        root, _base = repo
        subprocess.run(["git", "-C", str(root), "rm", "-q", "vendor/lib.py"],
                       check=True, capture_output=True)
        subprocess.run(["git", "-C", str(root), "commit", "-qm", "remove"],
                       check=True, capture_output=True)

        ws = Workspace(root=root, excludes=("vendor/*",), diff_base="HEAD~1",
                       diff_head="HEAD", scope=("docs",))
        excluded, out_of_scope = ws.hidden_by_rules()

        assert excluded == ["vendor/lib.py"]
        assert out_of_scope == []

    def test_a_change_no_rule_touches_names_nothing(self, repo):
        """The control. A field that fills up on an ordinary change is a field
        readers learn to ignore."""
        root, base = repo

        ws = Workspace(root=root, excludes=(), diff_base=base,
                       diff_head="HEAD")

        assert ws.hidden_by_rules() == ([], [])


def test_a_rename_into_the_reviewed_set_reports_its_old_path_too(repo):
    """And the caller must not read that as a removal.

    Measured 2026-09-09 across four rename shapes. Counting every `moved_from`
    was the first repair and it is wrong in this direction: a file moved *into*
    review reports its old, excluded path as `moved_from`, and nothing left the
    reviewed set at all. `cli.py` therefore counts a move only when the path
    that moved was itself reviewable.
    """
    root, _base = repo
    subprocess.run(["git", "-C", str(root), "mv", "vendor/lib.py",
                    "app/lib.py"], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(root), "commit", "-qm", "move in"],
                   check=True, capture_output=True)

    ws = Workspace(root=root, excludes=("*/vendor/*", "vendor/*"),
                   diff_base="HEAD~1", diff_head="HEAD")

    # Non-empty, so the diagnostic branch never runs for this shape — but the
    # list is what the next caller will read.
    assert [p for p, _ in ws.changed_files()] == ["app/lib.py"]
    assert dict(ws.every_changed_file()) == {"app/lib.py": "renamed",
                                             "vendor/lib.py": "moved_from"}


def test_a_rename_inside_the_reviewed_set_is_not_a_removal(repo):
    """The control. A file moved from one reviewable path to another has not
    left the reviewed set, and the old path is `moved_from` rather than
    `deleted` so the caller can tell the two apart."""
    root, _base = repo
    subprocess.run(["git", "-C", str(root), "mv", "app/views.py",
                    "app/handlers.py"], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(root), "commit", "-qm", "rename"],
                   check=True, capture_output=True)

    every = dict(Workspace(root=root, excludes=(), diff_base="HEAD~1",
                           diff_head="HEAD").every_changed_file())

    assert every == {"app/handlers.py": "renamed", "app/views.py": "moved_from"}
    # Not "deleted": `raw_changed_paths` runs `--no-renames` and would have
    # said so, and a list that says a false thing is one the next caller
    # believes.
    assert "deleted" not in every.values()


def test_a_directory_name_matches_everything_under_it(repo):
    """What a person means by "just look at the app code". Requiring
    `app/*` for that would be a trap rather than a feature."""
    paths = [p for p, _ in _ws(repo, ("app",)).changed_files()]

    assert paths == ["app/views.py"]


def test_a_glob_matches_by_pattern(repo):
    paths = [p for p, _ in _ws(repo, ("*.md",)).changed_files()]

    assert paths == ["README.md"]


def test_an_exact_path_matches_only_itself(repo):
    paths = [p for p, _ in _ws(repo, ("app/views.py",)).changed_files()]

    assert paths == ["app/views.py"]


def test_several_paths_are_a_union(repo):
    paths = sorted(p for p, _ in _ws(repo, ("app", "*.md")).changed_files())

    assert paths == ["README.md", "app/views.py"]


def test_a_scope_matching_nothing_reviews_nothing(repo):
    """Rather than silently falling back to everything. A flag that reviews the
    whole change when it was meant to review one file is worse than one that
    reviews nothing and says so."""
    assert _ws(repo, ("does/not/exist",)).changed_files() == []


def test_the_diff_is_narrowed_to_the_scope(repo):
    """Not only the file list. A briefing carrying the whole change while the
    coverage accounting claims one file would put text in front of the model
    that the artifact says was never in the review."""
    diff = _ws(repo, ("app",)).diff()

    assert "app/views.py" in diff
    assert "vendor/lib.py" not in diff


def test_what_was_left_out_is_available_to_the_report(repo):
    ws = _ws(repo, ("app",))
    skipped = ws.out_of_scope([p for p, _ in ws.all_changed_files()])

    assert sorted(skipped) == ["README.md", "vendor/lib.py"]


# ------------------------------------------------------ what it must not do


def test_scope_does_not_narrow_what_can_be_read(repo):
    """The failure that would make the tool worse the more precisely it is
    aimed. Following a caller out of the scoped file is the only way a finding
    gets checked."""
    ws = _ws(repo, ("app",))

    assert "VALUE = 2" in ws.blob_text("vendor/lib.py")
    assert "vendor/lib.py" in ws.tracked_files()


def test_scope_does_not_narrow_the_changed_line_map(repo):
    """Attribution is a fact about the change, not about what this run was
    asked to look at. Narrowing it would make an out-of-scope finding look
    pre-existing — and pre-existing findings are gated more softly, so a flag
    for looking at less would make the gate more permissive."""
    scoped = _ws(repo, ("app",)).changed_line_map()
    whole = _ws(repo).changed_line_map()

    assert scoped.files() == whole.files()


# ------------------------------------------ a scoped run cannot pass as full


def test_a_scoped_review_has_a_different_identity(repo):
    """Without this, a review of one file and a review of the change share a
    key, so the narrow one gets reused as the answer to the broad question —
    and a reused artifact is indistinguishable from a review that ran."""
    _root, base = repo
    revision = Revision(mode="diff", base=base, head="HEAD",
                        base_sha=base, head_sha="deadbeef")
    full = Config(prompt_dir=PROMPTS, gitlab=GitLabContext())
    scoped = Config(prompt_dir=PROMPTS, gitlab=GitLabContext(), scope=("app",))

    assert digest(review_identity(full, revision, None)) != \
        digest(review_identity(scoped, revision, None))


def test_the_report_says_the_review_was_scoped(repo):
    from security_agent.gate import decide
    from security_agent.report import render_markdown

    cfg = Config(prompt_dir=PROMPTS, gitlab=GitLabContext(), scope=("app",),
                 post_comment=False)
    outcome = ScanOutcome(mode="diff")
    outcome.coverage.changed = ["app/views.py"]
    outcome.coverage.out_of_scope = ["README.md", "vendor/lib.py"]

    markdown = render_markdown(cfg, outcome, decide(cfg, outcome))

    assert "Scoped review" in markdown
    assert "not a review of the change" in markdown
    assert "vendor/lib.py" in markdown


def test_an_unscoped_report_says_nothing_about_scope(repo):
    """A warning on every clean review is a warning nobody reads."""
    from security_agent.gate import decide
    from security_agent.report import render_markdown

    cfg = Config(prompt_dir=PROMPTS, gitlab=GitLabContext(), post_comment=False)
    markdown = render_markdown(cfg, ScanOutcome(mode="diff"),
                               decide(cfg, ScanOutcome(mode="diff")))

    assert "Scoped review" not in markdown
