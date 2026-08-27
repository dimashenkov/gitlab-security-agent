"""A change cannot excuse itself, and for a fortnight it could.

The guard exists so that a merge request adding a weakness and the entry
excusing it, in one commit, does not approve itself. It was written, it was
documented in two places, it had tests — and it had never once fired, because
the comparison behind it was wrong:

    str(Path(".security-agent-ignore.yml")).lstrip("./")   ->  "security-agent-ignore.yml"

`lstrip` takes a *set* of characters, not a prefix. Git reports the path with
its leading dot, so the two strings were never equal, and every run passed
`self_added=False` no matter what the change did.

It survived because the tests below it tested the link. `test_suppress.py`
called `apply(..., self_added=True)` directly, which proves the suppression
layer honours the flag and nothing about whether anything ever sets it. The two
CLI-level tests ran in `repo` mode, where `changed_files()` is empty by
construction, so the guard was `False` there for an unrelated reason and the
assertions still passed.

So every test here starts from a real git repository with a real commit that
edits a real file, and goes through the real entry point. Three lines of YAML
were enough to silence the whole tool; nothing shorter than the chain would
have noticed.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from security_agent.config import Config, GitLabContext
from security_agent.workspace import Workspace

IGNORE = ".security-agent-ignore.yml"

# One entry, no fingerprint, no knowledge of what the review will find. `*` in
# an fnmatch pattern crosses `/`, so this covers the repository.
BLANKET = """ignore:
  - path: "*"
    reason: legacy debt
"""


@pytest.fixture
def repo(tmp_path):
    """A base commit, then a change that adds code and a suppression together."""
    root = tmp_path / "repo"
    (root / "app").mkdir(parents=True)

    def git(*args):
        subprocess.run(["git", "-C", str(root), *args], check=True,
                       capture_output=True)

    subprocess.run(["git", "init", "-q", str(root)], check=True, capture_output=True)
    git("config", "user.email", "t@example.com")
    git("config", "user.name", "T")
    (root / "app" / "views.py").write_text("def get_user(uid):\n    return uid\n")
    git("add", "-A")
    git("commit", "-qm", "base")
    base = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"],
                          capture_output=True, text=True, check=True).stdout.strip()
    return root, base, git


def _ws(repo, **overrides):
    root, base, _git = repo
    return Workspace(root=root, diff_base=base, diff_head="HEAD", **overrides)


def _commit_suppression(repo, body=BLANKET):
    root, _base, git = repo
    (root / IGNORE).write_text(body)
    (root / "app" / "views.py").write_text(
        'def get_user(uid):\n    return db.execute("SELECT " + uid)\n')
    git("add", "-A")
    git("commit", "-qm", "add a weakness and the excuse for it")


# --------------------------------------------------- the question, asked of git


def test_a_change_that_adds_a_suppression_is_seen(repo):
    """The assertion the old comparison would have failed. It compared
    `security-agent-ignore.yml` against git's `.security-agent-ignore.yml`."""
    _commit_suppression(repo)

    assert _ws(repo).change_touches(IGNORE) is True


def test_a_change_that_leaves_it_alone_is_not_seen(repo):
    """A guard that always fires is a guard nobody can turn off legitimately —
    an entry accepted last month has to keep working."""
    root, _base, git = repo
    (root / IGNORE).write_text(BLANKET)
    git("add", "-A")
    git("commit", "-qm", "accept a risk, on its own")
    second = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"],
                            capture_output=True, text=True, check=True).stdout.strip()
    (root / "app" / "views.py").write_text("def get_user(uid):\n    return int(uid)\n")
    git("add", "-A")
    git("commit", "-qm", "a later change that touches nothing else")

    later = Workspace(root=root, diff_base=second, diff_head="HEAD")
    assert later.change_touches(IGNORE) is False


def test_a_narrowed_scope_cannot_hide_the_suppression(repo):
    """`--path src` says what this run is answerable for. It must not decide
    whether the change edited the rules it is judged by — otherwise the flag for
    looking at less also switches the guard off."""
    _commit_suppression(repo)

    scoped = _ws(repo, scope=("app",))

    assert [p for p, _ in scoped.changed_files()] == ["app/views.py"]
    assert scoped.change_touches(IGNORE) is True


def test_an_exclude_pattern_cannot_hide_the_suppression(repo):
    """Same reasoning, one layer down. An exclusion says what the model may
    read; letting it answer this question would hand a committed exclusion the
    power to disable the guard."""
    _commit_suppression(repo)

    excluded = _ws(repo, excludes=("*.yml",))

    assert IGNORE not in [p for p, _ in excluded.changed_files()]
    assert excluded.change_touches(IGNORE) is True


def test_deleting_the_file_counts_as_touching_it(repo):
    """Removing the rules is an edit to the rules."""
    root, _base, git = repo
    (root / IGNORE).write_text(BLANKET)
    git("add", "-A")
    git("commit", "-qm", "accept a risk")
    second = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"],
                            capture_output=True, text=True, check=True).stdout.strip()
    (root / IGNORE).unlink()
    git("add", "-A")
    git("commit", "-qm", "remove it")

    assert Workspace(root=root, diff_base=second,
                     diff_head="HEAD").change_touches(IGNORE) is True


def test_a_similarly_named_file_is_not_it(repo):
    """`fnmatch` is not involved here and must not be. This is one exact path."""
    root, _base, git = repo
    (root / "security-agent-ignore.yml").write_text(BLANKET)
    git("add", "-A")
    git("commit", "-qm", "a file with a similar name")

    assert _ws(repo).change_touches(IGNORE) is False


def test_a_repo_mode_run_has_no_change_to_ask_about(repo):
    """Whole-tree mode reviews everything and diffs nothing, so there is no
    "this change" for the guard to be about. False rather than an error — and
    named here because the old tests passed for exactly this reason, in diff
    mode, where it was hiding a defect."""
    _commit_suppression(repo)
    root, _base, _git = repo

    assert Workspace(root=root, diff_base="",
                     diff_head="HEAD").change_touches(IGNORE) is False


# ------------------------------------------------ and what the run does with it


def test_the_gate_is_told_the_suppression_is_self_added(repo, tmp_path):
    """The chain, end to end: a real commit, the real entry point, and the
    finding survives into the report instead of being silenced by the same
    change that introduced it."""
    from security_agent.models import Candidate, Finding
    from security_agent.suppress import apply as apply_suppressions
    from security_agent.suppress import load as load_rules

    _commit_suppression(repo)
    root, _base, _git = repo
    cfg = Config(gitlab=GitLabContext(), ignore_file=Path(IGNORE))
    rules, _warnings = load_rules(root / cfg.ignore_file)
    assert rules, "the fixture's suppression file must actually parse"

    candidate = Candidate(finding=Finding(
        title="SQL injection in get_user", severity="high", confidence="high",
        category="injection", file="app/views.py", line=2,
        impact="broad_data_access", reachable_without_authentication="yes",
        requires_user_interaction="no",
        evidence='return db.execute("SELECT " + uid)',
        description="uid is concatenated into a query.",
        exploit_scenario="An anonymous caller reads every row.",
        recommendation="Bind the parameter."))

    touched = _ws(repo).change_touches(str(cfg.ignore_file))
    kept, suppressed = apply_suppressions([candidate], rules, self_added=touched)

    assert touched is True
    assert kept == [candidate]
    assert suppressed == []


# ------------------- three fail-open paths the agent found in its own fix


def test_renaming_the_file_away_counts_as_touching_it(repo):
    """`-M` reports only the *new* path of a rename, so a change that moved the
    suppression file somewhere the review would not read it was reported as
    having left it alone. Rename detection is off here for that reason."""
    root, _base, git = repo
    (root / IGNORE).write_text(BLANKET)
    git("add", "-A")
    git("commit", "-qm", "accept a risk")
    second = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"],
                            capture_output=True, text=True, check=True).stdout.strip()
    git("mv", IGNORE, "somewhere-else.yml")
    git("commit", "-qm", "move the rules out of the way")

    later = Workspace(root=root, diff_base=second, diff_head="HEAD")
    assert later.change_touches(IGNORE) is True


def test_a_case_folded_name_still_fires_the_guard(repo):
    """On a case-insensitive filesystem `load_rules` opens
    `.Security-Agent-Ignore.yml` when asked for the lower-case name, so the
    rules apply while a byte-for-byte comparison misses and the guard does
    not fire. Folded in this direction only: over-firing costs an argument,
    under-firing costs the gate."""
    root, _base, git = repo
    (root / ".Security-Agent-Ignore.yml").write_text(BLANKET)
    git("add", "-A")
    git("commit", "-qm", "the same file, differently cased")

    assert _ws(repo).change_touches(IGNORE) is True


def test_a_git_failure_is_raised_rather_than_read_as_untouched(repo, monkeypatch):
    """The fail-open this replaces. `check=False` turned a git error into an
    empty string, `any()` over nothing into `False`, and `False` into "the
    change did not touch its own suppression file" — silently, on the one
    control that stops a merge request approving itself."""
    from security_agent.workspace import WorkspaceError

    ws = _ws(repo)

    def refuse(*_args, **kwargs):
        if kwargs.get("check", True):
            raise WorkspaceError("git exploded")
        return ""

    monkeypatch.setattr(ws, "git", refuse)

    with pytest.raises(WorkspaceError):
        ws.change_touches(IGNORE)
