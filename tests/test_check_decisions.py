"""The checker that keeps `DECISIONS.md` honest about itself.

Codex refused to admit the file without this, and the argument is the file's
own reason for existing: *without enforced states it becomes worse than missing
memory — it becomes confidently stale memory.* A ledger that looks strictly
structured and is machine-false is the failure it was written to prevent.

Every test here is a way the document goes wrong quietly. Renaming a test,
reversing a decision without saying so, letting a proposal sit among the
decisions — none of them would be noticed by anything else in the repository,
and all of them leave a reader trusting a sentence that is no longer true.
"""

from __future__ import annotations

import sys
from types import SimpleNamespace
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from check_decisions import DOC, check

DECISION = """## D-001 · A decision

| | |
|---|---|
| **Състояние** | действащо |
| **Обхват** | somewhere |
| **Проверено срещу** | {commit} |

**Решено.** This.

**Отхвърлено.** That.

**Причина.** Because.

**Наложено от.** `tools/check_decisions.py:check`.

**Доказателство.** `python3 tools/check_decisions.py`.

**Възражение (Codex).** It said something.

**Преразглежда се когато** a stated thing happens.
"""

PROPOSAL = """## P-001 · A proposal

| | |
|---|---|
| **Състояние** | предложено |
| **Обхват** | somewhere |

**Предложено.** This might be worth doing.

**Възражение (Codex).** It said something.

**Става решение когато** five cases exist.
"""


@pytest.fixture
def commit():
    import subprocess
    return subprocess.run(("git", "rev-parse", "--short", "HEAD"),
                          cwd=Path(__file__).resolve().parents[1],
                          capture_output=True, text=True,
                          check=True).stdout.strip()


def test_the_document_that_ships_is_clean():
    """The one that matters. Everything below tests the checker; this tests the
    file, and it is the assertion a reader of `DECISIONS.md` is relying on."""
    assert check(DOC.read_text(encoding="utf-8"), run_tests=False) == []


def test_a_file_the_checker_cannot_read_is_not_a_clean_file(commit):
    """The vacuous pass, and the reason it is checked first.

    Change the heading format and every loop below iterates over nothing —
    which reports success. A checker whose failure mode is silence is worse
    than none, because somebody stops looking.
    """
    problems = check("# Just prose, no entries\n", run_tests=False)
    assert problems and "reading nothing" in problems[0]


def test_a_state_that_carries_its_own_explanation_is_refused(commit):
    """`deystvashto, s izvestna dupka` was a real state in the first draft.

    It reads well and no parser can use it: the entry is active and qualified
    at once, and which half a reader takes away is up to them. The
    qualification goes in its own field.
    """
    body = DECISION.format(commit=commit).replace(
        "| действащо |", "| действащо, с известна дупка |")
    problems = check(body, run_tests=False)
    assert any("is not one of" in p for p in problems), problems


def test_a_decision_missing_its_evidence_is_refused(commit):
    """A decision without a command the reader can run is an opinion with a
    heading. The discarded alternative and the evidence are the whole value;
    what was chosen is already visible in the code."""
    body = DECISION.format(commit=commit).replace(
        "**Доказателство.** `python3 tools/check_decisions.py`.\n\n", "")
    problems = check(body, run_tests=False)
    assert any("Доказателство" in p for p in problems), problems


def test_a_symbol_that_no_longer_exists_is_caught(commit):
    """The ordinary way this file rots, and nothing else in the repository
    would notice: the code is renamed, the entry keeps citing the old name, and
    it goes on reading like an enforced rule."""
    body = DECISION.format(commit=commit).replace(
        "`tools/check_decisions.py:check`", "`tools/check_decisions.py:vanished`")
    problems = check(body, run_tests=False)
    assert any("no such symbol" in p for p in problems), problems


def test_a_commit_that_is_not_in_this_repository_is_caught(commit):
    """`Проверено срещу` is the entry's only claim about *when* it was true.
    A hash nobody can resolve makes that claim unfalsifiable."""
    body = DECISION.format(commit="0" * 12)
    problems = check(body, run_tests=False)
    assert any("not in this repository" in p for p in problems), problems


def test_a_superseded_entry_must_name_its_successor(commit):
    """Otherwise the reader has nowhere to go and no way to know the decision
    moved — which is indistinguishable from the decision being abandoned."""
    body = DECISION.format(commit=commit).replace(
        "| действащо |", "| заменено |")
    problems = check(body, run_tests=False)
    assert any("does not name its successor" in p for p in problems), problems


def test_supersession_must_point_both_ways(commit):
    """One direction leaves two entries that both read as current.

    Untested by anything until the first reversal happens, which is exactly why
    it is written now: the entry that replaces another will be written by
    somebody with none of this in mind.
    """
    old = DECISION.format(commit=commit).replace(
        "## D-001 · A decision", "## D-001 · The old one").replace(
        "| действащо |", "| заменено |").replace(
        "| **Обхват** | somewhere |", "| **Обхват** | somewhere |\n| **Заменено от** | D-002 |")
    new = DECISION.format(commit=commit).replace(
        "## D-001 · A decision", "## D-002 · The new one")

    problems = check(old + "\n" + new, run_tests=False)
    assert any("does not say so back" in p for p in problems), problems

    fixed = new.replace("| **Обхват** | somewhere |",
                        "| **Обхват** | somewhere |\n| **Заменя** | D-001 |")
    assert check(old + "\n" + fixed, run_tests=False) == []


def test_an_entry_cannot_replace_itself(commit):
    body = DECISION.format(commit=commit).replace(
        "| **Обхват** | somewhere |",
        "| **Обхват** | somewhere |\n| **Заменя** | D-001 |")
    problems = check(body, run_tests=False)
    assert any("replaces itself" in p for p in problems), problems


def test_a_proposal_is_held_to_the_proposal_schema_and_not_the_other_one(commit):
    """A proposal has no `Наложено от` and no `Проверено срещу` by
    construction — nothing enforces it, which is what makes it a proposal.
    Holding it to the decision schema would push somebody to invent both."""
    assert check(PROPOSAL, run_tests=False) == []

    without = PROPOSAL.replace("**Става решение когато** five cases exist.\n", "")
    problems = check(without, run_tests=False)
    assert any("Става решение когато" in p for p in problems), problems


def test_a_decision_id_is_never_reused(commit):
    """Two entries under one id makes every reference to it ambiguous, and
    references are how the supersession chain is read."""
    body = DECISION.format(commit=commit)
    problems = check(body + "\n" + body, run_tests=False)
    assert any("used twice" in p for p in problems), problems


def test_a_shallow_clone_says_it_cannot_check_rather_than_that_it_failed(
        monkeypatch):
    """CI clones at depth 20, and everything older is absent from the checkout
    while present in the repository.

    The tool reported nine entries as naming commits that do not exist — a
    confident false verdict from the thing that exists to keep the record
    honest, and the project's own distinction between "could not check" and
    "checked and wrong" broken inside it.
    """
    import check_decisions

    monkeypatch.setattr(check_decisions, "_shallow", lambda: True)
    monkeypatch.setattr(check_decisions.subprocess, "run",
                        lambda *a, **k: SimpleNamespace(returncode=1,
                                                        stdout="", stderr=""))

    problems = check_decisions.check(DOC.read_text(encoding="utf-8"),
                                     run_tests=False)

    assert problems, "a missing commit should still be reported"
    assert all("not in this repository" not in p for p in problems)
    assert any("shallow" in p for p in problems)

