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

import re
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from check_decisions import (
    DOC,
    blank_fences,
    check,
    parse,
    unparsed_headings,
)

DECISION = """## D-001 · A decision

| | |
|---|---|
| **State** | active |
| **Scope** | somewhere |
| **Checked against** | {commit} |

**Decided.** This.

**Rejected.** That.

**Reason.** Because.

**Enforced by.** `tools/check_decisions.py:check`.

**Evidence.** `python3 tools/check_decisions.py`.

**Objection (Codex).** It said something.

**Revisited when** a stated thing happens.
"""

PROPOSAL = """## P-001 · A proposal

| | |
|---|---|
| **State** | proposed |
| **Scope** | somewhere |

**Proposed.** This might be worth doing.

**Objection (Codex).** It said something.

**Becomes a decision when** five cases exist.
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


def test_every_entry_in_the_document_is_actually_read():
    """A clean report over twelve entries when there are thirteen.

    D-013 was written with an em dash where every other heading uses a middle
    dot. `ENTRY` requires the dot, so to this checker the entry did not exist:
    its body counted as part of D-012, its three required fields were never
    looked for, and its file references resolved against the wrong entry. The
    rule that authorises abandoning the project, unchecked for a day, and the
    report above said "every field present" the whole time.

    Counting is the check. Asserting `check() == []` cannot see an entry that
    was never parsed — the absent entry produces no problem to report.
    """
    text = DOC.read_text(encoding="utf-8")
    parsed = {e.id for e in parse(text)}

    # Counted from the **field table**, not from another heading regex. Two
    # sets built by closely related patterns agree when both are wrong the same
    # way — an indented heading disappears from each of them at once — so the
    # independent count is the one thing every entry has that a heading pattern
    # cannot see.
    # Counted in the same blanked view `parse` reads. Counting the raw text
    # would count a `| **State** |` row inside a fenced example — whose heading
    # is blanked — and the two would disagree over a document with no defect in
    # it, which is a test that fails for its own reasons.
    states = len(re.findall(r"^\s*\|\s*\*\*State\*\*\s*\|",
                            blank_fences(text), re.M))

    assert len(parsed) == states, (
        "{} entries parsed, {} `**State**` rows in the file — an entry is not "
        "being read".format(len(parsed), states))
    assert unparsed_headings(text) == []
    # The floor, and it moves with the file: an equality between two zeros
    # would pass over an empty document.
    assert states >= 16


def entry_text(commit="abc1234", **over) -> str:
    parts = {"id": "D-001", "title": "A real one", "state": "active",
             "decided": "**Decided.** x\n", "extra": "", "commit": commit}
    parts.update(over)
    return ("## {id} · {title}\n\n"
            "| **State** | {state} |\n"
            "| **Scope** | somewhere |\n"
            "| **Checked against** | {commit} |\n\n"
            "{extra}{decided}"
            "**Rejected.** x\n**Reason.** x\n**Enforced by.** x\n"
            "**Evidence.** x\n**Objection.** x\n**Revisited when** x\n"
            ).format(**parts)


class TestASectionIsNotSatisfiedBySomethingThatStartsLikeIt:
    """`**Decided by**` is a field. `Decided` is a required section. A bare
    prefix match let the first stand in for the second, so an entry carrying
    that field satisfied a requirement for a section it did not have. Three
    entries carry it, and all three also have a real `**Decided.**` — which is
    how it stayed invisible."""

    def test_the_field_does_not_stand_in_for_the_section(self, commit):
        text = entry_text(commit, decided="",
                          extra="**Decided by** the owner.\n")

        problems = check(text, run_tests=False)

        assert problems == [
            "D-001: no **Decided** section"], problems

    @pytest.mark.parametrize("run", [
        "​",   # zero-width space
        "‌",   # zero-width non-joiner
        "‍",   # zero-width joiner
        "﻿",   # byte-order mark used as a word joiner
        "́",   # a combining acute, which is not a letter either
    ])
    def test_an_invisible_character_is_not_a_boundary(self, run, commit):
        """`not ....isalpha()` was the second repair, and a zero-width joiner
        is not a letter and is not stripped — so the field walked through a
        door made of a character nobody can see. The question is what the next
        character *is*, not what it is not."""
        text = entry_text(commit, decided="",
                          extra="**Decided{}by** the owner.\n".format(run))

        assert check(text, run_tests=False) == ["D-001: no **Decided** section"]

    @pytest.mark.parametrize("run", ["  ", "\t", " \t ", "\n", " "])
    def test_whitespace_does_not_open_the_door_again(self, run, commit):
        """`Decided  by`, with two spaces. The first repair looked at the next
        two characters: neither was a letter, so the field satisfied the
        section again through a door one space wider. A rule about "the next
        character" has to find the next character."""
        text = entry_text(commit, decided="",
                          extra="**Decided{}by** the owner.\n".format(run))

        assert check(text, run_tests=False) == ["D-001: no **Decided** section"]

    @pytest.mark.parametrize("heading", [
        "**Decided.** x\n",
        "**Decided 2026-09-03.** x\n",
        "**Decided,** and namely x\n",
        "**Decided (after Codex overturned it).** x\n",
    ])
    def test_the_real_headings_still_count(self, heading, commit):
        """The floor. A rule that refuses `Decided by` and also refuses
        `Decided 2026-09-03` has replaced one wrong answer with another."""
        assert check(entry_text(commit, decided=heading),
                     run_tests=False) == []


def test_a_heading_the_checker_cannot_read_is_reported_not_skipped():
    """Requiring the separator is right. Reading its absence as "no entry
    here" is the defect — and it is this repository's own shape, in the
    checker for the file that records its decisions."""
    text = ("## D-001 · A real one\n\n"
            "| **State** | active |\n"
            "| **Scope** | somewhere |\n"
            "| **Checked against** | abc1234 |\n\n"
            "**Decided.** x\n**Rejected.** x\n**Reason.** x\n"
            "**Enforced by.** x\n**Evidence.** x\n**Objection.** x\n"
            "**Revisited when** x\n\n"
            "## D-002 — An em dash instead of the dot\n\n"
            "This body is invisible.\n")

    assert unparsed_headings(text) == ["D-002 — An em dash instead of the dot"]
    problems = check(text, run_tests=False)
    assert any("D-002" in p for p in problems), problems
    assert any("·" in p for p in problems), "the fix is not named"


@pytest.mark.parametrize("indent", ["", " ", "  ", "   "])
def test_an_indented_heading_is_read_like_any_other(indent, commit):
    """Markdown renders a heading with up to three leading spaces. Anchored at
    column zero, an indented entry was a heading to every reader and to no
    parser here — the same silence the em dash produced, by a character nobody
    can see."""
    text = indent + entry_text(commit)

    assert [e.id for e in parse(text)] == ["D-001"]
    assert check(text, run_tests=False) == []


def test_an_indented_malformed_heading_is_still_reported(commit):
    text = entry_text(commit) + "\n  ## D-002 — indented and malformed\n"

    assert unparsed_headings(text) == ["D-002 — indented and malformed"]


class TestAFencedBlockIsAnExampleAndNotStructure:
    """Without this, a document that shows what a malformed heading looks like
    fails its own check, and a correctly formatted example inside a code block
    becomes an extra decision that the checker then demands fields for."""

    def test_a_malformed_heading_inside_a_fence_is_not_a_problem(self, commit):
        text = (entry_text(commit)
                + "\n```markdown\n## D-999 — what not to write\n```\n")

        assert unparsed_headings(text) == []
        assert check(text, run_tests=False) == []

    def test_a_well_formed_heading_inside_a_fence_is_not_an_entry(self, commit):
        text = (entry_text(commit)
                + "\n```markdown\n## D-999 · An example, not a decision\n```\n")

        assert [e.id for e in parse(text)] == ["D-001"]
        assert check(text, run_tests=False) == []

    def test_a_tilde_fence_counts_too(self, commit):
        text = entry_text(commit) + "\n~~~\n## D-999 — inside a tilde fence\n~~~\n"

        assert unparsed_headings(text) == []

    def test_a_fenced_field_does_not_satisfy_a_missing_one(self, commit):
        """The worst of the three, and self-inflicted. Headings were found in
        the blanked text and bodies sliced from the original, so every fenced
        example fed fields and sections to the entry it sat in — a decision
        whose only `**State**` row and only `**Decided.**` were inside a code
        block passed with nothing reported, while a comment three lines away
        said fenced blocks are examples and not structure."""
        text = ("## D-001 · Fields only inside a fence\n\n"
                "| **Scope** | somewhere |\n"
                "| **Checked against** | {} |\n\n"
                "```markdown\n"
                "| **State** | active |\n"
                "**Decided.** this is an example of the format\n"
                "```\n"
                "**Rejected.** x\n**Reason.** x\n**Enforced by.** x\n"
                "**Evidence.** x\n**Objection.** x\n"
                "**Revisited when** x\n").format(commit)

        problems = check(text, run_tests=False)

        assert "D-001: no `State` field" in problems, problems
        assert "D-001: no **Decided** section" in problems, problems

    @pytest.mark.parametrize("text,ids", [
        # A fence never closed runs to the end of the document.
        ("```\n## D-999 · never closed\n", ["D-001"]),
        # A ``` line inside a ```` block is content, not a close.
        ("````\n```\n## D-999 · still inside\n````\n", ["D-001"]),
        # A run of backticks with text after it does not close anything.
        ("```\n```junk\n## D-999 · still inside\n```\n", ["D-001"]),
        # A longer tilde fence closes only on a run at least as long.
        ("~~~~\n~~~\n## D-999 · still inside\n~~~~\n", ["D-001"]),
        # A backtick fence's info string may not contain a backtick, so this
        # opens nothing and the heading below it is a real entry.
        ("```python`oops\n\n## D-002 · Not inside anything\n\n"
         "| **State** | active |\n| **Scope** | s |\n"
         "| **Checked against** | {commit} |\n\n"
         "**Decided.** x\n**Rejected.** x\n**Reason.** x\n"
         "**Enforced by.** x\n**Evidence.** x\n**Objection.** x\n"
         "**Revisited when** x\n", ["D-001", "D-002"]),
        # A tilde fence's info string may.
        ("~~~python`fine\n## D-999 · inside\n~~~\n", ["D-001"]),
        # A close may be indented at most three spaces from column zero, not
        # from the opener. Four spaces in is content.
        ("   ```\nexample\n    ```\n## D-999 · still inside\n", ["D-001"]),
        # And a tab-indented run does not close it either.
        ("```\nexample\n\t```\n## D-999 · still inside\n", ["D-001"]),
        # Trailing spaces after a closing fence are allowed. Refusing them
        # left the parser inside the fence and the heading below invisible.
        ("```\ncode\n```   \n\n## D-002 · After a close with trailing spaces\n\n"
         "| **State** | active |\n| **Scope** | s |\n"
         "| **Checked against** | {commit} |\n\n"
         "**Decided.** x\n**Rejected.** x\n**Reason.** x\n"
         "**Enforced by.** x\n**Evidence.** x\n**Objection.** x\n"
         "**Revisited when** x\n", ["D-001", "D-002"]),
        # A trailing tab closes it too — CommonMark allows spaces or tabs.
        # This case asserted the opposite first, which locked in a defect in
        # the silent direction: a fence Markdown had closed stayed open here,
        # and every real entry after it went unchecked.
        # `## D-999` sits inside the fence so the case proves both halves: the
        # opener was recognised (D-999 does not appear) and the tabbed line
        # closed it (D-002 does). Without the inner heading it would pass just
        # as well if the fence had never opened.
        ("```\n## D-999 · inside the fence\ncode\n```\t\n"
         "## D-002 · After a close with a trailing tab\n\n"
         "| **State** | active |\n| **Scope** | s |\n"
         "| **Checked against** | {commit} |\n\n"
         "**Decided.** x\n**Rejected.** x\n**Reason.** x\n"
         "**Enforced by.** x\n**Evidence.** x\n**Objection.** x\n"
         "**Revisited when** x\n", ["D-001", "D-002"]),
        # A *leading* tab is still not indentation: a tab is four columns, so
        # the line is indented code and closes nothing.
        ("```\ncode\n\t```\n## D-999 · still inside\n", ["D-001"]),
        # A stray carriage return does not refuse a close. Not reachable
        # through the CLI, which reads with universal newlines, but this
        # function is called directly and the failure is the silent one.
        ("```\ncode\n```\r\n## D-002 · After a close with a CR\n\n"
         "| **State** | active |\n| **Scope** | s |\n"
         "| **Checked against** | {commit} |\n\n"
         "**Decided.** x\n**Rejected.** x\n**Reason.** x\n"
         "**Enforced by.** x\n**Evidence.** x\n**Objection.** x\n"
         "**Revisited when** x\n", ["D-001", "D-002"]),
        # And a real close does end it.
        ("```\ncode\n```\n\n## D-002 · after a real close\n\n"
         "| **State** | active |\n| **Scope** | s |\n"
         "| **Checked against** | {commit} |\n\n"
         "**Decided.** x\n**Rejected.** x\n**Reason.** x\n"
         "**Enforced by.** x\n**Evidence.** x\n**Objection.** x\n"
         "**Revisited when** x\n", ["D-001", "D-002"]),
    ])
    def test_the_fence_rules_are_markdowns(self, text, ids, commit):
        """One regex got four of these wrong, each leaving real fenced text
        visible to the parser."""
        doc = entry_text(commit) + "\n" + text.format(commit=commit)

        assert [e.id for e in parse(doc)] == ids

    def test_an_entry_after_a_fence_keeps_its_body(self, commit):
        """A fence between two entries does not swallow the second.

        The docstring here used to say this proves offsets are preserved. It
        does not, and they are not: blanking keeps the line count, not the
        character offsets, and `parse` finds headings and slices bodies in the
        same transformed text, so it would pass just as well if the fenced
        lines were deleted outright. What it does prove is what its name says.
        """
        text = (entry_text(commit)
                + "\n```\nsome code\nover several\nlines\n```\n\n"
                + entry_text(commit, id="D-002", title="After a fence"))

        assert [e.id for e in parse(text)] == ["D-001", "D-002"]
        assert check(text, run_tests=False) == []


def test_a_file_the_checker_cannot_read_is_not_a_clean_file(commit):
    """The vacuous pass, and the reason it is checked first.

    Change the heading format and every loop below iterates over nothing —
    which reports success. A checker whose failure mode is silence is worse
    than none, because somebody stops looking.
    """
    problems = check("# Just prose, no entries\n", run_tests=False)
    assert problems and "reading nothing" in problems[0]


def test_a_state_that_carries_its_own_explanation_is_refused(commit):
    """`active, with a known hole` was a real state in the first draft.

    It reads well and no parser can use it: the entry is active and qualified
    at once, and which half a reader takes away is up to them. The
    qualification goes in its own field.
    """
    body = DECISION.format(commit=commit).replace(
        "| active |", "| active, with a known hole |")
    problems = check(body, run_tests=False)
    assert any("is not one of" in p for p in problems), problems


def test_a_decision_missing_its_evidence_is_refused(commit):
    """A decision without a command the reader can run is an opinion with a
    heading. The discarded alternative and the evidence are the whole value;
    what was chosen is already visible in the code."""
    body = DECISION.format(commit=commit).replace(
        "**Evidence.** `python3 tools/check_decisions.py`.\n\n", "")
    problems = check(body, run_tests=False)
    assert any("Evidence" in p for p in problems), problems


def test_a_symbol_that_no_longer_exists_is_caught(commit):
    """The ordinary way this file rots, and nothing else in the repository
    would notice: the code is renamed, the entry keeps citing the old name, and
    it goes on reading like an enforced rule."""
    body = DECISION.format(commit=commit).replace(
        "`tools/check_decisions.py:check`", "`tools/check_decisions.py:vanished`")
    problems = check(body, run_tests=False)
    assert any("no such symbol" in p for p in problems), problems


def test_a_commit_that_is_not_in_this_repository_is_caught(commit):
    """`Checked against` is the entry's only claim about *when* it was true.
    A hash nobody can resolve makes that claim unfalsifiable."""
    body = DECISION.format(commit="0" * 12)
    problems = check(body, run_tests=False)
    assert any("not in this repository" in p for p in problems), problems


def test_a_superseded_entry_must_name_its_successor(commit):
    """Otherwise the reader has nowhere to go and no way to know the decision
    moved — which is indistinguishable from the decision being abandoned."""
    body = DECISION.format(commit=commit).replace(
        "| active |", "| superseded |")
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
        "| active |", "| superseded |").replace(
        "| **Scope** | somewhere |", "| **Scope** | somewhere |\n| **Replaced by** | D-002 |")
    new = DECISION.format(commit=commit).replace(
        "## D-001 · A decision", "## D-002 · The new one")

    problems = check(old + "\n" + new, run_tests=False)
    assert any("does not say so back" in p for p in problems), problems

    fixed = new.replace("| **Scope** | somewhere |",
                        "| **Scope** | somewhere |\n| **Replaces** | D-001 |")
    assert check(old + "\n" + fixed, run_tests=False) == []


def test_an_entry_cannot_replace_itself(commit):
    body = DECISION.format(commit=commit).replace(
        "| **Scope** | somewhere |",
        "| **Scope** | somewhere |\n| **Replaces** | D-001 |")
    problems = check(body, run_tests=False)
    assert any("replaces itself" in p for p in problems), problems


def test_a_proposal_is_held_to_the_proposal_schema_and_not_the_other_one(commit):
    """A proposal has no `Enforced by` and no `Checked against` by
    construction — nothing enforces it, which is what makes it a proposal.
    Holding it to the decision schema would push somebody to invent both."""
    assert check(PROPOSAL, run_tests=False) == []

    without = PROPOSAL.replace("**Becomes a decision when** five cases exist.\n", "")
    problems = check(without, run_tests=False)
    assert any("Becomes a decision when" in p for p in problems), problems


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

