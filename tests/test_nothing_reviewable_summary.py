"""The sentence a reader gets when a change had nothing to review.

It is the whole report on that path: no findings, no coverage, one line. It had
no test of its own until 2026-09-09, and in that time it acquired four
readings, a fourth branch, and a clause about removals — each of which is a
claim about the change that nothing checked.

The defect that prompted these: a merge request whose only change was
`git rm vendor/guard.php` reached the last branch and said "This change adds or
modifies no file", naming no filter, over a removed guard. The same file
modified said "every file is excluded". A deletion was reported strictly worse
than a modification.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from security_agent.cli import _nothing_reviewable_summary as summary


def test_the_excludes_alone_are_named_and_the_scope_is_not():
    text = summary(["vendor/lib.py"], [], ())

    assert "excluded by configuration" in text
    assert "scope" not in text


def test_the_scope_alone_is_named_and_the_excludes_are_cleared():
    text = summary([], ["app/views.py"], ("docs",))

    assert "outside the reviewed scope (--path docs)" in text
    # Said in words, because the reader who has just been told "nothing was
    # reviewable" will otherwise go hunting through their exclude patterns.
    assert "The exclude rules did not do this." in text


def test_both_filters_are_counted_separately():
    text = summary(["vendor/lib.py"], ["app/views.py"], ("docs",))

    assert "1 file(s) are excluded" in text
    assert "1 file(s) are outside the reviewed scope" in text


def test_a_change_with_nothing_in_the_range_blames_no_configuration():
    text = summary([], [], ())

    assert "adds or modifies no file" in text
    assert "excluded" not in text
    assert "scope" not in text


def test_every_reading_says_it_is_not_a_verdict():
    """The clause that keeps "nothing was reviewable" from being read as
    "nothing is wrong". Four readings, one sentence, and it is the one a
    merge request preview shows."""
    for args in (([], [], ()), (["a"], [], ()), ([], ["b"], ("docs",)),
                 (["a"], ["b"], ())):
        assert "not a statement about the code" in summary(*args)


@pytest.mark.parametrize("deleted, expected", [
    (0, None),
    (1, "1 of them was deleted by this change."),
    (3, "3 of them were deleted by this change."),
])
def test_a_deletion_a_rule_covered_is_named_as_a_deletion(deleted, expected):
    """A rule hiding a *deletion* is the case worth naming: the removed lines
    of a deleted guard are exactly what a review exists to read.

    Codex, 2026-09-09, against the first version of this test — which asserted
    "removed from the reviewed set" and so **required a false sentence**. A
    file under an exclude rule was never in the reviewed set. What is true is
    that a rule was covering a file this change deleted.
    """
    text = summary(["vendor/guard.py"], [], (), deleted=deleted)

    if expected is None:
        assert "deleted by this change" not in text
    else:
        assert expected in text
        assert "removed from the reviewed set" not in text


def test_a_file_moved_behind_a_rule_is_named_as_a_move():
    """The other half, and it is the one where something really did leave the
    reviewed set: the path that moved was reviewable and its destination is
    not."""
    text = summary(["vendor/guard.py"], [], (), moved_out=2)

    assert "2 reviewable file(s) were moved to a path a rule covers" in text
    assert "deleted by this change" not in text


def test_both_can_be_true_of_one_change_and_are_said_separately():
    text = summary(["vendor/a.py", "vendor/b.py"], [], (), deleted=1,
                   moved_out=1)

    assert "1 of them was deleted by this change." in text
    assert "1 reviewable file(s) were moved to a path a rule covers" in text


def test_the_last_reading_never_claims_a_removal():
    """Nothing in the range means nothing was deleted or moved either. A count
    reaching here would be describing files the sentence has just said do not
    exist."""
    text = summary([], [], ())

    assert "deleted by this change" not in text
    assert "moved to a path a rule covers" not in text
