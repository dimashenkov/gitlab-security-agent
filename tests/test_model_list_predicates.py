"""Four spellings of "a list of model names", pinned against the same shapes.

`sentinel_compare._is_name_list`, `sentinel_compare._is_model_list`,
`sentinel_reference._model_list` and `stop_rule._names` all answer a version of
one question, in four files that cannot import one another: two read finished
artifacts and must not depend on `src/`, one is the comparator, one is the stop
rule. The repository already says of two of them that "the tests pin them
against the same shapes" — this is that test, for all four.

Written 2026-09-09 after Codex asked where the four disagree. They did, in five
places. Two are deliberate and are stated below; three were not and are fixed —
including one this file first recorded as deliberate and Codex then showed was
a predicate that could not make the distinction it was credited with. A
difference nobody wrote down is a difference that decides something later, and
the file it decides in is whichever one the reader did not open.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import sentinel_compare
import sentinel_reference
import stop_rule


def accepts_name_list(value) -> bool:
    return sentinel_compare._is_name_list(value)


def accepts_model_list(value) -> bool:
    return sentinel_compare._is_model_list(value)


def accepts_reference(value) -> bool:
    return sentinel_reference._model_list(value)


def accepts_names(value) -> bool:
    return stop_rule._names(value) is not None


ALL_FOUR = (accepts_name_list, accepts_model_list, accepts_reference,
            accepts_names)


@pytest.mark.parametrize("value", [
    "claude-opus-5",                     # a str walks into characters
    ["claude-opus-5", 7],
    [{}],                                # unhashable: raised TypeError once
    [["claude-opus-5"]],
    [" "],                               # blank is not a name
])
def test_every_spelling_refuses_what_is_not_a_list_of_names(value):
    """The agreement that matters. A shape one reader accepts and another
    refuses is a shape whose treatment depends on which file saw it first."""
    assert not any(fn(value) for fn in ALL_FOUR)


@pytest.mark.parametrize("value", [
    ["claude-opus-5"],
    ["claude-opus-5", "claude-haiku-4-5-20251001"],
])
def test_every_spelling_accepts_a_real_list(value):
    assert all(fn(value) for fn in ALL_FOUR)


def test_an_explicit_null_is_not_an_absent_field():
    """Codex, 2026-09-09, against the assertion this file used to make.

    `_names(None) -> []` was called a deliberate difference: "absence has a
    defined meaning in `stop_rule`". It could not make that distinction. The
    callers reach the field with `.get()`, which returns `None` both when the
    key is missing and when it is present and `null` — one a legacy row, the
    other malformed, and this predicate gave them the same answer.

    The tolerance now lives where the distinction exists: `reviewed` asks with
    `prov.get(field, [])`, so an absent key arrives as `[]` and an explicit
    null arrives as `None` and is refused, as it is by the other three.
    """
    assert not any(fn(None) for fn in ALL_FOUR)

    assert stop_rule.reviewed({"model_requested": "claude-opus-5"}) == set()
    assert stop_rule.reviewed(
        {"model_requested": "claude-opus-5", "models_served": None}) is None
    assert stop_rule.reviewed(
        {"model_requested": "claude-opus-5",
         "models_served": ["claude-opus-5"],
         "models_verified": None}) is None


@pytest.mark.parametrize("name, helper", [
    ("claude-haiku-4-5", True),
    ("claude-haiku-4-5-20251001", True),
    ("claude-haiku-", False),
    ("claude-haiku-sonnet-5", False),
    ("claude-haiku-not-a-model", False),
    ("claude-sonnet-5", False),
    ("claude-opus-5", False),
])
def test_the_helper_family_is_a_prefix_and_a_version(name, helper):
    """A bare prefix test let any string sit behind `claude-haiku-` and be
    read as the provider's own helper — in the predicate whose comment says an
    unknown responder is refused. Codex, 2026-09-09."""
    assert stop_rule._is_helper(name) is helper


def test_the_two_differences_that_are_deliberate():
    """Written down because they are choices, and an undocumented difference
    between four copies of one rule is the copy nobody checked.

    There were three. The `None` one turned out to be a defect wearing a
    justification, which is the reason this file exists: a difference nobody
    stated is a difference nobody examined, and stating it is what let it be
    examined.
    """
    # 1. An empty list. `_model_list` guards `models_served`, which a real row
    #    always fills, so empty is malformed there — and its `models_verified`
    #    caller allows `[]` explicitly, because a member with no finding fires
    #    no verifier.
    assert accepts_name_list([]) and accepts_model_list([]) and accepts_names([])
    assert not accepts_reference([])

    # 2. A duplicate. `_is_name_list` is shape only, because the case-id lists
    #    it also guards have their own sentence for a repeat — "reports one
    #    exclusion as two" — and a generic shape complaint would replace it.
    assert accepts_name_list(["a", "a"])
    assert not any(fn(["a", "a"]) for fn in
                   (accepts_model_list, accepts_reference, accepts_names))


def test_a_tuple_is_not_a_shape_any_artifact_carries():
    """The fourth difference, and the reason it is not repaired: JSON decodes
    arrays as lists, so no reader here can be handed a tuple by an artifact.
    Recorded rather than levelled, because levelling it would mean loosening
    two of the four to accept something nothing produces."""
    assert accepts_name_list(("a",)) and accepts_model_list(("a",))
    assert not accepts_reference(("a",)) and not accepts_names(("a",))
