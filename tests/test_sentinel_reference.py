"""The reference a model change is measured against.

Assembled the obvious way — newest row per case — it is a patchwork: the
sentinel's thirteen span three days and three versions of the reviewer, and
three carry no timestamp at all, so "newest" is decided by glob order. A delta
against that is a delta against no version in particular.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import sentinel_reference

DIGESTS = {}


def build_case(corpus: Path, case_id: str) -> str:
    """A case on disk, and the digest a row has to carry to be about it."""
    from artifact import case_digest

    directory = corpus / case_id
    for member in ("safe", "unsafe"):
        body = directory / member / "app"
        body.mkdir(parents=True)
        (body / "h.py").write_text("# {}\n".format(member), encoding="utf-8")
    (directory / "case.yml").write_text(yaml.safe_dump({
        "case_id": case_id, "language": "py", "family": "injection",
        "construction": "regression", "expected_category": ["injection"],
        "expected_file": ["app/h.py"],
    }), encoding="utf-8")
    DIGESTS[case_id] = case_digest(directory)
    return DIGESTS[case_id]


def write_row(root: Path, label: str, case_id: str, passed: bool,
              digest=None, **overrides) -> None:
    directory = root / label
    directory.mkdir(parents=True, exist_ok=True)
    row = {
        "case_id": case_id,
        "pair_success": passed,
        "case_digest": digest or DIGESTS.get(case_id),
        "unsafe_recall": passed,
        "safe_false_positive": False,
        "safe_exit": 0,
        "unsafe_exit": 1,
    }
    row.update(overrides)
    (directory / (case_id + ".json")).write_text(
        json.dumps(row.pop("_body", row)), encoding="utf-8")


@pytest.fixture()
def reference(tmp_path, monkeypatch):
    """Two cases, two passes, one of them disagreeing with itself."""
    experiment = tmp_path / "experiment"
    experiment.mkdir()
    (experiment / "manifest.json").write_text(
        json.dumps({"environment": {"system_prompt": "aaa"}}), encoding="utf-8")

    corpus = tmp_path / "corpus-real"
    for case_id in ("steady", "wobbly"):
        build_case(corpus, case_id)
    monkeypatch.setattr(sentinel_reference, "CORPUS", corpus)

    suite = tmp_path / "sentinel.yml"
    suite.write_text(yaml.safe_dump({"cases": ["steady", "wobbly"]}),
                     encoding="utf-8")

    for label in ("pass-a", "pass-b"):
        write_row(experiment, label, "steady", True)
    write_row(experiment, "pass-a", "wobbly", True)
    write_row(experiment, "pass-b", "wobbly", False)

    monkeypatch.setattr(sentinel_reference, "EXPERIMENT", experiment)
    monkeypatch.setattr(sentinel_reference, "SUITE", suite)
    return tmp_path


def test_a_case_the_reference_answers_two_ways_is_not_comparable(reference):
    """Taking either pass as *the* answer picks a side of the noise and hides
    that the disagreement exists — and then a model change that flips that case
    reads as an effect of the change."""
    body = sentinel_reference.build()

    assert body["cases"]["wobbly"]["unstable_under_reference"]
    assert body["comparable"] == ["steady"]
    assert body["unstable_under_reference"] == ["wobbly"]


def test_both_passes_are_recorded_not_the_later_one(reference):
    body = sentinel_reference.build()

    assert body["cases"]["steady"]["outcomes"] == {"pass-a": True,
                                                  "pass-b": True}
    assert body["cases"]["wobbly"]["outcomes"] == {"pass-a": True,
                                                  "pass-b": False}


def test_the_failure_shape_is_kept_beside_the_verdict(reference):
    """`fail -> fail` can hide a case getting worse in both members at once,
    and a comparison reading one bit per case would call that no change."""
    body = sentinel_reference.build()

    shape = body["cases"]["steady"]["shape"]["pass-a"]
    assert shape["missed"] is False and shape["false_alarm"] is False
    assert shape["exits"] == [0, 1]


def test_the_threshold_is_written_before_any_challenger_runs(reference):
    """A rule chosen after seeing which cases moved is a rule fitted to the
    answer. It is in the frozen file, so the file says when it was decided."""
    body = sentinel_reference.build()

    threshold = body["threshold"]

    # Numbers, not prose. The first version wrote the rule as a sentence and
    # the comparator then carried its own copy of it — two rules that can
    # drift, which is what putting the rule in code was meant to stop.
    assert threshold["reject_at_net"] == 2
    assert threshold["confirmations_required"] == 2

    # Versioned rather than described by flags. Three booleans stood here
    # saying what the comparison does and no code read them — a setting nobody
    # applies is a claim, and a claim in a frozen file reads as configuration.
    assert threshold["rule_version"] == 1
    assert "reject" in threshold["in_words"]
    assert not [k for k in threshold if k.startswith("counts_")], (
        "a flag nothing reads is worse than no flag")


def test_a_case_missing_from_the_reference_run_refuses(reference, capsys):
    """Comparing against a case the reference never measured is comparing
    against nothing, and returning 0 would let the run be bought anyway."""
    (reference / "experiment" / "pass-b" / "steady.json").unlink()

    monkey = pytest.MonkeyPatch()
    monkey.setattr(sys, "argv", ["sentinel_reference.py"])
    try:
        assert sentinel_reference.main() == 2
    finally:
        monkey.undo()
    assert "cannot be compared" in capsys.readouterr().err


def test_a_frozen_reference_is_not_rewritten(reference, tmp_path, capsys):
    target = tmp_path / "ref.json"
    target.write_text("{}", encoding="utf-8")

    monkey = pytest.MonkeyPatch()
    monkey.setattr(sys, "argv", ["sentinel_reference.py", "--write",
                                 str(target)])
    try:
        assert sentinel_reference.main() == 1
    finally:
        monkey.undo()
    assert target.read_text(encoding="utf-8") == "{}"


def test_check_refuses_when_the_frozen_file_no_longer_matches(
        reference, tmp_path, capsys):
    """A frozen reference that drifts is not a reference. The check exists so
    the drift is found before the paid run, not after it."""
    target = tmp_path / "ref.json"
    target.write_text(json.dumps(sentinel_reference.build()), encoding="utf-8")

    write_row(reference / "experiment", "pass-b", "steady", False)

    monkey = pytest.MonkeyPatch()
    monkey.setattr(sys, "argv", ["sentinel_reference.py", "--check",
                                 str(target)])
    try:
        assert sentinel_reference.main() == 2
    finally:
        monkey.undo()
    assert "does not match" in capsys.readouterr().err


def test_a_verdict_that_is_not_a_boolean_refuses(reference):
    """`bool(row.get("pair_success"))` turned the string "false" into True and
    a missing field into a valid failure. A damaged result would have changed
    the reference silently, in the direction nobody checks."""
    for value in ("false", None, 1):
        write_row(reference / "experiment", "pass-a", "steady", True,
                  pair_success=value)
        with pytest.raises(sentinel_reference.ReferenceError) as caught:
            sentinel_reference.build()
        assert "not a verdict" in str(caught.value)


def test_a_row_about_another_case_refuses(reference):
    """The filename matched, so the row was taken — whatever it said about
    itself."""
    write_row(reference / "experiment", "pass-a", "steady", True)
    path = reference / "experiment" / "pass-a" / "steady.json"
    body = json.loads(path.read_text())
    body["case_id"] = "somebody-else"
    path.write_text(json.dumps(body))

    with pytest.raises(sentinel_reference.ReferenceError) as caught:
        sentinel_reference.build()
    assert "about" in str(caught.value)


def test_a_file_holding_more_than_one_row_refuses(reference):
    """The first element was taken and the rest ignored."""
    path = reference / "experiment" / "pass-a" / "steady.json"
    row = json.loads(path.read_text())
    path.write_text(json.dumps([row, dict(row, pair_success=False)]))

    with pytest.raises(sentinel_reference.ReferenceError) as caught:
        sentinel_reference.build()
    assert "exactly one" in str(caught.value)


def test_passes_that_measured_different_versions_refuse(reference):
    """Only pass A's digest was recorded, and it was compared with nothing —
    so a row about an older version of the case could become the reference the
    whole comparison is measured against."""
    write_row(reference / "experiment", "pass-b", "steady", True,
              digest="0" * 16)

    with pytest.raises(sentinel_reference.ReferenceError) as caught:
        sentinel_reference.build()
    assert "disagree about which version" in str(caught.value)


def test_a_reference_about_a_case_that_has_since_changed_refuses(reference):
    """The corpus is the third party. Both passes agreeing means nothing if the
    case they agreed about is not the case on disk today."""
    for label in ("pass-a", "pass-b"):
        write_row(reference / "experiment", label, "steady", True,
                  digest="0" * 16)

    with pytest.raises(sentinel_reference.ReferenceError) as caught:
        sentinel_reference.build()
    assert "no longer on disk" in str(caught.value)

