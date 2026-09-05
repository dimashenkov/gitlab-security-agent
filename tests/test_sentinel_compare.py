"""The threshold, applied by code rather than written in prose.

Every case here is a file of the shape the challenger's runs will have, built
before any of them is bought. The point is that the rule cannot be shaped by
what those runs turn out to say — and that the ways it could quietly return
zero are each tried on purpose, because a quiet zero reads as "the cheaper
model is fine".
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import sentinel_compare

DIGEST = "d" * 16


def member(**overrides) -> dict:
    body = {
        # `model_substituted` is recorded by every real run, and the contract
        # requires it to be present and false: a row that never recorded it,
        # and was answered by another model, would otherwise pass.
        "provenance": {"system_prompt_sha": "aaa", "verifier_prompt_sha": "bbb",
                       "schema_sha": "ccc", "agent_version": "0.1.0",
                       "model_requested": "claude-sonnet-5",
                       "model_substituted": False,
                       "models_served": ["claude-sonnet-5"]},
        # `verify` is recorded by every real run, and the contract requires it
        # to be on: the reference was produced with it on, and a challenger
        # without it measures a different question.
        "settings": {"verify": True, "verify_model": "claude-opus-5",
                     "effort": "high"},
    }
    body.update(overrides)
    return body


def row(case_id: str, passed: bool, missed=None, false_alarm=False,
        run_id="r1", **overrides) -> dict:
    body = {
        "case_id": case_id,
        "pair_success": passed,
        "case_digest": DIGEST,
        # A run is one execution, and the comparator asks the rows to say so.
        "run_id": run_id,
        "unsafe_recall": (not missed) if missed is not None else passed,
        "safe_false_positive": false_alarm,
        "members": {"safe": member(), "unsafe": member()},
    }
    body.update(overrides)
    return body


def reference(tmp_path, cases=("one", "two", "three"), unstable=("wobbly",),
              failing=()) -> Path:
    entries = {}
    for case_id in list(cases) + list(unstable):
        passed = case_id not in failing
        shape = {"missed": not passed, "false_alarm": False, "exits": [0, 1]}
        entries[case_id] = {
            "outcomes": {"pass-a": passed, "pass-b": passed},
            "shape": {"pass-a": dict(shape), "pass-b": dict(shape)},
            "case_digest": DIGEST,
            "unstable_under_reference": case_id in unstable,
        }
    for case_id in unstable:
        entries[case_id]["outcomes"] = {"pass-a": True, "pass-b": False}

    path = tmp_path / "reference.json"
    path.write_text(json.dumps({
        "model": "claude-opus-5",
        "verifier_model": "claude-opus-5",
        # What served the reference, by member. The challenger has to have been
        # served the same set with its own model in place of the reference's —
        # the machinery held constant beside the subject under test.
        "observed_models": {"safe": ["claude-opus-5"],
                            "unsafe": ["claude-opus-5"]},
        "environment": {"system_prompt": "aaa", "verifier_prompt": "bbb",
                        "findings_schema": "ccc", "agent_version": "0.1.0"},
        "cases": entries,
        "comparable": sorted(cases),
        "unstable_under_reference": sorted(unstable),
        "threshold": {
            "reject_at_net": 2,
            "confirmations_required": 2,
            "rule_version": 2,
            "in_words": "two confirmed regressions reject the change; "
                        "improvements are reported and do not cancel them",
        },
    }), encoding="utf-8")
    return path


def run(tmp_path, name: str, rows: list) -> Path:
    """One run, stamped the way `pair_corpus.run_case` stamps: **per case**.

    The first version of this helper gave every row in a file the same
    `run_id`, and the comparator was written to expect that — a shape no
    producer here emits. The real pass directories would have been refused on
    the first case, and the test would have gone on passing.
    """
    stamped = []
    for r in rows:
        stamp = r.pop("run_id_override", None) or "{}:{}".format(
            name, r["case_id"])
        stamped.append(dict(r, run_id=stamp))
    path = tmp_path / name
    path.write_text(json.dumps(stamped), encoding="utf-8")
    return path


# ------------------------------------------------------- what the rule counts


def test_two_confirmed_regressions_reject_the_change(tmp_path):
    ref = reference(tmp_path)
    rows = [row("one", False), row("two", False), row("three", True)]
    result = sentinel_compare.compare(ref, [run(tmp_path, "a.json", rows),
                                            run(tmp_path, "b.json", rows)])

    assert result["regressed"] == ["one", "two"]
    assert result["net"] == 2 and result["verdict"] == "reject"


def test_one_confirmed_regression_decides_nothing(tmp_path):
    """Not a pass. The reference moved on its own in two of thirteen cases, so
    one is inside what the suite does by itself."""
    ref = reference(tmp_path)
    rows = [row("one", False), row("two", True), row("three", True)]
    result = sentinel_compare.compare(ref, [run(tmp_path, "a.json", rows),
                                            run(tmp_path, "b.json", rows)])

    assert result["net"] == 1 and result["verdict"] == "no decision"


def test_none_passes_the_gate(tmp_path):
    ref = reference(tmp_path)
    rows = [row(c, True) for c in ("one", "two", "three")]
    result = sentinel_compare.compare(ref, [run(tmp_path, "a.json", rows),
                                            run(tmp_path, "b.json", rows)])

    assert result["net"] == 0 and result["verdict"] == "passes the gate"


def test_a_regression_in_only_one_run_is_not_confirmed(tmp_path):
    """The whole reason two runs are required. One `pass -> fail` is as likely
    to be the suite moving as the model being worse — measured, not assumed."""
    ref = reference(tmp_path)
    first = run(tmp_path, "a.json", [row("one", False), row("two", True),
                                     row("three", True)])
    second = run(tmp_path, "b.json", [row(c, True) for c in
                                      ("one", "two", "three")])

    result = sentinel_compare.compare(ref, [first, second])
    assert result["regressed"] == [] and result["verdict"] == "passes the gate"


def test_improvements_do_not_pay_for_regressions(tmp_path):
    """Rule 1 subtracted improvements, and this test asserted the result: two
    confirmed regressions and two confirmed improvements came back as `net: 0`
    and **"passes the gate"** — a cheaper reviewer approved over two failures
    it had reproduced twice each.

    The arithmetic was not merely lenient, it was inconsistent with the
    comparator twenty lines above it, which refuses to order a missed weakness
    against a false alarm *inside* one case and calls the exchange `traded`,
    then netted the same two harms across cases as perfectly fungible. Nothing
    in this repository weighs them. Rule 2 weighs neither: improvements are
    reported and do not cancel.

    The reference answers exactly two of its eleven cases with a failure, so
    exactly two improvements existed to buy exactly two regressions. The
    permissive path was not a corner of the rule; it was its whole width.
    """
    ref = reference(tmp_path, cases=("one", "two", "three", "four"),
                    failing=("three", "four"))
    rows = [row("one", False), row("two", False),
            row("three", True), row("four", True)]
    result = sentinel_compare.compare(ref, [run(tmp_path, "a.json", rows),
                                            run(tmp_path, "b.json", rows)])

    assert result["regressed"] == ["one", "two"]
    assert sorted(result["improved"]) == ["four", "three"]
    assert result["net"] == 2 and result["verdict"] == "reject"


def test_a_retired_reference_is_refused_and_says_why(tmp_path):
    """The one frozen reference on disk cannot separate the model that
    reviewed from the model that verified — no row in `measurements/` carries
    `models_verified` — so a challenger changing only the reviewer cannot be
    held to it. Marked retired in the file rather than deleted: the rows behind
    it were paid for and remain the record of what that run answered.

    Asked before every other check, because otherwise the reader is handed a
    complaint about a served-model set for a file that is not a baseline, and
    goes off to fix the symptom.
    """
    ref = reference(tmp_path)
    body = json.loads(ref.read_text(encoding="utf-8"))
    body["retired"] = {"on": "2026-09-02", "why": "it cannot separate roles"}
    ref.write_text(json.dumps(body), encoding="utf-8")

    rows = [row(c, True) for c in ("one", "two", "three")]
    with pytest.raises(sentinel_compare.ComparisonError) as caught:
        sentinel_compare.compare(ref, [run(tmp_path, "a.json", rows),
                                       run(tmp_path, "b.json", rows)])

    assert "retired" in str(caught.value)
    assert "cannot separate roles" in str(caught.value)


def test_the_reference_on_disk_is_not_offered_as_a_baseline(tmp_path):
    """The rollout, not the rule. `RULE_VERSION` moved to 2 and the committed
    reference still says 1, so the documented invocation would refuse the only
    reference in the repository — with a message about arithmetic, for a file
    whose real problem is that it cannot answer the question at all. This test
    fails if the file is ever un-retired without being rebuilt."""
    frozen = json.loads(
        (Path(__file__).resolve().parents[1] / "measurements" / "reference"
         / "sentinel-opus.json").read_text(encoding="utf-8"))

    assert frozen.get("retired"), "the committed reference must say it is not one"
    assert frozen["retired"]["why"]
    assert frozen["retired"]["rule_version_frozen_under"] == 1


def test_a_reference_frozen_under_the_old_arithmetic_is_refused(tmp_path):
    """A rule change is not retroactive, and it is not silently applied either.
    A reference frozen under rule 1 agreed to `regressions - improvements`;
    deciding it under rule 2 would apply arithmetic the frozen file never
    accepted, which is how a threshold gets fitted to the result it exists to
    judge. Refused, so the change is a visible question."""
    ref = reference(tmp_path)
    body = json.loads(ref.read_text(encoding="utf-8"))
    body["threshold"]["rule_version"] = 1
    ref.write_text(json.dumps(body), encoding="utf-8")

    rows = [row(c, True) for c in ("one", "two", "three")]
    with pytest.raises(sentinel_compare.ComparisonError) as caught:
        sentinel_compare.compare(ref, [run(tmp_path, "a.json", rows),
                                       run(tmp_path, "b.json", rows)])

    assert "rule version 1" in str(caught.value)


def test_one_confirmed_regression_still_decides_nothing(tmp_path):
    """The threshold is two. One reproduced failure widens the sample; it does
    not reject, and it must not read as a pass either."""
    ref = reference(tmp_path, cases=("one", "two", "three"))
    rows = [row("one", False), row("two", True), row("three", True)]
    result = sentinel_compare.compare(ref, [run(tmp_path, "a.json", rows),
                                            run(tmp_path, "b.json", rows)])

    assert result["regressed"] == ["one"]
    assert result["net"] == 1 and result["verdict"] == "no decision"


def test_a_case_the_reference_answered_two_ways_is_not_counted(tmp_path):
    """It is excluded by name in the frozen file, and a challenger flipping it
    would otherwise read as an effect of the change."""
    ref = reference(tmp_path)
    rows = [row(c, True) for c in ("one", "two", "three")] + [
        row("wobbly", False)]
    result = sentinel_compare.compare(ref, [run(tmp_path, "a.json", rows),
                                            run(tmp_path, "b.json", rows)])

    assert "wobbly" not in result["regressed"]
    assert result["net"] == 0


# --------------------------------------------- failing, and failing differently


def test_a_still_failing_case_that_gains_a_second_failure_counts_down(tmp_path):
    """`fail -> fail` is not "no change" when the fixed member starts being
    flagged too. One bit per case would have called this steady."""
    ref = reference(tmp_path, failing=("one",))
    rows = [row("one", False, missed=True, false_alarm=True),
            row("two", True), row("three", True)]
    result = sentinel_compare.compare(ref, [run(tmp_path, "a.json", rows),
                                            run(tmp_path, "b.json", rows)])

    assert result["regressed"] == ["one"]


def test_trading_one_kind_of_failure_for_the_other_decides_nothing(tmp_path):
    """Missing a weakness and shouting about a fix are different harms. There
    is no order between them, so inventing one would be the gate deciding
    which way of being wrong is worse."""
    ref = reference(tmp_path, failing=("one",))
    rows = [row("one", False, missed=False, false_alarm=True),
            row("two", True), row("three", True)]
    result = sentinel_compare.compare(ref, [run(tmp_path, "a.json", rows),
                                            run(tmp_path, "b.json", rows)])

    assert result["traded"] == ["one"]
    assert result["regressed"] == [] and result["net"] == 0


# ------------------------------------------------------ what it refuses to do


def test_one_run_is_refused(tmp_path):
    ref = reference(tmp_path)
    rows = [row(c, True) for c in ("one", "two", "three")]
    with pytest.raises(sentinel_compare.ComparisonError) as caught:
        sentinel_compare.compare(ref, [run(tmp_path, "a.json", rows)])
    assert "needs 2" in str(caught.value)


def test_a_missing_case_is_refused(tmp_path):
    """Silently comparing the cases that happen to be in both files answers a
    narrower question in the words of the wider one."""
    ref = reference(tmp_path)
    full = run(tmp_path, "a.json", [row(c, True) for c in
                                    ("one", "two", "three")])
    short = run(tmp_path, "b.json", [row("one", True), row("two", True)])

    with pytest.raises(sentinel_compare.ComparisonError) as caught:
        sentinel_compare.compare(ref, [full, short])
    assert "three" in str(caught.value)


def test_a_duplicate_case_in_one_file_is_refused(tmp_path):
    ref = reference(tmp_path)
    rows = [row("one", True), row("one", False), row("two", True),
            row("three", True)]
    with pytest.raises(sentinel_compare.ComparisonError) as caught:
        sentinel_compare.compare(ref, [run(tmp_path, "a.json", rows),
                                       run(tmp_path, "b.json", rows)])
    assert "twice" in str(caught.value)


def test_a_case_outside_the_reference_is_refused(tmp_path):
    ref = reference(tmp_path)
    rows = [row(c, True) for c in ("one", "two", "three")] + [
        row("stray", True)]
    with pytest.raises(sentinel_compare.ComparisonError) as caught:
        sentinel_compare.compare(ref, [run(tmp_path, "a.json", rows),
                                       run(tmp_path, "b.json", rows)])
    assert "stray" in str(caught.value)


@pytest.mark.parametrize("value", [None, "false", 1, "true"])
def test_a_verdict_that_is_not_a_boolean_is_refused(tmp_path, value):
    """`bool("false")` is True, and a missing field reads as a failure. Either
    would move the count without anyone seeing it."""
    ref = reference(tmp_path)
    rows = [row("one", True), row("two", True), row("three", True)]
    rows[0]["pair_success"] = value
    with pytest.raises(sentinel_compare.ComparisonError) as caught:
        sentinel_compare.compare(ref, [run(tmp_path, "a.json", rows),
                                       run(tmp_path, "b.json", rows)])
    assert "not a verdict" in str(caught.value)


def test_a_case_measured_against_another_version_is_refused(tmp_path):
    ref = reference(tmp_path)
    rows = [row("one", True, case_digest="0" * 16), row("two", True),
            row("three", True)]
    with pytest.raises(sentinel_compare.ComparisonError) as caught:
        sentinel_compare.compare(ref, [run(tmp_path, "a.json", rows),
                                       run(tmp_path, "b.json", rows)])
    assert "different version" in str(caught.value)


@pytest.mark.parametrize("field,value", [
    ("model_requested", "claude-opus-5"),
    ("system_prompt_sha", "edited"),
])
def test_two_runs_from_different_systems_are_refused(tmp_path, field, value):
    """Repetition confirms nothing unless it repeats the same experiment. The
    second run could otherwise be on a third model and still be counted."""
    ref = reference(tmp_path)
    first = [row(c, True) for c in ("one", "two", "three")]
    other = member()
    other["provenance"] = dict(other["provenance"], **{field: value})
    second = [row(c, True, members={"safe": other, "unsafe": other})
              for c in ("one", "two", "three")]

    # Refused either way, and which check fires first depends on the field: a
    # changed prompt breaks the contract with the reference before the two
    # passes are even compared with each other. Both refusals are correct and
    # the test is about the refusal, not about which sentence explains it.
    with pytest.raises(sentinel_compare.ComparisonError) as caught:
        sentinel_compare.compare(ref, [run(tmp_path, "a.json", first),
                                       run(tmp_path, "b.json", second)])
    message = str(caught.value)
    # Refused, and which check speaks first depends on the field: a changed
    # prompt breaks the contract with the reference, and a changed model is
    # caught by the rule that one comparison measures one challenger. All
    # three are correct refusals; the test is about the refusal.
    assert any(reason in message for reason in (
        "different systems", "Only the model may differ",
        "different models"))


def test_the_verifier_model_is_part_of_the_identity(tmp_path):
    """It follows the reviewer unless held, so two runs can differ by their
    verifier alone — and that is the variable this experiment holds still."""
    ref = reference(tmp_path)
    first = [row(c, True) for c in ("one", "two", "three")]
    other = member()
    other["settings"] = dict(other["settings"], verify_model="claude-sonnet-5")
    second = [row(c, True, members={"safe": other, "unsafe": other})
              for c in ("one", "two", "three")]

    with pytest.raises(sentinel_compare.ComparisonError):
        sentinel_compare.compare(ref, [run(tmp_path, "a.json", first),
                                       run(tmp_path, "b.json", second)])


def test_a_refusal_exits_two_and_a_rejection_exits_one(tmp_path, capsys):
    """Three states, as everywhere else here: 0 nothing blocking, 1 the change
    is rejected, 2 the comparison could not be made."""
    ref = reference(tmp_path)
    rows = [row("one", False), row("two", False), row("three", True)]
    both = [str(run(tmp_path, "a.json", rows)),
            str(run(tmp_path, "b.json", rows))]

    monkey = pytest.MonkeyPatch()
    monkey.setattr(sys, "argv", ["sentinel_compare.py", str(ref), *both])
    try:
        assert sentinel_compare.main() == 1
    finally:
        monkey.undo()

    monkey = pytest.MonkeyPatch()
    monkey.setattr(sys, "argv", ["sentinel_compare.py", str(ref), both[0]])
    try:
        assert sentinel_compare.main() == 2
    finally:
        monkey.undo()
    assert "Refusing to compare" in capsys.readouterr().err


# ------------------------------------- what "two confirmations" actually means


def test_two_of_three_runs_are_a_confirmed_regression(tmp_path):
    """The false green in the first version, and the stricter-looking reading
    was the permissive one.

    `all()` and `not any()` demanded every run agree, so `fail, fail, pass`
    across three runs was not a confirmed regression — while the frozen rule
    says two. Two reproductions of the same failure came out green.
    """
    ref = reference(tmp_path)
    bad = [row("one", False), row("two", True), row("three", True)]
    good = [row(c, True) for c in ("one", "two", "three")]

    result = sentinel_compare.compare(ref, [run(tmp_path, "a.json", bad),
                                            run(tmp_path, "b.json", bad),
                                            run(tmp_path, "c.json", good)])

    assert result["regressed"] == ["one"]


def test_the_same_execution_twice_is_not_a_repetition(tmp_path):
    """The cheapest way to manufacture a rejection, and what anyone would type
    after being told to pass both runs."""
    ref = reference(tmp_path)
    rows = [row("one", False), row("two", False), row("three", True)]
    once = run(tmp_path, "a.json", rows)

    with pytest.raises(sentinel_compare.ComparisonError) as caught:
        sentinel_compare.compare(ref, [once, once])
    assert "same execution" in str(caught.value)


def test_a_case_measured_once_and_counted_twice_is_refused(tmp_path):
    """`run_id` is stamped per *case*, so "two executions" is a question about
    each case: one measurement of it must not appear in both files."""
    ref = reference(tmp_path)
    first = [row(c, True) for c in ("one", "two", "three")]
    second = [row(c, True) for c in ("one", "two", "three")]
    second[0]["run_id_override"] = "a.json:one"

    with pytest.raises(sentinel_compare.ComparisonError) as caught:
        sentinel_compare.compare(ref, [run(tmp_path, "a.json", first),
                                       run(tmp_path, "b.json", second)])
    assert "same execution" in str(caught.value)


def test_a_row_with_no_run_id_is_refused(tmp_path):
    ref = reference(tmp_path)
    rows = [row(c, True) for c in ("one", "two", "three")]
    path = run(tmp_path, "a.json", rows)
    body = json.loads(path.read_text())
    body[0].pop("run_id")
    path.write_text(json.dumps(body))

    with pytest.raises(sentinel_compare.ComparisonError) as caught:
        sentinel_compare.compare(ref, [path, run(tmp_path, "b.json", rows)])
    assert "for `run_id`, so nothing names which execution" in str(
        caught.value)


def test_a_row_that_cannot_say_what_produced_it_is_refused(tmp_path):
    """Two rows that do not record their system are not thereby the same
    system. Folded together they would confirm each other."""
    ref = reference(tmp_path)
    blank = {"settings": {}}
    rows = [row(c, True, members={"safe": blank, "unsafe": blank})
            for c in ("one", "two", "three")]

    with pytest.raises(sentinel_compare.ComparisonError) as caught:
        sentinel_compare.compare(ref, [run(tmp_path, "a.json", rows),
                                       run(tmp_path, "b.json", rows)])
    # Refused, and the first check to reach it names what is missing. A blank
    # member records no `provenance`, no substitution flag, no served model, no
    # verification, no verifier and no prompt digest — every one of those
    # sentences is the same absence, refused rather than forgiven, and which
    # one comes back depends only on the order of the checks.
    #
    # The list has grown three times as earlier checks were added, and each
    # time this assertion was the thing that noticed. That is the point of
    # accepting any of them rather than pinning one: the test holds "this is
    # refused and the reason names the absence", not "this exact sentence".
    message = str(caught.value)
    assert any(reason in message for reason in (
        "records no", "verification is None",
        "for `provenance`, so nothing says what answered it",
        "does not record whether the provider substituted")), message


@pytest.mark.parametrize("members,expected", [
    (None, "for `members`, where the safe and unsafe blocks are required"),
    ("safe and unsafe",
     "for `members`, where the safe and unsafe blocks are required"),
    ([{"safe": {}}], "for `members`, where the safe and unsafe blocks are "
                     "required"),
    ({"safe": None, "unsafe": None},
     "member, where a block with `provenance` is required"),
    ({"safe": "ok", "unsafe": "ok"},
     "member, where a block with `provenance` is required"),
    ({"safe": {"provenance": 3}, "unsafe": {"provenance": 3}},
     "for `provenance`, so nothing says what answered it"),
])
def test_a_malformed_challenger_is_refused_rather_than_crashing(
        tmp_path, members, expected):
    """Codex, 2026-09-05, seventeenth gate pass.

    The same class that had just been swept out of the reference checks was
    still standing on the challenger side: `row.get("members")` was consumed
    with `.values()`, and each block with `.get()`, before anything said either
    was a mapping. A malformed run crashed the comparator instead of being
    refused by it — and a crash is not a verdict.
    """
    ref = reference(tmp_path)
    rows = [row(c, True, members=members) for c in ("one", "two", "three")]

    with pytest.raises(sentinel_compare.ComparisonError) as caught:
        sentinel_compare.compare(ref, [run(tmp_path, "a.json", rows),
                                       run(tmp_path, "b.json", rows)])
    assert expected in str(caught.value)


@pytest.mark.parametrize("settings", ["verify on", 3, [], None])
def test_settings_that_are_not_an_object_are_refused(tmp_path, settings):
    """`null` is in this list because the first version of the check read
    `block.get("settings") or {}` — the tolerant read turned it into an empty
    object before the check could refuse it, so the malformed container was
    erased by the line written to catch it. Codex, 2026-09-05."""
    ref = reference(tmp_path)
    block = {"provenance": {"model_substituted": False,
                            "models_served": ["opus"]},
             "settings": settings}
    rows = [row(c, True, members={"safe": block, "unsafe": block})
            for c in ("one", "two", "three")]

    with pytest.raises(sentinel_compare.ComparisonError) as caught:
        sentinel_compare.compare(ref, [run(tmp_path, "a.json", rows),
                                       run(tmp_path, "b.json", rows)])
    assert "for `settings`, where an object is required" in str(caught.value)


@pytest.mark.parametrize("served", ["opus", 3, {"a": 1}, [1], [""], [None]])
def test_models_served_that_is_not_a_list_of_names_is_refused(
        tmp_path, served):
    """Truthiness was the whole test, and `set().update()` reads the value a
    hundred lines below — so a truthy non-sequence passed here and crashed
    there, after the baseline had been called usable. Codex, 2026-09-05."""
    ref = reference(tmp_path)
    block = {"provenance": {"model_substituted": False,
                            "models_served": served}}
    rows = [row(c, True, members={"safe": block, "unsafe": block})
            for c in ("one", "two", "three")]

    with pytest.raises(sentinel_compare.ComparisonError) as caught:
        sentinel_compare.compare(ref, [run(tmp_path, "a.json", rows),
                                       run(tmp_path, "b.json", rows)])
    assert "where a list of model names is required" in str(caught.value)


@pytest.mark.parametrize("observed", ["opus", 3, ["opus"]])
def test_observed_models_that_is_not_an_object_is_refused(tmp_path, observed):
    """Read with `.items()` far below and validated nowhere, so a truthy
    non-mapping crashed the comparator after `validate_reference` had called
    the baseline usable."""
    ref = reference(tmp_path)
    body = json.loads(ref.read_text(encoding="utf-8"))
    body["observed_models"] = observed
    ref.write_text(json.dumps(body), encoding="utf-8")

    state = sentinel_compare.validate_reference(ref)
    assert state.state == sentinel_compare.REF_UNUSABLE
    assert "where an object naming the models" in state.why


@pytest.mark.parametrize("names", [3, None, "claude-opus-5", [1], [""]])
def test_observed_models_values_are_lists_of_names(tmp_path, names):
    """Codex, 2026-09-05, twentieth gate pass. The outer mapping was checked
    and its values were not.

    The string case is the one worth keeping: Python walks
    `"claude-opus-5"` into thirteen characters, so a value nobody validated
    produced a comparison against thirteen one-letter model names — an answer,
    not a crash, which is the worse of the two failures.
    """
    ref = reference(tmp_path)
    body = json.loads(ref.read_text(encoding="utf-8"))
    body["observed_models"] = {"safe": names}
    ref.write_text(json.dumps(body), encoding="utf-8")

    state = sentinel_compare.validate_reference(ref)
    assert state.state == sentinel_compare.REF_UNUSABLE
    assert "where a list of model names is required" in state.why


@pytest.mark.parametrize("verified", ["claude-opus-5", 3, {}, "", 0, [1]])
def test_models_verified_that_is_not_a_list_of_names_is_refused(
        tmp_path, verified):
    """The last boundary of this class, and it fails two ways at once.

    `or []` turned `0`, `""` and `{}` into an empty list, so a malformed field
    arrived as "nothing was verified" — a meaningful answer the comparator acts
    on. A bare string walked into characters. Codex, 2026-09-05.
    """
    ref = reference(tmp_path)
    block = {"provenance": {"model_substituted": False,
                            "models_served": ["claude-opus-5"],
                            "models_verified": verified}}
    rows = [row(c, True, members={"safe": block, "unsafe": block})
            for c in ("one", "two", "three")]

    with pytest.raises(sentinel_compare.ComparisonError) as caught:
        sentinel_compare.compare(ref, [run(tmp_path, "a.json", rows),
                                       run(tmp_path, "b.json", rows)])
    assert "for `models_verified`, where a list of model names is required" \
        in str(caught.value)


@pytest.mark.parametrize("flag,expected", [
    (True, "and this run says it did"),
    ("false", "absent and unreadable are both"),
    (0, "absent and unreadable are both"),
    ({}, "absent and unreadable are both"),
    (None, "absent and unreadable are both"),
])
def test_a_substituted_model_is_refused_not_only_an_unrecorded_one(
        tmp_path, flag, expected):
    """The comment above the check had said "required to be false and present,
    not merely not-true" since the check was written, and the code implemented
    `is None` — so `model_substituted: true`, the provider stating in as many
    words that it answered with a different model, passed. Codex, 2026-09-05.
    """
    ref = reference(tmp_path)
    block = {"provenance": {"model_substituted": flag,
                            "models_served": ["claude-opus-5"]}}
    rows = [row(c, True, members={"safe": block, "unsafe": block})
            for c in ("one", "two", "three")]

    with pytest.raises(sentinel_compare.ComparisonError) as caught:
        sentinel_compare.compare(ref, [run(tmp_path, "a.json", rows),
                                       run(tmp_path, "b.json", rows)])
    message = str(caught.value)
    assert "`model_substituted` is" in message
    assert expected in message


@pytest.mark.parametrize("stamp", [[], {}, 3, "", "   ", True])
def test_a_run_id_that_is_not_a_name_is_refused(tmp_path, stamp):
    """`[]` and `{}` reached `set()` and raised `TypeError`; a number or a
    blank string was accepted as the identity of an execution, which is the one
    thing this check exists to establish. Codex, 2026-09-05."""
    ref = reference(tmp_path)
    rows = [row(c, True) for c in ("one", "two", "three")]
    path = run(tmp_path, "a.json", rows)
    body = json.loads(path.read_text())
    body[0]["run_id"] = stamp
    path.write_text(json.dumps(body))

    with pytest.raises(sentinel_compare.ComparisonError) as caught:
        sentinel_compare.compare(ref, [path, run(tmp_path, "b.json", rows)])
    assert "for `run_id`, so nothing names which execution" in str(
        caught.value)


def test_a_row_for_an_unstable_case_is_checked_like_every_other(tmp_path):
    """Codex, 2026-09-05, twenty-fourth round, and the reason the guards moved
    to the boundary.

    Every structural check lived in loops over `comparable`, so a row belonging
    to `unstable_under_reference` skipped all of them — and still fed the
    provenance and system-identity comparisons. The checks run from `read_run`
    now, over every row of every run.
    """
    ref = reference(tmp_path, cases=("one", "two"), unstable=("three",))
    rows = [row(c, True) for c in ("one", "two", "three")]
    broken = json.loads(json.dumps(rows))
    for r in broken:
        if r["case_id"] == "three":
            r["members"]["safe"]["provenance"]["models_served"] = "opus"

    path = run(tmp_path, "a.json", broken)
    with pytest.raises(sentinel_compare.ComparisonError) as caught:
        sentinel_compare.compare(ref, [path, run(tmp_path, "b.json", rows)])
    assert "three: the run records str for `models_served`" in str(
        caught.value)


def test_a_member_key_that_is_not_a_name_is_refused_not_a_crash(tmp_path):
    """Codex, 2026-09-05, twenty-fifth round.

    The pair-membership complaint formatted its keys with
    `", ".join(sorted(members))`, which raises `TypeError` on a key that is not
    a string — so a row with a non-string member key produced a crash where a
    refusal belonged. JSON cannot write such a key; an in-process caller can,
    and the contract belongs in one place either way.
    """
    ref = reference(tmp_path)
    rows = [row(c, True) for c in ("one", "two", "three")]
    block = rows[0]["members"]["safe"]
    for r in rows:
        r["members"] = {1: block, "unsafe": block}

    with pytest.raises(sentinel_compare.ComparisonError) as caught:
        sentinel_compare.compare(ref, [run(tmp_path, "a.json", rows),
                                       run(tmp_path, "b.json", rows)])
    assert "a pair is a safe and an unsafe member" in str(caught.value)


def test_a_name_list_never_accepts_a_bare_string():
    """The predicate itself, because a string is the case every hand-written
    version of this check got wrong."""
    assert sentinel_compare._is_name_list(["a", "b"])
    assert sentinel_compare._is_name_list([])
    assert not sentinel_compare._is_name_list("ab")
    assert not sentinel_compare._is_name_list(None)
    assert not sentinel_compare._is_name_list([" "])
    assert not sentinel_compare._is_name_list({"a": 1})


def test_a_member_with_no_settings_key_is_still_allowed(tmp_path):
    """The other half. An absent `settings` is a different thing from one that
    is present and unreadable: `verify_model` falls back to the requested
    model, so absence has a defined meaning and is not refused."""
    ref = reference(tmp_path)
    block = {"provenance": {"model_substituted": False,
                            "models_served": ["opus"]}}
    rows = [row(c, True, members={"safe": block, "unsafe": block})
            for c in ("one", "two", "three")]

    with pytest.raises(sentinel_compare.ComparisonError) as caught:
        sentinel_compare.compare(ref, [run(tmp_path, "a.json", rows),
                                       run(tmp_path, "b.json", rows)])
    assert "for `settings`, where an object is required" not in str(
        caught.value)


def test_the_threshold_comes_from_the_reference(tmp_path):
    """Prose in the frozen file and a constant in the comparator are two rules
    that can disagree, and the code's copy is the one that would decide. The
    numbers live in the reference; changing them changes the verdict."""
    ref = reference(tmp_path)
    body = json.loads(ref.read_text())
    body["threshold"]["reject_at_net"] = 1
    ref.write_text(json.dumps(body))

    rows = [row("one", False), row("two", True), row("three", True)]
    result = sentinel_compare.compare(ref, [run(tmp_path, "a.json", rows),
                                            run(tmp_path, "b.json", rows)])

    assert result["net"] == 1 and result["verdict"] == "reject"


def test_a_reference_that_failed_two_ways_refuses_the_shape_question(tmp_path):
    """A case stable on `pair_success` can still fail differently across the
    reference's own passes. Reading pass A picked one by position; there is
    nothing there to measure a change of shape against."""
    ref = reference(tmp_path, failing=("one",))
    body = json.loads(ref.read_text())
    body["cases"]["one"]["shape"]["pass-b"] = {"missed": False,
                                               "false_alarm": True,
                                               "exits": [1, 0]}
    ref.write_text(json.dumps(body))

    rows = [row("one", False, missed=True), row("two", True), row("three", True)]
    with pytest.raises(sentinel_compare.ComparisonError) as caught:
        sentinel_compare.compare(ref, [run(tmp_path, "a.json", rows),
                                       run(tmp_path, "b.json", rows)])
    assert "failed differently" in str(caught.value)


def test_a_pass_directory_is_a_run(tmp_path):
    """`experiment.py` writes one file per case under a pass directory. The
    first version accepted only a single file holding the whole pass, so
    pointed at the real layout it read every case file as its own run and
    refused for missing cases — the paid results could not be handed to the
    tool built to read them."""
    ref = reference(tmp_path)
    for label in ("pass-a", "pass-b"):
        directory = tmp_path / label
        directory.mkdir()
        for case_id in ("one", "two", "three"):
            # One file per case, each with its **own** stamp — the shape
            # `experiment.py` and `pair_corpus.run_case` actually write. The
            # first version of this test gave every case in a pass the same
            # `run_id`, so it agreed with a comparator that would have refused
            # the real files on the first case.
            (directory / (case_id + ".json")).write_text(json.dumps(
                row(case_id, case_id != "one",
                    run_id="{}:{}".format(label, case_id))), encoding="utf-8")

    result = sentinel_compare.compare(ref, [tmp_path / "pass-a",
                                            tmp_path / "pass-b"])
    assert result["regressed"] == ["one"]


def test_an_empty_pass_directory_is_refused(tmp_path):
    ref = reference(tmp_path)
    (tmp_path / "empty").mkdir()
    rows = [row(c, True) for c in ("one", "two", "three")]

    with pytest.raises(sentinel_compare.ComparisonError) as caught:
        sentinel_compare.compare(ref, [run(tmp_path, "a.json", rows),
                                       tmp_path / "empty"])
    assert "no result files" in str(caught.value)


# ------------------------------------------- a reference that cannot be read


def test_a_reference_with_no_comparable_cases_is_refused(tmp_path):
    """Every one of these ends as a quiet `net: 0`, and a quiet zero reads as
    the cheaper model being fine."""
    ref = reference(tmp_path)
    body = json.loads(ref.read_text())
    body["comparable"] = []
    body["unstable_under_reference"] = sorted(body["cases"])
    for entry in body["cases"].values():
        entry["unstable_under_reference"] = True
    ref.write_text(json.dumps(body))

    rows = [row(c, True) for c in ("one", "two", "three")]
    with pytest.raises(sentinel_compare.ComparisonError) as caught:
        sentinel_compare.compare(ref, [run(tmp_path, "a.json", rows),
                                       run(tmp_path, "b.json", rows)])
    assert "no comparable cases" in str(caught.value)


def test_a_case_dropped_from_both_lists_is_refused(tmp_path):
    """Present in the reference, in neither list: silently outside the sample.
    Nobody reading the verdict would know the question had narrowed."""
    ref = reference(tmp_path)
    body = json.loads(ref.read_text())
    body["comparable"] = ["one", "two"]
    ref.write_text(json.dumps(body))

    rows = [row(c, True) for c in ("one", "two", "three")]
    with pytest.raises(sentinel_compare.ComparisonError) as caught:
        sentinel_compare.compare(ref, [run(tmp_path, "a.json", rows),
                                       run(tmp_path, "b.json", rows)])
    assert "do not add up" in str(caught.value)


def test_a_reference_with_nothing_to_lose_is_refused(tmp_path):
    """If every comparable case already failed, no `pass -> fail` is possible
    and the gate cannot detect the thing it exists for — while still printing
    a confident `passes the gate`."""
    ref = reference(tmp_path, failing=("one", "two", "three"))

    rows = [row(c, False) for c in ("one", "two", "three")]
    with pytest.raises(sentinel_compare.ComparisonError) as caught:
        sentinel_compare.compare(ref, [run(tmp_path, "a.json", rows),
                                       run(tmp_path, "b.json", rows)])
    assert "nothing to lose" in str(caught.value)


def test_a_rule_version_this_comparator_does_not_implement_is_refused(tmp_path):
    """A rule that changed is a different question, and a frozen file that
    describes one rule while the code applies another is the drift that putting
    the rule in code was meant to end."""
    ref = reference(tmp_path)
    body = json.loads(ref.read_text())
    body["threshold"]["rule_version"] = 99
    ref.write_text(json.dumps(body))

    rows = [row(c, True) for c in ("one", "two", "three")]
    with pytest.raises(sentinel_compare.ComparisonError) as caught:
        sentinel_compare.compare(ref, [run(tmp_path, "a.json", rows),
                                       run(tmp_path, "b.json", rows)])
    assert "rule version" in str(caught.value)


@pytest.mark.parametrize("field", ["unsafe_recall", "safe_false_positive"])
def test_a_failure_kind_that_is_not_a_boolean_is_refused(tmp_path, field):
    """A missing `safe_false_positive` read as "no false alarm" and the string
    "false" as one. Either moves a case between counted and not counted,
    quietly, in the direction nobody checks."""
    ref = reference(tmp_path, failing=("one",))
    rows = [row("one", False, missed=True), row("two", True), row("three", True)]
    rows[0][field] = "false"

    with pytest.raises(sentinel_compare.ComparisonError) as caught:
        sentinel_compare.compare(ref, [run(tmp_path, "a.json", rows),
                                       run(tmp_path, "b.json", rows)])
    assert field in str(caught.value)


# ------------------------------- the reference gets the same scrutiny as a run


@pytest.mark.parametrize("name", ["reject_at_net", "confirmations_required"])
@pytest.mark.parametrize("value", [0, -1, 1.5, True, None])
def test_a_threshold_that_is_not_a_count_is_refused(tmp_path, name, value):
    """Zero, negative or a float changes the rule; `True` is an `int` in Python
    and would read as one confirmation. Any of them turns the gate into
    something other than what the frozen file says it is."""
    ref = reference(tmp_path)
    body = json.loads(ref.read_text())
    body["threshold"][name] = value
    ref.write_text(json.dumps(body))

    rows = [row(c, True) for c in ("one", "two", "three")]
    with pytest.raises(sentinel_compare.ComparisonError) as caught:
        sentinel_compare.compare(ref, [run(tmp_path, "a.json", rows),
                                       run(tmp_path, "b.json", rows)])
    assert name in str(caught.value)


def test_a_reference_that_records_missing_cases_is_refused(tmp_path):
    """`missing` was written by the freezer and read by nobody. A reference
    that could not measure part of its own suite describes a narrower question
    than the one it is named for."""
    ref = reference(tmp_path)
    body = json.loads(ref.read_text())
    body["missing"] = ["four"]
    ref.write_text(json.dumps(body))

    rows = [row(c, True) for c in ("one", "two", "three")]
    with pytest.raises(sentinel_compare.ComparisonError) as caught:
        sentinel_compare.compare(ref, [run(tmp_path, "a.json", rows),
                                       run(tmp_path, "b.json", rows)])
    assert "missing four" in str(caught.value)


def test_a_case_listed_twice_as_comparable_is_refused(tmp_path):
    ref = reference(tmp_path)
    body = json.loads(ref.read_text())
    body["comparable"] = ["one", "one", "two", "three"]
    ref.write_text(json.dumps(body))

    rows = [row(c, True) for c in ("one", "two", "three")]
    with pytest.raises(sentinel_compare.ComparisonError) as caught:
        sentinel_compare.compare(ref, [run(tmp_path, "a.json", rows),
                                       run(tmp_path, "b.json", rows)])
    assert "twice" in str(caught.value)


def test_a_reference_verdict_that_is_not_a_boolean_is_refused(tmp_path):
    """The challenger's rows were checked strictly and the reference was taken
    on trust — backwards, since the reference decides what the challenger is
    measured against. `"false"` is truthy and would read as a pass."""
    ref = reference(tmp_path)
    body = json.loads(ref.read_text())
    body["cases"]["one"]["outcomes"]["pass-a"] = "false"
    ref.write_text(json.dumps(body))

    rows = [row(c, True) for c in ("one", "two", "three")]
    with pytest.raises(sentinel_compare.ComparisonError) as caught:
        sentinel_compare.compare(ref, [run(tmp_path, "a.json", rows),
                                       run(tmp_path, "b.json", rows)])
    assert "not a verdict" in str(caught.value)


def test_a_reference_shape_that_is_not_a_boolean_is_refused(tmp_path):
    """A non-boolean here suppresses recognition of a newly gained kind of
    failure, which is the quiet direction."""
    ref = reference(tmp_path, failing=("one",))
    body = json.loads(ref.read_text())
    body["cases"]["one"]["shape"]["pass-a"]["false_alarm"] = "no"
    ref.write_text(json.dumps(body))

    rows = [row("one", False, missed=True), row("two", True), row("three", True)]
    with pytest.raises(sentinel_compare.ComparisonError) as caught:
        sentinel_compare.compare(ref, [run(tmp_path, "a.json", rows),
                                       run(tmp_path, "b.json", rows)])
    assert "false_alarm" in str(caught.value)


def test_a_run_the_provider_answered_with_another_model_is_refused(tmp_path):
    """Still refused, and now by what actually served rather than by a flag.

    The experiment is about which model was asked. A review the provider
    answered with a different one did not measure the model it names — and it
    shows as a served model the reference never saw, which is the same fact
    read from the machinery instead of from a boolean.
    """
    ref = reference(tmp_path)
    swapped = member()
    swapped["provenance"] = dict(swapped["provenance"],
                                 models_served=["claude-opus-4-8"])
    rows = [row(c, True, members={"safe": swapped, "unsafe": swapped})
            for c in ("one", "two", "three")]

    with pytest.raises(sentinel_compare.ComparisonError) as caught:
        sentinel_compare.compare(ref, [run(tmp_path, "a.json", rows),
                                       run(tmp_path, "b.json", rows)])
    assert "the machinery has to be the same" in str(caught.value)


def test_a_verifier_that_fires_on_some_cases_only_is_one_system(tmp_path):
    """The defect that would have refused the real Sonnet files on the first
    case: the verifier runs only where there is a finding, so `models_verified`
    differs between cases of the *same* run."""
    ref = reference(tmp_path)
    quiet = member()
    quiet["provenance"] = dict(quiet["provenance"], models_verified=[])
    verified = member()
    verified["provenance"] = dict(verified["provenance"],
                                  models_verified=["claude-opus-5"])

    rows = [row("one", True, members={"safe": quiet, "unsafe": quiet}),
            row("two", True, members={"safe": verified, "unsafe": verified}),
            row("three", True)]
    result = sentinel_compare.compare(ref, [run(tmp_path, "a.json", rows),
                                            run(tmp_path, "b.json", rows)])

    assert result["verdict"] == "passes the gate"


def test_a_verifier_the_provider_swapped_is_refused(tmp_path):
    """The gap that sat in the exact configuration this experiment runs.

    The whole design is a cheaper reviewer with the verifier held on Opus. Only
    the reviewer's substitution was checked, so a provider answering the
    verification with something smaller would have passed — and the cheaper
    reviewer would have looked fine because the thing measuring it had been
    made cheaper too. A quiet `net: 0`.
    """
    ref = reference(tmp_path)
    swapped = member()
    swapped["provenance"] = dict(swapped["provenance"],
                                 models_verified=["claude-haiku-4-5-20251001"])
    rows = [row(c, True, members={"safe": swapped, "unsafe": swapped})
            for c in ("one", "two", "three")]

    with pytest.raises(sentinel_compare.ComparisonError) as caught:
        sentinel_compare.compare(ref, [run(tmp_path, "a.json", rows),
                                       run(tmp_path, "b.json", rows)])
    assert "asked for claude-opus-5" in str(caught.value)


def test_the_verifier_held_where_it_was_is_accepted(tmp_path):
    """The intended arrangement has to pass, or the check is useless: a Sonnet
    reviewer with `verify_model` on Opus, and Opus doing the verifying."""
    ref = reference(tmp_path)
    held = member()
    held["provenance"] = dict(held["provenance"],
                              model_requested="claude-sonnet-5",
                              models_verified=["claude-opus-5"])
    rows = [row(c, True, members={"safe": held, "unsafe": held})
            for c in ("one", "two", "three")]

    result = sentinel_compare.compare(ref, [run(tmp_path, "a.json", rows),
                                            run(tmp_path, "b.json", rows)])
    assert result["verdict"] == "passes the gate"


def test_a_row_that_verified_with_verification_off_is_refused(tmp_path):
    """An artifact that cannot be true. Verification was off, so nothing
    verified; a row saying otherwise describes a run that did not happen, and
    accepting it means accepting whatever else it says."""
    ref = reference(tmp_path)
    impossible = member()
    impossible["settings"] = dict(impossible["settings"], verify=False)
    impossible["provenance"] = dict(impossible["provenance"],
                                    models_verified=["claude-opus-5"])
    rows = [row(c, True, members={"safe": impossible, "unsafe": impossible})
            for c in ("one", "two", "three")]

    with pytest.raises(sentinel_compare.ComparisonError) as caught:
        sentinel_compare.compare(ref, [run(tmp_path, "a.json", rows),
                                       run(tmp_path, "b.json", rows)])
    # The stronger rule speaks first now: verification has to be *on*, not
    # merely not-contradicted. Forbidding the impossible combination was the
    # weaker half of the same question, and it let a run with the layer
    # switched off through.
    assert "verification is False" in str(caught.value)


# ------------------------------- only the model may differ from the reference


@pytest.mark.parametrize("field,value", [
    ("system_prompt_sha", "edited"),
    ("verifier_prompt_sha", "edited"),
    ("schema_sha", "edited"),
    ("agent_version", "0.2.0"),
])
def test_a_challenger_that_changed_more_than_the_model_is_refused(
        tmp_path, field, value):
    """The comparator asked whether the two challenger passes agreed with each
    other and never whether either agreed with the reference.

    So a run with an edited prompt, a changed schema or a newer agent could be
    compared against the Opus reference and the entire difference attributed to
    the model — the error this repository exists against, arrived at through
    the tool built to prevent it.
    """
    ref = reference(tmp_path)
    moved = member()
    moved["provenance"] = dict(moved["provenance"], **{field: value})
    rows = [row(c, True, members={"safe": moved, "unsafe": moved})
            for c in ("one", "two", "three")]

    with pytest.raises(sentinel_compare.ComparisonError) as caught:
        sentinel_compare.compare(ref, [run(tmp_path, "a.json", rows),
                                       run(tmp_path, "b.json", rows)])
    assert "Only the model may differ" in str(caught.value)


def test_a_challenger_that_changed_only_the_model_is_accepted(tmp_path):
    """The control. A check that refuses the intended change is a check that
    gets removed."""
    ref = reference(tmp_path)
    rows = [row(c, True) for c in ("one", "two", "three")]

    result = sentinel_compare.compare(ref, [run(tmp_path, "a.json", rows),
                                            run(tmp_path, "b.json", rows)])
    assert result["verdict"] == "passes the gate"


def test_a_traded_case_is_not_reported_as_equivalence(tmp_path):
    """"passes the gate" is a statement about the threshold, and with a traded
    case present it was reading as "the models are the same". A case that
    swapped one kind of failure for the other did change; the rule declines to
    order the two, and saying so is more honest than a word that sounds like
    equivalence."""
    ref = reference(tmp_path, failing=("one",))
    rows = [row("one", False, missed=False, false_alarm=True),
            row("two", True), row("three", True)]

    result = sentinel_compare.compare(ref, [run(tmp_path, "a.json", rows),
                                            run(tmp_path, "b.json", rows)])
    assert result["traded"] == ["one"]
    assert result["verdict"] == "below the threshold, and cases changed"


def test_a_challenger_that_is_the_reference_model_is_refused(tmp_path):
    """Forget the environment variable and both passes run Opus. Everything
    matches, the comparison says "passes the gate" for a change that never
    happened, and the wider run gets bought on the strength of it. The one
    difference the reference permits is also the one it requires."""
    ref = reference(tmp_path)
    same = member()
    same["provenance"] = dict(same["provenance"],
                              model_requested="claude-opus-5",
                              models_served=["claude-opus-5"])
    rows = [row(c, True, members={"safe": same, "unsafe": same})
            for c in ("one", "two", "three")]

    with pytest.raises(sentinel_compare.ComparisonError) as caught:
        sentinel_compare.compare(ref, [run(tmp_path, "a.json", rows),
                                       run(tmp_path, "b.json", rows)])
    assert "no change here to measure" in str(caught.value)


# ------------------------------------------- absence is not agreement


@pytest.mark.parametrize("field,name", [
    ("system_prompt_sha", "system_prompt"),
    ("verifier_prompt_sha", "verifier_prompt"),
    ("schema_sha", "findings_schema"),
    ("agent_version", "agent_version"),
])
def test_a_missing_environment_digest_is_refused(tmp_path, field, name):
    """`if expected and recorded` forgave a row that recorded nothing.

    `_system_identity` asks only for a prompt and a model, so two rows missing
    the same digests confirmed each other and walked around the reference
    entirely — the contract satisfied by what neither of them said.
    """
    ref = reference(tmp_path)
    silent = member()
    silent["provenance"] = dict(silent["provenance"])
    silent["provenance"].pop(field)
    rows = [row(c, True, members={"safe": silent, "unsafe": silent})
            for c in ("one", "two", "three")]

    with pytest.raises(sentinel_compare.ComparisonError) as caught:
        sentinel_compare.compare(ref, [run(tmp_path, "a.json", rows),
                                       run(tmp_path, "b.json", rows)])
    assert "records no {}".format(name) in str(caught.value)


def test_a_run_that_names_no_model_is_refused(tmp_path):
    """Discarding `None` first meant a run recording no model at all left an
    empty set and skipped the check that it is a challenger."""
    ref = reference(tmp_path)
    nameless = member()
    nameless["provenance"] = dict(nameless["provenance"], model_requested="")
    rows = [row(c, True, members={"safe": nameless, "unsafe": nameless})
            for c in ("one", "two", "three")]

    with pytest.raises(sentinel_compare.ComparisonError) as caught:
        sentinel_compare.compare(ref, [run(tmp_path, "a.json", rows),
                                       run(tmp_path, "b.json", rows)])
    assert "records no `model_requested`" in str(caught.value)


def test_two_models_mixed_across_members_are_refused(tmp_path):
    """Opus on one member and Sonnet on the other produced a set of two, which
    is not the reference's model either — so the challenger check passed, while
    `_system_identity` saw one consistent system and let it through. One
    comparison measures one challenger."""
    ref = reference(tmp_path)
    other = member()
    other["provenance"] = dict(other["provenance"],
                               model_requested="claude-opus-5",
                               models_served=["claude-opus-5"])
    rows = [row(c, True, members={"safe": other, "unsafe": member()})
            for c in ("one", "two", "three")]

    with pytest.raises(sentinel_compare.ComparisonError) as caught:
        sentinel_compare.compare(ref, [run(tmp_path, "a.json", rows),
                                       run(tmp_path, "b.json", rows)])
    assert "different models" in str(caught.value)


def test_a_challenger_that_let_the_verifier_follow_is_refused(tmp_path):
    """The one that turns the experiment inside out.

    Only the *observed* verifier was checked, and only against what the
    challenger itself recorded. Forget `SECURITY_SCAN_VERIFY_MODEL` and the
    verifier follows the reviewer down to Sonnet: both passes agree with each
    other, the served-verifier check passes, and a quiet `net: 0` comes back
    for a run that changed both models at once. It would have measured "Sonnet
    judged by Sonnet" and reported it as "Sonnet against Opus".
    """
    ref = reference(tmp_path)
    followed = member()
    followed["settings"] = dict(followed["settings"],
                                verify_model="claude-sonnet-5")
    followed["provenance"] = dict(followed["provenance"],
                                  models_verified=["claude-sonnet-5"])
    rows = [row(c, True, members={"safe": followed, "unsafe": followed})
            for c in ("one", "two", "three")]

    with pytest.raises(sentinel_compare.ComparisonError) as caught:
        sentinel_compare.compare(ref, [run(tmp_path, "a.json", rows),
                                       run(tmp_path, "b.json", rows)])
    assert "measures a different question" in str(caught.value)


def test_a_challenger_that_records_no_verify_model_is_refused(tmp_path):
    ref = reference(tmp_path)
    silent = member()
    silent["settings"] = dict(silent["settings"])
    silent["settings"].pop("verify_model")
    rows = [row(c, True, members={"safe": silent, "unsafe": silent})
            for c in ("one", "two", "three")]

    with pytest.raises(sentinel_compare.ComparisonError) as caught:
        sentinel_compare.compare(ref, [run(tmp_path, "a.json", rows),
                                       run(tmp_path, "b.json", rows)])
    assert "records no `verify_model`" in str(caught.value)


def test_a_reference_with_one_outcome_per_case_is_refused(tmp_path):
    """A reference carrying one pass never checked itself for stability, and
    excluding the cases it disagreed with itself about rests on having two."""
    ref = reference(tmp_path)
    body = json.loads(ref.read_text())
    body["cases"]["one"]["outcomes"] = {"pass-a": True}
    ref.write_text(json.dumps(body))

    rows = [row(c, True) for c in ("one", "two", "three")]
    with pytest.raises(sentinel_compare.ComparisonError) as caught:
        sentinel_compare.compare(ref, [run(tmp_path, "a.json", rows),
                                       run(tmp_path, "b.json", rows)])
    assert "takes two" in str(caught.value)


def test_a_row_missing_a_member_says_so(tmp_path):
    """One member missing was reported as a model or identity complaint, which
    sends the reader to the wrong question."""
    ref = reference(tmp_path)
    rows = [row(c, True) for c in ("one", "two", "three")]
    rows[0]["members"] = {"safe": member()}

    with pytest.raises(sentinel_compare.ComparisonError) as caught:
        sentinel_compare.compare(ref, [run(tmp_path, "a.json", rows),
                                       run(tmp_path, "b.json", rows)])
    assert "a safe and an unsafe member" in str(caught.value)


def test_a_reference_with_no_environment_is_refused(tmp_path):
    ref = reference(tmp_path)
    body = json.loads(ref.read_text())
    body["environment"] = {}
    ref.write_text(json.dumps(body))

    rows = [row(c, True) for c in ("one", "two", "three")]
    with pytest.raises(sentinel_compare.ComparisonError) as caught:
        sentinel_compare.compare(ref, [run(tmp_path, "a.json", rows),
                                       run(tmp_path, "b.json", rows)])
    assert "no environment" in str(caught.value)


def test_a_challenger_with_verification_switched_off_is_refused(tmp_path):
    """The mirror of the previous defect, and the one that survived it.

    The check forbade the impossible combination — verification off with a
    model recorded as having verified — and never asked for the thing itself.
    So a challenger with the layer *switched off* and `verify_model` still
    written down passed: both runs agreed, and a quiet `net: 0` came back for
    "Sonnet with no verifier" measured against "Opus with one".
    """
    ref = reference(tmp_path)
    unverified = member()
    unverified["settings"] = dict(unverified["settings"], verify=False)
    unverified["provenance"] = dict(unverified["provenance"],
                                    models_verified=[])
    rows = [row(c, True, members={"safe": unverified, "unsafe": unverified})
            for c in ("one", "two", "three")]

    with pytest.raises(sentinel_compare.ComparisonError) as caught:
        sentinel_compare.compare(ref, [run(tmp_path, "a.json", rows),
                                       run(tmp_path, "b.json", rows)])
    assert "Removing a layer" in str(caught.value)


def test_a_challenger_that_does_not_record_verification_is_refused(tmp_path):
    """Absent is not true. Nothing about a missing field says the layer ran."""
    ref = reference(tmp_path)
    silent = member()
    silent["settings"] = dict(silent["settings"])
    silent["settings"].pop("verify")
    rows = [row(c, True, members={"safe": silent, "unsafe": silent})
            for c in ("one", "two", "three")]

    with pytest.raises(sentinel_compare.ComparisonError) as caught:
        sentinel_compare.compare(ref, [run(tmp_path, "a.json", rows),
                                       run(tmp_path, "b.json", rows)])
    assert "verification is None" in str(caught.value)


def test_a_reference_that_names_no_verifier_is_refused(tmp_path):
    """`if wanted_verifier:` skipped the whole contract when the field was
    absent — the rule held only for references that happened to carry it."""
    ref = reference(tmp_path)
    body = json.loads(ref.read_text())
    body.pop("verifier_model")
    ref.write_text(json.dumps(body))

    rows = [row(c, True) for c in ("one", "two", "three")]
    with pytest.raises(sentinel_compare.ComparisonError) as caught:
        sentinel_compare.compare(ref, [run(tmp_path, "a.json", rows),
                                       run(tmp_path, "b.json", rows)])
    # The refusal moved earlier on 2026-09-05: it is a fact about the
    # reference alone, so `validate_reference` answers it before any run is
    # read, and the D-013 preflight sees it too.
    assert "for `verifier_model`, so it does not say which model" in str(
        caught.value)


def test_the_machinery_the_reference_saw_must_serve_the_challenger_too(
        tmp_path):
    """Every unsafe member of the real reference carries Haiku beside Opus and
    every safe member does not: the CLI serves part of the verification with a
    smaller model wherever there is a finding.

    Demanding the requested model alone would refuse the challenger for the
    same reason it refuses the reference. Ignoring it would let the instrument
    change underneath the comparison. So it is compared: the same set, with the
    challenger's model in place of the reference's.
    """
    ref = reference(tmp_path)
    body = json.loads(ref.read_text())
    body["observed_models"]["unsafe"] = ["claude-haiku-4-5-20251001",
                                         "claude-opus-5"]
    ref.write_text(json.dumps(body))

    helped = member()
    helped["provenance"] = dict(helped["provenance"],
                                models_served=["claude-sonnet-5",
                                               "claude-haiku-4-5-20251001"])
    matching = [row(c, True, members={"safe": member(), "unsafe": helped})
                for c in ("one", "two", "three")]
    result = sentinel_compare.compare(ref, [run(tmp_path, "a.json", matching),
                                            run(tmp_path, "b.json", matching)])
    assert result["verdict"] == "passes the gate"

    # And the same run without the helper is a different instrument.
    alone = [row(c, True) for c in ("one", "two", "three")]
    with pytest.raises(sentinel_compare.ComparisonError) as caught:
        sentinel_compare.compare(ref, [run(tmp_path, "c.json", alone),
                                       run(tmp_path, "d.json", alone)])
    assert "the machinery has to be the same" in str(caught.value)

