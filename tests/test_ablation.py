"""The ablation's scoring, exercised without paying for a review.

`tools/ablation.py` answers one question: on the regression construction, is a
blocked merge evidence that the agent recognised the weakness, or only that the
diff deleted lines? Everything expensive about it is the API call; everything
that can be wrong about it is the reading of `findings.json`. So the artifact is
fed in directly here, shaped exactly as `report.build_json` writes it.

Four situations have to come out distinguishable, because they are the four the
tool exists to tell apart:

  * blocks only with the removed-control rule on — the rule is carrying it
  * blocks either way — severity carried it, the rule was redundant
  * never discovered — nothing downstream means anything
  * discovered every time but never blocks — recognition without a gate
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from ablation import (
    CONSTRUCTIONS,
    MEMBERS,
    Observation,
    base_id,
    cell_key,
    construction_of,
    group_cases,
    observe,
    rollup,
    score_case,
)

CASE = {"case_id": "go-abc", "expected_category": "dos",
        "expected_file": "openapi3filter/req_resp_decoder.go"}


# ------------------------------------------------------------------ artifacts

def finding(**overrides) -> dict:
    """One entry of `findings[]`, with the keys the scorer actually reads."""
    data = {
        "fingerprint": "abc123",
        "title": "Unbounded expansion in deepObject decoding",
        "severity": "high",
        "confidence": "high",
        "category": "dos",
        "file": "openapi3filter/req_resp_decoder.go",
        "line": 41,
        "verification": {
            "verdict": "confirmed",
            "removes_existing_control": False,
            "attributed_by": "added",
        },
    }
    data.update(overrides)
    return data


def artifact(findings=(), refuted=(), suppressed=(), blocking=()) -> dict:
    return {
        "verdict": {"exit_code": 1 if blocking else 0,
                    "blocked": bool(blocking),
                    "blocking_fingerprints": list(blocking)},
        "findings": list(findings),
        "refuted": list(refuted),
        "suppressed": list(suppressed),
    }


# ------------------------------------------------------------------- observing

def test_a_blocked_finding_is_read_out_whole():
    seen = observe(artifact([finding()], blocking=["abc123"]), CASE)
    assert seen.discovered
    assert seen.bucket == "findings"
    assert seen.confirmed
    assert (seen.severity, seen.confidence) == ("high", "high")
    assert seen.blocked
    assert seen.removes_control is False


def test_a_finding_in_another_file_is_not_the_target():
    other = finding(file="internal/other.go", fingerprint="zzz")
    assert not observe(artifact([other], blocking=["zzz"]), CASE).discovered


def test_a_finding_in_another_category_is_not_the_target():
    assert not observe(artifact([finding(category="injection")]), CASE).discovered


def test_a_refuted_target_still_counts_as_discovered():
    """`build_json` files refuted candidates in their own list.

    Looking only at `findings` would score "the verifier threw it away" as
    "never saw it" — the two call for opposite fixes, so they cannot share a
    number.
    """
    refuted = finding(verification={"verdict": "refuted",
                                    "removes_existing_control": False})
    seen = observe(artifact(refuted=[refuted]), CASE)
    assert seen.discovered
    assert seen.bucket == "refuted"
    assert not seen.confirmed
    assert not seen.blocked


def test_a_suppressed_target_counts_as_discovered():
    seen = observe(artifact(suppressed=[finding()]), CASE)
    assert seen.discovered
    assert seen.bucket == "suppressed"
    assert not seen.blocked


def test_the_blocking_match_wins_when_two_findings_match():
    quiet = finding(fingerprint="quiet", line=10)
    loud = finding(fingerprint="loud", line=88)
    seen = observe(artifact([quiet, loud], blocking=["loud"]), CASE)
    assert seen.blocked


def test_a_missing_removes_control_key_is_unknown_not_false():
    """If the artifact ever stops carrying the field, say so rather than guess.

    `False` would read as "the verifiers considered it and said no", which is a
    claim about the model. `None` is a claim about the artifact.
    """
    bare = finding(verification={"verdict": "confirmed"})
    assert observe(artifact([bare]), CASE).removes_control is None


# -------------------------------------------------------------------- grouping

def test_the_snap_sibling_groups_with_its_regression_case():
    regression = {"case_id": "go-abc", "construction": "regression", "language": "go"}
    snapshot = {"case_id": "go-abc-snap", "construction": "snapshot", "language": "go"}
    groups = group_cases([snapshot, regression])
    assert list(groups) == ["go-abc"]
    assert set(groups["go-abc"]) == set(CONSTRUCTIONS)


def test_construction_falls_back_to_the_id_when_the_manifest_is_silent():
    assert construction_of({"case_id": "go-abc-snap"}) == "snapshot"
    assert construction_of({"case_id": "go-abc"}) == "regression"
    # The manifest wins over the suffix — it is the thing the harvester wrote.
    assert construction_of(
        {"case_id": "go-abc", "construction": "snapshot"}) == "snapshot"


def test_base_id_leaves_a_plain_id_alone():
    assert base_id("go-abc") == "go-abc"
    assert base_id("go-abc-snap") == "go-abc"


# --------------------------------------------------------------------- scoring

def cells(**by_cell) -> dict:
    """Observations for one case, keyed as the runner keys them.

    Each keyword is `<construction>_<on|off>` and gives (unsafe, safe); a bare
    Observation means "and the safe member stayed quiet", which is the ordinary
    case and would otherwise be repeated in every fixture.
    """
    quiet = Observation()
    out = {}
    for name, value in by_cell.items():
        construction, gate = name.rsplit("_", 1)
        unsafe, safe = value if isinstance(value, tuple) else (value, quiet)
        out[(construction, gate == "on", "unsafe")] = unsafe
        out[(construction, gate == "on", "safe")] = safe
    return out


def group(base: str = "go-abc") -> dict:
    return {
        "regression": {"case_id": base, "construction": "regression",
                       "language": "go", "family": "dos"},
        "snapshot": {"case_id": base + "-snap", "construction": "snapshot",
                     "language": "go", "family": "dos"},
    }


def found(blocked: bool, removes: bool = False, severity: str = "medium") -> Observation:
    return Observation(discovered=True, bucket="findings", verdict="confirmed",
                       severity=severity, confidence="high", blocked=blocked,
                       removes_control=removes)


def case_the_rule_carries() -> dict:
    """Blocks on regression only while the rule is on.

    The finding rates below the bar; what stopped the merge was that the diff
    deleted a guard. On snapshot nothing is deleted, so the same weakness is
    seen and let through.
    """
    return score_case(group(), cells(
        regression_on=found(blocked=True, removes=True, severity="low"),
        regression_off=found(blocked=False, removes=True, severity="low"),
        snapshot_on=found(blocked=False, severity="low"),
        snapshot_off=found(blocked=False, severity="low"),
    ))


def case_blocks_either_way() -> dict:
    """Blocks with the rule on and with it off, on both constructions.

    Severity carried it; the rule was redundant. This is what a case looks like
    when the score is evidence of recognition.
    """
    return score_case(group("py-xyz"), cells(
        regression_on=found(blocked=True, removes=True, severity="high"),
        regression_off=found(blocked=True, severity="high"),
        snapshot_on=found(blocked=True, severity="high"),
        snapshot_off=found(blocked=True, severity="high"),
    ))


def case_never_discovered() -> dict:
    missed = Observation()
    return score_case(group("rb-nope"), cells(
        regression_on=missed, regression_off=missed,
        snapshot_on=missed, snapshot_off=missed,
    ))


def case_discovered_never_blocks() -> dict:
    """Seen in all four cells, gated in none.

    Recognition without a gate: the corpus question comes out well and the
    pipeline question comes out badly, and a single pass/fail would hide one of
    the two.
    """
    return score_case(group("ts-seen"), cells(
        regression_on=found(blocked=False, severity="low"),
        regression_off=found(blocked=False, severity="low"),
        snapshot_on=found(blocked=False, severity="low"),
        snapshot_off=found(blocked=False, severity="low"),
    ))


def test_every_cell_is_filled_for_both_members():
    case = case_blocks_either_way()
    assert set(case["cells"]) == {
        cell_key(c, g) for c in CONSTRUCTIONS for g in (True, False)}
    for cell in case["cells"].values():
        assert set(cell) == set(MEMBERS)


def test_a_missing_construction_leaves_its_cells_out():
    partial = {"regression": group()["regression"]}
    case = score_case(partial, cells(
        regression_on=found(blocked=True), regression_off=found(blocked=False)))
    assert set(case["cells"]) == {"regression/on", "regression/off"}


def test_a_failed_review_is_an_error_not_a_miss():
    """A cell that never ran must not be counted as "nothing was found"."""
    case = score_case(group(), {("regression", True, "unsafe"): "no output"})
    assert case["cells"]["regression/on"]["unsafe"] == {"error": "no output"}
    counted = rollup([case])["regression/on"]
    assert counted["scored"] == 0
    assert counted["unsafe_discovered"] == 0


def test_a_half_run_case_cannot_invent_a_difference():
    """Both comparisons are within-case, so a cell that never ran sits out.

    Otherwise one crashed review shows up as "the rule contributed one" or as a
    discovery gap, and the two headline numbers become artefacts of a timeout.
    """
    half = score_case(group("half"), cells(
        regression_on=found(blocked=True, removes=True), regression_off="boom",
        snapshot_on="boom", snapshot_off="boom"))
    summary = rollup([half])
    assert summary["regression/on"]["unsafe_blocked"] == 1
    assert summary["rule_paired_cases"] == 0
    assert summary["rule_contribution_regression"] == 0
    assert summary["discovery_paired_cases"] == 0
    assert summary["discovery_gap"] == 0


def test_the_rule_alone_is_what_the_two_regression_columns_differ_by():
    summary = rollup([case_the_rule_carries()])
    assert summary["regression/on"]["unsafe_blocked"] == 1
    assert summary["regression/off"]["unsafe_blocked"] == 0
    assert summary["rule_contribution_regression"] == 1


def test_a_case_that_blocks_either_way_owes_the_rule_nothing():
    summary = rollup([case_blocks_either_way()])
    assert summary["regression/on"]["unsafe_blocked"] == 1
    assert summary["regression/off"]["unsafe_blocked"] == 1
    assert summary["rule_contribution_regression"] == 0
    # And it blocks where the rule cannot reach at all.
    assert summary["snapshot/on"]["unsafe_blocked"] == 1


def test_a_case_that_was_never_discovered_scores_nowhere():
    summary = rollup([case_never_discovered()])
    for key in ("regression/on", "regression/off", "snapshot/on", "snapshot/off"):
        assert summary[key]["scored"] == 1          # it ran
        assert summary[key]["unsafe_discovered"] == 0
        assert summary[key]["unsafe_blocked"] == 0
    assert summary["discovery_gap"] == 0


def test_discovery_and_blocking_are_counted_separately():
    summary = rollup([case_discovered_never_blocks()])
    assert summary["regression/on"]["unsafe_discovered"] == 1
    assert summary["regression/on"]["unsafe_blocked"] == 0
    assert summary["snapshot/on"]["unsafe_discovered"] == 1
    # Discovery held where the diff deleted nothing: recognition, not direction.
    assert summary["discovery_gap"] == 0


def test_discovery_that_collapses_on_snapshot_shows_up_as_a_gap():
    """The failure this whole tool was built to catch.

    Found and blocked whenever the diff deletes something, invisible when the
    same weakness arrives as an addition. Blocking on regression looks perfect;
    the gap is the thing that says the score was carried by the direction of
    the diff.
    """
    case = score_case(group("php-shape"), cells(
        regression_on=found(blocked=True, removes=True, severity="low"),
        regression_off=found(blocked=False, removes=True, severity="low"),
        snapshot_on=Observation(),
        snapshot_off=Observation(),
    ))
    summary = rollup([case])
    assert summary["regression/on"]["unsafe_blocked"] == 1
    assert summary["discovery_regression_on"] == 1
    assert summary["discovery_snapshot_on"] == 0
    assert summary["discovery_gap"] == 1


def test_the_rollup_adds_up_over_several_cases():
    summary = rollup([case_the_rule_carries(), case_blocks_either_way(),
                      case_never_discovered(), case_discovered_never_blocks()])
    assert summary["cases"] == 4
    assert summary["regression/on"]["scored"] == 4
    assert summary["regression/on"]["unsafe_discovered"] == 3
    assert summary["regression/on"]["unsafe_blocked"] == 2
    assert summary["regression/off"]["unsafe_blocked"] == 1
    assert summary["rule_contribution_regression"] == 1
    assert summary["snapshot/on"]["unsafe_discovered"] == 3
    assert summary["snapshot/on"]["unsafe_blocked"] == 1
    assert summary["discovery_gap"] == 0
    assert summary["regression/on"]["unsafe_removes_control"] == 2


def test_a_safe_member_that_reports_the_target_is_counted_as_a_false_positive():
    case = score_case(group(), cells(
        regression_on=(found(blocked=True), found(blocked=False)),
        regression_off=found(blocked=False),
        snapshot_on=found(blocked=True),
        snapshot_off=found(blocked=True),
    ))
    summary = rollup([case])
    assert summary["regression/on"]["safe_false_positive"] == 1
    assert summary["regression/on"]["safe_scored"] == 1
    assert summary["snapshot/on"]["safe_false_positive"] == 0
