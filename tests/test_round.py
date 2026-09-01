"""`tools/round.py` decides whether a paid run answers anything.

Codex refused a 140-review pass without it, and the sentence is the whole
reason this file exists:

    You would then possess 140 valid contemporary reviews but no valid
    stability experiment.

A second pass measures movement only if which row it is compared to, and what
counts as agreement, are fixed **before** anything is spent. Everything below
is about that: the manifest cannot be rewritten, cases with no baseline stay
out of the stability denominator, the order is not alphabetical, and a
comparison with no manifest refuses rather than inventing a rule.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

TOOLS = Path(__file__).resolve().parents[1] / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import round as roundtool  # noqa: E402


@pytest.fixture()
def frozen(tmp_path, monkeypatch):
    """A round of four cases, two of which have run before."""
    monkeypatch.setattr(roundtool, "ROOT", tmp_path)
    monkeypatch.setattr(roundtool, "scope_cases",
                        lambda scope: ["a-one", "b-two", "c-three", "d-four"])
    monkeypatch.setattr(roundtool, "baselines",
                        lambda: {"a-one": {"pair_success": True},
                                 "b-two": {"pair_success": False}})
    monkeypatch.setattr(roundtool, "environment",
                        lambda: {"system_prompt": "aaaa", "adjudications": "bbbb"})
    monkeypatch.setattr(roundtool, "case_digest", lambda d: "digest")
    monkeypatch.setattr(roundtool, "legacy_case_digest", lambda d: "legacy")
    return tmp_path


def results_for(root, number, **verdicts):
    directory = root / "measurements" / "round-{}".format(number)
    directory.mkdir(parents=True, exist_ok=True)
    for case_id, passed in verdicts.items():
        (directory / (case_id + ".json")).write_text(
            json.dumps([{"case_id": case_id, "pair_success": passed}]),
            encoding="utf-8")


class TestAFrozenRoundStaysFrozen:
    def test_it_writes_the_manifest(self, frozen):
        assert roundtool.freeze(1, "approved", dry_run=False) == 0
        assert roundtool.manifest_path(1).is_file()

    def test_it_refuses_to_overwrite(self, frozen, capsys):
        roundtool.freeze(1, "approved", dry_run=False)
        capsys.readouterr()
        assert roundtool.freeze(1, "approved", dry_run=False) == 1
        assert "not rewritten" in capsys.readouterr().out

    def test_a_dry_run_writes_nothing(self, frozen):
        assert roundtool.freeze(1, "approved", dry_run=True) == 0
        assert not roundtool.manifest_path(1).exists()

    def test_a_dry_run_over_an_existing_round_still_reports(self, frozen):
        roundtool.freeze(1, "approved", dry_run=False)
        assert roundtool.freeze(1, "approved", dry_run=True) == 0


class TestOnlyComparableCasesCountAsStability:
    def test_a_case_that_never_ran_answers_recall_only(self, frozen):
        body = roundtool.build(1, "approved")
        by_id = {c["case_id"]: c for c in body["cases"]}
        assert by_id["c-three"]["contributes_to"] == ["recall"]
        assert by_id["a-one"]["contributes_to"] == ["stability", "recall"]

    def test_the_denominator_is_the_cases_with_a_baseline(self, frozen):
        counts = roundtool.build(1, "approved")["counts"]
        assert counts["cases"] == 4
        assert counts["reviews"] == 8
        assert counts["with_baseline"] == 2
        assert counts["without_baseline"] == 2

    def test_a_case_with_no_baseline_never_reaches_the_flip_count(self, frozen, capsys):
        """Left implicit, these would join a denominator they cannot be in."""
        roundtool.freeze(1, "approved", dry_run=False)
        results_for(frozen, 1, **{"a-one": True, "c-three": False})
        capsys.readouterr()
        roundtool.compare(1)
        out = capsys.readouterr().out
        assert "1 agreed, 0 flipped" in out
        assert "c-three" not in out


class TestTheOrderIsNotAlphabetical:
    def test_it_is_shuffled(self, frozen):
        order = roundtool.build(1, "approved")["protocol"]["order"]
        assert sorted(order) == ["a-one", "b-two", "c-three", "d-four"]
        assert order != sorted(order), (
            "alphabetical order puts each language in its own window, and "
            "confounds the language with the reset")

    def test_it_is_reproducible_from_the_seed(self, frozen):
        first = roundtool.build(1, "approved")["protocol"]["order"]
        second = roundtool.build(1, "approved")["protocol"]["order"]
        assert first == second

    def test_a_different_round_orders_differently(self, frozen):
        assert (roundtool.build(1, "approved")["protocol"]["order"]
                != roundtool.build(2, "approved")["protocol"]["order"])


class TestComparing:
    def test_a_flip_is_named(self, frozen, capsys):
        roundtool.freeze(1, "approved", dry_run=False)
        results_for(frozen, 1, **{"a-one": False, "b-two": False})
        capsys.readouterr()
        roundtool.compare(1)
        out = capsys.readouterr().out
        assert "1 agreed, 1 flipped" in out
        assert "a-one: True -> False" in out

    def test_a_case_not_yet_run_is_counted_apart_from_agreement(self, frozen, capsys):
        roundtool.freeze(1, "approved", dry_run=False)
        results_for(frozen, 1, **{"a-one": True})
        capsys.readouterr()
        roundtool.compare(1)
        assert "1 not yet run" in capsys.readouterr().out

    def test_the_agreement_line_refuses_to_claim_stability(self, frozen, capsys):
        roundtool.freeze(1, "approved", dry_run=False)
        results_for(frozen, 1, **{"a-one": True, "b-two": False})
        capsys.readouterr()
        roundtool.compare(1)
        assert "cannot establish stability" in capsys.readouterr().out

    def test_drift_since_freezing_is_announced(self, frozen, capsys, monkeypatch):
        """A ruling added between the passes rescores a verdict without
        rerunning anything, and the reader must not have to notice."""
        roundtool.freeze(1, "approved", dry_run=False)
        monkeypatch.setattr(roundtool, "environment",
                            lambda: {"system_prompt": "aaaa",
                                     "adjudications": "CHANGED"})
        results_for(frozen, 1, **{"a-one": True})
        capsys.readouterr()
        roundtool.compare(1)
        out = capsys.readouterr().out
        assert "adjudications" in out
        assert "not a stability measurement" in out

    def test_no_manifest_refuses_rather_than_inventing_a_rule(self, frozen, capsys):
        assert roundtool.compare(9) == 2
        assert "none may be invented now" in capsys.readouterr().out

    def test_an_incomplete_row_is_not_a_verdict(self, frozen, capsys):
        roundtool.freeze(1, "approved", dry_run=False)
        directory = frozen / "measurements" / "round-1"
        (directory / "a-one.json").write_text(
            json.dumps([{"case_id": "a-one", "pair_success": False,
                         "incomplete": True}]), encoding="utf-8")
        capsys.readouterr()
        roundtool.compare(1)
        assert "0 agreed, 0 flipped, 2 not yet run" in capsys.readouterr().out

def test_the_sentinel_scope_takes_the_suite_from_its_own_file():
    """One definition of the suite, not two.

    Naming the cases in `round.py` as well would give the sentinel two
    definitions that agree until they do not, and the one a paid run used would
    be whichever this function said rather than the one the rule produced.
    """
    import sys
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
    import round as round_tool
    from sentinel import read_cases

    root = Path(__file__).resolve().parents[1]
    frozen = read_cases(root / "suites" / "sentinel.yml")

    assert round_tool.scope_cases("sentinel") == sorted(frozen)


def test_a_sentinel_case_the_queue_will_not_run_stops_the_freeze(monkeypatch):
    """A suite that quietly shrinks between the freeze and the run is the
    sample changing after the question was set. Refused, not trimmed."""
    import sys
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
    import round as round_tool

    monkeypatch.setattr(round_tool.run_queue, "cases", lambda sweep: ["only-one"])

    with pytest.raises(SystemExit) as raised:
        round_tool.scope_cases("sentinel")

    assert "will not run" in str(raised.value)
