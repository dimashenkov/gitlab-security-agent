"""`tools/stability.py` decides whether the gate agrees with itself, untested.

It is the instrument the next paid window would be spent on, and nothing checked
what it does with the rows it is handed. Everything below tests `report`, which
is a pure function over already-collected rows — no review is run and no window
is spent to find out whether the arithmetic is right.

Two of these are regressions for defects the tool's own comments record: a
filename containing `|` shifted every field and made two identical runs read as
disagreeing, and comparing anchors rather than (category, file) made a stable
gate look unstable when two runs quoted different lines of one construct.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

TOOLS = Path(__file__).resolve().parents[1] / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import stability  # noqa: E402


def run_row(index, *, exit_code=1, blocking=(("injection", "app/handler.py", "0"),),
            severity="high", blocking_target=True):
    return {
        "run": index,
        "exit_code": exit_code,
        "blocked": exit_code == 1,
        "blocking": [list(b) for b in blocking],
        "target": {"severity": severity, "confidence": "high",
                   "verdict": "confirmed", "blocking": blocking_target},
        "reported": len(blocking),
        "cost": 0.5,
        "seconds": 30.0,
    }


def failed_row(index, error="review failed"):
    return {"run": index, "error": error}


class TestItCannotConcludeWithoutTwoRuns:
    def test_no_completed_runs_is_two_not_zero(self, capsys):
        """Nothing to compare is not agreement.

        Exit 0 here would say "the gate agreed with itself" on the strength of
        no observations at all — the confusion between "checked" and "could not
        check" this project is built to avoid.
        """
        assert stability.report([failed_row(0), failed_row(1)], "c", "unsafe") == 2
        assert "nothing to compare" in capsys.readouterr().out.lower()

    def test_one_completed_run_is_two(self, capsys):
        rows = [run_row(0), failed_row(1)]
        assert stability.report(rows, "c", "unsafe") == 2
        assert "nothing to compare" in capsys.readouterr().out.lower()


class TestAgreementAndDisagreement:
    def test_identical_runs_agree(self, capsys):
        rows = [run_row(0), run_row(1), run_row(2)]
        assert stability.report(rows, "c", "unsafe") == 0
        assert "Every run agreed" in capsys.readouterr().out

    def test_a_different_gate_outcome_is_a_disagreement(self, capsys):
        rows = [run_row(0, exit_code=1), run_row(1, exit_code=0, blocking=())]
        assert stability.report(rows, "c", "unsafe") == 1
        assert "disagreed with itself" in capsys.readouterr().out

    def test_one_disagreement_among_many_still_fails(self, capsys):
        rows = [run_row(0), run_row(1), run_row(2),
                run_row(3, exit_code=0, blocking=())]
        assert stability.report(rows, "c", "unsafe") == 1

    def test_failed_runs_are_excluded_but_counted(self, capsys):
        rows = [run_row(0), run_row(1), failed_row(2, "timed out")]
        assert stability.report(rows, "c", "unsafe") == 0
        out = capsys.readouterr().out
        assert "2 completed run(s)" in out
        assert "1 run(s) failed" in out
        assert "timed out" in out


class TestTwoWaysAStableGateUsedToLookUnstable:
    def test_a_pipe_in_a_filename_is_not_a_disagreement(self, capsys):
        """The field-shifting bug, as a property rather than a parser test.

        `blocking` was once a `|`-joined string, so a filename containing `|`
        moved every field along and two identical runs compared unequal — the
        stability tool reporting instability it had introduced itself.
        """
        weird = ("injection", "app/a|b.py", "0")
        rows = [run_row(0, blocking=(weird,)), run_row(1, blocking=(weird,))]
        assert stability.report(rows, "c", "unsafe") == 0

    def test_different_anchors_in_one_construct_are_not_a_disagreement(self):
        """Compared as (category, file), deliberately coarser than the anchor."""
        rows = [run_row(0, blocking=(("injection", "app/handler.py", "0"),)),
                run_row(1, blocking=(("injection", "app/handler.py", "7"),))]
        assert stability.report(rows, "c", "unsafe") == 0

    def test_a_different_file_is_a_disagreement(self):
        rows = [run_row(0, blocking=(("injection", "app/handler.py", "0"),)),
                run_row(1, blocking=(("injection", "app/other.py", "0"),))]
        assert stability.report(rows, "c", "unsafe") == 1


class TestTheBoundIsStatedAndCorrect:
    """Zero disagreements is not evidence of stability, and the tool says so."""

    @pytest.mark.parametrize("runs,expected", [(3, 63), (6, 39)])
    def test_the_upper_bound_matches_the_documented_numbers(self, capsys, runs, expected):
        stability.report([run_row(i) for i in range(runs)], "c", "unsafe")
        out = capsys.readouterr().out
        assert "{:.0f}%".format(expected) in out
        assert "cannot show stability" in out

    def test_more_runs_give_a_tighter_bound(self, capsys):
        bounds = []
        for runs in (3, 10):
            stability.report([run_row(i) for i in range(runs)], "c", "unsafe")
            line = [l for l in capsys.readouterr().out.splitlines()
                    if "upper bound" in l][0]
            bounds.append(line)
        assert bounds[0] != bounds[1]


class TestThePairCountCarriesItsCaveat:
    def test_agreement_is_reported_as_overlapping_pairs(self, capsys):
        """Three runs give three pairs, and three pairs are not three trials.

        Quoting "3 of 3 agreed" without this is how a sample of three
        observations gets read as three independent ones.
        """
        stability.report([run_row(i) for i in range(3)], "c", "unsafe")
        out = capsys.readouterr().out
        assert "3 of 3 run pair(s)" in out
        assert "overlapping, not independent" in out
        assert "3 runs give 3 pairs" in out
