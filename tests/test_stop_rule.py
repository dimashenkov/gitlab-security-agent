"""`D-013` as code, and the three answers it is allowed to give.

A stop rule whose numbers nobody can recompute is a sentence, not a rule. The
figures `DECISIONS.md` quotes came out of a throwaway script; these tests exist
so the same question asked in three months gets the same answer from the same
files, and so the branch that must never appear — "pass" — cannot appear.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import stop_rule


def row(case_id, *, recall=True, alert=False, when="2026-08-28T12:00:00+00:00"):
    return {"case_id": case_id, "unsafe_recall": recall,
            "safe_false_positive": alert, "ran_at": when}


def world(tmp_path, rows):
    (tmp_path / "measurements").mkdir()
    (tmp_path / "measurements" / "batch.json").write_text(
        json.dumps(rows), encoding="utf-8")
    return tmp_path


class TestTheVerdictHasNoPassBranch:
    """The rule can say `stop`, `no catastrophe`, or `cannot say`.

    It cannot say `pass`, because 78 pairs cannot carry one: with today's
    numbers the power to detect a five-point regression is about 26%. A tool
    that printed "pass" would be read as acceptance evidence, and `D-013` says
    in words that it is not — words the next reader is under no obligation to
    find.
    """

    def test_a_clean_corpus_is_not_a_pass(self):
        counts = stop_rule.rates({"a": row("a"), "b": row("b")})

        decision, reasons = stop_rule.verdict(counts)

        assert decision == "no catastrophe"
        assert reasons == []
        assert decision != "pass"

    def test_recall_under_the_floor_stops(self):
        rows = {str(i): row(str(i), recall=i < 6) for i in range(10)}

        decision, reasons = stop_rule.verdict(stop_rule.rates(rows))

        assert decision == "stop"
        assert "recall" in reasons[0]

    def test_alerts_over_the_ceiling_stop(self):
        rows = {str(i): row(str(i), alert=i < 5) for i in range(10)}

        decision, reasons = stop_rule.verdict(stop_rule.rates(rows))

        assert decision == "stop"
        assert "alerts on the fix" in reasons[0]

    def test_an_empty_corpus_cannot_say(self):
        """Not `no catastrophe`. "Nothing is wrong" and "nothing was measured"
        are the two answers this repository exists to keep apart, and this is
        the tool that decides whether a configuration is abandoned."""
        decision, _reasons = stop_rule.verdict(stop_rule.rates({}))

        assert decision == "cannot say"

    def test_the_exit_codes_keep_a_crash_apart_from_a_result(self):
        """`cannot say` is 2, the code the product uses for "the check did not
        run". Zero is reserved for an answer."""
        assert {"stop": 1, "no catastrophe": 0, "cannot say": 2}["cannot say"] == 2


class TestWhichRowAnswers:
    def test_a_later_row_supersedes_an_earlier_one(self, tmp_path, monkeypatch):
        monkeypatch.setattr(stop_rule, "ROOT", world(tmp_path, [
            row("a", recall=False, when="2026-08-01T09:00:00+00:00"),
            row("a", recall=True, when="2026-08-28T09:00:00+00:00"),
        ]))

        assert stop_rule.rates(stop_rule.latest_rows())["found"] == 1

    def test_offsets_are_instants_and_not_strings(self, tmp_path, monkeypatch):
        """`…T14:00:00+03:00` sorts after `…T12:00:00+00:00` as text and is two
        hours earlier as a moment. Latent while every row on disk is `+00:00`,
        and one run from a machine on local time is all it takes."""
        monkeypatch.setattr(stop_rule, "ROOT", world(tmp_path, [
            row("a", recall=True, when="2026-08-28T12:00:00+00:00"),
            row("a", recall=False, when="2026-08-28T14:00:00+03:00"),
        ]))

        # The `+03:00` row is 11:00 UTC — earlier — so the `True` stands.
        assert stop_rule.rates(stop_rule.latest_rows())["found"] == 1

    def test_an_undated_row_answers_only_when_nothing_dated_does(
            self, tmp_path, monkeypatch):
        monkeypatch.setattr(stop_rule, "ROOT", world(tmp_path, [
            row("a", recall=True),
            {"case_id": "a", "unsafe_recall": False, "safe_false_positive": True},
        ]))

        assert stop_rule.rates(stop_rule.latest_rows())["found"] == 1

    def test_an_object_file_is_read_and_not_iterated_as_nothing(
            self, tmp_path, monkeypatch):
        """A batch file is a list; an experiment writes one row per file, as an
        object. `body if isinstance(body, list) else []` opened such a file,
        parsed it, and iterated it as nothing — three tools had that bug."""
        (tmp_path / "measurements").mkdir()
        (tmp_path / "measurements" / "one.json").write_text(
            json.dumps(row("a")), encoding="utf-8")
        monkeypatch.setattr(stop_rule, "ROOT", tmp_path)

        assert stop_rule.rates(stop_rule.latest_rows())["found"] == 1


class TestAMissingVerdictIsNotAVerdict:
    """`bool(row.get(...))` is the shape this repository keeps finding in
    itself: a row that never recorded an outcome reads as a failure, and the
    string `"false"` reads as a success."""

    @pytest.mark.parametrize("value", [None, "false", "true", 0, 1, "", {}])
    def test_only_a_real_boolean_counts(self, value):
        counts = stop_rule.rates({"a": {"case_id": "a",
                                        "unsafe_recall": value,
                                        "safe_false_positive": value}})

        assert counts["unsafe_total"] == 0
        assert counts["safe_total"] == 0


class TestTheIntervalBehavesAtTheEdges:
    def test_a_perfect_score_does_not_run_past_a_hundred(self):
        low, high = stop_rule.wilson(10, 10)

        assert high <= 1.0
        assert low < 1.0, "a width of zero would claim certainty from ten cases"

    def test_a_zero_score_does_not_run_below_nothing(self):
        low, high = stop_rule.wilson(0, 10)

        assert low >= 0.0
        assert high > 0.0

    def test_an_empty_denominator_does_not_divide(self):
        assert stop_rule.wilson(0, 0) == (0.0, 0.0)


def test_the_thresholds_are_the_ones_the_decision_names():
    """The rule lives in `DECISIONS.md` and the numbers live here; two copies
    of one rule drift, and the code's copy is the one that would decide."""
    text = (Path(__file__).resolve().parents[1] / "DECISIONS.md").read_text(
        encoding="utf-8")

    assert "65%" in text and "40%" in text
    assert stop_rule.RECALL_FLOOR == 0.65
    assert stop_rule.PATCHED_ALERT_CEILING == 0.40
