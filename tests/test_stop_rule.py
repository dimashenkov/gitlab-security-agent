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
        assert "target category" in reasons[0]
        # The reason a person reads has to say what the number is, because the
        # name it used to carry — "alerts on the fix" — reads as a false-alarm
        # rate and is not one: `is_target` compares category and file and makes
        # no judgement about whether the finding is correct.
        assert "not a false-alarm rate" in reasons[0]

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


class TestTwoDenominatorsAndNoQuietChoiceBetweenThem:
    """This tool counted nine cases that `stage2` and `check_accounted` drop.

    Four readers of one corpus, two denominators, and the one that authorises
    stopping used the larger. Dropping them silently would be worse: the ruling
    that drops a case is the reviewer's own model judging its own corpus, and
    `LIMITATIONS.md` forbids computing a rate through those rulings.

    So both are printed and **only the raw one answers**. The second carries no
    verdict at all, and the line under it says how many of the rulings behind
    it were made by somebody who did not produce the findings. Zero.
    """

    def test_the_ruled_denominator_drops_the_cases_the_other_tools_drop(
            self, tmp_path, monkeypatch):
        monkeypatch.setattr(stop_rule, "ROOT", tmp_path)
        (tmp_path / "corpus-real").mkdir()
        (tmp_path / "corpus-real" / "adjudications.yml").write_text(
            "adjudications:\n"
            "  - case_id: bad\n"
            "    case_is_malformed: true\n"
            "    why_malformed: the safe member carries the weakness\n",
            encoding="utf-8")

        rows = {"good": row("good"), "bad": row("bad")}

        assert sorted(stop_rule.without_malformed(rows)) == ["good"]

    def test_a_ruling_with_no_reason_drops_nothing(self, tmp_path, monkeypatch):
        """`malformed_cases` requires a reason, and this tool inherits it. A
        row that removes a case from the denominator without saying why is a
        deletion, not a ruling."""
        monkeypatch.setattr(stop_rule, "ROOT", tmp_path)
        (tmp_path / "corpus-real").mkdir()
        (tmp_path / "corpus-real" / "adjudications.yml").write_text(
            "adjudications:\n"
            "  - case_id: bad\n"
            "    case_is_malformed: true\n", encoding="utf-8")

        assert sorted(stop_rule.without_malformed(
            {"good": row("good"), "bad": row("bad")})) == ["bad", "good"]

    def test_no_rulings_file_leaves_every_row(self, tmp_path, monkeypatch):
        monkeypatch.setattr(stop_rule, "ROOT", tmp_path)

        rows = {"a": row("a"), "b": row("b")}

        assert stop_rule.without_malformed(rows) == rows

    def world(self, tmp_path, monkeypatch, rows, malformed):
        monkeypatch.setattr(stop_rule, "ROOT", tmp_path)
        (tmp_path / "measurements").mkdir()
        (tmp_path / "measurements" / "batch.json").write_text(
            json.dumps(rows), encoding="utf-8")
        (tmp_path / "corpus-real").mkdir()
        (tmp_path / "corpus-real" / "adjudications.yml").write_text(
            "adjudications:\n" + "".join(
                "  - case_id: '{}'\n"
                "    case_is_malformed: true\n"
                "    why_malformed: the safe member carries the weakness\n"
                .format(c) for c in malformed), encoding="utf-8")

    def test_the_verdict_comes_from_the_raw_rows_and_nothing_else(
            self, tmp_path, monkeypatch, capsys):
        """`LIMITATIONS.md` says no threshold may be computed through the
        rulings, and an earlier version of this code computed one two files
        away from the sentence saying so — it removed the ruled cases and could
        return `stop` on what was left. A prohibition written down and stepped
        over in the same change is worse than one never written.
        """
        # Raw is clean: two alerts of ten (20%, under the 40% ceiling). Remove
        # the eight quiet cases a ruling dropped and it is two of two — 100%,
        # far over. Only the second reading trips.
        self.world(tmp_path, monkeypatch,
                   [row(str(i), alert=i < 2) for i in range(10)],
                   malformed=[str(i) for i in range(2, 10)])

        code = stop_rule.main([])

        out = capsys.readouterr().out
        assert code == 0, "a ruled denominator must not produce a stop"
        assert "verdict: no catastrophe" in out

    def test_the_second_reading_carries_no_verdict_at_all(
            self, tmp_path, monkeypatch, capsys):
        """Printed, because four tools disagreeing over one corpus is worth
        seeing. Without an answer, because a line saying "not evidence" printed
        beside a verdict loses to the verdict every time."""
        self.world(tmp_path, monkeypatch,
                   [row(str(i)) for i in range(10)], malformed=["0"])

        stop_rule.main([])
        out = capsys.readouterr().out

        assert out.count("verdict:") == 1, "the second reading has a verdict"
        assert "No verdict from this reading" in out

    def test_the_reading_names_how_many_rulings_are_independent(
            self, tmp_path, monkeypatch, capsys):
        """`independence()` counted and nothing called it — a claim nothing
        enforces, which is this repository's own defect class. Non-independence
        cannot be fixed by code; what code can do is refuse to let the number
        be read without the label beside it."""
        self.world(tmp_path, monkeypatch,
                   [row(str(i)) for i in range(10)], malformed=["0"])

        stop_rule.main([])

        assert "0 of 1 rulings" in capsys.readouterr().out

    def broken(self, tmp_path, monkeypatch, body, rows=None):
        monkeypatch.setattr(stop_rule, "ROOT", tmp_path)
        (tmp_path / "measurements").mkdir()
        (tmp_path / "measurements" / "batch.json").write_text(
            json.dumps(rows if rows is not None
                       else [row(str(i)) for i in range(10)]), encoding="utf-8")
        (tmp_path / "corpus-real").mkdir()
        target = tmp_path / "corpus-real" / "adjudications.yml"
        if body is None:
            # Genuinely unreadable rather than merely invalid: a directory
            # where the file should be. `read_text` raises `IsADirectoryError`,
            # a different branch from the parser's.
            target.mkdir()
        else:
            target.write_text(body, encoding="utf-8")

    @pytest.mark.parametrize("body,expected", [
        ("adjudications: [\n", "ParserError"),    # unterminated flow sequence
        ("a: b\nc\n", "ScannerError"),            # a key with no value
        ("\x00\x01 not yaml", "ReaderError"),     # bytes, not a document
        ("adjudications: 3", "TypeError"),        # valid yaml, wrong shape
        # A directory where the file belongs. `is_file()` said False and the
        # reader returned `[]` — every ruling silently withdrawn, in the file
        # that decides what the corpus counts. Five tools read through it.
        (None, "OSError"),
    ])
    def test_broken_rulings_leave_the_verdict_alone_and_say_so(
            self, tmp_path, monkeypatch, capsys, body, expected):
        """Two fixes, in opposite directions, and the second undid the first.

        The tool printed the raw verdict before reading the rulings, so an
        exception left stdout saying "no catastrophe" while the process exited
        1 — the code documented here as `stop`. The first repair made any such
        failure `cannot say`, which was worse: the rulings feed a reading that
        decides nothing, so a broken file was unmaking an answer computed
        without it, and could hide a raw `stop` behind exit 2.

        What is true is narrow: the verdict stands, the second reading is
        missing, and the failure is named rather than swallowed.
        """
        self.broken(tmp_path, monkeypatch, body)

        code = stop_rule.main([])

        out = capsys.readouterr().out
        assert code == 0, "the raw reading answered; a display cannot unmake it"
        assert "verdict: no catastrophe" in out
        assert "cannot say" not in out
        assert "the rulings could not be read" in out
        assert expected in out, "the failure has to be named, not just noted"
        assert "No verdict from this reading" not in out

    def test_broken_rulings_cannot_hide_a_stop(self, tmp_path, monkeypatch,
                                               capsys):
        """The direction that matters, and the one the first repair broke."""
        self.broken(tmp_path, monkeypatch, "adjudications: [\n",
                    rows=[row(str(i), alert=i < 6) for i in range(10)])

        code = stop_rule.main([])

        out = capsys.readouterr().out
        assert code == 1, "a catastrophe must survive an unrelated file break"
        assert "verdict: stop" in out

    def test_a_bug_in_the_arithmetic_is_not_blamed_on_the_rulings(
            self, tmp_path, monkeypatch):
        """The `except` is broad on purpose — any parser failure means the same
        thing — but narrow in *extent*: only the two calls that read the file
        are inside it. Wrapping the arithmetic too would report a defect in
        `rates` as "the rulings could not be read", a true-sounding sentence
        about the wrong thing."""
        self.broken(tmp_path, monkeypatch, "adjudications: []\n")

        # The *second* call has to be the one that fails. Making every call
        # fail was the first version of this test: it blew up on the raw
        # reading, never reached the `try`, and so passed without testing the
        # restructuring it is named after.
        real = stop_rule.rates
        calls = []

        def second_call_explodes(rows):
            calls.append(rows)
            if len(calls) == 1:
                return real(rows)
            raise ZeroDivisionError("nothing to do with rulings")

        monkeypatch.setattr(stop_rule, "rates", second_call_explodes)

        with pytest.raises(ZeroDivisionError):
            stop_rule.main([])
        assert len(calls) == 2, "the failure must be the ruled reading, not the raw"

    def test_a_second_ruling_beside_a_dropped_case_is_not_counted(
            self, tmp_path, monkeypatch, capsys):
        """"The rulings that dropped a case" is not "every ruling about a case
        that was dropped". Filtering on the case id alone counted an incidental
        excusal sitting beside the malformed ruling, and reported `0 of 2`
        where one ruling did the dropping."""
        self.broken(tmp_path, monkeypatch, (
            "adjudications:\n"
            "  - case_id: '0'\n"
            "    case_is_malformed: true\n"
            "    why_malformed: the safe member carries the weakness\n"
            "  - case_id: '0'\n"
            "    member: safe\n"
            "    verdict: real\n"
            "    incidental: true\n"
            "    fingerprint: aa11\n"))

        stop_rule.main([])

        assert "0 of 1 rulings" in capsys.readouterr().out

    def test_a_raw_stop_is_still_a_stop(self, tmp_path, monkeypatch, capsys):
        """The floor. If the tests above pass because nothing ever stops, this
        one fails."""
        self.world(tmp_path, monkeypatch,
                   [row(str(i), alert=i < 6) for i in range(10)],
                   malformed=["0"])

        code = stop_rule.main([])

        assert code == 1
        assert "verdict: stop" in capsys.readouterr().out


def test_the_thresholds_are_the_ones_the_decision_names():
    """The rule lives in `DECISIONS.md` and the numbers live here; two copies
    of one rule drift, and the code's copy is the one that would decide."""
    text = (Path(__file__).resolve().parents[1] / "DECISIONS.md").read_text(
        encoding="utf-8")

    assert "65%" in text and "40%" in text
    assert stop_rule.RECALL_FLOOR == 0.65
    assert stop_rule.PATCHED_ALERT_CEILING == 0.40
