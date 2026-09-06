"""The one number the prototype was missing, and the rules around it.

`tools/ordinary_noise.py` measures how often the reviewer alarms on a change
with nothing to find. Recall says it finds the weakness in a vulnerable file;
the corpus's other figure, 26%, is the alarm rate on the *patched twin* of a
vulnerable file — the hardest possible negative, and not a false-alarm rate on
ordinary work.

Most of what is tested here is not arithmetic. It is the set of refusals that
keep the number from being quietly better than the evidence: a denominator
chosen after the outcome, an unfinished review counted as a quiet one, a
finding count nobody could read folded into "no findings", and a case with no
verdict skipped rather than named.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import ordinary_noise as noise  # noqa: E402
import spend_gate  # noqa: E402


def seal(tmp_path, *cases):
    path = tmp_path / "seal.json"
    path.write_text(json.dumps({"selected": [
        {"case_id": c, "repo": "acme/" + c, "commit": "0" * 40,
         "language": "python", "stratum": "ordinary", "stratum_rules": []}
        for c in cases]}), encoding="utf-8")
    return path


def adjudication(tmp_path, **verdicts):
    path = tmp_path / "adj.json"
    path.write_text(json.dumps({
        "vendor": "xai",
        "cases": {c: {"verdict": v, "request_id": "r-" + c}
                  for c, v in verdicts.items()}}), encoding="utf-8")
    return path


def point(monkeypatch, seal_path, adj_path):
    monkeypatch.setattr(noise, "SEAL", seal_path)
    monkeypatch.setattr(noise, "ADJUDICATION", adj_path)


def row(case_id="c1", *, complete=True, blocked=False, findings=0, **over):
    out = {"case_id": case_id, "complete": complete, "blocked": blocked,
           "findings": findings}
    out.update(over)
    return out


def scored(body):
    """`score` with the denominator the caller would have read from the seal.

    The scorer takes the admitted ids rather than fetching them, so a record
    cannot define its own denominator. Tests supply what a correct caller
    would: the ids the record says it is about.
    """
    return noise.score(body, body.get("admitted_case_ids"))


def record(*rows, excluded=()):
    """A finished run over exactly these rows.

    `ran` and `admitted` match the row count because the scorer reconciles
    them: a record whose counts do not agree with its rows is `PARTIAL`, and a
    helper that left them out would make every case here partial and hide
    which ones are about that.
    """
    return {"estimand": "the observed reviewer alarm rate on the sample",
            "not_a": ["a false-alarm rate"],
            "excluded": [{"case_id": c, "verdict": "not_ordinary"}
                         for c in excluded],
            "ran": len(rows), "admitted": len(rows),
            "admitted_case_ids": sorted(r["case_id"] for r in rows),
            "rows": list(rows)}


class TestTheDenominatorIsChosenInAdvance:
    """D-014 excludes the three `not_ordinary` cases, and it was written
    before any review ran, because a rule chosen after the outcome is not a
    rule."""

    def test_only_ordinary_cases_are_admitted(self, tmp_path, monkeypatch):
        point(monkeypatch, seal(tmp_path, "a", "b", "c"),
              adjudication(tmp_path, a="ordinary", b="not_ordinary",
                           c="ordinary"))
        monkeypatch.setattr(noise, "SPLIT", (2, 1))
        admitted, excluded = noise.sample()
        assert [e["case_id"] for e in admitted] == ["a", "c"]
        assert excluded == [("b", "not_ordinary")]

    def test_a_verdict_this_rule_does_not_admit_is_excluded_not_counted(
            self, tmp_path, monkeypatch):
        """`unclear` is a real answer and it is not `ordinary`. It belongs
        outside the denominator, named, rather than in it because it was not
        explicitly `not_ordinary`."""
        point(monkeypatch, seal(tmp_path, "a", "b"),
              adjudication(tmp_path, a="ordinary", b="unclear"))
        monkeypatch.setattr(noise, "SPLIT", (1, 1))
        admitted, excluded = noise.sample()
        assert [e["case_id"] for e in admitted] == ["a"]
        assert excluded == [("b", "unclear")]

    def test_a_sealed_case_with_no_verdict_refuses(self, tmp_path, monkeypatch):
        """Skipping it would let the denominator be chosen now, after the
        sample is known — the thing D-014 exists to prevent."""
        point(monkeypatch, seal(tmp_path, "a", "b"),
              adjudication(tmp_path, a="ordinary"))
        with pytest.raises(noise.Refused, match="carry no verdict"):
            noise.sample()

    def test_a_verdict_that_is_not_a_record_refuses(self, tmp_path, monkeypatch):
        adj = tmp_path / "adj.json"
        adj.write_text(json.dumps({"cases": {"a": "ordinary"}}),
                       encoding="utf-8")
        point(monkeypatch, seal(tmp_path, "a"), adj)
        with pytest.raises(noise.Refused, match="holds str for this case"):
            noise.sample()

    def test_a_seal_with_no_selection_refuses(self, tmp_path, monkeypatch):
        path = tmp_path / "seal.json"
        path.write_text(json.dumps({"selected": []}), encoding="utf-8")
        point(monkeypatch, path, adjudication(tmp_path))
        with pytest.raises(noise.Refused, match="no `selected` list"):
            noise.sample()

    def test_an_unreadable_input_refuses_rather_than_returning_nothing(
            self, tmp_path, monkeypatch):
        bad = tmp_path / "bad.json"
        bad.write_text("{not json", encoding="utf-8")
        point(monkeypatch, bad, adjudication(tmp_path, a="ordinary"))
        with pytest.raises(noise.Refused):
            noise.sample()


class TestIncompleteIsNotQuiet:
    """An unfinished review found nothing because it stopped, not because
    there was nothing there. Three of four failures in an early run had exit
    code 2 and were scored as "found nothing"."""

    def test_it_is_in_neither_denominator(self, capsys):
        code = scored(record(
            row("a"), row("b", blocked=True), row("c", complete=False)))
        out = capsys.readouterr().out
        # A range over all three, not a point over the two that finished:
        # the missing one is counted first as quiet and then as an alarm.
        assert "1–2 of 3" in out
        assert "A range, not a point" in out
        assert "1 review(s) did not complete" in out
        assert code == 2

    def test_a_missing_complete_flag_is_not_a_finished_review(self, capsys):
        broken = {"case_id": "a", "blocked": False, "findings": 0}
        scored(record(row("b"), broken))
        assert "did not complete" in capsys.readouterr().out

    def test_nothing_completing_is_not_an_alarm_rate_of_zero(self, capsys):
        code = scored(record(row("a", complete=False)))
        out = capsys.readouterr().out
        assert "not an alarm rate of zero" in out
        assert code == 2


class TestTheTwoAlarmsAreNeverMerged:
    def test_blocking_and_reporting_are_counted_apart(self, capsys):
        scored(record(
            row("a", blocked=True, findings=3),
            row("b", blocked=False, findings=2),
            row("c", blocked=False, findings=0),
            row("d", blocked=False, findings=0)))
        out = capsys.readouterr().out
        assert "blocked the change                1 of 4" in out
        assert "reported at least one finding     2 of 4" in out
        assert "never added" in out

    def test_a_blocked_flag_that_is_missing_leaves_the_denominator(
            self, capsys):
        """Codex, 2026-09-06: it was coerced to `False` and then counted as a
        clean non-block, which is the optimistic direction and narrowed the
        interval as well. A row is in a figure only when its own field could
        be read."""
        code = scored(record(
            {"case_id": "a", "complete": True, "findings": 0},
            row("b", blocked=True)))
        out = capsys.readouterr().out
        assert "blocked the change                1–2 of 2" in out
        assert "no readable `blocked` verdict" in out
        assert code == 2

    def test_no_readable_blocked_verdict_at_all_says_so(self, capsys):
        scored(record({"case_id": "a", "complete": True, "findings": 0}))
        assert "no row recorded a readable value" in capsys.readouterr().out

    def test_an_unreadable_finding_count_is_not_a_quiet_review(self, capsys):
        """`None` findings is a review whose list could not be read, and
        folding it into "no findings" makes a noisy tool look quiet."""
        code = scored(record(
            row("a", findings=None), row("b", findings=0)))
        out = capsys.readouterr().out
        # `0 of 1`, not `0 of 2`. Codex, 2026-09-06: both figures divided by
        # every completed row, so the unreadable one counted as a review that
        # reported nothing — better than the truth, and a narrower interval.
        assert "reported at least one finding     0–1 of 2" in out
        assert "no readable finding count" in out
        assert code == 2

    @pytest.mark.parametrize("findings", [False, True, -1, "2", 1.5, None])
    def test_a_finding_count_that_is_not_a_count_leaves_the_denominator(
            self, capsys, findings):
        """Codex, 2026-09-06: `isinstance(value, int)` accepts booleans,
        because `bool` subclasses `int` — so `"findings": false` entered the
        reporting denominator as a review that found nothing. A negative count
        is not one either."""
        code = scored(record(
            row("a", findings=findings), row("b", findings=3)))
        out = capsys.readouterr().out
        assert "reported at least one finding     1–2 of 2" in out
        assert "no readable finding count" in out
        assert code == 2

    def test_a_genuine_zero_is_still_a_quiet_review(self, capsys):
        """The other half, so the rule above cannot pass by refusing every
        count."""
        code = scored(record(row("a", findings=0), row("b", findings=3)))
        out = capsys.readouterr().out
        assert "reported at least one finding     1 of 2" in out
        assert code == 0

    def test_a_clean_run_over_complete_rows_exits_zero(self, capsys):
        code = scored(record(row("a"), row("b", blocked=True)))
        assert code == 0
        assert "did not complete" not in capsys.readouterr().out


class TestAPartialRunIsNotTheMeasurement:
    """Codex, 2026-09-06: `--limit` produced an artifact carrying the full
    estimand and exiting 0, so a favourable prefix of one case could be
    mistaken for the answer — and a favourable prefix is the easiest to stop
    at."""

    def test_it_says_partial_and_exits_two(self, capsys):
        body = record(row("a"))
        body["ran"], body["admitted"] = 1, 27
        code = scored(body)
        out = capsys.readouterr().out
        assert "the record says 1 of 27 admitted case(s)" in out
        assert "a prefix of the sample is a different sample" in out.replace(
            "\n  ", " ")
        assert code == 2

    def test_a_whole_run_carries_no_such_warning(self, capsys):
        body = record(row("a"), row("b"))
        body["ran"], body["admitted"] = 2, 2
        code = scored(body)
        assert "PARTIAL" not in capsys.readouterr().out
        assert code == 0

    def test_repeating_one_quiet_case_is_not_a_whole_run(self, capsys):
        """Codex, 2026-09-06: the count reconciled and the identities did not,
        so twenty-seven copies of one quiet case passed as a whole run and
        printed an optimistically low rate."""
        body = record(row("a"), row("b", blocked=True))
        body["rows"] = [row("a"), row("a")]
        code = scored(body)
        out = capsys.readouterr().out
        assert "PARTIAL" in out
        assert "a repeated" in out
        assert "b missing" in out
        assert code == 2

    def test_a_case_from_outside_the_sample_is_not_a_substitute(self, capsys):
        body = record(row("a"), row("b"))
        body["rows"] = [row("a"), row("zz")]
        code = scored(body)
        out = capsys.readouterr().out
        assert "zz not in the sample" in out
        assert "b missing" in out
        assert code == 2

    def test_a_denominator_that_could_not_be_established_is_partial(
            self, capsys):
        """The scorer takes the admitted ids rather than fetching them, so a
        caller that could not read the seal hands it `None` — and an
        unverifiable denominator is not a verified one."""
        code = noise.score(record(row("a")), None)
        out = capsys.readouterr().out
        assert "the sealed sample could not be read" in out
        assert code == 2

    def test_no_figure_is_printed_at_all_when_the_sample_is_short(
            self, capsys):
        """Codex, 2026-09-06, the last of six rounds on this function: the
        rates were printed first and the PARTIAL line came after, so a missing
        noisy case produced a visibly better "0 of 26" and only then the
        warning. A number somebody has read is not unread because a line
        beneath it says not to trust it."""
        body = record(row("a", findings=0))
        code = noise.score(body, ["a", "b-the-noisy-one"])
        out = capsys.readouterr().out
        assert "No figure is printed" in out
        assert "0 of 1" not in out
        assert "95% CI" not in out
        assert "blocked the change" not in out
        assert code == 2

    def test_the_figure_is_printed_when_the_sample_is_whole(self, capsys):
        """The other half, so the suppression cannot pass by printing
        nothing ever."""
        body = record(row("a", findings=0), row("b", findings=2))
        code = noise.score(body, ["a", "b"])
        out = capsys.readouterr().out
        assert "No figure is printed" not in out
        assert "95% CI" in out
        assert code == 0

    def test_the_record_cannot_define_its_own_denominator(self, capsys):
        """Codex, 2026-09-06: taking the ids off the record let a file swap an
        admitted case for a quieter one outside the sample and update its own
        list to match, so every check agreed with every other."""
        body = record(row("outsider"))
        # The record says it is about `outsider`; the seal says otherwise.
        code = noise.score(body, ["ord-real-case"])
        out = capsys.readouterr().out
        assert "outsider not in the sample" in out
        assert "ord-real-case missing" in out
        assert code == 2

    def test_the_run_records_the_admitted_ids(self):
        """Against the committed sample, so the artifact carries what the
        scorer checks rather than the scorer trusting a count."""
        admitted, _ = noise.sample()
        assert len({e["case_id"] for e in admitted}) == noise.SPLIT[0]

    @pytest.mark.parametrize("ran,admitted", [
        (27, 27),      # the counts claim a whole run and one row is present
        (None, None),  # a record that cannot say how much it covered
        (2, None),
        (True, True),
    ])
    def test_the_counts_are_reconciled_against_the_rows(
            self, capsys, ran, admitted):
        """Codex, 2026-09-06: an artifact declaring `ran=27, admitted=27` while
        holding one row printed `0 of 1` under the full estimand and exited 0.
        The counts are metadata about the run; the rows are the run."""
        body = record(row("a"))
        body["ran"], body["admitted"] = ran, admitted
        code = scored(body)
        out = capsys.readouterr().out
        assert "PARTIAL" in out
        assert "holds 1 row(s)" in out
        assert code == 2


class TestTheSampleIsTheOneTheDecisionGoverns:
    def test_a_verdict_outside_the_enum_refuses(self, tmp_path, monkeypatch):
        """D-014 authorises one enum. A value outside it shrinking the
        denominator is the open-ended rule the decision exists to prevent."""
        point(monkeypatch, seal(tmp_path, "a", "b"),
              adjudication(tmp_path, a="ordinary", b="probably fine"))
        with pytest.raises(noise.Refused, match="outside"):
            noise.sample()

    def test_a_null_verdict_is_no_verdict(self, tmp_path, monkeypatch):
        """It was recorded as `None` and then silently excluded — the key was
        there, so the absent-verdict check never saw it."""
        point(monkeypatch, seal(tmp_path, "a", "b"),
              adjudication(tmp_path, a="ordinary", b=None))
        with pytest.raises(noise.Refused, match="carry no verdict"):
            noise.sample()

    def test_a_sample_of_the_wrong_shape_refuses(self, tmp_path, monkeypatch):
        point(monkeypatch, seal(tmp_path, "a", "b"),
              adjudication(tmp_path, a="ordinary", b="not_ordinary"))
        with pytest.raises(noise.Refused, match="changed shape"):
            noise.sample()

    def test_the_real_sample_is_the_one_it_governs(self):
        """Against the committed artifacts, not a fixture."""
        admitted, excluded = noise.sample()
        assert (len(admitted), len(excluded)) == noise.SPLIT
        assert all(e["verdict"] == "ordinary" for e in admitted)


class TestTheNumberCarriesItsName:
    def test_the_estimand_is_printed(self, capsys):
        scored(record(row("a")))
        assert "observed reviewer alarm rate" in capsys.readouterr().out

    def test_what_it_is_not_is_printed(self, capsys):
        scored(record(row("a")))
        assert "Not a false-alarm rate" in capsys.readouterr().out

    def test_the_excluded_cases_are_named(self, capsys):
        scored(record(row("a"), excluded=("x", "y")))
        out = capsys.readouterr().out
        assert "2 case(s) excluded by D-014" in out
        assert "x, y" in out

    def test_a_proportion_over_27_carries_an_interval(self, capsys):
        scored(record(*[row(str(i)) for i in range(27)]))
        assert "95% CI" in capsys.readouterr().out

    def test_the_interval_is_wide_on_a_small_sample(self):
        low, high = noise.wilson(0, 27)
        assert low < 1e-9
        assert high > 0.12, "zero of 27 does not establish a rate near zero"

    def test_the_interval_brackets_the_point(self):
        low, high = noise.wilson(7, 27)
        assert low < 7 / 27 < high


class TestTheBrokerAuthorisesIt:
    """The class is authorised by a decision rather than by a step of D-013's
    ordering, because the owner narrowed the goal on 2026-09-06 and D-013
    orders nothing about this measurement."""

    def test_the_class_is_declared(self):
        assert noise.SPEND_CLASS in spend_gate.SPEND_CLASSES
        assert spend_gate.SPEND_CLASSES[noise.SPEND_CLASS] == {
            "decision": "D-014"}

    def test_an_active_decision_permits(self):
        decision = spend_gate.authorise(noise.SPEND_CLASS)
        assert decision.state == spend_gate.PERMITTED
        assert "D-014" in decision.why

    def test_a_decision_that_is_not_active_refuses(self, monkeypatch):
        monkeypatch.setattr(spend_gate, "_decision_state",
                            lambda name, cls=None: ("superseded", cls))
        decision = spend_gate.authorise(noise.SPEND_CLASS)
        assert decision.state == spend_gate.REFUSED
        assert "does not authorise" in decision.why

    def test_a_decision_that_is_not_there_is_undetermined(self, monkeypatch):
        monkeypatch.setattr(spend_gate, "_decision_state",
                            lambda name, cls=None: (None, None))
        decision = spend_gate.authorise(noise.SPEND_CLASS)
        assert decision.state == spend_gate.UNDETERMINED
        assert "holds no such entry" in decision.why

    def test_a_decisions_file_that_cannot_be_read_is_undetermined(
            self, monkeypatch):
        def explode(name, cls=None):
            raise OSError("gone")

        monkeypatch.setattr(spend_gate, "_decision_state", explode)
        decision = spend_gate.authorise(noise.SPEND_CLASS)
        assert decision.state == spend_gate.UNDETERMINED
        assert "an unreadable authorisation is not one" in decision.why

    def test_a_decision_that_does_not_name_the_class_refuses(
            self, monkeypatch):
        """Codex, 2026-09-06: inferring "governs this class" from an active
        state meant any unrelated active decision, placed in the mapping,
        permitted spending — the mapping was the only thing binding them, and
        the mapping is written in the broker rather than in the decision."""
        monkeypatch.setattr(
            spend_gate, "_decision_state",
            lambda name, cls=None: ("active", "something_else"))
        decision = spend_gate.authorise(noise.SPEND_CLASS)
        assert decision.state == spend_gate.REFUSED
        assert "a decision about something else" in decision.why

    def test_a_decision_naming_no_class_refuses(self, monkeypatch):
        monkeypatch.setattr(spend_gate, "_decision_state",
                            lambda name, cls=None: ("active", None))
        assert spend_gate.authorise(
            noise.SPEND_CLASS).state == spend_gate.REFUSED

    def test_the_real_decision_names_the_real_class(self):
        """Both ends name each other, against the committed file."""
        state, authorises = spend_gate._decision_state("D-014")
        assert state == "active"
        assert authorises == noise.SPEND_CLASS

    def test_a_decisions_file_that_does_not_check_out_authorises_nothing(
            self, monkeypatch):
        """A malformed decision that keeps `State: active` still authorised
        spending: the field survives edits the rest of the entry does not."""
        import check_decisions

        monkeypatch.setattr(check_decisions, "check",
                            lambda text, run_tests: ["D-014: no **Reason**"])
        with pytest.raises(RuntimeError, match="has not authorised anything"):
            spend_gate._decision_state("D-014")

    def test_two_entries_with_one_name_authorise_nothing(self, monkeypatch):
        import check_decisions

        class Fake:
            id = "D-014"
            fields = {"State": "active", "Authorises": "ordinary_noise"}

        monkeypatch.setattr(check_decisions, "check",
                            lambda text, run_tests: [])
        monkeypatch.setattr(check_decisions, "parse",
                            lambda text: [Fake(), Fake()])
        with pytest.raises(RuntimeError, match="which one authorises"):
            spend_gate._decision_state("D-014")

    def test_an_unreadable_heading_does_not_read_as_a_missing_decision(
            self, monkeypatch, tmp_path):
        """The two produce opposite reports from one file: a heading the
        parser cannot see would come back as "no such decision", which reads
        as a missing authorisation when it is an unreadable one."""
        import check_decisions

        monkeypatch.setattr(check_decisions, "unparsed_headings",
                            lambda text: ["## D-099 — an em dash"])
        with pytest.raises(RuntimeError, match="cannot read"):
            spend_gate._decision_state("D-014")

    def test_the_review_call_passes_the_class(self, monkeypatch, tmp_path):
        """The gate is at `review`, and a runner that did not pass its class
        would spend against somebody else's authorisation."""
        seen = {}

        def fake(repo, base, head, out, provider="", profile="", *,
                 spend_class):
            seen["class"] = spend_class
            seen["range"] = (base, head)
            return {"ok": False, "seconds": 0.1, "error": "not run"}

        monkeypatch.setattr(noise, "review", fake)
        monkeypatch.setattr(noise, "repo_for", lambda clones, entry: tmp_path)
        noise.one({"case_id": "a", "commit": "f" * 40}, tmp_path)
        assert seen["class"] == "ordinary_noise"
        assert seen["range"] == ("f" * 40 + "^", "f" * 40)

    def test_the_configuration_matches_the_one_the_corpus_was_measured_with(
            self, monkeypatch, tmp_path):
        """A noise figure under a different configuration is a number about a
        different system, and it would sit beside the recall figure inviting a
        comparison it cannot bear. `claude-cli` is also the only permitted
        path: an API key is never used."""
        seen = {}

        def fake(repo, base, head, out, provider="", profile="", *,
                 spend_class):
            seen["provider"] = provider
            seen["profile"] = profile
            return {"ok": False, "seconds": 0.1, "error": "not run"}

        monkeypatch.setattr(noise, "review", fake)
        monkeypatch.setattr(noise, "repo_for", lambda clones, entry: tmp_path)
        noise.one({"case_id": "a", "commit": "f" * 40}, tmp_path)
        assert seen["provider"] == "claude-cli"
        assert seen["profile"] == ""

    def test_a_row_missing_an_optional_field_does_not_lose_a_paid_review(
            self, monkeypatch, tmp_path):
        """The first version indexed `entry["repo"]` while building the row,
        so a seal without it turned a finished review into a `KeyError` after
        the model had already answered."""
        def fake(repo, base, head, out, provider="", profile="", *,
                 spend_class):
            return {"ok": True, "seconds": 1.0, "payload": {
                "complete": True, "verdict": {"blocked": False},
                "findings": [], "usage": {}}}

        monkeypatch.setattr(noise, "review", fake)
        monkeypatch.setattr(noise, "repo_for", lambda clones, entry: tmp_path)
        row = noise.one({"case_id": "a", "commit": "f" * 40}, tmp_path)
        assert row["complete"] is True
        assert row["repo"] is None


class TestTheCommitIsCheckedBeforeAnythingIsSpent:
    def test_a_missing_clone_refuses(self, tmp_path):
        with pytest.raises(noise.Refused, match="no clone at"):
            noise.repo_for(tmp_path, {"case_id": "a", "repo": "acme/absent",
                                      "commit": "0" * 40})

    def test_a_root_commit_refuses_rather_than_being_reviewed(
            self, tmp_path, monkeypatch):
        """A root commit has no parent and no diff. Reviewing it against the
        empty tree would answer a different question."""
        import subprocess

        (tmp_path / "acme").mkdir()

        class Done:
            def __init__(self, code, out=""):
                self.returncode = code
                self.stdout = out

        calls = []

        def fake(cmd, **kwargs):
            calls.append(cmd)
            if "cat-file" in cmd:
                return Done(0)
            return Done(0, "onlyonecommit\n")

        monkeypatch.setattr(subprocess, "run", fake)
        with pytest.raises(noise.Refused, match="no parent"):
            noise.repo_for(tmp_path, {"case_id": "a", "repo": "x/acme",
                                      "commit": "0" * 40})
