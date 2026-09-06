"""The interleaved order, and the ledger that has to prove a run followed it.

The first design resumed by counting accepted rows per (arm, pass). Codex
refused it on 2026-09-06: a count is not a history. A deleted result rewinds
the inferred position, a copied one advances it, and either way the run
continues on a *different* interleave from the one that was committed — while
every digest it does check still matches.

So the tests below are five histories a count cannot tell apart from a good
one, plus the two states a crash between the result file and the ledger line
leaves behind.
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

import experiment  # noqa: E402
import sonnet_trial as trial  # noqa: E402

CASES = ["one", "two", "three"]
ENVIRONMENT = {"system_prompt": "aaa", "verifier_prompt": "bbb",
               "findings_schema": "ccc", "agent_version": "0.1.0",
               "scorer": "s", "reviewer": "r", "verify": "on"}


@pytest.fixture()
def trees(tmp_path, monkeypatch):
    """Two frozen arm manifests and an empty trial, all under `tmp_path`."""
    monkeypatch.setattr(experiment, "ROOT", tmp_path)
    monkeypatch.setattr(trial, "ROOT", tmp_path)

    for arm, model in (("opus-arm", "claude-opus-5"),
                       ("sonnet-arm", "claude-sonnet-5")):
        directory = experiment.home(arm)
        directory.mkdir(parents=True)
        (directory / "manifest.json").write_text(json.dumps({
            # The verifier is Opus in **both** arms: the trial changes the
            # reviewer and holds the verifier still, which is the arrangement
            # the comparator requires.
            "environment": dict(ENVIRONMENT, model_requested=model,
                                verifier_requested="claude-opus-5"),
            "protocol": {"order": list(CASES), "passes": ["a", "b"]},
            # `load` refuses a manifest with no cases, so the fixture carries
            # the block a real freeze writes rather than the minimum this file
            # happens to read.
            "cases": [{"case_id": case_id, "case_digest": "d" * 16}
                      for case_id in CASES],
        }), encoding="utf-8")
    return tmp_path


def frozen(name="t"):
    return trial.freeze(name, "opus-arm", "sonnet-arm")


append = trial.append          # the same writer the runner uses, not a copy


def result_for(name, index, body=None):
    """Write the accepted row a unit would have produced, and return its
    digest."""
    schedule, _ = trial.load_schedule(name)
    unit = schedule["units"][index]
    path = trial._result_path(schedule, unit)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(body or {"case_id": unit["case_id"],
                                        "pair_success": True}),
                    encoding="utf-8")
    return experiment.digest_file(path)


def step(name, index, *, close=True, body=None):
    """One completed unit: prepared, the result, then done."""
    schedule, schedule_digest = trial.load_schedule(name)
    unit = schedule["units"][index]
    append(name, {"kind": trial.PREPARED, "index": index,
                  "case_id": unit["case_id"], "arm": unit["arm"],
                  "pass": unit["pass"], "schedule_digest": schedule_digest})
    kept = result_for(name, index, body)
    if close:
        append(name, {"kind": trial.DONE, "index": index,
                      "result_digest": kept,
                      "schedule_digest": schedule_digest})
    return kept


class TestTheOrderIsCommittedBeforeAnyResult:
    def test_a_schedule_names_every_unit_with_its_case(self, trees):
        assert frozen() == 0
        schedule, _ = trial.load_schedule("t")
        assert len(schedule["units"]) == len(CASES) * 2 * 2
        for index, unit in enumerate(schedule["units"]):
            assert unit["index"] == index
            assert unit["case_id"] in CASES
            assert unit["arm"] in trial.ARMS

    def test_the_two_arms_are_actually_interleaved(self, trees):
        """The whole point. Two experiments run one after the other put every
        change in the world — the subscription window, provider load, an
        upstream release — entirely on the second arm, where it is
        indistinguishable from the model change being measured."""
        assert frozen() == 0
        schedule, _ = trial.load_schedule("t")
        arms = [u["arm"] for u in schedule["units"]]
        first_sonnet = arms.index("sonnet")
        last_opus = len(arms) - 1 - arms[::-1].index("opus")
        assert first_sonnet < last_opus, (
            "every sonnet unit falls after every opus one; this is not an "
            "interleave")

    def test_a_second_freeze_is_refused(self, trees):
        assert frozen() == 0
        assert frozen() == 2

    def test_a_result_that_already_exists_refuses_the_freeze(self, trees):
        """An order written after some of the answers are known is not an
        order committed before the results."""
        directory = experiment.home("opus-arm") / "pass-a"
        directory.mkdir(parents=True)
        (directory / "one.json").write_text("{}", encoding="utf-8")
        assert frozen() == 2

    def test_arms_differing_in_anything_but_the_model_are_refused(self, trees):
        path = experiment.home("sonnet-arm") / "manifest.json"
        body = json.loads(path.read_text(encoding="utf-8"))
        body["environment"]["system_prompt"] = "different"
        path.write_text(json.dumps(body), encoding="utf-8")
        assert frozen() == 2

    def test_two_arms_on_the_same_model_are_refused(self, trees):
        path = experiment.home("sonnet-arm") / "manifest.json"
        body = json.loads(path.read_text(encoding="utf-8"))
        body["environment"]["model_requested"] = "claude-opus-5"
        path.write_text(json.dumps(body), encoding="utf-8")
        assert frozen() == 2


class TestTheHistoriesACountCannotTellApart:
    """Each of these leaves the accepted-row count either right or plausible,
    and each is a different interleave from the committed one."""

    def clean(self, trees, steps=3):
        assert frozen() == 0
        for index in range(steps):
            step("t", index)
        _, _, problems = trial.verify("t")
        assert problems == [], problems
        return trial.load_schedule("t")[0]

    def test_a_clean_history_is_accepted(self, trees):
        self.clean(trees)

    def test_a_deleted_result_is_caught(self, trees):
        schedule = self.clean(trees)
        trial._result_path(schedule, schedule["units"][1]).unlink()
        _, _, problems = trial.verify("t")
        assert any("is not there" in p for p in problems), problems

    def test_a_result_rewritten_after_the_fact_is_caught(self, trees):
        """The row on disk and the row that was measured must be one file.
        Counting rows sees the same number either way."""
        schedule = self.clean(trees)
        path = trial._result_path(schedule, schedule["units"][1])
        path.write_text(json.dumps({"pair_success": False}), encoding="utf-8")
        _, _, problems = trial.verify("t")
        assert any("different content" in p for p in problems), problems

    def test_a_result_nothing_opened_a_step_for_is_caught(self, trees):
        """A review bought outside the committed order. A count takes it for
        progress and the run continues one unit further along than it is."""
        schedule = self.clean(trees)
        unit = schedule["units"][9]
        path = trial._result_path(schedule, unit)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{}", encoding="utf-8")
        _, _, problems = trial.verify("t")
        assert any("no ledger step accounts for" in p for p in problems), \
            problems

    def test_a_removed_ledger_line_is_caught(self, trees):
        self.clean(trees)
        path = trial.ledger_path("t")
        lines = path.read_text(encoding="utf-8").splitlines()
        path.write_text("\n".join(lines[:2] + lines[3:]) + "\n",
                        encoding="utf-8")
        _, _, problems = trial.verify("t")
        assert problems, "a removed line left no trace"

    def test_a_step_run_out_of_the_committed_order_is_caught(self, trees):
        assert frozen() == 0
        step("t", 0)
        step("t", 2)                      # unit 1 skipped
        _, _, problems = trial.verify("t")
        assert any("committed order says" in p for p in problems), problems

    def test_a_schedule_rewritten_under_a_running_trial_is_caught(self, trees):
        self.clean(trees)
        path = trial.home("t") / "schedule.json"
        body = json.loads(path.read_text(encoding="utf-8"))
        # Reversed *and renumbered*, so the file is a perfectly well-formed
        # schedule — a different committed order wearing the same name.
        body["units"] = [dict(unit, index=index) for index, unit
                         in enumerate(reversed(body["units"]))]
        path.write_text(json.dumps(body, indent=2, sort_keys=True) + "\n",
                        encoding="utf-8")
        _, _, problems = trial.verify("t")
        assert any("belongs to another trial" in p for p in problems), problems


class TestTheCrashBetweenTwoWrites:
    """Publishing the result and appending the ledger line are two writes and
    cannot be one. Codex, 2026-09-06: a crash between them must not leave a
    paid, perfectly good review looking like an injected stray."""

    def test_an_open_unit_whose_result_arrived_is_not_a_stray(self, trees):
        assert frozen() == 0
        step("t", 0)
        step("t", 1, close=False)         # result written, `done` never was
        _, entries, problems = trial.verify("t")
        assert problems == [], problems
        schedule, _ = trial.load_schedule("t")
        done, open_index = trial.position(schedule, entries)
        assert done == 1 and open_index == 1

    def test_an_open_unit_whose_result_never_arrived_is_re_run(self, trees):
        assert frozen() == 0
        schedule, schedule_digest = trial.load_schedule("t")
        unit = schedule["units"][0]
        append("t", {"kind": trial.PREPARED, "index": 0,
                     "case_id": unit["case_id"], "arm": unit["arm"],
                     "pass": unit["pass"],
                     "schedule_digest": schedule_digest})
        _, entries, problems = trial.verify("t")
        assert problems == [], problems
        assert trial.position(schedule, entries) == (0, 0)

    def test_two_units_opened_without_closing_the_first_is_caught(self, trees):
        """Recovery is for one interrupted step, not for a run that walked on
        past a step it never recorded."""
        assert frozen() == 0
        step("t", 0, close=False)
        step("t", 1, close=False)
        _, _, problems = trial.verify("t")
        assert any("still open" in p for p in problems), problems


class TestWhatTheLedgerSaysAboutTheReference:
    def test_a_trial_with_no_reference_says_so(self, trees, capsys):
        assert frozen() == 0
        step("t", 0)
        assert trial.status("t") == 0
        assert "reference: not frozen" in capsys.readouterr().out

    def test_a_reference_record_is_chained_like_any_other_line(self, trees):
        """It has no `index`, because it is not a unit of the schedule — using
        one would disturb the positional reading of the unit records. It is
        still in the chain, so removing it leaves a trace."""
        assert frozen() == 0
        step("t", 0)
        append("t", {"kind": trial.REFERENCE, "after_units": 1,
                     "reference_digest": "d" * 16})
        step("t", 1)
        _, _, problems = trial.verify("t")
        assert problems == [], problems

        path = trial.ledger_path("t")
        lines = path.read_text(encoding="utf-8").splitlines()
        path.write_text("\n".join(lines[:2] + lines[3:]) + "\n",
                        encoding="utf-8")
        _, _, problems = trial.verify("t")
        assert problems, "the reference record could be removed unnoticed"


class TestTheRunnerItself:
    """`_buy` is replaced throughout: no test in this file spends anything.

    Codex, 2026-09-06, on the version that had only `freeze` and `status`:
    "The tests manufacture all ledger states directly, so they do not exercise
    the claimed runner." These drive `run` and read what it wrote.
    """

    def stub(self, monkeypatch, *, works=True):
        bought = []

        def _buy(schedule, unit):
            bought.append((unit["index"], unit["arm"], unit["pass"]))
            if not works:
                return 2
            path = trial._result_path(schedule, unit)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps({"case_id": unit["case_id"],
                                        "pair_success": True}),
                            encoding="utf-8")
            return 0

        monkeypatch.setattr(trial, "_buy", _buy)
        # The anchor is answered too, because these tests are about the runner
        # and an unanchored ledger stops it for a different, correct reason.
        # The two tests that are about the anchor override this themselves.
        monkeypatch.setattr(trial, "committed_prefix",
                            lambda name: ("extends", "committed in git"))
        return bought

    def test_it_walks_the_committed_order_and_records_both_ends(
            self, trees, monkeypatch):
        bought = self.stub(monkeypatch)
        assert frozen() == 0
        assert trial.run("t", 3, recover=False) == 0

        schedule, _ = trial.load_schedule("t")
        assert bought == [(i, schedule["units"][i]["arm"],
                           schedule["units"][i]["pass"]) for i in range(3)]
        entries = trial.read_ledger("t")
        assert [e["kind"] for e in entries] == [
            trial.PREPARED, trial.DONE] * 3
        _, _, problems = trial.verify("t")
        assert problems == [], problems

    def test_a_unit_that_did_not_conclude_stays_open(self, trees,
                                                     monkeypatch):
        """The `prepared` line is already down when the review fails, and it
        stays: the next run picks that unit up rather than stepping past it."""
        self.stub(monkeypatch, works=False)
        assert frozen() == 0
        assert trial.run("t", None, recover=False) == 2
        entries = trial.read_ledger("t")
        assert [e["kind"] for e in entries] == [trial.PREPARED]
        schedule, _ = trial.load_schedule("t")
        assert trial.position(schedule, entries) == (0, 0)

    def test_an_open_unit_with_a_result_is_refused_without_recover(
            self, trees, monkeypatch, capsys):
        """The row is expected at that path and expected is not measured.
        Nothing in a JSON file binds it to the review this trial bought."""
        self.stub(monkeypatch)
        assert frozen() == 0
        step("t", 0, close=False)
        assert trial.run("t", None, recover=False) == 2
        assert "--recover" in capsys.readouterr().err

    def test_recover_accepts_it_and_says_so_in_the_ledger(self, trees,
                                                          monkeypatch):
        self.stub(monkeypatch)
        assert frozen() == 0
        step("t", 0, close=False)
        assert trial.run("t", 1, recover=True) == 0
        closed = [e for e in trial.read_ledger("t")
                  if e["kind"] == trial.DONE and e["index"] == 0]
        assert closed and closed[0].get("recovered") is True

    def test_steps_zero_buys_nothing_even_with_a_unit_open(self, trees,
                                                           monkeypatch):
        """Codex, 2026-09-06. `--steps` was checked only in the loop over new
        units, so the resume path walked straight past it: an operator asking
        "buy nothing, just tell me where I am" bought a review. A limit that
        holds except when somebody is being careful is the wrong way round."""
        bought = self.stub(monkeypatch)
        assert frozen() == 0
        schedule, schedule_digest = trial.load_schedule("t")
        unit = schedule["units"][0]
        append("t", {"kind": trial.PREPARED, "index": 0,
                     "case_id": unit["case_id"], "arm": unit["arm"],
                     "pass": unit["pass"],
                     "schedule_digest": schedule_digest})

        assert trial.run("t", 0, recover=False) == 0
        assert bought == []

    def test_a_negative_step_count_is_refused(self, trees, monkeypatch):
        bought = self.stub(monkeypatch)
        assert frozen() == 0
        assert trial.run("t", -1, recover=False) == 2
        assert bought == []

    def test_a_recovered_unit_counts_against_the_budget(self, trees,
                                                        monkeypatch):
        """Otherwise `--steps 1` recovers one *and* buys one."""
        bought = self.stub(monkeypatch)
        assert frozen() == 0
        step("t", 0, close=False)
        assert trial.run("t", 1, recover=True) == 0
        assert bought == []

    def test_an_open_unit_with_no_result_is_bought_under_its_own_line(
            self, trees, monkeypatch):
        """The re-buy path, which was the one live coverage hole after Codex
        enumerated every guard combination on 2026-09-06: an open unit whose
        review never happened, a working provider and a budget above zero.

        The `prepared` line already on disk is the one it closes — a second
        `prepared` for the same unit would be a history claiming the unit was
        started twice.
        """
        bought = self.stub(monkeypatch)
        assert frozen() == 0
        schedule, schedule_digest = trial.load_schedule("t")
        unit = schedule["units"][0]
        append("t", {"kind": trial.PREPARED, "index": 0,
                     "case_id": unit["case_id"], "arm": unit["arm"],
                     "pass": unit["pass"],
                     "schedule_digest": schedule_digest})

        assert trial.run("t", 2, recover=False) == 0
        assert bought[0] == (0, unit["arm"], unit["pass"])
        kinds = [e["kind"] for e in trial.read_ledger("t")]
        assert kinds == [trial.PREPARED, trial.DONE,
                         trial.PREPARED, trial.DONE]
        _, _, problems = trial.verify("t")
        assert problems == [], problems

    def test_a_diverged_anchor_stops_the_run(self, trees, monkeypatch):
        """`committed_prefix` has its own test for returning `diverged`, and
        `run` had none for acting on it — the branch every other anchor test
        was written around. Found by listing the guards rather than by waiting
        for the next round to find it.
        """
        bought = self.stub(monkeypatch)
        assert frozen() == 0
        monkeypatch.setattr(
            trial, "committed_prefix",
            lambda name: ("diverged", "not an extension of the committed one"))
        assert trial.run("t", None, recover=False) == 2
        assert bought == []
        assert trial.read_ledger("t") == []

    def test_a_diverged_anchor_stops_a_recovery_too(self, trees, monkeypatch):
        """And it is not a purchase guard: a rewritten ledger must not be
        extended by hand either."""
        self.stub(monkeypatch)
        assert frozen() == 0
        step("t", 0, close=False)
        before = len(trial.read_ledger("t"))
        monkeypatch.setattr(
            trial, "committed_prefix",
            lambda name: ("diverged", "not an extension of the committed one"))
        assert trial.run("t", None, recover=True) == 2
        assert len(trial.read_ledger("t")) == before

    def test_an_unanchored_ledger_with_lines_in_it_refuses(self, trees,
                                                           monkeypatch):
        """Codex, 2026-09-06, fifth round. `run` refused only `diverged` and
        spent on `unknown` — contradicting the contract three functions above
        it, which says `unknown` is "I could not check". An uncommitted ledger
        can be rewritten whole with every hash recomputed, and the chain inside
        the file agrees with itself the whole way."""
        bought = self.stub(monkeypatch)
        assert frozen() == 0
        step("t", 0)
        monkeypatch.setattr(trial, "committed_prefix",
                            lambda name: ("unknown", "git could not be asked"))
        assert trial.run("t", None, recover=False) == 2
        assert bought == []

    def test_an_empty_ledger_may_start_without_an_anchor(self, trees,
                                                         monkeypatch):
        """The other half, and it is not a weakening: before the first line
        exists there is no history to rewrite. A rule that blocked here would
        block every trial for ever.

        **No `--steps` here, deliberately.** The first version of this test
        passed `--steps 1` and so proved nothing: the anchor is read once,
        while the ledger is empty, and with the CLI's own default the loop then
        bought every remaining unit — the whole trial under an anchor that says
        "I could not check". Codex found it on the sixth round, and named the
        test as the thing that hid it: a test written to the fix rather than to
        the defect.
        """
        bought = self.stub(monkeypatch)
        assert frozen() == 0
        monkeypatch.setattr(trial, "committed_prefix",
                            lambda name: ("unknown", "not committed yet"))
        assert trial.run("t", None, recover=False) == 0
        assert len(bought) == 1, (
            "an unanchored invocation bought {} unit(s); the exception is for "
            "the first line, not for a run that writes fifty-two".format(
                len(bought)))

    def test_zero_steps_beats_the_unanchored_allowance(self, trees,
                                                       monkeypatch):
        """The intersection of two rules that each had a test.

        "An unanchored empty ledger may buy one unit" was written as
        `steps = 1`, which *raised* an explicit `--steps 0` to one — so the
        operator asking to buy nothing bought a review, against the contract
        sitting a few lines above it. The zero-steps test used an anchored
        ledger and the unanchored test used the default count, so nothing ever
        asked the two together. Codex, seventh round, 2026-09-06.
        """
        bought = self.stub(monkeypatch)
        assert frozen() == 0
        monkeypatch.setattr(trial, "committed_prefix",
                            lambda name: ("unknown", "not committed yet"))
        assert trial.run("t", 0, recover=False) == 0
        assert bought == []

    def test_zero_steps_records_nothing_even_with_recover(self, trees,
                                                          monkeypatch):
        """The third intersection of the same two rules, and the third time
        this file has been asked for one. Codex, 2026-09-06.

        The zero-step guard sat inside the "nothing was written" branch, so
        `--steps 0 --recover` reached the other branch and appended a `DONE`.
        Recovery costs no money, which is why it looked harmless — but it moves
        the trial on a unit, and `--steps 0` means this invocation changes
        nothing at all.
        """
        self.stub(monkeypatch)
        assert frozen() == 0
        step("t", 0, close=False)
        before = len(trial.read_ledger("t"))

        assert trial.run("t", 0, recover=True) == 0
        assert len(trial.read_ledger("t")) == before, \
            "a zero-step invocation wrote to the ledger"

    def test_a_broken_history_refuses_before_anything_is_bought(
            self, trees, monkeypatch, capsys):
        bought = self.stub(monkeypatch)
        assert frozen() == 0
        step("t", 0)
        schedule, _ = trial.load_schedule("t")
        trial._result_path(schedule, schedule["units"][0]).unlink()
        assert trial.run("t", None, recover=False) == 2
        assert bought == []
        assert "refusing to run" in capsys.readouterr().err


class TestTheChainNeedsAHeadOutsideItself:
    """A hash chain whose head lives in the file it protects can be rewritten
    whole. Codex, 2026-09-06. The anchor available here is git."""

    def test_an_uncommitted_ledger_is_unknown_not_sound(self, trees):
        assert frozen() == 0
        step("t", 0)
        state, why = trial.committed_prefix("t")
        assert state == "unknown"
        assert "committed" in why

    def test_a_ledger_that_extends_the_committed_one_says_so(self, trees,
                                                             monkeypatch):
        committed = "line one\n"

        def fake(argv, **kwargs):
            class Done:
                returncode = 0
                stdout = committed
            return Done()

        assert frozen() == 0
        trial.ledger_path("t").parent.mkdir(parents=True, exist_ok=True)
        trial.ledger_path("t").write_text(committed + "line two\n",
                                          encoding="utf-8")
        monkeypatch.setattr(trial.subprocess, "run", fake)
        assert trial.committed_prefix("t")[0] == "extends"

    def test_a_rewritten_ledger_is_caught_however_the_hashes_recompute(
            self, trees, monkeypatch):
        def fake(argv, **kwargs):
            class Done:
                returncode = 0
                stdout = "the line that was committed\n"
            return Done()

        assert frozen() == 0
        trial.ledger_path("t").parent.mkdir(parents=True, exist_ok=True)
        trial.ledger_path("t").write_text("a different history\n",
                                          encoding="utf-8")
        monkeypatch.setattr(trial.subprocess, "run", fake)
        state, why = trial.committed_prefix("t")
        assert state == "diverged"
        assert "not an extension" in why


class TestAMalformedScheduleIsReportedNotRaised:
    """`verify` exists to report what is wrong. Codex, 2026-09-06: a unit with
    a non-integer `seq` reached `entry.get("seq", "?") + 1` and raised
    `TypeError` out of the middle of it."""

    @pytest.mark.parametrize("unit", [3, None, "one", {"index": 5}])
    def test_a_unit_that_is_not_a_unit(self, trees, unit):
        assert frozen() == 0
        path = trial.home("t") / "schedule.json"
        body = json.loads(path.read_text(encoding="utf-8"))
        body["units"][1] = unit
        path.write_text(json.dumps(body), encoding="utf-8")
        with pytest.raises(trial.TrialError):
            trial.verify("t")

    def test_a_ledger_line_whose_seq_is_a_string(self, trees):
        assert frozen() == 0
        step("t", 0)
        path = trial.ledger_path("t")
        lines = path.read_text(encoding="utf-8").splitlines()
        first = json.loads(lines[0])
        first["seq"] = "nought"
        path.write_text("\n".join([json.dumps(first), *lines[1:]]) + "\n",
                        encoding="utf-8")
        _, _, problems = trial.verify("t")     # reports, does not raise
        assert problems

    def test_a_schedule_naming_no_experiment_for_an_arm(self, trees):
        assert frozen() == 0
        path = trial.home("t") / "schedule.json"
        body = json.loads(path.read_text(encoding="utf-8"))
        del body["arms"]["sonnet"]
        path.write_text(json.dumps(body), encoding="utf-8")
        with pytest.raises(trial.TrialError):
            trial.verify("t")


class TestRunningOneNamedCase:
    """`experiment.run(..., only=case_id)` is how the schedule chooses what to
    buy. A caller that asked for one case and silently got another would
    record a review of the wrong thing under the right name."""

    def test_a_case_outside_the_frozen_order_is_refused(self, trees, capsys):
        assert experiment.run("opus-arm", "a", None, only="nosuch") == 2
        assert "not in the frozen order" in capsys.readouterr().err
