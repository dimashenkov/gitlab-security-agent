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
import os
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
            # The suite block, because a real freeze writes one and the trial
            # compares it. Leaving it out made this fixture a shape production
            # cannot emit — the defect this file has already been caught by
            # once, where a green test stood over an impossible artifact.
            "suite": {"file": "suites/sentinel.yml", "digest": "f" * 16,
                      "count": len(CASES)},
            # `load` refuses a manifest with no cases, so the fixture carries
            # the block a real freeze writes rather than the minimum this file
            # happens to read — including the answer-key digest, which the
            # trial compares so that two arms cannot carry equal case ids over
            # different content.
            "cases": [{"case_id": case_id, "case_digest": "d" * 16,
                       "answer_key_digest": "k" * 16}
                      for case_id in CASES],
        }), encoding="utf-8")
        # The frozen prompt copies a real `experiment.py freeze` writes and
        # `experiment.run` reads. Omitting them made this fixture a shape
        # production cannot emit — the defect this file has been caught by
        # twice now, the second time when the schedule began binding their
        # bytes and every test here refused.
        prompts = directory / "prompts"
        prompts.mkdir(parents=True, exist_ok=True)
        for name, body in (("system.md", "the reviewer's brief"),
                           ("verifier.md", "the verifier's brief"),
                           ("findings.schema.json", "{}")):
            (prompts / name).write_text(body, encoding="utf-8")
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
        _, _, _, problems = trial.verify("t")
        assert problems == [], problems
        return trial.load_schedule("t")[0]

    def test_a_clean_history_is_accepted(self, trees):
        self.clean(trees)

    def test_a_deleted_result_is_caught(self, trees):
        schedule = self.clean(trees)
        trial._result_path(schedule, schedule["units"][1]).unlink()
        _, _, _, problems = trial.verify("t")
        assert any("is not there" in p for p in problems), problems

    def test_a_result_rewritten_after_the_fact_is_caught(self, trees):
        """The row on disk and the row that was measured must be one file.
        Counting rows sees the same number either way."""
        schedule = self.clean(trees)
        path = trial._result_path(schedule, schedule["units"][1])
        path.write_text(json.dumps({"pair_success": False}), encoding="utf-8")
        _, _, _, problems = trial.verify("t")
        assert any("different content" in p for p in problems), problems

    def test_a_result_nothing_opened_a_step_for_is_caught(self, trees):
        """A review bought outside the committed order. A count takes it for
        progress and the run continues one unit further along than it is."""
        schedule = self.clean(trees)
        unit = schedule["units"][9]
        path = trial._result_path(schedule, unit)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{}", encoding="utf-8")
        _, _, _, problems = trial.verify("t")
        assert any("no ledger step accounts for" in p for p in problems), \
            problems

    def test_a_removed_ledger_line_is_caught(self, trees):
        self.clean(trees)
        path = trial.ledger_path("t")
        lines = path.read_text(encoding="utf-8").splitlines()
        path.write_text("\n".join(lines[:2] + lines[3:]) + "\n",
                        encoding="utf-8")
        _, _, _, problems = trial.verify("t")
        assert problems, "a removed line left no trace"

    def test_a_step_run_out_of_the_committed_order_is_caught(self, trees):
        assert frozen() == 0
        step("t", 0)
        step("t", 2)                      # unit 1 skipped
        _, _, _, problems = trial.verify("t")
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
        _, _, _, problems = trial.verify("t")
        assert any("belongs to another trial" in p for p in problems), problems


class TestTheCrashBetweenTwoWrites:
    """Publishing the result and appending the ledger line are two writes and
    cannot be one. Codex, 2026-09-06: a crash between them must not leave a
    paid, perfectly good review looking like an injected stray."""

    def test_an_open_unit_whose_result_arrived_is_not_a_stray(self, trees):
        assert frozen() == 0
        step("t", 0)
        step("t", 1, close=False)         # result written, `done` never was
        _, _, entries, problems = trial.verify("t")
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
        _, _, entries, problems = trial.verify("t")
        assert problems == [], problems
        assert trial.position(schedule, entries) == (0, 0)

    def test_two_units_opened_without_closing_the_first_is_caught(self, trees):
        """Recovery is for one interrupted step, not for a run that walked on
        past a step it never recorded."""
        assert frozen() == 0
        step("t", 0, close=False)
        step("t", 1, close=False)
        _, _, _, problems = trial.verify("t")
        assert any("still open" in p for p in problems), problems


class TestFreezingTheReference:
    """The ledger line nothing wrote until now. `status` reported it and the
    tests manufactured it, which is a record of a thing that never happened."""

    def stub(self, monkeypatch, *, body=None, raises=None):
        """`sentinel_reference.build` replaced: no rows are read from disk and
        nothing is bought. Only this tool's decisions are under test."""
        import sentinel_reference

        def build():
            if raises is not None:
                raise raises
            return body if body is not None else {"comparable": ["one"],
                                                  "missing": []}

        monkeypatch.setattr(sentinel_reference, "build", build)
        monkeypatch.setattr(trial, "committed_prefix",
                            lambda name: ("extends", "committed in git"))
        # Nothing has moved. `drift` reads the real suite and corpus through
        # module constants this fixture's tmp_path does not replace, so it is
        # answered here — and asked for real in its own two tests below.
        monkeypatch.setattr(experiment, "drift", lambda body: [])

    def all_of_the_reference_arm(self, name="t"):
        """Every unit of the reference arm recorded, and none of the other."""
        schedule, _ = trial.load_schedule(name)
        for unit in schedule["units"]:
            if unit["arm"] == trial.REFERENCE_ARM:
                step(name, unit["index"])
            else:
                schedule_digest = trial.load_schedule(name)[1]
                trial.append(name, {"kind": trial.PREPARED,
                                    "index": unit["index"],
                                    "case_id": unit["case_id"],
                                    "arm": unit["arm"], "pass": unit["pass"],
                                    "schedule_digest": schedule_digest})
                result_for(name, unit["index"])
                trial.append(name, {"kind": trial.DONE, "index": unit["index"],
                                    "result_digest": experiment.digest_file(
                                        trial._result_path(schedule, unit)),
                                    "schedule_digest": schedule_digest})

    def test_it_writes_the_file_and_the_ledger_line(self, trees, monkeypatch,
                                                    tmp_path):
        self.stub(monkeypatch)
        assert frozen() == 0
        self.all_of_the_reference_arm()
        target = tmp_path / "reference.json"

        assert trial.reference("t", str(target)) == 0
        assert target.is_file()
        recorded = [e for e in trial.read_ledger("t")
                    if e["kind"] == trial.REFERENCE]
        assert len(recorded) == 1
        assert recorded[0]["reference_digest"] == \
            experiment.digest_file(target)
        assert trial.REFERENCE_ARM in recorded[0]["built_from"]
        _, _, _, problems = trial.verify("t")
        assert problems == [], problems

    def test_it_refuses_before_the_reference_arm_is_finished(
            self, trees, monkeypatch, tmp_path, capsys):
        """A baseline built from part of its own arm is a baseline about a
        smaller experiment, and nothing downstream says which cases it left
        out."""
        self.stub(monkeypatch)
        assert frozen() == 0
        step("t", 0)
        assert trial.reference("t", str(tmp_path / "r.json")) == 2
        assert "have not been recorded" in capsys.readouterr().err
        assert not (tmp_path / "r.json").exists()

    def test_a_second_reference_is_refused(self, trees, monkeypatch, tmp_path):
        """Freezing a second one is choosing which baseline the challenger is
        held to, after some of its answers are known."""
        self.stub(monkeypatch)
        assert frozen() == 0
        self.all_of_the_reference_arm()
        assert trial.reference("t", str(tmp_path / "a.json")) == 0
        assert trial.reference("t", str(tmp_path / "b.json")) == 2
        assert not (tmp_path / "b.json").exists()

    def test_it_builds_from_the_reference_arm_and_nothing_else(
            self, trees, monkeypatch, tmp_path):
        """The one thing this command exists to guarantee: the module-level
        `EXPERIMENT` every reader in the builder goes through is rebound to the
        reference arm's directory, and put back afterwards."""
        import sentinel_reference

        seen = {}
        original = sentinel_reference.EXPERIMENT

        def build():
            seen["from"] = sentinel_reference.EXPERIMENT
            return {"comparable": ["one"], "missing": []}

        monkeypatch.setattr(sentinel_reference, "build", build)
        monkeypatch.setattr(trial, "committed_prefix",
                            lambda name: ("extends", "committed in git"))
        monkeypatch.setattr(experiment, "drift", lambda body: [])
        assert frozen() == 0
        self.all_of_the_reference_arm()
        assert trial.reference("t", str(tmp_path / "r.json")) == 0

        schedule, _ = trial.load_schedule("t")
        assert seen["from"] == experiment.home(
            schedule["arms"][trial.REFERENCE_ARM]["experiment"])
        assert original == sentinel_reference.EXPERIMENT, \
            "the builder was left pointing at this trial's directory"

    def test_a_builder_refusal_writes_nothing(self, trees, monkeypatch,
                                              tmp_path):
        import sentinel_reference

        self.stub(monkeypatch,
                  raises=sentinel_reference.ReferenceError("two ways"))
        assert frozen() == 0
        self.all_of_the_reference_arm()
        assert trial.reference("t", str(tmp_path / "r.json")) == 2
        assert not (tmp_path / "r.json").exists()
        assert not [e for e in trial.read_ledger("t")
                    if e["kind"] == trial.REFERENCE]

    def test_a_moved_suite_or_corpus_stops_the_freeze(self, trees,
                                                      monkeypatch, tmp_path):
        """Rebinding `EXPERIMENT` does not make the build arm-only.

        Codex, 2026-09-06: `sentinel_reference.build()` takes its case list
        from the live `SUITE` and checks every row's digest against the live
        `CORPUS`, neither of which is the frozen arm — so a suite edited since
        the arm ran shapes the reference, or refuses it, for a reason that has
        nothing to do with the rows that were paid for. `experiment.drift`
        already answers that question about an arm, so it is asked.
        """
        self.stub(monkeypatch)
        monkeypatch.setattr(
            experiment, "drift",
            lambda body: ["the sentinel suite file has been rewritten"])
        assert frozen() == 0
        self.all_of_the_reference_arm()
        assert trial.reference("t", str(tmp_path / "r.json")) == 2
        assert not (tmp_path / "r.json").exists()

    def test_a_manifest_drift_cannot_read_is_not_agreement(self, trees,
                                                           monkeypatch,
                                                           tmp_path):
        """`drift` indexes keys an older manifest may not carry. A `KeyError`
        out of the check that authorises the build is "I could not look"
        arriving as a crash."""
        self.stub(monkeypatch)

        def explode(body):
            raise KeyError("suite")

        monkeypatch.setattr(experiment, "drift", explode)
        assert frozen() == 0
        self.all_of_the_reference_arm()
        assert trial.reference("t", str(tmp_path / "r.json")) == 2
        assert not (tmp_path / "r.json").exists()

    def test_recover_refuses_a_file_the_arm_did_not_produce(self, trees,
                                                            monkeypatch,
                                                            tmp_path):
        """`--recover` says "record this one", not "believe it".

        Codex, 2026-09-06: the first version recorded whatever digest the file
        happened to carry, so one slip permanently blessed an unrelated
        baseline. It rebuilds and compares now.
        """
        self.stub(monkeypatch)
        assert frozen() == 0
        self.all_of_the_reference_arm()
        target = tmp_path / "r.json"
        target.write_text('{"comparable": ["something else"]}',
                          encoding="utf-8")
        assert trial.reference("t", str(target), recover=True) == 2
        assert not [e for e in trial.read_ledger("t")
                    if e["kind"] == trial.REFERENCE]

    def test_a_ledger_line_appearing_during_the_build_stops_the_write(
            self, trees, monkeypatch, tmp_path):
        """Every other check runs before a build that reads dozens of files.
        Codex, 2026-09-06: another process appending a unit, freezing its own
        reference, or moving the anchor in that window was published straight
        over, with an `after_units` that was never true."""
        import sentinel_reference

        target = tmp_path / "r.json"
        self.stub(monkeypatch)
        assert frozen() == 0
        self.all_of_the_reference_arm()

        def build_and_meddle():
            trial.append("t", {"kind": trial.REFERENCE, "after_units": 0,
                               "reference_digest": "d" * 16})
            return {"comparable": ["one"], "missing": []}

        monkeypatch.setattr(sentinel_reference, "build", build_and_meddle)
        assert trial.reference("t", str(target)) == 2
        assert not target.exists()

    def test_a_ledger_rewritten_during_the_build_stops_the_freeze(
            self, trees, monkeypatch, tmp_path):
        """Codex, 2026-09-06, seventh round on this file.

        `_moved_since` compares verification results and record count, so a
        whole-ledger rewrite that keeps both passes it — and `seen` was read
        *after* the build, hashing the file as it already stood. The append
        then agreed with a ledger nobody in this invocation had ever read: the
        exact time-of-check defect the byte-state contract replaced the counter
        to remove, reintroduced by reading the state one line too late.

        Driven through `reference` rather than `append`, because the two direct
        tests of `append` pass their own `after` and cannot see where this
        function takes it.
        """
        import sentinel_reference

        target = tmp_path / "r.json"
        self.stub(monkeypatch)
        assert frozen() == 0
        self.all_of_the_reference_arm()

        def build_and_rewrite():
            # Same records, same count, different bytes — which is what a
            # rewrite with recomputed hashes looks like from `_moved_since`.
            path = trial.ledger_path("t")
            lines = [json.loads(line) for line
                     in path.read_text(encoding="utf-8").splitlines()]
            path.write_text("".join(
                json.dumps(line, sort_keys=True, separators=(",", ":")) + "\n"
                for line in lines), encoding="utf-8")
            return {"comparable": ["one"], "missing": []}

        monkeypatch.setattr(sentinel_reference, "build", build_and_rewrite)
        with pytest.raises(trial.TrialError) as caught:
            trial.reference("t", str(target))
        assert "written against" in str(caught.value)
        # The refusal lands at the append, after the file was published, so
        # what is left is the same state a crash between the two writes leaves:
        # a reference on disk that no line records. `--recover` is the way out
        # of it, and it rebuilds and compares before recording.
        assert not [e for e in trial.read_ledger("t")
                    if e["kind"] == trial.REFERENCE]

    def test_the_recorded_digest_is_of_what_was_produced(self, trees,
                                                         monkeypatch,
                                                         tmp_path):
        """Codex, 2026-09-06, ninth round.

        The digest was taken by reading the path back after publishing, so a
        file replaced in that instant was recorded as though it were what the
        arm's rows built — and `_reference_still_there` cannot see it, because
        both sides of its comparison moved together. The ledger records the
        bytes this invocation produced.

        `experiment.publish` is wrapped so the substitution happens exactly in
        the window: the real file is written, then overwritten, and the digest
        must still be the first one's.
        """
        self.stub(monkeypatch)
        assert frozen() == 0
        self.all_of_the_reference_arm()
        target = tmp_path / "r.json"
        real = experiment.publish

        def publish_then_meddle(path, text):
            written = real(path, text)
            path.write_text('{"substituted": true}', encoding="utf-8")
            return written

        monkeypatch.setattr(experiment, "publish", publish_then_meddle)
        assert trial.reference("t", str(target)) == 0

        recorded = next(e for e in trial.read_ledger("t")
                        if e["kind"] == trial.REFERENCE)
        expected = json.dumps({"comparable": ["one"], "missing": []},
                              indent=1) + "\n"
        assert recorded["reference_digest"] == \
            trial._digest_bytes(expected.encode("utf-8"))
        # And the substitution is then visible, which is the whole point of
        # writing the digest down.
        _, _, _, problems = trial.verify("t")
        assert any("different content than the freeze" in p
                   for p in problems), problems

    def test_a_recovered_digest_is_of_the_bytes_that_were_compared(
            self, trees, monkeypatch, tmp_path):
        """Same defect on the other branch: the file was validated, then read
        again for its digest, so a replacement in between was blessed."""
        self.stub(monkeypatch)
        assert frozen() == 0
        self.all_of_the_reference_arm()
        target = tmp_path / "r.json"
        good = json.dumps({"comparable": ["one"], "missing": []})
        target.write_text(good, encoding="utf-8")

        real_moved = trial._moved_since

        def moved_then_meddle(name, entries):
            answer = real_moved(name, entries)
            target.write_text('{"substituted": true}', encoding="utf-8")
            return answer

        monkeypatch.setattr(trial, "_moved_since", moved_then_meddle)
        assert trial.reference("t", str(target), recover=True) == 0

        recorded = next(e for e in trial.read_ledger("t")
                        if e["kind"] == trial.REFERENCE)
        assert recorded["reference_digest"] == \
            trial._digest_bytes(good.encode("utf-8"))

    def test_a_ledger_line_appearing_during_a_recovery_stops_it_too(
            self, trees, monkeypatch, tmp_path):
        """Both writers, not one. Codex, 2026-09-06: I put the re-check in
        front of the ordinary path and the recovery path went on recording a
        stale `after_units` and a second reference — the same shape as the
        `--steps 0 --recover` round two hours earlier, in the same file."""
        import sentinel_reference

        self.stub(monkeypatch)
        assert frozen() == 0
        self.all_of_the_reference_arm()
        target = tmp_path / "r.json"
        target.write_text(json.dumps({"comparable": ["one"], "missing": []}),
                          encoding="utf-8")

        def build_and_meddle():
            trial.append("t", {"kind": trial.REFERENCE, "after_units": 0,
                               "reference_digest": "d" * 16})
            return {"comparable": ["one"], "missing": []}

        monkeypatch.setattr(sentinel_reference, "build", build_and_meddle)
        assert trial.reference("t", str(target), recover=True) == 2
        recorded = [e for e in trial.read_ledger("t")
                    if e["kind"] == trial.REFERENCE]
        assert len(recorded) == 1, "the recovery recorded a second reference"

    def test_a_diverged_anchor_stops_the_freeze(self, trees, monkeypatch,
                                                tmp_path):
        """The same rule as `run`, and from the same function: a writer that
        enforced it separately would be the way round it."""
        self.stub(monkeypatch)
        assert frozen() == 0
        self.all_of_the_reference_arm()
        monkeypatch.setattr(trial, "committed_prefix",
                            lambda name: ("diverged", "not an extension"))
        assert trial.reference("t", str(tmp_path / "r.json")) == 2
        assert not (tmp_path / "r.json").exists()

    def test_an_existing_file_is_never_overwritten(self, trees, monkeypatch,
                                                   tmp_path):
        self.stub(monkeypatch)
        assert frozen() == 0
        self.all_of_the_reference_arm()
        target = tmp_path / "r.json"
        target.write_text("{}", encoding="utf-8")
        assert trial.reference("t", str(target)) == 2
        assert target.read_text(encoding="utf-8") == "{}"
        assert not [e for e in trial.read_ledger("t")
                    if e["kind"] == trial.REFERENCE]

    def test_a_file_with_no_ledger_line_is_not_a_dead_end(self, trees,
                                                          monkeypatch,
                                                          tmp_path):
        """The same two-writes problem the units have, found by asking of this
        command what Codex asked of those.

        Writing the file and appending its line cannot be one operation. A
        crash between them leaves a reference on disk that no line records —
        and every check above passes, because no `REFERENCE` line exists, so
        the run stopped at "already exists, not rewritten" for ever. The trial
        could never freeze a reference again.
        """
        self.stub(monkeypatch)
        assert frozen() == 0
        self.all_of_the_reference_arm()
        target = tmp_path / "r.json"
        # Exactly what the arm's rows build — that is the whole point of the
        # recovery: the interrupted freeze had already written this file.
        target.write_text(json.dumps({"comparable": ["one"], "missing": []}),
                          encoding="utf-8")

        assert trial.reference("t", str(target), recover=True) == 0
        recorded = [e for e in trial.read_ledger("t")
                    if e["kind"] == trial.REFERENCE]
        assert len(recorded) == 1
        assert recorded[0]["recovered"] is True
        assert recorded[0]["reference_digest"] == \
            experiment.digest_file(target)
        # Recorded, never rewritten: the bytes on disk are the ones the
        # interrupted freeze published, not a second rendering of them.
        assert json.loads(target.read_text(encoding="utf-8")) == {
            "comparable": ["one"], "missing": []}

    def test_recovering_a_reference_still_needs_the_arm_finished(
            self, trees, monkeypatch, tmp_path):
        """`--recover` accepts a file; it does not excuse a baseline built from
        part of its arm."""
        self.stub(monkeypatch)
        assert frozen() == 0
        step("t", 0)
        target = tmp_path / "r.json"
        target.write_text("{}", encoding="utf-8")
        assert trial.reference("t", str(target), recover=True) == 2
        assert not [e for e in trial.read_ledger("t")
                    if e["kind"] == trial.REFERENCE]

    def test_recovering_a_reference_is_refused_on_a_diverged_anchor(
            self, trees, monkeypatch, tmp_path):
        self.stub(monkeypatch)
        assert frozen() == 0
        self.all_of_the_reference_arm()
        target = tmp_path / "r.json"
        target.write_text("{}", encoding="utf-8")
        monkeypatch.setattr(trial, "committed_prefix",
                            lambda name: ("diverged", "not an extension"))
        assert trial.reference("t", str(target), recover=True) == 2
        assert not [e for e in trial.read_ledger("t")
                    if e["kind"] == trial.REFERENCE]


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
        # A real reference line names its file and the digest it was frozen
        # with, and `verify` checks the two against each other now.
        baseline = trial.home("t") / "reference.json"
        baseline.parent.mkdir(parents=True, exist_ok=True)
        baseline.write_text('{"comparable": []}', encoding="utf-8")
        append("t", {"kind": trial.REFERENCE, "after_units": 1,
                     "path": str(baseline),
                     "reference_digest": experiment.digest_file(baseline)})
        step("t", 1)
        _, _, _, problems = trial.verify("t")
        assert problems == [], problems

        path = trial.ledger_path("t")
        lines = path.read_text(encoding="utf-8").splitlines()
        path.write_text("\n".join(lines[:2] + lines[3:]) + "\n",
                        encoding="utf-8")
        _, _, _, problems = trial.verify("t")
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
        _, _, _, problems = trial.verify("t")
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
        _, _, _, problems = trial.verify("t")
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

    def test_a_rival_appending_while_a_review_is_bought_stops_this_run(
            self, trees, monkeypatch):
        """The window the conditional append exists for, driven through `run`
        rather than tested on `append` alone.

        A review takes minutes. Another process appending in that window used
        to be chained onto: this run's `done` line would follow a line it never
        read, and the two histories would interleave into one that neither
        process performed.
        """
        self.stub(monkeypatch)
        assert frozen() == 0

        def _buy(schedule, unit):
            trial.append("t", {"kind": trial.REFERENCE, "after_units": 0,
                               "reference_digest": "d" * 16})
            path = trial._result_path(schedule, unit)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("{}", encoding="utf-8")
            return 0

        monkeypatch.setattr(trial, "_buy", _buy)
        with pytest.raises(trial.TrialError) as caught:
            trial.run("t", 1, recover=False)
        assert "written against" in str(caught.value)

    def test_that_refusal_leaves_the_cli_with_exit_two(self, trees,
                                                       monkeypatch, capsys):
        """A traceback out of a tool that has just paid for a review reads as
        a crash rather than as the check working, and this repository does not
        answer "could not establish" with any other code."""
        self.stub(monkeypatch)
        assert frozen() == 0
        step("t", 0)
        lock = trial.ledger_path("t").with_suffix(".lock")
        lock.write_text("", encoding="utf-8")

        assert trial.main(["run", "t", "--steps", "1"]) == 2
        assert "refusing:" in capsys.readouterr().err

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


class TestTheLedgerIsWrittenByOneWriterWithOneRule:
    """Codex, 2026-09-06, after finding the same missing guard three times in
    this file and then being asked to enumerate every writer instead:
    *"`append()` supplies neither locking nor conditional append semantics,
    these are real race windows"*.

    Each caller was being fixed one at a time. The rule belongs in the writer.
    """

    def test_appending_onto_a_ledger_that_moved_is_refused(self, trees):
        assert frozen() == 0
        was = trial.ledger_state("t")
        step("t", 0)
        with pytest.raises(trial.TrialError) as caught:
            trial.append("t", {"kind": trial.REFERENCE, "after_units": 0},
                         after=was)
        assert "written against" in str(caught.value)

    def test_a_rewrite_that_keeps_the_record_count_is_refused(self, trees):
        """The class the counter could not see. Codex, 2026-09-06, sixth round
        on this file, after being asked to enumerate every byte mutation that
        leaves the parsed count unchanged: whitespace, key order, JSON escape
        spelling, CRLF, a trailing space before the newline, or a field nothing
        reads changed in the last line. Every one moves the file while
        `len(entries)` says it did not — so the writer compares the bytes."""
        assert frozen() == 0
        step("t", 0)
        was = trial.ledger_state("t")
        path = trial.ledger_path("t")
        lines = [json.loads(line) for line
                 in path.read_text(encoding="utf-8").splitlines()]
        # Same objects, same count, different bytes: re-rendered compactly,
        # where the writer leaves a space after each separator.
        path.write_text("".join(json.dumps(line, sort_keys=True,
                                           separators=(",", ":")) + "\n"
                                for line in lines), encoding="utf-8")
        assert len(trial.read_ledger("t")) == len(lines)

        with pytest.raises(trial.TrialError) as caught:
            trial.append("t", {"kind": trial.REFERENCE, "after_units": 1},
                         after=was)
        assert "written against" in str(caught.value)

    def test_an_unread_field_changed_in_the_last_line_is_refused(self, trees):
        """The other half of the same class: nothing hashes the final line,
        because nothing follows it, and schema validation does not reject an
        extra field. The whole-file digest does."""
        assert frozen() == 0
        step("t", 0)
        was = trial.ledger_state("t")
        path = trial.ledger_path("t")
        lines = path.read_text(encoding="utf-8").splitlines()
        last = json.loads(lines[-1])
        last["a_field_nobody_reads"] = "added"
        path.write_text("\n".join([*lines[:-1], json.dumps(last,
                                                           sort_keys=True)])
                        + "\n", encoding="utf-8")

        with pytest.raises(trial.TrialError):
            trial.append("t", {"kind": trial.REFERENCE, "after_units": 1},
                         after=was)

    def test_the_expected_length_is_optional_and_unchecked_when_absent(
            self, trees):
        """The tests that manufacture histories pass no `after`, and that is
        deliberate: they are building a state, not extending a known one."""
        assert frozen() == 0
        entry = trial.append("t", {"kind": trial.REFERENCE, "after_units": 0})
        assert entry["seq"] == 0

    def test_a_blank_line_is_a_mutation_the_counter_must_see(self, trees):
        """Codex, 2026-09-06, fourth round on this file.

        `read_ledger` skipped blank lines, so `after=N` compared N against the
        number of *records* rather than the file's length — and a blank line
        inserted between the read and the write moved the ledger while the
        conditional append passed anyway, chaining onto a file that had
        changed. A rule about a file's length has to be about the file.
        """
        assert frozen() == 0
        step("t", 0)
        path = trial.ledger_path("t")
        path.write_text(path.read_text(encoding="utf-8") + "\n",
                        encoding="utf-8")

        with pytest.raises(trial.TrialError) as caught:
            trial.append("t", {"kind": trial.REFERENCE, "after_units": 1},
                         after=2)
        assert "blank" in str(caught.value)

    def test_a_truncated_last_line_is_refused(self, trees):
        """The blank-line hole one byte along. Codex, 2026-09-06, fifth round:
        `splitlines()` gives the same record count whether the file ends with a
        newline or not, so `after=N` passed — and then append mode wrote the
        next object straight against the previous one, `}{`."""
        assert frozen() == 0
        step("t", 0)
        path = trial.ledger_path("t")
        path.write_text(path.read_text(encoding="utf-8").rstrip("\n"),
                        encoding="utf-8")

        with pytest.raises(trial.TrialError) as caught:
            trial.append("t", {"kind": trial.REFERENCE, "after_units": 1},
                         after=2)
        assert "newline" in str(caught.value)
        # And the file is still what it was: nothing joined two records.
        assert path.read_text(encoding="utf-8").count("{\"") == 2

    def test_a_blank_line_is_reported_by_verify_too(self, trees):
        assert frozen() == 0
        step("t", 0)
        path = trial.ledger_path("t")
        path.write_text("\n" + path.read_text(encoding="utf-8"),
                        encoding="utf-8")
        with pytest.raises(trial.TrialError):
            trial.verify("t")

    def test_a_left_over_lock_refuses_rather_than_writing(self, trees):
        """Two processes that both read a length of seven would both pass the
        conditional and both write line eight, so the read and the write are
        held together. A lock nobody released is named, not stepped over."""
        assert frozen() == 0
        lock = trial.ledger_path("t").with_suffix(".lock")
        lock.parent.mkdir(parents=True, exist_ok=True)
        lock.write_text("", encoding="utf-8")

        with pytest.raises(trial.TrialError) as caught:
            trial.append("t", {"kind": trial.REFERENCE, "after_units": 0})
        assert "another process is writing" in str(caught.value)
        assert trial.read_ledger("t") == []

    def test_the_lock_is_released_when_the_append_is_refused(self, trees):
        """A refusal that leaves the lock behind turns one race into a trial
        that can never be written to again."""
        assert frozen() == 0
        step("t", 0)
        with pytest.raises(trial.TrialError):
            trial.append("t", {"kind": trial.REFERENCE}, after=0)
        assert not trial.ledger_path("t").with_suffix(".lock").exists()
        trial.append("t", {"kind": trial.REFERENCE, "after_units": 1})


class TestTheFrozenBaselineIsCheckedAgainstItsLine:
    """Codex, 2026-09-06, eighth round, from an audit of every read-then-act in
    the file: the ledger recorded a path and a digest and nothing ever compared
    them again. A reference edited after the freeze passed every check here,
    and the comparison the trial exists for would have run against a baseline
    nobody recorded."""

    def frozen_reference(self, name="t", body='{"comparable": []}'):
        baseline = trial.home(name) / "reference.json"
        baseline.parent.mkdir(parents=True, exist_ok=True)
        baseline.write_text(body, encoding="utf-8")
        append(name, {"kind": trial.REFERENCE, "after_units": 1,
                      "path": str(baseline),
                      "reference_digest": experiment.digest_file(baseline)})
        return baseline

    def test_a_baseline_edited_after_the_freeze_is_caught(self, trees):
        assert frozen() == 0
        step("t", 0)
        baseline = self.frozen_reference()
        baseline.write_text('{"comparable": ["one"]}', encoding="utf-8")

        _, _, _, problems = trial.verify("t")
        assert any("different content than the freeze" in p
                   for p in problems), problems

    def test_a_baseline_that_is_gone_is_caught(self, trees):
        assert frozen() == 0
        step("t", 0)
        self.frozen_reference().unlink()
        _, _, _, problems = trial.verify("t")
        assert any("not at" in p for p in problems), problems

    def test_a_reference_line_with_no_path_is_caught(self, trees):
        assert frozen() == 0
        step("t", 0)
        append("t", {"kind": trial.REFERENCE, "after_units": 1,
                     "reference_digest": "d" * 16})
        _, _, _, problems = trial.verify("t")
        assert any("no path to it" in p for p in problems), problems

    def test_an_untouched_baseline_is_accepted(self, trees):
        assert frozen() == 0
        step("t", 0)
        self.frozen_reference()
        _, _, _, problems = trial.verify("t")
        assert problems == [], problems


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
        _, _, _, problems = trial.verify("t")     # reports, does not raise
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


class TestTwoArmsAreOneSuiteNotOneSequence:
    """The gate refused every input the tools can produce, and had since it
    was written.

    It compared `protocol.order` element by element. `experiment.build`
    shuffles with `random.Random(name)`, and the two arms must be two
    experiments, so two names, so two orders — matching only by accidental
    shuffle collision. Found 2026-09-07 while trying to run the trial the owner
    had made the priority.

    The sequence is also not what makes two arms comparable: `_buy` calls
    `experiment.run(..., only=unit["case_id"])`, so the arm's own order is
    checked for membership and filtered to one case, while the ledger, the
    reference and the comparator follow the trial's own `units`.
    """

    def manifest(self, tmp_path, arm, model, **overrides):
        directory = experiment.home(arm)
        directory.mkdir(parents=True, exist_ok=True)
        body = {
            "environment": dict(ENVIRONMENT, model_requested=model,
                                verifier_requested="claude-opus-5"),
            "protocol": {"order": list(CASES), "passes": ["a", "b"]},
            "suite": {"file": "suites/sentinel.yml", "digest": "f" * 16,
                      "count": len(CASES)},
            "cases": [{"case_id": c, "case_digest": "d" * 16,
                       "answer_key_digest": "k" * 16} for c in CASES],
        }
        body.update(overrides)
        (directory / "manifest.json").write_text(json.dumps(body),
                                                 encoding="utf-8")

    def test_different_sequences_over_the_same_cases_are_accepted(self, trees):
        """The defect, stated as the thing it blocked."""
        self.manifest(trees, "opus-arm", "claude-opus-5",
                      protocol={"order": list(CASES), "passes": ["a", "b"]})
        self.manifest(trees, "sonnet-arm", "claude-sonnet-5",
                      protocol={"order": list(reversed(CASES)),
                                "passes": ["a", "b"]})
        built = trial.build("t", "opus-arm", "sonnet-arm")
        assert sorted(built["cases"]) == sorted(CASES)

    def test_the_schedule_does_not_depend_on_which_arm_is_named_first(
            self, trees):
        """`units` shuffles the list it is given, and the list used to be
        whichever arm was passed first — so the same two arms produced two
        different schedules depending on the command line."""
        self.manifest(trees, "opus-arm", "claude-opus-5",
                      protocol={"order": list(CASES), "passes": ["a", "b"]})
        self.manifest(trees, "sonnet-arm", "claude-sonnet-5",
                      protocol={"order": list(reversed(CASES)),
                                "passes": ["a", "b"]})
        one = trial.build("t", "opus-arm", "sonnet-arm")
        assert one["cases"] == sorted(CASES)
        assert [u["case_id"] for u in one["units"]] == [
            u["case_id"] for u in trial.units(sorted(CASES), "t")]

    def test_different_suites_are_refused(self, trees):
        self.manifest(trees, "opus-arm", "claude-opus-5")
        self.manifest(trees, "sonnet-arm", "claude-sonnet-5",
                      suite={"file": "suites/other.yml", "digest": "e" * 16,
                             "count": len(CASES)})
        with pytest.raises(trial.TrialError, match="different suites"):
            trial.build("t", "opus-arm", "sonnet-arm")

    def test_equal_ids_over_different_content_are_refused(self, trees):
        """The strengthening Codex required over my own proposal: comparing
        the id sets alone would accept two arms whose cases have drifted."""
        self.manifest(trees, "opus-arm", "claude-opus-5")
        self.manifest(trees, "sonnet-arm", "claude-sonnet-5",
                      cases=[{"case_id": c, "case_digest": "z" * 16,
                              "answer_key_digest": "k" * 16} for c in CASES])
        with pytest.raises(trial.TrialError, match="different cases"):
            trial.build("t", "opus-arm", "sonnet-arm")

    def test_a_different_answer_key_is_refused(self, trees):
        self.manifest(trees, "opus-arm", "claude-opus-5")
        self.manifest(trees, "sonnet-arm", "claude-sonnet-5",
                      cases=[{"case_id": c, "case_digest": "d" * 16,
                              "answer_key_digest": "z" * 16} for c in CASES])
        with pytest.raises(trial.TrialError, match="different cases"):
            trial.build("t", "opus-arm", "sonnet-arm")

    def test_a_duplicate_case_is_refused_rather_than_collapsed(self, trees):
        """A set would have swallowed it, and the counts would then disagree
        with the schedule without anything saying so."""
        self.manifest(trees, "opus-arm", "claude-opus-5",
                      cases=[{"case_id": c, "case_digest": "d" * 16,
                              "answer_key_digest": "k" * 16}
                             for c in CASES + CASES[:1]])
        self.manifest(trees, "sonnet-arm", "claude-sonnet-5")
        with pytest.raises(trial.TrialError, match="twice"):
            trial.build("t", "opus-arm", "sonnet-arm")

    def test_a_manifest_with_no_suite_is_refused_not_crashed(self, trees):
        """"I could not check" is not "they match", and a `KeyError` raised
        from inside the comparison reports the failure far from its cause."""
        self.manifest(trees, "opus-arm", "claude-opus-5")
        directory = experiment.home("sonnet-arm")
        body = json.loads(
            (directory / "manifest.json").read_text(encoding="utf-8"))
        del body["suite"]
        (directory / "manifest.json").write_text(json.dumps(body),
                                                 encoding="utf-8")
        with pytest.raises(trial.TrialError, match="records no suite"):
            trial.build("t", "opus-arm", "sonnet-arm")


class TestTheSecondPassIsSecond:
    """The arms' manifests state the endpoint as "whether pass b's
    `pair_success` equals pass a's", over the question "do any cases give a
    different verdict in the second pass than in the first".

    A plain shuffle put 13 of the 26 arm/case combinations the other way round,
    so half the comparisons would have been the first pass against the second
    while claiming the reverse. Found by Codex on the gate before the first
    purchase, 2026-09-07 — one command before 104 member reviews.

    Rewriting the endpoint to say "two unordered replicates" was the other way
    out and is the wrong one: that is a preregistration, and changing what was
    written down to match what the code did is the failure this project records
    against itself.
    """

    def test_a_comes_before_b_for_every_arm_and_case(self):
        made = trial.units(["c{}".format(n) for n in range(13)], "seed")
        first = {}
        for unit in made:
            first.setdefault((unit["arm"], unit["case_id"]), unit["pass"])
        wrong = sorted(k for k, label in first.items() if label != "a")
        assert not wrong, (
            "{} of {} arm/case pairs run their second pass first: {}"
            .format(len(wrong), len(first), wrong[:5]))

    def test_it_holds_for_every_seed_that_was_tried(self):
        """One seed passing is a shuffle that happened to be in order. The
        constraint has to hold whatever the seed, or it is a coincidence."""
        for seed in ("a", "b", "sonnet-trial", "zzz", "2026-09-07"):
            made = trial.units(["c{}".format(n) for n in range(13)], seed)
            first = {}
            for unit in made:
                first.setdefault((unit["arm"], unit["case_id"]), unit["pass"])
            assert all(label == "a" for label in first.values()), seed

    def test_the_constraint_costs_the_shuffle_nothing(self):
        """**Swapped in place, not gathered**, and this is what tells them
        apart.

        The first version gave each pair the position of its earliest member
        and put the two adjacent. That threw away the second shuffled position
        and landed both passes of a case in nearly the same subscription
        window — measured, every pass gap became 1. Codex refused it on the
        gate before the first purchase.

        Swapping leaves both positions where the shuffle put them and only
        exchanges their contents, so every property of the plain shuffle
        survives. Measured over 200 seeds, the two agree on arm position, arm
        switches, and pass gap; they differ only in that 2583 pairs ran `b`
        first and now none do.
        """
        import random
        cases = ["c{}".format(n) for n in range(13)]

        def plain(seed):
            out = [{"case_id": c, "arm": a, "pass": p}
                   for c in cases for a in trial.ARMS for p in trial.PASSES]
            random.Random(seed).shuffle(out)
            return out

        def shape(made):
            arms = [u["arm"] for u in made]
            seen = {}
            for index, unit in enumerate(made):
                seen.setdefault((unit["arm"], unit["case_id"]), []).append(index)
            return (sum(1 for a, b in zip(arms, arms[1:]) if a != b),
                    sorted(abs(a - b) for a, b in seen.values()))

        for seed in ("a", "seed", "sonnet-trial", "2026-09-07"):
            assert shape(trial.units(cases, seed)) == shape(plain(seed)), seed

    def test_the_arms_still_interleave(self):
        """Named separately from the equality above, because a shuffle that
        happened to cluster would satisfy "same as the shuffle" and still be a
        bad schedule."""
        made = trial.units(["c{}".format(n) for n in range(13)], "seed")
        arms = [unit["arm"] for unit in made]
        switches = sum(1 for a, b in zip(arms, arms[1:]) if a != b)
        assert switches >= 8, (switches, arms[:12])

    def test_the_two_passes_of_a_case_are_not_forced_together(self):
        """The gather's own signature: every pair adjacent. If this comes back
        true, the schedule has stopped being a shuffle with a constraint and
        become a list of pairs."""
        made = trial.units(["c{}".format(n) for n in range(13)], "seed")
        seen = {}
        for index, unit in enumerate(made):
            seen.setdefault((unit["arm"], unit["case_id"]), []).append(index)
        gaps = [abs(a - b) for a, b in seen.values()]
        assert max(gaps) > 1, gaps

    def test_every_unit_is_still_there_exactly_once(self):
        """The reorder must not drop or duplicate one. 13 cases x 2 arms x 2
        passes, and a missing unit is a case measured in one arm only."""
        made = trial.units(["c{}".format(n) for n in range(13)], "seed")
        keys = [(u["arm"], u["case_id"], u["pass"]) for u in made]
        assert len(keys) == 52
        assert len(set(keys)) == 52
        assert [u["index"] for u in made] == list(range(52))


class TestTheScheduleBindsBytesNotNames:
    """The schedule recorded `experiment`, `model` and `verifier` per arm — the
    arm's *name*. A manifest, or a frozen prompt copy that `experiment.run`
    actually reads, could be edited after the schedule was frozen and nothing
    would notice: the schedule's own digest covers the schedule, and the
    environment digests cover the live tree rather than these copies.

    Codex found it on the gate before the first purchase, 2026-09-07.

    Checked in `verify`, so it runs before every spend — `run` and `reference`
    both come through there. The window that matters is between the freeze and
    the purchase, and a check that fires only when the schedule is written is a
    check about the wrong moment.
    """

    def frozen(self, trees):
        return trial.build("t", "opus-arm", "sonnet-arm")

    def prompts(self, arm, **files):
        directory = experiment.home(arm) / "prompts"
        directory.mkdir(parents=True, exist_ok=True)
        for name, body in files.items():
            (directory / name.replace("_", ".")).write_text(body,
                                                            encoding="utf-8")

    def test_the_bytes_are_recorded(self, trees):
        built = self.frozen(trees)
        for arm in ("opus", "sonnet"):
            assert built["arms"][arm]["manifest_digest"]
            # The three the fixture writes, which are the three a real freeze
            # copies. Asserted by name rather than by count: a count passes
            # while the wrong three are there.
            assert set(built["arms"][arm]["prompt_digests"]) == {
                "system.md", "verifier.md", "findings.schema.json"}

    def test_an_edited_manifest_is_caught(self, trees):
        self.prompts("opus-arm", system_md="a")
        self.prompts("sonnet-arm", system_md="a")
        built = self.frozen(trees)
        path = experiment.home("opus-arm") / "manifest.json"
        path.write_text(path.read_text(encoding="utf-8") + " ",
                        encoding="utf-8")
        moved = trial.arm_drift(built)
        assert any("manifest has changed" in m for m in moved), moved

    def test_an_edited_frozen_prompt_is_caught_and_named(self, trees):
        """Named, not counted. A reader told "something moved" cannot act; one
        told it was the verifier's brief can."""
        self.prompts("opus-arm", system_md="a", verifier_md="b")
        self.prompts("sonnet-arm", system_md="a", verifier_md="b")
        built = self.frozen(trees)
        path = experiment.home("opus-arm") / "prompts" / "verifier.md"
        path.write_text("b changed", encoding="utf-8")
        moved = trial.arm_drift(built)
        assert any("verifier.md" in m for m in moved), moved

    def test_a_lost_prompt_is_caught(self, trees):
        self.prompts("opus-arm", system_md="a", verifier_md="b")
        self.prompts("sonnet-arm", system_md="a", verifier_md="b")
        built = self.frozen(trees)
        (experiment.home("opus-arm") / "prompts" / "verifier.md").unlink()
        moved = trial.arm_drift(built)
        assert any("lost its frozen" in m for m in moved), moved

    def test_an_arm_with_no_frozen_prompts_is_refused_at_freeze(self, trees):
        """Not "nothing to compare": an arm whose instructions were never
        copied cannot say what its reviews would be bought against.

        The fixture writes them, so they are removed here — an arm frozen by
        an older `experiment.py`, which is exactly the case that must not pass
        quietly.
        """
        for entry in (experiment.home("opus-arm") / "prompts").iterdir():
            entry.unlink()
        (experiment.home("opus-arm") / "prompts").rmdir()
        with pytest.raises(trial.TrialError, match="no frozen prompt"):
            trial.build("t", "opus-arm", "sonnet-arm")

    def test_a_schedule_frozen_before_this_says_so(self, trees):
        """`arm_drift` walks what the schedule has. An older schedule carries
        no digests, and "there is nothing recorded to compare" must not read
        as "nothing has moved"."""
        self.prompts("opus-arm", system_md="a")
        self.prompts("sonnet-arm", system_md="a")
        built = self.frozen(trees)
        for arm in built["arms"].values():
            arm.pop("manifest_digest", None)
            arm.pop("prompt_digests", None)
        moved = trial.arm_drift(built)
        assert len(moved) == 2, moved
        assert all("before the manifest's bytes were recorded" in m
                   for m in moved), moved


class TestTheBytesAreCheckedAroundEveryPurchase:
    """`verify` checks the arms' bytes once per invocation, before the loop. A
    manifest or a frozen prompt could then change after that check and be
    consumed by a later unit unnoticed — and `experiment.run` compares the
    *live* prompt digests, not the frozen copies it supplies through
    `SECURITY_SCAN_PROMPT_DIR`, so it does not close the gap either.

    Even a single-unit invocation kept a check-then-use race. Codex, on the
    gate before the first purchase, 2026-09-07.

    The checks sit inside `_buy` rather than at its two call sites, because a
    check one caller can forget is a check that will be forgotten.
    """

    def ready(self, trees, monkeypatch):
        trial.freeze("t", "opus-arm", "sonnet-arm")
        schedule, _digest = trial.load_schedule("t")
        return schedule

    def test_a_manifest_that_moved_stops_the_purchase(self, trees,
                                                       monkeypatch):
        """Nothing is bought: `experiment.run` is replaced by something that
        fails the test if it is reached at all."""
        schedule = self.ready(trees, monkeypatch)
        path = experiment.home("opus-arm") / "manifest.json"
        path.write_text(path.read_text(encoding="utf-8") + " ",
                        encoding="utf-8")
        monkeypatch.setattr(
            experiment, "run",
            lambda *a, **k: pytest.fail("a review was bought after the "
                                        "manifest had moved"))
        unit = next(u for u in schedule["units"] if u["arm"] == "opus")
        assert trial._buy(schedule, unit) == 2

    def test_a_prompt_that_moves_during_the_purchase_stops_the_record(
            self, trees, monkeypatch):
        """The review is bought by then and cannot be unbought. What this
        establishes is whether the result may be recorded as this trial's — a
        row written under bytes that moved is a row about another instrument.
        """
        schedule = self.ready(trees, monkeypatch)
        path = experiment.home("opus-arm") / "prompts" / "system.md"

        def buy_and_move(*_a, **_k):
            path.write_text("something else", encoding="utf-8")
            return 0

        monkeypatch.setattr(experiment, "run", buy_and_move)
        unit = next(u for u in schedule["units"] if u["arm"] == "opus")
        assert trial._buy(schedule, unit) == 2

    def test_an_untouched_arm_buys_and_returns_what_run_said(self, trees,
                                                             monkeypatch):
        """The control. A check that refuses everything is not a check."""
        schedule = self.ready(trees, monkeypatch)
        monkeypatch.setattr(experiment, "run", lambda *a, **k: 0)
        unit = next(u for u in schedule["units"] if u["arm"] == "opus")
        assert trial._buy(schedule, unit) == 0

    def test_the_models_still_reach_the_environment(self, trees, monkeypatch):
        """The check must not have displaced what `_buy` was for: the arm's
        two models go into the environment before the review runs, so the
        ambient shell cannot decide which model is bought."""
        schedule = self.ready(trees, monkeypatch)
        seen = {}

        def record(*_a, **_k):
            seen["model"] = os.environ.get("SECURITY_SCAN_MODEL")
            seen["verifier"] = os.environ.get("SECURITY_SCAN_VERIFY_MODEL")
            return 0

        monkeypatch.setattr(experiment, "run", record)
        unit = next(u for u in schedule["units"] if u["arm"] == "sonnet")
        trial._buy(schedule, unit)
        assert seen["model"] == "claude-sonnet-5"
        assert seen["verifier"] == "claude-opus-5"


class TestARejectedResultIsMovedOutOfTheWay:
    """A unit whose arm's bytes moved *while it was being reviewed* is bought
    and unusable: the review was performed under an instrument that is not the
    frozen one, and putting the prompt back afterwards cannot make it valid.

    The after-check refused to record it and left it in the accepted `pass-*`
    directory, where the ledger held only `PREPARED` — indistinguishable from a
    crash after a good result. `--recover` would then admit the very result the
    check rejected, and an earlier version of the advice here *recommended*
    that. Codex, on the gate before the first purchase, 2026-09-07.

    So the result moves to `rejected/` with its reason beside it, and the unit
    is re-bought rather than rescued.
    """

    def ready(self, trees):
        trial.freeze("t", "opus-arm", "sonnet-arm")
        return trial.load_schedule("t")[0]

    def bought_then_moved(self, schedule, unit):
        def go(*_a, **_k):
            path = trial._result_path(schedule, unit)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('{"ok": true}', encoding="utf-8")
            manifest = experiment.home(
                schedule["arms"][unit["arm"]]["experiment"]) / "manifest.json"
            manifest.write_text(manifest.read_text(encoding="utf-8") + " ",
                                encoding="utf-8")
            return 0
        return go

    def test_the_result_leaves_the_accepted_directory(self, trees,
                                                      monkeypatch):
        schedule = self.ready(trees)
        unit = schedule["units"][0]
        monkeypatch.setattr(experiment, "run",
                            self.bought_then_moved(schedule, unit))
        assert trial._buy(schedule, unit) == 2
        assert not trial._result_path(schedule, unit).exists()

    def test_it_is_kept_with_the_reason_beside_it(self, trees, monkeypatch):
        """Kept, not deleted: it was paid for, and a reader asking what
        happened needs the thing itself as well as the sentence."""
        schedule = self.ready(trees)
        unit = schedule["units"][0]
        monkeypatch.setattr(experiment, "run",
                            self.bought_then_moved(schedule, unit))
        trial._buy(schedule, unit)
        arm = experiment.home(schedule["arms"][unit["arm"]]["experiment"])
        kept = sorted((arm / "rejected").iterdir())
        assert len(kept) == 2, kept
        why = next(p for p in kept if p.name.endswith(".why.txt"))
        assert "manifest has changed" in why.read_text(encoding="utf-8")

    def test_the_advice_does_not_point_at_recover(self, trees, monkeypatch,
                                                  capsys):
        """The defect this class replaced. An earlier version told the
        operator to take the rejected result with `--recover`, which is the one
        thing that must not happen to it."""
        schedule = self.ready(trees)
        unit = schedule["units"][0]
        monkeypatch.setattr(experiment, "run",
                            self.bought_then_moved(schedule, unit))
        trial.run("t", steps=1, recover=False)
        said = capsys.readouterr()
        assert "--recover" not in (said.out + said.err), said.err[-400:]

    def test_a_second_failed_attempt_does_not_erase_the_first(self, trees,
                                                              monkeypatch):
        """The unit stays open, so a retry is expected — and the first version
        used one deterministic name per unit, so the retry's quarantine
        replaced the first one. Two paid reviews, one surviving record, and
        nothing saying the other had existed.

        Codex, on the gate before the first purchase, 2026-09-07.
        """
        schedule = self.ready(trees)
        unit = schedule["units"][0]
        arm_home = experiment.home(
            schedule["arms"][unit["arm"]]["experiment"])

        # The manifest is put back between the attempts, which is what an
        # operator does: something moved, they restore it, they run again. The
        # before-check then passes and the second review is bought — and if it
        # fails the after-check too, its quarantine must not overwrite the
        # first one.
        manifest = arm_home / "manifest.json"

        def buy(body):
            def go(*_a, **_k):
                path = trial._result_path(schedule, unit)
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(body, encoding="utf-8")
                manifest.write_text(
                    manifest.read_text(encoding="utf-8") + " ",
                    encoding="utf-8")
                return 0
            return go

        good = manifest.read_text(encoding="utf-8")
        monkeypatch.setattr(experiment, "run", buy('{"attempt": 1}'))
        trial._buy(schedule, unit)
        manifest.write_text(good, encoding="utf-8")
        monkeypatch.setattr(experiment, "run", buy('{"attempt": 2}'))
        trial._buy(schedule, unit)

        kept = sorted(p for p in (arm_home / "rejected").iterdir()
                      if p.suffix == ".json")
        assert len(kept) == 2, [p.name for p in kept]
        bodies = sorted(p.read_text(encoding="utf-8") for p in kept)
        assert bodies == ['{"attempt": 1}', '{"attempt": 2}'], bodies

    def test_two_identical_results_do_not_multiply(self, trees, monkeypatch):
        """The name is the digest, so a retry that produced the same bytes is
        the same file — kept once, which is the truth about it."""
        schedule = self.ready(trees)
        unit = schedule["units"][0]
        arm_home = experiment.home(
            schedule["arms"][unit["arm"]]["experiment"])

        manifest = arm_home / "manifest.json"

        def go(*_a, **_k):
            path = trial._result_path(schedule, unit)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('{"same": true}', encoding="utf-8")
            manifest.write_text(manifest.read_text(encoding="utf-8") + " ",
                                encoding="utf-8")
            return 0

        good = manifest.read_text(encoding="utf-8")
        monkeypatch.setattr(experiment, "run", go)
        trial._buy(schedule, unit)
        manifest.write_text(good, encoding="utf-8")
        trial._buy(schedule, unit)
        kept = [p for p in (arm_home / "rejected").iterdir()
                if p.suffix == ".json"]
        assert len(kept) == 1, [p.name for p in kept]

    def test_one_result_under_two_reasons_keeps_both(self, trees,
                                                     monkeypatch):
        """The digest names the result, and the reason was written beside it —
        so a retry that produced the same bytes under a *different* drift
        replaced the first reason. The result looked untouched and half the
        audit history was gone. Codex, fifth gate round, 2026-09-07.

        The two attempts move different things: the manifest first, then a
        frozen prompt. Same result, two reasons, and both have to survive.
        """
        schedule = self.ready(trees)
        unit = schedule["units"][0]
        arm_home = experiment.home(
            schedule["arms"][unit["arm"]]["experiment"])
        manifest = arm_home / "manifest.json"
        prompt = arm_home / "prompts" / "system.md"

        def buy(move):
            def go(*_a, **_k):
                path = trial._result_path(schedule, unit)
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('{"identical": true}', encoding="utf-8")
                move()
                return 0
            return go

        good_manifest = manifest.read_text(encoding="utf-8")
        good_prompt = prompt.read_text(encoding="utf-8")

        monkeypatch.setattr(experiment, "run", buy(
            lambda: manifest.write_text(good_manifest + " ", encoding="utf-8")))
        trial._buy(schedule, unit)
        manifest.write_text(good_manifest, encoding="utf-8")

        monkeypatch.setattr(experiment, "run", buy(
            lambda: prompt.write_text(good_prompt + "x", encoding="utf-8")))
        trial._buy(schedule, unit)

        reasons = sorted((arm_home / "rejected").glob("*.why.txt"))
        assert len(reasons) == 2, [p.name for p in reasons]
        said = " ".join(p.read_text(encoding="utf-8") for p in reasons)
        assert "manifest has changed" in said, said
        assert "system.md has changed" in said, said

    def test_the_ledger_has_no_kind_it_cannot_write(self):
        """A constant without a writer is a name for a state the chain cannot
        carry, and a reader takes it for one it can. `REJECTED` was defined and
        never appended; the open `PREPARED` row and the quarantined files are
        what the design actually says."""
        assert not hasattr(trial, "REJECTED")

    def test_a_review_that_never_ran_leaves_nothing_behind(self, trees,
                                                           monkeypatch):
        """The control: no result, so nothing to quarantine, and the unit is
        simply open."""
        schedule = self.ready(trees)
        unit = schedule["units"][0]
        monkeypatch.setattr(experiment, "run", lambda *a, **k: 2)
        assert trial._buy(schedule, unit) == 2
        arm = experiment.home(schedule["arms"][unit["arm"]]["experiment"])
        assert not (arm / "rejected").exists()


class TestStatusSaysWhichCommandTakesTheResult:
    """`status` said an open unit with a result on disk would be recorded by
    "a resume". The recovery path is behind `--recover`, so an operator
    reading that runs `run` and gets the branch that buys the review again.

    Codex, on the gate before the first purchase, 2026-09-07 — the same round
    that found the advice inside `run` pointing at `--recover` for a result
    that must never be recovered. The two lines were wrong in opposite
    directions, and money sits under both.
    """

    def opened(self, trees, with_result):
        trial.freeze("t", "opus-arm", "sonnet-arm")
        schedule, digest = trial.load_schedule("t")
        unit = schedule["units"][0]
        trial.append("t", {"kind": trial.PREPARED, "index": 0,
                           "schedule_digest": digest},
                     after=trial.ledger_state("t"))
        if with_result:
            path = trial._result_path(schedule, unit)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("{}", encoding="utf-8")
        return schedule

    def test_a_result_on_disk_names_the_flag(self, trees, capsys):
        self.opened(trees, with_result=True)
        trial.status("t")
        said = capsys.readouterr().out
        assert "--recover" in said, said
        assert "buys the review again" in said, said

    def test_no_result_says_a_resume_re_runs_it(self, trees, capsys):
        """The control: without a result there is nothing to recover, and a
        plain resume is the right advice."""
        self.opened(trees, with_result=False)
        trial.status("t")
        said = capsys.readouterr().out
        assert "a resume re-runs it" in said, said
        assert "--recover" not in said, said
