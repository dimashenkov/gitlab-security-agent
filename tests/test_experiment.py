"""The rule is written before the money, or the money buys reviews and no answer.

Two passes over the same suite only answer "does it move on its own" if it was
decided in advance which pass-b row answers which pass-a row, what counts as a
disagreement, and what happens when a case is missing from one side. Decide any
of those afterwards, once the disagreements are on the screen, and the rule gets
fitted to them.

The tool went through five rounds of adversarial review and twenty defects, and
the last of them settled its present shape: a result produced while conditions
had changed was refused on the terminal and left on disk, where a later resume
counted it as an ordinary verdict. The transaction belonged to the experiment
and the write belonged to the queue. It writes its own results now.

Each test names the defect it holds, because a test whose reason is not written
down is a test somebody deletes when it becomes inconvenient.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import experiment


@pytest.fixture
def world(tmp_path, monkeypatch):
    """A repository-shaped tree with two cases and a suite naming them."""
    root = tmp_path
    (root / "corpus-real").mkdir()
    (root / "suites").mkdir()
    (root / "prompts").mkdir()
    (root / "tools").mkdir()
    (root / "src" / "security_agent").mkdir(parents=True)
    (root / "src" / "security_agent" / "__init__.py").write_text(
        '__version__ = "0.1.0"\n', encoding="utf-8")
    for name in ("system.md", "verifier.md", "findings.schema.json"):
        (root / "prompts" / name).write_text("{}\n".format(name), encoding="utf-8")
    for name in ("pair_corpus.py", "artifact.py", "check_accounted.py"):
        (root / "tools" / name).write_text("# {}\n".format(name), encoding="utf-8")
    (root / "corpus-real" / "adjudications.yml").write_text("{}\n", encoding="utf-8")

    for case_id, language in (("go-a", "go"), ("py-a", "python")):
        directory = root / "corpus-real" / case_id
        directory.mkdir()
        (directory / "case.yml").write_text(
            "case_id: {}\nlanguage: {}\nconstruction: regression\n".format(
                case_id, language), encoding="utf-8")
        (directory / "safe").mkdir()
        (directory / "safe" / "app.txt").write_text("safe\n", encoding="utf-8")

    suite = root / "suites" / "sentinel.yml"
    suite.write_text("cases:\n  - go-a   # pass\n  - py-a   # fail\n",
                     encoding="utf-8")

    monkeypatch.setattr(experiment, "ROOT", root)
    monkeypatch.setattr(experiment, "SUITE", suite)
    monkeypatch.setattr(experiment.round_tool, "ROOT", root)
    return root


def frozen_digest(root: Path, case_id: str) -> str:
    body = json.loads(
        (root / "measurements" / "experiment-e" / "manifest.json")
        .read_text(encoding="utf-8"))
    return {row["case_id"]: row["case_digest"] for row in body["cases"]}[case_id]


def row(case_id: str, digest: str, passed) -> dict:
    return {"case_id": case_id, "case_digest": digest, "pair_success": passed}


def accept(root: Path, label: str, body: dict, case_id: str = "") -> None:
    """Publish one accepted result into a pass, the way `run` does."""
    directory = root / "measurements" / "experiment-e" / "pass-{}".format(label)
    directory.mkdir(parents=True, exist_ok=True)
    name = case_id or body["case_id"]
    (directory / "{}.json".format(name)).write_text(
        json.dumps(body), encoding="utf-8")


def failing_write(nth: int, partial: bool = False):
    """A `Path.write_text` that fails once, on the nth call, then behaves.

    Self-disarming on purpose: reaching for `monkeypatch.undo()` to restore it
    reverts every patch that object made, the fixture's redirection of this tool
    onto a temporary tree included. That is not hypothetical — it happened, and
    the second freeze wrote three manifests into the real repository.
    """
    real = Path.write_text
    calls = {"n": 0, "fired": False}

    def write(self, *args, **kwargs):
        calls["n"] += 1
        if calls["n"] == nth and not calls["fired"]:
            calls["fired"] = True
            if partial:
                real(self, "half a file")
            raise OSError("disk full")
        return real(self, *args, **kwargs)

    return write


class TestTheFreeze:
    def test_the_endpoint_is_written_before_anything_runs(self, world):
        experiment.freeze("e", dry_run=False)
        body = json.loads((world / "measurements" / "experiment-e"
                           / "manifest.json").read_text())

        protocol = body["protocol"]
        assert "pair_success" in protocol["primary_endpoint"]
        assert "case_digest" in protocol["comparable"]
        assert "incomplete" in protocol["missing"]

    def test_one_order_serves_both_passes(self, world):
        """A different order per pass means the two met the subscription's
        windows differently, and the comparison would carry that too."""
        experiment.freeze("e", dry_run=False)
        body = json.loads((world / "measurements" / "experiment-e"
                           / "manifest.json").read_text())

        assert sorted(body["protocol"]["order"]) == ["go-a", "py-a"]
        assert body["protocol"]["passes"] == ["a", "b"]

    def test_it_says_what_it_cannot_answer(self, world):
        """Two throws of a coin that land differently prove the coin is not
        glued. They do not say how often it lands heads."""
        experiment.freeze("e", dry_run=False)
        body = json.loads((world / "measurements" / "experiment-e"
                           / "manifest.json").read_text())

        assert "do not estimate its rate" in body["protocol"]["not_answerable"]

    def test_a_frozen_experiment_is_not_rewritten(self, world):
        experiment.freeze("e", dry_run=False)

        assert experiment.freeze("e", dry_run=False) == 1

    def test_a_dry_run_writes_nothing(self, world):
        experiment.freeze("e", dry_run=True)

        assert not (world / "measurements" / "experiment-e").exists()


class TestAnEmptySuiteIsNotAnExperiment:
    """A suite naming no case ran the whole tool and reported that it had not
    moved.

    `sentinel.read_cases` recognises only lines beginning with `- `. Rewrite
    the suite as a YAML flow list — `cases: [go-a, py-a]`, legal and meaning
    the same thing — and it selects nothing. `freeze` then wrote a manifest
    with `counts.cases: 0`, `verify` reported nothing had moved over 0 cases,
    `run` reported nothing left in this pass, and `compare` printed "No
    movement observed in one paired repetition" and exited 0. Zero reviews
    bought, reported as a suite that did not move. `sentinel.main` refuses an
    empty selection with exit 2; this had no equivalent.
    """

    @pytest.fixture
    def flow_list(self, world):
        (world / "suites" / "sentinel.yml").write_text(
            "cases: [go-a, py-a]\n", encoding="utf-8")
        return world

    def test_the_suite_still_parses_as_yaml_and_still_names_nothing(
            self, flow_list):
        import yaml
        from sentinel import read_cases

        text = (flow_list / "suites" / "sentinel.yml").read_text()
        assert yaml.safe_load(text)["cases"] == ["go-a", "py-a"]
        assert read_cases(flow_list / "suites" / "sentinel.yml") == []

    def test_freezing_over_no_case_is_refused(self, flow_list, capsys):
        assert experiment.freeze("e", dry_run=False) == 2
        assert "names no case" in capsys.readouterr().err
        assert not (flow_list / "measurements" / "experiment-e"
                    / "manifest.json").exists()

    def test_a_manifest_already_frozen_over_no_case_is_refused(
            self, world, capsys):
        """One frozen before `freeze` learned to refuse is still on disk, and
        every command that reads it would otherwise succeed over nothing."""
        experiment.freeze("e", dry_run=False)
        path = world / "measurements" / "experiment-e" / "manifest.json"
        body = json.loads(path.read_text())
        body["cases"] = []
        body["protocol"]["order"] = []
        path.write_text(json.dumps(body), encoding="utf-8")

        assert experiment.verify("e") == 2
        assert experiment.run("e", "a", None) == 2
        assert experiment.compare("e") == 2
        err = capsys.readouterr().err
        assert "frozen with no cases" in err
        assert "never frozen" not in err

    def test_no_movement_is_never_printed_over_no_case(self, world, capsys):
        experiment.freeze("e", dry_run=False)
        path = world / "measurements" / "experiment-e" / "manifest.json"
        body = json.loads(path.read_text())
        body["cases"] = []
        path.write_text(json.dumps(body), encoding="utf-8")

        experiment.compare("e")
        assert "No movement observed" not in capsys.readouterr().out


class TestPublishing:
    """Every file this tool writes goes through one function, and these are its
    properties. Three separate defects lived here before it existed."""

    def test_a_failed_write_leaves_nothing_behind(self, world, monkeypatch):
        monkeypatch.setattr(Path, "write_text", failing_write(1, partial=True))

        assert experiment.freeze("e", dry_run=False) == 2
        assert not (world / "measurements" / "experiment-e"
                    / "manifest.json").exists()
        assert not list((world / "measurements").rglob("*.writing.*"))

    def test_a_failed_freeze_can_be_frozen_again(self, world, monkeypatch):
        """The consequence that made the first rollback worse than none: the
        leftover file made `freeze` refuse for ever after."""
        monkeypatch.setattr(Path, "write_text", failing_write(1))
        assert experiment.freeze("e", dry_run=False) == 2

        assert experiment.freeze("e", dry_run=False) == 0

    def test_it_does_not_overwrite_a_file_that_appeared(self, world):
        """`replace` overwrites, and an existence check at the top of a command
        is a check about an earlier moment. The rollback was taught not to
        delete a file it did not create; publishing had to be taught not to
        destroy one either, or the race was only half closed — which is worse
        than consistently open, because the careful half reads as a guarantee.
        """
        target = world / "measurements" / "experiment-e" / "manifest.json"
        target.parent.mkdir(parents=True)
        target.write_text("someone else's file", encoding="utf-8")

        assert experiment.publish(target, "ours") is False
        assert target.read_text() == "someone else's file"

    def test_staging_files_carry_the_process_that_made_them(self, world,
                                                            monkeypatch):
        """A fixed staging name lets two runs write over each other's and then
        remove them in each other's cleanup."""
        seen = []
        real = Path.write_text

        def write(self, *args, **kwargs):
            seen.append(self.name)
            return real(self, *args, **kwargs)

        monkeypatch.setattr(Path, "write_text", write)
        experiment.freeze("e", dry_run=False)

        staging = [name for name in seen if ".writing." in name]
        assert staging
        assert all(name.endswith(str(os.getpid())) for name in staging)


class TestVerifyFailsClosed:
    """Checked immediately before spending, because checking afterwards proves
    nothing: a change made and reverted between the passes leaves the files
    looking untouched."""

    def test_an_untouched_tree_passes(self, world):
        experiment.freeze("e", dry_run=False)

        assert experiment.verify("e") == 0

    def test_an_edited_case_refuses(self, world, capsys):
        experiment.freeze("e", dry_run=False)
        (world / "corpus-real" / "go-a" / "safe" / "app.txt").write_text("edited\n")

        assert experiment.verify("e") == 2
        assert "go-a: the case has been edited" in capsys.readouterr().out

    def test_a_deleted_case_refuses(self, world, capsys):
        experiment.freeze("e", dry_run=False)
        (world / "corpus-real" / "go-a" / "safe" / "app.txt").unlink()
        (world / "corpus-real" / "go-a" / "safe").rmdir()
        (world / "corpus-real" / "go-a" / "case.yml").unlink()
        (world / "corpus-real" / "go-a").rmdir()

        assert experiment.verify("e") == 2
        assert "the case is gone" in capsys.readouterr().out

    def test_an_edited_prompt_refuses(self, world, capsys):
        experiment.freeze("e", dry_run=False)
        (world / "prompts" / "system.md").write_text("rewritten\n")

        assert experiment.verify("e") == 2
        assert "system_prompt" in capsys.readouterr().out

    def test_a_rewritten_suite_refuses(self, world, capsys):
        """The suite file is the question. Rewriting it between the passes
        changes what was asked, not what was answered."""
        experiment.freeze("e", dry_run=False)
        (world / "suites" / "sentinel.yml").write_text(
            "cases:\n  - go-a   # pass\n", encoding="utf-8")

        assert experiment.verify("e") == 2
        assert "suite file has been rewritten" in capsys.readouterr().out

    def test_a_changed_adjudication_refuses(self, world, capsys):
        """Not part of what the reviewer sees, and part of what its answer
        means: a ruling added between the passes rescores a verdict without
        rerunning anything."""
        experiment.freeze("e", dry_run=False)
        (world / "corpus-real" / "adjudications.yml").write_text("go-a: real\n")

        assert experiment.verify("e") == 2
        assert "adjudications" in capsys.readouterr().out

    def test_editing_the_answer_key_refuses(self, world, capsys):
        """`case_digest` covers the members and deliberately not `case.yml`, so
        changing `expected_category` between the passes leaves the code the
        agent saw identical and changes how its findings are scored. Every flip
        it caused would have been reported as the product moving."""
        experiment.freeze("e", dry_run=False)
        (world / "corpus-real" / "go-a" / "case.yml").write_text(
            "case_id: go-a\nlanguage: go\nconstruction: regression\n"
            "expected_category: xss\n", encoding="utf-8")

        assert experiment.verify("e") == 2
        assert "answer key in case.yml" in capsys.readouterr().out

    def test_an_edited_scorer_refuses(self, world, capsys):
        """`agent_version` moves when somebody bumps it. The code that turns
        findings into `pair_success` is edited far more often, and a flip it
        caused would carry no fingerprint at all."""
        experiment.freeze("e", dry_run=False)
        (world / "tools" / "pair_corpus.py").write_text("# edited\n")

        assert experiment.verify("e") == 2
        assert "scorer" in capsys.readouterr().out

    def test_an_edited_reviewer_refuses(self, world, capsys):
        """The reviewer's source, not its version string: nothing forces a
        bump, so two passes could run different code."""
        experiment.freeze("e", dry_run=False)
        (world / "src" / "security_agent" / "agent.py").write_text(
            "# edited, version untouched\n", encoding="utf-8")

        assert experiment.verify("e") == 2
        assert "reviewer" in capsys.readouterr().out


class TestRunning:
    """The half that spends, and the reason the tool stopped driving the queue:
    a result is published only after the conditions are checked again."""

    def test_it_publishes_one_file_per_case(self, world, monkeypatch):
        experiment.freeze("e", dry_run=False)
        import pair_corpus

        monkeypatch.setattr(pair_corpus, "run_case", lambda case, **kw: {
            "case_id": case["case_id"], "pair_success": True,
            "case_digest": frozen_digest(world, case["case_id"])})

        assert experiment.run("e", "a", None) == 0
        assert sorted(experiment.accepted("e", "a")) == ["go-a", "py-a"]

    def test_a_change_while_a_case_ran_discards_that_result(
            self, world, monkeypatch, capsys):
        """The defect that decided this tool's shape. The previous design let
        the queue write the result before the check; when the check then found
        a change, it said so on the terminal and left the file on disk, where a
        later resume counted it as an ordinary verdict.
        """
        experiment.freeze("e", dry_run=False)
        import pair_corpus

        def fake(case, **kwargs):
            # Something moves while the review is running.
            (world / "prompts" / "system.md").write_text("changed mid-run\n")
            return {"case_id": case["case_id"], "pair_success": True,
                    "case_digest": frozen_digest(world, case["case_id"])}

        monkeypatch.setattr(pair_corpus, "run_case", fake)

        assert experiment.run("e", "a", None) == 2
        assert experiment.accepted("e", "a") == {}
        assert "discarded" in capsys.readouterr().out

    def test_a_change_before_a_case_stops_without_spending(
            self, world, monkeypatch, capsys):
        experiment.freeze("e", dry_run=False)
        import pair_corpus

        called = []
        monkeypatch.setattr(pair_corpus, "run_case",
                            lambda case, **kw: called.append(case) or {})
        (world / "prompts" / "system.md").write_text("changed before\n")

        assert experiment.run("e", "a", None) == 2
        assert called == []
        assert "moved since the freeze" in capsys.readouterr().out

    def test_it_resumes_from_what_was_accepted(self, world, monkeypatch):
        """Re-running the command continues; it does not repeat. The whole
        resume machinery the queue provided reduces to this."""
        experiment.freeze("e", dry_run=False)
        accept(world, "a", row("go-a", frozen_digest(world, "go-a"), True))

        import pair_corpus
        ran = []

        def fake(case, **kwargs):
            ran.append(case["case_id"])
            return {"case_id": case["case_id"], "pair_success": True,
                    "case_digest": frozen_digest(world, case["case_id"])}

        monkeypatch.setattr(pair_corpus, "run_case", fake)
        experiment.run("e", "a", None)

        assert ran == ["py-a"]

    def test_it_stops_after_the_requested_number(self, world, monkeypatch):
        experiment.freeze("e", dry_run=False)
        import pair_corpus

        monkeypatch.setattr(pair_corpus, "run_case", lambda case, **kw: {
            "case_id": case["case_id"], "pair_success": True,
            "case_digest": frozen_digest(world, case["case_id"])})

        experiment.run("e", "a", 1)

        assert len(experiment.accepted("e", "a")) == 1

    def test_an_unknown_pass_is_refused(self, world):
        experiment.freeze("e", dry_run=False)

        assert experiment.run("e", "c", None) == 2


class TestTheModelIsPartOfTheFreeze:
    """The defect: `freeze` records what produced the experiment and did not
    record *which model would answer*, so the two paid `run` commands were free
    to ask a different one.

    What it cost: the plan for the Sonnet gate was written as

        SECURITY_SCAN_MODEL=claude-sonnet-5 tools/experiment.py freeze …
        tools/experiment.py run … a
        tools/experiment.py run … b

    and the variable applies only to `freeze`, which spends nothing. Both `run`
    commands would have read an environment with no such variable, defaulted to
    `claude-opus-5` — the reference's own model — and bought 52 reviews of the
    model the experiment exists to replace. Nothing between the freeze and the
    comparator would have said a word, and the comparator only runs after the
    money is gone.
    """

    def test_the_freeze_records_the_model_and_the_verifier(
            self, world, monkeypatch):
        monkeypatch.setenv("SECURITY_SCAN_MODEL", "claude-sonnet-5")
        experiment.freeze("e", dry_run=False)

        body = json.loads((world / "measurements" / "experiment-e"
                           / "manifest.json").read_text(encoding="utf-8"))

        assert body["environment"]["model_requested"] == "claude-sonnet-5"
        # Unset means *the reviewer's own model*, not "none" — resolved the way
        # the reviewer resolves it rather than read raw.
        assert body["environment"]["verifier_requested"] == "claude-sonnet-5"
        assert body["environment"]["verify"] == "on"

    def test_a_pass_run_without_the_variable_stops_before_spending(
            self, world, monkeypatch, capsys):
        monkeypatch.setenv("SECURITY_SCAN_MODEL", "claude-sonnet-5")
        experiment.freeze("e", dry_run=False)

        import pair_corpus
        called = []
        monkeypatch.setattr(pair_corpus, "run_case",
                            lambda case, **kw: called.append(case) or {})
        # The next shell — the one that pays — has no such variable.
        monkeypatch.delenv("SECURITY_SCAN_MODEL")

        assert experiment.run("e", "a", None) == 2
        assert called == []
        out = capsys.readouterr().out
        assert "moved since the freeze" in out
        assert "model_requested" in out

    def test_a_different_verifier_stops_before_spending(
            self, world, monkeypatch, capsys):
        """The reviewer and the verifier are two choices, and swapping only the
        second one changes what the comparison measures just as surely."""
        monkeypatch.setenv("SECURITY_SCAN_MODEL", "claude-sonnet-5")
        experiment.freeze("e", dry_run=False)

        import pair_corpus
        called = []
        monkeypatch.setattr(pair_corpus, "run_case",
                            lambda case, **kw: called.append(case) or {})
        monkeypatch.setenv("SECURITY_SCAN_VERIFY_MODEL", "claude-opus-5")

        assert experiment.run("e", "a", None) == 2
        assert called == []
        assert "verifier_requested" in capsys.readouterr().out

    def test_verification_switched_off_stops_before_spending(
            self, world, monkeypatch, capsys):
        monkeypatch.setenv("SECURITY_SCAN_MODEL", "claude-sonnet-5")
        experiment.freeze("e", dry_run=False)

        import pair_corpus
        called = []
        monkeypatch.setattr(pair_corpus, "run_case",
                            lambda case, **kw: called.append(case) or {})
        monkeypatch.setenv("SECURITY_SCAN_VERIFY", "false")

        assert experiment.run("e", "a", None) == 2
        assert called == []

    def test_a_manifest_that_never_named_a_model_is_refused(
            self, world, monkeypatch, capsys):
        """Absence is not agreement. `drift` walks the keys the manifest *has*,
        so an experiment frozen before this record existed would be checked
        against nothing and read as agreeing with any shell at all.
        """
        experiment.freeze("e", dry_run=False)
        path = world / "measurements" / "experiment-e" / "manifest.json"
        body = json.loads(path.read_text(encoding="utf-8"))
        for key in ("model_requested", "verifier_requested", "verify"):
            body["environment"].pop(key)
        path.write_text(json.dumps(body), encoding="utf-8")

        import pair_corpus
        called = []
        monkeypatch.setattr(pair_corpus, "run_case",
                            lambda case, **kw: called.append(case) or {})

        assert experiment.run("e", "a", None) == 2
        assert called == []
        assert "before the model was recorded" in capsys.readouterr().out


class TestTheComparison:
    def test_agreement_and_a_flip_are_counted_and_named(self, world, capsys):
        experiment.freeze("e", dry_run=False)
        go, py = frozen_digest(world, "go-a"), frozen_digest(world, "py-a")
        accept(world, "a", row("go-a", go, True))
        accept(world, "a", row("py-a", py, True))
        accept(world, "b", row("go-a", go, True))
        accept(world, "b", row("py-a", py, False))

        assert experiment.compare("e") == 0
        out = capsys.readouterr().out
        assert "agreed with itself: 1" in out
        assert "flipped:            1" in out
        assert "py-a: pass -> fail" in out

    def test_a_flip_is_the_finding_not_a_failure(self, world, capsys):
        """Exiting non-zero on movement would make the answer the experiment
        was bought to produce look like a broken run."""
        experiment.freeze("e", dry_run=False)
        go, py = frozen_digest(world, "go-a"), frozen_digest(world, "py-a")
        accept(world, "a", row("go-a", go, True))
        accept(world, "a", row("py-a", py, True))
        accept(world, "b", row("go-a", go, False))
        accept(world, "b", row("py-a", py, True))

        assert experiment.compare("e") == 0
        assert "moves on its own" in capsys.readouterr().out

    def test_a_missing_verdict_makes_it_incomplete(self, world, capsys):
        """A partial pair is not evidence of agreement."""
        experiment.freeze("e", dry_run=False)
        go, py = frozen_digest(world, "go-a"), frozen_digest(world, "py-a")
        accept(world, "a", row("go-a", go, True))
        accept(world, "a", row("py-a", py, True))
        accept(world, "b", row("go-a", go, True))

        assert experiment.compare("e") == 2
        assert "no comparable pair" in capsys.readouterr().out

    def test_a_row_about_another_version_is_not_a_verdict(self, world, capsys):
        """The defect that abandoned round 1: a result whose case digest does
        not match is a verdict about a different case."""
        experiment.freeze("e", dry_run=False)
        go, py = frozen_digest(world, "go-a"), frozen_digest(world, "py-a")
        accept(world, "a", row("go-a", go, True))
        accept(world, "a", row("py-a", py, True))
        accept(world, "b", row("go-a", "0000", True))
        accept(world, "b", row("py-a", py, True))

        assert experiment.compare("e") == 2
        assert "wrong-version" in capsys.readouterr().out

    def test_a_verdict_that_is_not_a_boolean_is_not_a_verdict(
            self, world, capsys):
        """`"false"` is a non-empty string and would have read as a pass."""
        experiment.freeze("e", dry_run=False)
        go, py = frozen_digest(world, "go-a"), frozen_digest(world, "py-a")
        accept(world, "a", row("go-a", go, True))
        accept(world, "a", row("py-a", py, True))
        accept(world, "b", row("go-a", go, "false"))
        accept(world, "b", row("py-a", py, True))

        assert experiment.compare("e") == 2
        assert "not-a-verdict" in capsys.readouterr().out

    def test_a_run_that_did_not_conclude_is_not_agreement(self, world):
        experiment.freeze("e", dry_run=False)
        go, py = frozen_digest(world, "go-a"), frozen_digest(world, "py-a")
        accept(world, "a", row("go-a", go, True))
        accept(world, "a", row("py-a", py, True))
        accept(world, "b", row("go-a", go, None))
        accept(world, "b", row("py-a", py, True))

        assert experiment.compare("e") == 2

    def test_a_result_the_suite_did_not_ask_for_is_named(self, world, capsys):
        """A pass that ran cases the experiment never froze is not a clean pass
        that ran the right ones."""
        experiment.freeze("e", dry_run=False)
        go, py = frozen_digest(world, "go-a"), frozen_digest(world, "py-a")
        for label in ("a", "b"):
            accept(world, label, row("go-a", go, True))
            accept(world, label, row("py-a", py, True))
        accept(world, "b", row("uninvited", "x", True))

        assert experiment.compare("e") == 2
        assert "not in the suite" in capsys.readouterr().out

    def test_an_unreadable_result_is_named_not_skipped(self, world, capsys):
        """A file that will not parse is a case with no readable verdict.
        Skipping it turned a broken pass into a shorter one."""
        experiment.freeze("e", dry_run=False)
        go, py = frozen_digest(world, "go-a"), frozen_digest(world, "py-a")
        accept(world, "a", row("go-a", go, True))
        accept(world, "a", row("py-a", py, True))
        accept(world, "b", row("go-a", go, True))
        (world / "measurements" / "experiment-e" / "pass-b" / "py-a.json"
         ).write_text("{[", encoding="utf-8")

        assert experiment.compare("e") == 2
        assert "unreadable" in capsys.readouterr().out

    def test_no_movement_is_not_called_stability(self, world, capsys):
        """One paired repetition, over a suite that deliberately includes the
        cases already known to move."""
        experiment.freeze("e", dry_run=False)
        go, py = frozen_digest(world, "go-a"), frozen_digest(world, "py-a")
        for label in ("a", "b"):
            accept(world, label, row("go-a", go, True))
            accept(world, label, row("py-a", py, False))

        assert experiment.compare("e") == 0
        assert "is not 'the suite is stable'" in capsys.readouterr().out

    def test_it_refuses_when_something_moved_after_the_passes(
            self, world, capsys):
        """`run` closes the window up to the moment a case finishes. Without
        this, everything the experiment rests on could be edited afterwards and
        the comparison would still print "no movement observed"."""
        experiment.freeze("e", dry_run=False)
        go, py = frozen_digest(world, "go-a"), frozen_digest(world, "py-a")
        for label in ("a", "b"):
            accept(world, label, row("go-a", go, True))
            accept(world, label, row("py-a", py, False))
        (world / "prompts" / "system.md").write_text("rewritten after the fact\n")

        assert experiment.compare("e") == 2
        assert "have moved since the freeze" in capsys.readouterr().err

    def test_comparing_without_a_manifest_refuses(self, world, capsys):
        assert experiment.compare("never-frozen") == 2
        assert "none may be invented now" in capsys.readouterr().err

class TestTheSixthRoundOfDefects:
    """Four, on the simplified tool. Two of them could have produced a result
    that looked perfectly ordinary and was not."""

    def test_publishing_cannot_overwrite_even_between_the_check_and_the_write(
            self, world):
        """`replace` after an `exists()` check is two operations: two runs can
        both see nothing there and the second silently replaces the first. The
        window was narrowed to one line, and a line is still a window — and the
        harm is a result quietly swapped, which leaves the comparison looking
        entirely normal."""
        target = world / "measurements" / "experiment-e" / "pass-a" / "go-a.json"
        target.parent.mkdir(parents=True)
        target.write_text("the first run's result", encoding="utf-8")

        assert experiment.publish(target, "the second run's result") is False
        assert target.read_text() == "the first run's result"
        assert not list(target.parent.glob("*.writing.*"))

    def test_a_result_with_no_verdict_is_kept_aside_not_accepted(
            self, world, monkeypatch, capsys):
        """An accepted file is also what tells the next run to skip the case.
        Publishing an errored row as an ordinary result turned a transient
        provider failure into a case that could never be run again and an
        experiment that stayed incomplete for ever."""
        experiment.freeze("e", dry_run=False)
        import pair_corpus

        monkeypatch.setattr(pair_corpus, "run_case", lambda case, **kw: {
            "case_id": case["case_id"], "error": "provider fell over",
            "case_digest": frozen_digest(world, case["case_id"])})

        assert experiment.run("e", "a", None) == 2
        assert experiment.accepted("e", "a") == {}
        assert list((world / "measurements" / "experiment-e"
                     / "pass-a-unfinished").glob("*.json"))
        assert "kept aside" in capsys.readouterr().out

    def test_an_unfinished_case_is_run_again_next_time(self, world,
                                                       monkeypatch):
        """The point of keeping it apart: resume must retry it."""
        experiment.freeze("e", dry_run=False)
        import pair_corpus

        monkeypatch.setattr(pair_corpus, "run_case", lambda case, **kw: {
            "case_id": case["case_id"], "error": "provider fell over",
            "case_digest": frozen_digest(world, case["case_id"])})
        experiment.run("e", "a", None)

        ran = []
        monkeypatch.setattr(pair_corpus, "run_case", lambda case, **kw: (
            ran.append(case["case_id"]) or {
                "case_id": case["case_id"], "pair_success": True,
                "case_digest": frozen_digest(world, case["case_id"])}))
        experiment.run("e", "a", None)

        assert ran[0] == experiment_first_case(world)

    def test_the_rulings_reach_the_scoring(self, world, monkeypatch):
        """The manifest digests `adjudications.yml` and `drift` refuses when it
        moves — which said the rulings were part of the frozen scoring
        environment while the scoring ignored them, because `run_case` defaults
        to none."""
        experiment.freeze("e", dry_run=False)
        import pair_corpus

        seen = {}

        def fake(case, keep_dir=None, provider="", profile="",
                 adjudications=None):
            seen["adjudications"] = adjudications
            return {"case_id": case["case_id"], "pair_success": True,
                    "case_digest": frozen_digest(world, case["case_id"])}

        monkeypatch.setattr(pair_corpus, "run_case", fake)
        experiment.run("e", "a", 1)

        assert seen["adjudications"] is not None

    def test_the_passes_read_a_frozen_copy_of_the_prompts(self, world,
                                                          monkeypatch):
        """Hashing before a case and again after it compares two snapshots; it
        does not prove the file was the same in between. An edit made and
        reverted while a review runs is invisible to both checks and visible to
        the reviewer, which is the one reader that matters."""
        experiment.freeze("e", dry_run=False)
        frozen = world / "measurements" / "experiment-e" / "prompts"
        assert (frozen / "system.md").read_text() == "system.md\n"

        import pair_corpus
        seen = {}

        def fake(case, **kwargs):
            seen["dir"] = os.environ.get("SECURITY_SCAN_PROMPT_DIR")
            return {"case_id": case["case_id"], "pair_success": True,
                    "case_digest": frozen_digest(world, case["case_id"])}

        monkeypatch.setattr(pair_corpus, "run_case", fake)
        experiment.run("e", "a", 1)

        assert seen["dir"] == str(frozen)


def experiment_first_case(root: Path) -> str:
    body = json.loads((root / "measurements" / "experiment-e"
                       / "manifest.json").read_text())
    return body["protocol"]["order"][0]

