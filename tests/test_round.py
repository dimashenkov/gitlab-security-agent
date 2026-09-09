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
    """Rows as a paid pass writes them, into the round's own directory.

    **With the digest the round froze.** `pair_corpus` stamps every row with
    one and `compare` checks it, so a fixture without one builds a shape
    production never emits — and the `frozen` fixture pins `case_digest` to
    "digest", which is what these rows have to carry to be about the case that
    was frozen.
    """
    directory = root / "measurements" / "round-{}".format(number)
    directory.mkdir(parents=True, exist_ok=True)
    for case_id, passed in verdicts.items():
        (directory / (case_id + ".json")).write_text(
            json.dumps([{"case_id": case_id, "case_digest": "digest",
                         "pair_success": passed}]),
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

    def test_a_round_of_no_cases_is_refused(self, frozen, monkeypatch, capsys):
        """A scope that selects nothing froze, ran and compared without error.

        `sentinel.read_cases` reads only lines beginning with `- `, so a suite
        rewritten as a YAML flow list selects no case; `scope_cases("sentinel")`
        then finds nothing missing, because it is comparing two empty sets. The
        round is frozen over an empty denominator and the comparison reports
        that nothing moved, with no review bought.
        """
        monkeypatch.setattr(roundtool, "scope_cases", lambda scope: [])
        assert roundtool.freeze(1, "sentinel", dry_run=False) == 2
        assert "selected no case" in capsys.readouterr().out
        assert not roundtool.manifest_path(1).exists()

    def test_an_empty_manifest_is_not_a_round_in_which_nothing_moved(
            self, frozen, capsys):
        """One frozen before `freeze` learned to refuse is still on disk."""
        path = roundtool.manifest_path(1)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(
            {"round": 1, "cases": [], "environment": {},
             "counts": {"with_baseline": 0}}), encoding="utf-8")
        assert roundtool.compare(1) == 2
        assert "frozen with no cases" in capsys.readouterr().out


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

    def test_drift_since_freezing_refuses_rather_than_warns(
            self, frozen, capsys, monkeypatch):
        """A ruling added between the passes rescores a verdict without
        rerunning anything.

        The first version printed that and then printed the number anyway —
        while an edit to the *other* half of the scoring rule, `case.yml`, is
        exit 2 with nothing reported. One rule, two treatments, and the softer
        one was on the half that includes `adjudications.yml`.
        """
        roundtool.freeze(1, "approved", dry_run=False)
        monkeypatch.setattr(roundtool, "environment",
                            lambda: {"system_prompt": "aaaa",
                                     "adjudications": "CHANGED"})
        results_for(frozen, 1, **{"a-one": True})
        capsys.readouterr()

        assert roundtool.compare(1) == 2
        out = capsys.readouterr().out
        assert "adjudications" in out
        assert "no figure is reported" in out
        # And none is: the number would be that change, not the product.
        assert "agreed" not in out

    def test_no_drift_still_reports(self, frozen, capsys, monkeypatch):
        """The control. Without it the refusal above would swallow every
        round, and nothing could ever be compared."""
        roundtool.freeze(1, "approved", dry_run=False)
        results_for(frozen, 1, **{"a-one": True})
        capsys.readouterr()

        roundtool.compare(1)
        out = capsys.readouterr().out

        assert "no figure is reported" not in out
        assert "agreed" in out

    def test_no_manifest_refuses_rather_than_inventing_a_rule(self, frozen, capsys):
        assert roundtool.compare(9) == 2
        assert "none may be invented now" in capsys.readouterr().out

    def test_a_crashed_review_is_not_agreement(self, frozen, capsys):
        """A review that never produced an answer was counted as one.

        `pair_corpus.run_case` writes `pair_success` only on the success path.
        A pair that crashed carries `error` and neither that key nor
        `incomplete`, so the filter that drops incomplete rows admits it — and
        `bool(row.get("pair_success"))` turned the missing key into False,
        which against a frozen baseline of False agreed. The paid pass then
        reported "100% agreement" over a case whose review had fallen over.
        """
        roundtool.freeze(1, "approved", dry_run=False)
        directory = frozen / "measurements" / "round-1"
        (directory / "b-two.json").write_text(
            json.dumps([{"case_id": "b-two", "case_digest": "digest",
                         "error": "CalledProcessError: 1"}]), encoding="utf-8")
        capsys.readouterr()
        roundtool.compare(1)
        out = capsys.readouterr().out
        assert "0 agreed, 0 flipped" in out
        assert "without producing a verdict" in out
        assert "CalledProcessError" in out
        assert "100% agreement" not in out

    def test_a_stored_string_verdict_is_not_a_verdict(self, frozen, capsys):
        """`"false"` is a non-empty string: `bool()` read it as a pass."""
        roundtool.freeze(1, "approved", dry_run=False)
        results_for(frozen, 1, **{"b-two": "false"})
        capsys.readouterr()
        roundtool.compare(1)
        out = capsys.readouterr().out
        assert "0 agreed, 0 flipped" in out
        assert "without producing a verdict" in out

    def test_a_baseline_that_is_not_a_verdict_does_not_become_a_flip(
            self, frozen, capsys):
        """The other half of the same comparison: a null baseline would make
        every case flip against it, and the number would read as a finding."""
        roundtool.freeze(1, "approved", dry_run=False)
        path = roundtool.manifest_path(1)
        body = json.loads(path.read_text(encoding="utf-8"))
        for case in body["cases"]:
            if case["case_id"] == "b-two":
                case["baseline"] = {"pair_success": None}
        path.write_text(json.dumps(body), encoding="utf-8")
        results_for(frozen, 1, **{"b-two": True})
        capsys.readouterr()
        roundtool.compare(1)
        out = capsys.readouterr().out
        assert "0 agreed, 0 flipped" in out
        assert "not a verdict" in out

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


def _round_nine(tmp_path, monkeypatch, protocol=None, rows=()):
    """A frozen round with one case, and whatever rows the caller wants in it.

    The baseline is `pair_success: True`, so a row saying the same agrees and
    a row saying `False` is a flip — which is what makes "whose rows were
    counted" visible in the printed numbers rather than only in a set.
    """
    import round as round_tool

    monkeypatch.setattr(round_tool, "ROOT", tmp_path)
    monkeypatch.setattr(round_tool, "environment", lambda: {})
    home = tmp_path / "measurements" / "round-9"
    home.mkdir(parents=True)
    body = {
        "round": 9, "suite": "sentinel",
        "counts": {"cases": 1, "with_baseline": 1},
        "environment": {},
        "cases": [{"case_id": "one", "case_digest": "d" * 16,
                   "baseline": {"pair_success": True},
                   "contributes_to": ["stability"]}],
    }
    if protocol is not None:
        body["protocol"] = protocol
    (home / "manifest.json").write_text(json.dumps(body), encoding="utf-8")
    for name, row in rows:
        path = home / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(row), encoding="utf-8")
    return round_tool, home


def _row(model, passes):
    block = {"provenance": {"model_requested": model,
                            "models_served": [model],
                            "models_verified": []}}
    return {"case_id": "one", "case_digest": "d" * 16,
            "pair_success": passes, "ran_at": "2026-09-01T10:00:00+00:00",
            "members": {"safe": block, "unsafe": dict(block)}}


def test_freezing_under_another_model_is_refused(frozen, monkeypatch, capsys):
    """Codex, 2026-09-09, against the version that froze whatever the
    environment resolved to.

    Freezing under `SECURITY_SCAN_MODEL=claude-sonnet-5` made the round
    internally consistent and the comparison still wrong: `baselines()` comes
    from `check_accounted.verdicts()`, which is the product's answers and
    nothing else, so the pass printed "0 agreed, 1 flipped" and exited 0 over
    Sonnet against an Opus baseline. The cross-model comparison the round
    before was repaired to prevent, arriving through the freeze instead of
    through the run.
    """
    monkeypatch.setenv("SECURITY_SCAN_MODEL", "claude-sonnet-5")

    assert roundtool.freeze(1, "approved", dry_run=False) == 2
    assert "measurement of claude-opus-5" in capsys.readouterr().out
    # And nothing was written. A refusal that leaves a manifest behind is a
    # round somebody can run.
    assert not roundtool.manifest_path(1).is_file()


def test_freezing_with_the_variable_unset_is_not_refused(frozen, monkeypatch):
    """The control. Without it the test above passes over a `freeze` that
    refuses every round."""
    monkeypatch.delenv("SECURITY_SCAN_MODEL", raising=False)

    assert roundtool.freeze(1, "approved", dry_run=False) == 0
    assert roundtool.manifest_path(1).is_file()


def test_a_manifest_naming_another_model_is_refused(tmp_path, monkeypatch,
                                                   capsys):
    """Codex, 2026-09-09. Closing `freeze` did nothing about a manifest
    already on disk.

    Hand-edited, or written by an earlier revision of this same change, a
    manifest naming Sonnet was obeyed here — so the comparison put Sonnet rows
    against the Opus baselines `baselines()` draws from the product's own
    verdicts, printed "0 agreed, 1 flipped" and exited 0, reporting one model
    as the other moving on its own.
    """
    round_tool, _home = _round_nine(
        tmp_path, monkeypatch,
        protocol={"model": "claude-sonnet-5"},
        rows=[("one.json", _row("claude-sonnet-5", False))])

    assert round_tool.compare(9) == 2
    assert "naming model 'claude-sonnet-5'" in capsys.readouterr().out


def test_a_manifest_naming_the_product_is_not_refused(tmp_path, monkeypatch,
                                                      capsys):
    """The control. Without it the test above passes over a reader that
    refuses every manifest, and no round could ever be compared."""
    round_tool, _home = _round_nine(
        tmp_path, monkeypatch,
        protocol={"model": "claude-opus-5"},
        rows=[("one.json", _row("claude-opus-5", True))])

    round_tool.compare(9)
    out = capsys.readouterr().out

    assert "naming model" not in out
    assert "1 agreed" in out


def test_a_round_does_not_compare_one_model_against_another(tmp_path,
                                                            monkeypatch,
                                                            capsys):
    """Codex, 2026-09-09. `run_queue.result_path` writes a non-product run to
    `<case>.<model>.json` — in the round's own directory — so a round could
    hold rows from two models, and this reader took the latest by timestamp.
    The flips it reported as the product moving on its own were one model
    against another, and that number is what every gate threshold sits above.
    """
    round_tool, _home = _round_nine(
        tmp_path, monkeypatch,
        protocol={"model": "claude-opus-5"},
        rows=[("one.json", _row("claude-opus-5", True)),
              ("by-model/claude-sonnet-5/one.json", _row("claude-sonnet-5", False))])

    round_tool.compare(9)
    out = capsys.readouterr().out

    assert "1 agreed" in out
    assert "1 flipped" not in out
    # Named, not dropped in silence: the row was bought, and a reader that
    # removes it without saying so reports a round as thinner than it is.
    assert "produced by another model" in out


def test_the_frozen_model_s_own_rows_are_still_compared(tmp_path, monkeypatch,
                                                        capsys):
    """The control. Without it the test above passes over a reader that
    rejects every row, which would report a round that measured nothing."""
    round_tool, _home = _round_nine(
        tmp_path, monkeypatch,
        protocol={"model": "claude-opus-5"},
        rows=[("one.json", _row("claude-opus-5", False))])

    round_tool.compare(9)
    out = capsys.readouterr().out

    assert "1 flipped" in out
    assert "produced by another model" not in out


def test_a_row_for_a_case_the_round_never_froze_is_named(tmp_path, monkeypatch,
                                                        capsys):
    """Codex, 2026-09-09. Three states, and the first version had two.

    `frozen_digests.get(case_id)` answers `None` both for a case the manifest
    does not name and for a frozen case recorded before digests existed, and
    the falsey test let the first through — into `collected`, where the
    reporting loop, which walks the manifest, never looks at it again. A paid
    row for a case outside the round vanished without a word, under a comment
    claiming it was named. Absence read as agreement, in the line written to
    stop absence being read as agreement.
    """
    round_tool, _home = _round_nine(
        tmp_path, monkeypatch,
        protocol={"model": "claude-opus-5"},
        rows=[("one.json", _row("claude-opus-5", True)),
              ("two.json", dict(_row("claude-opus-5", False), case_id="two"))])

    round_tool.compare(9)
    out = capsys.readouterr().out

    assert "the manifest does not name" in out
    # And the round's own case is still compared, so the refusal is about the
    # stranger rather than about every row.
    assert "1 agreed" in out


def test_a_baseline_with_no_recorded_key_is_said_so(tmp_path, monkeypatch,
                                                   capsys):
    """Codex, 2026-09-09, the deeper form of the answer-key defect.

    The digests catch a key edited *after* the freeze. They cannot establish
    that the frozen baseline was itself scored under the frozen key — run a
    case under key A, change `case.yml` to B, freeze, run under B, and the
    flip is the key moving while every digest agrees.

    No row written before 2026-09-09 records the key it was judged by, so for
    those cases nothing can tell. The figure carries that rather than implying
    either answer.
    """
    round_tool, home = _round_nine(
        tmp_path, monkeypatch,
        protocol={"model": "claude-opus-5"},
        rows=[("one.json", _row("claude-opus-5", False))])

    round_tool.compare(9)
    out = capsys.readouterr().out

    assert "1 flipped" in out
    assert "scoring key is not recorded" in out


def test_a_baseline_with_a_recorded_key_carries_no_caveat(tmp_path,
                                                          monkeypatch, capsys):
    """The control. Without it the line above would print over every round for
    ever, including ones where the key *is* known — a caveat that never goes
    away is one nobody reads."""
    round_tool, home = _round_nine(
        tmp_path, monkeypatch,
        protocol={"model": "claude-opus-5"},
        rows=[("one.json", _row("claude-opus-5", False))])

    # **The same key the round froze, and the corpus agreeing with it.** The
    # first version of this control set a value matching nothing and asserted
    # the caveat stayed silent — so it pinned the defect: a baseline provably
    # scored under a *different* key printed nothing, while "I cannot tell"
    # spoke.
    from artifact import answer_key_digest

    case_dir = tmp_path / "corpus-real" / "one"
    case_dir.mkdir(parents=True)
    (case_dir / "case.yml").write_text("expected_category: [injection]\n",
                                       encoding="utf-8")

    body = json.loads((home / "manifest.json").read_text(encoding="utf-8"))
    key = answer_key_digest(case_dir)
    body["cases"][0]["answer_key_digest"] = key
    body["cases"][0]["baseline"]["answer_key_digest"] = key
    (home / "manifest.json").write_text(json.dumps(body), encoding="utf-8")

    round_tool.compare(9)
    out = capsys.readouterr().out

    assert "1 flipped" in out
    assert "scoring key is not recorded" not in out
    assert "different answer key" not in out


def test_a_baseline_scored_under_another_key_is_named(tmp_path, monkeypatch,
                                                     capsys):
    """The state the first version could not say anything about.

    It asked only whether the baseline's key was *present*, so a baseline
    provably scored under a different key printed nothing — the one case where
    the key is demonstrably what moved was the one that stayed silent, while
    "I cannot tell" spoke. The control beside it asserted that as correct.
    """
    round_tool, home = _round_nine(
        tmp_path, monkeypatch,
        protocol={"model": "claude-opus-5"},
        rows=[("one.json", _row("claude-opus-5", False))])

    # A real `case.yml`, so the frozen key matches the corpus and the earlier
    # refusal — which is about an edit *after* the freeze — does not fire
    # first. This test is about the other question: the key the baseline was
    # scored under.
    from artifact import answer_key_digest

    case_dir = tmp_path / "corpus-real" / "one"
    case_dir.mkdir(parents=True)
    (case_dir / "case.yml").write_text("expected_category: [injection]\n",
                                       encoding="utf-8")

    body = json.loads((home / "manifest.json").read_text(encoding="utf-8"))
    body["cases"][0]["answer_key_digest"] = answer_key_digest(case_dir)
    body["cases"][0]["baseline"]["answer_key_digest"] = "b" * 16
    (home / "manifest.json").write_text(json.dumps(body), encoding="utf-8")

    round_tool.compare(9)
    out = capsys.readouterr().out

    assert "different answer key" in out
    # And not the other sentence: this is not "I cannot tell", it is "I can,
    # and it moved".
    assert "scoring key is not recorded" not in out


def test_a_manifest_with_no_baseline_reaches_its_guard(tmp_path, monkeypatch,
                                                      capsys):
    """The guard that names this input was unreachable.

    `case["baseline"]["pair_success"]` subscripted before it, so
    `"baseline": null` raised `TypeError` out of the tool that reads a paid
    round — while the check four lines down says in as many words that a
    hand-edited manifest whose baseline is null would make every case flip
    against it. The `isinstance` read as coverage and was not.
    """
    round_tool, home = _round_nine(
        tmp_path, monkeypatch,
        protocol={"model": "claude-opus-5"},
        rows=[("one.json", _row("claude-opus-5", True))])

    body = json.loads((home / "manifest.json").read_text(encoding="utf-8"))
    body["cases"][0]["baseline"] = None
    (home / "manifest.json").write_text(json.dumps(body), encoding="utf-8")

    # A refusal with a sentence, not a traceback.
    assert round_tool.compare(9) == 2
    out = capsys.readouterr().out
    assert "0 agreed, 0 flipped" in out

    # And `contributes_to` missing entirely reaches the same place.
    body["cases"][0].pop("contributes_to", None)
    (home / "manifest.json").write_text(json.dumps(body), encoding="utf-8")
    assert round_tool.compare(9) == 2


def test_a_manifest_naming_a_case_twice_is_refused(tmp_path, monkeypatch,
                                                  capsys):
    """Codex, 2026-09-09. The reporting loop counts entries, not cases.

    A manifest naming a case twice counted one observation twice — "2 agreed"
    over a single measurement, exit 0 — and two entries with different
    baselines make the same row an agreement *and* a flip. `run_queue` refuses
    such a manifest before spending and this reader, which can be invoked on
    its own, did not.
    """
    round_tool, home = _round_nine(
        tmp_path, monkeypatch,
        protocol={"model": "claude-opus-5"},
        rows=[("one.json", _row("claude-opus-5", True))])

    body = json.loads((home / "manifest.json").read_text(encoding="utf-8"))
    body["cases"].append(dict(body["cases"][0]))
    (home / "manifest.json").write_text(json.dumps(body), encoding="utf-8")

    assert round_tool.compare(9) == 2
    out = capsys.readouterr().out
    assert "naming the same case more than once" in out
    assert "agreed" not in out, "a figure was printed over a manifest refused"


def test_an_answer_key_edited_after_the_freeze_is_refused(tmp_path,
                                                         monkeypatch, capsys):
    """Codex, 2026-09-09. `case_digest` covers the members, not `case.yml`.

    That exclusion is right for a row — a corrected category does not
    invalidate evidence about the same code — and wrong for a round, where
    what a pass *means* is one of the frozen conditions. Editing only the
    expectation left both this reader and the queue accepting the row, and a
    flip caused by the key moving was reported as the product moving.
    """
    round_tool, home = _round_nine(
        tmp_path, monkeypatch,
        protocol={"model": "claude-opus-5"},
        rows=[("one.json", _row("claude-opus-5", False))])

    case_dir = tmp_path / "corpus-real" / "one"
    case_dir.mkdir(parents=True)
    (case_dir / "case.yml").write_text("expected_category: [injection]\n",
                                       encoding="utf-8")

    body = json.loads((home / "manifest.json").read_text(encoding="utf-8"))
    body["cases"][0]["answer_key_digest"] = "frozen-under-the-old-key"
    (home / "manifest.json").write_text(json.dumps(body), encoding="utf-8")

    assert round_tool.compare(9) == 2
    assert "answer key that has changed" in capsys.readouterr().out


def test_an_unchanged_answer_key_is_not_refused(tmp_path, monkeypatch, capsys):
    """The control. Without it the test above passes over a reader that
    refuses every round, and nothing could ever be compared."""
    from artifact import answer_key_digest

    round_tool, home = _round_nine(
        tmp_path, monkeypatch,
        protocol={"model": "claude-opus-5"},
        rows=[("one.json", _row("claude-opus-5", False))])

    case_dir = tmp_path / "corpus-real" / "one"
    case_dir.mkdir(parents=True)
    (case_dir / "case.yml").write_text("expected_category: [injection]\n",
                                       encoding="utf-8")

    body = json.loads((home / "manifest.json").read_text(encoding="utf-8"))
    body["cases"][0]["answer_key_digest"] = answer_key_digest(case_dir)
    (home / "manifest.json").write_text(json.dumps(body), encoding="utf-8")

    round_tool.compare(9)
    out = capsys.readouterr().out

    assert "answer key that has changed" not in out
    assert "1 flipped" in out


def test_a_case_edited_after_the_freeze_is_not_compared(tmp_path, monkeypatch,
                                                       capsys):
    """Codex, 2026-09-09, and it predates the model work entirely.

    `freeze` records `case_digest` and `legacy_case_digest` for every case and
    `compare` read neither. Edit a member between the freeze and the paid run
    and the new row answers a different question from the baseline it is
    counted against — and when the two verdicts happen to agree, the tool
    prints a stability measurement over two different inputs and exits 0.
    `check_accounted` and `stage2` have applied this check to the same rows
    for weeks; this reader had not learnt it.
    """
    round_tool, _home = _round_nine(
        tmp_path, monkeypatch,
        protocol={"model": "claude-opus-5"},
        rows=[("one.json", dict(_row("claude-opus-5", True),
                                case_digest="e" * 16))])

    round_tool.compare(9)
    out = capsys.readouterr().out

    assert "a different version of their case" in out
    assert "measured nothing" in out


def test_a_row_about_the_frozen_version_is_compared(tmp_path, monkeypatch,
                                                    capsys):
    """The control. Without it the test above passes over a reader that
    rejects every row, which would report every round as empty."""
    round_tool, _home = _round_nine(
        tmp_path, monkeypatch,
        protocol={"model": "claude-opus-5"},
        rows=[("one.json", _row("claude-opus-5", True))])

    round_tool.compare(9)
    out = capsys.readouterr().out

    assert "1 agreed" in out
    assert "a different version of their case" not in out


def test_a_round_frozen_without_digests_still_compares(tmp_path, monkeypatch,
                                                       capsys):
    """A manifest from before `freeze` stored them records no digest, and
    refusing every row in it would turn an old round into one that measured
    nothing — the failure this check exists to prevent, in the other
    direction."""
    import json as _json

    round_tool, home = _round_nine(
        tmp_path, monkeypatch,
        protocol={"model": "claude-opus-5"},
        rows=[("one.json", _row("claude-opus-5", True))])
    body = _json.loads((home / "manifest.json").read_text(encoding="utf-8"))
    for case in body["cases"]:
        case.pop("case_digest", None)
        case.pop("legacy_case_digest", None)
    (home / "manifest.json").write_text(_json.dumps(body), encoding="utf-8")

    round_tool.compare(9)
    out = capsys.readouterr().out

    assert "1 agreed" in out
    assert "a different version of their case" not in out


def test_a_round_frozen_before_the_field_existed_means_the_product(
        tmp_path, monkeypatch, capsys):
    """Every round so far was bought with the product and none names a model.
    Reading the absence as "no model is acceptable" would let a foreign row
    into the oldest rounds, which are the ones with no protection at all."""
    round_tool, _home = _round_nine(
        tmp_path, monkeypatch, protocol=None,
        rows=[("one.json", _row("claude-opus-5", True)),
              ("by-model/claude-sonnet-5/one.json", _row("claude-sonnet-5", False))])

    round_tool.compare(9)
    out = capsys.readouterr().out

    assert "1 agreed" in out
    assert "produced by another model" in out


def test_a_comparison_that_compared_nothing_is_not_exit_zero(tmp_path,
                                                             monkeypatch,
                                                             capsys):
    """Exit 0 said "nothing wrong" about a round that measured nothing.

    Every case missing, or every row running without a verdict, printed the
    same green status as a round where everything agreed — and the exit code,
    which is what a pipeline reads, could not tell them apart.
    """
    import round as round_tool

    monkeypatch.setattr(round_tool, "ROOT", tmp_path)
    home = tmp_path / "measurements" / "round-9"
    home.mkdir(parents=True)
    (home / "manifest.json").write_text(json.dumps({
        "round": 9, "suite": "sentinel",
        "counts": {"cases": 1, "with_baseline": 1},
        "environment": {}, "cases": [
            {"case_id": "one", "case_digest": "d" * 16, "pair_success": True,
             "contributes_to": ["stability"]}],
    }), encoding="utf-8")
    monkeypatch.setattr(round_tool, "environment", lambda: {})

    assert round_tool.compare(9) == 2
    assert "measured nothing" in capsys.readouterr().out

