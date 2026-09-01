"""Freezing a result, and refusing to compare across a changed identity.

This exists because of a specific two days. The completeness rule, the
target-file definitions, the corpus membership and the response-limit behaviour
all changed at once, and a 2-of-6 could then be neither defended nor improved —
only withdrawn, because no part of it was attributable to any of the four.

The refusal is the feature. A comparison that quietly proceeds across a prompt
edit produces a delta that reads as a change in the reviewer and is not one.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from baseline import compare, freeze, identity_of, outcomes_of


def member(**overrides) -> dict:
    body = {
        "complete": True,
        "provenance": {"system_prompt_sha": "aaa", "verifier_prompt_sha": "bbb",
                       "schema_sha": "ccc", "agent_version": "0.1.0",
                       "models_served": ["claude-opus-5"]},
        "settings": {"fail_on": "high", "min_confidence": "medium"},
    }
    body.update(overrides)
    return body


def row(case_id: str, passed: bool = True, **extra) -> dict:
    body = {"case_id": case_id, "pair_success": passed,
            "unsafe_recall": passed, "safe_false_positive": False,
            "members": {"safe": member(), "unsafe": member()}}
    body.update(extra)
    return body


@pytest.fixture
def corpus(tmp_path) -> Path:
    root = tmp_path / "corpus-real"
    (root / "a-case").mkdir(parents=True)
    (root / "a-case" / "case.yml").write_text("expected_category: injection\n")
    return root


def write(tmp_path, name: str, rows: list) -> Path:
    path = tmp_path / name
    path.write_text(json.dumps(rows))
    return path


# ------------------------------------------------------------ what is frozen


def test_a_frozen_baseline_records_the_outcome_of_each_case(tmp_path, corpus, capsys):
    result = write(tmp_path, "r.json", [row("one"), row("two", passed=False)])
    out = tmp_path / "baseline.json"

    assert freeze(result, corpus, out) == 0
    data = json.loads(out.read_text())
    assert data["outcomes"]["one"]["outcome"] == "pass"
    assert data["outcomes"]["two"]["outcome"] == "fail"
    assert data["passed"] == 1 and data["scored"] == 2


def test_the_baseline_says_it_is_not_a_recall_figure(tmp_path, corpus, capsys):
    """It supports "this version did what that version did on this suite" and
    nothing about code outside it. A number without that sentence gets quoted
    without it."""
    freeze(write(tmp_path, "r.json", [row("one")]), corpus, tmp_path / "b.json")
    assert "not a recall figure" in capsys.readouterr().out


def test_an_unresolved_case_is_frozen_as_unresolved_not_as_a_failure(tmp_path, corpus):
    result = write(tmp_path, "r.json", [
        {"case_id": "one", "incomplete": ["unsafe"],
         "members": {"safe": member(), "unsafe": member(complete=False)}}])
    out = tmp_path / "b.json"

    freeze(result, corpus, out)
    assert json.loads(out.read_text())["outcomes"]["one"]["outcome"] == "unresolved"


def test_freezing_nothing_scorable_refuses(tmp_path, corpus):
    result = write(tmp_path, "r.json", [{"error": "boom"}])
    assert freeze(result, corpus, tmp_path / "b.json") == 2


# --------------------------------------------------------------- the refusal


@pytest.mark.parametrize("field,mutate", [
    ("prompts", lambda r: r[0]["members"]["safe"]["provenance"].update(
        {"system_prompt_sha": "edited"})),
    ("model", lambda r: r[0]["members"]["safe"]["provenance"].update(
        {"models_served": ["claude-sonnet-5"]})),
    ("settings", lambda r: r[0]["members"]["safe"]["settings"].update(
        {"fail_on": "medium"})),
])
def test_a_changed_system_is_named_and_compared_not_refused(
        tmp_path, corpus, capsys, field, mutate):
    """These three used to refuse, and refusing them broke the only regime the
    tool has.

    The intended sequence is: freeze a baseline, change a prompt, re-run the
    same cases, read the difference. With prompts in the refusal set, step two
    disqualifies step four — so the only comparison the tool allowed was one in
    which nothing worth measuring had happened, and `--force` was the only way
    to use it as designed, at the cost of a printed disclaimer that the delta
    meant nothing.

    A changed prompt, model or setting is the *cause* the delta is attributed
    to, not a reason the delta cannot be read. It is named at the top of the
    output for exactly that reason.
    """
    baseline = tmp_path / "b.json"
    freeze(write(tmp_path, "before.json", [row("one")]), corpus, baseline)

    after = [row("one")]
    mutate(after)
    assert compare(write(tmp_path, "after.json", after), corpus, baseline,
                   force=False) == 0
    out = capsys.readouterr().out
    assert "Refusing to compare" not in out
    assert "Under test" in out
    assert field in out


@pytest.mark.parametrize("field,mutate", [
    ("scorer_version", lambda mp: mp.setattr("baseline.SCORER_VERSION", 99)),
])
def test_a_changed_test_still_refuses(tmp_path, corpus, capsys, monkeypatch,
                                      field, mutate):
    """The other half. The scoring protocol is the instrument, and two numbers
    produced by different instruments are not subtractable however carefully
    the rest was held still."""
    baseline = tmp_path / "b.json"
    result = write(tmp_path, "r.json", [row("one")])
    freeze(result, corpus, baseline)

    mutate(monkeypatch)
    assert compare(result, corpus, baseline, force=False) == 2
    out = capsys.readouterr().out
    assert "Refusing to compare" in out
    assert field in out


def test_a_case_outside_the_suite_does_not_break_the_comparison(
        tmp_path, corpus, capsys):
    """The whole point of a ten-case suite run out of an eighty-two-case tree.

    The corpus digest used to hash everything under the directory, so editing
    any case — including one the suite never touches — read as a changed test
    and refused. The larger the corpus grows, the more often the sentinel would
    refuse for reasons that have nothing to do with it.
    """
    (corpus / "unrelated").mkdir()
    (corpus / "unrelated" / "case.yml").write_text("expected_category: xss\n")
    baseline = tmp_path / "b.json"
    result = write(tmp_path, "r.json", [row("a-case")])
    freeze(result, corpus, baseline)

    (corpus / "unrelated" / "case.yml").write_text("expected_category: dos\n")

    assert compare(result, corpus, baseline, force=False) == 0
    assert "Refusing to compare" not in capsys.readouterr().out


def test_editing_a_case_inside_the_suite_still_refuses(tmp_path, corpus, capsys):
    """The control, so narrowing the digest did not narrow it to nothing."""
    baseline = tmp_path / "b.json"
    result = write(tmp_path, "r.json", [row("a-case")])
    freeze(result, corpus, baseline)

    (corpus / "a-case" / "case.yml").write_text("expected_category: dos\n")

    assert compare(result, corpus, baseline, force=False) == 2
    assert "corpus" in capsys.readouterr().out


def test_a_deleted_suite_case_is_not_silently_dropped(tmp_path, corpus, capsys):
    """A named case that is gone hashes as absent rather than being skipped."""
    baseline = tmp_path / "b.json"
    result = write(tmp_path, "r.json", [row("a-case")])
    freeze(result, corpus, baseline)

    (corpus / "a-case" / "case.yml").unlink()
    (corpus / "a-case").rmdir()

    assert compare(result, corpus, baseline, force=False) == 2


def test_running_a_different_set_of_cases_is_a_different_suite(
        tmp_path, corpus, capsys):
    """A suite is the cases it names. Comparing sixty-six against a frozen ten
    is comparing two suites, and the message says which cases differ rather
    than pointing at a digest nobody can read."""
    baseline = tmp_path / "b.json"
    freeze(write(tmp_path, "b-run.json", [row("a-case")]), corpus, baseline)

    other = write(tmp_path, "other.json", [row("a-case"), row("extra")])
    assert compare(other, corpus, baseline, force=False) == 2
    out = capsys.readouterr().out
    assert "not the frozen suite" in out
    assert "extra" in out


def test_force_over_a_different_suite_still_says_so(tmp_path, corpus, capsys):
    """`--force` skips the refusal, not the report.

    The first version returned early only when force was false, so a forced run
    over a different set of cases printed one line about a new case, matched no
    exit condition, and returned 0 — a green regression gate over a comparison
    between two different suites. Found by Codex on review; the force test at
    the time only exercised an edited case, never a different set.
    """
    baseline = tmp_path / "b.json"
    freeze(write(tmp_path, "b-run.json", [row("a-case")]), corpus, baseline)

    other = write(tmp_path, "other.json", [row("a-case"), row("extra")])
    compare(other, corpus, baseline, force=True)
    out = capsys.readouterr().out
    assert "not the frozen suite" in out
    assert "extra" in out


def test_a_forced_comparison_does_not_claim_the_suite_matched(
        tmp_path, corpus, capsys):
    """The identity printed has to describe this run, not the frozen one.

    The corpus digest is deliberately taken over the *frozen* cases — the
    question it answers is whether that suite was edited — and passing the
    frozen list in for the `cases` field too made the field agree by
    construction, so a forced comparison over a different set displayed an
    identity saying the suite was unchanged.
    """
    baseline = tmp_path / "b.json"
    freeze(write(tmp_path, "b-run.json", [row("a-case")]), corpus, baseline)

    other = write(tmp_path, "other.json", [row("a-case"), row("extra")])
    compare(other, corpus, baseline, force=True)
    out = capsys.readouterr().out
    assert "cases" in out and "extra" in out


def test_a_baseline_frozen_before_suites_existed_still_compares(
        tmp_path, corpus, capsys):
    """Back-compatibility, asserted rather than promised in a comment.

    An old baseline has no `cases` field and a corpus digest over the whole
    tree. Comparing a scoped digest against a whole-tree one reports a changed
    corpus every time, and comparing a present `cases` against an absent one
    refuses outright — so the first version of the fallback refused every old
    baseline while its comment said it did not.
    """
    baseline = tmp_path / "b.json"
    result = write(tmp_path, "r.json", [row("a-case")])
    freeze(result, corpus, baseline)

    # Age it: strip the field a baseline frozen before this change would lack,
    # and restore the whole-tree digest it would have carried.
    from baseline import digest_tree
    data = json.loads(baseline.read_text())
    del data["identity"]["cases"]
    data["identity"]["corpus"] = digest_tree(corpus)
    baseline.write_text(json.dumps(data))

    assert compare(result, corpus, baseline, force=False) == 0
    assert "Refusing to compare" not in capsys.readouterr().out


def test_a_pair_that_fails_differently_is_named(tmp_path, corpus, capsys):
    """`pair_success` is one bit, so a failing pair can get worse in every way
    that matters and still read fail -> fail.

    Missing the weakness is one failure; missing it *and* blocking the fixed
    member is another. The corpus has already shown a case moving from (0,0) to
    (0,1) between two runs with the verdict unchanged both times, and the old
    output called that no change.
    """
    baseline = tmp_path / "b.json"
    freeze(write(tmp_path, "b-run.json",
                 [row("a-case", passed=False, safe_exit=0, unsafe_exit=0)]),
           corpus, baseline)

    after = write(tmp_path, "after.json",
                  [row("a-case", passed=False, safe_exit=1, unsafe_exit=0)])

    assert compare(after, corpus, baseline, force=False) == 0
    out = capsys.readouterr().out
    assert "still failing, differently" in out
    assert "a-case" in out


def test_a_pair_failing_the_same_way_is_not_named(tmp_path, corpus, capsys):
    """The control: the new line must not fire on every unchanged failure."""
    baseline = tmp_path / "b.json"
    result = write(tmp_path, "r.json",
                   [row("a-case", passed=False, safe_exit=0, unsafe_exit=0)])
    freeze(result, corpus, baseline)

    assert compare(result, corpus, baseline, force=False) == 0
    assert "still failing, differently" not in capsys.readouterr().out


def test_an_identical_rerun_says_so_rather_than_implying_an_effect(
        tmp_path, corpus, capsys):
    """A run with nothing changed is the noise floor, and it has to say it is.

    The same output — "no regression" — means one thing after a prompt edit and
    another after no edit at all, and only one of those two readings is about
    the reviewer. The sentinel's threshold is set from this run, so it must not
    be mistakable for a measured effect.
    """
    baseline = tmp_path / "b.json"
    result = write(tmp_path, "r.json", [row("one")])
    freeze(result, corpus, baseline)

    assert compare(result, corpus, baseline, force=False) == 0
    out = capsys.readouterr().out
    assert "Nothing under test changed" in out
    assert "run-to-run variation" in out


def test_editing_the_corpus_refuses_the_comparison(tmp_path, corpus, capsys):
    """A case edited between runs makes the two numbers about different code.

    The case id has to be the directory name now: the digest covers the suite's
    own cases, so a case the suite does not contain cannot change it.
    """
    baseline = tmp_path / "b.json"
    result = write(tmp_path, "r.json", [row("a-case")])
    freeze(result, corpus, baseline)

    (corpus / "a-case" / "case.yml").write_text("expected_category: xss\n")
    assert compare(result, corpus, baseline, force=False) == 2
    assert "corpus" in capsys.readouterr().out


def test_force_compares_anyway_and_says_the_two_runs_differ_in_question(
        tmp_path, corpus, capsys):
    """`--force` is for a changed *test* now, and only that.

    It used to be demonstrated with a prompt edit, which is no longer a refusal
    at all — and that is the point: the escape hatch used to be the normal way
    to run the tool, which is how you can tell the refusal was set on the wrong
    half.
    """
    baseline = tmp_path / "b.json"
    result = write(tmp_path, "r.json", [row("a-case")])
    freeze(result, corpus, baseline)

    (corpus / "a-case" / "case.yml").write_text("expected_category: xss\n")
    compare(result, corpus, baseline, force=True)
    assert "not answering the same question" in capsys.readouterr().out


# ------------------------------------------------------------- what compares


def test_an_unchanged_run_reports_no_regression(tmp_path, corpus, capsys):
    baseline = tmp_path / "b.json"
    result = write(tmp_path, "r.json", [row("one"), row("two")])
    freeze(result, corpus, baseline)

    assert compare(result, corpus, baseline, force=False) == 0
    assert "No regression" in capsys.readouterr().out


def test_a_case_that_stopped_passing_is_a_regression(tmp_path, corpus, capsys):
    baseline = tmp_path / "b.json"
    freeze(write(tmp_path, "before.json", [row("one")]), corpus, baseline)

    assert compare(write(tmp_path, "after.json", [row("one", passed=False)]),
                   corpus, baseline, force=False) == 1
    assert "regressed" in capsys.readouterr().out


def test_a_case_that_no_longer_completes_is_not_called_a_regression(
        tmp_path, corpus, capsys):
    """It did not fail. It has no result, and treating the two the same is the
    confusion that made a 2-of-6 out of three reviews that never ran."""
    baseline = tmp_path / "b.json"
    freeze(write(tmp_path, "before.json", [row("one")]), corpus, baseline)
    capsys.readouterr()                       # discard the freeze output

    after = [{"case_id": "one", "incomplete": ["unsafe"],
              "members": {"safe": member(), "unsafe": member(complete=False)}}]
    code = compare(write(tmp_path, "after.json", after), corpus, baseline,
                   force=False)
    out = capsys.readouterr().out

    assert code == 2, "an absent result is not a pass and not a failure"
    assert "no longer completes" in out
    # The label line, not the prose. The explanation below the table uses the
    # word to say the case is NOT one.
    assert "regressed:" not in out


def test_a_case_missing_from_the_run_is_not_silently_dropped(tmp_path, corpus, capsys):
    baseline = tmp_path / "b.json"
    freeze(write(tmp_path, "before.json", [row("one"), row("two")]), corpus, baseline)

    assert compare(write(tmp_path, "after.json", [row("one")]), corpus,
                   baseline, force=False) == 2
    # The check moved earlier and says the same thing more precisely: the run
    # is not the suite, and here is the case it is missing.
    out = capsys.readouterr().out
    assert "not the frozen suite" in out
    assert "absent here: two" in out


def test_the_identity_covers_every_field_that_changes_what_a_number_means(
        tmp_path, corpus):
    """A field left out of `IDENTITY` is a field that can move without anyone
    being told, which is exactly how the last measurement was lost."""
    from baseline import IDENTITY

    identity = identity_of([row("one")], corpus)
    assert set(IDENTITY) <= set(identity), set(IDENTITY) - set(identity)
    for field in ("corpus", "prompts", "model", "settings", "scorer_version",
                  "adjudications", "excluded"):
        assert field in IDENTITY, field


def test_outcomes_keep_the_two_halves_of_a_pair_apart(tmp_path):
    """A pair can fail because the unsafe member missed or because the safe one
    reported, and the fix for each is different."""
    outcomes = outcomes_of([row("one", passed=False)])
    assert outcomes["one"]["unsafe_target_recall"] is False
    assert outcomes["one"]["safe_target_persistence"] is False




def test_an_errored_case_is_never_no_regression(tmp_path, corpus, capsys):
    """The state machine knew `unresolved` and not `error`, so a case whose run
    blew up matched no branch, fell past every arm, and the comparison printed
    "No regression against the frozen suite" and exited 0.

    That is this product's own failure inside the tool that measures it: a
    check that did not run, reported as a check that passed. Found by an audit
    that was told to read the code rather than my description of it.
    """
    baseline = tmp_path / "b.json"
    freeze(write(tmp_path, "before.json", [row("one")]), corpus, baseline)

    after = [row("one")]
    after[0]["error"] = "the review process died"
    code = compare(write(tmp_path, "after.json", after), corpus, baseline,
                   force=False)
    printed = capsys.readouterr().out

    assert code == 2
    assert "No regression" not in printed
    assert "errored" in printed
