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


def test_a_case_that_stopped_passing_twice_is_a_regression(tmp_path, corpus, capsys):
    """Twice, because once is not evidence.

    Two failing rows for the same case is a failure the re-run confirmed. It is
    the same file: a case re-run to settle a doubt writes a second row beside
    the first, so the confirmation costs one case rather than another pass over
    the suite.
    """
    baseline = tmp_path / "b.json"
    freeze(write(tmp_path, "before.json", [row("one")]), corpus, baseline)

    first = write(tmp_path, "after.json", [row("one", passed=False, ran_at="t1")])
    again = write(tmp_path, "again.json", [row("one", passed=False, ran_at="t2")])

    assert compare([first, again], corpus, baseline, force=False) == 1
    out = capsys.readouterr().out
    assert "regressed" in out
    assert "2 of 2 runs" in out


def test_one_failure_is_a_question_rather_than_a_regression(
        tmp_path, corpus, capsys):
    """The threshold was one, implicitly, and that is measured wrong.

    Thirteen cases run twice on 2026-09-01 with nothing changed between the
    passes moved two — `go-m6jg-wr9m-cg2f` from pass to fail and
    `rb-g65v-27r3-5p6m` from fail to pass. Both directions: the suite does not
    decay under repetition, it moves. A gate blocking on the first sighting
    would block merges that broke nothing, and a gate that fires on noise is
    switched off after the third time.
    """
    baseline = tmp_path / "b.json"
    freeze(write(tmp_path, "before.json", [row("one")]), corpus, baseline)

    after = write(tmp_path, "after.json", [row("one", passed=False)])

    # 2, not 1: it is not called a regression. And not 0 either — the
    # comparison has no answer about this case yet, and 0 reads as clean, so
    # the confirming run would be left to whoever felt like paying for it.
    assert compare(after, corpus, baseline, force=False) == 2
    out = capsys.readouterr().out
    assert "failed once, unconfirmed" in out
    assert "regressed" not in out


def test_a_failure_that_did_not_repeat_is_not_called_passing(
        tmp_path, corpus, capsys):
    """One failing run and one passing is unstable, which is a third answer and
    a true one. Calling it a pass would be re-running until the result is
    convenient."""
    baseline = tmp_path / "b.json"
    freeze(write(tmp_path, "before.json", [row("one")]), corpus, baseline)

    first = write(tmp_path, "after.json", [row("one", passed=False, ran_at="t1")])
    again = write(tmp_path, "again.json", [row("one", passed=True, ran_at="t2")])

    assert compare([first, again], corpus, baseline, force=False) == 0
    out = capsys.readouterr().out
    assert "unstable: failed and passed in the same run" in out
    assert "one (1 of 2 runs failed)" in out
    assert "regressed" not in out


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

# ------------------------------------- what a confirmation actually requires


def test_a_confirmation_is_a_second_run_not_a_second_row(tmp_path, corpus):
    """Two rows are not two executions.

    `_rows_for` counted lines, so duplicating one fabricated a regression and
    deleting one hid it — and a merge that copied a file twice produced
    "2 of 2 runs" out of a single run. `run_case` stamps every result with
    `ran_at`; two confirmations are two stamps.
    """
    baseline = tmp_path / "b.json"
    freeze(write(tmp_path, "before.json", [row("one")]), corpus, baseline)

    doubled = write(tmp_path, "after.json", [
        row("one", passed=False, ran_at="t1"),
        row("one", passed=False, ran_at="t1"),
    ])

    assert compare(doubled, corpus, baseline, force=False) == 2


def test_a_second_result_file_is_how_a_confirmation_arrives(tmp_path, corpus,
                                                            capsys):
    """The workflow the first version described did not exist.

    It said "run those cases again into the same result file", and
    `pair_corpus --json` writes the whole file each time. So a re-run that
    failed left one row and could never confirm, and a re-run that passed
    erased the failure it was called to confirm — run-until-it-passes, reached
    by following the instructions.
    """
    baseline = tmp_path / "b.json"
    freeze(write(tmp_path, "before.json", [row("one")]), corpus, baseline)

    first = write(tmp_path, "first.json", [row("one", passed=False, ran_at="t1")])
    assert compare(first, corpus, baseline, force=False) == 2
    assert "into a NEW file" in capsys.readouterr().out

    again = write(tmp_path, "again.json", [row("one", passed=False, ran_at="t2")])
    assert compare([first, again], corpus, baseline, force=False) == 1


def test_a_later_error_is_not_hidden_by_earlier_mixed_runs(tmp_path, corpus):
    """`[fail, pass, error]` has a last state of `error`.

    Classifying it as unstable first returned 0 — "the check did not finish"
    reported as a green gate, which is the one thing this project exists to
    prevent. The endings that mean "no result" are asked about first.
    """
    baseline = tmp_path / "b.json"
    freeze(write(tmp_path, "before.json", [row("one")]), corpus, baseline)

    history = write(tmp_path, "after.json", [
        row("one", passed=False, ran_at="t1"),
        row("one", passed=True, ran_at="t2"),
        {"case_id": "one", "error": "boom", "ran_at": "t3"},
    ])

    assert compare(history, corpus, baseline, force=False) == 2


def test_only_unstable_cases_do_not_print_an_empty_candidate_list(
        tmp_path, corpus, capsys):
    """Folded into the candidates' sentence, a run with only unstable cases
    announced "0 case(s) failed once" above an empty list."""
    baseline = tmp_path / "b.json"
    freeze(write(tmp_path, "before.json", [row("one")]), corpus, baseline)

    mixed = write(tmp_path, "after.json", [
        row("one", passed=False, ran_at="t1"),
        row("one", passed=True, ran_at="t2"),
    ])

    compare(mixed, corpus, baseline, force=False)
    out = capsys.readouterr().out

    assert "0 case(s) failed once" not in out
    assert "failed and passed within the same comparison" in out


# ----------------------------------- what makes two failures one confirmation


def test_two_failures_under_different_prompts_are_not_a_confirmation(
        tmp_path, corpus, capsys):
    """A repetition is a repetition of the *same* experiment.

    The count was over every failing row in every file it was given, so a
    failure under one prompt and a failure under another were reported as a
    confirmed regression — the exact thing a repetition rule exists to rule
    out. `identity_of` cannot catch it either: it merges all the rows into one
    identity and cannot say which row came from which system.
    """
    baseline = tmp_path / "b.json"
    freeze(write(tmp_path, "before.json", [row("one")]), corpus, baseline)

    other = member()
    other["provenance"] = dict(other["provenance"], system_prompt_sha="zzz")

    first = write(tmp_path, "first.json",
                  [row("one", passed=False, run_id="r1")])
    again = write(tmp_path, "again.json",
                  [row("one", passed=False, run_id="r2",
                       members={"safe": other, "unsafe": other})])

    assert compare([first, again], corpus, baseline, force=True) == 2
    out = capsys.readouterr().out
    assert "failed once, unconfirmed" in out
    assert "regressed" not in out


def test_two_runs_begun_in_the_same_second_are_two_runs(tmp_path, corpus):
    """`ran_at` is stamped to the second, and at the start of the case.

    Keyed on it, two runs begun within one second — a scripted pair, a retry,
    anything concurrent — collapsed into one, which drops a confirming failure
    and reports a reproduced regression as an unconfirmed question.
    """
    baseline = tmp_path / "b.json"
    freeze(write(tmp_path, "before.json", [row("one")]), corpus, baseline)

    both = write(tmp_path, "after.json", [
        row("one", passed=False, ran_at="2026-09-01T10:00:00+00:00",
            run_id="r1"),
        row("one", passed=False, ran_at="2026-09-01T10:00:00+00:00",
            run_id="r2"),
    ])

    assert compare(both, corpus, baseline, force=False) == 1


def test_the_same_file_twice_is_not_a_confirmation(tmp_path, corpus):
    """The cheapest way to fake a re-run is to pass the file again."""
    baseline = tmp_path / "b.json"
    freeze(write(tmp_path, "before.json", [row("one")]), corpus, baseline)

    once = write(tmp_path, "after.json",
                 [row("one", passed=False, run_id="r1")])

    assert compare([once, once], corpus, baseline, force=False) == 2


def test_the_command_it_prints_can_actually_be_run(tmp_path, corpus, capsys):
    """The instruction was not runnable: `--provider` is required, and the
    printed line named none, so following it exactly ended in an argparse
    error and no second measurement. The provider is read from the row that
    failed — guessing a default would be worse, because one of the two bills.
    """
    import shlex

    from pair_corpus import _build_parser

    baseline = tmp_path / "b.json"
    freeze(write(tmp_path, "before.json", [row("one")]), corpus, baseline)

    served = member()
    served["provenance"] = dict(served["provenance"], provider="claude-cli")
    after = write(tmp_path, "after.json",
                  [row("one", passed=False,
                       members={"safe": served, "unsafe": served})])
    compare(after, corpus, baseline, force=False)

    printed = [line.strip() for line in capsys.readouterr().out.splitlines()
               if line.strip().startswith("tools/pair_corpus.py")]
    assert printed, "no command was printed to run"

    args = _build_parser().parse_args(shlex.split(printed[0])[1:])
    assert args.case == ["one"] and args.provider == "claude-cli"


def test_a_reproduced_failure_is_not_cancelled_by_a_later_pass(
        tmp_path, corpus, capsys):
    """A false green that was live.

    `[fail, fail, pass]` is mixed, and mixed was answered before the
    confirmation, so a regression reproduced twice was printed as "the suite
    moving on its own" and exited 0. Reproduced outranks moved: a later pass
    does not un-reproduce two failures, it makes the case one that fails some
    of the time, which is a failing case.
    """
    baseline = tmp_path / "b.json"
    freeze(write(tmp_path, "before.json", [row("one")]), corpus, baseline)

    history = write(tmp_path, "after.json", [
        row("one", passed=False, run_id="r1"),
        row("one", passed=False, run_id="r2"),
        row("one", passed=True, run_id="r3"),
    ])

    assert compare(history, corpus, baseline, force=False) == 1
    assert "regressed" in capsys.readouterr().out


def test_nothing_is_confirmed_from_runs_of_more_than_one_system(
        tmp_path, corpus, capsys):
    """Counting inside each group is not enough on its own.

    The tool has no notion of which group is the system under test, so two
    failures belonging to an older or foreign configuration — in a file
    somebody concatenated — were reported as a confirmed regression of the
    current one. Rather than guess which group is meant, the answer is that
    these inputs cannot say: exit 2, the case named, and two runs of one
    system asked for.
    """
    baseline = tmp_path / "b.json"
    freeze(write(tmp_path, "before.json", [row("one")]), corpus, baseline)

    other = member()
    other["provenance"] = dict(other["provenance"], system_prompt_sha="zzz")

    history = write(tmp_path, "after.json", [
        row("one", passed=False, run_id="r1"),
        row("one", passed=False, run_id="r2"),
        row("one", passed=True, run_id="r3",
            members={"safe": other, "unsafe": other}),
    ])

    assert compare(history, corpus, baseline, force=True) == 2
    out = capsys.readouterr().out
    assert "runs came from more than one system" in out
    assert "regressed" not in out


def test_a_pass_from_another_system_does_not_absorb_a_failure(
        tmp_path, corpus, capsys):
    """The second false green, reached from the other side.

    Instability was read across every row of the case, so a failure under the
    prompt being tested and a pass under a different one cancelled: the case
    was called unstable and exited 0. Neither run repeated the other, so the
    honest answer is the unconfirmed one — 2, and a named case to re-run.
    """
    baseline = tmp_path / "b.json"
    freeze(write(tmp_path, "before.json", [row("one")]), corpus, baseline)

    other = member()
    other["provenance"] = dict(other["provenance"], system_prompt_sha="zzz")

    split = write(tmp_path, "after.json", [
        row("one", passed=False, run_id="r1"),
        row("one", passed=True, run_id="r2",
            members={"safe": other, "unsafe": other}),
    ])

    assert compare(split, corpus, baseline, force=True) == 2
    out = capsys.readouterr().out
    assert "failed once, unconfirmed" in out
    assert "unstable: failed and passed" not in out


def test_the_denominator_is_the_history_of_one_system(
        tmp_path, corpus, capsys):
    """"2 of 3 runs" has to be three runs of the same thing.

    Counted across the whole file it put a pass produced by a different system
    in the same breath as two failures under this one — two experiments
    printed as one history.
    """
    baseline = tmp_path / "b.json"
    freeze(write(tmp_path, "before.json", [row("one")]), corpus, baseline)

    history = write(tmp_path, "after.json", [
        row("one", passed=False, run_id="r1"),
        row("one", passed=False, run_id="r2"),
        row("one", passed=True, run_id="r3"),
    ])

    assert compare(history, corpus, baseline, force=False) == 1
    assert "one (2 of 3 runs)" in capsys.readouterr().out


def test_one_passing_run_is_not_called_a_fix(tmp_path, corpus, capsys):
    """The same bar in the other direction.

    The pair that measured the noise turned a failure into a pass with nothing
    changed, so one passing run is not evidence of a fix — and "it passes now"
    was the exact sentence that measurement refuted. Neither answer gates; the
    word is what changes.
    """
    baseline = tmp_path / "b.json"
    freeze(write(tmp_path, "before.json", [row("one", passed=False)]),
           corpus, baseline)

    once = write(tmp_path, "after.json", [row("one", run_id="r1")])
    assert compare(once, corpus, baseline, force=False) == 0
    out = capsys.readouterr().out
    assert "passed once, unconfirmed" in out
    assert "fixed" not in out

    twice = write(tmp_path, "again.json", [
        row("one", run_id="r1"), row("one", run_id="r2")])
    assert compare(twice, corpus, baseline, force=False) == 0
    assert "fixed" in capsys.readouterr().out


def test_a_field_the_baseline_never_recorded_is_not_a_change(
        tmp_path, corpus, capsys):
    """`providers` was added to the identity after the format existed.

    Compared as a value, a baseline frozen before it reported the provider as
    having moved when nothing had, and a drift warning that is false is one
    that gets ignored. Not silently forgiven either: unknown is printed as
    unknown, because "not compared" and "compared, and equal" are the two
    things this tool exists to keep apart.
    """
    baseline = tmp_path / "b.json"
    served = member()
    served["provenance"] = dict(served["provenance"], provider="claude-cli")
    result = write(tmp_path, "r.json",
                   [row("one", members={"safe": served, "unsafe": served})])
    freeze(result, corpus, baseline)

    frozen = json.loads(baseline.read_text())
    frozen["identity"].pop("providers")
    baseline.write_text(json.dumps(frozen))

    assert compare(result, corpus, baseline, force=False) == 0
    out = capsys.readouterr().out
    assert "does not record it" in out
    assert "Under test — providers changed" not in out


def test_the_model_asked_for_is_recorded_beside_the_one_served(corpus):
    """Reading only what was served said "the model did not change" about two
    runs that asked for different models and were handed the same fallback —
    while the confirmation rule, which reads both, split them into two
    systems. The comparison's explanation then contradicted its verdict."""
    asked = member()
    asked["provenance"] = dict(asked["provenance"],
                               model_requested="claude-opus-5",
                               models_served=["claude-sonnet-5"])

    identity = identity_of([row("one", members={"safe": asked})], corpus,
                           ["one"])

    assert identity["model"] == ["claude-opus-5", "claude-sonnet-5"]


def test_deleting_a_field_from_the_baseline_does_not_switch_off_its_check(
        tmp_path, corpus, capsys):
    """The hole the compatibility exception opened.

    Absence was forgiven for every field, so removing a key from baseline.json
    removed the check it stood for — `corpus` included, which means a compare
    across an edited suite would have proceeded with no refusal, no warning
    and no `--force`. Only the fields added after baselines were already being
    frozen may read as "not recorded".
    """
    baseline = tmp_path / "b.json"
    result = write(tmp_path, "r.json", [row("a-case")])
    freeze(result, corpus, baseline)

    frozen = json.loads(baseline.read_text())
    frozen["identity"].pop("corpus")
    baseline.write_text(json.dumps(frozen))

    (corpus / "a-case" / "case.yml").write_text("expected_category: dos\n")

    assert compare(result, corpus, baseline, force=False) == 2
    assert "Refusing to compare" in capsys.readouterr().out


def test_a_fix_is_not_confirmed_across_systems_either(tmp_path, corpus, capsys):
    """The rule was applied to failures only.

    So a case could be printed as fixed and listed under "runs came from more
    than one system" in the same output — two passes from two configurations
    presented as a repetition.
    """
    baseline = tmp_path / "b.json"
    freeze(write(tmp_path, "before.json", [row("one", passed=False)]),
           corpus, baseline)

    other = member()
    other["provenance"] = dict(other["provenance"], system_prompt_sha="zzz")

    split = write(tmp_path, "after.json", [
        row("one", run_id="r1"),
        row("one", run_id="r2", members={"safe": other, "unsafe": other}),
    ])

    compare(split, corpus, baseline, force=True)
    out = capsys.readouterr().out
    assert "runs came from more than one system" in out
    assert "fixed" not in out


def test_runs_from_more_than_one_system_do_not_exit_zero(
        tmp_path, corpus, capsys):
    """The message said the inputs could not answer, and the process exited 0.

    With no failure anywhere, a case whose runs came from two systems printed
    "nothing is confirmed from them" and then "No regression against the
    frozen suite", and returned 0. A sentence that contradicts its own exit
    code is read by the exit code.
    """
    baseline = tmp_path / "b.json"
    freeze(write(tmp_path, "before.json", [row("one")]), corpus, baseline)

    other = member()
    other["provenance"] = dict(other["provenance"], system_prompt_sha="zzz")

    split = write(tmp_path, "after.json", [
        row("one", run_id="r1"),
        row("one", run_id="r2", members={"safe": other, "unsafe": other}),
    ])

    assert compare(split, corpus, baseline, force=True) == 2
    out = capsys.readouterr().out
    assert "No regression" not in out


def test_rows_that_do_not_say_what_produced_them_cannot_confirm(
        tmp_path, corpus, capsys):
    """Unknown is not a system two rows can share.

    A row with no provenance produced the same identity as any other such row,
    so two of them landed in one group and confirmed each other — a regression
    reported from runs whose configuration nothing recorded.
    """
    baseline = tmp_path / "b.json"
    freeze(write(tmp_path, "before.json", [row("one")]), corpus, baseline)

    blank = {"complete": True, "settings": {}}
    mute = write(tmp_path, "after.json", [
        row("one", passed=False, run_id="r1",
            members={"safe": blank, "unsafe": blank}),
        row("one", passed=False, run_id="r2",
            members={"safe": blank, "unsafe": blank}),
    ])

    assert compare(mute, corpus, baseline, force=True) == 2
    assert "regressed" not in capsys.readouterr().out


def test_the_current_state_is_the_latest_run_not_the_last_file(
        tmp_path, corpus, capsys):
    """`compare` concatenates the files in the order they were typed.

    Reading the last row as the current one made `compare new.json old.json`
    treat the older run as the state of every case, quietly reversing the
    verdicts below it. The stamp orders them, so the order of the arguments
    stops mattering.
    """
    baseline = tmp_path / "b.json"
    freeze(write(tmp_path, "before.json", [row("one")]), corpus, baseline)

    # The later run blew up; the earlier one passed. Given in the order that
    # puts the passing row last, the answer used to be "no regression".
    blew_up = write(tmp_path, "new.json",
                    [{"case_id": "one", "error": "boom", "run_id": "r2",
                      "ran_at": "2026-09-01T11:00:00.000000+00:00"}])
    passed = write(tmp_path, "old.json",
                   [row("one", run_id="r1",
                        ran_at="2026-09-01T10:00:00.000000+00:00")])

    assert compare([blew_up, passed], corpus, baseline, force=False) == 2
    out = capsys.readouterr().out
    assert "errored" in out
    assert "No regression" not in out


def test_partial_provenance_cannot_confirm_a_regression(
        tmp_path, corpus, capsys):
    """The unknown-system rule was walked around by half a record.

    Asking only whether *some* provenance existed let a row carrying nothing
    but a cost — or provenance on one member and none on the other — produce
    an ordinary identity whose prompt and model fields were all empty. Two of
    those then confirmed each other, which is a regression reported from runs
    whose system nothing recorded.
    """
    baseline = tmp_path / "b.json"
    freeze(write(tmp_path, "before.json", [row("one")]), corpus, baseline)

    half = member()
    half["provenance"] = {"reported_cost_usd": 0.41}
    thin = write(tmp_path, "after.json", [
        row("one", passed=False, run_id="r1",
            members={"safe": half, "unsafe": half}),
        row("one", passed=False, run_id="r2",
            members={"safe": half, "unsafe": half}),
    ])

    assert compare(thin, corpus, baseline, force=True) == 2
    assert "regressed" not in capsys.readouterr().out


def test_one_row_without_provenance_is_still_comparable(
        tmp_path, corpus, capsys):
    """Runners before provenance existed wrote files like this.

    A single legacy row confirms nothing on its own, and calling it
    unanswerable made every older result permanently uncomparable — a run with
    one passing row and no question in it included.
    """
    baseline = tmp_path / "b.json"
    blank = {"complete": True}
    legacy = [row("one", run_id="r1",
                  members={"safe": blank, "unsafe": blank})]
    result = write(tmp_path, "r.json", legacy)
    freeze(result, corpus, baseline)

    assert compare(result, corpus, baseline, force=False) == 0
    assert "No regression" in capsys.readouterr().out


def test_a_row_with_no_stamp_does_not_lose_to_an_older_one(
        tmp_path, corpus, capsys):
    """An unknown moment is not the earliest moment.

    Sorted as though it were, a new row carrying no stamp fell behind an old
    dated one, and the older result became the current state of the case — in
    `compare`, and worse in `freeze`, where it would be written into the
    baseline every later comparison is read against.
    """
    baseline = tmp_path / "b.json"
    freeze(write(tmp_path, "before.json", [row("one")]), corpus, baseline)

    history = write(tmp_path, "after.json", [
        row("one", passed=False, run_id="r1",
            ran_at="2026-08-01T10:00:00+00:00"),
        row("one", run_id="r2"),
    ])

    compare(history, corpus, baseline, force=False)
    out = capsys.readouterr().out
    assert "unstable" in out
    assert "regressed" not in out
