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
def test_a_moved_identity_refuses_the_comparison(tmp_path, corpus, capsys,
                                                 field, mutate):
    baseline = tmp_path / "b.json"
    freeze(write(tmp_path, "before.json", [row("one")]), corpus, baseline)

    after = [row("one")]
    mutate(after)
    assert compare(write(tmp_path, "after.json", after), corpus, baseline,
                   force=False) == 2
    out = capsys.readouterr().out
    assert "Refusing to compare" in out
    assert field in out


def test_editing_the_corpus_refuses_the_comparison(tmp_path, corpus, capsys):
    """A case edited between runs makes the two numbers about different code."""
    baseline = tmp_path / "b.json"
    result = write(tmp_path, "r.json", [row("one")])
    freeze(result, corpus, baseline)

    (corpus / "a-case" / "case.yml").write_text("expected_category: xss\n")
    assert compare(result, corpus, baseline, force=False) == 2
    assert "corpus" in capsys.readouterr().out


def test_force_compares_anyway_and_says_the_delta_is_not_attributable(
        tmp_path, corpus, capsys):
    baseline = tmp_path / "b.json"
    freeze(write(tmp_path, "before.json", [row("one")]), corpus, baseline)

    after = [row("one")]
    after[0]["members"]["safe"]["provenance"]["system_prompt_sha"] = "edited"
    compare(write(tmp_path, "after.json", after), corpus, baseline, force=True)
    assert "not attributable to the reviewer" in capsys.readouterr().out


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
    assert "absent from this run" in capsys.readouterr().out


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
