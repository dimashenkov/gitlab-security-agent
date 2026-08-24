"""The instrument that produced the recall number, and how it produced a wrong one.

Six harvested advisories were reviewed and the result was 2 of 6. Three of the
four failures had exit code 2 — the review never completed. The scorer read
`payload["findings"]` and never `payload["complete"]`, so "the check did not
run" arrived in the table as `MISS`, indistinguishable from "the agent read the
code and found nothing".

The product is careful about exactly this: exit 0 means checked, exit 2 means it
did not reach an answer, and a crash must never exit with the code for "found
something". The tool that measures the product had no such distinction, so a
denominator of six was quietly built out of three real reviews and three that
stopped early — and the direction of the error is the one that makes the product
look worse than the evidence supports, which is the direction nobody
double-checks.

The tests below are the ones that would have caught it.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from pair_corpus import _is_target, _keep_artifacts, _progress, hits_target, report

CASE = {"case_id": "py-2cp2", "language": "python", "family": "injection",
        "expected_category": "injection", "expected_file": "app/views.py"}

TARGET = {"category": "injection", "file": "src/app/views.py",
          "severity": "high", "title": "Command injection in the target"}


def payload(*findings, complete=True, stop_reason="completed") -> dict:
    return {"complete": complete, "stop_reason": stop_reason,
            "findings": list(findings), "verdict": {"exit_code": 0}}


# ------------------------------------------------- the three-valued answer


def test_a_completed_run_that_found_the_target_says_so():
    assert hits_target(payload(TARGET), CASE) is True


def test_a_completed_run_that_found_nothing_says_so():
    assert hits_target(payload(), CASE) is False


def test_an_incomplete_run_is_not_an_answer():
    """The bug, in one assertion.

    `False` here is a claim about the agent. `None` is a claim about the run,
    and it is the only one the artifact supports.
    """
    assert hits_target(payload(complete=False, stop_reason="max_turns"), CASE) is None


def test_an_incomplete_run_is_unresolved_even_when_it_did_report_the_target():
    """A run can stop early after finding it, and that is still not a measurement.

    Scoring it as a hit would be the same error with the sign flipped: it would
    credit recall to a review that never finished looking.
    """
    assert hits_target(payload(TARGET, complete=False), CASE) is None


def test_an_artifact_with_no_completeness_field_is_unresolved():
    """Older artifacts predate the field. Absent is not the same as True."""
    assert hits_target({"findings": [TARGET]}, CASE) is None


# ------------------------------------------------------------ what counts


def test_the_target_is_matched_on_category_and_path_not_prose():
    """Reworded every run; grading on wording would measure phrasing."""
    reworded = dict(TARGET, title="Unsanitised argument reaches a shell")
    assert hits_target(payload(reworded), CASE) is True


def test_a_finding_of_the_right_kind_in_the_wrong_file_is_not_the_target():
    assert hits_target(payload(dict(TARGET, file="src/app/other.py")), CASE) is False


def test_a_finding_in_the_right_file_of_the_wrong_kind_is_not_the_target():
    assert hits_target(payload(dict(TARGET, category="xss")), CASE) is False


def test_one_rule_decides_both_target_and_incidental():
    """These were two implementations of the same sentence, free to drift."""
    assert _is_target(TARGET, CASE) is True
    assert _is_target(dict(TARGET, category="xss"), CASE) is False


# --------------------------------------------- a fix that spans two files


def test_a_fix_in_two_files_counts_in_either():
    """20 of the 48 harvested manifests named one file where the fix touched
    several. Winter's CSRF fix normalises a name in `BackendController.php`
    and rejects the bad ones in `Controller.php`; the manifest named the file
    without the check in it, so finding the check was scored as finding it in
    the wrong place."""
    case = dict(CASE, expected_file=["app/views.py", "app/forms.py"])
    assert hits_target(payload(dict(TARGET, file="src/app/forms.py")), case) is True
    assert hits_target(payload(dict(TARGET, file="src/app/views.py")), case) is True
    assert hits_target(payload(dict(TARGET, file="src/app/other.py")), case) is False


def test_a_single_path_still_works_as_a_bare_string():
    """The hand-written corpus writes one path, unquoted, and must keep working."""
    assert hits_target(payload(TARGET), dict(CASE, expected_file="app/views.py")) is True


def test_a_target_path_is_repository_relative_not_a_basename():
    """`Controller.php` alone also matches `BackendController.php`, which would
    widen the target without anyone deciding to."""
    case = dict(CASE, expected_file=["modules/backend/classes/Controller.php"])
    impostor = dict(TARGET, file="modules/backend/classes/BackendController.php")
    assert hits_target(payload(impostor), case) is False


def test_a_case_naming_no_file_matches_on_category_alone():
    case = {"expected_category": "injection"}
    assert hits_target(payload(dict(TARGET, file="anywhere.py")), case) is True


# ------------------------------------------------------------- the report


def test_an_unresolved_case_is_named_rather_than_counted(capsys):
    """It must not vanish. A denominator that drops the runs that stopped
    early reads as coverage the run does not have."""
    report([
        {"case_id": "py-2cp2", "language": "python", "family": "injection",
         "incomplete": ["unsafe"], "cost": 1.2, "seconds": 300,
         "members": {"unsafe": {"stop_reason": "max_turns"}}},
        {"case_id": "go-sql-01", "language": "go", "family": "injection",
         "pair_success": True, "safe_false_positive": False, "unsafe_recall": True,
         "cost": 0.4, "size_delta": 0.0},
    ])
    out = capsys.readouterr().out
    assert "did not complete" in out
    assert "py-2cp2" in out
    assert "max_turns" in out
    # And it is not in the score: one pair, not two.
    assert "across 1 pairs" in out


def test_a_run_of_nothing_but_unresolved_cases_scores_nothing(capsys):
    report([{"case_id": "py-2cp2", "language": "python", "family": "injection",
             "incomplete": ["safe", "unsafe"], "cost": 2.0, "seconds": 100,
             "members": {}}])
    out = capsys.readouterr().out
    assert "did not complete" in out
    assert "nothing to score" in out


# ------------------------------------------- the line that threw away a run


def test_the_progress_line_survives_every_shape_a_case_can_finish_in():
    """It indexed `r["pair_success"]`, which an unresolved case does not have.

    The KeyError was raised inside the `as_completed` loop — before the
    `--json` write — so the first case that stopped early discarded every case
    already paid for. The progress line is the least important thing on that
    screen and must not be able to end the run.
    """
    for row in ({"error": "boom"},
                {"incomplete": ["unsafe"]},
                {"incomplete": ["safe", "unsafe"]},
                {"pair_success": True},
                {"pair_success": False},
                {}):
        assert _progress(row)          # a string, and no exception

    assert _progress({"pair_success": True}) == "pass"
    assert _progress({"pair_success": False}) == "FAIL"
    assert "did not complete" in _progress({"incomplete": ["unsafe"]})


# ------------------------------------------------------- hand adjudications


def test_an_adjudicated_finding_shows_its_verdict(capsys):
    report(
        [{"case_id": "rs-8rw6", "language": "rust", "family": "authz",
          "pair_success": False, "safe_false_positive": False,
          "unsafe_recall": False, "cost": 1.4, "size_delta": 0.0,
          "safe_incidental": [{"category": "authorization", "file": "doc/output.rs",
                               "severity": "high", "title": "Computed fields re-added"}],
          "unsafe_incidental": []}],
        adjudications=[{"case_id": "rs-8rw6", "member": "safe",
                        "file": "doc/output.rs", "verdict": "real"}],
    )
    out = capsys.readouterr().out
    assert "real" in out


def test_an_unadjudicated_finding_says_so_rather_than_looking_decided(capsys):
    """Blank would read as 'nothing to see'. Two of the first three adjudicated
    were real, so a silent blank understates the product."""
    report([{"case_id": "x", "language": "go", "family": "injection",
             "pair_success": False, "safe_false_positive": False,
             "unsafe_recall": False, "cost": 0.5, "size_delta": 0.0,
             "safe_incidental": [{"category": "injection", "file": "a.go",
                                  "severity": "low", "title": "Something"}],
             "unsafe_incidental": []}])
    out = capsys.readouterr().out
    assert "unadjudicated" in out


def test_a_malformed_case_is_excluded_by_name(tmp_path):
    """py-2cp2's safe member still carries the advisory's own weakness, so the
    pair cannot discriminate in either direction. Excluding it must be visible
    — a corpus that quietly shrinks has a denominator nobody can check."""
    from pair_corpus import load_cases, malformed_cases

    (tmp_path / "adjudications.yml").write_text(
        "adjudications:\n"
        "  - case_id: bad-case\n"
        "    case_is_malformed: true\n"
        "    why_malformed: the safe member is not safe\n")
    for name in ("bad-case", "good-case"):
        (tmp_path / name).mkdir()
        (tmp_path / name / "case.yml").write_text("language: go\nfamily: injection\n")

    assert "bad-case" in malformed_cases(tmp_path)
    assert [c["case_id"] for c in load_cases(tmp_path)] == ["good-case"]


# ------------------------------------------------- keeping the evidence


def test_the_artifact_of_a_run_that_stopped_early_is_kept(tmp_path):
    """The runner deleted its temp directory unconditionally.

    When four reviews stopped early, the only record of which limit burned was
    already gone, and the diagnosis had to be reconstructed from the product's
    source — ending in "one of these two causes, cannot tell from here".
    """
    work, keep = tmp_path / "work", tmp_path / "keep"
    (work / "unsafe-out").mkdir(parents=True)
    (work / "unsafe-out" / "findings.json").write_text(
        '{"complete": false, "stop_reason": "context_exhausted", '
        '"stop_detail": "API error 400: prompt is too long"}')

    _keep_artifacts(work, {"case_id": "py-2cp2", "incomplete": ["unsafe"]}, keep)

    saved = keep / "py-2cp2" / "unsafe" / "findings.json"
    assert saved.is_file()
    assert "prompt is too long" in saved.read_text()


def test_a_clean_pass_leaves_nothing_behind(tmp_path):
    """It has nothing to explain, and 48 cases of artifacts is its own problem."""
    work, keep = tmp_path / "work", tmp_path / "keep"
    (work / "safe-out").mkdir(parents=True)
    (work / "safe-out" / "findings.json").write_text("{}")

    _keep_artifacts(work, {"case_id": "ok", "pair_success": True}, keep)
    assert not keep.exists() or not list(keep.rglob("findings.json"))


def test_stop_detail_survives_into_the_signature():
    """It is the only field that says which limit burned, and it was dropped."""
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.insert(0, str(_Path(__file__).resolve().parents[1] / "tools"))
    from artifact import signature

    row = signature({"complete": False, "stop_reason": "context_exhausted",
                     "stop_detail": "API error 400: prompt is too long"}, {})
    assert row["stop_detail"] == "API error 400: prompt is too long"
