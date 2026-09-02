"""Reading one artifact — and refusing to read one that says nothing.

Every question this module answers is asked of fields that may be absent, and
three of them answered the reassuring thing when they were: two runs that
recorded nothing "agreed", a verdict with no `blocked` field "did not block",
and a case manifest with no answer key made every finding the weakness the case
was about. All three are the same defect — a check satisfied by the absence of
the data rather than by the data — and each one raises a number somebody else
then reads as a measurement.

Each test names what went wrong and what it cost.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import artifact


def run(exit_code=1, blocking=(("injection", "app/views.py", 0),),
        target_blocks=True):
    """A row of the shape `signature` writes."""
    return {
        "exit_code": exit_code,
        "blocking": sorted(list(row) for row in blocking),
        "target": {"blocking": target_blocks} if target_blocks is not None
        else None,
    }


class TestTwoRunsThatRecordedNothingDidNotAgree:
    """`controls_agree` compared values that default to absent, so two rows
    with nothing in them passed every test and returned True.

    `stability.py` sums that straight into an agreement rate and
    `injection_corpus.control_agreement` into another — the numbers that decide
    whether every other measurement in this project can be read. Artifacts with
    no recorded exit code raised both of them.
    """

    def test_two_empty_rows_are_refused_not_agreed(self):
        with pytest.raises(artifact.Incomparable):
            artifact.controls_agree({}, {})

    def test_two_rows_with_nothing_in_common_are_refused(self):
        with pytest.raises(artifact.Incomparable):
            artifact.controls_agree({"x": 1}, {"y": 2})

    def test_one_unreadable_side_is_enough_to_refuse(self):
        with pytest.raises(artifact.Incomparable):
            artifact.controls_agree(run(), {"blocking": [], "target": None})

    def test_a_run_with_no_exit_code_is_not_comparable(self):
        assert artifact.comparable({}) is False
        assert artifact.comparable({"exit_code": None}) is False
        assert artifact.comparable(run()) is True

    def test_two_recorded_runs_still_compare(self):
        """The refusal is about rows with no gate outcome, and nothing else:
        an empty blocking list and a `None` target are answers a run can give.
        """
        empty = run(exit_code=0, blocking=(), target_blocks=None)
        assert artifact.controls_agree(empty, run(exit_code=0, blocking=(),
                                                  target_blocks=None)) is True
        assert artifact.controls_agree(run(), run(exit_code=0)) is False


class TestAbsenceIsNotAVerdictAboutTheGate:
    def test_a_verdict_with_no_blocked_field_is_recorded_as_unknown(self):
        """`bool(verdict.get("blocked"))` stored "nobody wrote down what the
        gate did" as "the gate did not block".

        `finished_explicitly`, two lines below it in the same dict, already had
        the reason written out — an absent field counted as a negative answer
        poisons the rate it feeds with artifacts that predate the question.
        This field did not get the same treatment.
        """
        assert artifact.signature({}, {})["blocked"] is None
        assert artifact.signature({"verdict": {}}, {})["blocked"] is None

    def test_a_recorded_gate_decision_is_kept_as_it_was(self):
        assert artifact.signature(
            {"verdict": {"blocked": False}}, {})["blocked"] is False
        assert artifact.signature(
            {"verdict": {"blocked": True}}, {})["blocked"] is True


class TestACaseWithNoAnswerKeyHasNoTarget:
    def test_an_empty_manifest_does_not_make_every_finding_the_target(self):
        """`is_target(anything, {})` was True.

        `if wanted and ...` skipped the category test when no category was
        named, and `if not paths: return True` accepted any file when none was
        named — so a `case.yml` that failed to parse scored a review as having
        found the weakness the case is about. `check_accounted.verdicts` feeds
        `yaml.safe_load(...) or {}` straight in, and `check_corpus.py` calls
        each absence a problem that nothing here acted on.
        """
        finding = {"category": "anything", "file": "zzz.py"}
        assert artifact.is_target(finding, {}) is False
        assert artifact.target_disposition({"findings": [finding]}, {}) is None

    def test_one_missing_field_is_still_the_documented_looseness(self):
        """A case naming a category and no file matches that category anywhere,
        and a case naming a file and no category matches anything in it. Both
        are written down in `target_categories` and `target_paths`; only both
        at once is silence rather than looseness.
        """
        anywhere = {"expected_category": ["injection"]}
        assert artifact.is_target({"category": "injection", "file": "z.py"},
                                  anywhere) is True
        assert artifact.is_target({"category": "xss", "file": "z.py"},
                                  anywhere) is False

        in_one_file = {"expected_file": ["app/views.py"]}
        assert artifact.is_target({"category": "xss", "file": "app/views.py"},
                                  in_one_file) is True
        assert artifact.is_target({"category": "xss", "file": "other.py"},
                                  in_one_file) is False
