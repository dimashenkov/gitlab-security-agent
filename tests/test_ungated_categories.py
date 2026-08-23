"""Categories a project has chosen not to gate on.

Distinct from a suppression, and the distinction is the point. A suppression
says "we accept this specific risk" and is recorded per finding. This says "this
whole class does not stop merges here" — a standing policy — and so the finding
must still be reported in full. A policy that quietly deletes findings is
indistinguishable from a blind spot six months later.

These tests exercise the chain: config → gate → both rendered outputs. The
schema-level tests are the ones that were green last time the gate was broken.
"""

from __future__ import annotations

import pytest

from security_agent import report, terminal
from security_agent.config import Config
from security_agent.gate import EXIT_FINDINGS, EXIT_OK, decide
from security_agent.models import Candidate, Finding, ScanOutcome


def make_candidate(category="denial_of_service", severity="high", **overrides) -> Candidate:
    finding = Finding(
        title="Unbounded request body is read into memory",
        category=category, severity=severity, confidence="high",
        file="api/upload.py", line=12,
        description="No size limit.",
        exploit_scenario="A large upload exhausts the worker's memory.",
        recommendation="Cap the body size.",
        evidence="body = request.stream.read()",
        impact="denial_of_service",
        reachable_without_authentication="yes",
        requires_user_interaction="no",
    )
    candidate = Candidate(finding=finding, **overrides)
    candidate.severity = severity
    return candidate


def outcome_with(*candidates) -> ScanOutcome:
    outcome = ScanOutcome(mode="diff", model="claude-opus-5")
    outcome.reported = list(candidates)
    return outcome


def config(**overrides) -> Config:
    cfg = Config(post_comment=False, **overrides)
    return cfg


# ---------------------------------------------------------------------- gate


def test_an_excluded_category_does_not_block():
    candidate = make_candidate()
    decision = decide(config(ungated_categories=("denial_of_service",)),
                      outcome_with(candidate))
    assert decision.exit_code == EXIT_OK
    assert decision.blocking == []


def test_the_same_finding_blocks_without_the_exclusion():
    """The pair that proves the setting is what changed the verdict."""
    candidate = make_candidate()
    assert decide(config(), outcome_with(candidate)).exit_code == EXIT_FINDINGS


def test_other_categories_still_block():
    excluded = make_candidate()
    other = make_candidate(category="injection")
    decision = decide(config(ungated_categories=("denial_of_service",)),
                      outcome_with(excluded, other))
    assert decision.exit_code == EXIT_FINDINGS
    assert decision.blocking == [other]


def test_the_exclusion_is_case_insensitive():
    candidate = make_candidate(category="Denial_Of_Service")
    decision = decide(config(ungated_categories=("denial_of_service",)),
                      outcome_with(candidate))
    assert decision.exit_code == EXIT_OK


def test_a_removed_control_in_an_excluded_category_does_not_block():
    """The knob does exactly what its name says, with no unstated exception.

    A team that has ruled out a class of weakness has ruled out guards for that
    class. Making the removed-control rule survive the exclusion would produce a
    gate nobody can predict from the setting they wrote.
    """
    candidate = make_candidate(removes_control=True)
    decision = decide(config(ungated_categories=("denial_of_service",)),
                      outcome_with(candidate))
    assert decision.exit_code == EXIT_OK
    assert candidate in decision.policy_excluded


def test_removed_control_still_blocks_in_a_category_that_is_gated():
    candidate = make_candidate(category="authorization", severity="low",
                               removes_control=True)
    decision = decide(config(ungated_categories=("denial_of_service",)),
                      outcome_with(candidate))
    assert decision.exit_code == EXIT_FINDINGS


# --------------------------------------------------------------- visibility


def test_the_finding_is_still_reported_not_deleted():
    """The whole difference between this and a suppression."""
    candidate = make_candidate()
    outcome = outcome_with(candidate)
    decide(config(ungated_categories=("denial_of_service",)), outcome)
    assert outcome.reported == [candidate]
    assert outcome.suppressed == []


def test_the_verdict_names_the_setting_that_let_it_through():
    candidate = make_candidate()
    decision = decide(config(ungated_categories=("denial_of_service",)),
                      outcome_with(candidate))
    notes = " ".join(decision.non_blocking_reasons)
    assert "SECURITY_SCAN_UNGATED_CATEGORIES" in notes
    assert "denial_of_service" in notes


def test_the_job_log_marks_the_finding_itself(monkeypatch):
    monkeypatch.setenv("NO_COLOR", "1")
    candidate = make_candidate()
    outcome = outcome_with(candidate)
    decision = decide(config(ungated_categories=("denial_of_service",)), outcome)
    text = terminal.render(outcome, decision)
    assert "not gated — category excluded" in text
    assert "advisory" not in text


def test_the_markdown_report_marks_the_finding_itself():
    candidate = make_candidate()
    outcome = outcome_with(candidate)
    cfg = config(ungated_categories=("denial_of_service",))
    markdown = report.render_markdown(cfg, outcome, decide(cfg, outcome))
    assert "not gated — category excluded by policy" in markdown
    assert candidate.finding.evidence in markdown


def test_a_withheld_finding_is_counted_under_one_reason_only():
    """Counted twice, four findings read as seven and the numbers lose credit."""
    candidate = make_candidate(severity="low")
    decision = decide(config(ungated_categories=("denial_of_service",)),
                      outcome_with(candidate))
    notes = decision.non_blocking_reasons
    assert sum(1 for n in notes if "UNGATED_CATEGORIES" in n) == 1
    assert not any("below the high severity threshold" in n for n in notes)


def test_nothing_changes_when_no_category_is_excluded():
    candidate = make_candidate()
    outcome = outcome_with(candidate)
    decision = decide(config(), outcome)
    assert decision.policy_excluded == []
    assert decision.exit_code == EXIT_FINDINGS


# -------------------------------------------------------------------- config


@pytest.mark.parametrize("raw,expected", [
    ("denial_of_service", ("denial_of_service",)),
    ("denial_of_service, Logging", ("denial_of_service", "logging")),
    ("", ()),
])
def test_the_setting_is_read_from_the_environment(monkeypatch, raw, expected):
    monkeypatch.setenv("SECURITY_SCAN_UNGATED_CATEGORIES", raw)
    assert Config.from_env().ungated_categories == expected
