"""Tests for the pipeline verdict.

The rule that matters most here is the one about incomplete runs: an agent that
stopped early must never produce a green pipeline, because a green pipeline is
indistinguishable from "we checked and it's fine".
"""

from conftest import make_candidate
from security_agent.gate import EXIT_ERROR, EXIT_FINDINGS, EXIT_OK, blocking_findings, decide
from security_agent.models import (
    STOP_COMPLETED,
    STOP_REFUSAL,
    STOP_TURN_LIMIT,
    ScanOutcome,
)


def outcome_with(*candidates, **kwargs):
    outcome = ScanOutcome(mode="diff", stop_reason=kwargs.pop("stop_reason", STOP_COMPLETED))
    outcome.stop_detail = kwargs.pop("stop_detail", "")
    outcome.reported = list(candidates)
    for key, value in kwargs.items():
        setattr(outcome, key, value)
    return outcome


class TestIncompleteRuns:
    def test_turn_limit_is_an_error_not_a_pass(self, config):
        decision = decide(config, outcome_with(stop_reason=STOP_TURN_LIMIT))
        assert decision.exit_code == EXIT_ERROR
        assert "incomplete" in decision.reason.lower()

    def test_refusal_is_an_error_not_a_pass(self, config):
        decision = decide(config, outcome_with(stop_reason=STOP_REFUSAL))
        assert decision.exit_code == EXIT_ERROR

    def test_incomplete_can_be_allowed_through_explicitly(self, config):
        config.fail_on_incomplete = False
        decision = decide(config, outcome_with(stop_reason=STOP_TURN_LIMIT))
        assert decision.exit_code == EXIT_OK
        assert "did not complete" in decision.reason

    def test_incomplete_still_blocks_when_it_found_something(self, config):
        config.fail_on_incomplete = False
        decision = decide(config, outcome_with(make_candidate(), stop_reason=STOP_TURN_LIMIT))
        assert decision.exit_code == EXIT_FINDINGS


class TestThresholds:
    def test_high_blocks_at_the_default_threshold(self, config):
        decision = decide(config, outcome_with(make_candidate(severity="high")))
        assert decision.exit_code == EXIT_FINDINGS
        assert len(decision.blocking) == 1

    def test_medium_does_not_block_at_the_default_threshold(self, config):
        decision = decide(config, outcome_with(make_candidate(severity="medium")))
        assert decision.exit_code == EXIT_OK
        assert "below the high severity threshold" in " ".join(decision.non_blocking_reasons)

    def test_low_confidence_does_not_block(self, config):
        decision = decide(config, outcome_with(make_candidate(severity="critical", confidence="low")))
        assert decision.exit_code == EXIT_OK

    def test_fail_on_none_blocks_nothing(self, config):
        config.fail_on = "none"
        decision = decide(config, outcome_with(make_candidate(severity="critical")))
        assert decision.exit_code == EXIT_OK
        assert decision.blocking == []

    def test_clean_run_passes(self, config):
        decision = decide(config, outcome_with())
        assert decision.exit_code == EXIT_OK
        assert decision.reason == "No security findings."


class TestPreExisting:
    def test_pre_existing_does_not_block_by_default(self, config):
        candidate = make_candidate(severity="critical", in_changed_lines=False)
        decision = decide(config, outcome_with(candidate))
        assert decision.exit_code == EXIT_OK
        assert any("pre-existing" in note for note in decision.non_blocking_reasons)

    def test_pre_existing_blocks_when_opted_in(self, config):
        config.gate_pre_existing = True
        candidate = make_candidate(severity="critical", in_changed_lines=False)
        assert decide(config, outcome_with(candidate)).exit_code == EXIT_FINDINGS

    def test_introduced_findings_always_count(self, config):
        candidate = make_candidate(severity="high", in_changed_lines=True)
        assert decide(config, outcome_with(candidate)).exit_code == EXIT_FINDINGS


class TestBlockingSelection:
    def test_only_qualifying_findings_are_returned(self, config):
        candidates = [
            make_candidate(severity="critical", title="a"),
            make_candidate(severity="low", title="b"),
            make_candidate(severity="high", confidence="low", title="c"),
        ]
        blocking = blocking_findings(config, outcome_with(*candidates))
        assert [c.finding.title for c in blocking] == ["a"]

    def test_reasons_explain_everything_withheld(self, config):
        candidates = [
            make_candidate(severity="low", title="a"),
            make_candidate(severity="high", confidence="low", title="b"),
        ]
        decision = decide(config, outcome_with(*candidates))
        joined = " ".join(decision.non_blocking_reasons)
        assert "below the high severity threshold" in joined
        assert "below medium confidence" in joined
