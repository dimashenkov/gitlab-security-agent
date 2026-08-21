"""Tests for vote aggregation — layer 3 of the hallucination check.

The asymmetry is the point: it should be easy for verifiers to downgrade a
finding and hard for a single one to discard a critical.
"""

from conftest import make_candidate
from security_agent.models import (
    VERDICT_CONFIRMED,
    VERDICT_REFUTED,
    VERDICT_UNCERTAIN,
    Vote,
)
from security_agent.verify import _decide, _votes_for


def vote(verdict, **kwargs):
    return Vote(verdict=verdict, reasoning=kwargs.pop("reasoning", "because"), **kwargs)


class TestVoteCounts:
    def test_high_and_critical_get_at_least_two_verifiers(self, config):
        config.verify_votes = 1
        assert _votes_for(config, make_candidate(severity="critical")) == 2
        assert _votes_for(config, make_candidate(severity="high")) == 2

    def test_lower_severities_use_the_configured_count(self, config):
        config.verify_votes = 1
        assert _votes_for(config, make_candidate(severity="medium")) == 1

    def test_configured_count_wins_when_higher(self, config):
        config.verify_votes = 3
        assert _votes_for(config, make_candidate(severity="medium")) == 3

    def test_capped_at_five(self, config):
        config.verify_votes = 5
        assert _votes_for(config, make_candidate(severity="critical")) == 5


class TestAggregation:
    def test_unanimous_confirmation_confirms(self):
        candidate = make_candidate(severity="medium")
        candidate.votes = [vote(VERDICT_CONFIRMED)]
        _decide(candidate)
        assert candidate.verdict == VERDICT_CONFIRMED

    def test_single_refutation_refutes_a_non_critical(self):
        candidate = make_candidate(severity="high")
        candidate.votes = [vote(VERDICT_REFUTED)]
        _decide(candidate)
        assert candidate.verdict == VERDICT_REFUTED

    def test_majority_refutation_refutes(self):
        candidate = make_candidate(severity="medium")
        candidate.votes = [vote(VERDICT_REFUTED), vote(VERDICT_REFUTED), vote(VERDICT_CONFIRMED)]
        _decide(candidate)
        assert candidate.verdict == VERDICT_REFUTED

    def test_a_split_is_uncertain(self):
        candidate = make_candidate(severity="medium")
        candidate.votes = [vote(VERDICT_REFUTED), vote(VERDICT_CONFIRMED)]
        _decide(candidate)
        assert candidate.verdict == VERDICT_UNCERTAIN


class TestCriticalAsymmetry:
    def test_one_dissenting_vote_cannot_discard_a_critical(self):
        candidate = make_candidate(severity="critical")
        candidate.votes = [vote(VERDICT_REFUTED), vote(VERDICT_CONFIRMED)]
        _decide(candidate)
        assert candidate.verdict == VERDICT_UNCERTAIN
        assert candidate.verdict != VERDICT_REFUTED

    def test_unanimous_refutation_does_discard_a_critical(self):
        candidate = make_candidate(severity="critical")
        candidate.votes = [vote(VERDICT_REFUTED), vote(VERDICT_REFUTED)]
        _decide(candidate)
        assert candidate.verdict == VERDICT_REFUTED


class TestCorrections:
    def test_downgrades_are_applied(self):
        candidate = make_candidate(severity="high", confidence="high")
        candidate.votes = [vote(VERDICT_CONFIRMED, corrected_severity="medium",
                                corrected_confidence="medium")]
        _decide(candidate)
        assert candidate.severity == "medium"
        assert candidate.confidence == "medium"

    def test_upgrades_are_ignored(self):
        # A verifier sees one finding in isolation; it may lower a rating but
        # never raise one.
        candidate = make_candidate(severity="medium")
        candidate.votes = [vote(VERDICT_CONFIRMED, corrected_severity="critical")]
        _decide(candidate)
        assert candidate.severity == "medium"

    def test_uncertain_forces_low_confidence(self):
        candidate = make_candidate(severity="high", confidence="high")
        candidate.votes = [vote(VERDICT_REFUTED), vote(VERDICT_CONFIRMED)]
        _decide(candidate)
        assert candidate.verdict == VERDICT_UNCERTAIN
        assert candidate.confidence == "low"

    def test_refuted_findings_keep_their_original_rating(self):
        candidate = make_candidate(severity="high")
        candidate.votes = [vote(VERDICT_REFUTED, corrected_severity="low")]
        _decide(candidate)
        assert candidate.severity == "high"


class TestVerifierFailures:
    def test_a_finding_survives_when_verification_could_not_run(self):
        # Being unable to check a claim is not evidence against it.
        candidate = make_candidate(severity="high")
        candidate.votes = [Vote(verdict=VERDICT_UNCERTAIN, reasoning="", error="API timeout")]
        _decide(candidate)
        assert candidate.verdict == VERDICT_CONFIRMED
        assert "unverified" in candidate.verdict_reason

    def test_failed_votes_do_not_count_toward_the_tally(self):
        candidate = make_candidate(severity="critical")
        candidate.votes = [
            vote(VERDICT_REFUTED),
            Vote(verdict=VERDICT_UNCERTAIN, reasoning="", error="boom"),
        ]
        _decide(candidate)
        # One usable vote, so the two-vote critical rule does not apply.
        assert candidate.verdict == VERDICT_REFUTED
