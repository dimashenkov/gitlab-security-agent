"""Tests for vote aggregation — layer 3 of the hallucination check.

The asymmetry is the point: it should be easy for verifiers to downgrade a
finding and hard for a single one to discard a critical.
"""

import threading
import time

from conftest import make_candidate, make_finding
from security_agent.models import (
    VERDICT_CONFIRMED,
    VERDICT_REFUTED,
    VERDICT_UNCERTAIN,
    Usage,
    Vote,
)
from security_agent.verify import (
    _could_block,
    _decide,
    _partition,
    _votes_for,
    verify_candidates,
)


def vote(verdict, **kwargs):
    return Vote(verdict=verdict, reasoning=kwargs.pop("reasoning", "because"), **kwargs)


class TestVoteCounts:
    def test_findings_that_could_block_get_an_odd_panel(self, config):
        config.verify_votes = 1
        assert _votes_for(config, make_candidate(severity="critical")) == 3
        assert _votes_for(config, make_candidate(severity="high")) == 3

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
    def test_uncertain_forces_low_confidence(self):
        candidate = make_candidate(severity="high", confidence="high")
        candidate.votes = [vote(VERDICT_REFUTED), vote(VERDICT_CONFIRMED)]
        _decide(candidate)
        assert candidate.verdict == VERDICT_UNCERTAIN
        assert candidate.confidence == "low"


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


class TestVerificationScope:
    """Which findings are worth the cost of a verifier.

    Verification exists to stop the gate blocking on something unreal. A finding
    that cannot block has nothing to be protected from — and on a typical run
    those are most of them, so this is the largest avoidable cost in the tool.
    """

    def test_a_blocking_finding_is_verified(self, config):
        candidate = make_candidate(severity="high", confidence="high")
        gating, informational = _partition(config, [candidate])
        assert gating == [candidate] and informational == []

    def test_below_the_severity_threshold_is_not_verified(self, config):
        candidate = make_candidate(severity="low")
        gating, informational = _partition(config, [candidate])
        assert gating == [] and informational == [candidate]

    def test_a_severe_finding_is_verified_however_low_its_confidence(self, config):
        # The case that motivated this: the agent rated a real pickle.loads on
        # untrusted bytes `high` severity but only `low` confidence, so it fell
        # below the gate, was never verified, and passed silently. A cautious
        # first impression must not be able to bury a severe finding.
        candidate = make_candidate(severity="critical", confidence="low")
        gating, informational = _partition(config, [candidate])
        assert gating == [candidate] and informational == []

    def test_below_the_severity_threshold_is_still_skipped(self, config):
        # Severity only ever moves down, so no verdict can lift this over the bar.
        candidate = make_candidate(severity="low", confidence="high")
        _, informational = _partition(config, [candidate])
        assert informational == [candidate]

    def test_pre_existing_is_not_verified_by_default(self, config):
        candidate = make_candidate(severity="critical", in_changed_lines=False)
        _, informational = _partition(config, [candidate])
        assert informational == [candidate]

    def test_pre_existing_is_verified_when_it_can_block(self, config):
        config.gate_pre_existing = True
        candidate = make_candidate(severity="critical", in_changed_lines=False)
        gating, _ = _partition(config, [candidate])
        assert gating == [candidate]

    def test_nothing_is_verified_when_the_gate_is_off(self, config):
        config.fail_on = "none"
        candidate = make_candidate(severity="critical", confidence="high")
        gating, informational = _partition(config, [candidate])
        assert gating == [] and informational == [candidate]

    def test_one_step_below_the_threshold_is_still_verified(self, config):
        # Ratings can now be raised, so "below the bar" no longer means settled:
        # a medium finding is exactly what two verifiers might agree is high.
        candidate = make_candidate(severity="medium", confidence="high")
        gating, informational = _partition(config, [candidate])
        assert gating == [candidate] and informational == []

    def test_two_steps_below_is_not_verified(self, config):
        # A low finding promoted straight to high would be an extraordinary
        # disagreement, and verifying every low finding costs more than it is
        # worth. It still appears in the report.
        candidate = make_candidate(severity="low", confidence="high")
        _, informational = _partition(config, [candidate])
        assert informational == [candidate]

    def test_skipped_findings_say_why_in_the_report(self, config, monkeypatch):
        candidate = make_candidate(severity="low")
        verify_candidates(config, object(), object(), [candidate])
        assert candidate.verdict == VERDICT_CONFIRMED
        assert "cannot block" in candidate.verdict_reason
        assert "below the high severity threshold" in candidate.verdict_reason

    def test_skipping_costs_no_api_calls(self, config):
        # A client that would explode if touched proves nothing was sent.
        class Exploding:
            def __getattr__(self, name):
                raise AssertionError("the verifier must not be called")

        candidate = make_candidate(severity="low")
        usage = verify_candidates(config, object(), Exploding(), [candidate])
        assert usage.requests == 0


class TestOneHedgeCannotDecideTheGate:
    """The instability that made every other number unreadable.

    Four identical runs of one unsafe case gave three blocks and one pass — 3
    of 6 run pairs agreed. Nothing about the code changed between them. One
    verifier of two said `uncertain` where the others said `confirmed`; that
    alone forced the verdict to uncertain, uncertain forces confidence to
    `low`, and `low` is under the gate. A single hedge ungated a real finding,
    and which way a run went depended on how one reply happened to be phrased.

    Two verifiers cannot form a majority, so the outcome had to be settled by a
    rule, and the rule was unanimity. These tests hold the panel odd and the
    decision majority, so what decides the gate is what most verifiers saw.
    """

    def test_a_lone_hedge_among_three_does_not_unblock(self, config):
        candidate = make_candidate(severity="high", confidence="high")
        candidate.votes = [
            vote(VERDICT_CONFIRMED), vote(VERDICT_CONFIRMED),
            vote(VERDICT_UNCERTAIN),
        ]
        _decide(candidate)
        assert candidate.verdict == VERDICT_CONFIRMED
        assert candidate.confidence == "high"

    def test_two_hedges_among_three_do_leave_it_uncertain(self, config):
        """The majority is what decides, in both directions."""
        candidate = make_candidate(severity="high", confidence="high")
        candidate.votes = [
            vote(VERDICT_CONFIRMED), vote(VERDICT_UNCERTAIN),
            vote(VERDICT_UNCERTAIN),
        ]
        _decide(candidate)
        assert candidate.verdict == VERDICT_UNCERTAIN
        assert candidate.confidence == "low"

    def test_a_lone_refusal_among_three_does_not_discard_it(self, config):
        candidate = make_candidate(severity="high", confidence="high")
        candidate.votes = [
            vote(VERDICT_CONFIRMED), vote(VERDICT_CONFIRMED),
            vote(VERDICT_REFUTED),
        ]
        _decide(candidate)
        assert candidate.verdict == VERDICT_CONFIRMED

    def test_a_blocking_finding_never_gets_an_even_panel(self, config):
        """An even panel has no majority, so a rule decides instead of evidence."""
        for level in ("high", "critical"):
            for configured in (1, 2, 3, 4):
                config.verify_votes = configured
                panel = _votes_for(config, make_candidate(severity=level))
                assert panel % 2 == 1, (level, configured, panel)
                assert panel >= 3

    def test_the_panel_follows_the_threshold_not_a_fixed_level(self, config):
        """A project gating on `medium` needs medium findings settled too."""
        config.fail_on = "medium"
        assert _votes_for(config, make_candidate(severity="medium")) >= 3

    def test_one_verifier_can_still_not_delete_a_critical(self, config):
        """The protection the old asymmetry was written for, still standing."""
        candidate = make_candidate(severity="critical", confidence="high")
        candidate.votes = [
            vote(VERDICT_CONFIRMED), vote(VERDICT_CONFIRMED),
            vote(VERDICT_REFUTED),
        ]
        _decide(candidate)
        assert candidate.verdict != VERDICT_REFUTED


class TestConfidenceIsDecidedByThePanel:
    """Confidence used to be settled by whoever was least sure.

    It took the minimum, and took it across every usable vote rather than the
    confirming ones its own docstring named — so a verifier outvoted on whether
    the finding was even real still set the confidence for the panel. Because
    `low` is under the gate, that reply decided whether the merge was blocked.
    Fixing the verdict rule without this one would have left the same veto
    intact one step downstream.
    """

    def test_an_outvoted_verifier_does_not_set_the_confidence(self, config):
        candidate = make_candidate(severity="high", confidence="high")
        candidate.votes = [
            vote(VERDICT_CONFIRMED), vote(VERDICT_CONFIRMED),
            vote(VERDICT_UNCERTAIN, corrected_confidence="low"),
        ]
        _decide(candidate)
        assert candidate.confidence == "high"

    def test_one_confirming_verifier_alone_does_not_lower_it(self, config):
        candidate = make_candidate(severity="high", confidence="high")
        candidate.votes = [
            vote(VERDICT_CONFIRMED), vote(VERDICT_CONFIRMED),
            vote(VERDICT_CONFIRMED, corrected_confidence="low"),
        ]
        _decide(candidate)
        assert candidate.confidence == "high"

    def test_a_majority_does_lower_it(self, config):
        candidate = make_candidate(severity="high", confidence="high")
        candidate.votes = [
            vote(VERDICT_CONFIRMED),
            vote(VERDICT_CONFIRMED, corrected_confidence="low"),
            vote(VERDICT_CONFIRMED, corrected_confidence="low"),
        ]
        _decide(candidate)
        assert candidate.confidence == "low"

    def test_a_majority_can_still_raise_it(self, config):
        """The property that was worth keeping from the old rule.

        An agent hedging at `low` on a real weakness used to bury it
        permanently, because nothing downstream could undo a cautious first
        impression. Verifiers who read the callers know more than it did.
        """
        candidate = make_candidate(severity="high", confidence="low")
        candidate.votes = [
            vote(VERDICT_CONFIRMED, corrected_confidence="high"),
            vote(VERDICT_CONFIRMED, corrected_confidence="high"),
            vote(VERDICT_CONFIRMED),
        ]
        _decide(candidate)
        assert candidate.confidence == "high"

    def test_silence_counts_as_agreeing_with_the_claim(self, config):
        candidate = make_candidate(severity="high", confidence="medium")
        candidate.votes = [vote(VERDICT_CONFIRMED) for _ in range(3)]
        _decide(candidate)
        assert candidate.confidence == "medium"


class TestVerificationScopeIsIndependentOfGating:
    """What gets verified must not depend on what gets gated.

    These two questions look adjacent and are not. Verification asks whether a
    claim about the code is true; gating asks whether a true claim should stop
    a merge. Letting the second decide the first means a project that relaxes
    its policy quietly stops *checking*, and every finding it does report
    becomes less trustworthy at exactly the moment it is trusted more.

    It also made the setting impossible to study: with the two tied together,
    turning the removed-control rule off stopped verifying deletion-attributed
    findings, so "no longer gated" and "no longer verified" moved as one and no
    experiment could tell which had produced a difference.
    """

    def test_a_deleted_guard_is_verified_with_the_rule_on(self, config):
        config.gate_removed_controls = True
        candidate = make_candidate(severity="low", attributed_by="deleted")
        gating, _ = _partition(config, [candidate])
        assert gating == [candidate]

    def test_a_deleted_guard_is_verified_with_the_rule_off_too(self, config):
        """The regression. Off, this used to fall through to the severity test.

        A `low` finding attributed to a deletion then came back unverified
        rather than merely ungated — a project that had switched the rule off
        was told less about its own change, not just gated less on it.
        """
        config.gate_removed_controls = False
        candidate = make_candidate(severity="low", attributed_by="deleted")
        gating, informational = _partition(config, [candidate])
        assert gating == [candidate]
        assert informational == []

    def test_the_gating_rule_changes_no_verification_decision(self, config):
        """Swept across the settings, the partition must be identical."""
        candidates = [
            make_candidate(severity=level, attributed_by=attribution,
                           confidence=confidence)
            for level in ("low", "medium", "high", "critical")
            for attribution in ("added", "deleted", "")
            for confidence in ("low", "high")
        ]
        config.gate_removed_controls = True
        with_rule = _partition(config, candidates)
        config.gate_removed_controls = False
        without_rule = _partition(config, candidates)
        assert with_rule == without_rule


class TestConcurrentVerification:
    """Votes run in parallel; the aggregate must not depend on who finishes first.

    Measured before this: verification took 280 seconds of a 320-second job
    while the review itself took 100. The votes are independent conversations,
    so they were queueing for no reason.
    """

    def _candidates(self, n):
        return [make_candidate(severity="high", title="finding {}".format(i))
                for i in range(n)]

    def test_votes_are_attached_in_a_stable_order(self, config, monkeypatch):
        # Completion order is reversed relative to submission order; the vote
        # attached first must still be vote 0.
        import security_agent.verify as verify

        def fake_vote(cfg, ws, client, system, tools, candidate, vote_index):
            time.sleep(0.05 if vote_index == 0 else 0.0)
            return Vote(verdict=VERDICT_CONFIRMED,
                        reasoning="vote-{}".format(vote_index)), Usage()

        monkeypatch.setattr(verify, "_one_vote", fake_vote)
        monkeypatch.setattr(verify, "_system_blocks", lambda cfg: [])
        monkeypatch.setattr(verify, "read_only_tool_definitions", lambda diff_available: [])

        candidate = make_candidate(severity="high")
        verify.verify_candidates(config, _StubWorkspace(), object(), [candidate])

        assert [v.reasoning for v in candidate.votes] == ["vote-0", "vote-1", "vote-2"]

    def test_calls_actually_overlap(self, config, monkeypatch):
        import security_agent.verify as verify

        config.verify_concurrency = 4
        active, peak = [0], [0]
        lock = threading.Lock()

        def fake_vote(cfg, ws, client, system, tools, candidate, vote_index):
            with lock:
                active[0] += 1
                peak[0] = max(peak[0], active[0])
            time.sleep(0.05)
            with lock:
                active[0] -= 1
            return Vote(verdict=VERDICT_CONFIRMED, reasoning="r"), Usage()

        monkeypatch.setattr(verify, "_one_vote", fake_vote)
        monkeypatch.setattr(verify, "_system_blocks", lambda cfg: [])
        monkeypatch.setattr(verify, "read_only_tool_definitions", lambda diff_available: [])

        verify.verify_candidates(config, _StubWorkspace(), object(), self._candidates(4))
        assert peak[0] > 1, "verification ran sequentially"

    def test_concurrency_respects_the_configured_ceiling(self, config, monkeypatch):
        import security_agent.verify as verify

        config.verify_concurrency = 2
        active, peak = [0], [0]
        lock = threading.Lock()

        def fake_vote(cfg, ws, client, system, tools, candidate, vote_index):
            with lock:
                active[0] += 1
                peak[0] = max(peak[0], active[0])
            time.sleep(0.05)
            with lock:
                active[0] -= 1
            return Vote(verdict=VERDICT_CONFIRMED, reasoning="r"), Usage()

        monkeypatch.setattr(verify, "_one_vote", fake_vote)
        monkeypatch.setattr(verify, "_system_blocks", lambda cfg: [])
        monkeypatch.setattr(verify, "read_only_tool_definitions", lambda diff_available: [])

        verify.verify_candidates(config, _StubWorkspace(), object(), self._candidates(4))
        assert peak[0] <= 2

    def test_a_raising_worker_does_not_kill_the_run(self, config, monkeypatch):
        import security_agent.verify as verify

        def fake_vote(cfg, ws, client, system, tools, candidate, vote_index):
            if vote_index == 0:
                raise RuntimeError("worker exploded")
            return Vote(verdict=VERDICT_CONFIRMED, reasoning="ok"), Usage()

        monkeypatch.setattr(verify, "_one_vote", fake_vote)
        monkeypatch.setattr(verify, "_system_blocks", lambda cfg: [])
        monkeypatch.setattr(verify, "read_only_tool_definitions", lambda diff_available: [])

        candidate = make_candidate(severity="high")
        verify.verify_candidates(config, _StubWorkspace(), object(), [candidate])

        # The crash becomes an unusable vote, not a lost run — and being unable
        # to check a claim is not evidence against it.
        assert any(v.error for v in candidate.votes)
        assert candidate.verdict == VERDICT_CONFIRMED

    def test_usage_from_every_worker_is_counted(self, config, monkeypatch):
        import security_agent.verify as verify

        def fake_vote(cfg, ws, client, system, tools, candidate, vote_index):
            u = Usage()
            u.requests, u.output_tokens = 1, 100
            return Vote(verdict=VERDICT_CONFIRMED, reasoning="r"), u

        monkeypatch.setattr(verify, "_one_vote", fake_vote)
        monkeypatch.setattr(verify, "_system_blocks", lambda cfg: [])
        monkeypatch.setattr(verify, "read_only_tool_definitions", lambda diff_available: [])

        usage = verify.verify_candidates(config, _StubWorkspace(), object(), self._candidates(3))
        assert usage.requests == 9  # 3 findings x 3 votes each at high severity
        assert usage.output_tokens == 900


class _StubWorkspace:
    diff_base = ""


class TestConfidenceMovesBothWays:
    """Confidence records how much of the chain was seen, so a verifier that
    read the callers may know better than the agent that guessed.

    Severity stays one-directional for the opposite reason: it is a judgement
    about impact, where the agent had the wider view.

    **The rule under this changed on 2026-08-24.** It used to be "lowering takes
    one voice, raising takes all", justified as erring toward a visible finding.
    In gate terms it erred the other way: `low` is under the threshold, so a
    single voice lowering it made the finding invisible to the gate and the
    merge went through. Measured, that produced two different exit codes across
    four identical runs of the same code.

    It is now the median of the confirming verifiers. Confidence still moves in
    both directions — that property is why this class exists and it is kept —
    but it takes a majority to move it either way, and no single verifier can
    decide the gate.
    """

    def test_agreeing_verifiers_can_raise_confidence(self):
        candidate = make_candidate(severity="high", confidence="low")
        candidate.votes = [
            Vote(verdict=VERDICT_CONFIRMED, reasoning="found the caller",
                 corrected_confidence="high"),
            Vote(verdict=VERDICT_CONFIRMED, reasoning="traced it too",
                 corrected_confidence="high"),
            Vote(verdict=VERDICT_CONFIRMED, reasoning="and again",
                 corrected_confidence="high"),
        ]
        _decide(candidate)
        assert candidate.confidence == "high"

    def test_a_lone_voice_cannot_raise_it(self):
        # Silence is agreement with the claim, not a vote to change it.
        candidate = make_candidate(severity="high", confidence="low")
        candidate.votes = [
            Vote(verdict=VERDICT_CONFIRMED, reasoning="a", corrected_confidence="high"),
            Vote(verdict=VERDICT_CONFIRMED, reasoning="b"),
            Vote(verdict=VERDICT_CONFIRMED, reasoning="c"),
        ]
        _decide(candidate)
        assert candidate.confidence == "low"

    def test_a_lone_voice_cannot_lower_it_either(self):
        """The half of the old rule that was doing the damage.

        Under "lowering takes one voice", this returned `low`, the finding fell
        under the gate, and the merge proceeded — decided by one reply out of
        three.
        """
        candidate = make_candidate(severity="high", confidence="high")
        candidate.votes = [
            Vote(verdict=VERDICT_CONFIRMED, reasoning="a", corrected_confidence="low"),
            Vote(verdict=VERDICT_CONFIRMED, reasoning="b"),
            Vote(verdict=VERDICT_CONFIRMED, reasoning="c"),
        ]
        _decide(candidate)
        assert candidate.confidence == "high"

    def test_the_middle_opinion_wins(self):
        candidate = make_candidate(severity="high", confidence="low")
        candidate.votes = [
            Vote(verdict=VERDICT_CONFIRMED, reasoning="a", corrected_confidence="high"),
            Vote(verdict=VERDICT_CONFIRMED, reasoning="b", corrected_confidence="medium"),
            Vote(verdict=VERDICT_CONFIRMED, reasoning="c", corrected_confidence="medium"),
        ]
        _decide(candidate)
        assert candidate.confidence == "medium"

    def test_an_uncertain_verdict_still_forces_low(self):
        candidate = make_candidate(severity="high", confidence="high")
        candidate.votes = [
            Vote(verdict=VERDICT_CONFIRMED, reasoning="a", corrected_confidence="high"),
            Vote(verdict=VERDICT_REFUTED, reasoning="b"),
        ]
        _decide(candidate)
        assert candidate.verdict == VERDICT_UNCERTAIN
        assert candidate.confidence == "low"

    def test_the_pickle_case_now_blocks(self, config):
        # End to end over the exact shape that slipped through: high severity,
        # agent hedged at low confidence, verifiers found it real.
        candidate = make_candidate(severity="high", confidence="low",
                                   category="deserialization")
        gating, _ = _partition(config, [candidate])
        assert gating == [candidate], "it must at least be verified"

        candidate.votes = [
            Vote(verdict=VERDICT_CONFIRMED, reasoning="added by this change",
                 corrected_confidence="high"),
            Vote(verdict=VERDICT_CONFIRMED, reasoning="no sanitisation",
                 corrected_confidence="high"),
        ]
        _decide(candidate)
        assert _could_block(config, candidate)


class TestSeverityComesFromFacts:
    """Severity is computed, not voted on.

    It was the one rating that moved between runs on identical input, because
    "how bad is this" depends on things the diff does not contain. Verifiers now
    correct the *facts* — what the attacker gets, whether authentication is
    needed, whether a victim must act — and the number follows from them.
    """

    def test_the_label_the_agent_proposed_is_ignored(self):
        from security_agent.models import Candidate

        # The reviewer says `low`; the facts say code execution.
        finding = make_finding(severity="low", impact="code_execution",
                               reachable_without_authentication="yes",
                               requires_user_interaction="no")
        assert Candidate(finding=finding).severity == "critical"

    def test_authentication_and_interaction_each_cost_a_step(self):
        from security_agent.models import Candidate

        finding = make_finding(impact="code_execution",
                               reachable_without_authentication="no",
                               requires_user_interaction="yes")
        assert Candidate(finding=finding).severity == "medium"

    def test_unclear_changes_nothing(self):
        from security_agent.models import Candidate

        # The point of `unclear`: a model that cannot tell must not be rewarded
        # for guessing, and the same non-answer must give the same result.
        a = Candidate(finding=make_finding(impact="broad_data_access",
                                           reachable_without_authentication="unclear",
                                           requires_user_interaction="unclear"))
        b = Candidate(finding=make_finding(impact="broad_data_access",
                                           reachable_without_authentication="unclear",
                                           requires_user_interaction="unclear"))
        assert a.severity == b.severity == "high"

    def test_the_derivation_is_recorded(self):
        from security_agent.models import Candidate

        c = Candidate(finding=make_finding(impact="narrow_data_access",
                                           reachable_without_authentication="no",
                                           requires_user_interaction="no"))
        assert "narrow_data_access" in c.severity_derivation
        assert "authentication required" in c.severity_derivation

    def test_unanimous_verifiers_can_correct_a_fact(self):
        candidate = make_candidate(impact="narrow_data_access",
                                   reachable_without_authentication="no",
                                   requires_user_interaction="no")
        before = candidate.severity
        candidate.votes = [
            Vote(verdict=VERDICT_CONFIRMED, reasoning="found an unauthenticated route",
                 corrected_reachable="yes"),
            Vote(verdict=VERDICT_CONFIRMED, reasoning="same",
                 corrected_reachable="yes"),
        ]
        _decide(candidate)
        assert before == "low" and candidate.severity == "medium"
        assert "verifiers corrected" in candidate.severity_derivation

    def test_a_split_on_the_facts_changes_nothing(self):
        candidate = make_candidate(impact="broad_data_access",
                                   reachable_without_authentication="no",
                                   requires_user_interaction="no")
        candidate.votes = [
            Vote(verdict=VERDICT_CONFIRMED, reasoning="a", corrected_reachable="yes"),
            Vote(verdict=VERDICT_CONFIRMED, reasoning="b", corrected_reachable="unclear"),
        ]
        _decide(candidate)
        assert candidate.severity == "medium", "disagreeing verifiers must not move it"

    def test_an_unknown_impact_falls_back_to_the_reviewer(self):
        from security_agent.models import Candidate

        c = Candidate(finding=make_finding(severity="high", impact="something_new"))
        assert c.severity == "high"
        assert "not derived" in c.severity_derivation
