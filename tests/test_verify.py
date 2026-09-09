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
    StageMetrics,
    Usage,
    Vote,
)
from security_agent.verify import (
    _brief,
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

    def test_a_finding_one_step_under_the_bar_still_gets_a_panel(self, config):
        """It can be corrected over the bar, so it can block on one vote.

        This asserted `medium` gets a single verifier under a `high` threshold,
        which was the hole: `_worth_verifying` reaches one step below the bar
        precisely because a verdict can lift a finding over it, and a lift from
        one voice is the single-verifier decision odd panels exist to prevent.
        """
        config.verify_votes = 1
        assert _votes_for(config, make_candidate(severity="medium")) == 3

    def test_a_finding_that_cannot_reach_the_bar_uses_the_configured_count(self, config):
        # Two steps under: no verdict lifts it that far, so nothing it returns
        # can block, so there is nothing for a panel to protect.
        config.verify_votes = 1
        assert _votes_for(config, make_candidate(severity="low")) == 1

    def test_a_low_deletion_gets_a_panel_because_it_can_block_anyway(self, config):
        """A removed control blocks whatever the severity says.

        So a `low` finding attributed to a deletion could be called a removed
        control by one verifier and block on that alone — severity never
        entered into it, which is why sizing the panel on severity missed this.
        """
        config.verify_votes = 1
        candidate = make_candidate(severity="low")
        candidate.attributed_by = "deleted"
        assert _votes_for(config, candidate) == 3

    def test_no_panel_when_the_category_is_ungated(self, config):
        config.verify_votes = 1
        config.ungated_categories = ("injection",)
        assert _votes_for(config, make_candidate(severity="high")) == 1

    def test_configured_count_wins_when_higher(self, config):
        config.verify_votes = 3
        assert _votes_for(config, make_candidate(severity="medium")) == 3

    def test_a_critical_keeps_its_panel_when_nothing_can_block(self, config):
        """Three routes reach one seat for a critical, and each is a setting
        about the *exit code*.

        `fail_threshold=None`, an ungated category, and a pre-existing finding
        under `gate_pre_existing=false` all make `_could_become_blocking`
        false — so the panel collapsed to one verifier, and one `uncertain`
        reply or one errored session deleted a critical from the report a
        person reads. Turning the gate off is asking not to be blocked, not
        asking to be left uninformed. Codex, 2026-09-09.
        """
        config.verify_votes = 1

        config.fail_on = "none"
        assert _votes_for(config, make_candidate(severity="critical")) == 3

        config.fail_on = "high"
        config.ungated_categories = ("injection",)
        assert _votes_for(config, make_candidate(severity="critical")) == 3

        config.ungated_categories = ()
        config.gate_pre_existing = False
        pre_existing = make_candidate(severity="critical")
        pre_existing.in_changed_lines = False
        assert _votes_for(config, pre_existing) == 3

    def test_a_low_finding_under_the_same_settings_does_not(self, config):
        """The control. Without it the rule above could be "everything gets
        three seats", which is a bill rather than a protection."""
        config.verify_votes = 1
        config.fail_on = "none"
        assert _votes_for(config, make_candidate(severity="low")) == 1

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

    def test_a_lone_survivor_cannot_refute_a_panel_of_three(self):
        """This passed on a panel of two, which `_votes_for` cannot produce.

        Panels are one, three or five. Built at two, the old assertion held for
        a reason that never occurs in a run — and its stated rule, that a
        failed vote does not count toward the tally, is now only half true: it
        does not agree with anything, and it does hold its seat in the
        denominator. Rebuilt at the size a real panel has.

        Two dead sessions must not do what three dead sessions cannot: being
        unable to check a claim is not evidence against it, so the finding
        stands on what the reviewer said.
        """
        candidate = make_candidate(severity="critical")
        candidate.votes = [
            vote(VERDICT_REFUTED),
            Vote(verdict=VERDICT_UNCERTAIN, reasoning="", error="boom"),
            Vote(verdict=VERDICT_UNCERTAIN, reasoning="", error="boom"),
        ]
        _decide(candidate)

        assert candidate.verdict == VERDICT_CONFIRMED
        assert "never reported" in candidate.verdict_reason

    def test_a_full_panel_of_three_still_refutes_on_a_majority(self):
        """The control. A rule that ignored every refutation would be safe and
        useless, and this is the case the one above must not have broken."""
        candidate = make_candidate(severity="high")
        candidate.votes = [vote(VERDICT_REFUTED), vote(VERDICT_REFUTED),
                           vote(VERDICT_CONFIRMED)]
        _decide(candidate)

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

    def test_turning_the_gate_off_does_not_turn_the_checking_off(self, config):
        """`FAIL_ON=none` used to skip verification entirely.

        The reasoning was that verification decides gating, so with no gate
        there is nothing to decide. That is backwards for the deployment this
        project settled on: advisory mode is where the report IS the product,
        and an unverified finding is exactly what wastes the reader's time —
        no independent refutation, no odd panel, no requirement that a
        confirmation say what it searched for.

        It was also the obvious way to make the tool advisory. Someone who does
        not want a blocked merge reaches for this and silently loses every
        protection built for the finding rather than for the gate. The way to
        make it advisory is `allow_failure: true` on the job.
        """
        config.fail_on = "none"
        candidate = make_candidate(severity="critical", confidence="high")
        gating, informational = _partition(config, [candidate])
        assert gating == [candidate] and informational == []

    def test_with_no_gate_the_scope_floor_is_the_default_not_everything(self, config):
        """Verifying every `low` on a large change costs more than it buys, and
        that is true whether or not a gate exists."""
        config.fail_on = "none"
        low = make_candidate(severity="low", confidence="high")
        gating, informational = _partition(config, [low])
        assert gating == [] and informational == [low]

        medium = make_candidate(severity="medium", confidence="high")
        gating, _ = _partition(config, [medium])
        assert gating == [medium], "one step below the default floor still counts"

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


class TestNoSingleVerifierPathToTheGate:
    """Every remaining way one reply could decide a merge.

    The first pass at this fixed the obvious path — an even panel plus
    unanimity — and left three more in the branches it did not look at. All
    three are the same mistake: a rule whose bar was set by what it read as
    the cautious direction, without checking which way the exit code moved.
    """

    def test_a_critical_is_confirmed_by_a_majority_not_by_everyone(self, config):
        """Unanimity was required to *confirm*, which is backwards.

        The asymmetry was written to make a critical hard to dismiss. Read as
        written, two verifiers confirming and one hedging gave `uncertain`,
        which forces confidence to `low`, which is under the gate — so the rule
        protecting criticals was the easiest way to ungate one.
        """
        candidate = make_candidate(severity="critical", confidence="high")
        candidate.votes = [
            vote(VERDICT_CONFIRMED), vote(VERDICT_CONFIRMED),
            vote(VERDICT_UNCERTAIN),
        ]
        _decide(candidate)
        assert candidate.verdict == VERDICT_CONFIRMED
        assert candidate.confidence == "high"

    def test_a_critical_still_needs_every_verifier_to_discard_it(self, config):
        """The facts derive the rating, rather than the rating being pinned.

        `severity="critical"` on the candidate used to be enough, because the
        panel read whatever state it was handed. It derives its own now, so a
        test that pinned a rating the facts do not support was asserting about
        a candidate no run produces — and a fixture in an impossible state is
        how an impossible document went unnoticed for a day.
        """
        candidate = make_candidate(impact="code_execution", confidence="high")
        assert candidate.severity == "critical"
        candidate.votes = [
            vote(VERDICT_REFUTED), vote(VERDICT_REFUTED), vote(VERDICT_CONFIRMED),
        ]
        _decide(candidate)
        assert candidate.verdict != VERDICT_REFUTED

    def test_the_critical_branch_reads_the_derived_severity(self, config):
        """Not the model's own label, which is the part that moves between runs.

        Reading `finding.severity` here restored a dependence on a rated label
        that computing severity from facts was introduced to remove.
        """
        # `severity=` on the model's own finding says critical; the derived
        # rating on the candidate says high.
        candidate = make_candidate(severity="high", confidence="high",
                                   severity_claimed="critical")
        candidate.votes = [
            vote(VERDICT_REFUTED), vote(VERDICT_REFUTED), vote(VERDICT_CONFIRMED),
        ]
        _decide(candidate)
        # Majority refutes and it is not critical by the derived rating, so the
        # critical protection does not apply.
        assert candidate.verdict == VERDICT_REFUTED

    def test_one_verifier_cannot_correct_a_fact_across_the_gate(self, config):
        """Severity is computed from these facts, so a correction moves the gate.

        A lone proposal used to carry when the others were silent — and the
        proposer might be the verifier outvoted on whether the finding was real.
        """
        candidate = make_candidate(
            confidence="high", impact="metadata_disclosure",
            reachable_without_authentication="yes",
            requires_user_interaction="no")
        candidate.votes = [
            vote(VERDICT_CONFIRMED, corrected_impact="code_execution"),
            vote(VERDICT_CONFIRMED), vote(VERDICT_CONFIRMED),
        ]
        _decide(candidate)
        assert "code_execution" not in candidate.severity_derivation

    def test_a_majority_can_correct_a_fact(self, config):
        candidate = make_candidate(
            confidence="high", impact="metadata_disclosure",
            reachable_without_authentication="yes",
            requires_user_interaction="no")
        candidate.votes = [
            vote(VERDICT_CONFIRMED, corrected_impact="code_execution"),
            vote(VERDICT_CONFIRMED, corrected_impact="code_execution"),
            vote(VERDICT_CONFIRMED),
        ]
        _decide(candidate)
        assert candidate.severity == "critical"


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
        monkeypatch.setattr(verify, "verifier_tool_definitions",
                            lambda schema, diff_available: [])

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
        monkeypatch.setattr(verify, "verifier_tool_definitions",
                            lambda schema, diff_available: [])

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
        monkeypatch.setattr(verify, "verifier_tool_definitions",
                            lambda schema, diff_available: [])

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
        monkeypatch.setattr(verify, "verifier_tool_definitions",
                            lambda schema, diff_available: [])

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
        monkeypatch.setattr(verify, "verifier_tool_definitions",
                            lambda schema, diff_available: [])

        usage = verify.verify_candidates(config, _StubWorkspace(), object(), self._candidates(3))
        assert usage.requests == 9  # 3 findings x 3 votes each at high severity
        assert usage.output_tokens == 900


class _StubWorkspace:
    diff_base = ""


class TestTheVerifiedCountMatchesWhatWasVerified:
    """`verification.verified` in the artifact, against the findings' own reasons.

    Counted above the SECURITY_SCAN_VERIFY_MAX cut, it counted arrivals rather
    than verifications: on any run over the limit the artifact said N verified
    while N-of-those carried the reason "not verified — beyond the
    SECURITY_SCAN_VERIFY_MAX limit". One artifact, two answers.
    """

    def _patch(self, monkeypatch):
        import security_agent.verify as verify

        def fake_vote(cfg, ws, client, system, tools, candidate, vote_index):
            return Vote(verdict=VERDICT_CONFIRMED, reasoning="r"), Usage()

        monkeypatch.setattr(verify, "_one_vote", fake_vote)
        monkeypatch.setattr(verify, "_system_blocks", lambda cfg: [])
        monkeypatch.setattr(verify, "verifier_tool_definitions",
                            lambda schema, diff_available: [])
        return verify

    def test_findings_past_the_limit_are_not_counted_as_verified(self, config, monkeypatch):
        verify = self._patch(monkeypatch)
        config.verify_max_findings = 1
        metrics = StageMetrics()

        candidates = [make_candidate(severity="high", title="finding {}".format(i))
                      for i in range(3)]
        verify.verify_candidates(config, _StubWorkspace(), object(), candidates,
                                 metrics=metrics)

        assert metrics.verified == 1

    def test_no_finding_is_both_counted_and_told_it_was_not_verified(
            self, config, monkeypatch):
        # The contradiction itself, asserted without naming a number: whatever
        # `verified` says, it may not exceed the findings that actually got a
        # panel. Anything else is a report arguing with itself.
        verify = self._patch(monkeypatch)
        config.verify_max_findings = 2
        metrics = StageMetrics()

        candidates = [make_candidate(severity="high", title="finding {}".format(i))
                      for i in range(5)]
        verify.verify_candidates(config, _StubWorkspace(), object(), candidates,
                                 metrics=metrics)

        assert metrics.verified == sum(1 for c in candidates if c.votes)
        assert all(not c.votes for c in candidates
                   if "not verified" in (c.verdict_reason or ""))


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


class TestConfirmationsCarryTheirEvidence:
    """The Winter failure, turned into a rule.

    A reviewer reported a real local defect — `execPageAction` discards its
    404 and falls through — as a security weakness, and a verifier confirmed
    it. Neither opened the caller. Every caller runs `actionExists` on the
    same object first, so one function would have refuted it.

    Both prompts already said to read the callers, and had for weeks. So the
    fix is not another sentence: a confirmation now has to state what would
    have refuted the finding and where it looked, or it is not a confirmation.
    """

    def test_a_confirmation_that_shows_no_search_becomes_uncertain(self):
        from security_agent.panel import require_evidence

        vote = require_evidence(Vote(
            verdict=VERDICT_CONFIRMED,
            reasoning="The 404 is discarded and the action runs anyway."))

        assert vote.verdict == VERDICT_UNCERTAIN
        assert "downgraded from confirmed" in vote.reasoning
        # And it says which link was missing, so the report can be argued with.
        assert "refute" in vote.reasoning

    def test_a_token_answer_does_not_count_as_a_search(self):
        """"checked" is not a statement about the code."""
        from security_agent.panel import require_evidence

        for excuse in ("", "n/a", "checked", "yes", "looked"):
            vote = require_evidence(Vote(
                verdict=VERDICT_CONFIRMED, reasoning="Confirmed.",
                control_search=excuse))
            assert vote.verdict == VERDICT_UNCERTAIN, excuse

    def test_a_confirmation_that_names_what_it_searched_survives(self):
        from security_agent.panel import require_evidence

        vote = require_evidence(Vote(
            verdict=VERDICT_CONFIRMED,
            reasoning="No caller validates.",
            control_search="Searched modules/backend for a call to "
                           "actionExists before dispatch; none of the three "
                           "callers performs one."))

        assert vote.verdict == VERDICT_CONFIRMED

    def test_claiming_unauthenticated_reach_requires_naming_the_entry(self):
        """The claim that escalates severity is the claim that needs evidence."""
        from security_agent.panel import require_evidence

        vote = require_evidence(Vote(
            verdict=VERDICT_CONFIRMED, reasoning="Reachable.",
            control_search="Searched app/ and lib/ for an auth decorator on "
                           "the route; there is none.",
            corrected_reachable="yes"))

        assert vote.verdict == VERDICT_UNCERTAIN
        assert "entry point" in vote.reasoning

    def test_naming_the_entry_point_lets_it_stand(self):
        from security_agent.panel import require_evidence

        vote = require_evidence(Vote(
            verdict=VERDICT_CONFIRMED, reasoning="Reachable.",
            control_search="Searched app/ and lib/ for an auth decorator on "
                           "the route; there is none.",
            corrected_reachable="yes",
            entry_point="app/urls.py:8 routes /export to the handler with no "
                        "authentication middleware"))

        assert vote.verdict == VERDICT_CONFIRMED

    def test_an_empty_refutation_is_downgraded_too(self):
        """This test used to assert the opposite, with the reasoning that
        "refuting is the direction that already costs it something".

        It costs nothing. `refuted` removes the candidate from the report
        entirely; `uncertain` keeps it visible, tagged "unverified chain", at
        low confidence. So the rule guarded the direction that would *report*
        something and left open the one that makes a finding disappear — three
        empty refutations discarded a critical finding with no reasoning and no
        search recorded anywhere. Found by `gpt-6-astra` on 2026-09-06.

        Codex adjudicated the shape on 2026-09-07: leaving it "preserves an
        unauditable path for deleting findings", and demanding prose alone
        "only proves the model produced prose; it does not prove it inspected
        code" — so a refutation states the control, caller or broken link it
        found and where.
        """
        from security_agent.panel import require_evidence

        vote = require_evidence(Vote(verdict=VERDICT_REFUTED, reasoning="No."))
        assert vote.verdict == VERDICT_UNCERTAIN
        assert "downgraded from refuted" in vote.reasoning
        assert "control, caller or broken link" in vote.reasoning

    def test_a_downgraded_vote_carries_no_decision_with_it(self):
        """Codex, 2026-09-07, on the gate pass for this very repair.

        `replace` kept every field but the verdict, so a unanimous panel of
        evidence-free refutations carrying `removes_existing_control: yes`
        became usable `uncertain` seats whose flag still set `removes_control`
        — and that flag gates whatever the severity and confidence say. The
        repair for silent deletion would have turned quiet refuters into a
        merge wall instead: the same verifiers, the opposite failure.

        A vote that could not say what it looked at has not established the
        control was removed either. The seat is kept; its claims are not.
        """
        from security_agent.panel import decide
        from security_agent.panel import require_evidence

        votes = [require_evidence(Vote(verdict=VERDICT_REFUTED,
                                        reasoning="No.",
                                        removes_control="yes"))
                 for _ in range(3)]
        assert all(v.verdict == VERDICT_UNCERTAIN for v in votes)
        assert all(v.removes_control == "" for v in votes)

        decided = decide(make_finding(severity="high"), votes)
        assert decided.removes_control is False, \
            "evidence-free refutations blocked the merge as a removed control"

    def test_a_real_removed_control_still_gates(self):
        """The control. A rule that cleared the flag from every vote would make
        the removed-control path unreachable, which is a different failure."""
        from security_agent.panel import decide
        from security_agent.panel import require_evidence

        votes = [require_evidence(Vote(
            verdict=VERDICT_CONFIRMED,
            reasoning="The check is gone.",
            control_search="require_admin, removed from views.py line 40",
            removes_control="yes")) for _ in range(3)]
        assert all(v.verdict == VERDICT_CONFIRMED for v in votes)

        decided = decide(make_finding(severity="high"), votes)
        assert decided.removes_control is True

    def test_a_refutation_that_says_what_it_found_stands(self):
        """The other half. A rule that refused every refutation would make the
        panel unable to discard anything, which is a different failure."""
        from security_agent.panel import require_evidence

        vote = require_evidence(Vote(
            verdict=VERDICT_REFUTED,
            reasoning="Every caller validates first.",
            control_search="require_admin in views.py line 40, on both paths"))
        assert vote.verdict == VERDICT_REFUTED

    def test_an_uncertain_vote_is_left_alone(self):
        """It is already the answer this rule downgrades *to*."""
        from security_agent.panel import require_evidence

        vote = require_evidence(Vote(verdict=VERDICT_UNCERTAIN,
                                      reasoning="Could not establish it."))
        assert vote.verdict == VERDICT_UNCERTAIN
        assert "downgraded" not in vote.reasoning

    def test_a_refutation_is_not_asked_for_an_entry_point(self):
        """The entry-point rule is about reachability being *claimed*, not
        denied. Asking a refutation to name the attacker's way in would be
        asking it to argue the case it is refuting."""
        from security_agent.panel import require_evidence

        vote = require_evidence(Vote(
            verdict=VERDICT_REFUTED, reasoning="Not reachable.",
            control_search="the router registers no public path for it",
            corrected_reachable="yes"))
        assert vote.verdict == VERDICT_REFUTED

    def test_a_finding_that_does_not_claim_unauthenticated_reach_needs_no_entry(self):
        """A hardcoded credential has no call chain, and demanding one would
        push a whole class of true findings into `uncertain`."""
        from security_agent.panel import require_evidence

        vote = require_evidence(Vote(
            verdict=VERDICT_CONFIRMED, reasoning="The key is in the repository.",
            control_search="Searched for a vault lookup or env indirection "
                           "around this constant; the literal is used directly.",
            corrected_reachable="unclear"))

        assert vote.verdict == VERDICT_CONFIRMED


class TestTheVerifierSeesWhatAdmittedTheFinding:
    """Codex, 2026-09-06, on the gate pass for the deletion repair.

    `report_finding` validates a citation from a deleted file through
    `removed_text`, at the base revision. The verifier reloaded through
    `raw_text`, which necessarily fails there — so a finding about a removed
    authorisation check was admitted and then handed to a verifier that could
    not see the evidence which admitted it. The likely vote is `refuted`, for
    a reason that has nothing to do with the code.
    """

    def deletion_only(self, git_repo):
        import subprocess
        env = {"GIT_AUTHOR_NAME": "Test", "GIT_AUTHOR_EMAIL": "t@example.com",
               "GIT_COMMITTER_NAME": "Test",
               "GIT_COMMITTER_EMAIL": "t@example.com",
               "PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": str(git_repo)}

        def git(*args):
            return subprocess.run(("git", "-C", str(git_repo), *args),
                                  check=True, capture_output=True, text=True,
                                  env=env).stdout

        (git_repo / "auth.py").write_text(
            "def check(user):\n"
            "    if not user.is_admin:\n"
            "        raise Denied()\n", encoding="utf-8")
        git("add", "-A")
        git("commit", "-qm", "the guard")
        base = git("rev-parse", "HEAD").strip()
        (git_repo / "auth.py").unlink()
        git("add", "-A")
        git("commit", "-qm", "remove the guard")
        return base, git("rev-parse", "HEAD").strip()

    def test_the_brief_carries_the_removed_lines(self, git_repo):
        from security_agent.config import Config
        from security_agent.workspace import Workspace

        base, head = self.deletion_only(git_repo)
        ws = Workspace(root=git_repo, diff_base=base, diff_head=head,
                       excludes=())
        # `make_candidate` builds its own finding from the same overrides;
        # a `finding=` kwarg is ignored and the default path survives, which
        # is how the first version of this test read `app/views.py`.
        candidate = make_candidate(attributed_by="deleted", file="auth.py",
                                   line=3, evidence="        raise Denied()")

        brief = _brief(Config.from_env(), ws, candidate, 0)
        assert "raise Denied()" in brief
        assert "was deleted by the change" in brief
        assert "base revision" in brief


class _ForbiddenClient:
    """Any attribute of this is a paid call, so it raises instead.

    The panel then errors on every vote through the path a real outage takes —
    `verify_candidates` catching an exception out of a worker — rather than
    through a stub that hands back errored votes ready-made.
    """

    def __getattr__(self, name):
        raise RuntimeError("a paid API call was attempted: client.{}".format(name))


class _EmptyWorkspace:
    """A workspace with no files, so `_brief` takes its documented error path."""

    diff_base = ""

    def raw_text(self, path):
        from security_agent.workspace import WorkspaceError

        raise WorkspaceError("this workspace holds no files")

    removed_text = raw_text


class TestEveryFindingLeavesTheStageInOneBasket:
    """The counters the `Verified` row is built from, at the runner.

    Two populations used to be counted nowhere. A finding past
    SECURITY_SCAN_VERIFY_MAX was stamped `confirmed` with the reason "not
    verified — beyond the limit" and appeared in no total; a finding whose every
    verifier call errored was counted in `verification_failed` *and* in
    `verified`. So the terminal's denominator — `verified + skipped` — could
    never be smaller than its numerator, and the row could only read "N of N".

    Measured 2026-09-07 with `_ForbiddenClient`: three unverified criticals
    rendered "0 of 0", four dead panels rendered "4 of 4". Adjudicated the same
    day: keep the dispositions apart instead of forcing them into one ratio.
    """

    def _patch(self, monkeypatch, vote=None):
        import security_agent.verify as verify

        if vote is not None:
            monkeypatch.setattr(
                verify, "_one_vote",
                lambda cfg, ws, client, system, tools, candidate, index: (
                    vote(candidate, index), Usage()))
        monkeypatch.setattr(verify, "_system_blocks", lambda cfg: [])
        monkeypatch.setattr(verify, "verifier_tool_definitions",
                            lambda schema, diff_available: [])
        return verify

    def test_findings_past_the_limit_are_counted_as_over_the_limit(
            self, config, monkeypatch):
        verify = self._patch(monkeypatch)
        config.verify_max_findings = 0
        metrics = StageMetrics()
        candidates = [make_candidate(severity="critical", title="crit {}".format(i))
                      for i in range(3)]

        verify.verify_candidates(config, _EmptyWorkspace(), _ForbiddenClient(),
                                 candidates, metrics=metrics)

        assert metrics.verification_over_limit == 3
        # The number the row needs: three findings entered the stage, none of
        # them completed. Before this, both sides of the ratio were zero.
        assert metrics.verification_presented == 3
        assert metrics.verification_completed == 0

    def test_a_panel_whose_every_call_failed_did_not_complete(
            self, config, monkeypatch):
        self._patch(monkeypatch)
        import security_agent.verify as verify

        config.verify_votes = 1
        metrics = StageMetrics()
        candidates = [make_candidate(severity="high", title="finding {}".format(i))
                      for i in range(4)]

        verify.verify_candidates(config, _EmptyWorkspace(), _ForbiddenClient(),
                                 candidates, metrics=metrics)

        assert all(v.error for c in candidates for v in c.votes)
        assert metrics.verification_unavailable == 4
        assert metrics.verification_completed == 0
        assert metrics.verification_presented == 4

    def test_a_partial_panel_completes_and_is_recorded_as_short(
            self, config, monkeypatch):
        """One vote of three lost is still a verdict two verifiers reached.

        The old `verification_failed` said only "at least one call errored",
        which is the same value for this run and for a panel that died — the
        two readings the report could not tell apart.
        """
        def one_bad_vote(candidate, index):
            if index == 0:
                return Vote(verdict=VERDICT_UNCERTAIN, reasoning="",
                            error="verification call failed: boom")
            return Vote(verdict=VERDICT_CONFIRMED, reasoning="r")

        verify = self._patch(monkeypatch, vote=one_bad_vote)
        metrics = StageMetrics()
        candidates = [make_candidate(severity="high")]

        verify.verify_candidates(config, _EmptyWorkspace(), object(),
                                 candidates, metrics=metrics)

        assert metrics.verification_completed == 1
        assert metrics.verification_degraded == 1
        assert metrics.verification_unavailable == 0
        assert metrics.verification_failed == 1

    def test_the_dispositions_account_for_every_finding_that_entered(
            self, config, monkeypatch):
        """The property the ratio rests on, asserted without naming a number.

        Skipped, over the limit, completed, unavailable — one basket each, and
        their sum is what a reader is told the stage was given.
        """
        verify = self._patch(monkeypatch)
        config.verify_max_findings = 2
        config.fail_on = "high"
        metrics = StageMetrics()
        candidates = (
            [make_candidate(severity="high", title="gating {}".format(i))
             for i in range(4)]
            + [make_candidate(severity="low", title="informational")])

        verify.verify_candidates(config, _EmptyWorkspace(), _ForbiddenClient(),
                                 candidates, metrics=metrics)

        assert metrics.verification_presented == len(candidates)
        assert (metrics.verification_completed + metrics.verification_unavailable
                == metrics.verified)


class TestTheCostOfAPanelThatFailedStaysVisible:
    """Why `verified` kept meaning "submitted" and `verification_completed` is
    a new field rather than a rename.

    `ScanOutcome.verification_ran` reads `metrics.verified` to decide whether a
    stage ran whose token usage nobody reported — `verify_cli` returns no
    `Usage` at all by design. A panel where every call errored *ran*, and spent,
    and reported nothing. Had `verified` been redefined to mean "completed",
    that run would answer `verification_ran = False`, the unreported-stage
    marker would not be merged, and `total_usage` would present the review's
    cost as the whole run's cost — the exact defect `Usage.unreported_stage`
    exists to prevent, one level up.
    """

    def test_a_stage_where_every_call_failed_still_counts_as_having_run(
            self, config, monkeypatch):
        import security_agent.verify as verify
        from security_agent.models import ScanOutcome

        monkeypatch.setattr(verify, "_system_blocks", lambda cfg: [])
        monkeypatch.setattr(verify, "verifier_tool_definitions",
                            lambda schema, diff_available: [])
        config.verify_votes = 1
        # No turns, no tool calls, no exposures: `review_ran` is false, so the
        # one unreported stage this can count is the verification one.
        outcome = ScanOutcome(mode="diff", model="claude-opus-5")

        verify.verify_candidates(config, _EmptyWorkspace(), _ForbiddenClient(),
                                 [make_candidate(severity="high")],
                                 metrics=outcome.metrics)

        assert outcome.metrics.verification_completed == 0
        assert outcome.verification_ran, (
            "the panel ran and spent; a total that drops it is a bill nobody sees")
        assert outcome.total_usage().unreported_stages == 1


class TestBothRunnersCountTheSameWay:
    """The CLI runner's counters, beside the API runner's.

    The two runners exist to be comparable — that is the whole reason this
    project can measure anything — so a counter that means one thing on the API
    path and another through `claude` would make two runs of the same code
    incomparable while looking identical. They already held one copy each of
    "count a failure"; the dispositions are shared through
    `verify._note_disposition` instead.

    Here rather than in `test_verify_cli.py` because the assertion is the
    agreement between the two, and that file's harness is built around a real
    child process, which this question does not need. Nothing here launches a
    process or spends anything: the session is replaced at `_one_vote`.
    """

    def _run_cli(self, config, candidates, monkeypatch, vote):
        from security_agent import verify_cli
        from security_agent.budget import Profile, RunBudget
        from security_agent.models import Revision

        monkeypatch.setattr(verify_cli.runner, "cli_available",
                            lambda executable: "/nonexistent/claude")
        monkeypatch.setattr(
            verify_cli.ClaudeCodeVerifier, "_one_vote",
            lambda self, path, candidate, index, allowance, root, slot: vote(
                candidate, index))
        metrics = StageMetrics()
        budget = RunBudget(Profile(
            "test", review_turns=None, review_tool_calls=40,
            verifier_sessions=30, verifier_tool_calls=10, runtime_seconds=600))
        verify_cli.verify_candidates_with_cli(
            config, _EmptyWorkspace(), candidates, budget,
            revision=Revision(mode="diff"), metrics=metrics)
        return metrics

    def _run_api(self, config, candidates, monkeypatch, vote):
        import security_agent.verify as verify

        monkeypatch.setattr(verify, "_system_blocks", lambda cfg: [])
        monkeypatch.setattr(verify, "verifier_tool_definitions",
                            lambda schema, diff_available: [])
        monkeypatch.setattr(
            verify, "_one_vote",
            lambda cfg, ws, client, system, tools, candidate, index: (
                vote(candidate, index), Usage()))
        metrics = StageMetrics()
        verify.verify_candidates(config, _EmptyWorkspace(), object(),
                                 candidates, metrics=metrics)
        return metrics

    @staticmethod
    def _dead(candidate, index):
        return Vote(verdict=VERDICT_UNCERTAIN, reasoning="",
                    error="the verifier session raised RuntimeError: boom")

    def test_a_dead_panel_is_unavailable_on_both_paths(self, config, monkeypatch):
        config.verify_votes = 1
        api = self._run_api(
            config, [make_candidate(severity="high", title="a")],
            monkeypatch, self._dead)
        cli = self._run_cli(
            config, [make_candidate(severity="high", title="a")],
            monkeypatch, self._dead)

        assert api.verification_unavailable == cli.verification_unavailable == 1
        assert api.verification_completed == cli.verification_completed == 0
        assert api.verification_presented == cli.verification_presented == 1

    def test_findings_past_the_limit_are_counted_on_both_paths(
            self, config, monkeypatch):
        config.verify_max_findings = 1
        config.verify_votes = 1
        def made():
            # A fresh set per runner: votes are appended to the candidates, so
            # reusing them would let the first run decide the second's counts.
            return [make_candidate(severity="high", title="f {}".format(i))
                    for i in range(3)]

        api = self._run_api(config, made(), monkeypatch, self._dead)
        cli = self._run_cli(config, made(), monkeypatch, self._dead)

        assert api.verification_over_limit == cli.verification_over_limit == 2
        assert api.verification_presented == cli.verification_presented == 3

    def test_verification_switched_off_is_counted_on_both_paths(
            self, config, monkeypatch):
        """`SECURITY_SCAN_VERIFY=false` returns from both runners before any
        disposition is recorded, so three findings nobody checked left
        `verification_presented` at zero and the row read "0 of 0" — a
        denominator saying nothing was owed rather than that nothing was done.

        Codex found it on the gate for the four counters that fixed the other
        cases: the repair had reached every branch except the one that returns
        first. Its own disposition and not folded into
        `verification_skipped`, which means "this finding could not block" — a
        judgement about one finding, where this is a setting true of all of
        them.
        """
        config.verify = False

        def made():
            return [make_candidate(severity="high", title="f {}".format(i))
                    for i in range(3)]

        api = self._run_api(config, made(), monkeypatch, self._dead)
        cli = self._run_cli(config, made(), monkeypatch, self._dead)

        assert api.verification_disabled == cli.verification_disabled == 3
        assert api.verification_presented == cli.verification_presented == 3
        assert api.verification_completed == cli.verification_completed == 0
        assert api.verification_skipped == cli.verification_skipped == 0

    def test_a_suppressed_finding_and_a_retained_one_are_both_accounted(
            self, config, monkeypatch):
        """With verification off, the two populations land in two different
        baskets and the sum still has to be right.

        An accepted-risk finding never reaches either runner: `cli.py` marks it
        `verification_skipped` before the stage is entered, because "this
        finding could not block" is true of it whatever the setting says. The
        retained ones reach the stage and are `verification_disabled`. Both
        records are correct and the denominator is their sum — which is what
        `verification_presented` being a sum over dispositions, rather than a
        count taken at the door, is for.

        Codex asked for this one on the second gate round, having found that
        the field's comment claimed the setting was "true of every finding in
        the run". It is not; the comment is now what the code does.
        """
        config.verify = False
        metrics = StageMetrics()
        # What `cli.py` records for a suppressed finding, before any runner.
        metrics.verification_skipped += 1

        retained = [make_candidate(severity="high", title="f {}".format(i))
                    for i in range(2)]
        import security_agent.verify as verify
        monkeypatch.setattr(verify, "_system_blocks", lambda cfg: [])
        verify.verify_candidates(config, _EmptyWorkspace(), object(),
                                 retained, metrics=metrics)

        assert metrics.verification_disabled == 2
        assert metrics.verification_skipped == 1
        assert metrics.verification_presented == 3
        assert metrics.verification_completed == 0
