"""Tests for the pipeline verdict.

The rule that matters most here is the one about incomplete runs: an agent that
stopped early must never produce a green pipeline, because a green pipeline is
indistinguishable from "we checked and it's fine".
"""

from conftest import make_candidate
from security_agent.config import Config, GitLabContext
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


class TestRemovedControlsBlock:
    """Deleting a security control blocks on that alone.

    Every part of this rule existed — the question to the verifier, the
    aggregation, the config flag, the verification scope — except the line in
    the gate that acts on it. 282 tests passed because none of them followed
    the rule all the way to the verdict. Five runs over a merge request
    reverting the fix for CVE-2023-41040 confirmed it five times and blocked it
    zero times.
    """

    def test_a_removed_control_blocks_below_the_severity_threshold(self, config):
        candidate = make_candidate(severity="low", confidence="high",
                                   removes_control=True)
        decision = decide(config, outcome_with(candidate))
        assert decision.exit_code == EXIT_FINDINGS
        assert decision.blocking == [candidate]

    def test_it_blocks_below_the_confidence_threshold_too(self, config):
        candidate = make_candidate(severity="low", confidence="low",
                                   removes_control=True)
        assert decide(config, outcome_with(candidate)).exit_code == EXIT_FINDINGS

    def test_it_can_be_switched_off(self, config):
        config.gate_removed_controls = False
        candidate = make_candidate(severity="low", removes_control=True)
        assert decide(config, outcome_with(candidate)).exit_code == EXIT_OK

    def test_it_does_not_override_pre_existing(self, config):
        # Code the change did not touch is not this author's to answer for,
        # whatever the verifiers concluded about it.
        candidate = make_candidate(severity="low", removes_control=True,
                                   in_changed_lines=False)
        assert decide(config, outcome_with(candidate)).exit_code == EXIT_OK

    def test_fail_on_none_still_means_none(self, config):
        config.fail_on = "none"
        candidate = make_candidate(severity="critical", removes_control=True)
        assert decide(config, outcome_with(candidate)).exit_code == EXIT_OK

    def test_an_ordinary_finding_is_unaffected(self, config):
        candidate = make_candidate(severity="low", removes_control=False)
        assert decide(config, outcome_with(candidate)).exit_code == EXIT_OK


class TestTheVerdictNamesTheRuleThatApplied:
    """Two different rules block, and the message has to say which one did.

    A finding stopped for deleting a guard is usually below the severity
    threshold. Telling its author it was "at or above the high threshold" sends
    them to argue with a number that had nothing to do with the decision —
    which is what the first real pipeline run reported.
    """

    def test_a_removed_control_is_described_as_one(self, config):
        candidate = make_candidate(severity="medium", removes_control=True)
        reason = decide(config, outcome_with(candidate)).reason
        assert "removes an existing security control" in reason
        assert "threshold" not in reason

    def test_an_ordinary_finding_still_cites_the_threshold(self, config):
        candidate = make_candidate(severity="critical", confidence="high")
        reason = decide(config, outcome_with(candidate)).reason
        assert "at or above the high threshold" in reason
        assert "removes an existing" not in reason

    def test_both_rules_at_once_are_both_named(self, config):
        candidates = [
            make_candidate(severity="low", removes_control=True, title="a"),
            make_candidate(severity="critical", confidence="high", title="b"),
        ]
        reason = decide(config, outcome_with(*candidates)).reason
        assert "removes an existing security control" in reason
        assert "at or above the high threshold" in reason


class TestAnUnknownRatingCannotUnGateAFinding:
    """One capital letter used to carry a critical finding past the gate.

    `severity_rank` and `confidence_rank` return -1 for a word nobody
    recognises. That is right for sorting — an unknown value goes to one end
    and stays there — and it was read as a threshold: `-1 < minimum` meant an
    unrecognised rating was quietly treated as *less* severe than `low`, so it
    never blocked. The report still rendered it as CRITICAL and the pipeline
    still exited 0.

    Neither field is derived or validated on that path. `Finding.from_dict`
    takes `str(data["confidence"])`, and the schema's enum is enforced by the
    API — except on the hand-rolled fallback in `_parse_verdict`, which exists
    precisely for when it was not.
    """

    def _blocks(self, cfg, **overrides) -> bool:
        from security_agent.gate import blocking_findings

        candidate = make_candidate(**overrides)
        outcome = ScanOutcome(mode="diff", model="m")
        outcome.reported = [candidate]
        return bool(blocking_findings(cfg, outcome))

    def test_a_capital_letter_is_the_same_word(self, config):
        """`High` and `high` are one rating written two ways."""
        assert self._blocks(config, severity="critical", confidence="High")
        assert self._blocks(config, severity="Critical", confidence="high")

    def test_surrounding_whitespace_is_the_same_word(self, config):
        assert self._blocks(config, severity="critical", confidence=" high ")

    def test_a_rating_nobody_recognises_does_not_silently_pass(self, config):
        """It fails toward blocking. An unparseable rating is a statement that
        the rating could not be read — never that it was low."""
        assert self._blocks(config, severity="critical", confidence="pretty sure")
        assert self._blocks(config, severity="devastating", confidence="high")

    def test_a_recognised_rating_below_the_bar_still_does_not_block(self, config):
        """The fix must not turn the threshold off."""
        assert not self._blocks(config, severity="low", confidence="high")
        assert not self._blocks(config, severity="critical", confidence="low")


class TestSomeEndingsAreNotTheOperatorsToForgive:
    """`fail_on_incomplete=false` is a policy about partial reviews. It is not
    permission for a profile to conclude when it says it cannot.

    `probe` is six turns and no verifiers, sized to run on every save, and
    `Profile.conclusive` has said `False` about it since the day it was written
    — to nobody. The flag was read nowhere outside `budget.py`, so a probe that
    signed off ended `completed` and exited 0. Making it a stop reason was half
    the fix; the other half is that a setting meaning "accept partial reviews"
    must not turn it back into a pass.

    Found by the author reading the file, after nine review rounds had passed
    over it.
    """

    def test_a_profile_that_cannot_conclude_never_exits_zero(self):
        from security_agent.models import STOP_INCONCLUSIVE

        outcome = outcome_with(stop_reason=STOP_INCONCLUSIVE)

        for forgiving in (True, False):
            cfg = Config(gitlab=GitLabContext(), fail_on_incomplete=forgiving)
            decision = decide(cfg, outcome)

            assert decision.exit_code == EXIT_ERROR, (
                "fail_on_incomplete={} let a non-conclusive profile "
                "pass".format(forgiving))
            assert "property of the profile" in decision.reason

    def test_an_ordinary_truncation_is_still_the_operators_call(self):
        """The flag keeps working for what it is for. A rule that swallowed
        every incomplete ending would take away a real choice about a team's own
        risk, and would be removed for it."""
        from security_agent.models import STOP_TURN_LIMIT

        cfg = Config(gitlab=GitLabContext(), fail_on_incomplete=False)

        assert decide(cfg, outcome_with(
            stop_reason=STOP_TURN_LIMIT)).exit_code != EXIT_ERROR

    def test_the_set_is_not_empty(self):
        """A refactor that emptied it would leave every test above passing."""
        from security_agent.gate import NEVER_FORGIVEN

        assert NEVER_FORGIVEN
