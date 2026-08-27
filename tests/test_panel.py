"""What a panel decides when some of its seats never got filled.

A verifier session can die — the API call raises, the CLI is killed at the
deadline, the run's seat budget was already committed. Every one of those ends
in a `Vote` carrying `error`, and the seat stays in `candidate.votes` so that
the panel can still see how many voices it was supposed to have.

The defect these tests are written against is what happened when it did not
look: every rule counted the votes that came back, so a lost session did not
weaken the panel, it *shrank* it. One survivor out of three was a majority of
one, and that reply alone could refute the claim, correct the facts severity is
computed from, switch on the removed-control gate, or set the panel's
confidence to `low` — which is under the gate. Whether a merge blocked then
depended on which session happened to crash, which is the same instability the
odd panel was introduced to remove.

Everything here goes through `verify._decide`, the caller that applies the
panel's answer to a candidate, and two tests go further: one through
`RunBudget`, because the seats that go empty are the ones a budget refused, and
one through the session document, because the loader recomputes the same
disposition in another process and a rule that disagrees with itself across
that boundary rejects honest documents.
"""

from __future__ import annotations

from conftest import make_candidate
from security_agent.budget import Profile, RunBudget
from security_agent.models import (
    VERDICT_CONFIRMED,
    VERDICT_REFUTED,
    VERDICT_UNCERTAIN,
    Revision,
    Vote,
)
from security_agent.session_document import read_session, write_session
from security_agent.tools import Session
from security_agent.verify import _could_block, _decide, _votes_for


def vote(verdict=VERDICT_CONFIRMED, **kwargs):
    return Vote(verdict=verdict, reasoning=kwargs.pop("reasoning", "because"), **kwargs)


def empty_seat(reason="the verifier was stopped at its deadline"):
    """A seat that was reserved and never spoke, in the shape every path uses."""
    return Vote(verdict=VERDICT_UNCERTAIN, reasoning="", error=reason)


class TestALoneSurvivorDecidesNothing:
    """Two of three sessions die. The third must not become the panel."""

    def test_it_cannot_refute_the_claim(self):
        """With the survivors as the denominator this returned `refuted`.

        One reply out of a three-seat panel discarded the finding and the merge
        went through — decided by two crashes, not by two verifiers.
        """
        candidate = make_candidate()
        candidate.votes = [vote(VERDICT_REFUTED), empty_seat(), empty_seat()]

        _decide(candidate)

        assert candidate.verdict == VERDICT_CONFIRMED

    def test_it_cannot_leave_the_claim_uncertain_either(self, config):
        """`uncertain` is the quieter half of the same failure.

        It forces confidence to `low`, and `low` is under the gate, so a panel
        that could not meet ungated the finding just as effectively as a
        refutation would have — while three dead seats blocked the merge. Two
        crashes must not be worth more than three.
        """
        candidate = make_candidate()
        candidate.votes = [vote(VERDICT_UNCERTAIN), empty_seat(), empty_seat()]

        _decide(candidate)

        assert candidate.verdict == VERDICT_CONFIRMED
        assert candidate.confidence == "high"
        assert _could_block(config, candidate)

    def test_it_cannot_correct_a_fact_severity_is_computed_from(self):
        """Corrections were already documented as needing a majority of the
        whole panel. The code took its majority over the votes that arrived,
        so with two seats empty one proposal was that majority and moved the
        rating on its own."""
        candidate = make_candidate(impact="narrow_data_access",
                                   reachable_without_authentication="no",
                                   requires_user_interaction="no")
        candidate.votes = [vote(corrected_reachable="yes"), empty_seat(),
                           empty_seat()]

        _decide(candidate)

        assert candidate.severity == "low"
        assert "verifiers corrected" not in candidate.severity_derivation

    def test_it_cannot_switch_on_the_removed_control_gate(self):
        """This flag blocks whatever the severity says, so it is the cheapest
        route from one reply to a blocked merge. Unanimity among survivors is
        unanimity of one when the other two sessions died."""
        candidate = make_candidate()
        candidate.votes = [vote(removes_control="yes"), empty_seat(),
                           empty_seat()]

        _decide(candidate)

        assert candidate.removes_control is False

    def test_it_cannot_lower_the_panels_confidence(self, config):
        """The median was taken over the survivors, so the one verifier left
        was the median. `low` is under the gate: a crash in two sessions and a
        cautious word in the third let the merge through."""
        candidate = make_candidate(confidence="high")
        candidate.votes = [vote(corrected_confidence="low"), empty_seat(),
                           empty_seat()]

        _decide(candidate)

        assert candidate.confidence == "high"
        assert _could_block(config, candidate)


class TestAPanelThatDidMeetStillDecides:
    """The fix must not turn every panel that lost a seat into a rubber stamp.

    Half the seats or more is a quorum, and every panel this system builds is
    odd, so two of three is a majority of the panel — those two decide.
    """

    def test_a_surviving_majority_refutes(self):
        candidate = make_candidate()
        candidate.votes = [vote(VERDICT_REFUTED), vote(VERDICT_REFUTED),
                           empty_seat()]

        _decide(candidate)

        assert candidate.verdict == VERDICT_REFUTED

    def test_a_surviving_majority_corrects_a_fact(self):
        candidate = make_candidate(impact="narrow_data_access",
                                   reachable_without_authentication="no",
                                   requires_user_interaction="no")
        candidate.votes = [vote(corrected_reachable="yes"),
                           vote(corrected_reachable="yes"), empty_seat()]

        _decide(candidate)

        assert candidate.severity == "medium"
        assert "verifiers corrected reachable" in candidate.severity_derivation

    def test_a_surviving_majority_lowers_the_confidence(self):
        candidate = make_candidate(confidence="high")
        candidate.votes = [vote(corrected_confidence="low"),
                           vote(corrected_confidence="low"), empty_seat()]

        _decide(candidate)

        assert candidate.confidence == "low"

    def test_a_full_panel_still_switches_on_the_removed_control_gate(self):
        candidate = make_candidate()
        candidate.votes = [vote(removes_control="yes") for _ in range(3)]

        _decide(candidate)

        assert candidate.removes_control is True

    def test_every_seat_erroring_still_leaves_the_claim_standing(self):
        """Being unable to check a claim is not evidence against it — and the
        answer must be the same one an unfilled panel gives, or the rule has a
        step in it where losing one more session changes the verdict."""
        candidate = make_candidate()
        candidate.votes = [empty_seat(), empty_seat(), empty_seat()]

        _decide(candidate)

        assert candidate.verdict == VERDICT_CONFIRMED
        assert "unverified" in candidate.verdict_reason


class TestTheSeatsComeFromTheBudget:
    """Where empty seats actually come from, joined up to what they decide.

    `verify_cli` reserves one seat per vote for the whole run, on one thread,
    before any session starts. A pool that runs out in the middle of a panel
    leaves that finding with fewer voices than it was promised — and nothing
    about the claim changed, only the money.
    """

    def test_a_pool_that_runs_out_mid_panel_cannot_decide_on_one_vote(self, config):
        budget = RunBudget(profile=Profile(
            "test-pool", review_turns=20, review_tool_calls=100, verifier_sessions=4,
            verifier_tool_calls=15, runtime_seconds=1_200))
        candidates = [make_candidate(), make_candidate(title="A second finding")]
        jobs = [(c, i) for c in candidates for i in range(_votes_for(config, c))]

        seats = [budget.reserve_verifier() for _ in jobs]

        # Three seats for the first panel, one for the second, then nothing.
        assert [seat is not None for seat in seats] == [True] * 4 + [False] * 2
        second = candidates[1]
        second.votes = [vote(VERDICT_REFUTED)] + [
            empty_seat("no verifier session was available") for _ in range(2)]

        _decide(second)

        assert second.verdict == VERDICT_CONFIRMED


class TestTheLoaderAgreesAboutAnUnfilledPanel:
    """The rule has to give the same answer in the other process.

    The `claude` CLI runner puts a process boundary in the middle of the run:
    the child writes the votes and the disposition into a session document and
    the parent recomputes the disposition from the same votes, refusing any
    document it cannot reproduce. So an errored seat has to survive the round
    trip *and* be counted the same way at both ends — a panel rule that read
    only the votes that arrived at one end and every seat at the other would
    reject the honest document a killed verifier produces.
    """

    def test_a_document_written_with_an_empty_seat_is_read_back(self, tmp_path):
        revision = Revision(mode="mr", base="main", head="HEAD",
                            base_sha="a" * 40, head_sha="b" * 40)
        candidate = make_candidate(confidence="high")
        candidate.votes = [vote(corrected_confidence="low"), vote(),
                           empty_seat()]
        _decide(candidate)
        session = Session()
        session.candidates.append(candidate)
        # The loader refuses a document whose accepted-citation count does not
        # match its findings, so the session has to be one a real review could
        # have left behind.
        session.metrics.citations_accepted = 1

        path = tmp_path / "session.json"
        write_session(path, session, run_id="job-1", revision=revision,
                      config_digest="digest")
        loaded = read_session(path, run_id="job-1", revision=revision,
                              config_digest="digest")

        restored = loaded.candidates[0]
        assert [v.error for v in restored.votes] == ["", "", candidate.votes[2].error]
        assert restored.verdict == candidate.verdict == VERDICT_CONFIRMED
        assert restored.confidence == candidate.confidence == "high"
