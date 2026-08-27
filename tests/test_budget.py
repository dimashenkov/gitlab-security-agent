"""The ceilings, and the three ways one silently becomes a verdict.

A budget is easy to test wrongly: assert that a counter increments, watch the
suite go green, and ship a limit that stops the run and lets the report say "no
findings". All three failures guarded here are of that shape.

**`verifiers` is a run-wide session ceiling, not a panel.** It was documented
as "votes per candidate" and enforced as a pool for the whole run, and the
odd-panel rule — which exists because an even panel settles a disagreement by
rule instead of by evidence — was applied to it, where it guarded nothing. The
panel size is `Config.verify_votes`, read by `verify._votes_for`, and that is
where odd is enforced. What this ceiling really decides is how many of the
panel's seats can be filled, so what it needs guarding against is starvation.

**A verifier with no tool calls blocks everything.** It cannot search for the
control it is required to name, a verdict that cannot say what it looked for is
downgraded to `uncertain`, and `uncertain` is under the gate. Zero looks like a
saving and is a total outage.

**Exhaustion is exit 2.** Tested as the sentence the report carries, not only
as a flag, because the flag was never the part that got dropped.
"""

from __future__ import annotations

import pytest

from conftest import make_candidate
from security_agent.budget import (
    PROFILES,
    SMALLEST_GATING_PANEL,
    STOPPED_RUNTIME,
    STOPPED_TOOL_CALLS,
    STOPPED_TURNS,
    STOPPED_VERIFIERS,
    Allowance,
    Profile,
    RunBudget,
    profile_named,
)
from security_agent.verify import _votes_for


def _budget(**overrides) -> RunBudget:
    base = dict(name="test", review_turns=20, review_tool_calls=100,
                verifier_sessions=3, verifier_tool_calls=15,
                runtime_seconds=1_200)
    turns_enforced = overrides.pop("turns_enforced", True)
    base.update(overrides)
    return RunBudget(profile=Profile(**base), turns_enforced=turns_enforced)


# --------------------------------- a pool that cannot seat what it pays for


@pytest.mark.parametrize("count", [1, 2])
def test_a_pool_too_small_to_seat_a_panel_is_refused(count):
    """A verifier bought and then discarded.

    Seats are reserved before the sessions start, and a panel that lost half
    its seats is not quorate, so a pool of one or two funds sessions whose
    votes `panel._quorate` throws away — money spent to change nothing. Refused
    where the profile is written, not at aggregation time, where the sessions
    have already been paid for.
    """
    with pytest.raises(ValueError) as raised:
        _budget(verifier_sessions=count)
    assert "cannot seat a panel" in str(raised.value)


def test_an_even_pool_is_allowed_because_a_pool_is_not_a_panel():
    """The check this replaced refused 2, 4 and 6 as "an even panel".

    It was guarding the wrong field. A panel is `Config.verify_votes` and
    `verify._votes_for` already forces it odd; a *pool* of four seats is a
    perfectly sensible budget — a panel of three and a spare — and refusing it
    protected nothing while making the field look like the panel size.
    """
    assert _budget(verifier_sessions=4).profile.verifier_sessions == 4


def test_a_verifier_with_no_tool_calls_is_refused():
    """It reads like a cheap verifier and is a gate that blocks everything."""
    with pytest.raises(ValueError) as raised:
        _budget(verifier_sessions=3, verifier_tool_calls=0)
    assert "uncertain" in str(raised.value)


@pytest.mark.parametrize("name", sorted(PROFILES))
def test_every_shipped_profile_is_constructible(name):
    """The constructor is only a guard if nothing already violates it."""
    verifiers = PROFILES[name].verifier_sessions
    assert verifiers == 0 or verifiers >= SMALLEST_GATING_PANEL


def test_the_pool_is_a_run_wide_ceiling_and_not_votes_per_candidate(config):
    """What the field was documented as, put through the code that spends it.

    `Profile.verifiers` said "votes per candidate" and `reserve_verifier` hands
    out one seat per vote *in the whole run* — so the second gate-eligible
    finding of a run gets no verifier at all under a profile that reads as
    three votes each. This is the arrangement `verify_cli` builds: one job per
    vote per candidate, every seat reserved on one thread before anything is
    launched.
    """
    budget = RunBudget(profile=PROFILES["normal"])
    candidates = [make_candidate(), make_candidate(title="A second finding")]
    jobs = [(c, i) for c in candidates for i in range(_votes_for(config, c))]

    seats = [budget.reserve_verifier() for _ in jobs]

    assert len(jobs) == 6, "three votes each, as the panel rule requires"
    assert [seat is not None for seat in seats] == [True] * 3 + [False] * 3
    assert budget.check() == STOPPED_VERIFIERS


def test_a_profile_declares_no_verifier_turn_ceiling():
    """A limit nobody applied, disagreeing with the one that runs.

    `verifier_turns` was declared here — 8 for `normal`, 12 for `deep` — and
    read by nothing: no code compared a verifier's turns against it and no
    report printed it. The ceiling actually in force is
    `verify.MAX_VERIFY_TURNS`, which is 14. A second copy of a limit, applied
    by nobody and disagreeing with the enforced one, is worse than no limit,
    because the number is what does the reassuring.

    The argument is still accepted and ignored so that call sites outside
    `budget.py` keep working; what must not come back is a stored ceiling.
    """
    from dataclasses import fields

    from security_agent.verify import MAX_VERIFY_TURNS

    stored = {f.name for f in fields(PROFILES["normal"])}

    assert "verifier_turns" not in stored
    # The argument is gone too. It survived a rename as an accepted-and-ignored
    # `InitVar` only because five call sites were outside one agent's remit;
    # all five are reachable now, and an argument that does nothing is the next
    # person's afternoon.
    with pytest.raises(TypeError):
        Profile(name="x", review_turns=1, review_tool_calls=1,
                verifier_sessions=0, verifier_tool_calls=0,
                runtime_seconds=1, verifier_turns=8)
    assert MAX_VERIFY_TURNS == 14


def test_probe_has_no_verifiers_at_all():
    """Zero rather than one on purpose. One verifier produces a verdict-shaped
    object with a single unchecked opinion behind it; zero cannot be mistaken
    for verification by anyone reading the artifact."""
    assert PROFILES["probe"].verifier_sessions == 0


def test_probe_can_never_conclude():
    """Its turn ceiling sits below the middle of the measured distribution —
    7-13 turns for a real review — so it stops early by design. A profile that
    usually stops early must not be able to render a verdict."""
    assert PROFILES["probe"].conclusive is False
    assert all(PROFILES[name].conclusive for name in PROFILES if name != "probe")


def test_the_default_profile_covers_the_longest_measured_run():
    """895 seconds and 13 turns is the longest review actually observed. A
    ceiling level with the maximum is a ceiling that truncates the next one."""
    normal = profile_named("normal")
    assert normal.runtime_seconds > 895
    assert normal.review_turns > 13


# ------------------------------------------- allowances, not a shared pool


def test_each_verifier_gets_its_own_tool_calls():
    """The property that makes concurrent verifiers safe without a lock: no
    session can spend another's allowance, so scheduling cannot change what a
    verifier managed to check before voting."""
    budget = _budget(verifier_sessions=3, verifier_tool_calls=5)
    first = budget.reserve_verifier()
    second = budget.reserve_verifier()

    for _ in range(5):
        assert budget.note_tool_call(first) is True

    assert first.remaining == 0
    assert second.remaining == 5
    assert budget.note_tool_call(second) is True


def test_a_spent_verifier_does_not_end_the_review():
    """It has finished searching and still votes. Ending the run because one
    verifier used its budget would turn a thorough vote into a failed review."""
    budget = _budget(verifier_sessions=3, verifier_tool_calls=2)
    allowance = budget.reserve_verifier()

    budget.note_tool_call(allowance)
    budget.note_tool_call(allowance)

    assert budget.note_tool_call(allowance) is False
    assert budget.check() == ""
    assert budget.note_tool_call() is True     # the reviewer is unaffected


def test_the_reviewer_running_out_does_end_the_review():
    budget = _budget(review_tool_calls=2)

    assert [budget.note_tool_call() for _ in range(2)] == [True, True]
    assert budget.note_tool_call() is False
    assert budget.check() == STOPPED_TOOL_CALLS


def test_a_verifier_seat_is_claimed_before_the_session_runs():
    """The concurrency bug in one assertion: three verifiers starting together
    each see room for one more if capacity is counted on completion."""
    budget = _budget(verifier_sessions=3)
    seats = [budget.reserve_verifier() for _ in range(3)]

    assert all(seat is not None for seat in seats)
    assert budget.reserve_verifier() is None
    assert budget.verifier_sessions == 3


def test_a_refused_verifier_seat_stops_the_run():
    budget = _budget(verifier_sessions=3)
    for _ in range(3):
        budget.reserve_verifier()

    assert budget.reserve_verifier() is None
    assert budget.check() == STOPPED_VERIFIERS


def test_a_zero_verifier_profile_grants_no_seats():
    """`probe` must not acquire a panel by accident."""
    budget = RunBudget(profile=PROFILES["probe"])

    assert budget.reserve_verifier() is None
    assert budget.verifier_sessions == 0


def test_unspent_allowance_is_not_reclaimed_and_the_report_says_so():
    """The trade this design accepts. Reclaiming means reading a child's
    remaining count while other children are still spending, which is the race
    the reservation exists to avoid — so it is reported instead of hidden."""
    budget = _budget(review_tool_calls=10, verifier_sessions=3, verifier_tool_calls=15)
    budget.reserve_verifier()
    budget.note_tool_call()

    assert budget.allocated_tool_calls == 25    # 10 + one verifier's 15
    assert budget.spent_tool_calls == 1
    assert "1 spent of 25 allocated" in "\n".join(budget.summary())


def test_allocation_counts_seats_taken_not_seats_permitted():
    """A run that used one verifier allocated one verifier's worth. Reporting
    the profile's maximum would describe a budget that was never granted."""
    budget = _budget(review_tool_calls=10, verifier_sessions=3, verifier_tool_calls=15)

    assert budget.allocated_tool_calls == 10
    assert budget.profile.allocated_tool_calls == 55


# ------------------------------------------------- the ceilings themselves


def test_the_tool_call_that_hits_the_ceiling_still_runs():
    """Off-by-one in the direction that matters: the call which reaches the
    limit is served and the next one is refused. Refusing the one that reaches
    it throws away work already decided on."""
    budget = _budget(review_tool_calls=3)

    assert [budget.note_tool_call() for _ in range(3)] == [True, True, True]
    assert budget.note_tool_call() is False


def test_the_run_stops_on_the_ceiling_whichever_route_spent_it():
    """Two budgets with identical numbers reported different exhaustion.

    `stopped_by` used to be decided inside `RunBudget.note_tool_call`, from a
    flag `Allowance` stored while counting. The Claude Code runner does not
    spend that way: it folds the child's tool calls straight onto
    `budget.review`, so the reviewer reached its ceiling, the allowance knew
    it, and the run said nothing had stopped it — a truncated review whose
    budget looked untouched. Exhaustion is now one derived fact, read by
    `check()`, so both routes give the same answer.
    """
    through_budget = _budget(review_tool_calls=2)
    direct = _budget(review_tool_calls=2)

    for _ in range(2):
        through_budget.note_tool_call()
        direct.review.note_tool_call()

    assert direct.review.exhausted is through_budget.review.exhausted is True
    assert direct.check() == STOPPED_TOOL_CALLS == through_budget.check()


def test_an_allowance_cannot_disagree_with_its_own_counter():
    """The second copy of a derivable fact, in one assertion.

    `exhausted` was a stored flag beside `spent` and `ceiling`, so an allowance
    reconstructed from counters — which is what crossing a process boundary
    amounts to — arrived spent out and reported room to spare.
    """
    reconstructed = Allowance("verifier 1", ceiling=15, spent=15)

    assert reconstructed.exhausted is True
    assert reconstructed.remaining == 0
    assert reconstructed.note_tool_call() is False


def test_a_refused_call_still_counts_as_an_attempt():
    """One documented rule, so the number means the same thing on both
    runners. Counting only successes lets a session with a broken argument
    loop for free."""
    budget = _budget(review_tool_calls=2)
    budget.note_tool_call()
    budget.note_tool_call()

    assert budget.spent_tool_calls == 2


def test_time_stops_the_run_even_with_every_other_ceiling_untouched():
    """The one ceiling no runner can avoid reporting. Zero tool calls, zero
    turns, and still stopped."""
    budget = _budget(runtime_seconds=0)

    assert budget.check() == STOPPED_RUNTIME
    assert budget.note_tool_call() is False
    assert budget.reserve_verifier() is None


def test_the_first_ceiling_hit_is_the_one_reported():
    """A second ceiling arriving later must not rewrite the reason. "Stopped
    on time" and "stopped on tool calls" lead to different next actions."""
    budget = _budget(review_tool_calls=1, runtime_seconds=0)
    budget.check()

    budget.note_tool_call()
    assert budget.stopped_by == STOPPED_RUNTIME


# ----------------------------------------- a limit nobody applies is named


def test_a_runner_that_cannot_count_turns_says_so_rather_than_pretending():
    """The Claude Code CLI has no `--max-turns`. A usage report showing
    "3 / 20" for a runner that never checked is a report that invented the
    check."""
    budget = _budget(turns_enforced=False)
    for _ in range(50):
        budget.note_review_turn()

    assert budget.check() == ""
    assert "not enforceable by this runner" in "\n".join(budget.summary())


def test_an_enforced_turn_limit_still_stops_the_run():
    budget = _budget(review_turns=2)
    budget.note_review_turn()
    budget.note_review_turn()

    assert budget.check() == STOPPED_TURNS


def test_a_profile_with_no_turn_limit_reports_that_too():
    budget = _budget(review_turns=None)
    budget.note_review_turn()

    assert budget.check() == ""
    assert "no turn limit in this profile" in "\n".join(budget.summary())


# -------------------------------------------- exhaustion is never a verdict


def test_an_exhausted_budget_says_it_is_not_a_statement_about_the_code():
    """The whole point. This sentence is what stands between a truncated run
    and a reader concluding the code is clean."""
    budget = _budget(review_tool_calls=1)
    budget.note_tool_call()

    sentence = budget.why_stopped()
    assert "not a statement about the code" in sentence
    assert "tool calls" in sentence


def test_a_run_that_finished_says_nothing():
    """`why_stopped` must be empty rather than reassuring — a report that
    always carries a caveat is a report whose caveat is ignored."""
    assert _budget().why_stopped() == ""


@pytest.mark.parametrize("kwargs,expected", [
    ({"review_tool_calls": 1}, "tool calls"),
    ({"verifier_sessions": 3}, "verifier"),
    ({"runtime_seconds": 0}, "time limit"),
    ({"review_turns": 1}, "turn limit"),
])
def test_every_ceiling_can_explain_itself(kwargs, expected):
    """A stop reason with no explanation would raise a KeyError inside the
    reporting path — which is how a paid run was discarded once already."""
    budget = _budget(**kwargs)
    budget.note_review_turn()
    budget.note_tool_call()
    for _ in range(4):
        budget.reserve_verifier()
    budget.check()

    assert expected in budget.why_stopped()


# --------------------------------------- tokens absent, and absent honestly


def test_a_runner_that_cannot_report_tokens_says_so():
    """Never zero. A fabricated number is worse than an admitted gap, and the
    Claude Code path is a real gap."""
    lines = "\n".join(_budget().summary())

    assert "not reported by this runner" in lines
    assert "0 in, 0 out" not in lines


def test_reported_tokens_accumulate_across_sessions():
    budget = _budget()
    budget.note_usage(input_tokens=100, output_tokens=10, cost_usd=0.02)
    budget.note_usage(input_tokens=50, output_tokens=5, cost_usd=0.01)

    lines = "\n".join(budget.summary())
    assert "150 in, 15 out" in lines
    assert "$0.03" in lines


def test_a_partial_report_does_not_invent_the_missing_half():
    """A runner giving output tokens and no input tokens must not have the
    input side filled in with zero."""
    budget = _budget()
    budget.note_usage(output_tokens=10)

    assert budget.input_tokens is None
    assert budget.output_tokens == 10


def test_the_summary_names_a_profile_that_cannot_conclude():
    """Carried into the usage report because that is what gets pasted into a
    merge request when someone says "the scan was clean"."""
    budget = RunBudget(profile=PROFILES["probe"])

    assert "never conclusive" in budget.summary()[0]


def test_an_unknown_profile_name_lists_the_real_ones():
    with pytest.raises(ValueError) as raised:
        profile_named("quick")

    assert "normal" in str(raised.value)
    assert "probe" in str(raised.value)
