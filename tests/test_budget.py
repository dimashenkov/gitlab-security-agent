"""The ceilings, and the two ways a ceiling silently becomes a verdict.

A budget is easy to test wrongly: assert that a counter increments, watch the
suite go green, and ship a limit that stops the run and lets the report say
"no findings". Both failures this file guards are of that shape.

**A profile is a configuration file for the aggregation rule.** `verifiers: 2`
looks like a budget choice and is not one — two votes cannot form a majority,
so the tie is settled by rule rather than by evidence. Measured, that exact
configuration produced three blocks and one pass across four identical runs of
one case. The constructor refuses it, so the revert cannot arrive disguised as
a cost saving.

**Exhaustion is exit 2.** Tested here as the sentence the report carries, not
only as a flag, because the flag was never the part that got dropped.
"""

from __future__ import annotations

import pytest

from security_agent.budget import (
    PROFILES,
    STOPPED_RUNTIME,
    STOPPED_TOOL_CALLS,
    STOPPED_VERIFIERS,
    Profile,
    RunBudget,
    profile_named,
)


def _budget(**overrides) -> RunBudget:
    base = dict(name="test", review_turns=20, verifiers=3, verifier_turns=8,
                runtime_seconds=1_200, tool_calls=100)
    base.update(overrides)
    return RunBudget(profile=Profile(**base))


# ------------------------------------------- a panel that cannot be even


@pytest.mark.parametrize("count", [2, 4, 6])
def test_an_even_panel_is_refused_at_construction(count):
    """Not validated at aggregation time, where a wrong panel has already been
    paid for. Refused where the profile is written."""
    with pytest.raises(ValueError) as raised:
        Profile(name="two", review_turns=20, verifiers=count, verifier_turns=8,
                runtime_seconds=600, tool_calls=100)
    assert "majority" in str(raised.value)


@pytest.mark.parametrize("name", sorted(PROFILES))
def test_every_shipped_profile_has_an_odd_panel(name):
    """The constructor is only a guard if nothing already violates it."""
    assert PROFILES[name].verifiers in (0, 1, 3, 5)


def test_probe_has_no_verifiers_at_all():
    """Zero rather than one on purpose. One verifier produces a verdict-shaped
    object with a single unchecked opinion behind it; zero cannot be mistaken
    for verification by anyone reading the artifact."""
    assert PROFILES["probe"].verifiers == 0


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


# ------------------------------------- capacity reserved, not counted after


def test_a_verifier_seat_is_claimed_before_the_session_runs():
    """The concurrency bug in one assertion: three verifiers starting together
    each see room for one more if capacity is counted on completion."""
    budget = _budget(verifiers=3)

    assert [budget.reserve_verifier() for _ in range(3)] == [True, True, True]
    assert budget.reserve_verifier() is False
    assert budget.verifier_sessions == 3


def test_a_refused_verifier_seat_stops_the_run():
    budget = _budget(verifiers=1)
    budget.reserve_verifier()

    assert budget.reserve_verifier() is False
    assert budget.check() == STOPPED_VERIFIERS


def test_a_zero_verifier_profile_grants_no_seats():
    """`probe` must not acquire a panel by accident."""
    budget = _budget(verifiers=0)

    assert budget.reserve_verifier() is False
    assert budget.verifier_sessions == 0


# ------------------------------------------------- the ceilings themselves


def test_the_tool_call_that_hits_the_ceiling_still_runs():
    """Off-by-one in the direction that matters: the call which reaches the
    limit is served and the next one is refused. Refusing the one that reaches
    it throws away work already decided on."""
    budget = _budget(tool_calls=3)

    assert [budget.note_tool_call() for _ in range(3)] == [True, True, True]
    assert budget.note_tool_call() is False
    assert budget.check() == STOPPED_TOOL_CALLS


def test_time_stops_the_run_even_with_every_other_ceiling_untouched():
    """The one ceiling no runner can avoid reporting. Zero tool calls, zero
    turns, and still stopped."""
    budget = _budget(runtime_seconds=0)

    assert budget.check() == STOPPED_RUNTIME
    assert budget.note_tool_call() is False
    assert budget.reserve_verifier() is False


def test_the_first_ceiling_hit_is_the_one_reported():
    """A second ceiling arriving later must not rewrite the reason. "Stopped
    on time" and "stopped on tool calls" lead to different next actions."""
    budget = _budget(tool_calls=1, runtime_seconds=0)
    budget.check()

    budget.note_tool_call()
    assert budget.stopped_by == STOPPED_RUNTIME


# -------------------------------------------- exhaustion is never a verdict


def test_an_exhausted_budget_says_it_is_not_a_statement_about_the_code():
    """The whole point. This sentence is what stands between a truncated run
    and a reader concluding the code is clean."""
    budget = _budget(tool_calls=1)
    budget.note_tool_call()

    sentence = budget.why_stopped()
    assert "not a statement about the code" in sentence
    assert "tool calls" in sentence


def test_a_run_that_finished_says_nothing():
    """`why_stopped` must be empty rather than reassuring — a report that
    always carries a caveat is a report whose caveat is ignored."""
    assert _budget().why_stopped() == ""


@pytest.mark.parametrize("kwargs,expected", [
    ({"tool_calls": 1}, "tool calls"),
    ({"verifiers": 0}, "verifier"),
    ({"runtime_seconds": 0}, "time limit"),
])
def test_every_ceiling_can_explain_itself(kwargs, expected):
    """A stop reason with no explanation would raise a KeyError inside the
    reporting path — which is how a paid run was discarded once already."""
    budget = _budget(**kwargs)
    budget.note_tool_call()
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
