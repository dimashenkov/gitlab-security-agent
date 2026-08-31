"""Context is a budget, because turn ceilings do not bound it.

A `/usage` reading on 2026-08-31 showed a session allowance exhausted with 97%
of it spent above 150k context — many turns over an already huge conversation
rather than many turns. The same run reported 920k output tokens against 16.3M
cache reads: every turn pays for the whole history again.

Turn and tool-call ceilings bound how many times the history is re-read, not
how large it is by then. These tests are about the second quantity, and about
the one rule that makes bounding it safe: a review made smaller to fit a budget
must say so, and can never become a clean pass by fitting.
"""
from __future__ import annotations

import pytest

from security_agent.context_budget import BYTES_PER_TOKEN, ContextBudget
from security_agent.tools import Session, ToolResult, _budgeted


def big(tokens: int) -> str:
    return "x" * int(tokens * BYTES_PER_TOKEN)


class TestTheEstimateRunsHigh:
    def test_an_empty_string_costs_nothing(self):
        assert ContextBudget().estimate("") == 0

    def test_anything_at_all_costs_something(self):
        """A result that costs nothing would not need budgeting."""
        assert ContextBudget().estimate("x") >= 1

    def test_it_does_not_understate(self):
        """Understating spends the allowance the budget was added to protect."""
        budget = ContextBudget()
        text = "x" * 3000
        assert budget.estimate(text) >= len(text) / 4, (
            "a four-bytes-per-token estimate is optimistic for source code")


class TestUnboundedIsTheDefault:
    def test_a_fresh_session_is_unbounded(self):
        """A budget that appeared silently would change every existing run."""
        assert not Session().context.bounded

    def test_nothing_is_refused_when_unbounded(self):
        session = Session()
        result = _budgeted(session, "get_diff", ToolResult(big(500_000), "huge"))
        assert not result.is_error
        assert session.context.refused_results == 0

    def test_it_still_counts_while_unbounded(self):
        """Measuring is free and is how anyone learns the limit is needed."""
        session = Session()
        _budgeted(session, "get_diff", ToolResult(big(1000), "s"))
        assert session.context.estimated_result_tokens > 0


class TestTheCheckHappensBeforeTheContentEnters:
    """The "one last huge tool call" problem.

    A 20k result admitted at 105k against a 110k ceiling does not stop at 110k.
    It lands at 125k, and the ceiling measured nothing.
    """

    def test_a_result_that_would_cross_the_limit_is_not_returned(self):
        session = Session()
        session.context = ContextBudget(soft=80, hard=100)
        session.context.estimated_result_tokens = 90
        result = _budgeted(session, "read_file", ToolResult(big(50), "big"))
        assert result.is_error
        assert "not returned" in result.content

    def test_the_refused_content_does_not_enter_the_estimate(self):
        """Only the refusal message does, and it is a fraction of the result.

        The estimate can still pass `hard` — the refusal is text in the
        conversation, and not counting it let a run of repeated refusals grow
        the real context while the number stood still. What must not happen is
        the 50k result landing in it.
        """
        session = Session()
        session.context = ContextBudget(soft=80, hard=100)
        session.context.estimated_result_tokens = 90
        _budgeted(session, "read_file", ToolResult(big(5000), "big"))
        assert session.context.estimated_result_tokens < 5000

    def test_the_refusal_message_is_counted(self):
        session = Session()
        session.context = ContextBudget(soft=80, hard=100)
        session.context.estimated_result_tokens = 90
        _budgeted(session, "read_file", ToolResult(big(50), "big"))
        assert session.context.estimated_result_tokens > 90

    def test_the_refusal_says_what_to_do_next(self):
        session = Session()
        session.context = ContextBudget(soft=10, hard=20)
        result = _budgeted(session, "search_code", ToolResult(big(500), "big"))
        assert "Narrow the request" in result.content

    def test_a_result_that_fits_is_returned_whole(self):
        session = Session()
        session.context = ContextBudget(soft=900, hard=1000)
        body = big(50)
        result = _budgeted(session, "read_file", ToolResult(body, "s"))
        assert result.content.startswith(body)


class TestARefusalIsRecordedNotDropped:
    """A review that could not read something has a gap, and it must reach the
    report. Making the input less parseable must never make the failure less
    visible."""

    def test_the_refusal_is_counted(self):
        session = Session()
        session.context = ContextBudget(soft=10, hard=20)
        _budgeted(session, "get_diff", ToolResult(big(500), "big"))
        assert session.context.refused_results == 1
        assert session.context.refused_tokens > 0

    def test_the_event_names_the_tool_and_the_reason(self):
        session = Session()
        session.context = ContextBudget(soft=10, hard=20)
        _budgeted(session, "get_diff", ToolResult(big(500), "big"))
        refused = [e for e in session.context.events if not e.admitted]
        assert [e.tool for e in refused] == ["get_diff"]
        assert refused[0].reason
        # The refusal message is its own admitted event, under its own name, so
        # `largest_result` cannot report it as a get_diff that was delivered.
        assert session.context.events[-1].tool == "get_diff:refusal"
        assert session.context.events[-1].admitted

    def test_the_summary_says_something_was_refused(self):
        session = Session()
        session.context = ContextBudget(soft=10, hard=20)
        _budgeted(session, "get_diff", ToolResult(big(500), "big"))
        assert "refused for space" in session.context.summary()


class TestAnErrorIsAlwaysDelivered:
    def test_an_error_result_is_not_refused_for_space(self):
        """Refusing the message that explains a bad argument leaves the model
        guessing at the moment it most needs to narrow its request."""
        session = Session()
        session.context = ContextBudget(soft=1, hard=2)
        result = _budgeted(session, "read_file",
                           ToolResult("no such path", "error", is_error=True))
        assert result.content == "no such path"


class TestTheSoftLimitAdvisesRatherThanStops:
    def test_below_the_soft_limit_nothing_is_appended(self):
        session = Session()
        session.context = ContextBudget(soft=1000, hard=2000)
        body = big(10)
        assert _budgeted(session, "read_file", ToolResult(body, "s")).content == body

    def test_above_it_the_result_carries_a_hint(self):
        session = Session()
        session.context = ContextBudget(soft=10, hard=1000)
        session.context.estimated_result_tokens = 20
        result = _budgeted(session, "read_file", ToolResult(big(5), "s"))
        assert "context budget" in result.content

    def test_the_hint_rides_on_a_result_rather_than_a_turn(self):
        """A turn costs the whole history again, which is what is being saved."""
        session = Session()
        session.context = ContextBudget(soft=10, hard=1000)
        session.context.estimated_result_tokens = 20
        body = big(5)
        result = _budgeted(session, "read_file", ToolResult(body, "s"))
        assert result.content.startswith(body)


class TestWhatIsLeft:
    @pytest.mark.parametrize("hard,expected", [(0, None), (100, 100)])
    def test_remaining_is_absent_when_unbounded(self, hard, expected):
        budget = ContextBudget(hard=hard)
        assert budget.remaining == expected


class TestTheHeaviestResultIsNamed:
    """A run's context is not spent evenly.

    One whole-file read or one unbounded diff outweighs the twenty calls around
    it, and the total alone does not say which — so tightening a limit would
    start by guessing. `estimated_tokens` per event was recorded and read by
    nothing until `tools/unenforced.py` said so, hours after that check was
    added to the suite.
    """

    def test_it_names_the_biggest_single_result(self):
        session = Session()
        session.context = ContextBudget(soft=100_000, hard=200_000)
        _budgeted(session, "search_code", ToolResult(big(10), "s"))
        _budgeted(session, "get_diff", ToolResult(big(4000), "s"))
        _budgeted(session, "read_file", ToolResult(big(50), "s"))
        assert session.context.largest_result.tool == "get_diff"

    def test_a_refused_result_can_be_the_heaviest(self):
        """It is the one worth knowing about: it did not fit."""
        session = Session()
        session.context = ContextBudget(soft=10, hard=100)
        _budgeted(session, "read_file", ToolResult(big(5), "s"))
        _budgeted(session, "get_diff", ToolResult(big(5000), "s"))
        heaviest = session.context.largest_result
        assert heaviest.tool == "get_diff"
        assert not heaviest.admitted

    def test_the_summary_carries_it(self):
        session = Session()
        session.context = ContextBudget(soft=100_000, hard=200_000)
        _budgeted(session, "get_diff", ToolResult(big(4000), "s"))
        assert "heaviest get_diff" in session.context.summary()

    def test_an_empty_budget_has_no_heaviest_and_does_not_raise(self):
        assert ContextBudget().largest_result.tool == ""
        assert "heaviest" not in ContextBudget().summary()
