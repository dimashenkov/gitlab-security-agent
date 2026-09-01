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
        session.context = ContextBudget(soft=80, hard=100, enforcing=True)
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
        session.context = ContextBudget(soft=80, hard=100, enforcing=True)
        session.context.estimated_result_tokens = 90
        _budgeted(session, "read_file", ToolResult(big(5000), "big"))
        assert session.context.estimated_result_tokens < 5000

    def test_the_refusal_message_is_counted(self):
        session = Session()
        session.context = ContextBudget(soft=80, hard=100, enforcing=True)
        session.context.estimated_result_tokens = 90
        _budgeted(session, "read_file", ToolResult(big(50), "big"))
        assert session.context.estimated_result_tokens > 90

    def test_the_refusal_says_what_to_do_next(self):
        session = Session()
        session.context = ContextBudget(soft=10, hard=20, enforcing=True)
        result = _budgeted(session, "search_code", ToolResult(big(500), "big"))
        assert "Narrow the request" in result.content

    def test_a_result_that_fits_is_returned_whole(self):
        session = Session()
        session.context = ContextBudget(soft=900, hard=1000, enforcing=True)
        body = big(50)
        result = _budgeted(session, "read_file", ToolResult(body, "s"))
        assert result.content.startswith(body)


class TestARefusalIsRecordedNotDropped:
    """A review that could not read something has a gap, and it must reach the
    report. Making the input less parseable must never make the failure less
    visible."""

    def test_the_refusal_is_counted(self):
        session = Session()
        session.context = ContextBudget(soft=10, hard=20, enforcing=True)
        _budgeted(session, "get_diff", ToolResult(big(500), "big"))
        assert session.context.refused_results == 1
        assert session.context.refused_tokens > 0

    def test_the_event_names_the_tool_and_the_reason(self):
        session = Session()
        session.context = ContextBudget(soft=10, hard=20, enforcing=True)
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
        session.context = ContextBudget(soft=10, hard=20, enforcing=True)
        _budgeted(session, "get_diff", ToolResult(big(500), "big"))
        assert "refused for space" in session.context.summary()


class TestAnErrorIsAlwaysDelivered:
    def test_an_error_result_is_not_refused_for_space(self):
        """Refusing the message that explains a bad argument leaves the model
        guessing at the moment it most needs to narrow its request."""
        session = Session()
        session.context = ContextBudget(soft=1, hard=2, enforcing=True)
        result = _budgeted(session, "read_file",
                           ToolResult("no such path", "error", is_error=True))
        assert result.content == "no such path"


class TestTheSoftLimitAdvisesRatherThanStops:
    def test_below_the_soft_limit_nothing_is_appended(self):
        session = Session()
        session.context = ContextBudget(soft=1000, hard=2000, enforcing=True)
        body = big(10)
        assert _budgeted(session, "read_file", ToolResult(body, "s")).content == body

    def test_above_it_the_result_carries_a_hint(self):
        session = Session()
        session.context = ContextBudget(soft=10, hard=1000, enforcing=True)
        session.context.estimated_result_tokens = 20
        result = _budgeted(session, "read_file", ToolResult(big(5), "s"))
        assert "context budget" in result.content

    def test_the_hint_rides_on_a_result_rather_than_a_turn(self):
        """A turn costs the whole history again, which is what is being saved."""
        session = Session()
        session.context = ContextBudget(soft=10, hard=1000, enforcing=True)
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
        session.context = ContextBudget(soft=100_000, hard=200_000, enforcing=True)
        _budgeted(session, "search_code", ToolResult(big(10), "s"))
        _budgeted(session, "get_diff", ToolResult(big(4000), "s"))
        _budgeted(session, "read_file", ToolResult(big(50), "s"))
        assert session.context.largest_result.tool == "get_diff"

    def test_a_refused_result_can_be_the_heaviest(self):
        """It is the one worth knowing about: it did not fit."""
        session = Session()
        session.context = ContextBudget(soft=10, hard=100, enforcing=True)
        _budgeted(session, "read_file", ToolResult(big(5), "s"))
        _budgeted(session, "get_diff", ToolResult(big(5000), "s"))
        heaviest = session.context.largest_result
        assert heaviest.tool == "get_diff"
        assert not heaviest.admitted

    def test_the_summary_carries_it(self):
        session = Session()
        session.context = ContextBudget(soft=100_000, hard=200_000, enforcing=True)
        _budgeted(session, "get_diff", ToolResult(big(4000), "s"))
        assert "heaviest get_diff" in session.context.summary()

    def test_an_empty_budget_has_no_heaviest_and_does_not_raise(self):
        assert ContextBudget().largest_result.tool == ""
        assert "heaviest" not in ContextBudget().summary()


class TestObservingIsTheDefault:
    """Measurement first, enforcement second.

    A limit is a number somebody has to choose, and this project has built four
    wrong rules by choosing one from expectation. Setting a limit alone
    therefore measures: it counts what enforcement would have kept out, on a
    review that behaved exactly as it would have anyway — which is the only
    thing that makes the number worth having.
    """

    def test_a_limit_alone_does_not_refuse(self):
        session = Session()
        session.context = ContextBudget(soft=10, hard=20)
        result = _budgeted(session, "get_diff", ToolResult(big(500), "big"))
        assert not result.is_error
        assert session.context.refused_results == 0

    def test_it_records_what_would_have_happened(self):
        session = Session()
        session.context = ContextBudget(soft=10, hard=20)
        _budgeted(session, "get_diff", ToolResult(big(500), "big"))
        assert session.context.would_refuse_results == 1
        assert session.context.would_refuse_tokens >= 500

    def test_it_counts_the_run_that_would_have_happened_not_this_one(self):
        """The whole number, and the first version had it wrong.

        This run never refuses, so once its estimate passes the limit it stays
        past it and every later result reads as refused. The enforcing run it
        claims to describe would have refused the first one, stayed under the
        ceiling, and admitted the four small ones after it.
        """
        session = Session()
        session.context = ContextBudget(soft=400, hard=500)
        _budgeted(session, "get_diff", ToolResult(big(600), "huge"))
        for _ in range(4):
            _budgeted(session, "read_file", ToolResult(big(10), "small"))

        assert session.context.would_refuse_results == 1, (
            "counting this run's total would have said five")
        assert session.context.estimated_result_tokens > session.context.hard
        assert session.context.shadow_tokens < session.context.hard

    def test_a_run_of_refusals_is_not_free_in_the_imagined_run(self):
        """The refusal message is what the enforcing run would carry instead.
        Zero would make a session of nothing but refusals look costless."""
        session = Session()
        session.context = ContextBudget(soft=400, hard=500)
        for _ in range(3):
            _budgeted(session, "get_diff", ToolResult(big(600), "huge"))
        assert session.context.shadow_tokens > 0
        assert session.context.would_refuse_results == 3

    def test_the_content_still_reaches_the_model(self):
        """A measurement taken on an altered run measures the alteration."""
        session = Session()
        session.context = ContextBudget(soft=10, hard=20)
        body = big(500)
        assert _budgeted(session, "read_file",
                         ToolResult(body, "s")).content.startswith(body)

    def test_the_accounting_still_happens(self):
        session = Session()
        session.context = ContextBudget(soft=10, hard=20)
        _budgeted(session, "read_file",
                  ToolResult(big(500), "s", exposures=(("app.py", "read_file"),)))
        assert session.exposures == [("app.py", "read_file")]

    def test_enforcing_refuses(self):
        session = Session()
        session.context = ContextBudget(soft=10, hard=20, enforcing=True)
        assert _budgeted(session, "get_diff", ToolResult(big(500), "b")).is_error


class TestWhereTheCostActuallyIs:
    """Everything already in the conversation is re-read before each new result.

    So a result's real cost is its size times what came after it. Forty thousand
    tokens fetched last is forty thousand; the same forty thousand fetched first
    with nineteen calls behind it is nearly eight hundred thousand, and that is
    the shape of 920k output against 16.3M cache reads. Without this, a limit
    gets tightened where it is easiest rather than where the cost is.
    """

    def _run(self, *sizes):
        session = Session()
        for i, size in enumerate(sizes):
            _budgeted(session, "tool{}".format(i), ToolResult(big(size), "s"))
        return session.context

    def test_an_early_result_costs_more_than_a_late_one(self):
        early = self._run(1000, 10, 10, 10)
        late = self._run(10, 10, 10, 1000)

        assert early.amplification() > late.amplification()
        assert early.estimated_result_tokens == late.estimated_result_tokens

    def test_the_heaviest_tool_by_amplification_is_named(self):
        """Not the largest result — the one that cost the most across the run."""
        session = Session()
        _budgeted(session, "get_diff", ToolResult(big(1000), "s"))
        for _ in range(18):
            _budgeted(session, "search_code", ToolResult(big(1), "s"))
        _budgeted(session, "read_file", ToolResult(big(3000), "s"))

        assert session.context.largest_result.tool == "read_file"
        assert session.context.by_tool()[0][0] == "get_diff"

    def test_the_last_result_amplifies_nothing(self):
        session = Session()
        _budgeted(session, "get_diff", ToolResult(big(1000), "s"))
        assert session.context.amplification() == 0

    def test_an_empty_run_does_not_raise(self):
        assert ContextBudget().amplification() == 0
        assert ContextBudget().by_tool() == []

    def test_a_refused_result_does_not_amplify_what_came_before_it(self):
        """It never entered the conversation, so nothing was re-read because of
        it. Counting it inflated every earlier result with content nobody
        paid for."""
        with_refusal = Session()
        with_refusal.context = ContextBudget(soft=10, hard=1_000, enforcing=True)
        _budgeted(with_refusal, "get_diff", ToolResult(big(100), "s"))
        _budgeted(with_refusal, "read_file", ToolResult(big(5000), "refused"))

        assert with_refusal.context.refused_results == 1
        tools = dict((tool, tokens) for tool, tokens, _ in
                     with_refusal.context.by_tool())
        # The refusal message is real text and is counted under its own name.
        # The five thousand tokens that never arrived are counted nowhere.
        assert "read_file" not in tools
        assert "read_file:refusal" in tools
        assert max(tools.values()) < 5000
