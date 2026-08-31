"""How much of the conversation the review has already spent.

A `/usage` reading on 2026-08-31 showed a session allowance exhausted with 97%
of it spent above 150k context: not many turns, but many turns over an already
huge conversation. Every turn re-reads everything before it, so a review that
lets tool results accumulate pays for the whole history again at each step —
the same run reported 920k output tokens against 16.3M cache reads, a ratio of
about one to eighteen.

Turn and tool-call ceilings do not bound that. They bound how many times the
history is re-read, not how large it is by then. So context is budgeted here,
as a first-class quantity beside the others.

## It is an estimate, of one part, and it is named as one

Nothing in the CLI reports the live context size, so this counts the bytes we
put into the conversation and divides. Every name here says `estimated` rather
than reading as a measurement, because the day it is quoted as one is the day
someone builds a rule on it — this project has already built four wrong rules by
treating a measurable number as a stand-in for an unmeasurable one.

`estimated_result_tokens` is the narrower and more accurate name for what is
counted: **tool-result payload**. Not the system prompt, not the tool schemas,
not the reviewer's own output, not the tool arguments. The first name for it was
`estimated_context_tokens`, which claimed the whole conversation and would have
been believed. The real context is always larger than this number, so a ceiling
set here should be set below the context the run is meant to fit in.

Within what it does count, it errs high: bytes, not characters, over a divisor
lower than real code needs. A budget that understates spends the allowance it
was added to protect; one that overstates makes a reviewer ask why it stopped
early, and a question is the cheaper failure.

## What it must never do

Refusing a tool result to stay inside the budget makes the review smaller. That
is only acceptable when it is **visible**: every refusal is recorded, counts
toward the run being incomplete, and can never turn into a clean pass. Making
the input less parseable must never make the security decision more permissive
or the failure less visible, and a budget is a way of making the input less
parseable on purpose.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

# Bytes per token, deliberately low so the estimate runs high. English prose is
# nearer four; source code, with its punctuation and short identifiers, is
# routinely under three. An integer because the division is a ceiling.
BYTES_PER_TOKEN = 3

# Roughly what the refusal message costs. Used only by the imagined enforcing
# run in `shadow`, where the real message is never built. A constant rather
# than a measurement of the real string because it is one sentence and the
# imagined run is an estimate throughout; what it must not be is zero, or a
# session of nothing but refusals would look free.
_REFUSAL_MESSAGE_TOKENS = 100


@dataclass
class ContextEvent:
    """One thing that entered the conversation, or was refused entry."""

    tool: str
    estimated_tokens: int
    admitted: bool
    reason: str = ""


@dataclass
class ContextBudget:
    """The running estimate, and the two limits it is judged against.

    `soft` is where the review should start finishing what it is doing. `hard`
    is where a result stops being admitted at all. Both default to zero, which
    means unbounded — an explicit opt-in, because a budget switched on by
    default would silently change every existing run.
    """

    soft: int = 0
    hard: int = 0
    # Whether crossing the hard limit refuses a result or only records that it
    # would have. Observation is the default when a limit is first set, because
    # the numbers to set it to do not exist yet: this project has built four
    # wrong rules from expectation, and one run of "37% of reviews would have
    # been cut at 80k, 4% at 120k" is worth more than any of them. The report
    # says which mode was in force, because a limit that quietly did nothing
    # would be worse than no limit at all.
    enforcing: bool = False
    estimated_result_tokens: int = 0
    admitted_results: int = 0
    refused_results: int = 0
    refused_tokens: int = 0
    # What enforcement would have cost, counted while enforcing nothing.
    would_refuse_results: int = 0
    would_refuse_tokens: int = 0
    # The estimate an *enforcing* run would have carried, which is not the one
    # this run carries. Without it the observation is worthless: once the real
    # total passes `hard` it stays past it, so every later result is counted as
    # "would have been refused" — while the enforcing run it claims to describe
    # would have refused the first one, stayed under the limit, and admitted
    # most of the rest. The first version reported that inflated number, which
    # is exactly the shape of thing this project keeps mistaking for a
    # measurement.
    shadow_tokens: int = 0
    events: List[ContextEvent] = field(default_factory=list)

    @classmethod
    def configured(cls, hard: int, soft: int = 0,
                   enforcing: bool = False) -> "ContextBudget":
        """The budget one run was asked for.

        Zero hard is unbounded, and then the soft limit is meaningless rather
        than merely unused — `Config.validate` refuses that combination, and
        this refuses to invent one.

        A soft limit derived rather than given is three quarters of the hard
        one. It is a starting point, not a measurement: the number a run should
        actually use comes from telemetry across real reviews, and until there
        is some, a round fraction that is visibly a default is more honest than
        a precise-looking constant nobody derived.
        """
        if hard <= 0:
            return cls()
        return cls(hard=hard, soft=soft if soft else (hard * 3) // 4,
                   enforcing=enforcing)

    @property
    def bounded(self) -> bool:
        return self.hard > 0

    @property
    def remaining(self) -> Optional[int]:
        """Tokens left before the hard limit, or None when unbounded."""
        return None if not self.bounded else max(0, self.hard - self.estimated_result_tokens)

    @property
    def over_soft(self) -> bool:
        return bool(self.soft) and self.estimated_result_tokens >= self.soft

    @property
    def over_hard(self) -> bool:
        return self.bounded and self.estimated_result_tokens >= self.hard

    def estimate(self, text: str) -> int:
        """Tokens `text` will cost, rounded up.

        Bytes, not characters. `len()` counts characters, and one Cyrillic or
        CJK character is two to three UTF-8 bytes — a budget written to err high
        that measured characters would have understated exactly the inputs it
        understands least.

        Never zero for a non-empty string: a result that costs nothing is a
        result that would not have to be budgeted.
        """
        if not text:
            return 0
        size = len(text.encode("utf-8"))
        return max(1, -(-size // BYTES_PER_TOKEN))

    def would_exceed(self, text: str) -> bool:
        """Would admitting this cross the hard limit?

        Asked *before* the content enters the conversation. Asking afterwards
        is the "one last huge tool call" problem: a 20k result admitted at 105k
        against a 110k limit does not stop at 110k, it lands at 125k, and the
        limit measured nothing.
        """
        if not self.bounded:
            return False
        return self.estimated_result_tokens + self.estimate(text) > self.hard

    def admit(self, tool: str, text: str) -> int:
        """Count content that is going to the model. Returns its estimate."""
        cost = self.estimate(text)
        self.estimated_result_tokens += cost
        self.admitted_results += 1
        self.events.append(ContextEvent(tool, cost, admitted=True))
        return cost

    def refuse(self, tool: str, text: str, reason: str) -> int:
        """Count content that was kept out. It costs nothing and is not free.

        Recorded rather than dropped: a review that could not read something is
        a review with a gap in it, and the gap has to reach the report.
        """
        cost = self.estimate(text)
        self.refused_results += 1
        self.refused_tokens += cost
        self.events.append(ContextEvent(tool, cost, admitted=False,
                                        reason=reason))
        return cost

    def shadow(self, text: str) -> bool:
        """Would an *enforcing* run have refused this? Advances that run.

        The observing mode's whole value is a number for "37% of real reviews
        would have been cut at 80k" taken from real reviews rather than from
        anyone's expectation. That number has to come from a second, imagined
        run — the one where the refusals actually happened — because in this run
        nothing is refused and the total keeps climbing. Reading "over the
        limit" off *this* total counted every result after the first crossing as
        refused, while the run it described would have refused one and carried
        on under the ceiling.

        Returns whether the imagined run would have refused, and moves that run
        forward either way: a refusal there costs it only the refusal message,
        which is what it costs here too.
        """
        cost = self.estimate(text)
        if self.bounded and self.shadow_tokens + cost > self.hard:
            self.would_refuse_results += 1
            self.would_refuse_tokens += cost
            # The refusal message is what the enforcing run would have carried
            # instead. Small, and not nothing — a run of refusals still grows.
            self.shadow_tokens += _REFUSAL_MESSAGE_TOKENS
            return True
        self.shadow_tokens += cost
        return False

    def amplification(self) -> int:
        """Roughly what this run's tool output cost across the whole run.

        Everything already in the conversation is re-read before each new
        result arrives, so a result's real cost is its size times the number of
        results that came after it. Forty thousand tokens as the last thing
        fetched is forty thousand; the same forty thousand fetched first with
        nineteen calls behind it is nearly eight hundred thousand — and that is
        the shape of 920k output against 16.3M cache reads.

        The clock is position among the *admitted* results rather than the
        model's turn number, because the child process that runs the tools on
        the CLI path does not count turns and would have reported zero for
        every run on the path that matters most. Refused results are not in the
        clock at all: they never entered the conversation, so counting them
        would inflate everything before them with content nobody paid for.

        It is a proxy and it has one known bias. Several tool calls returned in
        a single assistant turn enter the next request together, so the first
        of them is not re-read before the second — this counts as though it
        were, and over-states the earlier members of a parallel batch. It is
        recorded here rather than corrected because nothing at this layer knows
        where a turn ended, and a number whose bias is written down can still
        rank tools; one whose bias is not will be quoted as a measurement.
        """
        admitted = [e for e in self.events if e.admitted]
        total = len(admitted)
        return sum(e.estimated_tokens * (total - 1 - i)
                   for i, e in enumerate(admitted))

    def by_tool(self) -> List[tuple]:
        """(tool, tokens, amplified) per tool, heaviest amplified first."""
        admitted = [e for e in self.events if e.admitted]
        total = len(admitted)
        totals: dict = {}
        for i, event in enumerate(admitted):
            tokens, amplified = totals.get(event.tool, (0, 0))
            totals[event.tool] = (
                tokens + event.estimated_tokens,
                amplified + event.estimated_tokens * (total - 1 - i),
            )
        return sorted(((tool, t, a) for tool, (t, a) in totals.items()),
                      key=lambda row: row[2], reverse=True)

    def hint(self) -> str:
        """A line for the model when the budget is getting tight, or "".

        Appended to a result rather than sent as its own turn: a turn costs the
        whole history again, which is the thing being economised.
        """
        if not self.bounded or not self.over_soft:
            return ""
        left = self.remaining
        return ("\n\n[context budget: about {:,} of {:,} estimated tokens of "
                "tool output used, {:,} left. Prefer narrow reads — a line "
                "range, a single file, a tighter pattern.]".format(
                    self.estimated_result_tokens, self.hard, left or 0))

    @property
    def largest_result(self) -> ContextEvent:
        """The single heaviest thing a tool returned, admitted or not.

        A run's context is usually not spent evenly: one whole-file read or one
        unbounded diff accounts for more than the twenty calls around it, and
        the total alone does not say which. This names it, so tightening a
        limit can start from the tool that actually costs.
        """
        return max(self.events, key=lambda e: e.estimated_tokens,
                   default=ContextEvent("", 0, admitted=True))

    def summary(self) -> str:
        heaviest = self.largest_result
        biggest = ("" if not heaviest.tool else
                   ", heaviest {} at {:,}".format(heaviest.tool,
                                                  heaviest.estimated_tokens))
        if not self.bounded:
            return ("context: {:,} estimated tokens of tool output{} "
                    "(unbounded)".format(self.estimated_result_tokens, biggest))
        line = ("context: {:,} of {:,} estimated tokens of tool output{}, "
                "{} result(s) admitted".format(
                    self.estimated_result_tokens, self.hard,
                    biggest, self.admitted_results))
        if self.refused_results:
            line += ", {} refused for space ({:,} estimated tokens)".format(
                self.refused_results, self.refused_tokens)
        return line
