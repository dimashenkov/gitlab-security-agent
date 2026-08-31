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
    estimated_result_tokens: int = 0
    admitted_results: int = 0
    refused_results: int = 0
    refused_tokens: int = 0
    events: List[ContextEvent] = field(default_factory=list)

    @classmethod
    def configured(cls, hard: int, soft: int = 0) -> "ContextBudget":
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
        return cls(hard=hard, soft=soft if soft else (hard * 3) // 4)

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
        self.events.append(ContextEvent(tool, cost, admitted=False, reason=reason))
        return cost

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
