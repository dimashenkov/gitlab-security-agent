"""One budget policy, handed out as fixed allowances that nobody shares.

Local development on a Claude subscription and CI on a paid API key are the
same problem wearing different clothes: a review that wanders costs something
the operator did not agree to. On the subscription it is a plan limit that
stops the developer working; on the API it is money. Both want the same answer
— stop, and say plainly that stopping is not a verdict.

**Allowances, not a shared counter.** The reviewer gets a number of tool calls
it may spend. Each verifier gets its own, reserved before it starts, and never
gives the remainder back. Verifiers run concurrently — under the Claude Code
runner they are separate processes — so a shared counter would have to be read
across a boundary while other sessions are still spending it. That is a race,
and a race in a budget is a race in the security decision: whether a verifier
got to search before voting would depend on scheduling.

The cost is that unspent allowance is not reclaimed. A verifier that answers in
two calls does not return the other thirteen. That is the intended trade — the
alternative is exactly the read-while-others-write the reservation exists to
avoid — and `summary()` reports allocated and spent separately so a ceiling
nobody reached cannot read as a ceiling nobody needed.

Three things are counted, and deliberately not tokens alone:

* **wall clock**, which every runner can measure;
* **tool calls**, counted at the one dispatcher every tool goes through — an
  attempt counts whether it succeeds, fails validation, or is refused for
  budget, so the number means the same thing on both runners;
* **verifier sessions**, the largest single cost and the easiest to multiply
  by accident.

Token counts are recorded when a runner can supply them honestly and are never
required. The Claude Code CLI reports usage per run; the Messages API reports
it per turn; a limit that depends on a number the backend may not give is a
limit that exists and does not work.

The rule that matters more than any number here: **exhausting the budget is
exit 2.** A review that stopped early found what it found in the time it had,
and rendering that as a clean result is the failure this project exists to
prevent — the same failure as an incomplete run scored as "found nothing".
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

# Named so a message can say which ceiling was hit rather than "the budget".
STOPPED_RUNTIME = "runtime"
STOPPED_TOOL_CALLS = "tool_calls"
STOPPED_VERIFIERS = "verifier_sessions"
STOPPED_TURNS = "turns"

_EXPLANATIONS = {
    STOPPED_RUNTIME: "the run reached its time limit",
    STOPPED_TOOL_CALLS: "the run reached its limit on tool calls",
    STOPPED_VERIFIERS: "the run reached its limit on verifier sessions",
    STOPPED_TURNS: "the run reached its turn limit",
}


# The smallest panel a finding that could block ever gets. `verify._votes_for`
# escalates any gate-eligible claim to three votes and forces the count odd, so
# three is also the smallest number of seats a run must be able to hand out
# before verification means anything at all.
SMALLEST_GATING_PANEL = 3


@dataclass(frozen=True)
class Profile:
    """A named policy. Allowances are cut from it, one per session.

    `verifiers` is a **run-wide ceiling on verifier sessions** — the money
    limit, and the largest single cost in the tool. It is not the panel size,
    although it was documented as "votes per candidate" for as long as the
    field has existed. Nothing reads it that way: `RunBudget.reserve_verifier`
    is its only consumer and it hands out one seat per *vote across the whole
    run*, so `verifier_sessions=3` seats one three-vote panel and every later
    gate-eligible finding is reported unverified.

    How many votes a claim gets is `Config.verify_votes`
    (`SECURITY_SCAN_VERIFY_VOTES`, `--verifiers`), read by `verify._votes_for`,
    which escalates a gate-eligible claim to three and forces the count odd —
    and that is where the odd-panel rule belongs. It used to be applied to this
    field instead, which guarded nothing: an odd *budget* does not make a panel
    odd, and a profile could not have made one even if it tried.

    What this field does need guarding against is starvation. Seats are
    reserved before the sessions start, so a pool smaller than the panel leaves
    the rest of the seats empty, and `panel._quorate` discards a panel that
    lost half its seats — the run pays for a session whose vote cannot count.

    `review_turns` is `None` when the runner cannot enforce it. The Claude Code
    CLI has no `--max-turns`, and a profile that advertises twenty turns to a
    runner which does not count turns is a profile that lies. Wall clock and
    tool calls are the portable ceilings; turns are an extra the Messages API
    path can offer and the CLI path cannot.

    There is no `verifier_turns`. It was declared here, never read by anything,
    and never reported — the real ceiling on a verifier's turns is
    `verify.MAX_VERIFY_TURNS`, which is 14, while this field said 8 for
    `normal` and 12 for `deep`. A second copy of a limit, disagreeing with the
    enforced one and applied by nobody, is worse than no limit at all. The
    argument is still accepted and ignored so that call sites outside this
    module keep working; delete it from them and then delete it from here.
    """

    name: str
    review_turns: Optional[int]
    review_tool_calls: int
    verifier_sessions: int
    verifier_tool_calls: int
    runtime_seconds: int
    # Some profiles cannot produce a verdict at all, whatever they find.
    conclusive: bool = True

    def __post_init__(self) -> None:
        if self.verifier_sessions and self.verifier_sessions < SMALLEST_GATING_PANEL:
            raise ValueError(
                "{}: {} verifier session(s) cannot seat a panel. A finding that "
                "could block gets {} votes, seats are reserved before the "
                "sessions start, and a panel that lost half its seats decides "
                "nothing — so this buys a verifier whose vote is discarded. "
                "Use 0 for no verification at all.".format(
                    self.name, self.verifier_sessions, SMALLEST_GATING_PANEL))
        if self.verifier_sessions and self.verifier_tool_calls < 1:
            raise ValueError(
                "{}: a verifier with no tool calls cannot search for the "
                "control it is required to name, and a verdict that cannot say "
                "what it looked for is downgraded to uncertain — which is under "
                "the gate. Every finding would block.".format(self.name))

    @property
    def allocated_tool_calls(self) -> int:
        """The most this profile can hand out, if every verifier is used."""
        return self.review_tool_calls + self.verifier_sessions * self.verifier_tool_calls


PROFILES: Dict[str, Profile] = {
    # Small enough to run on every save, and honest about what that buys.
    # Real reviews measured 7-13 turns and 265-895 seconds, so six turns cuts
    # through the middle of the distribution: this stops early most of the
    # time, by design. It is therefore never allowed to conclude anything —
    # see `conclusive`.
    "probe": Profile("probe", review_turns=6, review_tool_calls=40,
                     verifier_sessions=0, verifier_tool_calls=0,
                     runtime_seconds=300, conclusive=False),
    # The local default. Room above the measured maximum rather than level
    # with it: a ceiling that only just covers the longest observed run is a
    # ceiling that truncates the next one.
    # `verifier_sessions=3` is one panel for the whole run: the first gate-eligible
    # finding is checked and any later one is reported unverified, which blocks
    # rather than passes but is not a checked result. Raising it is a real
    # increase in spend, so it is a decision to take with a measurement rather
    # than in passing.
    "normal": Profile("normal", review_turns=20, review_tool_calls=100,
                      verifier_sessions=3, verifier_tool_calls=15,
                      runtime_seconds=1_200),
    # Asked for explicitly, never a default.
    "deep": Profile("deep", review_turns=40, review_tool_calls=250,
                    verifier_sessions=3, verifier_tool_calls=25,
                    runtime_seconds=1_800),
}

DEFAULT_PROFILE = "normal"


@dataclass
class Allowance:
    """A fixed number of tool calls, held by exactly one session.

    Handed over whole before the session starts. Nothing reads it from outside
    while it is being spent, and nothing else spends from it — which is what
    makes concurrent verifiers safe without a lock.
    """

    label: str
    ceiling: int
    spent: int = 0

    def note_tool_call(self) -> bool:
        """Count one attempt. False means this one should be refused.

        An attempt counts whether the tool succeeds, fails validation, or is
        rejected — one documented rule, so the number means the same thing on
        both runners. Counting only successes would let a session with a broken
        argument loop for free.

        The call that reaches the ceiling is served; the next one is refused.
        Refusing the one that reaches it throws away work already decided on.
        """
        if self.exhausted:
            return False
        self.spent += 1
        return True

    @property
    def exhausted(self) -> bool:
        """Nothing left to spend. **The one definition of exhaustion.**

        Derived rather than stored. It used to be a flag set inside
        `note_tool_call`, which made it a second copy of a fact the counters
        already hold: an allowance spent through any other route — the CLI
        runner folds a child's spend straight onto `budget.review` — had the
        counter moved and the flag left behind, and `RunBudget` read the flag.
        So two budgets with identical numbers reported different exhaustion.
        """
        return self.spent >= self.ceiling

    @property
    def remaining(self) -> int:
        return max(0, self.ceiling - self.spent)


@dataclass
class RunBudget:
    """What has been allocated, what was spent, and whether anything is left.

    One per run. Wall clock is global because there is only one clock; tool
    calls live in the allowances and are never pooled.
    """

    profile: Profile
    started: float = field(default_factory=time.monotonic)
    # Set False by a runner that cannot count turns. Reported as unenforced
    # rather than silently ignored: a limit nobody applies must not appear in a
    # usage report as though it had been.
    turns_enforced: bool = True
    review: Allowance = field(init=False)
    verifier_allowances: List[Allowance] = field(default_factory=list)
    review_turns: int = 0
    # Recorded when a runner can supply them, never required. `None` means the
    # backend did not say — which is reported as "unavailable", never as zero.
    input_tokens: Optional[int] = None
    output_tokens: Optional[int] = None
    cost_usd: Optional[float] = None
    stopped_by: str = ""

    def __post_init__(self) -> None:
        self.review = Allowance("review", self.profile.review_tool_calls)

    @property
    def elapsed(self) -> float:
        return time.monotonic() - self.started

    @property
    def exhausted(self) -> bool:
        return bool(self.stopped_by)

    @property
    def verifier_sessions(self) -> int:
        return len(self.verifier_allowances)

    @property
    def allocated_tool_calls(self) -> int:
        """What was handed out — not what the profile permits.

        A run that used one verifier allocated one verifier's worth, and
        reporting the profile's maximum instead would describe a budget that
        was never granted.
        """
        return self.review.ceiling + sum(a.ceiling for a in self.verifier_allowances)

    @property
    def spent_tool_calls(self) -> int:
        return self.review.spent + sum(a.spent for a in self.verifier_allowances)

    def note_tool_call(self, allowance: Optional[Allowance] = None) -> bool:
        """Spend from one allowance. Defaults to the reviewer's."""
        if self.check():
            return False
        target = allowance or self.review
        allowed = target.note_tool_call()
        # Whether the run has stopped is asked of `check()`, which reads the
        # reviewer's allowance directly. Deciding it here as well would make
        # the answer depend on which entry point spent the call — and the
        # Claude Code runner spends through `budget.review` rather than
        # through this method.
        self.check()
        return allowed

    def note_review_turn(self) -> None:
        self.review_turns += 1
        limit = self.profile.review_turns
        if self.turns_enforced and limit is not None and self.review_turns >= limit:
            self.stopped_by = STOPPED_TURNS

    def reserve_verifier(self) -> Optional[Allowance]:
        """Claim a verifier session and its own tool calls, or refuse.

        One atomic step, before the session starts, because verifiers run
        concurrently — and under the Claude Code runner, in separate processes.
        Counting afterwards lets several sessions each observe spare capacity
        and start together, which is how a panel of three becomes a panel of
        six. Returns the allowance to hand to that session, or `None`.
        """
        if self.check():
            return None
        if self.verifier_sessions >= self.profile.verifier_sessions:
            self.stopped_by = STOPPED_VERIFIERS
            return None
        allowance = Allowance(
            "verifier {}".format(self.verifier_sessions + 1),
            self.profile.verifier_tool_calls)
        self.verifier_allowances.append(allowance)
        return allowance

    def check(self) -> str:
        """The ceiling that has been hit, or "". Cheap enough to call often.

        The reviewer's allowance is read here rather than flagged when it is
        spent, so that a run stops on the same fact whichever way the calls
        were counted. Only the reviewer's exhaustion ends the run: a verifier
        that spends its allowance has finished searching and still votes.

        Tool calls are tested before the clock because reaching an allowance is
        an event that definitely happened, while `elapsed` becomes true at the
        moment somebody asks — and a report naming the wrong ceiling sends the
        reader to raise the wrong limit.
        """
        if self.stopped_by:
            return self.stopped_by
        if self.review.exhausted:
            self.stopped_by = STOPPED_TOOL_CALLS
        elif self.elapsed > self.profile.runtime_seconds:
            self.stopped_by = STOPPED_RUNTIME
        return self.stopped_by

    def note_usage(self, input_tokens=None, output_tokens=None, cost_usd=None) -> None:
        """Record what a runner could tell us. Absent stays absent."""
        if input_tokens is not None:
            self.input_tokens = (self.input_tokens or 0) + int(input_tokens)
        if output_tokens is not None:
            self.output_tokens = (self.output_tokens or 0) + int(output_tokens)
        if cost_usd is not None:
            self.cost_usd = (self.cost_usd or 0.0) + float(cost_usd)

    def why_stopped(self) -> str:
        """A sentence for the report, or "" if nothing stopped the run."""
        if not self.stopped_by:
            return ""
        return (
            "{}. This is not a statement about the code — the review stopped "
            "before it finished looking. Raise the profile or the limit for a "
            "complete review.".format(_EXPLANATIONS[self.stopped_by]))

    def summary(self) -> List[str]:
        """The usage report, with unavailable and unenforced figures named."""
        lines = [
            "Profile: {}{}".format(
                self.profile.name,
                "" if self.profile.conclusive else " (never conclusive)"),
            "Reviewer turns: {}{}".format(self.review_turns, self._turn_ceiling()),
            "Verifier sessions: {} / {}".format(self.verifier_sessions,
                                                self.profile.verifier_sessions),
            # Allocated, not permitted, and spent separately from both. Without
            # the middle number "40 of 100" hides that sixty of those hundred
            # were handed to verifiers and were never the reviewer's to spend.
            "Tool calls: {} spent of {} allocated (reviewer {}/{})".format(
                self.spent_tool_calls, self.allocated_tool_calls,
                self.review.spent, self.review.ceiling),
            "Runtime: {} / {}".format(_clock(self.elapsed),
                                      _clock(self.profile.runtime_seconds)),
        ]
        if self.input_tokens is None and self.output_tokens is None:
            # Said plainly rather than printed as zero. A fabricated number is
            # worse than an admitted gap, and this one is a real gap: not every
            # runner can report tokens.
            lines.append("Model token usage: not reported by this runner")
        else:
            lines.append("Model tokens: {} in, {} out".format(
                self.input_tokens or 0, self.output_tokens or 0))
        if self.cost_usd is not None:
            lines.append("Cost: ${:.2f}".format(self.cost_usd))
        return lines

    def _turn_ceiling(self) -> str:
        if self.profile.review_turns is None:
            return " (no turn limit in this profile)"
        if not self.turns_enforced:
            return " / {} (not enforceable by this runner)".format(
                self.profile.review_turns)
        return " / {}".format(self.profile.review_turns)


def _clock(seconds: float) -> str:
    minutes, rest = divmod(int(seconds), 60)
    return "{}m {:02d}s".format(minutes, rest)


def profile_named(name: str) -> Profile:
    if name not in PROFILES:
        raise ValueError("unknown profile {!r}; choose one of {}".format(
            name, ", ".join(sorted(PROFILES))))
    return PROFILES[name]
