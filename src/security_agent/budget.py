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


@dataclass(frozen=True)
class Profile:
    """A named policy. Allowances are cut from it, one per session.

    `verifiers` is votes per candidate and is odd on purpose. Two verifiers
    cannot form a majority, so a disagreement between them is settled by a rule
    rather than by evidence — measured, that produced three blocks and one pass
    across four identical runs of one case, because a single hedge forced the
    verdict to uncertain and uncertain is under the gate. A profile that quietly
    sets two would revert that fix while looking like a budget choice.

    `review_turns` is `None` when the runner cannot enforce it. The Claude Code
    CLI has no `--max-turns`, and a profile that advertises twenty turns to a
    runner which does not count turns is a profile that lies. Wall clock and
    tool calls are the portable ceilings; turns are an extra the Messages API
    path can offer and the CLI path cannot.
    """

    name: str
    review_turns: Optional[int]
    review_tool_calls: int
    verifiers: int
    verifier_turns: int
    verifier_tool_calls: int
    runtime_seconds: int
    # Some profiles cannot produce a verdict at all, whatever they find.
    conclusive: bool = True

    def __post_init__(self) -> None:
        if self.verifiers not in (0, 1, 3, 5):
            raise ValueError(
                "{}: a verifier panel must be odd — {} verifiers cannot form a "
                "majority, and settling a disagreement by rule instead of by "
                "evidence is the defect the odd panel fixed".format(
                    self.name, self.verifiers))
        if self.verifiers and self.verifier_tool_calls < 1:
            raise ValueError(
                "{}: a verifier with no tool calls cannot search for the "
                "control it is required to name, and a verdict that cannot say "
                "what it looked for is downgraded to uncertain — which is under "
                "the gate. Every finding would block.".format(self.name))

    @property
    def allocated_tool_calls(self) -> int:
        """The most this profile can hand out, if every verifier is used."""
        return self.review_tool_calls + self.verifiers * self.verifier_tool_calls


PROFILES: Dict[str, Profile] = {
    # Small enough to run on every save, and honest about what that buys.
    # Real reviews measured 7-13 turns and 265-895 seconds, so six turns cuts
    # through the middle of the distribution: this stops early most of the
    # time, by design. It is therefore never allowed to conclude anything —
    # see `conclusive`.
    "probe": Profile("probe", review_turns=6, review_tool_calls=40,
                     verifiers=0, verifier_turns=0, verifier_tool_calls=0,
                     runtime_seconds=300, conclusive=False),
    # The local default. Room above the measured maximum rather than level
    # with it: a ceiling that only just covers the longest observed run is a
    # ceiling that truncates the next one.
    "normal": Profile("normal", review_turns=20, review_tool_calls=100,
                      verifiers=3, verifier_turns=8, verifier_tool_calls=15,
                      runtime_seconds=1_200),
    # Asked for explicitly, never a default.
    "deep": Profile("deep", review_turns=40, review_tool_calls=250,
                    verifiers=3, verifier_turns=12, verifier_tool_calls=25,
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
    exhausted: bool = False

    def note_tool_call(self) -> bool:
        """Count one attempt. False means this one should be refused.

        An attempt counts whether the tool succeeds, fails validation, or is
        rejected — one documented rule, so the number means the same thing on
        both runners. Counting only successes would let a session with a broken
        argument loop for free.
        """
        if self.exhausted:
            return False
        self.spent += 1
        if self.spent >= self.ceiling:
            self.exhausted = True
        return True

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
    verifier_turns: int = 0
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
        if target.exhausted and target is self.review:
            # Only the reviewer's exhaustion ends the run. A verifier that
            # spends its allowance has finished searching and still votes; the
            # review around it is unaffected.
            self.stopped_by = STOPPED_TOOL_CALLS
        return allowed

    def note_review_turn(self) -> None:
        self.review_turns += 1
        limit = self.profile.review_turns
        if self.turns_enforced and limit is not None and self.review_turns >= limit:
            self.stopped_by = STOPPED_TURNS

    def note_verifier_turn(self) -> None:
        self.verifier_turns += 1

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
        if self.verifier_sessions >= self.profile.verifiers:
            self.stopped_by = STOPPED_VERIFIERS
            return None
        allowance = Allowance(
            "verifier {}".format(self.verifier_sessions + 1),
            self.profile.verifier_tool_calls)
        self.verifier_allowances.append(allowance)
        return allowance

    def check(self) -> str:
        """The ceiling that has been hit, or "". Cheap enough to call often."""
        if self.stopped_by:
            return self.stopped_by
        if self.elapsed > self.profile.runtime_seconds:
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
                                                self.profile.verifiers),
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
