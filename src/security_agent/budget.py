"""One budget, shared by the reviewer and every verifier in a run.

Local development on a Claude subscription and CI on a paid API key are the
same problem wearing different clothes: a review that wanders costs something
the operator did not agree to. On the subscription it is a plan limit that
stops the developer working; on the API it is money. Both want the same answer
— stop, and say plainly that stopping is not a verdict.

Three things are counted, and deliberately not tokens alone:

* **wall clock**, which every runner can measure;
* **tool calls**, which this project owns end to end because every tool goes
  through one dispatch;
* **verifier sessions**, which are the largest single cost and the easiest to
  multiply by accident.

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
    """A named set of ceilings.

    `verifiers` is votes per candidate and is odd on purpose. Two verifiers
    cannot form a majority, so a disagreement between them is settled by a rule
    rather than by evidence — measured, that produced three blocks and one pass
    across four identical runs of one case, because a single hedge forced the
    verdict to uncertain and uncertain is under the gate. A profile that quietly
    sets two would revert that fix while looking like a budget choice.
    """

    name: str
    review_turns: int
    verifiers: int
    verifier_turns: int
    runtime_seconds: int
    tool_calls: int
    # Some profiles cannot produce a verdict at all, whatever they find.
    conclusive: bool = True

    def __post_init__(self) -> None:
        if self.verifiers not in (0, 1, 3, 5):
            raise ValueError(
                "{}: a verifier panel must be odd — {} verifiers cannot form a "
                "majority, and settling a disagreement by rule instead of by "
                "evidence is the defect the odd panel fixed".format(
                    self.name, self.verifiers))


PROFILES: Dict[str, Profile] = {
    # Small enough to run on every save, and honest about what that buys.
    # Real reviews measured 7-13 turns and 265-895 seconds, so six turns cuts
    # through the middle of the distribution: this stops early most of the
    # time, by design. It is therefore never allowed to conclude anything —
    # see `conclusive`.
    "probe": Profile("probe", review_turns=6, verifiers=0, verifier_turns=0,
                     runtime_seconds=300, tool_calls=40, conclusive=False),
    # The local default. Room above the measured maximum rather than level
    # with it: a ceiling that only just covers the longest observed run is a
    # ceiling that truncates the next one.
    "normal": Profile("normal", review_turns=20, verifiers=3, verifier_turns=8,
                      runtime_seconds=1_200, tool_calls=100),
    # Asked for explicitly, never a default.
    "deep": Profile("deep", review_turns=40, verifiers=3, verifier_turns=12,
                    runtime_seconds=1_800, tool_calls=250),
}

DEFAULT_PROFILE = "normal"


@dataclass
class RunBudget:
    """What has been spent, and whether anything is left.

    Shared by every session in a run. Verifier capacity is *reserved* before a
    session starts rather than counted after it ends: verifiers run
    concurrently, and counting on completion lets three of them each see room
    for one more and start together.
    """

    profile: Profile
    started: float = field(default_factory=time.monotonic)
    tool_calls: int = 0
    review_turns: int = 0
    verifier_turns: int = 0
    verifier_sessions: int = 0
    # Recorded when a runner can supply them, never required. `None` means the
    # backend did not say — which is reported as "unavailable", never as zero.
    input_tokens: Optional[int] = None
    output_tokens: Optional[int] = None
    cost_usd: Optional[float] = None
    stopped_by: str = ""

    @property
    def elapsed(self) -> float:
        return time.monotonic() - self.started

    @property
    def exhausted(self) -> bool:
        return bool(self.stopped_by)

    def note_tool_call(self) -> bool:
        """Count one call. False means this one should be refused."""
        if self.check():
            return False
        self.tool_calls += 1
        if self.tool_calls >= self.profile.tool_calls:
            self.stopped_by = STOPPED_TOOL_CALLS
        return True

    def note_review_turn(self) -> None:
        self.review_turns += 1
        if self.review_turns >= self.profile.review_turns:
            self.stopped_by = STOPPED_TURNS

    def note_verifier_turn(self) -> None:
        self.verifier_turns += 1

    def reserve_verifier(self) -> bool:
        """Claim a verifier session up front, or refuse.

        Reserved rather than counted afterwards because verifiers run
        concurrently. Counting on completion lets several sessions each observe
        spare capacity and start together, which is how a panel of three
        becomes a panel of six.
        """
        if self.check():
            return False
        if self.verifier_sessions >= self.profile.verifiers:
            self.stopped_by = STOPPED_VERIFIERS
            return False
        self.verifier_sessions += 1
        return True

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
        """The usage report, with unavailable figures named as unavailable."""
        lines = [
            "Profile: {}{}".format(
                self.profile.name,
                "" if self.profile.conclusive else " (never conclusive)"),
            "Reviewer turns: {} / {}".format(self.review_turns,
                                             self.profile.review_turns),
            "Verifier sessions: {} / {}".format(self.verifier_sessions,
                                                self.profile.verifiers),
            "Tool calls: {} / {}".format(self.tool_calls, self.profile.tool_calls),
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


def _clock(seconds: float) -> str:
    minutes, rest = divmod(int(seconds), 60)
    return "{}m {:02d}s".format(minutes, rest)


def profile_named(name: str) -> Profile:
    if name not in PROFILES:
        raise ValueError("unknown profile {!r}; choose one of {}".format(
            name, ", ".join(sorted(PROFILES))))
    return PROFILES[name]
