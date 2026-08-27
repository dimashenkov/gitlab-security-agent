"""What a panel of verifiers decides, worked out once for every reader.

Everything here is a pure function of a finding and the votes cast on it. That
matters because there are two readers, and for a while there were two rules.

`verify` runs the panel and applies the answer. `session_document` reads a
finished session back across a process boundary and has to decide whether the
disposition written in it is one this panel could have produced — a document is
free to say anything, and the fields it would say wrongly are severity,
confidence, the verdict and the removed-control flag, each of which is the whole
gate decision on its own. That loader used to *bound* those fields instead:
accept any severity the recorded facts and corrections could justify, any
confidence some vote wrote down. The bound is wider than the rule. Three
confirming votes where one says `low` and two stay silent median to `high`, and
silence is agreement with the claim — yet a stored `low` sat inside the bound,
and `low` is under the gate. One hedging verifier could ungate a real finding
through the document rather than through the panel.

So the rule lives here, in one place, with no config and no I/O, and both
readers call it. The alternative — a second majority rule written into the
loader — is the failure this module exists to prevent, and the drifting copy is
always the one nobody reads.

One thing every rule here shares: **the panel is its reserved seats, not the
replies that arrived.** A verifier session can die, and it leaves behind a vote
carrying `error`. Counting only the votes that came back turns a lost session
into a smaller panel, and a smaller panel is one where fewer voices form a
majority — so a transport failure, not a verifier, decides the gate. Every
denominator below is `len(votes)`; what an empty seat may never do is help
anything reach a threshold.

Separate from `verify` rather than inside it because `verify` imports the
Anthropic SDK, and the loader runs in the child process on the path that costs
nothing.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Tuple

from .models import (
    VERDICT_CONFIRMED,
    VERDICT_REFUTED,
    VERDICT_UNCERTAIN,
    Finding,
    Vote,
    confidence_rank,
    severity_rank,
)
from .severity import derive


@dataclass(frozen=True)
class Disposition:
    """Everything a panel decides about one finding.

    Frozen and returned rather than written into the candidate, so the same
    call can be made by a reader that has no candidate to write into. The three
    facts are carried even though nothing stores them: severity is computed
    from them, so a caller explaining a rating needs to see which fact moved.
    """

    verdict: str
    removes_control: bool
    # The facts as the panel left them — the reviewer's, or a correction a
    # majority of the panel agreed on.
    impact: str
    reachable: str
    interaction: str
    severity: str
    severity_derivation: str
    confidence: str


def initial_rating(finding: Finding) -> Tuple[str, str]:
    """The severity a finding carries before any verifier has spoken.

    `Candidate.__post_init__` and the document loader both need this, and they
    need the same answer: the loader reconstructs the state the panel started
    from, so a different starting point here would make every recomputation
    below disagree with the run it is checking.
    """
    derived, why = derive(
        finding.impact,
        finding.reachable_without_authentication,
        finding.requires_user_interaction,
        finding.category,
    )
    if derived:
        return derived, why
    # An impact the table cannot rate leaves the reviewer's own label standing,
    # and says so rather than inventing a number.
    return finding.severity, "not derived ({}); using the reviewer's own rating".format(why)


def decide(finding: Finding, votes: List[Vote]) -> Disposition:
    """Turn the votes into a disposition, changing nothing.

    The starting state is established here rather than accepted from the
    caller. An earlier version took severity, its derivation and confidence as
    arguments, and that was a seam rather than a convenience: the verifier and
    the loader could begin from different states and both be told they agreed,
    which is the one thing this function exists to prevent. It also made
    repeated calls read the previous disposition as the starting point instead
    of the finding.

    Everything the panel needs is in the finding and the votes. The critical
    asymmetry below keys off the *derived* severity, which is now derived here,
    from the facts — the same value every caller would compute.
    """
    severity, severity_derivation = initial_rating(finding)
    confidence = finding.confidence
    # **The denominator is the seats, not the survivors.** `votes` holds one
    # entry per seat the panel reserved; a session that died leaves its seat
    # filled by a vote carrying `error`, and an empty seat is evidence in
    # neither direction. It must not count as agreement, and — the part that
    # was wrong here — it must not shrink the denominator until a smaller
    # number of voices becomes a majority.
    #
    # With two of three sessions dead, counting only survivors let one reply
    # carry a correction, switch on the removed-control gate and set the
    # panel's confidence by itself. That is the single-verifier decision the
    # odd panel was introduced to remove, arriving through a transport failure
    # instead of through a vote — so whether a merge blocked depended on which
    # session happened to crash.
    usable = [v for v in votes if not v.error]
    seats = len(votes)
    verdict = _verdict(votes, severity)

    # Unanimity of the *seats*, like every other upward move here. One verifier
    # calling it a removed control is not enough to gate a merge on, and a
    # panel of one survivor is unanimous by default. This flag gates whatever
    # the severity says, so a lone voice turning it on is a merge blocked by a
    # crash; the finding itself still stands on its own rating, because the
    # verdict rule above never lets an unfilled panel dismiss a claim.
    removes_control = (
        verdict != VERDICT_REFUTED
        and seats > 0
        and len(usable) == seats
        and all(v.removes_control == "yes" for v in usable)
    )

    if not usable or verdict == VERDICT_REFUTED:
        # Nothing to correct from, or nothing left to rate. Either way the
        # rating and the confidence stay exactly as they arrived.
        return Disposition(
            verdict=verdict,
            removes_control=removes_control,
            impact=finding.impact,
            reachable=finding.reachable_without_authentication,
            interaction=finding.requires_user_interaction,
            severity=severity,
            severity_derivation=severity_derivation,
            confidence=confidence,
        )

    # Severity is no longer a thing anyone votes on. It is computed from three
    # facts about the finding, so a verifier that disagrees corrects a fact and
    # the number follows — the label was the one part that moved between runs,
    # and taking opinions on it directly is what made it move.
    impact, reachable, interaction, corrected = _corrected_facts(finding, votes)
    severity, severity_derivation = _rating(
        finding, impact, reachable, interaction, corrected,
        severity, severity_derivation)

    return Disposition(
        verdict=verdict,
        removes_control=removes_control,
        impact=impact,
        reachable=reachable,
        interaction=interaction,
        severity=severity,
        severity_derivation=severity_derivation,
        confidence=_confidence(verdict, votes, confidence),
    )


def _confidence(verdict: str, votes: List[Vote], claimed: str) -> str:
    """What the panel leaves confidence at, for a claim it did not refute.

    Confidence moves in both directions, because it means something different
    from severity: it records how much of the chain was actually seen, not how
    bad the outcome would be. A verifier that read the callers and closed a
    link the agent could only guess at knows more about that than the agent
    did.

    This exists because the alternative was worse. When only downgrades were
    allowed, an agent that hedged at `low` on a real `pickle.loads` buried the
    finding permanently — nothing downstream could ever undo a cautious first
    impression.
    """
    if verdict == VERDICT_UNCERTAIN:
        # An unresolved chain is exactly what `low` confidence means, and it
        # keeps the finding visible without letting it block the merge.
        return "low"
    # Confirmed; refuted never reaches here.
    return agreed_confidence(votes, claimed)


def _verdict(votes: List[Vote], severity: str) -> str:
    """The majority rule, and the one place it is written down.

    `votes` is one entry per reserved seat. The counting below is over the
    votes that were actually cast, and the quorum at the end is over the seats,
    because those two questions have different right answers — see `_quorate`.
    """
    usable = [v for v in votes if not v.error]
    if not usable:
        # Being unable to check a claim is not evidence against it. What to
        # tell the reader about why is the caller's business; the claim itself
        # survives.
        return VERDICT_CONFIRMED

    verdict = _majority(usable, severity)
    if verdict != VERDICT_CONFIRMED and not _quorate(votes, usable):
        # The panel never met, so it has dismissed nothing. Both of the other
        # outcomes end with the finding not blocking — `refuted` removes it,
        # and `uncertain` forces confidence to `low`, which is under the gate —
        # so returning either one here would let two dead sessions ungate a
        # real finding through the single reply that survived.
        #
        # This is the same answer the no-usable-vote branch above gives, and
        # the same one `verify._decide` gives when every seat errored: a claim
        # nobody could check stands exactly as the reviewer left it. Without
        # this, three errored seats blocked the merge and two errored seats did
        # not, which is not a rule anybody could hold in their head.
        return VERDICT_CONFIRMED
    return verdict


def _quorate(votes: List[Vote], usable: List[Vote]) -> bool:
    """Did enough of the panel meet to decide anything against the claim?

    Half the reserved seats or more. `verify._votes_for` forces every panel
    odd, so for any panel this system can really build, half-or-more is a
    majority of the seats — one survivor out of three is not quorate, two are.

    A quorum rather than a plain seat-majority in each rule, because those two
    fail in opposite directions. Counting empty seats against a *refutation*
    protects the finding; counting them against a *confirmation* would mean a
    panel that lost a seat could no longer confirm, landing on `uncertain` —
    and `uncertain` is under the gate. So confirmation keeps the survivors as
    its denominator, refutation needs the panel to have met, and everything
    else in this module needs a majority of the seats outright.
    """
    return len(usable) * 2 >= len(votes)


def _majority(usable: List[Vote], severity: str) -> str:
    """What the verifiers that did answer add up to."""
    refuted = [v for v in usable if v.verdict == VERDICT_REFUTED]
    confirmed = [v for v in usable if v.verdict == VERDICT_CONFIRMED]

    # The derived severity, not the model's own label. Reading `finding.severity`
    # here quietly restored the dependence on a rated label that computing
    # severity from facts was introduced to remove — the label was the one part
    # that moved between identical runs.
    is_severe = severity_rank(severity) >= severity_rank("critical")
    if is_severe and len(usable) >= 2:
        # Unanimity to *discard* a critical — that is the whole asymmetry, and
        # it was written the other way round. Requiring unanimity to confirm
        # meant two verifiers confirming and one hedging gave `uncertain`,
        # which forces confidence to `low`, which is under the gate. The rule
        # meant to make a critical hard to dismiss made it easy to ungate.
        if len(refuted) == len(usable):
            return VERDICT_REFUTED
        if len(confirmed) * 2 > len(usable):
            return VERDICT_CONFIRMED
        return VERDICT_UNCERTAIN
    if len(refuted) * 2 > len(usable):
        return VERDICT_REFUTED
    if len(confirmed) * 2 > len(usable):
        # A majority, not unanimity. Requiring every verifier to agree made a
        # single hedge decide the gate: `uncertain` forces confidence to `low`,
        # `low` is under the threshold, and the merge went through with the
        # finding sitting in the report saying nothing had been settled.
        #
        # The asymmetry this replaces was written to protect findings — "it is
        # cheaper to be wrong toward a visible finding than an invisible one" —
        # and in gate terms it did the opposite, because a finding that does not
        # block is the invisible one. Unanimity is kept where it belongs, above,
        # for discarding a critical.
        return VERDICT_CONFIRMED
    return VERDICT_UNCERTAIN


def _corrected_facts(
    finding: Finding, votes: List[Vote]
) -> Tuple[str, str, str, List[str]]:
    """The three facts severity is computed from, after the panel corrects them.

    A correction needs a majority of the whole panel behind it — not merely
    agreement among those who spoke. Severity is computed from these facts, so
    a correction is a move on the gate, and the same rule applies to it as to
    every other move on the gate: one voice does not decide.

    `votes` is therefore every reserved seat, including the ones that errored.
    The sentence above was written before the code matched it: the denominator
    used to be the votes that came back, so with two of three sessions dead the
    survivor's proposal was "a majority" and moved the rating on its own.
    """
    facts = {
        "impact": finding.impact,
        "reachable": finding.reachable_without_authentication,
        "interaction": finding.requires_user_interaction,
    }
    changed = []
    for key, attr in (("impact", "corrected_impact"),
                      ("reachable", "corrected_reachable"),
                      ("interaction", "corrected_interaction")):
        # A majority of the panel, not "everyone who spoke up". One verifier
        # proposing a correction while the rest stay silent used to carry it —
        # and that verifier might be the one outvoted on whether the finding
        # was real at all. Severity is computed from these facts, so a single
        # proposal could move the finding across the gate on its own.
        proposed = [getattr(v, attr) for v in votes
                    if not v.error and getattr(v, attr)]
        agreed = {value for value in proposed if proposed.count(value) * 2 > len(votes)}
        if len(agreed) == 1 and facts[key] not in agreed:
            facts[key] = agreed.pop()
            changed.append(key)
    return facts["impact"], facts["reachable"], facts["interaction"], changed


def _rating(
    finding: Finding,
    impact: str,
    reachable: str,
    interaction: str,
    corrected: List[str],
    severity: str,
    severity_derivation: str,
) -> Tuple[str, str]:
    """Recompute severity from the corrected facts, or leave it where it was."""
    derived, why = derive(impact, reachable, interaction, finding.category)
    if not derived:
        return severity, severity_derivation
    return derived, why + (
        "; verifiers corrected {}".format(", ".join(corrected)) if corrected else "")


def agreed_confidence(votes: List[Vote], claimed: str) -> str:
    """What the panel, as a panel, thinks was actually seen.

    The **median** of the confirming verifiers, with silence counted as
    agreement with the claim. Two things changed here and both had the same
    cause.

    It used to take the minimum, and to take it over *every* usable vote rather
    than the confirming ones its own docstring named. So a verifier in the
    minority — outvoted on whether the finding was even real — still set the
    confidence for the whole panel by proposing `low`. Since `low` is under the
    gate, that one reply decided whether the merge was blocked, which is the
    single-verifier veto the majority rule above was written to remove.

    The old asymmetry was justified as erring toward a visible finding. In gate
    terms it did the opposite: a finding that does not block is the invisible
    one. A median errs toward what most of the panel saw, in both directions,
    and one outlier moves nothing.

    A seat whose session errored is silence too, and it is counted the same
    way: as agreement with the claim. Without it the median was taken over the
    survivors, so one verifier out of a three-seat panel that lost two sessions
    proposed `low` and the whole panel's confidence became `low` — under the
    gate, decided by a crash. `votes` is therefore every reserved seat.
    """
    confirming = [v for v in votes
                  if not v.error and v.verdict == VERDICT_CONFIRMED]
    if not confirming:
        return claimed
    empty_seats = sum(1 for v in votes if v.error)
    proposals = [v.corrected_confidence or claimed for v in confirming]
    proposals.extend([claimed] * empty_seats)
    return sorted(proposals, key=confidence_rank)[len(proposals) // 2]
