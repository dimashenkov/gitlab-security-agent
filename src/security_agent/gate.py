"""Turning a set of findings into a pipeline verdict.

Kept separate from reporting on purpose: what gets *shown* and what gets
*blocked* are different decisions, and conflating them produces a gate that
either hides findings it will not block on, or blocks on everything it shows.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List

from .config import Config
from .models import (
    CONFIDENCE_ORDER,
    SEVERITY_ORDER,
    STOP_EXPLANATIONS,
    STOP_INCONCLUSIVE,
    Candidate,
    ScanOutcome,
    confidence_rank,
    recognised,
    severity_rank,
)

# Exit codes. 1 means "the code has a problem", 2 means "the check itself did
# not run properly" — a distinction worth keeping, because the first is the
# author's to fix and the second is the pipeline owner's.
EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2


@dataclass
class Decision:
    exit_code: int
    reason: str
    blocking: List[Candidate] = field(default_factory=list)
    non_blocking_reasons: List[str] = field(default_factory=list)
    # Findings that would otherwise have been judged on their merits but belong
    # to a category this project does not gate on. Carried on the decision so
    # the report can mark them individually: a high-severity finding sitting
    # under a green pipeline needs to say which setting let it through, next to
    # the finding, not in a footnote.
    policy_excluded: List[Candidate] = field(default_factory=list)

    @property
    def blocked(self) -> bool:
        return self.exit_code != EXIT_OK


def blocking_findings(cfg: Config, outcome: ScanOutcome) -> List[Candidate]:
    """Which reported findings actually stop the merge.

    A finding blocks when it is severe enough, confident enough, and the change
    under review is responsible for it. Everything filtered out here still
    appears in the report — it is excluded from the gate, not from view.
    """
    threshold = cfg.fail_threshold
    if threshold is None:
        return []

    minimum_severity = severity_rank(threshold)
    minimum_confidence = confidence_rank(cfg.min_confidence)

    ungated = {c.lower() for c in cfg.ungated_categories}

    blocking = []
    for candidate in outcome.reported:
        if not candidate.in_changed_lines and not cfg.gate_pre_existing:
            continue

        # A category the project has decided not to gate on takes precedence
        # over every rule below, including the removed-control one. A team that
        # has ruled out a whole class of weakness has ruled out guards for that
        # class too, and a knob with an unstated exception is worse than one
        # that does exactly what its name says. The finding is still reported in
        # full; only its power to stop the merge is withheld.
        if candidate.finding.category.lower() in ungated:
            continue

        # A change that deletes a security control blocks on that alone. The
        # question there is not how bad the resulting weakness scores but why a
        # guard someone deliberately added is being taken away, and that belongs
        # to the author of the change rather than to a severity scale. Measured:
        # a merge request reverting the fix for CVE-2023-41040 was found and
        # confirmed on five runs out of five and blocked on none of them,
        # because three independent reads agreed it rated below the threshold.
        if candidate.removes_control and cfg.gate_removed_controls:
            blocking.append(candidate)
            continue

        # A value nobody recognises is not a value below the threshold. Both
        # ranks return -1 for an unknown word, and `-1 < minimum` was letting a
        # `confidence` of "High" — one capital letter — carry a `critical`
        # finding past the gate: rendered as CRITICAL in the report, absent
        # from `blocking_fingerprints`, exit 0. `recognised()` is asked first,
        # so an unparseable rating fails toward blocking and says so, rather
        # than silently passing.
        if recognised(candidate.severity, SEVERITY_ORDER) and (
                severity_rank(candidate.severity) < minimum_severity):
            continue
        if recognised(candidate.confidence, CONFIDENCE_ORDER) and (
                confidence_rank(candidate.confidence) < minimum_confidence):
            continue
        blocking.append(candidate)
    return blocking


def policy_excluded(cfg: Config, outcome: ScanOutcome) -> List[Candidate]:
    """Reported findings whose category this project has chosen not to gate on."""
    ungated = {c.lower() for c in cfg.ungated_categories}
    if not ungated:
        return []
    return [c for c in outcome.reported if c.finding.category.lower() in ungated]


# Endings `fail_on_incomplete` may not override. One entry, and the reason it is
# a set rather than an `if` is that the next one will be added by somebody who
# finds this line rather than by somebody who remembers the rule.
NEVER_FORGIVEN = frozenset({STOP_INCONCLUSIVE})


def _reviewed_nothing(outcome: ScanOutcome) -> bool:
    """Did this run open no part of the change at all?

    The difference between a review that stopped early and a review that never
    started, which `fail_on_incomplete` was treating as one thing.

    That flag is a policy about *partial* coverage: the agent read six of ten
    files, the operator knows which six, and letting the pipeline through while
    the limits are tuned is their call about their own risk. It says so, and
    that reasoning is sound for every ending where work happened — a turn
    limit, a budget that ran out mid-search, a truncated diff.

    It is not sound when nothing happened. The CLI failing to start, the MCP
    server never coming up, a terminal object that will not parse: there is no
    partial coverage to weigh, and "no blocking findings" over a review that
    opened no file is the sentence this whole product exists to prevent. Six of
    the eight ways the local runner can fail reached exit 0 through that flag.

    Read from coverage accounting rather than from the stop reason, because a
    set of stop reasons can only be right about the endings somebody thought to
    add to it — and this repository has now been caught four times by a check
    that knew a list of spellings. Whether a file was opened is a fact about
    the run, and it stays true for endings nobody has invented yet.

    Three signs of work, not one. A file opened is the obvious one; a tool call
    covers listing the change or searching for a caller, which is a review
    doing its job without having opened anything yet; and a reported finding is
    the strongest of all, because nothing can report a weakness in code it did
    not read. A rule resting on the first alone would have called a truncated
    review with findings in it absent, and a rule that fires on real work is a
    rule that gets switched off.
    """
    return not (outcome.coverage.examined or outcome.tool_calls
                or outcome.reported)


def _partial(outcome: ScanOutcome) -> bool:
    """Did this run fail to cover the change it claims to have reviewed?

    Two ways, and until now only one of them reached here. The agent can stop
    early — that is `stop_reason`. Or the change can be larger than the diff the
    reviewer is shown: `Workspace._bounded` cuts at a ceiling and records it,
    and everything after the cut was never put in front of the model. The run
    then ends `completed`, the coverage accounting says every changed file was
    accounted for, and the gate exits 0 — "checked and clean" over the first
    part of a change. That is the failure this product exists to prevent, and
    the only thing standing in front of it was a warning in the report.

    Read from `coverage.diff_truncated` rather than from the notice appended to
    the diff, because the notice is text in the model's context and an author
    can write the same sentence into a file. The flag is accounting.

    It is deliberately *not* in `NEVER_FORGIVEN`. A profile that cannot conclude
    is a property of the configuration and no run of it means anything; a
    truncated diff is a property of one change, and the operator has real moves
    — split the change, narrow the review with `--path`, or raise
    `SECURITY_SCAN_DIFF_CEILING_BYTES`. That last one was named here
    before it existed, which made the remedy a sentence rather than a
    move; a reader told to do something they cannot do is a reader who
    stops reading. A
    ceiling nobody can get past would make a large legitimate change permanently
    unmergeable, and a gate that cannot be satisfied gets deleted rather than
    obeyed. So it fails loudly by default and stays forgivable by the same
    documented flag as every other partial review.
    """
    return not outcome.complete or outcome.coverage.diff_truncated


def _why_partial(outcome: ScanOutcome) -> str:
    """The sentence naming which of the two happened, for the author to act on.

    Truncation is named separately because the remedy is different: nothing
    about turn limits tells anyone to split a merge request.
    """
    if not outcome.complete:
        return STOP_EXPLANATIONS.get(outcome.stop_reason, "the review did not complete")
    return (
        "the change was larger than the reviewer can be shown, so it read the "
        "first part of the diff and no more. Split the change, or narrow the "
        "review with --path, for a complete reading")


def decide(cfg: Config, outcome: ScanOutcome) -> Decision:
    """The pipeline verdict for this run."""
    # An incomplete review has no opinion worth acting on. Reporting "no
    # blocking findings" after the agent ran out of turns would be the single
    # most damaging thing this tool could do, because it looks exactly like a
    # pass.
    # Some endings are not the operator's to forgive.
    #
    # `SECURITY_SCAN_FAIL_ON_INCOMPLETE=false` exists so a team can let a
    # truncated review through while they tune the limits — a policy choice
    # about *their* risk. `probe` is not that. It is six turns and no verifiers,
    # sized to stop early, and it says of itself that it cannot conclude. A flag
    # meaning "accept partial reviews" turning that into exit 0 would let a
    # profile documented as never conclusive hand out clean passes.
    if outcome.stop_reason in NEVER_FORGIVEN:
        return Decision(
            exit_code=EXIT_ERROR,
            reason=(
                "{}. No setting makes this a pass: it is a property of the "
                "profile, not a policy about partial reviews.".format(
                    STOP_EXPLANATIONS.get(outcome.stop_reason,
                                          "the review could not conclude"))),
        )

    if _partial(outcome) and _reviewed_nothing(outcome):
        explanation = _why_partial(outcome)
        detail = " ({})".format(outcome.stop_detail) if outcome.stop_detail else ""
        return Decision(
            exit_code=EXIT_ERROR,
            reason=(
                "{}{}, and it opened no part of the change. That is not a "
                "partial review to weigh — it is an absent one, and no setting "
                "makes it a pass.".format(explanation, detail)),
        )

    if _partial(outcome) and cfg.fail_on_incomplete:
        explanation = _why_partial(outcome)
        detail = " ({})".format(outcome.stop_detail) if outcome.stop_detail else ""
        return Decision(
            exit_code=EXIT_ERROR,
            reason=(
                "Review incomplete — {}{}. The result cannot be treated as a "
                "pass. Set SECURITY_SCAN_FAIL_ON_INCOMPLETE=false to allow "
                "partial reviews through.".format(explanation, detail)
            ),
        )

    blocking = blocking_findings(cfg, outcome)
    notes = _non_blocking_notes(cfg, outcome, blocking)
    excluded = policy_excluded(cfg, outcome)

    if blocking:
        # Two different rules can block, and the message has to name the one
        # that actually applied. A finding stopped for deleting a guard is
        # often below the severity threshold, and telling its author it was
        # "at or above the threshold" sends them to argue with the wrong number.
        removed = [c for c in blocking if c.removes_control]
        rated = [c for c in blocking if not c.removes_control]

        parts = []
        if removed:
            parts.append(
                "{} finding(s) where this change removes an existing security "
                "control ({})".format(len(removed), _levels(removed))
            )
        if rated:
            parts.append(
                "{} finding(s) at or above the {} threshold with at least {} "
                "confidence ({})".format(
                    len(rated), cfg.fail_on, cfg.min_confidence, _levels(rated))
            )

        return Decision(
            exit_code=EXIT_FINDINGS,
            reason="; ".join(parts) + ".",
            blocking=blocking,
            non_blocking_reasons=notes,
            policy_excluded=excluded,
        )

    if _partial(outcome):
        # Named even when it is forgiven. "Coverage is partial" is the whole
        # difference between this exit 0 and a clean one, and the sentence
        # carries which of the two produced it.
        why = "the change was too large to be shown in full"
        if not outcome.complete:
            why = outcome.stop_detail or outcome.stop_reason
        return Decision(
            exit_code=EXIT_OK,
            reason=(
                "No blocking findings, but the review did not complete ({}). "
                "Coverage is partial.".format(why)
            ),
            non_blocking_reasons=notes,
            policy_excluded=excluded,
        )

    if outcome.reported:
        return Decision(
            exit_code=EXIT_OK,
            reason="{} finding(s) reported, none at or above the {} threshold.".format(
                len(outcome.reported), cfg.fail_on),
            non_blocking_reasons=notes,
            policy_excluded=excluded,
        )

    return Decision(
        exit_code=EXIT_OK,
        reason="No security findings.",
        non_blocking_reasons=notes,
    )


def _levels(candidates: List[Candidate]) -> str:
    counts = {}
    for candidate in candidates:
        counts[candidate.severity] = counts.get(candidate.severity, 0) + 1
    return ", ".join(
        "{} {}".format(count, level)
        for level, count in sorted(counts.items(), key=lambda kv: -severity_rank(kv[0]))
    )


def _non_blocking_notes(
    cfg: Config, outcome: ScanOutcome, blocking: List[Candidate]
) -> List[str]:
    """Say out loud what was found but deliberately not gated on.

    Without this, a report showing four findings and a green pipeline reads as a
    bug rather than as policy.
    """
    notes: List[str] = []
    blocked_ids = {id(c) for c in blocking}
    withheld = [c for c in outcome.reported if id(c) not in blocked_ids]

    # Each withheld finding is attributed to one reason, not to every rule that
    # would independently have withheld it. A low-severity finding in an
    # excluded category counted under both headings makes four findings look
    # like seven, and a reader who notices the arithmetic stops trusting the
    # rest of the numbers. Policy exclusion is decided first, so it wins.
    ungated_names = {c.lower() for c in cfg.ungated_categories}
    withheld_by_policy = [
        c for c in withheld if c.finding.category.lower() in ungated_names]
    withheld = [
        c for c in withheld if c.finding.category.lower() not in ungated_names]

    if cfg.fail_threshold is None:
        if outcome.reported:
            notes.append(
                "{} finding(s) reported but SECURITY_SCAN_FAIL_ON=none, so "
                "nothing blocks the merge.".format(len(outcome.reported))
            )
        return notes

    low_severity = sum(
        1 for c in withheld
        if severity_rank(c.severity) < severity_rank(cfg.fail_on)
    )
    low_confidence = sum(
        1 for c in withheld
        if severity_rank(c.severity) >= severity_rank(cfg.fail_on)
        and confidence_rank(c.confidence) < confidence_rank(cfg.min_confidence)
    )
    pre_existing = sum(
        1 for c in withheld
        if not c.in_changed_lines
        and severity_rank(c.severity) >= severity_rank(cfg.fail_on)
        and confidence_rank(c.confidence) >= confidence_rank(cfg.min_confidence)
    )

    by_policy: dict = {}
    for candidate in withheld_by_policy:
        name = candidate.finding.category.lower()
        by_policy[name] = by_policy.get(name, 0) + 1
    if by_policy:
        # Named per category rather than totalled: "3 not gated" invites the
        # reader to assume a bug, where "3 in denial_of_service" points at the
        # setting that produced it.
        notes.append(
            "{} in categor{} excluded by SECURITY_SCAN_UNGATED_CATEGORIES ({})".format(
                sum(by_policy.values()), "y" if len(by_policy) == 1 else "ies",
                ", ".join(sorted(by_policy))))

    if low_severity:
        notes.append("{} below the {} severity threshold".format(low_severity, cfg.fail_on))
    if low_confidence:
        notes.append(
            "{} below {} confidence (including any downgraded during "
            "verification)".format(low_confidence, cfg.min_confidence)
        )
    if pre_existing and not cfg.gate_pre_existing:
        notes.append(
            "{} pre-existing, not introduced by this change (set "
            "SECURITY_SCAN_GATE_PRE_EXISTING=true to gate on these)".format(pre_existing)
        )
    if outcome.refuted:
        notes.append("{} refuted during verification".format(len(outcome.refuted)))
    if outcome.suppressed:
        notes.append(
            "{} suppressed by {}".format(len(outcome.suppressed), cfg.ignore_file)
        )
    return notes
