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
    STOP_EXPLANATIONS,
    Candidate,
    ScanOutcome,
    confidence_rank,
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

    blocking = []
    for candidate in outcome.reported:
        if not candidate.in_changed_lines and not cfg.gate_pre_existing:
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

        if severity_rank(candidate.severity) < minimum_severity:
            continue
        if confidence_rank(candidate.confidence) < minimum_confidence:
            continue
        blocking.append(candidate)
    return blocking


def decide(cfg: Config, outcome: ScanOutcome) -> Decision:
    """The pipeline verdict for this run."""
    # An incomplete review has no opinion worth acting on. Reporting "no
    # blocking findings" after the agent ran out of turns would be the single
    # most damaging thing this tool could do, because it looks exactly like a
    # pass.
    if not outcome.complete and cfg.fail_on_incomplete:
        explanation = STOP_EXPLANATIONS.get(outcome.stop_reason, "the review did not complete")
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

    if blocking:
        counts = {}
        for candidate in blocking:
            counts[candidate.severity] = counts.get(candidate.severity, 0) + 1
        summary = ", ".join(
            "{} {}".format(count, level)
            for level, count in sorted(
                counts.items(), key=lambda kv: -severity_rank(kv[0]))
        )
        return Decision(
            exit_code=EXIT_FINDINGS,
            reason=(
                "{} finding(s) at or above the {} threshold with at least {} "
                "confidence: {}.".format(
                    len(blocking), cfg.fail_on, cfg.min_confidence, summary)
            ),
            blocking=blocking,
            non_blocking_reasons=notes,
        )

    if not outcome.complete:
        return Decision(
            exit_code=EXIT_OK,
            reason=(
                "No blocking findings, but the review did not complete ({}). "
                "Coverage is partial.".format(outcome.stop_detail or outcome.stop_reason)
            ),
            non_blocking_reasons=notes,
        )

    if outcome.reported:
        return Decision(
            exit_code=EXIT_OK,
            reason="{} finding(s) reported, none at or above the {} threshold.".format(
                len(outcome.reported), cfg.fail_on),
            non_blocking_reasons=notes,
        )

    return Decision(
        exit_code=EXIT_OK,
        reason="No security findings.",
        non_blocking_reasons=notes,
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
