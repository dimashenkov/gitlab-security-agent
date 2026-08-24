"""Core value types shared across the agent.

`Finding` mirrors one item of ``prompts/findings.schema.json``. That file is the
single source of truth: it is loaded at runtime to build the `report_finding`
tool's schema, so the model is validated against it at the API layer rather than
after the fact. A field added here without a schema change will always be absent.

A `Finding` is only ever the model's *claim*. What survives citation checking and
adversarial verification is a `Candidate`, which carries the claim plus the
evidence for believing it. Only candidates gate the pipeline.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence

# Ordered weakest-to-strongest. Comparisons go through `severity_rank` /
# `confidence_rank` so an unrecognised value from a future schema revision sorts
# low instead of raising.
# A quoted line shorter than this is punctuation or a keyword, shared by
# most of the file, and identifies nothing.
MIN_ANCHOR_CHARS = 8

SEVERITY_ORDER: Sequence[str] = ("low", "medium", "high", "critical")
CONFIDENCE_ORDER: Sequence[str] = ("low", "medium", "high")

SEVERITY_EMOJI = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🔵",
}

# Verification verdicts.
VERDICT_CONFIRMED = "confirmed"
VERDICT_UNCERTAIN = "uncertain"
VERDICT_REFUTED = "refuted"


def severity_rank(severity: str) -> int:
    try:
        return SEVERITY_ORDER.index(severity)
    except ValueError:
        return -1


def confidence_rank(confidence: str) -> int:
    try:
        return CONFIDENCE_ORDER.index(confidence)
    except ValueError:
        return -1


@dataclass(frozen=True)
class Finding:
    """One claim from the agent, exactly as the schema defines it."""

    title: str
    severity: str
    confidence: str
    category: str
    file: str
    line: int
    impact: str
    reachable_without_authentication: str
    requires_user_interaction: str
    evidence: str
    description: str
    exploit_scenario: str
    recommendation: str

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Finding":
        return cls(
            title=str(data["title"]),
            severity=str(data["severity"]),
            confidence=str(data["confidence"]),
            category=str(data["category"]),
            file=str(data["file"]),
            line=int(data["line"]),
            impact=str(data.get("impact", "")),
            reachable_without_authentication=str(
                data.get("reachable_without_authentication", "unclear")),
            requires_user_interaction=str(data.get("requires_user_interaction", "unclear")),
            evidence=str(data["evidence"]),
            description=str(data["description"]),
            exploit_scenario=str(data["exploit_scenario"]),
            recommendation=str(data["recommendation"]),
        )

    @property
    def fingerprint(self) -> str:
        """Stable identity for suppression and comment de-duplication.

        Built from the category, the file, and the **first line of quoted
        code** — never from prose. The title was in here once, and measuring
        five runs over an identical diff produced five different fingerprints
        for the same weakness, because the model rewords a title every time
        ("Removal of '..' guard reintroduces…", "Reverted CVE-2023-41040
        fix…"). That silently broke the only escape hatch a blocking gate has:
        an accepted risk recorded in the ignore file would stop matching on the
        next run and block the merge again.

        Quoted code is the right anchor because layer 1 has already proved it
        exists in the file, and because it is the one part of a finding that
        describes the defect without describing it in words. Only the first
        line is used, so a run that quotes three lines and a run that quotes two
        still agree.

        Line numbers stay out: unrelated edits move code, and an accepted risk
        must survive that.
        """
        return self.fingerprints[0] if self.fingerprints else _digest(
            self.category, self.file, "")

    @property
    def anchors(self) -> List[str]:
        """Every quoted line, normalised — each one an identity for this finding.

        One anchor was not enough. Anchoring on the *first* quoted line assumed
        two runs quoting the same construct would start in the same place, and
        measurement says they do not: across four identical runs of one case,
        three quoted

            rows, err := s.db.QueryContext(r.Context(),

        and the fourth started a line later, at the `fmt.Sprintf` inside it. Same
        weakness, same file, same verdict, different fingerprint — and an
        accepted risk recorded from one run would have stopped matching on the
        next, which is the exact failure that moving off the title was meant to
        end.

        So identity is the whole set. Two findings are the same when any anchor
        is shared, which survives a run quoting one line more, one line fewer,
        or starting anywhere inside the same block.
        """
        seen, out = set(), []
        for line in self.evidence.splitlines():
            collapsed = " ".join(line.split()).lstrip("+- ")
            # Punctuation-only lines — a lone brace or paren — are shared by
            # half the file and would make unrelated findings look identical.
            if len(collapsed) >= MIN_ANCHOR_CHARS and collapsed not in seen:
                seen.add(collapsed)
                out.append(collapsed)
        return out

    @property
    def fingerprints(self) -> List[str]:
        """Every value this finding could legitimately be recorded under.

        The first is what gets printed and what a person copies into the ignore
        file; the rest exist so that a suppression written against one run still
        matches the next.
        """
        return [_digest(self.category, self.file, a) for a in self.anchors]


def _digest(category: str, file: str, anchor: str) -> str:
    return hashlib.sha256(
        "|".join((category, file, anchor)).encode("utf-8")).hexdigest()[:16]


@dataclass
class Vote:
    """One verifier's independent opinion on a finding."""

    verdict: str
    reasoning: str
    corrected_impact: str = ""
    corrected_reachable: str = ""
    corrected_interaction: str = ""
    corrected_confidence: str = ""
    removes_control: str = ""   # "yes" | "no" | "" when not asked
    error: str = ""
    # Which model actually answered this vote — a server-side fallback can
    # substitute one mid-review, and a blocking verdict should say so.
    served_models: List[str] = field(default_factory=list)

    @property
    def refutes(self) -> bool:
        return self.verdict == VERDICT_REFUTED


@dataclass
class Candidate:
    """A finding plus everything learned while checking whether to believe it."""

    finding: Finding

    # --- layer 1: citation checking, done at report time ---
    evidence_located_line: Optional[int] = None
    line_corrected_from: Optional[int] = None
    in_changed_lines: bool = True
    path_verified: bool = True
    # "added" when this change wrote the cited code, "deleted" when it removed
    # code where the weakness now sits, "" when the code predates the change.
    attributed_by: str = "added"

    # --- layer 2/3: adversarial verification ---
    votes: List[Vote] = field(default_factory=list)
    verdict: str = VERDICT_CONFIRMED
    verdict_reason: str = ""
    # Set when every verifier agrees the change removed a control that was
    # deliberately there. Gated on separately from severity: the question is not
    # "how bad is this" but "why is a guard someone added being taken away".
    removes_control: bool = False

    # --- final disposition ---
    severity: str = ""
    confidence: str = ""
    suppressed_by: str = ""
    # How `severity` was arrived at, for the report. A derived number nobody can
    # retrace is no better than a guessed one.
    severity_derivation: str = ""

    def __post_init__(self) -> None:
        if not self.severity:
            # Derived from the facts the model reported, not from the label it
            # proposed — that label was the one thing that moved between runs.
            from .severity import derive

            derived, why = derive(
                self.finding.impact,
                self.finding.reachable_without_authentication,
                self.finding.requires_user_interaction,
                self.finding.category,
            )
            self.severity = derived or self.finding.severity
            self.severity_derivation = why if derived else (
                "not derived ({}); using the reviewer's own rating".format(why))
        if not self.confidence:
            self.confidence = self.finding.confidence

    @property
    def line(self) -> int:
        """The line to cite: the located one when it disagrees with the claim."""
        if self.evidence_located_line:
            return self.evidence_located_line
        return self.finding.line

    @property
    def fingerprint(self) -> str:
        return self.finding.fingerprint

    @property
    def refuted(self) -> bool:
        return self.verdict == VERDICT_REFUTED

    @property
    def sort_key(self) -> tuple:
        return (
            -severity_rank(self.severity),
            -confidence_rank(self.confidence),
            self.finding.file,
            self.line,
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "fingerprint": self.fingerprint,
            "title": self.finding.title,
            "severity": self.severity,
            "confidence": self.confidence,
            "category": self.finding.category,
            "file": self.finding.file,
            "line": self.line,
            "impact": self.finding.impact,
            "reachable_without_authentication": self.finding.reachable_without_authentication,
            "requires_user_interaction": self.finding.requires_user_interaction,
            "severity_derivation": self.severity_derivation,
            "evidence": self.finding.evidence,
            "description": self.finding.description,
            "exploit_scenario": self.finding.exploit_scenario,
            "recommendation": self.finding.recommendation,
            "verification": {
                "verdict": self.verdict,
                "reason": self.verdict_reason,
                "votes": [
                    {
                        "verdict": v.verdict,
                        "reasoning": v.reasoning,
                        "corrected_impact": v.corrected_impact,
                        "corrected_confidence": v.corrected_confidence,
                        "error": v.error,
                    }
                    for v in self.votes
                ],
                "claimed_severity": self.finding.severity,
                "claimed_confidence": self.finding.confidence,
                "claimed_line": self.finding.line,
                "evidence_located_line": self.evidence_located_line,
                "line_corrected": self.line_corrected_from is not None,
                "introduced_by_this_change": self.in_changed_lines,
                "attributed_by": self.attributed_by,
                "removes_existing_control": self.removes_control,
                "path_verified": self.path_verified,
            },
            "suppressed_by": self.suppressed_by,
        }


@dataclass
class RejectedClaim:
    """A claim that never became a candidate, and why.

    Kept and reported: a run that quietly discards half of what the agent said
    is not auditable, and the rejection reasons are the main signal for whether
    the prompt or the tools need work.
    """

    title: str
    file: str
    reason: str
    detail: str = ""


@dataclass
class ToolCallRecord:
    """One tool invocation, kept for the audit trail in the job log and report."""

    turn: int
    name: str
    arguments: Dict[str, Any]
    summary: str
    is_error: bool = False


@dataclass
class Usage:
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    cache_write_tokens: int = 0
    requests: int = 0

    def add(self, usage: Any) -> None:
        self.requests += 1
        self.input_tokens += getattr(usage, "input_tokens", 0) or 0
        self.output_tokens += getattr(usage, "output_tokens", 0) or 0
        self.cache_read_tokens += getattr(usage, "cache_read_input_tokens", 0) or 0
        self.cache_write_tokens += getattr(usage, "cache_creation_input_tokens", 0) or 0

    def merge(self, other: "Usage") -> None:
        self.requests += other.requests
        self.input_tokens += other.input_tokens
        self.output_tokens += other.output_tokens
        self.cache_read_tokens += other.cache_read_tokens
        self.cache_write_tokens += other.cache_write_tokens

    def cost_usd(self, input_per_mtok: float, output_per_mtok: float) -> float:
        """Approximate spend. Cache writes bill ~1.25x input, reads ~0.1x."""
        return (
            self.input_tokens * input_per_mtok
            + self.cache_write_tokens * input_per_mtok * 1.25
            + self.cache_read_tokens * input_per_mtok * 0.1
            + self.output_tokens * output_per_mtok
        ) / 1_000_000

    def to_dict(self) -> Dict[str, int]:
        return {
            "requests": self.requests,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "cache_read_tokens": self.cache_read_tokens,
            "cache_write_tokens": self.cache_write_tokens,
        }


# Why the agent stopped. Only `completed` means the review reached a conclusion;
# every other value means the verdict is partial and must not be reported as a
# clean pass.
STOP_COMPLETED = "completed"
STOP_TURN_LIMIT = "turn_limit"
STOP_TIME_LIMIT = "time_limit"
STOP_BUDGET = "budget_exhausted"
STOP_REFUSAL = "refusal"
STOP_ERROR = "error"

INCOMPLETE_STOPS = (STOP_TURN_LIMIT, STOP_TIME_LIMIT, STOP_BUDGET, STOP_REFUSAL, STOP_ERROR)

STOP_EXPLANATIONS = {
    STOP_TURN_LIMIT: "the agent hit its turn limit before finishing the review",
    STOP_TIME_LIMIT: "the agent hit its time limit before finishing the review",
    STOP_BUDGET: "the agent exhausted its token budget before finishing the review",
    STOP_REFUSAL: "the model declined to continue the review",
    STOP_ERROR: "the review ended with an error",
}


@dataclass
class StageMetrics:
    """What each stage did, so its value can be argued about with numbers.

    The open question this exists to answer is whether adversarial verification
    earns roughly three times the cost of the review itself. That cannot be
    settled by opinion, and it cannot be settled after the fact from a report
    that only shows what survived — it needs counts of what each stage saw,
    rejected, and changed.
    """

    # Layer 1, inside report_finding.
    citations_accepted: int = 0
    citations_rejected_unknown_path: int = 0
    citations_rejected_not_found: int = 0
    citations_rejected_ambiguous: int = 0
    citations_rejected_too_short: int = 0
    lines_corrected: int = 0

    # Layers 2 and 3.
    verified: int = 0
    verification_skipped: int = 0
    verification_failed: int = 0

    # The number that decides whether verification is worth its cost: findings
    # whose gate disposition it actually changed.
    verdicts_changed: int = 0

    def note_citation_rejection(self, reason: str) -> None:
        if "does not appear" in reason:
            self.citations_rejected_not_found += 1
        elif "appears" in reason and "times" in reason:
            self.citations_rejected_ambiguous += 1
        elif "too short" in reason:
            self.citations_rejected_too_short += 1
        else:
            self.citations_rejected_unknown_path += 1

    def to_dict(self) -> Dict[str, Any]:
        return {
            "citations": {
                "accepted": self.citations_accepted,
                "rejected_unknown_path": self.citations_rejected_unknown_path,
                "rejected_not_found": self.citations_rejected_not_found,
                "rejected_ambiguous": self.citations_rejected_ambiguous,
                "rejected_too_short": self.citations_rejected_too_short,
                "lines_corrected": self.lines_corrected,
            },
            "verification": {
                "verified": self.verified,
                "skipped": self.verification_skipped,
                "failed": self.verification_failed,
                "verdicts_changed": self.verdicts_changed,
            },
        }


@dataclass
class Coverage:
    """Which changed files were actually looked at.

    "The model stopped calling tools" is not a completion criterion — it records
    that the agent decided it was done, which is the thing under question. This
    is the deterministic answer: every file in the change is accounted for as
    examined, excluded by configuration, or neither.

    Neither is the interesting column. It is not necessarily wrong — an agent
    that reads a diff and judges a rename uninteresting has covered it — but it
    is the difference between a review and a glance, and it belongs in the report
    rather than in nobody's head.
    """

    changed: List[str] = field(default_factory=list)
    examined: List[str] = field(default_factory=list)
    excluded: List[str] = field(default_factory=list)

    @property
    def unopened(self) -> List[str]:
        """Changed files the agent never opened."""
        seen = set(self.examined)
        return [path for path in self.changed if path not in seen]

    @property
    def complete(self) -> bool:
        return not self.unopened

    def to_dict(self) -> Dict[str, Any]:
        return {
            "changed": self.changed,
            "examined": sorted(self.examined),
            "excluded": self.excluded,
            "unopened": self.unopened,
            "complete": self.complete,
        }


@dataclass
class Provenance:
    """What actually produced this verdict.

    A blocking gate has to be reproducible enough to argue with. Without this,
    "the same code passed last week" has no answer: the model may have been
    swapped by a server-side fallback mid-review, a prompt may have been edited,
    or the finding schema may have changed shape. Each of those changes the
    verdict and none of them shows up in a diff.
    """

    model_requested: str = ""
    models_served: List[str] = field(default_factory=list)
    system_prompt_sha: str = ""
    verifier_prompt_sha: str = ""
    schema_sha: str = ""
    agent_version: str = ""

    def note_served(self, model: str) -> None:
        if model and model not in self.models_served:
            self.models_served.append(model)

    @property
    def model_substituted(self) -> bool:
        """Did anything other than the requested model answer?"""
        return any(m != self.model_requested for m in self.models_served)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "model_requested": self.model_requested,
            "models_served": self.models_served,
            "model_substituted": self.model_substituted,
            "system_prompt_sha": self.system_prompt_sha,
            "verifier_prompt_sha": self.verifier_prompt_sha,
            "schema_sha": self.schema_sha,
            "agent_version": self.agent_version,
        }


@dataclass
class ScanOutcome:
    """Everything the gating, reporting, and comment layers need."""

    mode: str
    stop_reason: str = STOP_COMPLETED
    stop_detail: str = ""
    summary: str = ""
    turns: int = 0
    model: str = ""

    # Everything the agent claimed, partitioned by what happened to it. A
    # candidate appears in exactly one list, and all four are shown in the
    # report — dropping something from the gate never means hiding it.
    reported: List[Candidate] = field(default_factory=list)
    refuted: List[Candidate] = field(default_factory=list)
    suppressed: List[Candidate] = field(default_factory=list)
    rejected_claims: List[RejectedClaim] = field(default_factory=list)
    duplicates_dropped: int = 0

    tool_calls: List[ToolCallRecord] = field(default_factory=list)
    files_examined: List[str] = field(default_factory=list)
    usage: Usage = field(default_factory=Usage)
    verification_usage: Usage = field(default_factory=Usage)
    provenance: Provenance = field(default_factory=Provenance)
    coverage: Coverage = field(default_factory=Coverage)
    metrics: StageMetrics = field(default_factory=StageMetrics)

    @property
    def complete(self) -> bool:
        return self.stop_reason == STOP_COMPLETED

    @property
    def all_candidates(self) -> List[Candidate]:
        return self.reported + self.suppressed + self.refuted

    def total_usage(self) -> Usage:
        total = Usage()
        total.merge(self.usage)
        total.merge(self.verification_usage)
        return total

    def counts_by_severity(self) -> Dict[str, int]:
        counts = {level: 0 for level in SEVERITY_ORDER}
        for candidate in self.reported:
            if candidate.severity in counts:
                counts[candidate.severity] += 1
        return counts

    def worst_severity(self) -> Optional[str]:
        if not self.reported:
            return None
        return max(self.reported, key=lambda c: severity_rank(c.severity)).severity
