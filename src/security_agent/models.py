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
# Cache pricing, in multiples of the input rate. One definition, here, because
# there were three — two of them wrong — and a constant copied into a tool is a
# constant nobody updates when the rate changes.
CACHE_READ_MULTIPLIER = 0.1
CACHE_WRITE_MULTIPLIERS = {"5m": 1.25, "1h": 2.0}


def cache_write_multiplier(cache_ttl: str) -> float:
    """What a cache write costs, as a multiple of the input rate.

    An unrecognised TTL takes the higher rate. Overstating a cost prompts a
    question; understating one is believed.
    """
    return CACHE_WRITE_MULTIPLIERS.get(cache_ttl, max(CACHE_WRITE_MULTIPLIERS.values()))


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


def _normalise(value: str) -> str:
    """Case and whitespace only. `"High"` and `"high"` are the same word.

    The schema constrains these server-side, and `_parse_verdict` has a
    hand-rolled fallback for exactly the case where that constraint did not
    hold — so a value arriving with a capital letter is a real path, and it
    used to become rank -1.
    """
    return (value or "").strip().lower()


def severity_rank(severity: str) -> int:
    """Position in the order, or -1 for a value nobody recognises.

    The -1 is safe for *sorting* — an unknown value goes to one end and stays
    there. It was read as a *threshold* comparison in the gate, where `-1 <
    anything` meant an unrecognised severity was quietly treated as less severe
    than `low` and stopped blocking. One sentinel, two callers, opposite safe
    directions. The gate now asks `recognised()` first.
    """
    try:
        return SEVERITY_ORDER.index(_normalise(severity))
    except ValueError:
        return -1


def confidence_rank(confidence: str) -> int:
    try:
        return CONFIDENCE_ORDER.index(_normalise(confidence))
    except ValueError:
        return -1


def recognised(value: str, order: Sequence[str]) -> bool:
    """Is this a word the project knows?

    Separate from the rank so a caller has to decide what an unknown value
    means rather than inheriting -1's arithmetic. For the gate it means "this
    cannot be the reason a finding does not block".
    """
    return _normalise(value) in order


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
            if collapsed and collapsed not in seen and _distinctive(collapsed):
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


# Lines that carry no identity. Length alone is not the test — `if err != nil {`
# is fifteen characters and appears in every function of a Go file, so matching
# on it would let an accepted risk silence an unrelated finding in the same file
# and category. What matters is whether the line says anything specific to *this*
# code: a name, a call, a literal.
_BOILERPLATE = frozenset({
    "if err != nil {", "} else {", "end", "});", "})", "}", "{", ");", ")",
    "return", "return nil", "return err", "return nil, err", "return false",
    "return true", "return result", "return None", "pass", "continue", "break",
    "catch (Exception e) {", "try {", "try:", "except:", "finally {",
    "public:", "private:", "else:", "else", "do", "begin", "rescue", "ensure",
})


def _distinctive(line: str) -> bool:
    """Is this line specific enough to identify one finding?

    An anchor is used to decide whether an accepted risk still applies. A line
    shared by half the file would make that decision wrongly and silently, in
    the direction that hides a finding — so a line has to carry a name, a call
    or a literal, not just structure.
    """
    if len(line) < MIN_ANCHOR_CHARS or line in _BOILERPLATE:
        return False
    # Something that looks like an identifier of its own, or a literal. A line
    # made only of keywords, punctuation and short tokens describes control
    # flow that appears everywhere.
    words = [w.strip("(),;:{}[]&*") for w in line.replace(".", " ").split()]
    return any(len(w) >= 4 for w in words if w not in _KEYWORDS) or (
        '"' in line or "'" in line)


_KEYWORDS = frozenset({
    "func", "def", "return", "if", "else", "elif", "for", "while", "case",
    "switch", "try", "catch", "except", "finally", "class", "struct", "type",
    "const", "var", "let", "public", "private", "static", "void", "int",
    "bool", "string", "true", "false", "null", "nil", "none", "self", "this",
    "and", "or", "not", "end", "then", "begin", "rescue", "ensure", "do",
})


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
    # The two links a confirmation rests on, stated rather than implied.
    # A verifier confirmed that a discarded 404 let unvalidated actions run,
    # without ever opening the caller — which validates with the identical
    # predicate on the identical object first. The instruction to read callers
    # was already in both prompts and had been for weeks; prose did not fix it,
    # so the verdict now has to carry the evidence or it is not a confirmation.
    control_search: str = ""    # what guard was looked for, where, and found
    entry_point: str = ""       # the caller or entry an attacker comes through
    # Which files this verifier actually opened, and — separately — every file
    # whose bytes reached it through any channel. The second is the one that
    # answers "was the payload seen": a whole-change `get_diff` carries every
    # changed file without opening any of them, and `search_code` returns lines
    # from files nobody named. Reading exposure off the opened list would
    # answer "no" while the text sat in the context window, which is the
    # difference between a verifier that resisted and one that was never tried.
    files_read: List[str] = field(default_factory=list)
    exposures: List[tuple] = field(default_factory=list)   # (path, channel)
    error: str = ""
    # How the verdict arrived: `submit_verdict` (an argument the verifier
    # deliberately submitted) or `final_message` (a schema-constrained reply).
    # Both are valid and they are not equally strong — the first is also the
    # verifier saying it is finished, where the second is inferred from the
    # conversation ending. Recorded so the artifact does not have to pretend
    # they are the same event.
    channel: str = ""
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
            #
            # Through `panel` rather than straight to the table, because the
            # document loader has to reconstruct exactly this starting point to
            # check a recorded disposition against the rule that produced it. A
            # second copy of these four lines is a second answer to "what was
            # this rated before anyone verified it".
            from .panel import initial_rating

            self.severity, self.severity_derivation = initial_rating(self.finding)
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

    def cost_usd(self, input_per_mtok: float, output_per_mtok: float,
                 cache_ttl: str = "1h") -> float:
        """Approximate spend, at the cache rate this run actually pays.

        The write multiplier depends on the cache TTL, and this took the
        five-minute rate while the agent runs with a one-hour TTL — so every
        cost this reported, in the merge request comment and the job log alike,
        was low. It is a small number on a page of larger ones, which is
        precisely why nobody checked it for two weeks.
        """
        return (
            self.input_tokens * input_per_mtok
            + self.cache_write_tokens * input_per_mtok * cache_write_multiplier(cache_ttl)
            + self.cache_read_tokens * input_per_mtok * CACHE_READ_MULTIPLIER
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
# Three reasons that were one. `error` used to hold everything from "the
# conversation outgrew the context window" to "the network was down", and a
# review that stopped early could not be diagnosed from its own artifact —
# the only field separating them was `stop_detail`, which no consumer kept.
# Diagnosing four incomplete runs afterwards cost a day and still ended in
# "one of these two, cannot tell from the code".
STOP_CONTEXT = "context_exhausted"
STOP_RESPONSE_TOO_LONG = "response_too_long"
STOP_TRANSPORT = "transport_error"
STOP_ERROR = "error"

INCOMPLETE_STOPS = (
    STOP_TURN_LIMIT, STOP_TIME_LIMIT, STOP_BUDGET, STOP_REFUSAL,
    STOP_CONTEXT, STOP_RESPONSE_TOO_LONG, STOP_TRANSPORT, STOP_ERROR,
)

STOP_EXPLANATIONS = {
    STOP_TURN_LIMIT: "the agent hit its turn limit before finishing the review",
    STOP_TIME_LIMIT: "the agent hit its time limit before finishing the review",
    STOP_BUDGET: "the agent exhausted its token budget before finishing the review",
    STOP_REFUSAL: "the model declined to continue the review",
    STOP_CONTEXT: (
        "the conversation outgrew the model's context window — the review read "
        "more than it could hold"
    ),
    STOP_RESPONSE_TOO_LONG: "a single response hit the per-response token limit",
    STOP_TRANSPORT: "the Claude API could not be reached",
    STOP_ERROR: "the review ended with an error",
}


@dataclass
class TurnRecord:
    """One request to the model, and what came back.

    Aggregate usage says what a review cost and nothing about where it went.
    When four reviews stopped early, the question "which turn, holding how
    much, asking for how much room" had no answer in the artifact — the
    diagnosis had to be rebuilt from the source and ended in "one of two,
    cannot tell". Per-turn is the granularity that answers it, and it is a few
    hundred bytes.
    """

    turn: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    cache_write_tokens: int = 0
    # What the request asked for, which the retry changes mid-review.
    max_tokens: int = 0
    stop_reason: str = ""
    # True when this turn is a replay of one that came back truncated. Its
    # tokens were charged and its work was thrown away, so a review with
    # replays costs more than its turn count suggests.
    replay: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "turn": self.turn,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "cache_read_tokens": self.cache_read_tokens,
            "cache_write_tokens": self.cache_write_tokens,
            "max_tokens": self.max_tokens,
            "stop_reason": self.stop_reason,
            "replay": self.replay,
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
    # Changed files a `--path` scope left out. Distinct from `excluded`, which
    # is policy applied to every run; this is one operator asking for less on
    # one run, and a reader needs to know which of the two happened.
    out_of_scope: List[str] = field(default_factory=list)

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
            "out_of_scope": self.out_of_scope,
            "unopened": self.unopened,
            "complete": self.complete,
        }


@dataclass
class Revision:
    """Which commits were actually read.

    A finding is a claim about code at a moment. Without the moment it cannot
    be checked: `HEAD` and `main` name different commits on different days, and
    an archived artifact saying it reviewed `HEAD` says nothing at all. The
    accepted-risk file is matched against findings, so an entry accepted
    against one revision has to be traceable to it.

    Both forms are kept. The symbolic one is what the operator configured and
    is what appears in a pipeline definition; the resolved SHA is the only part
    that identifies a commit.
    """

    mode: str = ""
    base: str = ""
    head: str = ""
    base_sha: str = ""
    head_sha: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "mode": self.mode,
            "base": self.base,
            "head": self.head,
            "base_sha": self.base_sha,
            "head_sha": self.head_sha,
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
    revision: Revision = field(default_factory=Revision)
    turn_records: List[TurnRecord] = field(default_factory=list)
    coverage: Coverage = field(default_factory=Coverage)
    metrics: StageMetrics = field(default_factory=StageMetrics)

    # Did the reviewer say it was done, or did it merely stop? With the
    # Messages API those are close: `end_turn` is the model choosing to stop. A
    # provider that runs its own loop offers no such distinction — its process
    # exits zero either way — so completion becomes something the reviewer
    # states through `finish_review`, and both runners read the same statement.
    #
    # Recorded rather than gated, for now. Making it a failure today would fail
    # runs that are fine; the point is to have the rate from real reviews
    # before tightening it.
    finished_explicitly: bool = False
    # Questions the reviewer could not settle, in its own words. "I could not
    # tell" is a real answer and this is where it goes; without somewhere to
    # put it, a gap becomes silence.
    unresolved: List[str] = field(default_factory=list)

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
