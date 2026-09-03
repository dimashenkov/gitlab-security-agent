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
import math
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

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
        return self.fingerprints[0]

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
        for collapsed in quoted_lines(self.evidence):
            if collapsed not in seen and distinctive(collapsed):
                seen.add(collapsed)
                out.append(collapsed)
        return out

    @property
    def fingerprints(self) -> List[str]:
        """Every value this finding could legitimately be recorded under.

        The first is what gets printed and what a person copies into the ignore
        file; the rest exist so that a suppression written against one run still
        matches the next. Never empty — the report prints `fingerprints[0]`
        under "accept this risk by adding", and `suppress.Rule.matches` asks
        whether the value in the ignore file is *in this list*. A finding whose
        printed identity was absent from the list was an escape hatch that
        silently did nothing: the entry was written, the reason was recorded,
        the merge blocked again on the next run, and nothing said why.

        The fallback covers the finding whose every quoted line is boilerplate,
        which `anchors` rejects on purpose. It is the whole quote rather than
        the empty string, because the empty string is the *same* value for
        every anchorless finding in one file and category — and `report_finding`
        drops a candidate whose fingerprint equals an earlier one as a
        duplicate, so a shared identity there does not weaken suppression, it
        deletes findings. Less stable between runs than an anchor, and that is
        the right direction: an identity that fails to match costs a repeated
        suppression entry, one that matches too much hides a weakness.
        """
        values = [_digest(self.category, self.file, a) for a in self.anchors]
        return values or [
            _digest(self.category, self.file, "\n".join(quoted_lines(self.evidence)))]


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


def quoted_lines(evidence: str) -> List[str]:
    """The quoted code, one normalised line at a time, diff markers removed.

    Shared by `anchors` and by the fallback fingerprint so the two cannot drift:
    the fallback exists precisely for the quote `anchors` returns nothing for,
    and a second copy of this normalisation would decide that differently.

    Public, and named without an underscore, because the drift it was written to
    prevent happened anyway one directory over: `tools/artifact.py` had its own
    copy of this normalisation and its own weaker idea of which lines count, so
    the scorer merged findings the agent that produced them keeps apart. It
    imports these two now.
    """
    out = []
    for line in evidence.splitlines():
        collapsed = " ".join(line.split()).lstrip("+- ")
        if collapsed:
            out.append(collapsed)
    return out


def distinctive(line: str) -> bool:
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


# The four names the Messages API uses on a response's `usage` object. Read as
# "present or absent", not "truthy or falsy": a response that says zero tokens
# and a response that says nothing at all are different answers, and the second
# is the one this type exists to keep visible.
_RESPONSE_FIELDS = (
    ("input_tokens", "input_tokens"),
    ("output_tokens", "output_tokens"),
    ("cache_read_input_tokens", "cache_read_tokens"),
    ("cache_creation_input_tokens", "cache_write_tokens"),
)


def _is_count(value: Any) -> bool:
    """A number this can turn into a token count, and nothing else.

    `isinstance(v, (int, float))` was the whole test, and `json.loads` parses
    the bare literals `NaN` and `Infinity` by default — `runner_claude_code`
    reads the CLI's stdout with it — so `int(nan)` raised `ValueError` and
    `int(inf)` `OverflowError` out of a function whose documented answer to a
    shape it does not recognise is "this runner reported nothing". A bool was
    already excluded, for the same reason: `True` is an `int` and is not a
    count.
    """
    return (isinstance(value, (int, float)) and not isinstance(value, bool)
            and math.isfinite(value))


@dataclass
class Usage:
    """What a run used, and how much of that is actually known.

    Three states, not two, because two could not express the case that
    matters. A total assembled from several stages can be complete, empty, or
    *partial* — some stage ran and its figures never arrived — and a partial
    total presented as a total is the same defect as a zero presented as a
    measurement, one level up.

    `requests` and `unreported_stages` are both counters of observed events.
    Neither is a claim a writer makes about the record: the first is
    incremented by the response that carried figures, the second by the
    contribution that carried none. Nothing here can be set to assert that a
    number is trustworthy, which is the shape this project keeps failing on.
    """

    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    cache_write_tokens: int = 0
    requests: int = 0
    # Contributions known to have happened whose figures never arrived. It has
    # to be a count rather than a flag so that `merge` can carry it: the whole
    # point is that a total remembers which of its parts it could not see.
    unreported_stages: int = 0

    def add(self, usage: Any) -> None:
        """Count one provider response.

        A response object carrying none of the four names is a gap, not a
        request that used nothing. It used to increment `requests` regardless,
        so `Usage().add(object())` left `requests == 1` beside four zeros —
        which read as reported, and priced at a confident $0.00. The absence
        of the fields is the evidence; `or 0` on each one erased it.
        """
        values = {ours: getattr(usage, theirs, None)
                  for theirs, ours in _RESPONSE_FIELDS}
        if all(value is None for value in values.values()):
            self.unreported_stages += 1
            return
        self.requests += 1
        for name, value in values.items():
            setattr(self, name, getattr(self, name) + int(value or 0))

    def merge(self, other: "Usage") -> None:
        self.requests += other.requests
        self.input_tokens += other.input_tokens
        self.output_tokens += other.output_tokens
        self.cache_read_tokens += other.cache_read_tokens
        self.cache_write_tokens += other.cache_write_tokens
        # Carried, so the unknown half of a total survives being added up.
        # Without this, merging a reported stage with an unreported one gave
        # `requests > 0` and the unknown half simply disappeared — the review
        # stage's cost presented as the whole review's cost, in the merge
        # request comment and in the stored artifact alike.
        self.unreported_stages += other.unreported_stages

    @classmethod
    def unreported_stage(cls) -> "Usage":
        """A stage that ran and whose figures never arrived.

        A value rather than a setter, so the only way to record a gap is to
        merge one in — and merging can only ever make a total less certain,
        never more. `ScanOutcome` builds these, because it is the only place
        that knows a stage ran: `verify_cli.verify_candidates_with_cli`
        deliberately returns no `Usage` at all while still incrementing
        `metrics.verified`, so "verification happened and reported nothing" is
        visible there and nowhere inside this type.
        """
        return cls(unreported_stages=1)

    @property
    def counted(self) -> int:
        return (self.input_tokens + self.output_tokens
                + self.cache_read_tokens + self.cache_write_tokens)

    @property
    def reported(self) -> bool:
        """Did anything at all say what was used?

        Derived from the two records that can only come from a real
        contribution: a counted response, or tokens actually held. It read
        `requests > 0` alone, which called `Usage(input_tokens=100)` unreported
        and let `to_dict` overwrite those hundred tokens with `null` — a fix
        for losing figures that lost figures.
        """
        return self.requests > 0 or self.counted > 0

    # The four names the Claude Code CLI writes. Read off its own session
    # transcripts under `~/.claude/projects/`, which are the same binary's
    # record and cost nothing to look at: 1729 usage blocks, every one of them
    # spelled this way — the Messages API spelling, not the camelCase of the
    # neighbouring `modelUsage`.
    CLI_FIELDS = ("input_tokens", "output_tokens",
                  "cache_creation_input_tokens", "cache_read_input_tokens")

    @classmethod
    def from_provider(cls, block: Any) -> "Usage":
        """One run's usage as a provider reported it, or a recorded gap.

        All four names or none. A block carrying only some of them is not read
        partially: the two plain counts without the two cache counts is an
        understated cost that reads as measured, and this whole class exists
        because a figure that reads as measured and is not is worse than an
        admitted absence. So an unexpected shape — a spelling nobody
        anticipated, a truncated document, a future field set — produces "this
        runner reported nothing", which is true, rather than a number that is
        not.

        `requests=1`, because a provider that reports per run reports once.
        """
        if not isinstance(block, dict):
            return cls.unreported_stage()
        values = [block.get(name) for name in cls.CLI_FIELDS]
        if not all(_is_count(v) for v in values):
            return cls.unreported_stage()
        return cls(input_tokens=int(values[0]), output_tokens=int(values[1]),
                   cache_write_tokens=int(values[2]),
                   cache_read_tokens=int(values[3]), requests=1)

    @property
    def recorded(self) -> bool:
        """Has anything at all been written into this accumulator?

        Wider than `reported`: a stage that ran and said nothing about what it
        used has recorded a gap, which is a record. The distinction exists so
        that `ScanOutcome.total_usage` can tell an accumulator nobody touched
        from one that already accounts for its own silence — without it, that
        silence was counted twice and the artifact reported two stages having
        reported nothing where one had.
        """
        return self.reported or self.unreported_stages > 0

    @property
    def complete(self) -> bool:
        """Is everything that happened inside these numbers?

        False means the figures are real and there is more that nobody
        counted, which is why `cost_usd` refuses to price it: a floor offered
        as a total is read as a total.
        """
        return self.unreported_stages == 0

    def cost_usd(self, input_per_mtok: float, output_per_mtok: float,
                 cache_ttl: str = "1h") -> Optional[float]:
        """Approximate spend, or `None` when the runner reported no usage.

        The write multiplier depends on the cache TTL, and this took the
        five-minute rate while the agent runs with a one-hour TTL — so every
        cost this reported, in the merge request comment and the job log alike,
        was low. It is a small number on a page of larger ones, which is
        precisely why nobody checked it for two weeks.

        `None` rather than `0.0` for a run nobody reported, and it is the
        return type that enforces it: the previous signature let every caller
        add an unmeasured review into a total and print the result as a bill.
        A caller that must show a figure now has to decide what to say about
        not knowing, which is the decision that was being skipped.

        `None` for an incomplete total too, and for the same reason. A review
        whose verifier reported nothing has a real figure for its review stage,
        and handing that back from a method called `cost_usd` puts a partial
        cost everywhere a total belongs. `partial_cost_usd` returns it under a
        name that cannot be mistaken for the whole.
        """
        if not self.reported or not self.complete:
            return None
        return self._price(input_per_mtok, output_per_mtok, cache_ttl)

    def partial_cost_usd(self, input_per_mtok: float, output_per_mtok: float,
                         cache_ttl: str = "1h") -> Optional[float]:
        """What the stages that did report add up to — a floor, never a total.

        Only useful beside `unreported_stages`, and every caller prints the
        two together: a floor on its own is indistinguishable from a total,
        which is the whole reason it is not what `cost_usd` returns.
        """
        if not self.reported:
            return None
        return self._price(input_per_mtok, output_per_mtok, cache_ttl)

    def _price(self, input_per_mtok: float, output_per_mtok: float,
               cache_ttl: str) -> float:
        return (
            self.input_tokens * input_per_mtok
            + self.cache_write_tokens * input_per_mtok * cache_write_multiplier(cache_ttl)
            + self.cache_read_tokens * input_per_mtok * CACHE_READ_MULTIPLIER
            + self.output_tokens * output_per_mtok
        ) / 1_000_000

    def to_dict(self) -> Dict[str, Any]:
        """The stored block: the figures, and how much of the run they cover.

        `null` and not five zeros when nothing reported. An artifact that
        records "the provider did not say" as "it used nothing" is this
        repository's own absent-versus-zero rule broken inside the record the
        rule is about — `budget.py` has printed "not reported by this runner"
        for the same gap since it was written, and the artifact beside it said
        $0.00.

        `null` rather than an extra key holding the numbers, because a reader
        that ignores the extra key still gets the right answer: nothing to
        sum. But only when there is genuinely nothing — an earlier version
        keyed this on `requests` alone and wrote `null` over real token counts
        held by a `Usage` built directly, destroying figures in the name of
        not inventing them.

        `complete` and `unreported_stages` travel too, because a total that
        covers three of a review's four stages is a third thing, and a reader
        who sees only the figure cannot tell it from a whole one.
        """
        body: Dict[str, Any] = {
            "reported": self.reported,
            "complete": self.complete,
            "unreported_stages": self.unreported_stages,
            "requests": self.requests,
        }
        for _, name in _RESPONSE_FIELDS:
            body[name] = getattr(self, name) if self.reported else None
        return body

    @classmethod
    def from_dict(cls, data: Any) -> "Usage":
        """Read a stored `usage` block back, whichever era wrote it.

        One reader, so no tool re-derives "was this reported" from the keys
        itself and gets it slightly different. It tolerates three shapes:

        * the current block, `null` counts and `requests` 0 — not reported;
        * the five-zero block the `cli-batch-*` measurements of August 2026
          stored — also not reported, and it must read that way, because
          those runs were paid for out of a subscription and nothing about
          them was free;
        * a block with figures — reported, use them.

        `unreported_stages` is read back; `reported` and `complete` are not.
        The asymmetry is the point, and it is narrower than it first reads. A
        count of gaps can only make a total less certain, so a wrong one is
        survivable; `reported` and `complete` are *conclusions*, and a
        truncated or hand-written artifact that carries them would assert a
        measurement it does not hold. Both are re-derived from the figures.

        This is not forgery protection and must not be described as such. The
        figures they are derived from are in the same file: an artifact edited
        to say `"requests": 1` reads back as a measured run priced at zero, and
        deleting `"unreported_stages"` heals a partial record. What re-deriving
        buys is that a *stale or partial* artifact — one written by an older
        version, or cut short — cannot claim more than its own numbers support.
        An artifact somebody chose to rewrite is outside what any of this can
        see.
        """
        body = data if isinstance(data, dict) else {}

        def count(key: str) -> int:
            value = body.get(key)
            return int(value) if _is_count(value) else 0

        return cls(
            unreported_stages=count("unreported_stages"),
            input_tokens=count("input_tokens"),
            output_tokens=count("output_tokens"),
            cache_read_tokens=count("cache_read_tokens"),
            cache_write_tokens=count("cache_write_tokens"),
            requests=count("requests"),
        )


# Why the agent stopped. Only `completed` means the review reached a conclusion;
# every other value means the verdict is partial and must not be reported as a
# clean pass.
STOP_COMPLETED = "completed"
STOP_TURN_LIMIT = "turn_limit"
STOP_TIME_LIMIT = "time_limit"
STOP_BUDGET = "budget_exhausted"
STOP_REFUSAL = "refusal"
# The profile cannot conclude, whatever the review did.
#
# `probe` is six turns and no verifiers, sized to run on every save, and its
# whole point is that it stops early most of the time. `Profile.conclusive` said
# so from the day it was written — and said it to nobody: the flag was read
# nowhere outside `budget.py`, so a probe that called `finish_review` ended
# `completed` and the gate returned 0. A profile that documents itself as never
# conclusive, and can exit "checked and clean", is worse than one that never
# claimed it.
STOP_INCONCLUSIVE = "profile_cannot_conclude"
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
    STOP_INCONCLUSIVE: (
        "this profile cannot conclude a review — what it found are leads, and "
        "what it did not find means nothing"
    ),
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
    # The whole-change diff was cut off at its ceiling, so the reviewer saw the
    # first part of it and no more. Structural, not prose: the notice appended
    # to the diff is what the *model* reads, and an attacker can write the same
    # sentence into a file. This is what the artifact and the gate can rely on.
    diff_truncated: bool = False
    # Tool results the context budget kept out of the conversation. The reviewer
    # asked for something and got none of it, which is a hole in the reading
    # whatever it decided afterwards. Structural for the same reason as
    # `diff_truncated`: the refusal message is text the model reads, and a
    # review is not made complete by a model choosing to stop asking.
    context_refusals: int = 0
    # What the limit would have kept out on a run where it kept out nothing.
    # Not a hole in the review — nothing was withheld — so it never makes a run
    # incomplete. It is the measurement, and it is here rather than in a log
    # because a number nobody sees is a number nobody sets a limit from.
    context_would_refuse: int = 0
    # (path, why) for changed files no reviewer could have read: a binary blob,
    # a submodule pointer, a permission change, a rename that edited nothing.
    #
    # In the report because "2 of 5 changed files opened" reads as a thin review
    # when three of the five had no line in them to open. And separated from the
    # unopened ones because the two mean opposite things: one is work not done,
    # the other is work that does not exist. A mode change is still worth a
    # reader's eye — a script becoming executable is a real change — which is
    # why it is named rather than silently subtracted.
    unreadable: List[Tuple[str, str]] = field(default_factory=list)
    # Files this change deleted. Not in `changed`, which is the list of files a
    # reviewer is asked to *open* and a deleted file cannot be opened — and so,
    # until this line existed, a deletion appeared in no part of the report at
    # all. It is not unreadable either: every removed line of it is in the diff.
    # A deleted security control is one of the things this product exists to
    # catch, and it was the one kind of change nothing said had happened.
    deleted: List[str] = field(default_factory=list)
    # The entire text of the change was put in front of the reviewer once,
    # whole and uncut — not one file of it, not the first part of it, and not a
    # result the context budget kept out.
    #
    # Recorded and not yet gated on, deliberately. Whether healthy runs already
    # do this cannot be read off the artifacts already paid for: none of them
    # records which tools were called. Gating on an unmeasured habit is how the
    # last two completeness proposals would have failed reviews that were fine.
    # So it is observed first and enforced second, the same order the context
    # limit was given, and the observation is in the artifact where a rule can
    # later be set from it rather than from an expectation.
    whole_diff_delivered: bool = False

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
            "diff_truncated": self.diff_truncated,
            "context_refusals": self.context_refusals,
            "context_would_refuse": self.context_would_refuse,
            "unreadable": [{"path": path, "why": why}
                           for path, why in self.unreadable],
            "deleted": self.deleted,
            "whole_diff_delivered": self.whole_diff_delivered,
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
    # Every model that answered anything, review and verification together, and
    # `models_verified` says which of them were the verifier's. Kept apart
    # because the two answer different questions and one flag was reading as
    # both: on 2026-09-02 twelve paid reviews recorded `model_substituted:
    # true` with Haiku beside the requested Opus, which reads as "the review
    # ran on a different model" and would invalidate the measurement — while
    # what had happened was the CLI serving part of the *verification* with a
    # smaller model. The first is a reason to throw the numbers away; the
    # second is noise. Nothing in the artifact could tell them apart.
    models_served: List[str] = field(default_factory=list)
    models_verified: List[str] = field(default_factory=list)
    # Which model the *verifier* was asked for. Empty means it follows the
    # reviewer, which is the default. Recorded because "was the verifier the
    # one we chose" cannot be answered from the reviewer's model when the two
    # are deliberately different — and holding the verifier still is the whole
    # shape of a model comparison.
    verifier_requested: str = ""
    system_prompt_sha: str = ""
    verifier_prompt_sha: str = ""
    schema_sha: str = ""
    agent_version: str = ""
    # How the run was authenticated, when the provider could say — the local
    # runner asks `claude auth status` and records the two fields that decide
    # anything. Never the account's email or organisation, which the same
    # command returns and which decide nothing.
    #
    # Here so the report can say what was established instead of what was
    # hoped. Removing an API key from a child process proves the child cannot
    # use that key; it proves nothing about how the CLI's own stored login is
    # billed, and this project spent a week describing local runs as free on
    # the strength of that inference.
    auth_method: str = ""
    auth_subscription: str = ""
    # Which runner produced this. The artifact recorded the model, the prompts
    # and the schema and never this, so nothing downstream could tell a local
    # review from one the API was billed for — including the tracker row whose
    # whole job was to say no local run had been billed, which read a container
    # no artifact has ever had and skipped every file in silence.
    provider: str = ""
    # What the provider said this run would have cost, in dollars, or `None`
    # when it said nothing. *Notional*, and the name says so, because it is
    # not a bill: the CLI reports `total_cost_usd` on a subscription too, and
    # on a Max plan a two-token reply came back as $0.29. Anything reading that
    # figure as "this run was charged" would mark every subscription run as
    # billed — so the billed/not question is answered by `auth_method`, and
    # this is recorded beside it as the provider's own arithmetic.
    reported_cost_usd: Optional[float] = None

    @property
    def billing(self) -> str:
        """One line for the report, and "unstated" when nothing was learned."""
        if self.auth_method == "claude.ai" and self.auth_subscription:
            return "Claude subscription ({})".format(self.auth_subscription)
        if self.auth_method:
            return "the Claude Code login in use ({})".format(self.auth_method)
        return "not established by this run"

    def note_served(self, model: str, verifying: bool = False) -> None:
        """Record a model that answered. `verifying` marks the verifier's."""
        if not model:
            return
        if model not in self.models_served:
            self.models_served.append(model)
        if verifying and model not in self.models_verified:
            self.models_verified.append(model)

    @property
    def review_models(self) -> List[str]:
        """The models that answered the *review*.

        Verification is excluded by subtraction, which drops a model that did
        both jobs: run the reviewer and the verifier on one model and the list
        comes back empty, so the run reads as having had no reviewer at all.
        The requested model is always one of them when it answered, so it is
        kept rather than subtracted away.
        """
        served = [m for m in self.models_served if m not in self.models_verified]
        if self.model_requested in self.models_served and not served:
            return [self.model_requested]
        return served

    @property
    def model_substituted(self) -> bool:
        """Did anything other than the requested model answer the review?

        The verifier's models are excluded on purpose. This flag decides
        whether a result is about the model it claims to be about, and a
        smaller model used for part of the verification does not change that —
        while reading it as substitution would discard a run that is sound.
        `verifier_substituted` asks the other question separately.
        """
        return any(m != self.model_requested for m in self.review_models)

    @property
    def verifier_substituted(self) -> bool:
        """Did the verification run on something other than the model asked for?

        Against `verifier_requested`, not against the reviewer's model. The
        first version compared the two, and that is wrong in the one
        arrangement this field exists for: a cheaper reviewer with the verifier
        deliberately held where it was reads as a substitution on every run,
        which makes the flag useless exactly where it is needed. A flag that
        cries on the intended configuration is a flag nobody can act on.
        """
        wanted = self.verifier_requested or self.model_requested
        return any(m != wanted for m in self.models_verified)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "model_requested": self.model_requested,
            "models_verified": list(self.models_verified),
            "verifier_requested": self.verifier_requested,
            "verifier_substituted": self.verifier_substituted,
            "models_served": self.models_served,
            "model_substituted": self.model_substituted,
            "system_prompt_sha": self.system_prompt_sha,
            "verifier_prompt_sha": self.verifier_prompt_sha,
            "schema_sha": self.schema_sha,
            "agent_version": self.agent_version,
            # Written, because a field the artifact does not carry is a field
            # nothing downstream can read — and these were added for readers
            # that then found nothing. `probe_spend` was rewritten to decide
            # from `auth_method` on the same day this omitted it.
            "provider": self.provider,
            "auth_method": self.auth_method,
            "auth_subscription": self.auth_subscription,
            "reported_cost_usd": self.reported_cost_usd,
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
    # (path, channel) for every file whose bytes reached the model, which is a
    # different question from which files it opened: a whole-change `get_diff`
    # carries every changed file without opening one, and `search_code`
    # returns lines from files nobody named.
    #
    # It travels this far because the gate needs it. Deciding whether a review
    # did any work from `tool_calls` counts a *refused* read as work — the
    # attempt is accounting, not evidence that anything reached the reviewer —
    # and deciding it from `files_examined` answers "nothing" for a review that
    # read the entire diff and opened no file.
    exposures: List[tuple] = field(default_factory=list)
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
    # A Markdown document this project rendered itself, for the one case where
    # a run left nothing else: the crash trace. Separate from `stop_detail`,
    # which is a sentence and is always escaped, because the report needs to
    # know which of the two it is holding — and deciding that by counting
    # newlines is a check satisfied by a shape rather than by the thing.
    #
    # Everything inside it has already been through `rendering`, at the point
    # each string was placed. Nothing else may ever be assigned here.
    trace_markdown: str = ""
    # A digest of the accepted risks in force when this ran. Part of the
    # review's identity, so it has to be written into the artifact as well as
    # computed for the comparison — recorded on one side only, no artifact
    # would ever match and reuse would silently never happen.
    suppressions_digest: str = ""
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

    @property
    def review_ran(self) -> bool:
        """Did the reviewer do anything, whatever it reported about it?

        Read off what a review leaves behind rather than off its usage, which
        is the field in question. Any of the three is proof: a turn was taken,
        a tool was called, or something reached the model.
        """
        return bool(self.turns or self.tool_calls or self.exposures)

    @property
    def verification_ran(self) -> bool:
        """Did a verifier panel actually sit?

        `metrics.verified` counts findings that went through one, and it is
        incremented on both verification paths — including
        `verify_cli.verify_candidates_with_cli`, which by design returns no
        `Usage` at all. That pairing is exactly the case this property exists
        for: the stage happened, and nothing about its cost came back.
        """
        return self.metrics.verified > 0

    def total_usage(self) -> Usage:
        """Every stage's usage, with the stages nobody counted still in it.

        Merging the two `Usage` objects alone loses the unknown half. An
        unreported stage arrives here as a default `Usage()` — five zeros,
        indistinguishable from a stage that never ran — so a review whose
        verifier reported nothing came out with `requests > 0` and presented
        the review stage's cost as the whole review's cost, in the merge
        request comment and in the stored artifact alike. A partial figure
        reading as the total is the same defect as a zero reading as a
        measurement, one level up.

        This class is the only place the difference is knowable: `Usage` sees
        two empty accumulators and cannot tell which of them was asked.
        """
        total = Usage()
        total.merge(self.usage)
        total.merge(self.verification_usage)
        for ran, stage in ((self.review_ran, self.usage),
                           (self.verification_ran, self.verification_usage)):
            # `not stage.recorded`, not `not stage.reported`. A stage that
            # already counted its own gap — `add()` given a response carrying
            # none of the four token fields does exactly that — is unreported
            # *and* accounted for, so adding another gap here counted it twice
            # and the artifact said two stages reported nothing when one did.
            # The total stayed correctly incomplete either way; the number
            # beside it did not, and a number nobody can reproduce is the thing
            # this whole change is about.
            if ran and not stage.recorded:
                total.merge(Usage.unreported_stage())
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
