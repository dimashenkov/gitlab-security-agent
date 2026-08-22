"""Layers 2 and 3 of the hallucination check: adversarial verification.

Layer 1 (``evidence.py``) proves the cited code exists. That is necessary and
nowhere near sufficient — the code can be real while the vulnerability is not.
This module puts each surviving claim in front of an independent reviewer whose
instructions are to refute it, in a **fresh conversation with no access to the
original agent's reasoning**. Independence is the whole point: a model asked to
re-check its own chain of thought tends to find it convincing.

The verifier gets the same read-only tools as the agent, because a verdict
reached without reading the callers is not worth having. It does not get
`report_finding`: its only output is a verdict on the one claim it was handed.
"""

from __future__ import annotations

import json
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional, Tuple

import anthropic

from .config import Config
from .evidence import excerpt
from .models import (
    VERDICT_CONFIRMED,
    VERDICT_REFUTED,
    VERDICT_UNCERTAIN,
    Candidate,
    Usage,
    Vote,
    confidence_rank,
    severity_rank,
)
from .tools import Session, dispatch, read_only_tool_definitions
from .transport import TransportFailure, stream_message
from .workspace import Workspace, WorkspaceError

log = logging.getLogger(__name__)

# A verifier investigating one claim needs far fewer turns than an agent
# reviewing a whole change set; this ceiling is generous for reading a file,
# finding its callers, and checking one control.
MAX_VERIFY_TURNS = 14

VERDICT_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["verdict", "reasoning", "corrected_severity", "corrected_confidence"],
    "properties": {
        "verdict": {
            "type": "string",
            "enum": [VERDICT_CONFIRMED, VERDICT_UNCERTAIN, VERDICT_REFUTED],
        },
        "reasoning": {
            "type": "string",
            "description": (
                "Two to four sentences naming the specific control, caller, or "
                "broken link that decided the verdict, with file and line "
                "references."
            ),
        },
        "corrected_severity": {
            "type": "string",
            "enum": ["critical", "high", "medium", "low", ""],
            "description": "A lower severity if the claim overstated impact; empty to agree.",
        },
        "corrected_confidence": {
            "type": "string",
            "enum": ["high", "medium", "low", ""],
            "description": "Your own confidence, which may be higher or lower than claimed: it records how much of the chain you actually saw. Raise it when you closed a link the reviewer could not; lower it when a link is weaker than claimed. Empty to agree.",
        },
    },
}


def verify_candidates(
    cfg: Config,
    ws: Workspace,
    client: Any,
    candidates: List[Candidate],
) -> Usage:
    """Verify every candidate in place. Returns the tokens this stage cost."""
    usage = Usage()
    if not candidates:
        return usage

    if not cfg.verify:
        for candidate in candidates:
            candidate.verdict = VERDICT_CONFIRMED
            candidate.verdict_reason = "verification disabled (SECURITY_SCAN_VERIFY=false)"
        return usage

    # Verification exists to keep the gate from blocking on something unreal.
    # A finding that cannot block under the current settings has nothing to be
    # protected from, and on a typical run these are most of them — verifying
    # them is the largest avoidable cost in the whole tool. Decide this before
    # touching the prompt file or the client, so a run with nothing to verify
    # does no work at all.
    candidates, informational = _partition(cfg, candidates)
    for candidate in informational:
        candidate.verdict = VERDICT_CONFIRMED
        candidate.verdict_reason = (
            "not verified — reported for information only, as it cannot block "
            "the merge at the current settings ({})".format(_why_not_gating(cfg, candidate))
        )
    if informational:
        log.info(
            "skipping verification for %d finding(s) that cannot block; verifying %d",
            len(informational), len(candidates),
        )
    if not candidates:
        return usage

    system = _system_blocks(cfg)
    tools = read_only_tool_definitions(diff_available=bool(ws.diff_base))

    to_verify = candidates[: cfg.verify_max_findings]
    if len(candidates) > len(to_verify):
        log.warning(
            "verifying only the first %d of %d findings (SECURITY_SCAN_VERIFY_MAX); "
            "the remainder are reported unverified",
            len(to_verify), len(candidates),
        )
        for candidate in candidates[cfg.verify_max_findings:]:
            candidate.verdict = VERDICT_CONFIRMED
            candidate.verdict_reason = (
                "not verified — beyond the SECURITY_SCAN_VERIFY_MAX limit of {}".format(
                    cfg.verify_max_findings)
            )

    # Every vote is an independent conversation over a read-only workspace —
    # that independence is the whole point of the design, and it also means
    # there is no reason to run them one at a time. Sequentially, verification
    # took 280 of a 320-second job while the review itself took 100; the votes
    # simply queued behind each other.
    jobs = [
        (candidate, vote_index)
        for candidate in to_verify
        for vote_index in range(_votes_for(cfg, candidate))
    ]
    for index, candidate in enumerate(to_verify, start=1):
        log.info(
            "verifying %d/%d: %s (%s) — %d vote(s)",
            index, len(to_verify), candidate.finding.title,
            candidate.severity, _votes_for(cfg, candidate),
        )

    workers = max(1, min(cfg.verify_concurrency, len(jobs)))
    log.info("running %d verification call(s) across %d worker(s)", len(jobs), workers)

    results: Dict[Tuple[int, int], Vote] = {}
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(_one_vote, cfg, ws, client, system, tools, candidate, vote_index):
                (id(candidate), vote_index)
            for candidate, vote_index in jobs
        }
        for future in as_completed(futures):
            key = futures[future]
            try:
                vote, vote_usage = future.result()
            except Exception as exc:  # a worker must not take the run down
                log.exception("a verification call raised")
                vote, vote_usage = Vote(
                    verdict=VERDICT_UNCERTAIN, reasoning="",
                    error="verification call raised {}: {}".format(type(exc).__name__, exc),
                ), Usage()
            results[key] = vote
            usage.merge(vote_usage)

    # Votes are attached in a fixed order rather than completion order, so a
    # rerun of the same findings aggregates identically regardless of which
    # worker happened to finish first.
    for candidate, vote_index in jobs:
        vote = results.get((id(candidate), vote_index))
        if vote is not None:
            candidate.votes.append(vote)

    for candidate in to_verify:
        for number, vote in enumerate(candidate.votes, start=1):
            log.info(
                "  [%s] vote %d: %s — %s",
                candidate.finding.title[:40], number,
                vote.verdict if not vote.error else "unavailable",
                (vote.error or vote.reasoning)[:180],
            )
        _decide(candidate)
        log.info("  verdict: %s — %s", candidate.verdict, candidate.verdict_reason[:200])

    return usage


def _partition(cfg: Config, candidates: List[Candidate]) -> Tuple[List[Candidate], List[Candidate]]:
    """Split into (worth verifying, informational only).

    Skipping verification for findings that cannot block is the largest cost
    saving in the tool, but two runs over the same merge request showed the trap
    in taking it too literally. The agent rated a real `pickle.loads` on
    untrusted bytes `high` severity but only `low` confidence; that put it below
    the gate, so it was never verified, and a genuinely dangerous finding passed
    silently. The agent's own first impression had become final.

    So severity and confidence are treated differently here. Confidence is a
    statement about how much of the chain the agent managed to see, and a
    verifier reading with fresh eyes routinely sees more — it is exactly the
    thing that should be allowed to settle it. Severity is a judgement about
    impact, and there the agent had more context than any single verifier will.

    A severe finding is therefore always verified, whatever confidence it
    claims. Everything below the severity threshold is still skipped, because no
    verdict can lift it over the bar.
    """
    if cfg.fail_threshold is None:
        return [], list(candidates)  # nothing can block; verify nothing

    gating, informational = [], []
    for candidate in candidates:
        if _worth_verifying(cfg, candidate):
            gating.append(candidate)
        else:
            informational.append(candidate)
    return gating, informational


def _worth_verifying(cfg: Config, candidate: Candidate) -> bool:
    """Could a verifier's verdict change whether this blocks?"""
    if severity_rank(candidate.severity) < severity_rank(cfg.fail_on):
        return False  # verification cannot raise severity, so this stays below
    # Otherwise it is severe enough and in scope, and confidence — the only
    # thing left that could keep it from blocking — is the verifier's to settle.
    return candidate.in_changed_lines or cfg.gate_pre_existing


def _could_block(cfg: Config, candidate: Candidate) -> bool:
    """Does this finding block the merge as currently rated?"""
    if severity_rank(candidate.severity) < severity_rank(cfg.fail_on):
        return False
    if confidence_rank(candidate.confidence) < confidence_rank(cfg.min_confidence):
        return False
    return candidate.in_changed_lines or cfg.gate_pre_existing


def _why_not_gating(cfg: Config, candidate: Candidate) -> str:
    if cfg.fail_threshold is None:
        return "SECURITY_SCAN_FAIL_ON=none"
    if severity_rank(candidate.severity) < severity_rank(cfg.fail_on):
        return "below the {} severity threshold".format(cfg.fail_on)
    if confidence_rank(candidate.confidence) < confidence_rank(cfg.min_confidence):
        return "below {} confidence".format(cfg.min_confidence)
    return "pre-existing, not introduced by this change"


def _votes_for(cfg: Config, candidate: Candidate) -> int:
    """How many independent verifiers this claim gets.

    Critical and high findings are escalated to at least two, for an asymmetric
    reason: dropping a real critical costs far more than the extra call, so a
    single dissenting verifier must not be able to discard one on its own.
    """
    votes = cfg.verify_votes
    if severity_rank(candidate.severity) >= severity_rank("high"):
        votes = max(votes, 2)
    return min(votes, 5)


# ------------------------------------------------------------------ one vote


def _one_vote(
    cfg: Config,
    ws: Workspace,
    client: Any,
    system: List[Dict[str, Any]],
    tools: List[Dict[str, Any]],
    candidate: Candidate,
    vote_index: int,
) -> Tuple[Vote, Usage]:
    """Run one verifier to completion in its own conversation."""
    usage = Usage()
    session = Session()  # scratch state; the verifier records no findings
    messages: List[Dict[str, Any]] = [
        {"role": "user", "content": [{"type": "text", "text": _brief(cfg, ws, candidate, vote_index)}]}
    ]

    cached_block: Optional[Dict[str, Any]] = None
    for turn in range(1, MAX_VERIFY_TURNS + 1):
        session.turn = turn
        try:
            response = _request(cfg, client, system, messages, tools)
        except (anthropic.APIStatusError, anthropic.APIConnectionError,
                TransportFailure) as exc:
            return Vote(
                verdict=VERDICT_UNCERTAIN,
                reasoning="",
                error="verification call failed: {}".format(exc),
            ), usage

        usage.add(response.usage)

        if response.stop_reason == "refusal":
            return Vote(
                verdict=VERDICT_UNCERTAIN, reasoning="",
                error="the verifier declined to assess this finding",
            ), usage

        messages.append({"role": "assistant", "content": response.content})

        if response.stop_reason == "pause_turn":
            continue

        tool_uses = [b for b in response.content if getattr(b, "type", "") == "tool_use"]
        if not tool_uses:
            vote = _parse_verdict(response)
            if vote is not None:
                return vote, usage
            return Vote(
                verdict=VERDICT_UNCERTAIN, reasoning="",
                error="the verifier did not return a parsable verdict",
            ), usage

        results = []
        for block in tool_uses:
            result = dispatch(ws, session, getattr(block, "name", ""), getattr(block, "input", {}) or {})
            entry: Dict[str, Any] = {
                "type": "tool_result",
                "tool_use_id": block.id,
                "content": result.content or "(no output)",
            }
            if result.is_error:
                entry["is_error"] = True
            results.append(entry)
            log.debug("    %s: %s", getattr(block, "name", "?"), result.summary)

        if cached_block is not None:
            cached_block.pop("cache_control", None)
        results[-1]["cache_control"] = {"type": "ephemeral"}
        cached_block = results[-1]
        messages.append({"role": "user", "content": results})

    return Vote(
        verdict=VERDICT_UNCERTAIN, reasoning="",
        error="the verifier ran out of turns before reaching a verdict",
    ), usage


def _request(
    cfg: Config,
    client: Any,
    system: List[Dict[str, Any]],
    messages: List[Dict[str, Any]],
    tools: List[Dict[str, Any]],
) -> Any:
    return _stream(
        client,
        model=cfg.verifier_model,
        max_tokens=cfg.max_tokens,
        system=system,
        messages=messages,
        tools=tools,
        thinking={"type": "adaptive"},
        output_config={
            "effort": cfg.verify_effort,
            "format": {"type": "json_schema", "schema": VERDICT_SCHEMA},
        },
    )


def _stream(client: Any, **params: Any) -> Any:
    return stream_message(client, params, label="verifier turn")


def _parse_verdict(response: Any) -> Optional[Vote]:
    """Read the structured verdict out of the final message.

    ``output_config.format`` guarantees the final text is JSON matching the
    schema, so this is a parse rather than an extraction — but a malformed
    result is treated as "no verdict" rather than crashing the run.
    """
    text = "".join(
        block.text for block in response.content
        if getattr(block, "type", "") == "text"
    ).strip()
    if not text:
        return None
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        start, end = text.find("{"), text.rfind("}")
        if start == -1 or end <= start:
            return None
        try:
            data = json.loads(text[start : end + 1])
        except json.JSONDecodeError:
            return None
    if not isinstance(data, dict) or "verdict" not in data:
        return None
    verdict = str(data.get("verdict", "")).strip()
    if verdict not in (VERDICT_CONFIRMED, VERDICT_UNCERTAIN, VERDICT_REFUTED):
        return None
    return Vote(
        verdict=verdict,
        reasoning=str(data.get("reasoning", "")).strip(),
        corrected_severity=str(data.get("corrected_severity", "") or "").strip(),
        corrected_confidence=str(data.get("corrected_confidence", "") or "").strip(),
    )


# ---------------------------------------------------------------- aggregation


def _decide(candidate: Candidate) -> None:
    """Turn the votes into a verdict and apply any agreed downgrades."""
    usable = [v for v in candidate.votes if not v.error]
    if not usable:
        candidate.verdict = VERDICT_CONFIRMED
        errors = "; ".join(v.error for v in candidate.votes if v.error)
        candidate.verdict_reason = (
            "reported unverified — verification could not run ({})".format(
                errors or "no verifier responded")
        )
        return

    refuted = [v for v in usable if v.verdict == VERDICT_REFUTED]
    confirmed = [v for v in usable if v.verdict == VERDICT_CONFIRMED]

    is_severe = severity_rank(candidate.finding.severity) >= severity_rank("critical")
    if is_severe and len(usable) >= 2:
        # Unanimity required to discard a critical: one dissenting verifier
        # downgrades it to `uncertain`, where a human still sees it, rather than
        # removing it from the report's gating set on its own.
        if len(refuted) == len(usable):
            verdict = VERDICT_REFUTED
        elif len(confirmed) == len(usable):
            verdict = VERDICT_CONFIRMED
        else:
            verdict = VERDICT_UNCERTAIN
    elif len(refuted) * 2 > len(usable):
        verdict = VERDICT_REFUTED
    elif len(confirmed) == len(usable):
        verdict = VERDICT_CONFIRMED
    else:
        verdict = VERDICT_UNCERTAIN

    candidate.verdict = verdict
    candidate.verdict_reason = _reason(usable, verdict)

    if verdict == VERDICT_REFUTED:
        return

    # Severity moves down only. It is a judgement about impact, and the agent
    # that traced the path had more of the picture than a verifier looking at
    # one finding in isolation.
    for vote in usable:
        if (0 <= severity_rank(vote.corrected_severity)
                < severity_rank(candidate.severity)):
            candidate.severity = vote.corrected_severity

    if verdict == VERDICT_UNCERTAIN:
        # An unresolved chain is exactly what `low` confidence means, and it
        # keeps the finding visible without letting it block the merge.
        candidate.confidence = "low"
    elif verdict == VERDICT_CONFIRMED:
        # Confidence moves in both directions, because it means something
        # different from severity: it records how much of the chain was actually
        # seen, not how bad the outcome would be. A verifier that read the
        # callers and closed a link the agent could only guess at knows more
        # about that than the agent did.
        #
        # This exists because the alternative was worse. When only downgrades
        # were allowed, an agent that hedged at `low` on a real `pickle.loads`
        # buried the finding permanently — nothing downstream could ever undo a
        # cautious first impression.
        candidate.confidence = _agreed_confidence(usable, candidate.confidence)
    else:
        for vote in usable:
            if (0 <= confidence_rank(vote.corrected_confidence)
                    < confidence_rank(candidate.confidence)):
                candidate.confidence = vote.corrected_confidence


def _agreed_confidence(votes: List[Vote], claimed: str) -> str:
    """The confidence every confirming verifier can stand behind.

    The lowest of what they proposed, so raising takes agreement while lowering
    takes only one dissent — the same asymmetry used everywhere else here, for
    the same reason: it is cheaper to be wrong in the direction of a visible
    finding than an invisible one.

    A verifier that leaves the field empty is agreeing with the claim, not
    voting for it, so silence cannot raise anything on its own.
    """
    proposals = [v.corrected_confidence for v in votes if v.corrected_confidence]
    if not proposals or len(proposals) < len(votes):
        # At least one verifier did not express an opinion; keep the claim.
        lowered = [c for c in proposals if confidence_rank(c) < confidence_rank(claimed)]
        return min(lowered, key=confidence_rank) if lowered else claimed
    return min(proposals, key=confidence_rank)


def _reason(votes: List[Vote], verdict: str) -> str:
    """Pick the verifier reasoning that best explains the aggregate verdict."""
    preferred = [v for v in votes if v.verdict == verdict and v.reasoning]
    if preferred:
        head = preferred[0].reasoning
    else:
        head = next((v.reasoning for v in votes if v.reasoning), "")
    if len(votes) > 1:
        tally = "{}/{} verifier(s) agreed".format(
            sum(1 for v in votes if v.verdict == verdict), len(votes))
        return "{} — {}".format(tally, head) if head else tally
    return head


# -------------------------------------------------------------------- prompt


def _system_blocks(cfg: Config) -> List[Dict[str, Any]]:
    path = cfg.resolved_prompt_dir() / "verifier.md"
    return [{
        "type": "text",
        "text": path.read_text(encoding="utf-8"),
        "cache_control": {"type": "ephemeral", "ttl": cfg.cache_ttl},
    }]


def _brief(cfg: Config, ws: Workspace, candidate: Candidate, vote_index: int) -> str:
    """The claim under review, plus the code around it as a starting point."""
    finding = candidate.finding
    parts = [
        "A reviewer has proposed the following finding. Investigate it and "
        "return a verdict.",
        "",
        "## The claim",
        "",
        "- **Title:** {}".format(finding.title),
        "- **Severity claimed:** {}".format(finding.severity),
        "- **Confidence claimed:** {}".format(finding.confidence),
        "- **Category:** {}".format(finding.category),
        "- **Location:** `{}` line {}".format(finding.file, candidate.line),
        "",
        "**Quoted code** (already confirmed to exist at that location):",
        "",
        "```",
        finding.evidence.strip(),
        "```",
        "",
        "**What the reviewer says is wrong:**",
        finding.description.strip(),
        "",
        "**The exploit path they claim:**",
        finding.exploit_scenario.strip(),
        "",
    ]

    try:
        file_text = ws.raw_text(finding.file)
        window, start, stop = excerpt(file_text, candidate.line, radius=60)
        parts += [
            "## Starting context",
            "",
            "`{}` lines {}-{} (read more of it, and other files, with the tools):".format(
                finding.file, start, stop),
            "",
            "```",
            window,
            "```",
            "",
        ]
    except WorkspaceError as exc:
        parts += ["## Starting context", "", "Could not load the file: {}".format(exc), ""]

    if ws.diff_base and not candidate.in_changed_lines:
        parts += [
            "Note: this code is **not** part of the change under review — it "
            "already existed. Judge whether the weakness is real; the report "
            "records separately that it is pre-existing.",
            "",
        ]

    parts += [
        "## Your task",
        "",
        "Try to refute this claim. Read what you need to. Then return the JSON "
        "verdict.",
    ]
    if vote_index > 0:
        # Independent verifiers must not be identical requests, or the cache
        # would return one opinion N times instead of N opinions.
        parts += [
            "",
            "Approach this from a different angle than an obvious first pass: "
            "start from the sink and work backwards to every caller that can "
            "reach it, rather than starting from the quoted line.",
        ]
    return "\n".join(parts)
