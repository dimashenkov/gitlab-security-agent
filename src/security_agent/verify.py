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
from dataclasses import replace
from typing import Any, Dict, List, Optional, Tuple

import anthropic

from .config import Config
from .evidence import ATTRIBUTED_DELETED, excerpt
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
from .panel import decide
from .tools import Session, dispatch, verifier_tool_definitions
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
    # `control_search` and `entry_point` are required so the model has to
    # confront the question on every verdict rather than omitting the field.
    # Without that, a verifier that simply never mentions its search sends
    # every finding to `uncertain` and the gate stops blocking anything — the
    # rule would read as caution and act as an off switch. Required means it
    # must answer; the length check downstream is what decides whether the
    # answer is a statement or a token.
    "required": ["verdict", "reasoning", "corrected_impact",
                 "corrected_reachable_without_authentication",
                 "corrected_requires_user_interaction", "corrected_confidence",
                 "control_search", "entry_point"],
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
        "corrected_impact": {
            "type": "string",
            "enum": ["code_execution", "broad_data_access", "narrow_data_access",
                     "state_change", "metadata_disclosure", "denial_of_service", ""],
            "description": (
                "Correct what the attacker actually achieves, if the reviewer "
                "got it wrong. Empty to agree. Severity is computed from this "
                "and the two fields below — you are not asked to rate the "
                "finding, only to establish the facts it is rated from."
            ),
        },
        "corrected_reachable_without_authentication": {
            "type": "string",
            "enum": ["yes", "no", "unclear", ""],
            "description": (
                "Correct whether an unauthenticated caller can reach the "
                "vulnerable code. You have read the callers, so you are often "
                "better placed to say than the reviewer was. Empty to agree."
            ),
        },
        "corrected_requires_user_interaction": {
            "type": "string",
            "enum": ["yes", "no", "unclear", ""],
            "description": "Correct whether a victim must act. Empty to agree.",
        },
        "removes_existing_control": {
            "type": "string",
            "enum": ["yes", "no", ""],
            "description": (
                "Does this weakness exist because the change under review "
                "REMOVED a check, guard, validation, or other security control "
                "that was previously in place? `yes` only when you can see the "
                "removal in the diff and the weakness follows from it. Deleting "
                "unrelated code near an existing weakness is `no`. Leave empty "
                "if the change adds no deletions here."
            ),
        },
        "control_search": {
            "type": "string",
            "description": (
                "What you looked for that would REFUTE this finding, where you "
                "looked, and what you found. Name the guard, validation, or "
                "check you expected to exist, the files you searched, and the "
                "result — including 'searched X and Y, no such check exists'. "
                "Required to confirm: a confirmation without it is an opinion "
                "about the quoted lines, not a verdict about the code. If you "
                "did not search, say so and answer `uncertain`."
            ),
        },
        "entry_point": {
            "type": "string",
            "description": (
                "The caller or entry point through which an attacker reaches "
                "this code, with file and line — the specific chain, not 'it is "
                "reachable'. Required to confirm a finding you also mark "
                "reachable without authentication. If every caller you found "
                "validates first, that is a refutation, not a confirmation."
            ),
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
    provenance: Optional[Any] = None,
    metrics: Optional[Any] = None,
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
    if metrics is not None:
        metrics.verification_skipped += len(informational)
        metrics.verified += len(candidates)
    if informational:
        log.info(
            "skipping verification for %d finding(s) that cannot block; verifying %d",
            len(informational), len(candidates),
        )
    if not candidates:
        return usage

    system = _system_blocks(cfg)
    tools = verifier_tool_definitions(VERDICT_SCHEMA,
                                      diff_available=bool(ws.diff_base))

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
            if provenance is not None:
                for model in getattr(vote, "served_models", ()) or ():
                    provenance.note_served(model)

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
        before = (candidate.severity, candidate.confidence, candidate.verdict,
                  candidate.removes_control)
        _decide(candidate)
        if metrics is not None:
            if any(v.error for v in candidate.votes):
                metrics.verification_failed += 1
            after = (candidate.severity, candidate.confidence, candidate.verdict,
                     candidate.removes_control)
            if before != after:
                metrics.verdicts_changed += 1
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
    gating, informational = [], []
    for candidate in candidates:
        if _worth_verifying(cfg, candidate):
            gating.append(candidate)
        else:
            informational.append(candidate)
    return gating, informational


def _worth_verifying(cfg: Config, candidate: Candidate) -> bool:
    """Could a verifier's verdict change whether this blocks?

    Both ratings can now move up, so "below the threshold" no longer means
    "settled". A finding one step under the bar is exactly the one a pair of
    verifiers might agree belongs over it, and skipping it would recreate the
    trap this rule was written to close — just one level down.

    One step, not all of them. A two-level promotion (`low` to `high`) would be
    an extraordinary disagreement between the agent and both verifiers, and
    verifying every `low` finding on a large change costs more than that case is
    worth. Anything skipped still appears in the report, labelled with why.
    """
    if candidate.attributed_by == ATTRIBUTED_DELETED:
        # Whether this is a removed control is the verifier's call, and it can
        # block regardless of severity — so severity cannot be used to skip it.
        #
        # Deliberately not conditioned on `gate_removed_controls`. Verification
        # scope is decided by what a verdict could change about the *finding*,
        # never by the gating policy in force: a project that has switched the
        # rule off still deserves to know whether its change deleted a guard,
        # and a claim that it did is exactly the kind worth checking against the
        # file. Tying the two together also made the setting impossible to
        # ablate — turning the rule off silently stopped verifying these, so
        # "ungated" and "unverified" moved as one and no experiment could
        # separate them.
        return True
    if severity_rank(candidate.severity) < severity_rank(_verify_floor(cfg)) - 1:
        return False
    return candidate.in_changed_lines or cfg.gate_pre_existing


# What a finding must reach to be worth verifying when nothing can block.
# Verification scope has to stay decided by what a verdict changes about the
# finding, so turning the gate off cannot turn the checking off with it.
DEFAULT_VERIFY_FLOOR = "high"


def _verify_floor(cfg: Config) -> str:
    """The severity that decides verification scope, gate or no gate.

    `SECURITY_SCAN_FAIL_ON=none` used to skip verification entirely — the
    reasoning being that verification exists to decide gating, so with no gate
    there is nothing to decide. That is wrong in the deployment this project
    has settled on. Advisory mode is where the **report** is the whole product,
    and an unverified finding is precisely the thing that wastes the reader's
    time: no independent refutation, no odd panel, no requirement that a
    confirmation say what it searched for.

    It was also the obvious way to make the tool advisory. Someone who does not
    want a blocked merge reaches for `FAIL_ON=none` and silently loses every
    protection built for the finding rather than for the gate. The way to make
    it advisory is `allow_failure: true` on the job.

    The function below already refuses to tie verification scope to
    `gate_removed_controls`, and says why. This is the same rule, applied to
    the setting that was still breaking it.
    """
    return DEFAULT_VERIFY_FLOOR if cfg.fail_threshold is None else cfg.fail_on


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


def _could_become_blocking(cfg: Config, candidate: Candidate) -> bool:
    """Could any verdict this panel returns end with the merge blocked?

    Sized on the outcome, not on the rating the finding arrives with. Using the
    current severity left two more single-verifier paths to a gate decision,
    both in exactly the places `_worth_verifying` deliberately reaches beyond
    the threshold to cover:

    * a `medium` finding under a `high` threshold got one vote, could be
      corrected upward by that vote, and blocked on it alone;
    * a `low` finding attributed to a deletion got one vote, could be called a
      removed control by that vote, and blocked regardless of severity.

    Both are the fault that odd panels were introduced to remove, surviving in
    the branches that were not looked at.
    """
    if cfg.fail_threshold is None:
        return False
    if candidate.finding.category.lower() in {
            c.lower() for c in cfg.ungated_categories}:
        return False
    if not candidate.in_changed_lines and not cfg.gate_pre_existing:
        return False
    if candidate.attributed_by == ATTRIBUTED_DELETED and cfg.gate_removed_controls:
        # A verifier can call this a removed control, which blocks whatever the
        # severity says.
        return True
    # One step of upward correction is what `_worth_verifying` allows for, so
    # it is what the panel has to be able to survive.
    return severity_rank(candidate.severity) >= severity_rank(cfg.fail_on) - 1


def _votes_for(cfg: Config, candidate: Candidate) -> int:
    """How many independent verifiers this claim gets.

    Findings that could block are escalated to **three**, and three rather than
    two for a specific reason: two verifiers cannot form a majority, so any
    disagreement between them is settled by a rule rather than by evidence, and
    whichever rule is chosen becomes a coin flip on the phrasing of one reply.

    Measured: with two verifiers, four identical runs of one unsafe case gave
    three blocks and one pass — 3 of 6 run pairs agreed. The disagreement was
    never about the code. One verifier said `uncertain` where the others said
    `confirmed`, that alone forced the verdict to uncertain, and uncertain
    forces confidence to `low`, which is under the gate. A single hedge
    silently ungated a real finding.

    An odd number is the cheapest fix that makes the outcome depend on what a
    majority saw rather than on who hedged. It costs one extra verifier call
    per blocking-eligible finding — most runs have one or two.
    """
    votes = cfg.verify_votes
    if _could_become_blocking(cfg, candidate):
        votes = max(votes, 3)
    if votes % 2 == 0:
        # An even panel has no majority to appeal to. Whatever tie-break is
        # written for it decides the gate on its own, which is the failure this
        # is here to remove.
        votes += 1
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
    served: List[str] = []
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
        served.append(getattr(response, "model", "") or cfg.verifier_model)

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
                return _tagged(vote, served, session), usage
            return _tagged(Vote(
                verdict=VERDICT_UNCERTAIN, reasoning="",
                error="the verifier did not return a parsable verdict",
            ), served, session), usage

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

        if session.verdict is not None:
            # Submitted as an argument rather than left in the final message.
            # The vote and the statement that this verifier is finished are the
            # same act, which is the only version of "done" a provider running
            # its own loop can also produce.
            vote = _vote_from_payload(session.verdict)
            if vote is not None:
                vote.channel = "submit_verdict"
                return _tagged(vote, served, session), usage
            return _tagged(Vote(
                verdict=VERDICT_UNCERTAIN, reasoning="",
                error="the verifier submitted a verdict that could not be read",
            ), served, session), usage

        if cached_block is not None:
            cached_block.pop("cache_control", None)
        results[-1]["cache_control"] = {"type": "ephemeral"}
        cached_block = results[-1]
        messages.append({"role": "user", "content": results})

    return _tagged(Vote(
        verdict=VERDICT_UNCERTAIN, reasoning="",
        error="the verifier ran out of turns before reaching a verdict",
    ), served, session), usage


def _tagged(vote: Vote, served: List[str], session: Optional[Session] = None) -> Vote:
    """Carry the models that answered back across the thread boundary.

    Attached to the vote rather than returned separately because the votes are
    what survive the worker pool; a fourth return value would have to be
    threaded through every call site for one field. The files the verifier
    opened ride along for the same reason, and they answer a question the
    verdict alone cannot: a payload in a file that was never read did not fail,
    it was never tried.
    """
    vote.served_models = list(dict.fromkeys(m for m in served if m))
    if session is not None:
        vote.files_read = list(session.files_examined)
        vote.exposures = list(session.exposures)
    return vote


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


# Long enough to name a file and a thing looked for. A verifier that answers
# "checked" or "n/a" has not made the statement the field exists to extract.
MIN_EVIDENCE_CHARS = 24


def _require_evidence(vote: Vote) -> Vote:
    """A confirmation that cannot say what it checked is not a confirmation.

    Winter's reviewer reported a real local defect — a discarded 404 — as a
    security weakness, and a verifier confirmed it, without either of them
    opening the caller. Every caller validates with the identical predicate on
    the identical object first, so the finding was refutable by reading one
    function. Both prompts already said to read the callers. They had said it
    for weeks.

    So this is not another sentence of prose. `confirmed` is downgraded to
    `uncertain` unless the vote states what would have refuted the finding and
    where it looked, and — where the finding rests on being reachable by an
    unauthenticated caller — which entry point that is. `uncertain` is a real
    answer here, the same way it is everywhere else in this project: a
    consistent "I could not establish it" beats a confident guess.
    """
    if vote.verdict != VERDICT_CONFIRMED:
        return vote

    missing = []
    if len(vote.control_search) < MIN_EVIDENCE_CHARS:
        missing.append("what it searched for that would refute the finding")
    if (vote.corrected_reachable or "").lower() == "yes" and (
            len(vote.entry_point) < MIN_EVIDENCE_CHARS):
        missing.append("the entry point an unauthenticated attacker comes through")
    if not missing:
        return vote

    return replace(
        vote,
        verdict=VERDICT_UNCERTAIN,
        reasoning=(
            "{} (downgraded from confirmed: the verdict did not state {})"
        ).format(vote.reasoning, " or ".join(missing)).strip(),
    )


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
    vote = _vote_from_payload(data)
    if vote is not None:
        vote.channel = "final_message"
    return vote


def _vote_from_payload(data: Any) -> Optional[Vote]:
    """One verdict payload to one `Vote`, whichever channel carried it.

    Both routes end here on purpose. A schema-constrained final message and a
    `submit_verdict` argument are two transports for the same object, and two
    conversions would be two definitions of what a verdict means — with the
    less-used one drifting quietly until a runner disagreed with itself.
    """
    if not isinstance(data, dict) or "verdict" not in data:
        return None
    verdict = str(data.get("verdict", "")).strip()
    if verdict not in (VERDICT_CONFIRMED, VERDICT_UNCERTAIN, VERDICT_REFUTED):
        return None
    return _require_evidence(Vote(
        verdict=verdict,
        reasoning=str(data.get("reasoning", "")).strip(),
        corrected_impact=str(data.get("corrected_impact", "") or "").strip(),
        corrected_reachable=str(
            data.get("corrected_reachable_without_authentication", "") or "").strip(),
        corrected_interaction=str(
            data.get("corrected_requires_user_interaction", "") or "").strip(),
        corrected_confidence=str(data.get("corrected_confidence", "") or "").strip(),
        removes_control=str(data.get("removes_existing_control", "") or "").strip().lower(),
        control_search=str(data.get("control_search", "") or "").strip(),
        entry_point=str(data.get("entry_point", "") or "").strip(),
    ))


# ---------------------------------------------------------------- aggregation


def _decide(candidate: Candidate) -> None:
    """Apply the panel's decision to the candidate.

    The decision itself is `panel.decide`, which computes it from the finding
    and the votes and touches nothing. Applying it and computing it are split
    because the session document loader has to ask the same question about a
    disposition somebody else recorded, and it has no candidate to write into.
    Two answers to that question is the defect this split closes: the loader
    used to bound severity and confidence instead of recomputing them, and a
    stored `low` confidence that no panel would have produced sat inside the
    bound — under the gate.
    """
    usable = [v for v in candidate.votes if not v.error]
    if not usable:
        candidate.verdict = VERDICT_CONFIRMED
        errors = "; ".join(v.error for v in candidate.votes if v.error)
        candidate.verdict_reason = (
            "reported unverified — verification could not run ({})".format(
                errors or "no verifier responded")
        )
        return

    # The finding and the votes, and nothing about the candidate's current
    # state. `decide` establishes its own starting rating, so calling this twice
    # gives the same answer both times rather than reading the first answer as
    # the second one's starting point.
    decided = decide(candidate.finding, candidate.votes)
    candidate.verdict = decided.verdict
    # Prose about the decision rather than part of it, so it stays here: a
    # finding that was never verified carries a reason its caller wrote, and
    # the loader cannot recompute either one.
    candidate.verdict_reason = _reason(usable, decided.verdict)
    candidate.removes_control = decided.removes_control
    candidate.severity = decided.severity
    candidate.severity_derivation = decided.severity_derivation
    candidate.confidence = decided.confidence


def _reason(votes: List[Vote], verdict: str) -> str:
    """Pick the verifier reasoning that best explains the aggregate verdict."""
    preferred = [v for v in votes if v.verdict == verdict and v.reasoning]
    if preferred:
        head = preferred[0].reasoning
    else:
        head = next((v.reasoning for v in votes if v.reasoning), "")
    # What was looked for, beside what was concluded. A confirmation is only
    # worth as much as the refutation that was attempted, and a reader
    # overruling the gate needs to see which one that was.
    search = next((v.control_search for v in votes
                   if v.verdict == verdict and v.control_search), "")
    if search:
        head = "{} Searched: {}".format(head, search).strip()
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
        # The whole file when it is small. A sixty-line window is an arbitrary
        # boundary, and the control that decides a finding is routinely on the
        # other side of it — the verifier then spends a turn on `read_file` to
        # fetch what could have arrived for less. Anthropic's filter pastes the
        # whole file unconditionally; the cap is what makes it safe to copy,
        # since an unbounded prompt is how one claim eats the response budget.
        if len(file_text) <= cfg.verifier_context_chars:
            parts += [
                "## Starting context",
                "",
                "`{}`, in full ({} characters). Other files are still yours to "
                "read with the tools.".format(finding.file, len(file_text)),
                "",
                "```",
                file_text,
                "```",
                "",
            ]
        else:
            window, start, stop = excerpt(file_text, candidate.line, radius=60)
            parts += [
                "## Starting context",
                "",
                "`{}` lines {}-{} of a {}-character file (read more of it, and "
                "other files, with the tools):".format(
                    finding.file, start, stop, len(file_text)),
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
