"""The agent loop.

A manual loop rather than the SDK's tool runner, because a blocking CI gate
needs things the runner does not surface: a hard turn ceiling, a wall-clock
ceiling, a moving prompt-cache breakpoint over a conversation that grows every
turn, and — most importantly — the ability to distinguish "reviewed everything
and found nothing" from "ran out of turns". Only the first may report a clean
pass, and conflating them is how a security gate becomes theatre.
"""

from __future__ import annotations

import hashlib
import logging
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import anthropic

from .config import Config
from .models import (
    STOP_BUDGET,
    STOP_COMPLETED,
    STOP_CONTEXT,
    STOP_ERROR,
    STOP_REFUSAL,
    STOP_RESPONSE_TOO_LONG,
    STOP_TIME_LIMIT,
    STOP_TRANSPORT,
    STOP_TURN_LIMIT,
    Provenance,
    Revision,
    ScanOutcome,
    ToolCallRecord,
    TurnRecord,
    Usage,
)
from .tools import Session, dispatch, load_finding_schema, tool_definitions
from .transport import TransportFailure, split_capability_error, stream_message
from .workspace import Workspace

log = logging.getLogger(__name__)

# What the API says when the conversation no longer fits. Matched on the
# message rather than the status code alone: a 400 is also how a malformed
# request arrives, and the two need different answers — one means read less,
# the other means fix the code.
_CONTEXT_MARKERS = ("prompt is too long", "context window", "too many tokens",
                    "maximum context length", "exceeds the maximum")


def _is_context_error(status_code: int, message: str) -> bool:
    """Did the conversation outgrow the model, or is this a different 400?

    This distinction is the whole reason `error` was split. Four reviews
    stopped early and every one of them recorded `error`, so the question
    "did it read more than it could hold, or did the network drop" had no
    answer in the artifact — only in `stop_detail`, which nothing kept.
    """
    if status_code != 400:
        return False
    lowered = (message or "").lower()
    return any(marker in lowered for marker in _CONTEXT_MARKERS)

# A security reviewer discusses exploitation for a living, so a policy decline is
# a realistic failure mode for this workload specifically. With server-side
# fallbacks enabled the API re-runs the turn on another model inside the same
# call instead of handing back a dead run.
BETA_FALLBACK = "server-side-fallback-2026-07-01"
# Task budgets let the model pace an open-ended investigation and land it, rather
# than being cut off mid-trace by a ceiling it cannot see.
BETA_TASK_BUDGET = "task-budgets-2026-03-13"

# The most room a single response may be given. `max_tokens` covers thinking as
# well as output under adaptive thinking, so a hard security question at high
# effort can exhaust a 32k ceiling before the model reaches its tool call. This
# is the ceiling the retry may climb to, not the default.
MAX_RESPONSE_TOKENS = 64_000

# The only stop reasons that mean the model finished a turn on its own terms.
# `pause_turn` and `max_tokens` are handled before this and never reach it.
FINISHED_CLEANLY = frozenset({"end_turn", "tool_use", "stop_sequence"})

# Reasons the API can return that mean the turn was cut short. Named so the
# artifact says which, rather than recording a review that never finished as
# one that finished and found nothing.
_API_STOP_REASONS = {
    "model_context_window_exceeded": STOP_CONTEXT,
    "context_window_exceeded": STOP_CONTEXT,
}


def _turn_record(turn: int, response: Any, max_tokens: int, replay: bool) -> TurnRecord:
    usage = getattr(response, "usage", None)

    def count(name: str) -> int:
        return int(getattr(usage, name, 0) or 0) if usage else 0

    return TurnRecord(
        turn=turn,
        input_tokens=count("input_tokens"),
        output_tokens=count("output_tokens"),
        cache_read_tokens=count("cache_read_input_tokens"),
        cache_write_tokens=count("cache_creation_input_tokens"),
        max_tokens=max_tokens,
        stop_reason=str(getattr(response, "stop_reason", "") or ""),
        replay=replay,
    )


def _stop_reason_for(api_stop_reason: Optional[str]) -> str:
    """Map an unexpected API stop reason onto one of ours.

    Unknown maps to `error` rather than to `completed`. A reason nobody has
    read the documentation for is not evidence that the review finished.
    """
    return _API_STOP_REASONS.get(api_stop_reason or "", STOP_ERROR)


@dataclass
class Capabilities:
    """Which optional API features this run uses.

    Both are on by default and dropped together, once, if the account cannot use
    them. A scanner that hard-fails because an org lacks a beta is a scanner that
    gets deleted from the pipeline.
    """

    task_budget: bool = True
    refusal_fallback: bool = True

    @property
    def betas(self) -> List[str]:
        betas = []
        if self.task_budget:
            betas.append(BETA_TASK_BUDGET)
        if self.refusal_fallback:
            betas.append(BETA_FALLBACK)
        return betas

    @property
    def any_enabled(self) -> bool:
        return bool(self.betas)


class SecurityAgent:
    def __init__(self, cfg: Config, workspace: Workspace, client: Optional[Any] = None) -> None:
        self.cfg = cfg
        self.ws = workspace
        self.client = client or anthropic.Anthropic(
            max_retries=cfg.max_retries,
            timeout=cfg.request_timeout,
        )
        self.session = Session()
        self.usage = Usage()
        self.caps = Capabilities(
            task_budget=cfg.use_task_budget,
            refusal_fallback=cfg.use_refusal_fallback,
        )
        self._cached_block: Optional[Dict[str, Any]] = None

    # ------------------------------------------------------------------ run

    def run(self, mode: str, briefing: str) -> ScanOutcome:
        diff_available = bool(self.ws.diff_base) and mode == "diff"
        finding_schema = load_finding_schema(self.cfg.resolved_prompt_dir())
        tools = tool_definitions(finding_schema, diff_available=diff_available)
        system = self._system_blocks()

        messages: List[Dict[str, Any]] = [
            {"role": "user", "content": [{"type": "text", "text": briefing}]}
        ]

        outcome = ScanOutcome(mode=mode, model=self.cfg.model)
        outcome.provenance = _provenance(self.cfg)
        outcome.revision = self._revision(mode)
        if diff_available:
            outcome.coverage.changed = [path for path, _ in self.ws.changed_files()]
            if getattr(self.ws, "scope", ()):
                outcome.coverage.out_of_scope = self.ws.out_of_scope(
                    [path for path, _ in self.ws.all_changed_files()])
        deadline = time.monotonic() + self.cfg.max_runtime_seconds
        # Raised once, and kept raised. A review that needed the room on one
        # turn will very likely need it again, and paying for a truncated
        # response to discover that a second time is waste.
        ceiling = self.cfg.max_tokens
        replayed = False
        stop_reason = STOP_COMPLETED
        stop_detail = ""
        summary = ""

        while True:
            if self.session.turn >= self.cfg.max_turns:
                stop_reason = STOP_TURN_LIMIT
                stop_detail = "hit the turn limit of {} (SECURITY_SCAN_MAX_TURNS)".format(
                    self.cfg.max_turns)
                break
            if time.monotonic() > deadline:
                stop_reason = STOP_TIME_LIMIT
                stop_detail = "hit the time limit of {}s (SECURITY_SCAN_MAX_RUNTIME)".format(
                    self.cfg.max_runtime_seconds)
                break
            if self.usage.output_tokens > self.cfg.max_output_tokens_total:
                stop_reason = STOP_BUDGET
                stop_detail = "hit the output budget of {} tokens".format(
                    self.cfg.max_output_tokens_total)
                break

            self.session.turn += 1
            try:
                response = self._request(system, messages, tools, ceiling)
            except anthropic.APIStatusError as exc:
                message = getattr(exc, "message", "") or str(exc)
                stop_reason = (
                    STOP_CONTEXT if _is_context_error(exc.status_code, message)
                    else STOP_ERROR
                )
                stop_detail = "API error {}: {}".format(exc.status_code, message)
                break
            except (anthropic.APIConnectionError, TransportFailure) as exc:
                stop_reason = STOP_TRANSPORT
                stop_detail = "could not reach the Claude API: {}".format(exc)
                break

            self.usage.add(response.usage)
            outcome.turn_records.append(_turn_record(
                self.session.turn, response, ceiling, replay=replayed))
            replayed = False
            outcome.provenance.note_served(getattr(response, "model", "") or self.cfg.model)
            self._log_turn(response)

            if response.stop_reason == "refusal":
                stop_reason = STOP_REFUSAL
                detail = getattr(response, "stop_details", None)
                category = getattr(detail, "category", None) if detail else None
                stop_detail = "the model declined to continue the review" + (
                    " (category: {})".format(category) if category else "")
                break

            if response.stop_reason == "max_tokens":
                # Recoverable, and worth recovering: the truncated response was
                # never appended to `messages` (the break above happens first),
                # so the conversation is exactly as it was and the turn can be
                # replayed with more room. Adaptive thinking counts toward
                # `max_tokens`, so the turn that hits this is the turn the model
                # thought hardest about — which on a matched pair is the member
                # that has something to find. Ending the review there loses
                # precisely the reviews that were working.
                if ceiling < MAX_RESPONSE_TOKENS:
                    ceiling = min(ceiling * 2, MAX_RESPONSE_TOKENS)
                    self.session.turn -= 1        # the turn did not happen
                    replayed = True
                    log.info("response truncated; replaying the turn with "
                             "max_tokens=%d", ceiling)
                    continue
                stop_reason = STOP_RESPONSE_TOO_LONG
                stop_detail = (
                    "a single response hit max_tokens twice, at {} and {}; "
                    "raise SECURITY_SCAN_MAX_TOKENS or lower "
                    "SECURITY_SCAN_EFFORT".format(self.cfg.max_tokens, ceiling)
                )
                break

            messages.append({"role": "assistant", "content": response.content})

            if response.stop_reason == "pause_turn":
                # A server-side tool paused mid-turn; resending the history
                # resumes it. Nothing to execute on our side.
                continue

            # An allowlist, not a chain of special cases. Everything the loop
            # did not name fell through to the branch below, and a response
            # with no tool call was then declared a completed review — so
            # `model_context_window_exceeded`, which is what current models
            # return instead of a 400 when generation reaches the context
            # limit, would have reported a clean pass on a review that ran out
            # of room. That is the one thing this product must never do, and
            # the deny-list shape guarantees the next unnamed reason does it
            # again.
            if response.stop_reason not in FINISHED_CLEANLY:
                stop_reason = _stop_reason_for(response.stop_reason)
                stop_detail = "the API ended the turn with stop_reason={!r}".format(
                    response.stop_reason)
                break

            tool_uses = [b for b in response.content if getattr(b, "type", "") == "tool_use"]
            if not tool_uses:
                summary = _final_text(response)
                stop_reason = STOP_COMPLETED
                break

            results = self._execute(tool_uses)
            self._move_cache_breakpoint(results)
            messages.append({"role": "user", "content": results})

            if self.session.finished:
                # The reviewer said so itself, which is the only statement both
                # runners can read the same way. Everything else — the process
                # exiting, the model falling silent — is inference about a
                # provider's loop.
                summary = self.session.final_summary
                stop_reason = STOP_COMPLETED
                break

        outcome.stop_reason = stop_reason
        outcome.stop_detail = stop_detail
        outcome.summary = summary.strip()
        # Recorded, not gated. A review that ends on `end_turn` without calling
        # `finish_review` still completed as far as the Messages API is
        # concerned — the model chose to stop — so turning this into a failure
        # today would fail runs that are fine. It is written down so the rate
        # can be read off twenty real reviews instead of guessed at, and
        # tightened when there is a number.
        outcome.finished_explicitly = self.session.finished
        outcome.unresolved = list(self.session.unresolved)
        outcome.turns = self.session.turn
        outcome.tool_calls = list(self.session.tool_calls)
        outcome.files_examined = list(self.session.files_examined)
        # What actually reached the model, which is what the gate reads to
        # tell a review that stopped early from one that never started.
        outcome.exposures = list(self.session.exposures)
        outcome.coverage.examined = list(self.session.files_examined)
        outcome.coverage.diff_truncated = self.ws.diff_truncated
        outcome.metrics = self.session.metrics
        outcome.rejected_claims = list(self.session.rejected)
        outcome.duplicates_dropped = self.session.duplicates_dropped
        outcome.usage = self.usage
        return outcome

    @property
    def candidates(self) -> List[Any]:
        return self.session.candidates

    def _revision(self, mode: str) -> Revision:
        """Resolve what was reviewed to commits, not to names.

        `HEAD` and a branch name point somewhere different tomorrow, so an
        archived artifact that records only the symbolic form cannot say what
        it read. Both are kept: the symbolic form is what the pipeline was
        configured with, the SHA is what identifies the commit.
        """
        def resolve(rev: str) -> str:
            if not rev:
                return ""
            return self.ws.git("rev-parse", rev, check=False).strip()

        base = self.ws.diff_base if mode == "diff" else ""
        head = self.ws.diff_head or "HEAD"
        return Revision(mode=mode, base=base, head=head,
                        base_sha=resolve(base), head_sha=resolve(head))

    # -------------------------------------------------------------- requests

    def _system_blocks(self) -> List[Dict[str, Any]]:
        """The system prompt, as a single cacheable block.

        Nothing run-specific goes in here. Per-run context lives in the first
        user message instead, so this prefix — tool definitions plus system
        prompt — is byte-identical across every turn *and* every pipeline, which
        is what makes a one-hour cache TTL worth paying for.
        """
        path = self.cfg.resolved_prompt_dir() / "system.md"
        return [{
            "type": "text",
            "text": path.read_text(encoding="utf-8"),
            "cache_control": {"type": "ephemeral", "ttl": self.cfg.cache_ttl},
        }]

    def _request(
        self,
        system: List[Dict[str, Any]],
        messages: List[Dict[str, Any]],
        tools: List[Dict[str, Any]],
        max_tokens: Optional[int] = None,
    ) -> Any:
        params: Dict[str, Any] = {
            "model": self.cfg.model,
            "max_tokens": max_tokens or self.cfg.max_tokens,
            "system": system,
            "messages": messages,
            "tools": tools,
            "thinking": {"type": "adaptive"},
            "output_config": {"effort": self.cfg.effort},
        }
        if self.caps.task_budget:
            params["output_config"]["task_budget"] = {
                "type": "tokens",
                "total": self.cfg.task_budget_tokens,
            }

        try:
            return self._stream(params, self.caps)
        except anthropic.BadRequestError as exc:
            if not self.caps.any_enabled or not _is_capability_error(exc):
                raise
            log.warning(
                "retrying without optional betas (%s): %s",
                ", ".join(self.caps.betas), getattr(exc, "message", exc),
            )
            self.caps = Capabilities(task_budget=False, refusal_fallback=False)
            params["output_config"].pop("task_budget", None)
            return self._stream(params, self.caps)

    def _stream(self, params: Dict[str, Any], caps: Capabilities) -> Any:
        return stream_message(
            self.client,
            params,
            betas=caps.betas or None,
            fallbacks="default" if caps.refusal_fallback else None,
            label="turn {}".format(self.session.turn),
        )

    # ----------------------------------------------------------------- tools

    def _execute(self, tool_uses: List[Any]) -> List[Dict[str, Any]]:
        """Run every tool call from one assistant turn.

        All results go back in a single user message. Splitting them across
        messages teaches the model to stop issuing parallel calls, which costs
        turns on exactly the wide searches this review depends on.
        """
        results: List[Dict[str, Any]] = []
        for block in tool_uses:
            name = getattr(block, "name", "")
            args = getattr(block, "input", {}) or {}
            result = dispatch(self.ws, self.session, name, args)
            self.session.tool_calls.append(ToolCallRecord(
                turn=self.session.turn,
                name=name,
                arguments=args if isinstance(args, dict) else {},
                summary=result.summary,
                is_error=result.is_error,
            ))
            log.info("  %-20s %s%s", name, result.summary,
                     " [rejected]" if result.is_error else "")
            entry: Dict[str, Any] = {
                "type": "tool_result",
                "tool_use_id": block.id,
                "content": result.content or "(no output)",
            }
            if result.is_error:
                entry["is_error"] = True
            results.append(entry)
        return results

    def _move_cache_breakpoint(self, results: List[Dict[str, Any]]) -> None:
        """Keep one rolling cache breakpoint at the end of the conversation.

        The prefix only ever grows, so marking the newest tool result means the
        next turn reads everything before it from cache. The previous marker is
        removed first: breakpoints are limited per request, and leaving a trail
        of them would exhaust the allowance within a few turns.
        """
        if self._cached_block is not None:
            self._cached_block.pop("cache_control", None)
            self._cached_block = None
        if not results:
            return
        results[-1]["cache_control"] = {"type": "ephemeral"}
        self._cached_block = results[-1]

    # --------------------------------------------------------------- logging

    def _log_turn(self, response: Any) -> None:
        served = getattr(response, "model", "") or self.cfg.model
        log.info(
            "turn %d — stop=%s in=%s cache_read=%s out=%s%s",
            self.session.turn,
            response.stop_reason,
            getattr(response.usage, "input_tokens", "?"),
            getattr(response.usage, "cache_read_input_tokens", 0),
            getattr(response.usage, "output_tokens", "?"),
            " served_by={}".format(served) if served != self.cfg.model else "",
        )
        for block in response.content:
            if getattr(block, "type", "") == "text" and block.text.strip():
                log.debug("  note: %s", block.text.strip()[:2000])


def _provenance(cfg: Config) -> Provenance:
    """Hash what the verdict depends on, so a changed verdict has an explanation.

    Prompts and the finding schema are read from disk at run time, which is what
    makes them easy to iterate on and also what makes them invisible when they
    change. Recording their hashes puts "the prompt moved" and "the model was
    substituted" in the artifact next to the verdict, rather than leaving a
    reviewer to wonder why the same code was judged differently.
    """
    from . import __version__

    prompts = cfg.resolved_prompt_dir()
    return Provenance(
        # Both paths stamp this. A field only one runner sets is a field
        # every reader has to special-case, and the reader that decides
        # whether a local run was billed would have read an empty string.
        provider=cfg.provider,
        model_requested=cfg.model,
        system_prompt_sha=_sha(prompts / "system.md"),
        verifier_prompt_sha=_sha(prompts / "verifier.md"),
        schema_sha=_sha(prompts / "findings.schema.json"),
        agent_version=__version__,
    )


def _sha(path) -> str:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()[:16]
    except OSError:
        return ""


def _final_text(response: Any) -> str:
    return "\n\n".join(
        block.text for block in response.content
        if getattr(block, "type", "") == "text" and block.text.strip()
    )


def _is_capability_error(exc: Exception) -> bool:
    """Is this 400 about an unavailable beta, rather than a malformed request?"""
    capability, _ = split_capability_error(exc)
    return capability
