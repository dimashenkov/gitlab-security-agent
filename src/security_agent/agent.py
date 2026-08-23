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
    STOP_ERROR,
    STOP_REFUSAL,
    STOP_TIME_LIMIT,
    STOP_TURN_LIMIT,
    Provenance,
    ScanOutcome,
    ToolCallRecord,
    Usage,
)
from .tools import Session, dispatch, load_finding_schema, tool_definitions
from .transport import TransportFailure, split_capability_error, stream_message
from .workspace import Workspace

log = logging.getLogger(__name__)

# A security reviewer discusses exploitation for a living, so a policy decline is
# a realistic failure mode for this workload specifically. With server-side
# fallbacks enabled the API re-runs the turn on another model inside the same
# call instead of handing back a dead run.
BETA_FALLBACK = "server-side-fallback-2026-07-01"
# Task budgets let the model pace an open-ended investigation and land it, rather
# than being cut off mid-trace by a ceiling it cannot see.
BETA_TASK_BUDGET = "task-budgets-2026-03-13"


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
        if diff_available:
            outcome.coverage.changed = [path for path, _ in self.ws.changed_files()]
        deadline = time.monotonic() + self.cfg.max_runtime_seconds
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
                response = self._request(system, messages, tools)
            except anthropic.APIStatusError as exc:
                stop_reason = STOP_ERROR
                stop_detail = "API error {}: {}".format(
                    exc.status_code, getattr(exc, "message", str(exc)))
                break
            except (anthropic.APIConnectionError, TransportFailure) as exc:
                stop_reason = STOP_ERROR
                stop_detail = "could not reach the Claude API: {}".format(exc)
                break

            self.usage.add(response.usage)
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
                stop_reason = STOP_ERROR
                stop_detail = (
                    "a single response hit max_tokens ({}); raise "
                    "SECURITY_SCAN_MAX_TOKENS".format(self.cfg.max_tokens)
                )
                break

            messages.append({"role": "assistant", "content": response.content})

            if response.stop_reason == "pause_turn":
                # A server-side tool paused mid-turn; resending the history
                # resumes it. Nothing to execute on our side.
                continue

            tool_uses = [b for b in response.content if getattr(b, "type", "") == "tool_use"]
            if not tool_uses:
                summary = _final_text(response)
                stop_reason = STOP_COMPLETED
                break

            results = self._execute(tool_uses)
            self._move_cache_breakpoint(results)
            messages.append({"role": "user", "content": results})

        outcome.stop_reason = stop_reason
        outcome.stop_detail = stop_detail
        outcome.summary = summary.strip()
        outcome.turns = self.session.turn
        outcome.tool_calls = list(self.session.tool_calls)
        outcome.files_examined = list(self.session.files_examined)
        outcome.coverage.examined = list(self.session.files_examined)
        outcome.metrics = self.session.metrics
        outcome.rejected_claims = list(self.session.rejected)
        outcome.duplicates_dropped = self.session.duplicates_dropped
        outcome.usage = self.usage
        return outcome

    @property
    def candidates(self) -> List[Any]:
        return self.session.candidates

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
    ) -> Any:
        params: Dict[str, Any] = {
            "model": self.cfg.model,
            "max_tokens": self.cfg.max_tokens,
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
