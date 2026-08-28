"""Adversarial verification through the developer's own `claude`, not the API.

`verify.py` runs each verifier as a conversation this process drives, turn by
turn, against the Messages API — and every one of those turns is money. That is
the right thing in CI and the wrong thing on a laptop, where the rule this
project holds itself to (*a cosmetic change does not justify a paid run*) has
already stopped verification from being exercised for days at a time. This
module runs the same panel through the `claude` CLI, under the login that CLI
already has rather than under an API key.

## What is the same, deliberately

Everything that decides anything. The brief is `verify._brief`, the prompt is
`verify._system_blocks`, the verdict is read by `verify._vote_from_payload` —
which is what applies `_require_evidence` — and the panel is `verify._decide`.
None of that is restated here, because a second reading of a verdict is a second
definition of what a verdict means, and the less-used copy drifts quietly until
one runner disagrees with the other about whether a merge blocks.

What changes is only the transport: instead of our loop calling the API, the CLI
owns the loop and our tools answer it over MCP, exactly as `runner_claude_code`
already does for the review. The verifier's tool set has no `report_finding`
and its only way to answer is `submit_verdict`, so on this transport the vote and
the verifier's statement that it is finished are the same act — which is the only
kind of "done" a provider running its own loop can produce.

## What this file is written against

**A verifier that did not vote must never render as one that agreed.** On this
transport there are many more ways for that to happen than on the API: the CLI
can exit zero having done nothing, the child can be killed before it writes its
session document, the document can belong to another run, or it can be there
with no verdict in it. Every one of those ends in a `Vote` carrying `error`.
`verify._decide` treats an errored vote as unusable, and a candidate whose votes
all errored is reported *unverified* — never confirmed by a panel that never
spoke.

**A seat is reserved before a session starts.** `RunBudget.reserve_verifier`
hands out the seat and that verifier's own tool-call allowance in one step,
because these sessions run concurrently in separate processes and a counter read
across that boundary is a race inside the security decision. The reservations
happen on this thread, before any process is launched, so how many verifiers a
run gets does not depend on how the pool happened to schedule them.
"""

from __future__ import annotations

import json
import logging
import shutil
import tempfile
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, List, Optional, Tuple

from . import runner_claude_code as runner
from .budget import Allowance, RunBudget
from .config import Config
from .mcp_server import VERIFIER
from .models import (
    VERDICT_CONFIRMED,
    VERDICT_UNCERTAIN,
    Candidate,
    Revision,
    Vote,
)
from .session_document import SessionDocumentError, read_session
from .verify import (
    _brief,
    _decide,
    _partition,
    _system_blocks,
    _tagged,
    _vote_from_payload,
    _votes_for,
    _why_not_gating,
)
from .workspace import Workspace

log = logging.getLogger(__name__)

# The channel a verdict arrives through on this transport. There is only one:
# the CLI's final message is prose we never constrain with a schema, so a vote
# that did not come through the tool is not a vote.
CHANNEL = "submit_verdict"


def verify_candidates_with_cli(
    cfg: Config,
    ws: Workspace,
    candidates: List[Candidate],
    budget: RunBudget,
    *,
    executable: str = "claude",
    config_digest: str = "",
    revision: Optional[Revision] = None,
    provenance: Optional[Any] = None,
    metrics: Optional[Any] = None,
) -> None:
    """Verify every candidate in place, the way `verify.verify_candidates` does.

    Returns nothing rather than a `Usage`. The Messages API reports tokens per
    turn and this runner never sees a turn; reporting a zero would put "nobody
    counted" and "nothing was spent" in the same field, which is the confusion
    `RunBudget.summary` already refuses to make.

    `revision` is the one argument the API path has no use for. The verifier's
    session document is bound to the commits it describes, so both processes
    have to name the same pair; when the caller does not supply them they are
    resolved from the workspace here rather than left empty, because an empty
    base also takes the diff tools away from the verifier — and whether the
    change *removed* a control is a question that cannot be answered without
    them.
    """
    ClaudeCodeVerifier(
        cfg, ws, budget, executable=executable, config_digest=config_digest,
        revision=revision,
    ).verify(candidates, provenance=provenance, metrics=metrics)


class ClaudeCodeVerifier:
    """One run's panel, each vote a `claude -p` session answered by our tools."""

    def __init__(
        self,
        cfg: Config,
        workspace: Workspace,
        budget: RunBudget,
        *,
        executable: str = "claude",
        config_digest: str = "",
        revision: Optional[Revision] = None,
    ) -> None:
        self.cfg = cfg
        self.ws = workspace
        self.budget = budget
        self.executable = executable
        self.config_digest = config_digest
        self.revision = revision if revision is not None else _revision_of(workspace)
        self.run_id = uuid.uuid4().hex[:16]

    # ---------------------------------------------------------------- panel

    def verify(
        self,
        candidates: List[Candidate],
        *,
        provenance: Optional[Any] = None,
        metrics: Optional[Any] = None,
    ) -> None:
        if not candidates:
            return

        if not self.cfg.verify:
            for candidate in candidates:
                _skip(candidate, "verification disabled (SECURITY_SCAN_VERIFY=false)")
            return

        # Which findings are worth a session, and how many votes each gets, are
        # decisions with long arguments behind them in `verify.py`. They are
        # called, never restated: a runner that verified a different set than
        # the API path would make the two incomparable, which is the whole
        # reason this project can measure anything.
        gating, informational = _partition(self.cfg, candidates)
        for candidate in informational:
            _skip(candidate, (
                "not verified — reported for information only, as it cannot "
                "block the merge at the current settings ({})".format(
                    _why_not_gating(self.cfg, candidate))))
        to_verify = gating[: self.cfg.verify_max_findings]
        for candidate in gating[self.cfg.verify_max_findings:]:
            log.warning(
                "verifying only the first %d of %d findings (SECURITY_SCAN_VERIFY_MAX)",
                len(to_verify), len(gating))
            _skip(candidate, (
                "not verified — beyond the SECURITY_SCAN_VERIFY_MAX limit of "
                "{}".format(self.cfg.verify_max_findings)))
        if metrics is not None:
            metrics.verification_skipped += len(informational)
            metrics.verified += len(gating)
        if not to_verify:
            return

        path = runner.cli_available(self.executable)
        if path is None:
            # The same refusal the review runner makes, for the same reason:
            # there is no route from here to the paid API, because which
            # account is charged is not a decision to make on somebody's
            # behalf. Raised rather than turned into an errored vote per
            # finding — "every verifier failed" describes a panel that ran and
            # could not answer, and nothing ran here at all.
            raise runner.RunnerError(
                "the `{}` command is not on PATH, so no verifier can be run. "
                "This runner will not fall back to the paid API.".format(
                    self.executable))

        jobs = [
            (candidate, vote_index)
            for candidate in to_verify
            for vote_index in range(_votes_for(self.cfg, candidate))
        ]
        # Reserved here, on one thread, before anything is launched. Doing it
        # inside the workers would have several sessions each observe spare
        # capacity and start together — which is how a panel of three becomes a
        # panel of six — and would also make the number of verifiers a run got
        # depend on the scheduler rather than on the profile.
        seats = [self.budget.reserve_verifier() for _ in jobs]

        root = Path(tempfile.mkdtemp(prefix="security-verify-"))
        try:
            votes = self._run_panel(path, jobs, seats, root)
        finally:
            # Every document has been read back by now; what is left is the
            # transcript-free scratch space the sessions ran in.
            shutil.rmtree(root, ignore_errors=True)

        # Attached in job order rather than completion order, so a rerun of the
        # same findings aggregates identically whichever session finished first.
        for (candidate, _index), vote in zip(jobs, votes):
            candidate.votes.append(vote)
            if provenance is not None:
                for model in vote.served_models:
                    provenance.note_served(model)

        for candidate in to_verify:
            for number, vote in enumerate(candidate.votes, start=1):
                log.info(
                    "  [%s] vote %d: %s — %s",
                    candidate.finding.title[:40], number,
                    vote.verdict if not vote.error else "unavailable",
                    (vote.error or vote.reasoning)[:180])
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
            log.info("  verdict: %s — %s", candidate.verdict,
                     candidate.verdict_reason[:200])

    def _run_panel(
        self,
        path: str,
        jobs: List[Tuple[Candidate, int]],
        seats: List[Optional[Allowance]],
        root: Path,
    ) -> List[Vote]:
        """One vote per job, in slot order, whatever happened to each session."""
        votes: List[Optional[Vote]] = [None] * len(jobs)
        for slot, seat in enumerate(seats):
            if seat is None:
                # No seat, no session — and no silent drop either. The panel
                # gets a vote that says it was never cast, which `_decide`
                # counts as unusable.
                votes[slot] = _failed(
                    "no verifier session was available: this run's budget of {} "
                    "verifier session(s) was already committed, so this claim "
                    "was not checked".format(self.budget.profile.verifier_sessions))

        live = [slot for slot, seat in enumerate(seats) if seat is not None]
        if live:
            workers = max(1, min(self.cfg.verify_concurrency, len(live)))
            log.info("running %d verifier session(s) across %d worker(s)",
                     len(live), workers)
            with ThreadPoolExecutor(max_workers=workers) as pool:
                futures = {}
                for slot in live:
                    candidate, vote_index = jobs[slot]
                    futures[pool.submit(
                        self._one_vote, path, candidate, vote_index,
                        seats[slot], root, slot)] = slot
                for future in as_completed(futures):
                    slot = futures[future]
                    try:
                        votes[slot] = future.result()
                    except Exception as exc:  # a worker must not take the run down
                        log.exception("a verifier session raised")
                        votes[slot] = _failed(
                            "the verifier session raised {}: {}".format(
                                type(exc).__name__, exc))

        # Every slot was filled above, on all three paths. The cast is here so
        # a future edit that forgets one fails a type check rather than putting
        # a `None` where a vote belongs.
        return [vote if vote is not None else _failed(
            "no vote was recorded for this verifier session") for vote in votes]

    # ----------------------------------------------------------- one session

    def _one_vote(
        self,
        path: str,
        candidate: Candidate,
        vote_index: int,
        allowance: Allowance,
        root: Path,
        slot: int,
    ) -> Vote:
        """Run one verifier to a vote, or to an error that says why there is none."""
        # A run id per session, not per run. The document a session reads back
        # must be the one that session wrote: with one id, a stale document
        # from a sibling — same run, same commits, same config — would satisfy
        # every binding check and be read as this verifier's vote.
        run_id = "{}.{}".format(self.run_id, slot)
        handoff = runner.Handoff(root / "vote-{}".format(slot), run_id,
                                 self.config_digest)
        handoff.mcp_config.write_text(json.dumps(runner.build_mcp_config(
            repo=self.ws.root,
            base_sha=self.revision.base_sha,
            head_sha=self.revision.head_sha,
            tool_set=VERIFIER,
            allowance=allowance,
            handoff=handoff,
            # Deliberately no scope. Scope narrows which findings a run is
            # answerable for; this finding has already passed that filter, and
            # narrowing what the verifier may look at would hide the deletion
            # elsewhere in the change that decides `removes_existing_control`.
        ), indent=2), encoding="utf-8")

        command = runner.build_command(
            executable=path,
            # The prompt file the API path reads, through the function that
            # decides which file that is.
            system_prompt=_system_blocks(self.cfg)[0]["text"],
            mcp_config=handoff.mcp_config,
            model=self.cfg.verifier_model,
        )
        result = self._launch(
            command, _brief(self.cfg, self.ws, candidate, vote_index), handoff)
        return self._collect(handoff, result, allowance, run_id)

    def _launch(
        self, command: List[str], brief: str, handoff: runner.Handoff
    ) -> runner.CliResult:
        """Run one session to completion, or kill it when the run's time is up.

        One clock for the whole run, as the review runner uses: verifiers are
        the last stage, and a per-session deadline that fitted comfortably could
        still let three of them run past the profile's limit together.
        """
        remaining = max(1.0, self.budget.profile.runtime_seconds - self.budget.elapsed)
        # The shared launcher, which kills a process group rather than one
        # process. `subprocess.run(timeout=...)` left our MCP server running
        # against the hostile checkout after the parent had moved on, racing the
        # collection of this session's files and the deletion of its directory.
        return runner.launch(
            command, stdin=brief, cwd=handoff.cwd, timeout=remaining,
            limit_seconds=self.budget.profile.runtime_seconds)

    def _collect(
        self,
        handoff: runner.Handoff,
        result: runner.CliResult,
        allowance: Allowance,
        run_id: str,
    ) -> Vote:
        """The vote this session cast, or an error naming what stopped it.

        A recorded verdict is accepted even when the CLI's own ending was
        untidy: `submit_verdict` is refused twice, so a verdict in the document
        is the verifier's single considered answer *and* its statement that it
        had finished, and discarding it would shrink the panel over something
        that happened afterwards.

        A killed session is the exception, and not for tidiness. The child
        server writes its document when its client's pipes close — which is
        what killing the CLI does — so a document may appear *while* this
        function runs. Reading it would be reading a session that was still
        going when the deadline cut it off, and a verdict reached under a
        truncated search is exactly the thing this project refuses to present as
        a checked result.
        """
        self._fold_spend(handoff, allowance)

        if result.killed:
            return _failed(result.detail or "the verifier was stopped at its deadline")

        if not handoff.session_document.exists():
            # Whatever the CLI said about itself, this session never reached
            # its end. The crash journal is then the whole story, and it is
            # diagnostics — how far it got — never a verdict.
            # Joined here, deliberately. A `Vote.error` is one string and is
            # only ever read by a person through the report's own escaping, so
            # the two halves can travel together — unlike `stop_detail`, where
            # the report has to know which kind of string it is holding.
            sentence, trace = runner._crash_detail(handoff, result)
            return _failed(sentence + ("\n\n" + trace if trace else ""))

        try:
            session = read_session(
                handoff.session_document,
                run_id=run_id,
                revision=self.revision,
                config_digest=self.config_digest,
            )
        except SessionDocumentError as exc:
            # A document that exists and cannot be trusted is worse than none:
            # it has the shape of an answer.
            return _failed(
                "the verifier wrote a session document this run cannot accept: "
                "{}".format(exc))

        served = _served_models(result, self.cfg)
        if session.verdict is None:
            return _tagged(_failed(
                "the verifier ended without submitting a verdict ({}); a claim "
                "with no vote behind it is not verified".format(_ending(result))
            ), served, session)

        vote = _vote_from_payload(session.verdict)
        if vote is None:
            return _tagged(_failed(
                "the verifier submitted a verdict that could not be read"
            ), served, session)

        # Which channel carried it, recorded rather than assumed: a verdict
        # submitted as a tool argument and one scraped out of a final message
        # are not equally trustworthy, and the artifact should not pretend they
        # are the same event.
        vote.channel = CHANNEL
        return _tagged(vote, served, session)

    @staticmethod
    def _fold_spend(handoff: runner.Handoff, allowance: Allowance) -> None:
        """Copy the child's spending onto the allowance this process holds.

        The allowance was handed over whole and spent in another process. Left
        unfolded, the run's usage report would show a ceiling that was allocated
        and never touched, which reads as capacity nobody needed.
        """
        spent = handoff.spent_tool_calls()
        if spent is None:
            return
        for _ in range(spent):
            allowance.note_tool_call()


# --------------------------------------------------------------------- pieces


def _failed(error: str) -> Vote:
    """A vote that was not cast, in the one shape `_decide` treats as unusable.

    `uncertain` rather than anything else because the field is required and no
    verdict was reached; what makes this vote unusable is `error` being set, and
    every path that could not produce a verdict comes through here so that none
    of them can accidentally produce a verdict instead.
    """
    return Vote(verdict=VERDICT_UNCERTAIN, reasoning="", error=error)


def _skip(candidate: Candidate, reason: str) -> None:
    """Record a finding that was never verified, and why, in one place."""
    candidate.verdict = VERDICT_CONFIRMED
    candidate.verdict_reason = reason


def _ending(result: runner.CliResult) -> str:
    """How the session ended, for the error of a vote that never arrived."""
    if result.failed:
        return result.detail or "the CLI produced no usable output"
    unnamed = runner._unnamed(result.subtype)
    if unnamed:
        return unnamed
    return "the session ended with {!r}".format(result.subtype)


def _served_models(result: runner.CliResult, cfg: Config) -> List[str]:
    """Which model actually answered, taken from the CLI when it says.

    A server-side fallback can substitute a model mid-session, and a blocking
    verdict should be able to say which one reached it. What the CLI reports is
    preferred over what we asked for, because the second is an intention and the
    first is an observation.
    """
    usage = result.payload.get("modelUsage")
    if isinstance(usage, dict) and usage:
        return [str(name) for name in usage]
    model = result.payload.get("model")
    if isinstance(model, str) and model:
        return [model]
    return [cfg.verifier_model] if cfg.verifier_model else []


def _revision_of(ws: Workspace) -> Revision:
    """The commits the verifier is asked about, resolved to SHAs.

    Both processes have to name the same pair or the session document is
    refused, and `main` names different code on different days. Resolution that
    fails leaves the SHA empty on both sides, which still agrees — it just says
    less.
    """
    head = ws.diff_head or "HEAD"

    def resolve(rev: str) -> str:
        return ws.git("rev-parse", rev, check=False).strip() if rev else ""

    return Revision(
        mode="diff" if ws.diff_base else "repo",
        base=ws.diff_base,
        head=head,
        base_sha=resolve(ws.diff_base),
        head_sha=resolve(head),
    )
