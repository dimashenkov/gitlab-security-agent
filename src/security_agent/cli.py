"""Command line entry point — the whole run, in order."""

from __future__ import annotations

import argparse
import logging
import os
import sys
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Optional, Sequence

from . import __version__
from .config import PROVIDER_API, PROVIDER_CLI, PROVIDERS, Config, ConfigError
from .gate import EXIT_ERROR, EXIT_OK, decide
from .models import VERDICT_REFUTED
from .workspace import Workspace, WorkspaceError

log = logging.getLogger("security_agent")


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    _configure_logging(args.verbose, args.quiet)

    try:
        cfg = _build_config(args)
    except ConfigError as exc:
        log.error("configuration error: %s", exc)
        return EXIT_ERROR

    try:
        return _run(cfg, args)
    except WorkspaceError as exc:
        log.error("%s", exc)
        return EXIT_ERROR
    except KeyboardInterrupt:
        log.error("interrupted")
        return EXIT_ERROR
    except Exception:
        # An uncaught exception would let the interpreter exit 1, which in this
        # tool's vocabulary means "the code has blocking findings" — a crash
        # would be indistinguishable from a vulnerability. Every unexpected
        # failure is exit 2: the check did not run.
        log.exception("the security review crashed")
        return EXIT_ERROR


def _run(cfg: Config, args: argparse.Namespace) -> int:
    # Imported here so `--help` and config errors do not pay for the SDK import.
    import anthropic

    from . import terminal
    from .agent import SecurityAgent
    from .briefing import build as build_briefing
    from .forge import publish
    from .report import ReportError, render_markdown, write_artifacts
    from .suppress import SuppressionError
    from .suppress import apply as apply_suppressions
    from .suppress import load as load_rules
    from .verify import verify_candidates

    if _skip_requested(cfg, args):
        return EXIT_OK

    root = Path(args.repo or ".").resolve()
    # `--changed-only` is a diff review with a name a person would reach for.
    # An explicit `--mode` still wins, so the two cannot disagree silently.
    mode = args.mode or ("diff" if args.changed_only else cfg.resolve_mode())

    base, head = _resolve_range(cfg, root, mode, args)
    workspace = Workspace(root=root, excludes=cfg.excludes, diff_base=base,
                          diff_head=head, scope=cfg.scope,
                          diff_ceiling=cfg.diff_ceiling_bytes)

    # Before anything else about the change is decided: can it rewrite the
    # rules it is judged by?
    #
    # It used to be asked further down, after the empty-review return — so a
    # change that edited a prompt and touched no reviewable file exited 0
    # without the question being put. And it was asked of the *filtered* list,
    # so an exclude pattern or a `--path` covering the prompt directory
    # answered it. Both are the same defect: a guard whose input the guarded
    # party supplies.
    from .config import prompt_dir_risk

    risk = prompt_dir_risk(cfg.resolved_prompt_dir(), root,
                           workspace.raw_changed_paths())
    if risk and risk.startswith("REFUSE"):
        log.error("%s", risk[len("REFUSE: "):])
        return EXIT_ERROR
    if risk:
        log.warning("%s", risk)

    if mode == "diff":
        changed = workspace.changed_files()
        if cfg.scope:
            skipped = workspace.out_of_scope(
                [path for path, _ in workspace.all_changed_files()])
            log.info("scope %s: reviewing %d of %d changed file(s)",
                     ", ".join(cfg.scope), len(changed), len(changed) + len(skipped))
        if not changed:
            # Not a bare return. That left no artifact and, worse, left the
            # previous run's note on the merge request still claiming its
            # verdict — so a change that removed the vulnerable file kept the
            # comment that found it. An empty diff is a real result and gets a
            # real artifact.
            log.info("no reviewable files changed — writing an empty result")
            return _nothing_to_review(cfg, args, mode, base, head)
        log.info("reviewing %d changed file(s) in %s..%s",
                 len(changed), _abbrev(base), _abbrev(head))
    else:
        log.info("reviewing %d tracked file(s) at %s",
                 len(workspace.tracked_files()), _abbrev(head))

    try:
        rules, warnings = load_rules(root / cfg.ignore_file)
    except SuppressionError as exc:
        log.error("%s", exc)
        return EXIT_ERROR
    for warning in warnings:
        log.warning("%s", warning)
    if rules:
        log.info("%d active suppression rule(s) from %s", len(rules), cfg.ignore_file)

    # Reuse is decided *after* the rules are read, and the rules are part of
    # what makes a stored result the answer to this question. Decided before,
    # an artifact produced when a risk had not yet been accepted was handed
    # back listing findings that entry now silences — and one produced before
    # an entry expired kept hiding what it no longer covers.
    if args.reuse:
        reused = _reuse(cfg, args, root, mode, base, head,
                        suppressions=_suppression_digest(rules))
        if reused is not None:
            return reused

    if cfg.provider == PROVIDER_API and not _has_credentials():
        log.error(
            "no Anthropic credentials found. Set ANTHROPIC_API_KEY as a masked "
            "CI/CD variable on the project."
        )
        return EXIT_ERROR
    if cfg.provider == PROVIDER_CLI:
        # The credential check above is deliberately skipped rather than
        # widened: this runner authenticates as the developer, through the CLI
        # they installed, and an API key present in the environment is the one
        # thing it must not reach for. The runner removes it from the child's
        # environment for the same reason.
        problem = _cli_provider_problem(cfg)
        if problem:
            log.error("%s", problem)
            return EXIT_ERROR

    briefing = build_briefing(cfg, workspace, mode)
    log.info("starting review — provider=%s model=%s effort=%s mode=%s",
             cfg.provider, cfg.model, cfg.effort, mode)

    client = None
    if cfg.provider == PROVIDER_API:
        client = anthropic.Anthropic(max_retries=cfg.max_retries,
                                     timeout=cfg.request_timeout)
        agent = SecurityAgent(cfg, workspace, client=client)
        with _folded("review", "Reviewing the change"):
            outcome = agent.run(mode=mode, briefing=briefing)
        candidates = list(agent.candidates)
    else:
        outcome, candidates, budget, digest = _review_with_cli(
            cfg, workspace, mode, briefing, base, head)

    log.info(
        "agent finished: %s%s, %d turn(s), %d candidate finding(s)",
        outcome.stop_reason,
        # Which limit burned, not just that one did. The log said `error` and
        # left the reader to guess between a context overflow, a bad request
        # and a dead network.
        " ({})".format(outcome.stop_detail) if outcome.stop_detail else "",
        outcome.turns, len(candidates),
    )

    # Layers 2 and 3 of the hallucination check. Layer 1 already ran inside
    # `report_finding`, so everything here cites code that provably exists.
    if candidates:
        with _folded("verify", "Verifying {} finding(s)".format(len(candidates))):
            if client is not None:
                outcome.verification_usage = verify_candidates(
                    cfg, workspace, client, candidates,
                    provenance=outcome.provenance, metrics=outcome.metrics)
            else:
                # Through the same CLI, not the API. Splitting providers
                # mid-review would mean one review's findings were read by two
                # execution paths — and, worse here, that every successful local
                # review still arrived with a bill, which is the one thing this
                # provider exists to prevent.
                from .verify_cli import verify_candidates_with_cli

                verify_candidates_with_cli(
                    cfg, workspace, candidates, budget, config_digest=digest,
                    revision=outcome.revision, provenance=outcome.provenance,
                    metrics=outcome.metrics)

    # A suppression the change itself adds cannot excuse that change.
    # Asked of git, not of the filtered file list. Three things were wrong with
    # the comparison this replaces, and the first alone meant the guard had
    # never once fired since it was written:
    #
    # * `str(".security-agent-ignore.yml").lstrip("./")` strips every leading
    #   character in the *set* `{".", "/"}`, not the prefix `"./"`, so it
    #   produced `security-agent-ignore.yml` and git reports
    #   `.security-agent-ignore.yml`. The two are never equal.
    # * `changed_files()` applies the scope, so `--path src` would have hidden a
    #   root-level suppression file from the guard.
    # * `changed_files()` also applies the excludes, so an exclude pattern
    #   covering the file would have switched the guard off.
    #
    # A merge request that adds a weakness and the entry excusing it, in one
    # commit, is the case this exists for. It was exploitable with three lines
    # of YAML and no knowledge of the finding.
    ignore_touched = workspace.change_touches(str(cfg.ignore_file))
    if ignore_touched and rules:
        log.warning(
            "%s is edited by this change, so its entries do not apply here — "
            "they take effect from the next change onward", cfg.ignore_file)
    # Recorded before the gate reads anything, because it is part of what makes
    # this run's answer this run's answer.
    outcome.suppressions_digest = _suppression_digest(rules)
    kept, suppressed = apply_suppressions(candidates, rules, self_added=ignore_touched)
    outcome.suppressed = suppressed
    outcome.refuted = [c for c in kept if c.verdict == VERDICT_REFUTED]
    outcome.reported = [c for c in kept if c.verdict != VERDICT_REFUTED]

    decision = decide(cfg, outcome)

    try:
        paths = write_artifacts(cfg, outcome, decision)
    except ReportError as exc:
        # Exit 2, not 1: the review may have found real problems, but a report
        # that cannot be written where it was asked to go is a failed check, not
        # a verdict on the code.
        log.error("%s", exc)
        return EXIT_ERROR
    log.debug("wrote %s and %s", paths["markdown"], paths["json"])
    print(terminal.render(outcome, decision, report_path=paths["markdown"]))

    if cfg.post_comment and not args.no_comment:
        publish(cfg.gitlab, render_markdown(cfg, outcome, decision))

    # No closing log line: the rendered banner above already states the verdict,
    # and saying it twice in two formats is how a job log becomes unreadable.
    return decision.exit_code


# ------------------------------------------------------------------- helpers


@contextmanager
def _folded(name: str, title: str):
    """Collapse a noisy phase in the GitLab job log.

    The trace of what the agent read is worth keeping — it is how you audit a
    verdict you disagree with — but it should not be the first thing on screen.
    Folded, it is one clickable line; the verdict stays visible without
    scrolling. Outside GitLab the markers are invisible control characters, so
    there is nothing to switch off.
    """
    from . import terminal

    started = int(time.time())
    sys.stdout.write(terminal.section(name, title, True, started) + "\n")
    sys.stdout.flush()
    try:
        yield
    finally:
        sys.stdout.write(terminal.section(name, "", False, int(time.time())) + "\n")
        sys.stdout.flush()


def _nothing_to_review(cfg: Config, args: argparse.Namespace, mode: str,
                       base: str, head: str) -> int:
    """A completed review of a change with nothing reviewable in it.

    Complete, because it is: every changed file was excluded by configuration,
    and that is an answer rather than a failure. It gets an artifact and a
    posted note for the same reason every other run does — so that the absence
    of a comment always means something went wrong, and the presence of one
    always describes this run rather than the last.
    """
    from .agent import _provenance
    from .gate import decide
    from .models import ScanOutcome
    from .report import ReportError, render_markdown, write_artifacts

    outcome = ScanOutcome(mode=mode, model=cfg.model)
    outcome.provenance = _provenance(cfg)
    outcome.summary = (
        "Every file in this change is excluded by configuration, so there was "
        "nothing to review. This is not a statement about the code."
    )
    decision = decide(cfg, outcome)
    try:
        paths = write_artifacts(cfg, outcome, decision)
    except ReportError as exc:
        log.error("%s", exc)
        return EXIT_ERROR

    from . import terminal

    print(terminal.render(outcome, decision, report_path=paths["markdown"]))
    if cfg.post_comment and not args.no_comment:
        from .forge import publish

        publish(cfg.gitlab, render_markdown(cfg, outcome, decision))
    return decision.exit_code


def _reuse(cfg: Config, args: argparse.Namespace, root: Path, mode: str,
           base: str, head: str, suppressions: str = ""):
    """Return the earlier run's exit code, or None to go and pay for one.

    Reuse is keyed on the whole identity — both revisions, the prompts, the
    schema, the requested model, and every gate setting — not on the pull
    request. A new commit is new code, and Anthropic's action reuses per pull
    request, which is why its own tracker carries a report of the cache
    skipping new commits.

    An incomplete artifact is never reused. It is not a cheaper result, it is
    an absent one, and treating it as an answer is the confusion that turned
    three reviews which never ran into a recall figure.
    """
    import json

    from .agent import _provenance
    from .identity import reusable, review_identity
    from .models import Provenance, Revision

    artifact = Path(cfg.output_dir) / "findings.json"
    if not artifact.is_file():
        return None
    try:
        previous = json.loads(artifact.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None

    probe = Workspace(root=root, excludes=cfg.excludes, diff_base=base, diff_head=head)

    def resolve(rev: str) -> str:
        return probe.git("rev-parse", rev, check=False).strip() if rev else ""

    current = review_identity(
        cfg,
        Revision(mode=mode, base=base, head=head,
                 base_sha=resolve(base), head_sha=resolve(head)),
        Provenance(**{k: v for k, v in (previous.get("provenance") or {}).items()
                      if k in Provenance.__dataclass_fields__}),
        suppressions=suppressions,
    )
    # The prompts and schema are hashed from disk at run time, so the recorded
    # provenance is only a valid stand-in when the files have not moved since.
    current.update({k: v for k, v in _provenance(cfg).to_dict().items()
                    if k in current})

    if not reusable(previous, current):
        return None

    verdict = previous.get("verdict") or {}
    log.info("reusing the review of %s..%s — same code, prompts, model and "
             "settings as the artifact already in %s. Pass --no-reuse to pay "
             "for a replicate.", _abbrev(base), _abbrev(head), cfg.output_dir)
    return int(verdict.get("exit_code", EXIT_OK))


def _skip_requested(cfg: Config, args: argparse.Namespace) -> bool:
    """Honour the documented escape hatch on the merge request itself."""
    label = args.skip_label
    if label and label in cfg.gitlab.mr_labels:
        log.warning(
            "merge request carries the %r label — skipping the security review. "
            "This is recorded in the pipeline, not hidden.", label,
        )
        return True
    return False


def _resolve_range(
    cfg: Config, root: Path, mode: str, args: argparse.Namespace
) -> tuple:
    """Work out which two commits bound the change under review.

    GitLab hands us `CI_MERGE_REQUEST_DIFF_BASE_SHA` — the merge base as of when
    the pipeline was created — which is exactly the right base and needs no
    recomputation. It is only present in merge request pipelines, and only
    reachable when the clone is deep enough, so both cases fall back to a merge
    base computed against the default branch.
    """
    probe = Workspace(root=root, excludes=cfg.excludes)
    gl = cfg.gitlab

    # An explicit head, or one the forge named, must exist. Falling back to
    # local `HEAD` reviewed a different commit and said nothing — the base has
    # raised for exactly this since it was written, and the head silently did
    # the opposite. A head nobody named is `HEAD` by construction and needs no
    # check.
    head = args.head or gl.source_branch_sha
    if head and not probe.rev_exists(head):
        raise WorkspaceError(
            "head revision {!r} is not in this clone, so the review would read "
            "a different commit than the one it was asked about. In a merge "
            "request pipeline this means the clone is too shallow — set "
            "GIT_DEPTH: 0.".format(head))
    head = head or "HEAD"

    if mode != "diff":
        return "", head

    if args.base:
        if not probe.rev_exists(args.base):
            raise WorkspaceError(
                "base revision {!r} is not in this clone".format(args.base))
        return args.base, head

    if probe.rev_exists(gl.diff_base_sha):
        return gl.diff_base_sha, head

    # `origin/HEAD` first: it is what the remote says its default branch is,
    # which beats guessing at a name. A clone whose default is `master`, or a
    # fork whose default was renamed, resolves correctly here and would fall
    # through to a wrong branch — or to no base at all — on the guesses below.
    candidates = []
    origin_head = probe.git(
        "symbolic-ref", "--quiet", "--short", "refs/remotes/origin/HEAD",
        check=False).strip()
    if origin_head:
        candidates.append(origin_head)
    candidates += ["origin/" + gl.default_branch, gl.default_branch]

    for candidate in candidates:
        if probe.rev_exists(candidate):
            merge_base = probe.git("merge-base", candidate, head, check=False).strip()
            if merge_base:
                log.info("diff base: merge base with %s (%s)", candidate, merge_base[:12])
                return merge_base, head

    raise WorkspaceError(
        "cannot determine a diff base. In a merge request pipeline this comes "
        "from CI_MERGE_REQUEST_DIFF_BASE_SHA — make sure the job runs with "
        "GIT_DEPTH: 0 so the base commit is in the clone. Pass --base <sha> to "
        "override, or use --mode repo to review the whole tree."
    )


def _review_with_cli(cfg: Config, workspace, mode: str, briefing: str,
                     base: str, head: str):
    """Run the review through the developer's own `claude`, under its own login.

    Returns the outcome, its candidates, and the budget — the budget because
    verification draws its seats from the same one, and handing it back is what
    keeps the reviewer's allowance and each verifier's allowance disjoint parts
    of a single policy rather than two policies that happen to agree.
    """
    from .budget import PROFILES, RunBudget
    from .runner_claude_code import ClaudeCodeRunner

    profile = PROFILES.get(cfg.profile, PROFILES["normal"])
    # This runner cannot count turns — the CLI has no `--max-turns` — so the
    # budget says so rather than printing a ceiling nobody applied.
    budget = RunBudget(profile=profile, turns_enforced=False)

    revision = _revision_for(mode, base, head, workspace)
    runner = ClaudeCodeRunner(cfg, workspace, budget)
    runner.config_digest = _digest_for(cfg, revision)

    with _folded("review", "Reviewing the change"):
        outcome = runner.run(mode=mode, briefing=briefing, revision=revision)
    return outcome, list(outcome.reported), budget, runner.config_digest


def _digest_for(cfg: Config, revision) -> str:
    """The short key for "what policy produced this".

    Every handoff file is bound to it, so a document written under one set of
    gate settings cannot be read back into a run under another. Same code, other
    policy, different review — and a document accepted across that line would be
    a cheaper answer to a question nobody asked.
    """
    from .agent import _provenance
    from .identity import digest, review_identity

    return digest(review_identity(cfg, revision, _provenance(cfg)))


def _revision_for(mode: str, base: str, head: str, workspace):
    from .models import Revision

    def resolve(rev: str) -> str:
        if not rev:
            return ""
        try:
            return workspace.git("rev-parse", rev).strip()
        except WorkspaceError:
            return ""

    head_sha = resolve(head)
    if not head_sha:
        # Not `or "HEAD"`. That is a name, not a commit, and it was written
        # into the artifact as one — so a review could not say which code it
        # read, and the session document bound itself to a string. The same
        # substitution was removed from the MCP configuration hours earlier and
        # reappeared here.
        raise WorkspaceError(
            "could not resolve {!r} to a commit. A review that cannot name the "
            "code it read cannot be archived, compared or reused.".format(head))
    return Revision(mode=mode, base=base, head=head,
                    base_sha=resolve(base), head_sha=head_sha)


def _suppression_digest(rules) -> str:
    """A stable key for the accepted risks in force.

    Over what each rule matches on **and its reason**, not over the file. Order
    and formatting are not policy, so a reordered list or a reindented entry is
    the same policy and must not refuse a reuse.

    The reason is in, and my first argument for leaving it out was wrong twice.
    It said an edit there would "teach the reader to pass `--force`" — which
    conflates two workflows: `--force` belongs to the baseline comparison and
    reuse is controlled by `--no-reuse`. And the reason is the only field a
    person reads when deciding whether an accepted risk still makes sense, so a
    review reused across a rewritten one is reused across a changed
    justification. Rewriting a reason is rare and deliberate; one fresh review
    is the right price for it.
    """
    import hashlib
    import json

    shape = sorted(
        (getattr(rule, "fingerprint", "") or "",
         getattr(rule, "path", "") or "",
         getattr(rule, "category", "") or "",
         str(getattr(rule, "expires", "") or ""),
         " ".join(str(getattr(rule, "reason", "") or "").split()))
        for rule in rules or ()
    )
    if not shape:
        return ""
    return hashlib.sha256(
        json.dumps(shape, sort_keys=True).encode("utf-8")).hexdigest()[:16]


def _cli_provider_problem(cfg: Config) -> str:
    """Why `--provider claude-cli` cannot run this review, or "".

    Every answer here is a refusal rather than a downgrade. The runner exists to
    stop a review costing money, so the one failure it must never have is
    quietly becoming the paid path — and the second is quietly becoming a
    weaker review that still renders a verdict.
    """
    from .runner_claude_code import (
        AUTH_MISSING,
        AUTH_UNKNOWN,
        authentication,
        cli_available,
    )

    if cli_available() is None:
        return (
            "--provider {} needs the `claude` command on PATH, and it is not "
            "there. This runner uses the CLI you already have; it will not fall "
            "back to the paid API, because which account is charged is not a "
            "decision to make on your behalf.".format(PROVIDER_CLI)
        )

    # Asked before the run rather than discovered during it. A CLI that is
    # installed and not logged in spends the whole launch — process group, MCP
    # server, teardown — to arrive at a generic error, and the check that would
    # have caught "no usable credential" early is deliberately skipped on this
    # path because there is no API key to look for.
    #
    # Only a definite `no` refuses. An older CLI without the subcommand answers
    # `unknown`, and refusing on that would make a working installation
    # unusable on the strength of a guess about its version.
    auth = authentication()
    if auth.state == AUTH_UNKNOWN:
        # Said out loud. The run continues — refusing on "I could not tell"
        # would make a working installation unusable on a guess about its
        # version — but a check that quietly did not happen is a check nobody
        # knows to look into, and the report then carries no billing line for
        # a reason the reader has no way to learn.
        log.warning("could not read the CLI's authentication: %s. The review "
                    "will run and its report will not state a billing mode.",
                    auth.detail)
    if auth.state == AUTH_MISSING:
        return (
            "--provider {} needs a logged-in `claude`, and {}. Run `claude "
            "auth login` first. No review was started and no Anthropic API "
            "fallback was performed.".format(PROVIDER_CLI, auth.detail)
        )
    return ""


def _abbrev(rev: str) -> str:
    """Shorten a SHA for logging, but never a branch name."""
    if len(rev) > 12 and all(c in "0123456789abcdef" for c in rev.lower()):
        return rev[:12]
    return rev


def _has_credentials() -> bool:
    """The SDK resolves several credential sources; only fail when none exist."""
    return any(
        os.environ.get(name)
        for name in ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_PROFILE")
    ) or Path(os.path.expanduser("~/.config/anthropic")).exists()



def _build_config(args: argparse.Namespace) -> Config:
    cfg = Config.from_env()
    if args.model:
        cfg.model = args.model
    if args.effort:
        cfg.effort = args.effort
    if args.fail_on:
        cfg.fail_on = args.fail_on
    if args.min_confidence:
        cfg.min_confidence = args.min_confidence
    if args.max_turns:
        cfg.max_turns = args.max_turns
    if args.path:
        cfg.scope = tuple(args.path)
    if args.provider:
        cfg.provider = args.provider
    if args.profile:
        cfg.profile = args.profile
    if args.output_dir:
        cfg.output_dir = Path(args.output_dir)
    if args.prompt_dir:
        cfg.prompt_dir = Path(args.prompt_dir)
    if args.no_verify:
        cfg.verify = False
    if args.verify_votes:
        cfg.verify_votes = args.verify_votes
    if args.no_comment:
        cfg.post_comment = False
    cfg.validate()
    return cfg


def _configure_logging(verbose: bool, quiet: bool) -> None:
    level = logging.DEBUG if verbose else (logging.WARNING if quiet else logging.INFO)
    logging.basicConfig(
        level=level,
        format="%(message)s",
        stream=sys.stderr,
    )
    # The SDK's own HTTP logging is noise in a job log unless asked for.
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("anthropic").setLevel(
        logging.DEBUG if verbose else logging.WARNING)
    # `-v` is for seeing what the agent did, not for HTTP wire traces. Left
    # alone, httpcore's DEBUG output buries the review in per-frame noise —
    # 150 KB in the first two minutes of a run, with the agent's own lines
    # scattered through it. Set ANTHROPIC_LOG=debug when the transport is
    # genuinely what you need to look at.
    for chatty in ("httpcore", "httpx", "urllib3", "hpack", "h11"):
        logging.getLogger(chatty).setLevel(logging.WARNING)


def _parse_args(argv: Optional[Sequence[str]]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="gitlab-security-agent",
        description=(
            "AI security review for GitLab CI. Reviews a merge request diff (or "
            "a whole repository) with a tool-using agent, verifies every finding "
            "against the real code, and exits non-zero when something should "
            "block the merge."
        ),
        epilog=(
            "Exit codes: 0 nothing blocking · 1 blocking findings · 2 the review "
            "could not be completed."
        ),
    )
    parser.add_argument("--version", action="version", version=__version__)
    parser.add_argument("--repo", metavar="PATH", help="Repository to review (default: cwd).")
    parser.add_argument("--mode", choices=("diff", "repo"),
                        help="Override the automatic diff/repo choice.")
    parser.add_argument("--base", metavar="REV", help="Diff base revision.")
    parser.add_argument("--head", metavar="REV", help="Diff head revision.")
    parser.add_argument(
        "--provider", choices=PROVIDERS,
        help="Who runs the review. {} is the default and what CI uses. {} "
             "shells out to your own `claude`, under whatever login it has — "
             "what that costs is a property of that login, which the run "
             "reports rather than assumes. There is no automatic choice "
             "between them: if the one "
             "you name cannot run, the review fails rather than quietly "
             "charging the other.".format(PROVIDER_API, PROVIDER_CLI))
    parser.add_argument(
        "--profile", choices=("probe", "normal", "deep"),
        help="Ceilings for a local run: time, tool calls and verifier count. "
             "`probe` is small enough to run on every save and is never allowed "
             "to conclude anything — what it finds is a lead. Only the "
             "{} provider reads this.".format(PROVIDER_CLI))
    parser.add_argument(
        "--changed-only", action="store_true",
        help="Review this branch against the commit it left from. Resolves the "
             "base as the merge base with the default branch — not its tip, "
             "which would pull in everyone else's work.")
    parser.add_argument(
        "--path", metavar="PATH", action="append", default=[],
        help="Only be answerable for changed files under this path or matching "
             "this glob. Repeatable. Narrows what is reviewed, never what the "
             "agent may read — it still follows callers anywhere in the "
             "repository, which is the only way a finding gets checked.")
    parser.add_argument("--model", help="Model id (default: claude-opus-5).")
    parser.add_argument("--effort", choices=("low", "medium", "high", "xhigh", "max"))
    parser.add_argument("--fail-on", choices=("critical", "high", "medium", "low", "none"),
                        help="Severity that blocks the merge (default: high).")
    parser.add_argument("--min-confidence", choices=("high", "medium", "low"),
                        help="Lowest confidence that may block (default: medium).")
    parser.add_argument("--max-turns", type=int, help="Cap on agent turns.")
    parser.add_argument("--no-verify", action="store_true",
                        help="Skip adversarial verification (citation checks still run).")
    parser.add_argument("--verify-votes", type=int,
                        help="Independent verifiers per finding (1-5).")
    parser.add_argument("--no-comment", action="store_true",
                        help="Do not post to the merge request.")
    parser.add_argument("--output-dir", metavar="PATH", help="Where to write the report.")
    parser.add_argument("--reuse", action="store_true",
                        help="Exit with the earlier artifact's verdict when the "
                             "code, prompts, schema, model and gate settings all "
                             "match it. A pipeline re-run costs nothing; a new "
                             "commit still pays. An incomplete artifact is never "
                             "reused — it is an absent result, not a cheap one.")
    parser.add_argument("--prompt-dir", metavar="PATH",
                        help="The agent's prompt directory. Never point this inside "
                             "the repository under review.")
    parser.add_argument("--skip-label", default="skip-ai-security",
                        help="Merge request label that skips the review.")
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("-q", "--quiet", action="store_true")
    return parser.parse_args(argv)


if __name__ == "__main__":
    sys.exit(main())
