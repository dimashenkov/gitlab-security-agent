"""Command line entry point — the whole run, in order."""

from __future__ import annotations

import argparse
import logging
import os
import sys
from pathlib import Path
from typing import Optional, Sequence

from . import __version__
from .config import Config, ConfigError
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

    from .agent import SecurityAgent
    from .briefing import build as build_briefing
    from .gitlab import publish
    from .report import ReportError, render_markdown, render_terminal, write_artifacts
    from .suppress import SuppressionError
    from .suppress import apply as apply_suppressions
    from .suppress import load as load_rules
    from .verify import verify_candidates

    if _skip_requested(cfg, args):
        return EXIT_OK

    root = Path(args.repo or ".").resolve()
    mode = args.mode or cfg.resolve_mode()

    base, head = _resolve_range(cfg, root, mode, args)
    workspace = Workspace(root=root, excludes=cfg.excludes, diff_base=base, diff_head=head)

    if mode == "diff":
        changed = workspace.changed_files()
        if not changed:
            log.info("no reviewable files changed in this merge request — nothing to do")
            return EXIT_OK
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

    if not _has_credentials():
        log.error(
            "no Anthropic credentials found. Set ANTHROPIC_API_KEY as a masked "
            "CI/CD variable on the project."
        )
        return EXIT_ERROR

    client = anthropic.Anthropic(max_retries=cfg.max_retries, timeout=cfg.request_timeout)
    agent = SecurityAgent(cfg, workspace, client=client)

    log.info("starting review — model=%s effort=%s mode=%s", cfg.model, cfg.effort, mode)
    outcome = agent.run(mode=mode, briefing=build_briefing(cfg, workspace, mode))
    candidates = list(agent.candidates)
    log.info(
        "agent finished: %s, %d turn(s), %d candidate finding(s)",
        outcome.stop_reason, outcome.turns, len(candidates),
    )

    # Layers 2 and 3 of the hallucination check. Layer 1 already ran inside
    # `report_finding`, so everything here cites code that provably exists.
    if candidates:
        log.info("verifying %d finding(s)", len(candidates))
        outcome.verification_usage = verify_candidates(
            cfg, workspace, client, candidates,
            provenance=outcome.provenance, metrics=outcome.metrics)

    # A suppression the change itself adds cannot excuse that change.
    ignore_touched = any(
        path == str(cfg.ignore_file).lstrip("./")
        for path, _ in workspace.changed_files()
    )
    if ignore_touched and rules:
        log.warning(
            "%s is edited by this change, so its entries do not apply here — "
            "they take effect from the next change onward", cfg.ignore_file)
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
    log.info("wrote %s and %s", paths["markdown"], paths["json"])
    print(render_terminal(outcome, decision))

    if cfg.post_comment and not args.no_comment:
        publish(cfg.gitlab, render_markdown(cfg, outcome, decision))

    _log_verdict(decision)
    return decision.exit_code


# ------------------------------------------------------------------- helpers


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

    head = args.head or gl.source_branch_sha or "HEAD"
    if not probe.rev_exists(head):
        head = "HEAD"

    if mode != "diff":
        return "", head

    if args.base:
        if not probe.rev_exists(args.base):
            raise WorkspaceError(
                "base revision {!r} is not in this clone".format(args.base))
        return args.base, head

    if probe.rev_exists(gl.diff_base_sha):
        return gl.diff_base_sha, head

    for candidate in ("origin/" + gl.default_branch, gl.default_branch):
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


def _log_verdict(decision) -> None:
    if decision.exit_code == EXIT_OK:
        log.info("PASS — %s", decision.reason)
    elif decision.exit_code == EXIT_ERROR:
        log.error("ERROR — %s", decision.reason)
    else:
        log.error("BLOCKED — %s", decision.reason)


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
