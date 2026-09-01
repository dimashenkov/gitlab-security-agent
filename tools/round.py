#!/usr/bin/env python3
"""Freeze what a repeat run is, before it is bought — then read it afterwards.

    tools/round.py freeze 1 --scope approved
    tools/round.py freeze 1 --scope approved --dry-run
    tools/round.py compare 1

## Why this exists rather than just running the queue again

Codex's objection to buying 140 reviews without it, and it is the whole point:

> You would then possess 140 valid contemporary reviews but no valid stability
> experiment.

A second pass answers "did the verdict move" only if it is decided **in
advance** which pass-2 row each pass-1 row is comparable to, and under what
rule they count as agreeing. Deciding either afterwards — once the
disagreements are visible — produces a number chosen to fit them. So the case
list, the order, the environment and the endpoints are written once, before
anything is spent, and the file refuses to be overwritten.

## Three things the manifest fixes that would otherwise be decided later

**Which cases have a comparable baseline.** Fourteen of the sixty-two have
never run, so they cannot contribute to stability at all — they contribute a
first observation of recall and nothing else. Left implicit, they would quietly
join a denominator they do not belong in.

**The order.** The queue runs alphabetically, which puts every `cs-` case in
the first window and every `ts-` case in the last. Language would then be
confounded with the window, the reset, and whatever the plan does at its
boundary, and no amount of care afterwards separates them. The order here is a
shuffle seeded by the round number: reproducible, recorded, and not
alphabetical.

**What "the same" means.** `case_digest` per case, the prompt and schema
hashes, the adjudication file's hash, the model and profile. If any of them
moves between the passes, the comparison is between two different questions and
the file says so rather than a reader having to notice.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, ClassVar, Dict, List, Optional

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "src"))

import check_accounted  # noqa: E402
import run_queue  # noqa: E402
from artifact import case_digest, legacy_case_digest  # noqa: E402

FIVE_LANGUAGES = ("go", "php", "py", "ts", "js")


class Sweep:
    """The shape `run_queue.cases` expects, with nothing selected."""

    # A stand-in for the parsed arguments `run_queue.cases` reads, with
    # nothing selected. It is never mutated and never instantiated twice,
    # so the shared-default hazard the rule warns about cannot arise —
    # but the rule is right in general, so the exemption is written here
    # rather than switched off for the file.
    case: ClassVar[List[str]] = []
    language = None
    construction = None


def digest_of(path: Path) -> str:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()[:16]
    except OSError:
        return ""


def environment() -> Dict[str, Any]:
    """Everything that would make two passes answer different questions."""
    return {
        "agent_version": (ROOT / "src" / "security_agent" / "__init__.py")
        .read_text(encoding="utf-8").split('__version__ = "')[1].split('"')[0],
        "system_prompt": digest_of(ROOT / "prompts" / "system.md"),
        "verifier_prompt": digest_of(ROOT / "prompts" / "verifier.md"),
        "findings_schema": digest_of(ROOT / "prompts" / "findings.schema.json"),
        # Not part of what the reviewer sees, and part of what its answer means:
        # a ruling added between the passes rescores a verdict without rerunning
        # anything.
        "adjudications": digest_of(ROOT / "corpus-real" / "adjudications.yml"),
    }


def baselines() -> Dict[str, Dict[str, Any]]:
    """The verdict each case already has, and where it came from.

    Taken from `check_accounted.verdicts()`, which only counts a row that says
    which version of the case it saw. A case whose only rows predate that record
    has no comparable baseline, and saying so here is the difference between a
    stability denominator and a wish.
    """
    return {case_id: {"pair_success": passed}
            for case_id, passed in check_accounted.verdicts().items()}


def scope_cases(scope: str) -> List[str]:
    eligible = run_queue.cases(Sweep())
    if scope == "all":
        return sorted(eligible)
    if scope == "five":
        return sorted(c for c in eligible
                      if c.split("-")[0] in FIVE_LANGUAGES)
    if scope == "approved":
        # What the owner agreed to on 2026-08-31: the five languages, plus every
        # case that has never run, plus rb-g65v — whose ruling is correct and
        # excuses nothing until the row carries a fingerprint.
        five = {c for c in eligible if c.split("-")[0] in FIVE_LANGUAGES}
        unrun = set(check_accounted.account().get("unrun", [])) & set(eligible)
        held = {"rb-g65v-27r3-5p6m", "rb-g65v-27r3-5p6m-snap"} & set(eligible)
        return sorted(five | unrun | held)
    raise SystemExit("unknown scope {!r}".format(scope))


def manifest_path(number: int) -> Path:
    return ROOT / "measurements" / "round-{}".format(number) / "manifest.json"


def build(number: int, scope: str) -> Dict[str, Any]:
    chosen = scope_cases(scope)
    known = baselines()

    rows = []
    for case_id in chosen:
        directory = ROOT / "corpus-real" / case_id
        body = {}
        manifest = directory / "case.yml"
        if manifest.is_file():
            import yaml
            body = yaml.safe_load(manifest.read_text(encoding="utf-8")) or {}
        rows.append({
            "case_id": case_id,
            "language": body.get("language", ""),
            "construction": body.get("construction", ""),
            "case_digest": case_digest(directory),
            "legacy_case_digest": legacy_case_digest(directory),
            # The half that decides what this case can answer.
            "baseline": known.get(case_id),
            "contributes_to": (["stability", "recall"] if case_id in known
                               else ["recall"]),
        })

    # Seeded by the round number so it is reproducible from the file alone, and
    # shuffled so no language sits entirely inside one window.
    order = [r["case_id"] for r in rows]
    random.Random(number).shuffle(order)

    comparable = [r for r in rows if r["baseline"] is not None]
    return {
        "round": number,
        "scope": scope,
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "environment": environment(),
        "protocol": {
            "provider": "claude-cli",
            "profile": "normal",
            "order": order,
            "order_seed": number,
            # Written down because choosing it after seeing the disagreements is
            # how a threshold gets fitted to them.
            "primary_endpoint":
                "per case, whether pair_success is the same as the baseline's. "
                "Reported as agreed / flipped, over the cases that have a "
                "baseline and nothing else.",
            "secondary_endpoints": [
                "recall in this pass, over every case in the round",
                "agreement on which findings match the case's target",
            ],
            "excluded_from_stability":
                "cases with no baseline — they have never run, so there is "
                "nothing to have moved",
        },
        "counts": {
            "cases": len(rows),
            "reviews": 2 * len(rows),
            "with_baseline": len(comparable),
            "without_baseline": len(rows) - len(comparable),
        },
        "cases": rows,
    }


def freeze(number: int, scope: str, dry_run: bool) -> int:
    path = manifest_path(number)
    if path.exists() and not dry_run:
        print("{} already exists. A frozen round is not rewritten — that is "
              "what freezing it was for. Use the next number."
              .format(path.relative_to(ROOT)))
        return 1

    body = build(number, scope)
    counts = body["counts"]
    print("round {} · scope {}".format(number, scope))
    print("  {} case(s), {} review(s)".format(counts["cases"], counts["reviews"]))
    print("  {} with a baseline — the stability denominator".format(
        counts["with_baseline"]))
    print("  {} without one; they answer recall only".format(
        counts["without_baseline"]))
    print("  order: shuffled, seed {}".format(number))
    if dry_run:
        print("\nNothing written.")
        return 0

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(body, indent=2, ensure_ascii=False) + "\n",
                    encoding="utf-8")
    print("\nWritten to {}. Run the queue with:".format(path.relative_to(ROOT)))
    print("  tools/run_queue.py --round {} --case ... (see the manifest order)"
          .format(number))
    return 0


def compare(number: int) -> int:
    """Read a finished round against the manifest that was frozen before it."""
    path = manifest_path(number)
    if not path.is_file():
        print("No manifest for round {}. It was never frozen, so there is no "
              "rule to compare against and none may be invented now."
              .format(number))
        return 2
    body = json.loads(path.read_text(encoding="utf-8"))

    directory = path.parent
    results: Dict[str, Any] = {}
    for result in sorted(directory.glob("*.json")):
        if result.name == "manifest.json":
            continue
        try:
            rows = json.loads(result.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        for row in rows if isinstance(rows, list) else []:
            if isinstance(row, dict) and row.get("case_id") and not row.get("incomplete"):
                results[row["case_id"]] = row

    now = environment()
    drifted = [k for k, v in body["environment"].items() if now.get(k) != v]
    if drifted:
        print("Changed since the round was frozen: {}. The two passes are not "
              "answering the same question and the comparison below is not a "
              "stability measurement.\n".format(", ".join(sorted(drifted))))

    agreed = flipped = missing = 0
    moves: List[str] = []
    for case in body["cases"]:
        if "stability" not in case["contributes_to"]:
            continue
        row = results.get(case["case_id"])
        if row is None:
            missing += 1
            continue
        before = case["baseline"]["pair_success"]
        after = bool(row.get("pair_success"))
        if before == after:
            agreed += 1
        else:
            flipped += 1
            moves.append("{}: {} -> {}".format(case["case_id"], before, after))

    total = agreed + flipped
    print("stability, over the {} case(s) frozen with a baseline:".format(
        body["counts"]["with_baseline"]))
    print("  {} agreed, {} flipped, {} not yet run".format(agreed, flipped, missing))
    for line in moves:
        print("    " + line)
    if total:
        print("  {:.0%} agreement — one pass against one pass, so this bounds "
              "instability and cannot establish stability.".format(agreed / total))
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)

    it = sub.add_parser("freeze", help="write the manifest for a round")
    it.add_argument("number", type=int)
    it.add_argument("--scope", default="approved",
                    choices=("approved", "five", "all"))
    it.add_argument("--dry-run", action="store_true")

    done = sub.add_parser("compare", help="read a round against its manifest")
    done.add_argument("number", type=int)

    args = parser.parse_args(argv)
    if args.command == "freeze":
        return freeze(args.number, args.scope, args.dry_run)
    return compare(args.number)


if __name__ == "__main__":
    raise SystemExit(main())
