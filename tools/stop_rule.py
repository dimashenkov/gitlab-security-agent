#!/usr/bin/env python3
"""Apply `D-013` to the artifacts on disk: does this configuration stop?

    tools/stop_rule.py            # the two rates and the verdict
    tools/stop_rule.py --rows     # every case that contributes, and how

## Why this exists

`D-013` names two thresholds — recall below 65%, or an alert on the patched
member above 40% — and the numbers it was written against came out of a
throwaway script. A stop rule whose numbers nobody can recompute is not a stop
rule; it is a sentence. This is the rule as code, so the same question asked in
three months gets the same answer from the same files.

## What it deliberately does not do

**It cannot say "pass".** There is no such branch, because 78 pairs cannot
carry one — see `D-013`. The verdict is `stop` or `no catastrophe`, and the
second is not an endorsement. Anyone quoting this as evidence of acceptance is
quoting something it does not contain.

**It does not compute precision.** The corpus is a 50/50 mixture of vulnerable
and patched members, and a precision drawn from that balance is not a statement
about what a reader in a pipeline experiences. `D-013` withdrew that number for
exactly this reason and this tool will not print it.
"""

from __future__ import annotations

import argparse
import glob
import json
import math
import sys
from pathlib import Path
from typing import Dict, Optional, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent))

from artifact import instant

ROOT = Path(__file__).resolve().parents[1]

# From `D-013`. Constants, not literals buried in a branch: the rule is
# supposed to be readable without following the code that applies it.
RECALL_FLOOR = 0.65
PATCHED_ALERT_CEILING = 0.40


def wilson(hits: int, total: int, z: float = 1.96) -> Tuple[float, float]:
    """A confidence interval that behaves at the edges.

    Wilson rather than the textbook normal approximation, which gives an
    interval running past 100% — or a width of zero — exactly where a small
    corpus lands most often. With 78 cases that is not an academic point.
    """
    if not total:
        return (0.0, 0.0)
    p = hits / total
    denominator = 1 + z * z / total
    centre = (p + z * z / (2 * total)) / denominator
    spread = z * math.sqrt(p * (1 - p) / total + z * z / (4 * total * total))
    spread /= denominator
    return (max(0.0, centre - spread), min(1.0, centre + spread))


def latest_rows() -> Dict[str, dict]:
    """The most recent row per case, from every measurement file.

    Ordered by `artifact.instant`, the same reader `check_accounted` and
    `stage2` use. Not by string: `…T14:00:00+03:00` sorts after
    `…T12:00:00+00:00` and is two hours earlier. Not by filename either —
    `round.compare` settled a case that way until 2026-09-03, and renaming two
    files moved its answer.
    """
    best: Dict[str, Tuple[Optional[object], dict]] = {}
    for path in glob.glob(str(ROOT / "measurements" / "**" / "*.json"),
                          recursive=True):
        if Path(path).name == "manifest.json":
            continue
        try:
            stored = json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        # A batch file is a list of rows; an experiment writes one row per
        # file, as an object. Reading only lists opened the file, parsed it,
        # and iterated it as nothing.
        for row in (stored if isinstance(stored, list) else [stored]):
            if not isinstance(row, dict):
                continue
            case_id = row.get("case_id")
            if not case_id:
                continue
            when = instant(row.get("ran_at"))
            held = best.get(case_id)
            if held is None:
                best[case_id] = (when, row)
                continue
            kept_when, _kept = held
            # An undated row answers only when nothing dated does — the rule
            # `stage2._settle` follows. Two undated rows used to be settled by
            # whichever the glob handed over last.
            if when is not None and (kept_when is None or when > kept_when):
                best[case_id] = (when, row)
    return {case_id: row for case_id, (_when, row) in best.items()}


def rates(rows: Dict[str, dict]) -> dict:
    """The two numbers `D-013` thresholds, and the counts behind them.

    `is True` / `is False`, never `bool(...)`. `pair_corpus` writes these only
    on the success path, so a review that crashed carries neither — and
    `bool(None)` is `False`, which would score a run that never happened as a
    miss. A stored `"false"` would go the other way and read as a hit.
    """
    found = missed = fired = quiet = 0
    for row in rows.values():
        recall = row.get("unsafe_recall")
        if recall is True:
            found += 1
        elif recall is False:
            missed += 1
        alert = row.get("safe_false_positive")
        if alert is True:
            fired += 1
        elif alert is False:
            quiet += 1
    return {
        "found": found, "missed": missed, "fired": fired, "quiet": quiet,
        "unsafe_total": found + missed, "safe_total": fired + quiet,
    }


def verdict(counts: dict) -> Tuple[str, list]:
    """`stop`, `no catastrophe`, or `cannot say` — never `pass`.

    "Cannot say" is a real answer and gets its own exit code. A corpus with no
    usable rows must not read as one that found no catastrophe: this is the
    tool that decides whether a configuration is abandoned, and the difference
    between "nothing is wrong" and "nothing was measured" is the whole subject
    of this repository.
    """
    reasons = []
    if not counts["unsafe_total"] or not counts["safe_total"]:
        return "cannot say", ["no usable rows on one side of the pair"]

    recall = counts["found"] / counts["unsafe_total"]
    alert = counts["fired"] / counts["safe_total"]
    if recall < RECALL_FLOOR:
        reasons.append("recall {:.0%} is below the {:.0%} floor".format(
            recall, RECALL_FLOOR))
    if alert > PATCHED_ALERT_CEILING:
        reasons.append("alerts on the fix {:.0%} exceed the {:.0%} ceiling"
                       .format(alert, PATCHED_ALERT_CEILING))
    return ("stop" if reasons else "no catastrophe"), reasons


def render(counts: dict, decision: str, reasons: list) -> str:
    lines = ["{} case(s) with a usable latest row".format(
        max(counts["unsafe_total"], counts["safe_total"])), ""]
    lines.append("                     alerts   quiet")
    lines.append("  vulnerable      {:>8} {:>7}".format(
        counts["found"], counts["missed"]))
    lines.append("  patched         {:>8} {:>7}".format(
        counts["fired"], counts["quiet"]))
    lines.append("")
    for name, hits, total, floor, ceiling in (
            ("recall", counts["found"], counts["unsafe_total"],
             RECALL_FLOOR, None),
            ("alert on the fix", counts["fired"], counts["safe_total"],
             None, PATCHED_ALERT_CEILING)):
        if not total:
            lines.append("  {:<18} no usable rows".format(name))
            continue
        low, high = wilson(hits, total)
        bound = ("floor {:.0%}".format(floor) if floor is not None
                 else "ceiling {:.0%}".format(ceiling))
        lines.append("  {:<18} {:>3}/{:<3} = {:>3.0%}   95% CI {:.0%}–{:.0%}"
                     "   {}".format(name, hits, total, hits / total,
                                    low, high, bound))
    lines.append("")
    lines.append("  verdict: {}".format(decision))
    for reason in reasons:
        lines.append("    {}".format(reason))
    if decision == "no catastrophe":
        lines.append("    Not a pass. This rule has no pass branch — see "
                     "D-013 — and cannot see a drop under 13 points.")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--rows", action="store_true",
                        help="list every contributing case")
    args = parser.parse_args()

    rows = latest_rows()
    counts = rates(rows)
    decision, reasons = verdict(counts)
    print(render(counts, decision, reasons))

    if args.rows:
        print()
        for case_id in sorted(rows):
            row = rows[case_id]
            print("  {:<24} recall={!r:<6} alert={!r:<6} {}".format(
                case_id, row.get("unsafe_recall"),
                row.get("safe_false_positive"), row.get("ran_at") or "undated"))

    # 1 is "stop", the same code the product uses for "there is something
    # blocking". 2 is "could not answer", never 0 — a crash must not exit like
    # a clean result.
    return {"stop": 1, "no catastrophe": 0, "cannot say": 2}[decision]


if __name__ == "__main__":
    raise SystemExit(main())
