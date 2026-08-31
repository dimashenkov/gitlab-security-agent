#!/usr/bin/env python3
"""What the reviews on this machine cost, from artifacts already written.

    tools/spend.py                      # every artifact under .security-scan and journal
    tools/spend.py --since 2026-08-01
    tools/spend.py path/to/findings.json ...
    tools/spend.py --by month

**Nothing is sent anywhere.** It reads files this machine already wrote and
prints. A security reviewer that reads private code and then reports usage
outward is a tool many teams will not run at all, and the number is just as
useful on the machine that produced it.

## The distinction the whole tool is built around

`total_cost_usd` is not a bill. The Claude Code CLI reports it on a subscription
too — a two-token reply on a Max plan came back as $0.29 — so on that path it is
what the run *would* have cost at API list price and nobody was charged it. This
project has already built three wrong rules about its weekly allowance by reading
that number as money spent, so the split is not a footnote here: billed and
notional are counted separately, printed separately, and never added together.

Which one a run is comes from `provenance.provider`, not from the size of the
number.

## Absent is not zero

A run whose provider reported no cost contributes to a count of unreported runs
and to no total. Padding it with 0.00 would drag a median toward the floor while
looking like a cheap run, which is the same defect one level up from the one
`Usage` exists to prevent. The same applies to the token counts: `Usage` carries
`unreported_stages` precisely so a total can admit which of its parts it could
not see, and that admission is printed rather than dropped.
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

ROOT = Path(__file__).resolve().parents[1]

# Where an artifact lands by default. `SECURITY_SCAN_OUTPUT_DIR` moves it, so a
# caller with a different layout passes paths instead.
DEFAULT_GLOBS = (".security-scan/**/findings.json", "journal/**/findings.json")

BILLED = "anthropic-api"
NOTIONAL = "claude-cli"

TOKEN_FIELDS = ("input_tokens", "output_tokens",
                "cache_read_tokens", "cache_write_tokens")


def artifacts(paths: Iterable[Path]) -> List[Dict[str, Any]]:
    """Every readable artifact among `paths`, unreadable ones skipped.

    Skipped rather than fatal: this is a report about runs that happened, and
    one corrupt file should not stop it describing the rest. The count of files
    that could not be read is printed, because a silently shorter report is the
    failure this project keeps finding in its own tools.
    """
    out: List[Dict[str, Any]] = []
    for path in paths:
        try:
            body = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if isinstance(body, dict):
            body["_path"] = str(path)
            out.append(body)
    return out


def _provenance(row: Dict[str, Any]) -> Dict[str, Any]:
    value = row.get("provenance")
    return value if isinstance(value, dict) else {}


def cost_of(row: Dict[str, Any]) -> Optional[float]:
    """The reported cost, or None when the provider reported none."""
    value = _provenance(row).get("reported_cost_usd")
    return float(value) if isinstance(value, (int, float)) else None


def billed(row: Dict[str, Any]) -> bool:
    """Was anyone actually charged for this run?

    Decided by the provider, never by whether a number is present: the CLI
    reports a figure on a subscription too, which is the confusion this answers.
    """
    return _provenance(row).get("provider") == BILLED


def who_paid(row: Dict[str, Any]) -> str:
    prov = _provenance(row)
    if prov.get("provider") == BILLED:
        return "API key — billed"
    subscription = prov.get("auth_subscription")
    if subscription:
        return "subscription ({}) — notional".format(subscription)
    if prov.get("provider") == NOTIONAL:
        return "Claude Code login — notional"
    return "unknown"


def when(row: Dict[str, Any]) -> str:
    return str(row.get("generated_at") or "")


def tokens(row: Dict[str, Any]) -> Dict[str, Optional[int]]:
    usage = row.get("usage")
    usage = usage if isinstance(usage, dict) else {}
    return {name: usage.get(name) for name in TOKEN_FIELDS}


def unreported_stages(row: Dict[str, Any]) -> int:
    usage = row.get("usage")
    value = usage.get("unreported_stages") if isinstance(usage, dict) else None
    return value if isinstance(value, int) else 0


def _period(stamp: str, by: str) -> str:
    if not stamp:
        return "undated"
    return stamp[:7] if by == "month" else stamp[:10]


def summarise(rows: List[Dict[str, Any]], by: str = "day",
              unreadable: int = 0) -> int:
    if not rows:
        print("No artifacts found. Point it at a findings.json, or run a "
              "review first.")
        return 2

    groups: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for row in rows:
        groups[_period(when(row), by)].append(row)

    print("{:<12} {:>5} {:>12} {:>12} {:>9}".format(
        by, "runs", "billed $", "notional $", "no cost"))
    print("-" * 54)

    totals = {"billed": [], "notional": [], "silent": 0, "runs": 0}
    for period in sorted(groups):
        members = groups[period]
        bill = [c for c in (cost_of(r) for r in members if billed(r)) if c is not None]
        note = [c for c in (cost_of(r) for r in members if not billed(r)) if c is not None]
        silent = sum(1 for r in members if cost_of(r) is None)
        totals["billed"] += bill
        totals["notional"] += note
        totals["silent"] += silent
        totals["runs"] += len(members)
        print("{:<12} {:>5} {:>12} {:>12} {:>9}".format(
            period, len(members),
            "{:.2f}".format(sum(bill)) if bill else "—",
            "{:.2f}".format(sum(note)) if note else "—",
            silent or "—"))

    print("-" * 54)
    print("{:<12} {:>5} {:>12} {:>12} {:>9}".format(
        "total", totals["runs"],
        "{:.2f}".format(sum(totals["billed"])) if totals["billed"] else "—",
        "{:.2f}".format(sum(totals["notional"])) if totals["notional"] else "—",
        totals["silent"] or "—"))

    # The two columns are never added. Doing so would produce one number that is
    # part bill and part list price, which is the exact confusion this tool
    # exists to prevent — and it would be the number someone quoted.
    print("\nThe two money columns are separate on purpose and are not added.")
    if totals["billed"]:
        print("  billed:   ${:.2f} across {} run(s) — an API key paid this"
              .format(sum(totals["billed"]), len(totals["billed"])))
    if totals["notional"]:
        median = statistics.median(totals["notional"])
        print("  notional: ${:.2f} across {} run(s), ${:.2f} median — API list "
              "price for the tokens used, charged to nobody"
              .format(sum(totals["notional"]), len(totals["notional"]), median))
    if totals["silent"]:
        print("  {} run(s) reported no cost at all. Absent, not $0.00, and not "
              "counted in either column.".format(totals["silent"]))

    gaps = sum(unreported_stages(r) for r in rows)
    if gaps:
        print("  {} stage(s) ran without reporting their tokens, so the token "
              "counts above are a floor.".format(gaps))
    if unreadable:
        print("  {} file(s) could not be read and are not in any number here."
              .format(unreadable))
    return 0


def detail(rows: List[Dict[str, Any]]) -> None:
    print("\n{:<22} {:<10} {:<38} {}".format("when", "cost", "who paid", "model"))
    print("-" * 96)
    for row in sorted(rows, key=when):
        cost = cost_of(row)
        print("{:<22} {:<10} {:<38} {}".format(
            when(row)[:19] or "undated",
            "{:.3f}".format(cost) if cost is not None else "not reported",
            who_paid(row),
            _provenance(row).get("model_requested", "")))


def collect(args: argparse.Namespace) -> List[Path]:
    if args.paths:
        return [Path(p) for p in args.paths]
    found: List[Path] = []
    for pattern in DEFAULT_GLOBS:
        found += sorted(ROOT.glob(pattern))
    return found


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("paths", nargs="*", help="artifacts to read")
    parser.add_argument("--by", default="day", choices=("day", "month"))
    parser.add_argument("--since", default="", help="ISO date; earlier runs are skipped")
    parser.add_argument("--detail", action="store_true", help="one line per run")
    args = parser.parse_args(argv)

    paths = collect(args)
    rows = artifacts(paths)
    unreadable = len(paths) - len(rows)
    if args.since:
        rows = [r for r in rows if when(r) >= args.since]

    code = summarise(rows, args.by, unreadable)
    if args.detail and rows:
        detail(rows)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
