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
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

ROOT = Path(__file__).resolve().parents[1]

# Where an artifact lands by default. `SECURITY_SCAN_OUTPUT_DIR` moves it, so a
# caller with a different layout passes paths instead.
DEFAULT_GLOBS = (".security-scan/**/findings.json", "journal/**/findings.json",
                 # This repository's own kept artifacts. Without it the tool
                 # reported "no artifacts found" in the tree that has spent the
                 # most, because the first two are where a *user's* run writes.
                 "measurements/**/findings.json")

# The queue writes one row per invocation, and that is a different record from
# an artifact: the corpus runs kept an artifact only for the members that
# failed. Read as a separate source and never merged, because a review can
# appear in both and nothing keys them together — summing them would inflate
# the one number this tool exists to state carefully.
QUEUE_LOG = "measurements/queue/log.jsonl"
# Set by `queue_rows`: lines it could not parse, or -1 for a log it
# could not read at all.
QUEUE_SKIPPED = 0

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


# Three, because two could not express the case that matters. The first
# version had `billed()` returning a bool keyed on `provider`, and it was wrong
# in exactly the way this tool exists to prevent: `claude-cli` is how the run
# was launched, not who paid for it. `Authentication.method` is `claude.ai` for
# a subscription login and `api-key` or `console` for a billed one, so a CLI run
# whose stored login is an API key is charged — and was being reported as
# notional. A subscription figure and a bill were about to be added under the
# wrong heading by the tool written to keep them apart.
CHARGED = "charged"
NOTIONAL_ = "notional"
UNKNOWN = "unknown"


def paid_by(row: Dict[str, Any]) -> str:
    """`charged`, `notional`, or `unknown` — never inferred from the number.

    `unknown` is a real answer and is never folded into either money column.
    Guessing it as notional would understate a bill, and understating a cost is
    believed while overstating one prompts a question.
    """
    prov = _provenance(row)
    if prov.get("provider") == BILLED:
        # The Messages API path: an API key is the only way it runs.
        return CHARGED
    method = (prov.get("auth_method") or "").strip()
    if method == "claude.ai" and prov.get("auth_subscription"):
        return NOTIONAL_
    if method in ("api-key", "console"):
        return CHARGED
    # An empty method is the CLI declining to say, an unparseable answer, or a
    # timeout. All three are "nobody established this".
    return UNKNOWN


def billed(row: Dict[str, Any]) -> bool:
    """Kept for readers that want the yes/no; `paid_by` is the honest answer."""
    return paid_by(row) == CHARGED


def who_paid(row: Dict[str, Any]) -> str:
    prov = _provenance(row)
    state = paid_by(row)
    if state == CHARGED:
        return "API key — billed"
    if state == NOTIONAL_:
        return "subscription ({}) — notional".format(prov.get("auth_subscription"))
    return "not established — counted in neither column"


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


def queue_rows(path: Path) -> List[Dict[str, Any]]:
    """The queue's own log, reshaped into the fields `summarise` reads.

    Every row is notional by construction: the queue runs on `claude-cli`, and
    the log says so in `notional_api_cost_source` rather than leaving a reader
    to infer it from the provider.
    """
    if not path.is_file():
        return []
    out: List[Dict[str, Any]] = []
    try:
        body = path.read_text(encoding="utf-8")
    except OSError:
        # `is_file()` passing does not make the read succeed, and a report that
        # silently loses the whole log is the failure this tool is about.
        globals()["QUEUE_SKIPPED"] = -1
        return []
    skipped = 0
    for line in body.splitlines():
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except ValueError:
            skipped += 1
            continue
        if not isinstance(row, dict) or row.get("kind") != "review":
            continue
        cost = row.get("notional_api_cost")
        provenance: Dict[str, Any] = {
            "provider": NOTIONAL,
            "model_requested": row.get("model", ""),
            # Carried when the row has them. Rows written before the queue
            # recorded these classify as unknown, which is what they are: the
            # log did not say, and the cost cannot be assigned to a pot on the
            # strength of the runner's name.
            "auth_method": row.get("auth_method") or "",
            "auth_subscription": row.get("auth_subscription") or "",
        }
        if isinstance(cost, (int, float)):
            provenance["reported_cost_usd"] = float(cost)
        usage: Dict[str, Any] = {name: row.get(name) for name in TOKEN_FIELDS}
        # `usage_reported` false means the run finished and its figures never
        # arrived: an admitted gap, not four zeros.
        usage["unreported_stages"] = 0 if row.get("usage_reported") else 1
        out.append({
            "generated_at": row.get("started_at", ""),
            "provenance": provenance,
            "usage": usage,
            "_path": "{}:{}/{}".format(path, row.get("case_id"), row.get("member")),
        })
    # Counted, not swallowed. The artifact path promises unreadable records are
    # reported; this one had the same obligation and dropped them in silence.
    globals()["QUEUE_SKIPPED"] = skipped
    return out


def instant(stamp: str) -> Optional[datetime]:
    """`stamp` as an aware UTC datetime, or None when it cannot be read.

    Parsed rather than compared as text. Every other tool here compares ISO
    strings and is correct only while everything writes UTC — which breaks the
    moment one record carries a local offset, because `2026-08-31T01:00+03:00`
    sorts after `2026-08-30` and belongs before it. A tool whose purpose is
    accounting should not knowingly keep a boundary that is wrong.

    A timestamp with no offset is *not* assumed to be UTC. Guessing a timezone
    moves a run between days, and this returns None so it is reported as undated
    instead.
    """
    if not stamp:
        return None
    try:
        parsed = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc)


def _period(stamp: str, by: str) -> str:
    moment = instant(stamp)
    if moment is None:
        return "undated"
    return moment.strftime("%Y-%m" if by == "month" else "%Y-%m-%d")


def summarise(rows: List[Dict[str, Any]], by: str = "day",
              unreadable: int = 0, source: str = "artifacts",
              skipped_lines: int = 0) -> int:
    if not rows:
        print("Nothing to report. No records were found — which is not the "
              "same as nothing having been spent.")
        return 2

    groups: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for row in rows:
        groups[_period(when(row), by)].append(row)

    print("{:<12} {:>5} {:>11} {:>12} {:>9} {:>9}".format(
        by, "runs", "charged $", "notional $", "unknown", "no cost"))
    print("-" * 62)

    totals: Dict[str, Any] = {CHARGED: [], NOTIONAL_: [], "unknown": 0,
                              "silent": 0, "runs": 0}
    for period in sorted(groups):
        members = groups[period]
        pots: Dict[str, List[float]] = {CHARGED: [], NOTIONAL_: []}
        unknown = silent = 0
        for row in members:
            cost = cost_of(row)
            if cost is None:
                silent += 1
                continue
            state = paid_by(row)
            if state == UNKNOWN:
                # A figure exists and nobody established which pot it belongs
                # in. Putting it in the cheaper one would understate a bill, so
                # it is counted as a run and its money is reported nowhere.
                unknown += 1
                continue
            pots[state].append(cost)
        for state in (CHARGED, NOTIONAL_):
            totals[state] += pots[state]
        totals["unknown"] += unknown
        totals["silent"] += silent
        totals["runs"] += len(members)
        print("{:<12} {:>5} {:>11} {:>12} {:>9} {:>9}".format(
            period, len(members),
            "{:.2f}".format(sum(pots[CHARGED])) if pots[CHARGED] else "—",
            "{:.2f}".format(sum(pots[NOTIONAL_])) if pots[NOTIONAL_] else "—",
            unknown or "—", silent or "—"))

    print("-" * 62)
    print("{:<12} {:>5} {:>11} {:>12} {:>9} {:>9}".format(
        "total", totals["runs"],
        "{:.2f}".format(sum(totals[CHARGED])) if totals[CHARGED] else "—",
        "{:.2f}".format(sum(totals[NOTIONAL_])) if totals[NOTIONAL_] else "—",
        totals["unknown"] or "—", totals["silent"] or "—"))

    # Never added. One number that is part bill and part list price is the exact
    # confusion this tool exists to prevent, and it would be the number quoted.
    print("\nThe money columns are separate on purpose and are not added.")
    if totals[CHARGED]:
        print("  charged:  ${:.2f} across {} run(s) — an API key paid this"
              .format(sum(totals[CHARGED]), len(totals[CHARGED])))
    if totals[NOTIONAL_]:
        median = statistics.median(totals[NOTIONAL_])
        print("  notional: ${:.2f} across {} run(s), ${:.2f} median — API list "
              "price for the tokens used, charged to nobody"
              .format(sum(totals[NOTIONAL_]), len(totals[NOTIONAL_]), median))
    if totals["unknown"]:
        print("  {} run(s) reported a cost with no established billing. Their "
              "money is in neither column, because assigning it to the cheaper "
              "one would understate a bill.".format(totals["unknown"]))
    if totals["silent"]:
        print("  {} run(s) reported no cost at all. Absent, not $0.00."
              .format(totals["silent"]))

    # The four counts, named, or nothing. The previous version printed a
    # sentence about "the token counts above" being a floor while the table
    # carried no token columns at all, and a test passed against it.
    counted = [tokens(r) for r in rows]
    sums = {name: sum(v[name] for v in counted if isinstance(v[name], int))
            for name in TOKEN_FIELDS}
    missing = sum(1 for v in counted
                  if any(not isinstance(v[name], int) for name in TOKEN_FIELDS))
    if any(sums.values()):
        print("\ntokens: " + " · ".join(
            "{} {:,}".format(name.replace("_tokens", ""), sums[name])
            for name in TOKEN_FIELDS))
        print("  Not summed into one figure: cache reads are a tenth of the "
              "input rate and cache writes are twice it, so a total of the four "
              "is dominated by the cheapest of them.")
        gaps = sum(unreported_stages(r) for r in rows)
        if gaps or missing:
            print("  A floor, not a total: {} stage(s) ran without reporting, "
                  "and {} run(s) are missing at least one count."
                  .format(gaps, missing))

    if source == "artifacts":
        print("\nSource: retained artifacts. This repository keeps an artifact "
              "for the members that failed, so this is a selected sample and "
              "not total spend.")
    else:
        print("\nSource: the queue's own log — one row per invocation it ran, "
              "and nothing it did not.")
    if unreadable:
        print("  {} file(s) could not be read and are in no number here."
              .format(unreadable))
    if skipped_lines == -1:
        print("  The queue log exists and could not be read at all.")
    elif skipped_lines:
        print("  {} line(s) of the queue log did not parse and are in no "
              "number here.".format(skipped_lines))
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
    parser.add_argument(
        "--source", default="artifacts", choices=("artifacts", "queue"),
        help="artifacts written by a review, or the queue's own log. Separate "
             "on purpose: a review can be in both and nothing keys them "
             "together, so adding them would double-count")
    args = parser.parse_args(argv)

    if args.source == "queue":
        rows = queue_rows(ROOT / QUEUE_LOG)
        unreadable = 0
        skipped = QUEUE_SKIPPED
    else:
        skipped = 0
        paths = collect(args)
        rows = artifacts(paths)
        unreadable = len(paths) - len(rows)
    if args.since:
        # Compared as instants, not as text: an offset timestamp sorts by its
        # local hour and belongs at its UTC one. A run whose stamp cannot be
        # read is kept rather than dropped — a filter that silently removes
        # what it cannot parse makes the report shorter and says nothing.
        try:
            floor = instant(args.since) or instant(args.since + "T00:00:00+00:00")
        except ValueError:
            floor = None
        if floor is not None:
            rows = [r for r in rows
                    if instant(when(r)) is None or instant(when(r)) >= floor]

    code = summarise(rows, args.by, unreadable, args.source, skipped)
    if args.source == "artifacts" and queue_rows(ROOT / QUEUE_LOG):
        print("\nThe queue log holds review rows this source does not: "
              "tools/spend.py --source queue. Not added to the above — a "
              "review can appear in both and nothing keys them together.")
    if args.detail and rows:
        detail(rows)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
