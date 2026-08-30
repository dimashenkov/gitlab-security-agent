#!/usr/bin/env python3
"""Is every case accounted for? The end condition, made checkable.

The measurement ends when no failure is left without an outcome — not when a
fraction reaches a number. Every case is exactly one of:

    passes            the pair discriminated, nothing owed
    fixed             it failed, something was changed, it was measured again
    limitation        it failed and `LIMITATIONS.md` says why it is not fixed
    invalid           `adjudications.yml` rules it unable to measure anything
    unaccounted       none of the above — the work that is left

The report that says the work is done reads like this, and the numbers sum:

    34 cases: 20 pass, 8 fixed and re-measured, 4 limitations, 2 invalid.

That is the whole test. A case with no row is the thing this exists to find,
because a fraction can look finished while a dozen failures sit unexplained
behind it — which is how point 9 accumulated seventeen of them unnoticed.

    tools/check_accounted.py                # exit 1 while anything is unaccounted
    tools/check_accounted.py --construction regression

Why it terminates, and this is the part that is easy to lose: two of the four
outcomes remove a case permanently. A limitation is never re-measured and an
invalid case is never scored, so the pool can only grow if a fix breaks
something else. If a round removes more than it returns, the sequence ends. If
it does not, that is itself the signal to stop — the fixes are not working —
rather than a reason to run another round.
"""

from __future__ import annotations

import argparse
import glob
import json
import re
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def rulings() -> set:
    path = ROOT / "corpus-real" / "adjudications.yml"
    try:
        body = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, ValueError):
        return set()
    rows = body if isinstance(body, list) else body.get("adjudications") or []
    return {r.get("case_id") for r in rows
            if isinstance(r, dict) and r.get("case_is_malformed")}


def named_in_limitations() -> set:
    """Cases `LIMITATIONS.md` names, matched on a whole identifier.

    Bounded, not `in`: every snapshot case is its twin's id with `-snap` on the
    end, so a substring test let one sentence account for two different pairs.
    """
    try:
        text = (ROOT / "LIMITATIONS.md").read_text(encoding="utf-8")
    except OSError:
        return set()
    out = set()
    for manifest in (ROOT / "corpus-real").glob("*/case.yml"):
        case_id = manifest.parent.name
        if re.search(r"(?<![\w-])" + re.escape(case_id) + r"(?![\w-])", text):
            out.add(case_id)
    return out


def verdicts() -> dict:
    """The latest recorded answer per case, from every batch and the queue."""
    latest = {}
    for path in (glob.glob(str(ROOT / "measurements" / "*.json"))
                 + glob.glob(str(ROOT / "measurements" / "queue" / "*.json"))):
        try:
            body = json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        for row in body if isinstance(body, list) else []:
            if not isinstance(row, dict) or not row.get("case_id"):
                continue
            if row.get("incomplete"):
                continue
            when = row.get("ran_at") or ""
            case_id = row["case_id"]
            if case_id not in latest or when >= latest[case_id][0]:
                latest[case_id] = (when, bool(row.get("pair_success")))
    return {case_id: ok for case_id, (_when, ok) in latest.items()}


def account(construction=None) -> dict:
    invalid = rulings()
    limitations = named_in_limitations()
    answers = verdicts()

    buckets = {"pass": [], "limitation": [], "invalid": [], "unaccounted": [],
               "unrun": []}
    for manifest in sorted((ROOT / "corpus-real").glob("*/case.yml")):
        case_id = manifest.parent.name
        body = yaml.safe_load(manifest.read_text(encoding="utf-8")) or {}
        if construction and body.get("construction") != construction:
            continue
        if case_id in invalid:
            buckets["invalid"].append(case_id)
        elif case_id not in answers:
            buckets["unrun"].append(case_id)
        elif answers[case_id]:
            buckets["pass"].append(case_id)
        elif case_id in limitations:
            buckets["limitation"].append(case_id)
        else:
            buckets["unaccounted"].append(case_id)
    return buckets


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--construction", choices=("regression", "snapshot"))
    args = parser.parse_args()

    buckets = account(args.construction)
    total = sum(len(v) for v in buckets.values())

    print("{} case(s){}: {} pass, {} limitation(s), {} invalid, {} not run, "
          "{} unaccounted".format(
              total, " ({})".format(args.construction) if args.construction else "",
              len(buckets["pass"]), len(buckets["limitation"]),
              len(buckets["invalid"]), len(buckets["unrun"]),
              len(buckets["unaccounted"])))

    if buckets["unaccounted"]:
        print("\nfailed, and nothing says why:")
        for case_id in buckets["unaccounted"]:
            print("  " + case_id)
        print("\nEach needs one of: a fix that is then re-measured, a line in "
              "LIMITATIONS.md, or a ruling that the case cannot measure "
              "anything. There is no fourth.")
    return 1 if buckets["unaccounted"] or buckets["unrun"] else 0


if __name__ == "__main__":
    sys.exit(main())
