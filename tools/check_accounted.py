#!/usr/bin/env python3
"""Is every case accounted for? The end condition, made checkable.

The measurement ends when no failure is left without an outcome — not when a
fraction reaches a number. Every case is exactly one of:

    pass              the pair discriminated, nothing owed
    limitation        it failed and `LIMITATIONS.md` says why it is not fixed
    invalid           `adjudications.yml` rules it unable to measure anything
    not run           in the corpus, no result recorded for it
    unaccounted       none of the above — the work that is left

There is deliberately no `fixed` bucket, and this docstring promised one for a
while. A case that failed, was changed and then measured again lands in `pass`,
where it cannot be told apart from a case that never failed. Nothing records
which case was fixed, so the bucket would have to be filled by hand — and with
zero fixes made so far it would be empty in every case. Said here rather than
implemented: a tally that names an outcome it cannot compute is worse than one
that does not name it.

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

sys.path.insert(0, str(Path(__file__).resolve().parent))

from artifact import (
    case_digest,
    is_target,
    legacy_case_digest,
    load_adjudications,
    ruled_incidental,
)

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


def passed(row: dict, case: dict) -> bool:
    """Did this pair discriminate, judged by the key in force **now**?

    Not the boolean the scorer wrote. Answer keys are corrected when they turn
    out to name the wrong thing, and `php-p2ch-c2c3-4xm5` is the proof: it is
    stored as a failure, and against today's key it passes — the finding is
    `authn-authz` in `Controller.php` and the case expects exactly that. The
    stored value answers the key as it stood that afternoon.

    `stage2.py` learned this and this tool did not, an hour after being written
    beside it. Falls back to the stored boolean only for rows too old to carry
    findings, which cannot be re-judged at all.
    """
    if "safe_findings" not in row or "unsafe_findings" not in row:
        return row.get("pair_success") is True
    excused = ruled_incidental(
        load_adjudications(ROOT / "corpus-real"), row.get("case_id"), "safe")
    found = any(is_target(f, case) for f in row.get("unsafe_findings") or [])
    persists = any(is_target(f, case)
                   and f.get("fingerprint") not in excused
                   for f in row.get("safe_findings") or [])
    return found and not persists


def about_this_version(case_id: str, row: dict) -> bool:
    """Is this row a result about the case as it stands today?

    `tools/stage2.py` has asked this since a case had its weakness deleted by a
    bug and then repaired: the recorded failure was a failure at reviewing code
    that no longer existed, and nothing in the batch said so. The rule is copied
    rather than re-invented — either digest counts, because the definition
    narrowed to the members so a corrected answer key stops discarding the run
    it was corrected for, and the old whole-tree value still means the members
    are unchanged.

    A row with no digest at all predates the record and is not a verdict about
    today's case either.
    """
    directory = ROOT / "corpus-real" / case_id
    if not (directory / "case.yml").is_file():
        return False
    return row.get("case_digest") in {case_digest(directory),
                                      legacy_case_digest(directory)}


def verdicts() -> dict:
    """The latest recorded answer per case, from every batch and the queue.

    Two rows for one case are ordered by `ran_at`. When neither carries one the
    comparison is `"" >= ""`, which is true, so the winner used to be whichever
    file the filesystem handed over last — an ordering nobody chose and nothing
    printed. `rb-mx5j-mp4f-g8jg` had three rows, two failures from before the
    answer key was repaired and one pass from after, and the case was reported
    as failing because of glob order. Rows that are not about today's version of
    the case are dropped first, which removes that comparison in the case that
    provoked it and, where it survives, leaves it between rows that at least
    measured the same thing.
    """
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
            case_id = row["case_id"]
            if not about_this_version(case_id, row):
                continue
            when = row.get("ran_at") or ""
            if case_id not in latest or when >= latest[case_id][0]:
                latest[case_id] = (when, row)

    out = {}
    for case_id, (_when, row) in latest.items():
        manifest = ROOT / "corpus-real" / case_id / "case.yml"
        if not manifest.is_file():
            continue
        case = yaml.safe_load(manifest.read_text(encoding="utf-8")) or {}
        out[case_id] = passed(row, case)
    return out


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
