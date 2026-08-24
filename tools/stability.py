#!/usr/bin/env python3
"""Run the same code repeatedly and ask whether the gate agrees with itself.

Not a corpus score. One case, one member, N identical runs — the only
measurement that can separate "the change moved the verdict" from "the verdict
moves anyway". Without it every other number here is a claim about one sample
of a distribution nobody has looked at.

It exists because that distribution turned out to be wide. Four identical runs
of one unsafe case gave three blocks and one pass: 3 of 6 run pairs agreed. The
cause was two aggregation rules that let a single verifier's hedge take a real
finding under the gate. Nothing in the corpus scores could have shown that —
they each ran a case once and reported the answer as the answer.

Cheapest measurement in the project and the one that decides whether the rest
can be read, so it is a tool rather than a script someone rewrites each time.

    tools/stability.py corpus/ --case go-sql-01 --member unsafe --runs 4
    tools/stability.py corpus-real/ --case py-2cp2-2r3c-7p7r --runs 6 --json out.json
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
import tempfile
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from injection_corpus import controls_agree, signature
from pair_corpus import build_repo, cost_of, load_cases, review


def one_run(case: dict, member: str, index: int) -> dict:
    work = Path(tempfile.mkdtemp(prefix="stability-")).resolve()
    try:
        repo, base, head = build_repo(case["_dir"], member, work)
        result = review(repo, base, head, work / "out")
        if not result["ok"]:
            return {"run": index, "error": result.get("error", "review failed")}
        row = signature(result["payload"], case)
        row["run"] = index
        row["cost"] = cost_of(result["payload"]["usage"])
        row["seconds"] = result["seconds"]
        return row
    except Exception as exc:
        return {"run": index, "error": "{}: {}".format(type(exc).__name__, exc)}
    finally:
        shutil.rmtree(work, ignore_errors=True)


def describe(row: dict) -> str:
    target = row.get("target") or {}
    return "{:<7}{:<10}{:<12}{:<12}{}".format(
        row.get("exit_code", "?"),
        target.get("severity") or "-",
        target.get("confidence") or "-",
        target.get("verdict") or "-",
        "BLOCKS" if target.get("blocking") else "does not block",
    )


def report(rows: list, case_id: str, member: str) -> int:
    broken = [r for r in rows if "error" in r]
    good = [r for r in rows if "error" not in r]

    print("\n{} / {}".format(case_id, member))
    print("{:<5}{:<7}{:<10}{:<12}{:<12}{}".format(
        "run", "exit", "severity", "confidence", "verdict", "gate"))
    print("-" * 62)
    for row in sorted(rows, key=lambda r: r["run"]):
        if "error" in row:
            print("{:<5}{}".format(row["run"], str(row["error"])[:52]))
        else:
            print("{:<5}{}".format(row["run"], describe(row)))

    if len(good) < 2:
        print("\nFewer than two runs completed; nothing to compare.")
        return 2

    pairs = agreements = 0
    for i in range(len(good)):
        for j in range(i + 1, len(good)):
            pairs += 1
            agreements += controls_agree(good[i], good[j])

    exits = Counter(r.get("exit_code") for r in good)
    print("\nagreement: {} of {} run pair(s)".format(agreements, pairs))
    print("exit codes: {}".format(
        ", ".join("{} x{}".format(code, n) for code, n in sorted(exits.items()))))
    if broken:
        print("{} run(s) failed and are excluded from the comparison".format(len(broken)))
    print("cost ${:.2f} across {} completed run(s)".format(
        sum(r.get("cost", 0) for r in good), len(good)))

    if agreements == pairs:
        print("\nEvery run agreed on what the gate does. That is what the "
              "measurement can show; with {} runs it does not bound how often "
              "they would differ.".format(len(good)))
        return 0
    print("\nThe gate disagreed with itself on identical input. Any result "
          "measured on this case — a corpus score, an injection trial, an "
          "ablation cell — is one sample of that, not the answer.")
    return 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("cases", help="directory holding case.yml manifests")
    parser.add_argument("--case", required=True)
    parser.add_argument("--member", default="unsafe", choices=("safe", "unsafe"))
    parser.add_argument("--runs", type=int, default=4)
    parser.add_argument("-c", "--concurrency", type=int, default=4)
    parser.add_argument("--json", metavar="PATH")
    args = parser.parse_args()

    matches = [c for c in load_cases(Path(args.cases)) if c["case_id"] == args.case]
    if not matches:
        sys.exit("no case {!r} under {}".format(args.case, args.cases))
    if args.runs < 2:
        sys.exit("at least two runs are needed to compare anything")

    case = matches[0]
    print("{} identical run(s) of {}/{} — {} review(s)".format(
        args.runs, args.case, args.member, args.runs))

    with ThreadPoolExecutor(max_workers=max(1, min(args.concurrency, args.runs))) as pool:
        rows = list(pool.map(lambda i: one_run(case, args.member, i), range(args.runs)))

    # Written before the report, so a formatting bug cannot discard runs that
    # have already been paid for.
    if args.json:
        Path(args.json).write_text(json.dumps(rows, indent=2))
        print("raw results written to {}".format(args.json))

    return report(rows, args.case, args.member)


if __name__ == "__main__":
    sys.exit(main())
