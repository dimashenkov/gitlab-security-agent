#!/usr/bin/env python3
"""Run the same review N times and report how much the answer moves.

Every design decision in this repository so far was made from a single run, and
the gate is a step function on a severity label — so the question that matters
is not "what did it find" but "how much does what it finds change when nothing
else does". This measures that, and nothing else.

Usage:
    tools/measure_variance.py --repo ../some-project --base main --head feature -n 5

Findings are grouped by fingerprint, which is stable across line moves and
re-wordings by design, so the same weakness lines up across runs.
"""

from __future__ import annotations

import argparse
import json
import shutil
import statistics
import subprocess
import sys
import tempfile
from collections import Counter, defaultdict
from pathlib import Path

# claude-opus-5, $/MTok. Only used for the cost column.
IN_RATE, OUT_RATE = 5.0, 25.0


def cost_of(usage: dict) -> float:
    return (
        usage["input_tokens"] * IN_RATE
        + usage["cache_write_tokens"] * IN_RATE * 1.25
        + usage["cache_read_tokens"] * IN_RATE * 0.1
        + usage["output_tokens"] * OUT_RATE
    ) / 1e6


def run_once(args: argparse.Namespace, index: int) -> dict:
    out_dir = Path(tempfile.mkdtemp(prefix="variance-{}-".format(index)))
    cmd = [
        sys.executable, "-m", "security_agent",
        "--repo", args.repo, "--no-comment",
        "--output-dir", str(out_dir),
    ]
    if args.base:
        cmd += ["--mode", "diff", "--base", args.base]
        if args.head:
            cmd += ["--head", args.head]
    else:
        cmd += ["--mode", "repo"]
    if args.effort:
        cmd += ["--effort", args.effort]

    # check=False on purpose: a non-zero exit is the product here, not a failure.
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    payload_path = out_dir / "findings.json"
    if not payload_path.is_file():
        shutil.rmtree(out_dir, ignore_errors=True)
        return {"ok": False, "exit_code": proc.returncode,
                "error": proc.stderr.strip().splitlines()[-1:] or ["no output"]}

    payload = json.loads(payload_path.read_text())
    shutil.rmtree(out_dir, ignore_errors=True)
    return {"ok": True, "exit_code": proc.returncode, "payload": payload}


def summarise(runs: list) -> None:
    good = [r for r in runs if r["ok"]]
    if not good:
        print("every run failed; nothing to compare")
        return

    print("\n{}\n{} of {} runs produced a report\n".format("=" * 78, len(good), len(runs)))

    # --- the number that decides the pipeline ---
    exits = Counter(r["exit_code"] for r in good)
    print("exit code      " + "  ".join(
        "{}x{}".format(count, code) for code, count in sorted(exits.items())))
    if len(exits) > 1:
        print("               ^ THE GATE IS NOT STABLE: identical input, different verdict")

    costs = [cost_of(r["payload"]["usage"]) for r in good]
    turns = [r["payload"]["coverage"]["turns"] for r in good]
    print("cost           ${:.3f} median  (${:.3f}–${:.3f})".format(
        statistics.median(costs), min(costs), max(costs)))
    print("turns          {} median  ({}–{})".format(
        int(statistics.median(turns)), min(turns), max(turns)))

    # --- per finding, keyed by the fingerprint that is meant to be stable ---
    seen = defaultdict(list)
    blocking = Counter()
    for r in good:
        payload = r["payload"]
        blocked = set(payload["verdict"]["blocking_fingerprints"])
        for f in payload["findings"] + payload.get("refuted", []):
            seen[f["fingerprint"]].append(f)
            if f["fingerprint"] in blocked:
                blocking[f["fingerprint"]] += 1

    print("\n{:<18}{:>7}{:>9}  {:<24}{:<20}{}".format(
        "fingerprint", "seen", "blocks", "severity", "confidence", "title"))
    print("-" * 110)
    for fp, items in sorted(seen.items(), key=lambda kv: -len(kv[1])):
        sev = Counter(i["severity"] for i in items)
        conf = Counter(i["confidence"] for i in items)
        flag = "  <-- unstable" if len(sev) > 1 or 0 < blocking[fp] < len(good) else ""
        print("{:<18}{:>4}/{:<2}{:>9}  {:<24}{:<20}{}{}".format(
            fp, len(items), len(good), "{}/{}".format(blocking[fp], len(good)),
            _dist(sev), _dist(conf), items[0]["title"][:34], flag))

    unstable = [fp for fp, items in seen.items()
                if len(items) < len(good)
                or len(Counter(i["severity"] for i in items)) > 1
                or 0 < blocking[fp] < len(good)]
    print("\n{} of {} findings varied between runs".format(len(unstable), len(seen)))
    if not unstable and len(exits) == 1:
        print("stable across {} runs at this sample size".format(len(good)))


def _dist(counter: Counter) -> str:
    return " ".join("{}x{}".format(n, k) for k, n in counter.most_common())


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True)
    parser.add_argument("--base", help="diff base; omit for a whole-repository review")
    parser.add_argument("--head")
    parser.add_argument("--effort")
    parser.add_argument("-n", "--runs", type=int, default=5)
    parser.add_argument("--json", metavar="PATH", help="write the raw payloads here")
    args = parser.parse_args()

    runs = []
    for i in range(1, args.runs + 1):
        print("run {}/{} ...".format(i, args.runs), end=" ", flush=True)
        result = run_once(args, i)
        if result["ok"]:
            payload = result["payload"]
            print("exit {} · {} finding(s) · ${:.3f}".format(
                result["exit_code"], payload["counts"]["reported"],
                cost_of(payload["usage"])))
        else:
            print("FAILED: {}".format(result.get("error")))
        runs.append(result)

    summarise(runs)
    if args.json:
        Path(args.json).write_text(json.dumps(
            [r.get("payload") for r in runs if r["ok"]], indent=2))
        print("\nraw payloads written to {}".format(args.json))
    return 0


if __name__ == "__main__":
    sys.exit(main())
