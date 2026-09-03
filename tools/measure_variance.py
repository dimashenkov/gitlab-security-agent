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
import time
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Optional

# claude-opus-5, $/MTok. Only used for the cost column.
# Pricing lives in the package, not here. There were three copies of these
# constants and two of them were wrong — a rate copied into a tool is a rate
# nobody updates.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from security_agent.config import MODEL_PRICING
from security_agent.models import Usage

MODEL = "claude-opus-5"
CACHE_TTL = "1h"


def cost_of(usage: dict) -> Optional[float]:
    """What a review cost, or `None` when the runner reported no usage.

    The four counts used to be indexed out of the block directly, so a run
    that reported nothing arrived as four zeros and priced at $0.00 — and
    this tool's whole output is a median with a range, which an unmeasured
    run drags to the floor while looking like a cheap run.
    """
    input_rate, output_rate = MODEL_PRICING[MODEL]
    return Usage.from_dict(usage).cost_usd(input_rate, output_rate, CACHE_TTL)


def run_once(args: argparse.Namespace, index: int) -> dict:
    out_dir = Path(tempfile.mkdtemp(prefix="variance-{}-".format(index)))
    cmd = [
        sys.executable, "-m", "security_agent",
        "--repo", args.repo, "--no-comment",
        "--provider", args.provider,
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
    started = time.monotonic()
    # check=False on purpose: a non-zero exit is the product here, not a failure.
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    seconds = time.monotonic() - started

    payload_path = out_dir / "findings.json"
    if not payload_path.is_file():
        shutil.rmtree(out_dir, ignore_errors=True)
        return {"ok": False, "index": index, "seconds": seconds,
                "exit_code": proc.returncode,
                "error": proc.stderr.strip().splitlines()[-1:] or ["no output"]}

    payload = json.loads(payload_path.read_text())
    shutil.rmtree(out_dir, ignore_errors=True)
    # Keep the agent's own log: without it a slow or retrying run looks
    # identical to a fast one, and "why did that take 17 minutes" is
    # unanswerable after the fact.
    retries = proc.stderr.count("retrying in")
    return {"ok": True, "index": index, "seconds": seconds, "retries": retries,
            "exit_code": proc.returncode, "payload": payload}


def summarise(runs: list, provider: str = "claude-cli") -> int:
    """Print the comparison, and return the exit code it earns.

    Returns 0 for an answer, 2 for "not enough runs to compare". `main` used to
    return 0 unconditionally, so a wrapper reading the exit code could not tell
    "the gate is stable" from "nothing was measured" — the two answers this
    repository exists to keep apart, in the tool that measures whether the gate
    holds still.
    """
    good = [r for r in runs if r["ok"]]
    if not good:
        print("every run failed; nothing to compare")
        return 2

    print("\n{}\n{} of {} runs produced a report\n".format("=" * 78, len(good), len(runs)))

    # --- the number that decides the pipeline ---
    exits = Counter(r["exit_code"] for r in good)
    print("exit code      " + "  ".join(
        "{}x{}".format(count, code) for code, count in sorted(exits.items())))
    if len(exits) > 1:
        print("               ^ THE GATE IS NOT STABLE: identical input, different verdict")

    # Only the runs that reported. A median over a set padded with zeros for
    # the runs nobody measured is not the median of anything, and the row it
    # prints reads as a spread of real prices.
    costs = [c for c in (cost_of(r["payload"]["usage"]) for r in good) if c is not None]
    turns = [r["payload"]["coverage"]["turns"] for r in good]
    if not costs:
        print("cost           not reported by this runner for any of the {} "
              "run(s) — absent, not $0.000".format(len(good)))
    else:
        # Priced from tokens at API rates. On the CLI path nobody is billed
        # those rates — the run came out of a subscription — so the column is a
        # notional figure and says so. Reading it as money spent is how three
        # wrong rules about the weekly limit were built from a number that was
        # never a bill.
        label = "cost" if provider == "anthropic-api" else "cost (notional)"
        print("{:<15}${:.3f} median  (${:.3f}–${:.3f}){}".format(
            label, statistics.median(costs), min(costs), max(costs),
            "" if len(costs) == len(good) else
            "  over {} of {} runs; the rest reported no usage".format(
                len(costs), len(good))))
        if provider != "anthropic-api":
            print("               ^ API list price for the tokens used, not an "
                  "amount anyone was charged")
    print("turns          {} median  ({}–{})".format(
        int(statistics.median(turns)), min(turns), max(turns)))
    times = [r["seconds"] for r in good]
    print("time per run   {:.0f}s median  ({:.0f}–{:.0f}s)".format(
        statistics.median(times), min(times), max(times)))
    retried = sum(r.get("retries", 0) for r in good)
    if retried:
        print("               {} transient retry/retries across the set".format(retried))

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

    # One run cannot disagree with itself. Four crashes and a survivor printed
    # "stable across 1 runs at this sample size" — agreement manufactured out
    # of the four absences, in the tool that decides whether the gate holds
    # still. The cost and exit-code rows above are honest for a single run;
    # only the stability claim is not, so only it is withheld.
    if len(good) < 2:
        print("\nNot a measurement of stability: {} of {} run(s) produced a "
              "report, and one run cannot disagree with itself.".format(
                  len(good), len(runs)))
        return 2

    if not unstable and len(exits) == 1:
        print("stable across {} runs at this sample size".format(len(good)))
        if len(good) < len(runs):
            # The claim is about the runs that reported, and the ones that did
            # not are not evidence for it. Said beside the claim rather than
            # further up, because this line is the one that gets quoted.
            print("  over {} of {} run(s) — the {} that produced no report "
                  "are not agreement".format(
                      len(good), len(runs), len(runs) - len(good)))
    return 0


def _dist(counter: Counter) -> str:
    return " ".join("{}x{}".format(n, k) for k, n in counter.most_common())


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True)
    parser.add_argument("--base", help="diff base; omit for a whole-repository review")
    parser.add_argument("--head")
    parser.add_argument("--effort")
    # Defaulted, and defaulted to the CLI, because the omission bricked the
    # tool. `python -m security_agent` with no provider takes the Messages API
    # path, which needs an `ANTHROPIC_API_KEY`; the owner ruled that key out
    # permanently on 2026-08-30 (D-007). So this tool existed, was the obvious
    # thing to reach for when variance was finally wanted, and could not be run
    # at all — the flag it needed was one it never offered.
    #
    # `anthropic-api` is still reachable by name. Naming it is the point: which
    # account pays is not a decision this tool makes on anyone's behalf.
    parser.add_argument("--provider", default="claude-cli",
                        choices=("claude-cli", "anthropic-api"),
                        help="default claude-cli, which runs on your own "
                             "logged-in `claude` and needs no API key")
    parser.add_argument("-n", "--runs", type=int, default=5)
    parser.add_argument("-c", "--concurrency", type=int, default=5,
                        help="How many reviews to run at once. They share nothing.")
    parser.add_argument("--json", metavar="PATH", help="write the raw payloads here")
    args = parser.parse_args()

    # The runs are independent by construction — same input, no shared state —
    # so running them one after another only makes the measurement slower, not
    # more correct. Five sequential runs took 86 minutes; concurrently they take
    # as long as the slowest one.
    workers = max(1, min(args.concurrency, args.runs))
    print("running {} review(s) across {} worker(s)\n".format(args.runs, workers))

    started = time.monotonic()
    runs = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(run_once, args, i): i
                   for i in range(1, args.runs + 1)}
        for future in as_completed(futures):
            result = future.result()
            if result["ok"]:
                payload = result["payload"]
                cost = cost_of(payload["usage"])
                print("run {} · exit {} · {} finding(s) · {} · {:.0f}s{}".format(
                    result["index"], result["exit_code"],
                    payload["counts"]["reported"],
                    "${:.3f}".format(cost) if cost is not None else "cost n/r",
                    result["seconds"],
                    " · {} retries".format(result["retries"]) if result["retries"] else ""))
            else:
                print("run {} FAILED after {:.0f}s: {}".format(
                    result["index"], result["seconds"], result.get("error")))
            runs.append(result)
    print("\nwall clock: {:.0f}s".format(time.monotonic() - started))
    runs.sort(key=lambda r: r["index"])

    code = summarise(runs, args.provider)
    if args.json:
        # Written whatever the code. The payloads are what was paid for, and a
        # run that could not be compared is still a run somebody bought.
        Path(args.json).write_text(json.dumps(
            [r.get("payload") for r in runs if r["ok"]], indent=2))
        print("\nraw payloads written to {}".format(args.json))
    # `return 0` was unconditional here. A wrapper reading the exit code could
    # not tell "the gate is stable" from "nothing was measured", which is the
    # distinction this whole repository is built around — missing from the tool
    # that measures whether the gate holds still.
    return code


if __name__ == "__main__":
    sys.exit(main())
