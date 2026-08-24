#!/usr/bin/env python3
"""Separate "recognised the weakness" from "noticed the diff deletes lines".

`corpus-real/` holds every pair in two constructions:

  * **regression** — the safe member adds the maintainers' fix, the unsafe
    member reverts it. Symmetric, but every unsafe member *deletes* something.
  * **snapshot** (`-snap`) — both members add an implementation from a shared
    baseline. Neither deletes, so the direction of the diff carries no answer.

The agent has a rule, `SECURITY_SCAN_GATE_REMOVED_CONTROLS`, that blocks a
merge whenever a change removes an existing security control, whatever its
severity. The rule is worth having. It also means a good score on `regression`
could come from the shape of the diff rather than from having understood the
code — and a corpus that rewards the shape of the diff measures nothing about
recognition.

This runs each case four ways:

    construction ∈ {regression, snapshot}  x  gate rule ∈ {on, off}

and records, per member, what actually happened at each stage rather than a
single pass/fail: was the target reported at all (discovery), did the verifier
confirm it, what severity and confidence it ended up with, whether it blocked,
and whether it was labelled a removed control.

Two numbers are the point:

  * regression-ON blocked minus regression-OFF blocked — what the rule alone
    contributes.
  * discovery on regression versus discovery on snapshot — if discovery holds
    when nothing is deleted, the corpus rewards recognition; if it collapses,
    the regression score was carried by the direction of the diff.

Every run costs money: four cells x two members = eight reviews per case.

Usage:
    tools/ablation.py corpus-real/ --case go-xhj3-7xw9-vr34 --json out.json

`--case` takes the base id; the `-snap` sibling is picked up with it.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).resolve().parent))

from pair_corpus import build_repo, cost_of, load_cases

SNAP_SUFFIX = "-snap"
CONSTRUCTIONS = ("regression", "snapshot")
MEMBERS = ("safe", "unsafe")

# Where a candidate can end up in the artifact. `build_json` splits them into
# separate lists, so looking only at `findings` would score a target the
# verifier refuted as never discovered — which is exactly the distinction this
# tool exists to make.
BUCKETS = ("findings", "refuted", "suppressed")


# ----------------------------------------------------------------- observing

@dataclass
class Observation:
    """What one review did with the finding the case is about.

    A tuple, not a boolean. "Did not block" covers four different failures —
    never seen, seen and refuted, confirmed but rated below the bar, confirmed
    and above the bar but ruled out by policy — and collapsing them loses the
    only thing worth paying for.
    """

    discovered: bool = False
    bucket: str = ""            # which list of the artifact it landed in
    verdict: str = ""           # findings[].verification.verdict
    severity: str = ""
    confidence: str = ""
    blocked: bool = False
    # None means the artifact did not carry the field at all, which is a
    # different statement from "the verifiers said no".
    removes_control: Optional[bool] = None

    @property
    def confirmed(self) -> bool:
        return self.verdict == "confirmed"


def matches_target(finding: dict, case: dict) -> bool:
    """Same rule as `pair_corpus.hits_target`: category and file, never prose.

    The wording changes every run; grading on it would measure phrasing.
    """
    want_category = case.get("expected_category")
    want_file = case.get("expected_file")
    if want_category and finding.get("category") != want_category:
        return False
    return not want_file or str(finding.get("file", "")).endswith(want_file)


def observe(payload: dict, case: dict) -> Observation:
    """Locate the target finding in one artifact and describe its fate."""
    blocking = set(payload.get("verdict", {}).get("blocking_fingerprints", []))

    for bucket in BUCKETS:
        matches = [f for f in payload.get(bucket) or [] if matches_target(f, case)]
        if not matches:
            continue
        # More than one match is possible (same category, same file, two
        # lines). Prefer the one that actually blocked: it is the one the
        # pipeline acted on, and picking by list order would report "not
        # blocked" while the merge was in fact stopped.
        chosen = next(
            (f for f in matches if f.get("fingerprint") in blocking), matches[0])
        verification = chosen.get("verification") or {}
        return Observation(
            discovered=True,
            bucket=bucket,
            verdict=str(verification.get("verdict", "")),
            severity=str(chosen.get("severity", "")),
            confidence=str(chosen.get("confidence", "")),
            blocked=chosen.get("fingerprint") in blocking,
            removes_control=(
                bool(verification["removes_existing_control"])
                if "removes_existing_control" in verification else None),
        )
    return Observation()


# -------------------------------------------------------------------- running

def review(repo: Path, base: str, head: str, out: Path, gate_on: bool) -> dict:
    """One review, with the removed-control rule forced on or off.

    Own wrapper rather than `pair_corpus.review` because that one does not pass
    an environment, and the setting under test is read by `Config.from_env()`.
    The parent environment is inherited so the API key survives; only the one
    variable is pinned, so a value already exported cannot silently decide the
    experiment.
    """
    env = dict(os.environ)
    env["SECURITY_SCAN_GATE_REMOVED_CONTROLS"] = "true" if gate_on else "false"

    cmd = [
        sys.executable, "-m", "security_agent",
        "--repo", str(repo), "--mode", "diff", "--base", base, "--head", head,
        "--no-comment", "--output-dir", str(out),
    ]
    started = time.monotonic()
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False, env=env)
    seconds = time.monotonic() - started

    payload_path = out / "findings.json"
    if not payload_path.is_file():
        return {"ok": False, "seconds": seconds,
                "error": (proc.stderr.strip().splitlines() or ["no output"])[-1]}
    return {"ok": True, "seconds": seconds, "exit_code": proc.returncode,
            "payload": json.loads(payload_path.read_text(encoding="utf-8"))}


def run_unit(spec: dict, gate_on: bool, member: str) -> dict:
    """Build one member of one case and review it under one gate setting."""
    label = "{}-{}-{}".format(spec["case_id"], "on" if gate_on else "off", member)
    # Resolved: on macOS the temp directory is reached through a symlink and
    # the report writer refuses to write through one.
    work = Path(tempfile.mkdtemp(prefix="abl-{}-".format(label))).resolve()
    try:
        repo, base, head = build_repo(spec["_dir"], member, work / member)
        result = review(repo, base, head, work / "out", gate_on)
    except Exception as exc:                # one broken case must not stop the run
        result = {"ok": False, "seconds": 0.0,
                  "error": "{}: {}".format(type(exc).__name__, exc)}
    finally:
        shutil.rmtree(work, ignore_errors=True)
    result.update({"case_id": spec["case_id"], "gate_on": gate_on, "member": member})
    return result


# -------------------------------------------------------------------- grouping

def base_id(case_id: str) -> str:
    return case_id[: -len(SNAP_SUFFIX)] if case_id.endswith(SNAP_SUFFIX) else case_id


def construction_of(spec: dict) -> str:
    """The manifest is authoritative; the id suffix is the fallback."""
    declared = str(spec.get("construction", "")).strip().lower()
    if declared in CONSTRUCTIONS:
        return declared
    return "snapshot" if spec["case_id"].endswith(SNAP_SUFFIX) else "regression"


def group_cases(cases: list) -> dict:
    """Collect case directories into {base id: {construction: spec}}."""
    groups: dict = {}
    for spec in cases:
        groups.setdefault(base_id(spec["case_id"]), {})[construction_of(spec)] = spec
    return groups


def cell_key(construction: str, gate_on: bool) -> str:
    return "{}/{}".format(construction, "on" if gate_on else "off")


CELL_KEYS = [cell_key(c, g) for c in CONSTRUCTIONS for g in (True, False)]


# --------------------------------------------------------------------- scoring

def score_case(group: dict, observations: dict) -> dict:
    """One case's four cells.

    `observations` is {(construction, gate_on, member): Observation | error
    string}, which is what the runner produces and what the tests hand in
    directly.
    """
    spec = group.get("regression") or next(iter(group.values()))
    case = {"case_id": base_id(spec["case_id"]),
            "language": spec.get("language", "?"),
            "family": spec.get("family", "?"),
            "cells": {}}
    for construction in CONSTRUCTIONS:
        if construction not in group:
            continue
        for gate_on in (True, False):
            cell: dict = {}
            for member in MEMBERS:
                seen = observations.get((construction, gate_on, member))
                if isinstance(seen, Observation):
                    # `confirmed` is a property, so it is not in asdict(); it is
                    # written out because the rollup counts it and because a
                    # reader of the JSON should not have to know the verdict
                    # vocabulary to ask "did the verifier agree".
                    cell[member] = dict(asdict(seen), confirmed=seen.confirmed)
                else:
                    cell[member] = {"error": str(seen or "not run")}
            case["cells"][cell_key(construction, gate_on)] = cell
    return case


def _cell(case: dict, construction: str, gate_on: bool, member: str) -> dict:
    return (case.get("cells", {})
            .get(cell_key(construction, gate_on), {})
            .get(member, {}))


def _count(cases: list, construction: str, gate_on: bool, member: str, field: str) -> tuple:
    """(how many were true, how many cells actually produced an answer)."""
    usable = [_cell(c, construction, gate_on, member) for c in cases]
    usable = [c for c in usable if c and "error" not in c]
    return sum(1 for c in usable if c.get(field)), len(usable)


def rollup(cases: list) -> dict:
    """The four questions, as counts."""
    out: dict = {"cases": len(cases)}
    for construction in CONSTRUCTIONS:
        for gate_on in (True, False):
            key = cell_key(construction, gate_on)
            blocked, n = _count(cases, construction, gate_on, "unsafe", "blocked")
            discovered, _ = _count(cases, construction, gate_on, "unsafe", "discovered")
            confirmed, _ = _count(cases, construction, gate_on, "unsafe", "confirmed")
            removed, _ = _count(cases, construction, gate_on, "unsafe", "removes_control")
            false_positive, safe_n = _count(
                cases, construction, gate_on, "safe", "discovered")
            out[key] = {
                "scored": n,
                "unsafe_discovered": discovered,
                "unsafe_confirmed": confirmed,
                "unsafe_blocked": blocked,
                "unsafe_removes_control": removed,
                "safe_false_positive": false_positive,
                "safe_scored": safe_n,
            }

    # Also paired: what the rule contributes is a difference within a case, so
    # a case that only ran under one setting cannot be on one side of it.
    on, off, both = _paired_blocking(cases, "regression")
    out["rule_blocked_on"] = on
    out["rule_blocked_off"] = off
    out["rule_paired_cases"] = both
    out["rule_contribution_regression"] = on - off

    # The comparison the corpus lives or dies on. Discovery, not blocking:
    # blocking mixes in the severity threshold and the rule itself, discovery
    # is the closest thing here to "did it understand the code".
    #
    # Counted only over cases where both constructions produced an answer. A
    # difference of counts taken over different denominators is not a
    # comparison, and one crashed cell would otherwise show up as a gap.
    regression, snapshot, paired = _paired_discovery(cases)
    out["discovery_regression_on"] = regression
    out["discovery_snapshot_on"] = snapshot
    out["discovery_paired_cases"] = paired
    out["discovery_gap"] = regression - snapshot
    return out


def _paired_blocking(cases: list, construction: str) -> tuple:
    """Blocking with the rule on and off, over cases that ran under both."""
    on = off = both = 0
    for case in cases:
        with_rule = _cell(case, construction, True, "unsafe")
        without = _cell(case, construction, False, "unsafe")
        if not with_rule or not without or "error" in with_rule or "error" in without:
            continue
        both += 1
        on += bool(with_rule.get("blocked"))
        off += bool(without.get("blocked"))
    return on, off, both


def _paired_discovery(cases: list) -> tuple:
    """Discovery on the unsafe member, over cases both constructions scored."""
    regression = snapshot = paired = 0
    for case in cases:
        left = _cell(case, "regression", True, "unsafe")
        right = _cell(case, "snapshot", True, "unsafe")
        if not left or not right or "error" in left or "error" in right:
            continue
        paired += 1
        regression += bool(left.get("discovered"))
        snapshot += bool(right.get("discovered"))
    return regression, snapshot, paired


# ---------------------------------------------------------------------- output

MEMBER_WIDTH = 33


def _member_line(cell: dict) -> str:
    if "error" in cell:
        return "{:<{}}".format("error: " + cell["error"][:24], MEMBER_WIDTH)
    if not cell.get("discovered"):
        return "{:<{}}".format("not discovered", MEMBER_WIDTH)
    removes = {True: "rm", False: "--", None: "?"}[cell.get("removes_control")]
    return "{:<11}{:<14}{:<3}{:<5}".format(
        (cell.get("verdict") or "-")[:10],
        "{}/{}".format(cell.get("severity") or "?", cell.get("confidence") or "?")[:13],
        removes,
        "BLK" if cell.get("blocked") else "-")


def print_case(case: dict) -> None:
    print("\n{}  [{} / {}]".format(case["case_id"], case["language"], case["family"]))
    print("  {:<17}{:<{w}}{:<{w}}".format(
        "cell", "unsafe member", "safe member", w=MEMBER_WIDTH))
    print("  {:<17}{:<{w}}{:<{w}}".format(
        "", "verdict    sev/conf      rm blk",
        "verdict    sev/conf      rm blk", w=MEMBER_WIDTH))
    print("  " + "-" * (17 + 2 * MEMBER_WIDTH))
    for key in CELL_KEYS:
        cell = case["cells"].get(key)
        if cell is None:
            print("  {:<17}{}".format(key, "(construction missing from the corpus)"))
            continue
        print("  {:<17}{}{}".format(
            key, _member_line(cell.get("unsafe", {})), _member_line(cell.get("safe", {}))))


def report(cases: list, totals: dict) -> None:
    for case in sorted(cases, key=lambda c: c["case_id"]):
        print_case(case)

    summary = rollup(cases)
    n = summary["cases"]

    print("\n" + "=" * 78)
    print("ABLATION over {} case(s)".format(n))
    print("=" * 78)

    print("\n{:<18}{:>8}{:>12}{:>11}{:>10}{:>12}".format(
        "cell", "scored", "discovered", "confirmed", "blocked", "safe FP"))
    print("-" * 71)
    for key in CELL_KEYS:
        row = summary[key]
        print("{:<18}{:>8}{:>12}{:>11}{:>10}{:>12}".format(
            key, row["scored"], row["unsafe_discovered"], row["unsafe_confirmed"],
            row["unsafe_blocked"], row["safe_false_positive"]))

    reg_on, reg_off = summary["regression/on"], summary["regression/off"]
    snap_on, snap_off = summary["snapshot/on"], summary["snapshot/off"]

    print("\n1. regression, rule ON  — unsafe members blocked: {}/{}".format(
        reg_on["unsafe_blocked"], reg_on["scored"]))
    print("2. regression, rule OFF — unsafe members blocked: {}/{}".format(
        reg_off["unsafe_blocked"], reg_off["scored"]))
    print("   over the {} case(s) that ran under both settings: {} blocked with "
          "the rule\n   on, {} with it off — the rule alone accounts for {}".format(
              summary["rule_paired_cases"], summary["rule_blocked_on"],
              summary["rule_blocked_off"], summary["rule_contribution_regression"]))
    print("3. snapshot (nothing is deleted, the rule cannot fire)")
    print("     rule ON : discovered {}/{}, blocked {}".format(
        snap_on["unsafe_discovered"], snap_on["scored"], snap_on["unsafe_blocked"]))
    print("     rule OFF: discovered {}/{}, blocked {}".format(
        snap_off["unsafe_discovered"], snap_off["scored"], snap_off["unsafe_blocked"]))
    print("4. DISCOVERY, not blocking, across constructions (rule ON),")
    print("   over the {} case(s) where both constructions ran:".format(
        summary["discovery_paired_cases"]))
    print("     regression {}   snapshot {}   gap {}".format(
        summary["discovery_regression_on"], summary["discovery_snapshot_on"],
        summary["discovery_gap"]))
    if summary["discovery_gap"] <= 0:
        print("     Discovery holds when nothing is deleted: on these cases the")
        print("     corpus is rewarding recognition, not the direction of the diff.")
    else:
        print("     Discovery drops on snapshot. On these cases part of the")
        print("     regression score came from the direction of the diff, not from")
        print("     having recognised the weakness.")

    labelled = reg_on["unsafe_removes_control"]
    print("\n   removed-control label on regression/unsafe (rule ON): {}/{}".format(
        labelled, reg_on["scored"]))

    if totals.get("cost"):
        print("\ntotal cost ${:.2f} across {} review(s)".format(
            totals["cost"], totals["reviews"]))

    print("\nThese are counts over a handful of cases, not rates. With this many")
    print("cases the interval around any percentage covers most of the range, so")
    print("read the numbers as 'this happened N times', never as a failure rate.")
    print("Note also that turning the rule off changes more than the gate: a")
    print("low-severity finding attributed to a deletion is no longer worth")
    print("verifying, so the OFF arm can differ in verification too.")


# ------------------------------------------------------------------------ main

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("cases", help="directory holding case.yml manifests")
    parser.add_argument("--case", action="append", metavar="ID",
                        help="Run only this case; repeatable. Give the base id — "
                             "its -snap sibling comes with it.")
    parser.add_argument("-c", "--concurrency", type=int, default=4)
    parser.add_argument("--json", metavar="PATH")
    args = parser.parse_args()

    groups = group_cases(load_cases(Path(args.cases)))
    if args.case:
        wanted = {base_id(c) for c in args.case}
        missing = wanted - set(groups)
        if missing:
            sys.exit("no such case: " + ", ".join(sorted(missing)))
        groups = {k: v for k, v in groups.items() if k in wanted}
    if not groups:
        sys.exit("no cases matched")

    partial = [k for k, g in groups.items() if len(g) < len(CONSTRUCTIONS)]
    if partial:
        print("only one construction present for: {}\n"
              "  the comparison this tool exists to make needs both.".format(
                  ", ".join(sorted(partial))))

    units = [
        (base, construction, spec, gate_on, member)
        for base, group in sorted(groups.items())
        for construction, spec in sorted(group.items())
        for gate_on in (True, False)
        for member in MEMBERS
    ]
    print("{} case(s), {} review(s), {} worker(s)\n".format(
        len(groups), len(units), min(args.concurrency, len(units))))

    seen: dict = {}
    totals = {"cost": 0.0, "reviews": 0}
    with ThreadPoolExecutor(max_workers=max(1, min(args.concurrency, len(units)))) as pool:
        futures = {
            pool.submit(run_unit, spec, gate_on, member): (base, construction, gate_on, member)
            for base, construction, spec, gate_on, member in units
        }
        for future in as_completed(futures):
            base, construction, gate_on, member = futures[future]
            result = future.result()
            key = (construction, gate_on, member)
            spec = groups[base][construction]
            if not result["ok"]:
                seen.setdefault(base, {})[key] = result["error"]
                outcome = "ERROR " + result["error"][:40]
            else:
                observation = observe(result["payload"], spec)
                seen.setdefault(base, {})[key] = observation
                totals["cost"] += cost_of(result["payload"]["usage"])
                totals["reviews"] += 1
                outcome = "{} {}".format(
                    "found" if observation.discovered else "MISS",
                    "BLOCK" if observation.blocked else "-")
            print("  {:<24} {:<11} {:<4} {:<7} {}".format(
                base, construction, "on" if gate_on else "off", member, outcome))

    cases = [score_case(groups[base], seen.get(base, {})) for base in sorted(groups)]
    report(cases, totals)

    if args.json:
        Path(args.json).write_text(
            json.dumps({"cases": cases, "rollup": rollup(cases), "totals": totals},
                       indent=2),
            encoding="utf-8")
        print("\nraw results written to {}".format(args.json))
    return 0


if __name__ == "__main__":
    sys.exit(main())
