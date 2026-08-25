#!/usr/bin/env python3
"""Reviews of real changes, and what a person decided about each finding.

The corpus is this project's own construction. It can say "version X found
these known targets on the frozen suite" and it cannot say what the reviewer
does on code nobody built to be reviewed. The release criteria call for a
200-merge-request shadow deployment for that, on a team that has agreed to it.
There is no such team.

What there is, is this repository: 24 commits in two days, real changes to real
code, each one a diff against its parent. Reviewing those and recording a human
verdict per finding is not independent evidence — the same person wrote the
prompts, the code, and the verdicts — but it is the only evidence available
that is not a case built to be passed, and it accumulates instead of being
bought in one lump.

    tools/journal.py add .security-scan/findings.json --ref 79faa25
    tools/journal.py report

`add` files the artifact and writes a verdict stub with one entry per finding,
each set to `unadjudicated`. `report` refuses to fold those into a rate:
"not yet judged" and "judged not real" are different statements, and the whole
history of this project is the second one quietly absorbing the first.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from collections import Counter
from pathlib import Path

import yaml

JOURNAL = Path("journal")
VERDICTS = ("real", "not_real", "unclear", "unadjudicated")


def entry_dir(root: Path, ref: str) -> Path:
    return root / ref


def load_entries(root: Path) -> list:
    """Every filed review, newest name last. Missing verdicts are not errors."""
    entries = []
    for verdict_file in sorted(root.glob("*/verdict.yml")):
        data = yaml.safe_load(verdict_file.read_text(encoding="utf-8")) or {}
        data["_dir"] = verdict_file.parent
        data.setdefault("ref", verdict_file.parent.name)
        entries.append(data)
    return entries


def summarise(finding: dict, blocking: set) -> dict:
    return {
        "fingerprint": finding.get("fingerprint", ""),
        "category": finding.get("category", ""),
        "severity": finding.get("severity", ""),
        "file": finding.get("file", ""),
        "line": finding.get("line", 0),
        "title": finding.get("title", ""),
        "blocked_the_merge": finding.get("fingerprint") in blocking,
        # The only field a person fills in. It stays `unadjudicated` until
        # someone reads the code, and nothing here will quietly decide it.
        "verdict": "unadjudicated",
        "note": "",
    }


def add(artifact: Path, ref: str, root: Path) -> int:
    payload = json.loads(artifact.read_text(encoding="utf-8"))
    destination = entry_dir(root, ref)
    if (destination / "verdict.yml").exists():
        print("{} is already filed; edit {}/verdict.yml rather than re-adding, "
              "or a verdict already given would be overwritten with a stub."
              .format(ref, destination), file=sys.stderr)
        return 1
    destination.mkdir(parents=True, exist_ok=True)
    shutil.copy2(artifact, destination / "findings.json")

    blocking = set(payload.get("verdict", {}).get("blocking_fingerprints", []))
    revision = payload.get("revision", {})
    stub = {
        "ref": ref,
        # Kept because a finding is a claim about code at a moment, and the
        # verdict below is a claim about the finding.
        "reviewed_base": revision.get("base_sha", ""),
        "reviewed_head": revision.get("head_sha", ""),
        "model": payload.get("model", ""),
        "complete": bool(payload.get("complete")),
        "stop_reason": payload.get("stop_reason", ""),
        "exit_code": payload.get("verdict", {}).get("exit_code"),
        "findings": [summarise(f, blocking) for f in payload.get("findings", [])],
    }
    (destination / "verdict.yml").write_text(
        yaml.safe_dump(stub, sort_keys=False, allow_unicode=True), encoding="utf-8")

    print("filed {} — {} finding(s), {}".format(
        ref, len(stub["findings"]),
        "complete" if stub["complete"] else
        "INCOMPLETE ({})".format(stub["stop_reason"] or "no reason recorded")))
    if stub["findings"]:
        print("Set a verdict on each in {}/verdict.yml before it counts for "
              "anything.".format(destination))
    return 0


def report(root: Path) -> int:
    entries = load_entries(root)
    if not entries:
        print("nothing filed under {}".format(root))
        return 2

    incomplete = [e for e in entries if not e.get("complete")]
    findings = [f for e in entries for f in (e.get("findings") or [])]
    tally = Counter(f.get("verdict", "unadjudicated") for f in findings)
    judged = tally["real"] + tally["not_real"]

    print("\n{} review(s) filed, {} finding(s).".format(len(entries), len(findings)))
    if incomplete:
        # Above the numbers. A review that stopped early reported fewer
        # findings than it would have, and folding it in reads as a quiet run.
        print("{} review(s) did not complete and their finding counts mean "
              "nothing: {}".format(
                  len(incomplete), ", ".join(e["ref"] for e in incomplete)))

    print("\n{:<16}{:>8}".format("verdict", "count"))
    print("-" * 24)
    for name in VERDICTS:
        print("{:<16}{:>8}".format(name, tally[name]))

    if not judged:
        print("\nNothing has been adjudicated, so there is no rate to report. "
              "Every finding above is a claim nobody has checked.")
        return 0

    print("\nOf the {} finding(s) a person has judged, {} were real "
          "({:.0f}%).".format(judged, tally["real"], 100 * tally["real"] / judged))
    if tally["unadjudicated"]:
        print("{} finding(s) are not yet judged and are excluded from that "
              "figure — not counted as wrong. The two are different "
              "statements.".format(tally["unadjudicated"]))
    if tally["unclear"]:
        print("{} were left `unclear`, which is a real answer and stays out of "
              "the rate.".format(tally["unclear"]))

    blocked = [f for f in findings if f.get("blocked_the_merge")]
    if blocked:
        wrong = sum(1 for f in blocked if f.get("verdict") == "not_real")
        print("\n{} finding(s) actually blocked a merge; {} of those were "
              "judged not real.".format(len(blocked), wrong))

    print("\nThis is not independent evidence: the same person wrote the "
          "prompts, the code under review, and the verdicts above.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--journal", default=str(JOURNAL), metavar="DIR")
    sub = parser.add_subparsers(dest="command", required=True)

    adder = sub.add_parser("add", help="file a review artifact")
    adder.add_argument("artifact")
    adder.add_argument("--ref", required=True,
                       help="what was reviewed — a commit sha or MR id")

    sub.add_parser("report", help="what has been filed and judged")

    args = parser.parse_args()
    root = Path(args.journal)

    if args.command == "add":
        artifact = Path(args.artifact)
        if not artifact.is_file():
            print("no such artifact: {}".format(artifact), file=sys.stderr)
            return 2
        root.mkdir(parents=True, exist_ok=True)
        return add(artifact, args.ref, root)
    if not root.is_dir():
        print("no journal at {} — file something with `add` first".format(root),
              file=sys.stderr)
        return 2
    return report(root)


if __name__ == "__main__":
    sys.exit(main())
