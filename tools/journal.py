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

# The trial's vocabulary, not a truth vocabulary. "Is this finding real" turned
# out to be the wrong question for deciding whether to keep running the tool: a
# finding can be perfectly real and still worth nothing, because the author had
# already seen it before the agent said anything. The question that decides is
# whether it showed him something he had missed and changed what he did.
VERDICTS = (
    "novel_actionable",     # he had missed it, and changed code because of it
    "already_known",        # real, and in his pre-review note
    "real_non_actionable",  # real, and nothing was done or needed doing
    "not_real",
    "unclear",
    "unadjudicated",
)

# The only verdict that argues for keeping the tool. Everything else is neutral
# or a cost. Ten wrong findings dismissed in a minute each establish low
# irritation, not value, and a count of findings establishes nothing at all.
VALUABLE = ("novel_actionable",)


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
        # The fields a person fills in. They stay empty until someone reads the
        # code, and nothing here will quietly decide them.
        "verdict": "unadjudicated",
        # How long adjudicating this one took. The tool has to beat the
        # attention it costs, and attention is the part nobody bills for.
        "minutes": 0,
        # Which rulings in `precedents.yml` apply to this finding, tagged by
        # hand. Nothing suppresses on them — they are proposed, and this is how
        # the month decides which are worth adopting. A precedent that matches
        # a `novel_actionable` finding is dangerous; one that repeatedly
        # matches `not_real` is a candidate.
        #
        # Tagged by a person because the facts they turn on are not in any
        # field: whether an SSRF controls only the path, whether an environment
        # variable crosses a trust boundary, whether a race is reachable.
        # Another model classifier would cost money and add a second
        # stochastic decision to a measurement built to remove one.
        "applicable_precedents": [],
        "note": "",
    }


def add(artifact: Path, ref: str, root: Path, noticed: str = "") -> int:
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
        # Written BEFORE the agent's output is read. If the report is read
        # first, a useful finding can no longer be told apart from something
        # the author would have noticed anyway, and the trial answers a
        # different question than the one it was set up for.
        "noticed_before_running": noticed,
        # A security issue the human found that the agent did not. Without a
        # place to write it, the trial counts hits and never misses.
        "missed_by_the_agent": "",
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
    judged = sum(tally[name] for name in VERDICTS
                 if name not in ("unadjudicated", "unclear"))
    valuable = sum(tally[name] for name in VALUABLE)
    minutes = sum(int(f.get("minutes") or 0) for f in findings)
    misses = [e for e in entries if (e.get("missed_by_the_agent") or "").strip()]

    print("\n{} review(s) filed, {} finding(s).".format(len(entries), len(findings)))
    if incomplete:
        # Above the numbers. A review that stopped early reported fewer
        # findings than it would have, and folding it in reads as a quiet run.
        print("{} review(s) did not complete and their finding counts mean "
              "nothing: {}".format(
                  len(incomplete), ", ".join(e["ref"] for e in incomplete)))

    print("\n{:<22}{:>8}".format("verdict", "count"))
    print("-" * 30)
    for name in VERDICTS:
        print("{:<22}{:>8}".format(name, tally[name]))

    if misses:
        # The column that stops this being a scoreboard of hits. A tool that
        # never contradicts you and never finds what you found yourself has
        # told you nothing.
        print("\n{} review(s) where a person found a security issue the agent "
              "did not: {}".format(len(misses), ", ".join(e["ref"] for e in misses)))

    if not judged:
        print("\nNothing has been adjudicated, so there is nothing to decide "
              "on. Every finding above is a claim nobody has checked.")
        return 0

    print("\nOf the {} finding(s) a person has judged, {} showed something "
          "that had been missed and changed the code ({:.0f}%).".format(
              judged, valuable, 100 * valuable / judged))
    for name in ("already_known", "real_non_actionable", "not_real"):
        if tally[name]:
            print("  {} were {}".format(tally[name], name.replace("_", " ")))
    if minutes:
        print("Adjudication cost {} minute(s) across those findings."
              .format(minutes))
    if tally["unadjudicated"]:
        print("{} finding(s) are not yet judged and are excluded — not counted "
              "as wrong. The two are different statements."
              .format(tally["unadjudicated"]))
    if tally["unclear"]:
        print("{} were left `unclear`, which is a real answer and stays out of "
              "the count.".format(tally["unclear"]))

    # What the proposed rulings would have done, had any been in force. This is
    # the whole reason they are `proposed` rather than adopted: a precedent that
    # would have eaten a finding the author called real is not a precision
    # improvement, it is a miss with a justification attached.
    tagged = Counter(name for f in findings
                     for name in (f.get("applicable_precedents") or []))
    if tagged:
        print("\nProposed precedents, and what they would have suppressed:")
        print("{:<40}{:>8}{:>12}".format("precedent", "matched", "on real"))
        print("-" * 60)
        for name, count in tagged.most_common():
            dangerous = sum(
                1 for f in findings
                if name in (f.get("applicable_precedents") or [])
                and f.get("verdict") in VALUABLE)
            print("{:<40}{:>8}{:>12}".format(name, count, dangerous))
        harmful = [n for n in tagged if any(
            n in (f.get("applicable_precedents") or []) and f.get("verdict") in VALUABLE
            for f in findings)]
        if harmful:
            print("Do not adopt {} — it matched a finding you judged worth "
                  "acting on.".format(", ".join(harmful)))

    blocked = [f for f in findings if f.get("blocked_the_merge")]
    if blocked:
        wrong = sum(1 for f in blocked if f.get("verdict") == "not_real")
        print("\n{} finding(s) actually blocked a merge; {} of those were "
              "judged not real.".format(len(blocked), wrong))

    # The decision, spelled out, because the counts above do not make it and a
    # reader looking for a reason to keep a tool will find one in any table.
    print("\nKeep it if at least one of those {} was something that would "
          "otherwise have shipped. Turn it off if none was, if wrong findings "
          "keep costing real attention, or if you catch yourself reading a "
          "quiet report as reassurance.".format(valuable))
    if len(entries) < 10:
        print("{} of 10 eligible changes so far — too few to decide on."
              .format(len(entries)))

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
    adder.add_argument("--noticed", default="",
                       help="what YOU spotted before reading the report. Write "
                            "it before you open the report, or a useful finding "
                            "cannot be told apart from one you would have found "
                            "anyway.")

    sub.add_parser("report", help="what has been filed and judged")

    args = parser.parse_args()
    root = Path(args.journal)

    if args.command == "add":
        artifact = Path(args.artifact)
        if not artifact.is_file():
            print("no such artifact: {}".format(artifact), file=sys.stderr)
            return 2
        root.mkdir(parents=True, exist_ok=True)
        return add(artifact, args.ref, root, args.noticed)
    if not root.is_dir():
        print("no journal at {} — file something with `add` first".format(root),
              file=sys.stderr)
        return 2
    return report(root)


if __name__ == "__main__":
    sys.exit(main())
