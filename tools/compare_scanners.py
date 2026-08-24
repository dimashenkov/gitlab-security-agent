#!/usr/bin/env python3
"""Score other scanners on the same pairs, with the same rule.

The corpus is not ours in any useful sense — it is a set of matched safe/unsafe
pairs, and any tool that reads source can be pointed at them. That makes it the
only honest way to compare: same code, same question, same scoring, no
per-tool interpretation of what counts as a hit.

Semgrep is here because it is what GitLab's SAST analyzers run, so scoring it is
scoring the thing this agent would sit next to in a pipeline. CodeQL is what
GitHub runs; it is supported for the languages where a database can be built
without compiling, which is why the compiled-language cases go unscored rather
than being quietly counted as misses.

    pair passes = the safe member produces no finding in the target file
                  AND the unsafe member produces one

Deliberately more generous to the other tools than to our own agent: theirs is
matched on file alone, not category, because a rule id like
`javascript.react.security.audit.react-dangerouslysetinnerhtml` does not map to
our category vocabulary and forcing it would measure the mapping. Where the
comparison is unfair, it is unfair in their favour.

Usage:
    tools/compare_scanners.py corpus/ --scanner semgrep
    tools/compare_scanners.py corpus/ --scanner semgrep --json /tmp/semgrep.json
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
import time
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from pair_corpus import build_repo, load_cases

# Semgrep's own curated security rulesets. `p/security-audit` plus the
# language packs is the closest public equivalent to what a GitLab SAST job
# runs; `--config auto` was rejected because it varies with what the registry
# serves on the day and would make the number unreproducible.
SEMGREP_CONFIGS = ("p/security-audit", "p/secrets", "p/owasp-top-ten")

# CodeQL builds a database without compiling only for these. Java, Go, C# and
# C/C++ need a working build of the case, which these minimal cases do not have,
# so they are reported as unsupported rather than as misses.
CODEQL_NO_BUILD = {"python", "javascript", "typescript", "ruby"}
CODEQL_LANGUAGE = {"typescript": "javascript", "javascript": "javascript",
                   "python": "python", "ruby": "ruby"}


def run_semgrep(repo: Path, target: str) -> dict:
    cmd = ["semgrep", "scan", "--json", "--quiet", "--no-git-ignore",
           "--metrics", "off", "--disable-version-check"]
    for config in SEMGREP_CONFIGS:
        cmd += ["--config", config]
    cmd.append(str(repo))
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if not proc.stdout.strip():
        return {"ok": False, "error": (proc.stderr.strip().splitlines()
                                       or ["no output"])[-1][:120]}
    payload = json.loads(proc.stdout)
    hits = [r for r in payload.get("results", [])
            if str(r.get("path", "")).endswith(target)]
    return {"ok": True, "hit": bool(hits),
            "rules": sorted({r.get("check_id", "") for r in hits}),
            "total": len(payload.get("results", []))}


def run_codeql(repo: Path, target: str, language: str) -> dict:
    lang = CODEQL_LANGUAGE.get(language)
    if lang is None:
        return {"ok": False, "unsupported": True,
                "error": "codeql needs a build for {}".format(language)}
    db = repo.parent / "codeql-db"
    build = subprocess.run(
        ["codeql", "database", "create", str(db), "--language", lang,
         "--source-root", str(repo), "--overwrite"],
        capture_output=True, text=True, check=False)
    if build.returncode != 0:
        return {"ok": False,
                "error": (build.stderr.strip().splitlines() or ["db failed"])[-1][:120]}
    sarif = repo.parent / "results.sarif"
    scan = subprocess.run(
        ["codeql", "database", "analyze", str(db),
         "codeql/{}-queries:codeql-suites/{}-security-extended.qls".format(lang, lang),
         "--format", "sarif-latest", "--output", str(sarif)],
        capture_output=True, text=True, check=False)
    if not sarif.is_file():
        return {"ok": False,
                "error": (scan.stderr.strip().splitlines() or ["analyze failed"])[-1][:120]}
    payload = json.loads(sarif.read_text())
    results = [r for run in payload.get("runs", []) for r in run.get("results", [])]

    def path_of(result: dict) -> str:
        for loc in result.get("locations", []):
            uri = loc.get("physicalLocation", {}).get("artifactLocation", {}).get("uri", "")
            if uri:
                return uri
        return ""

    hits = [r for r in results if path_of(r).endswith(target)]
    return {"ok": True, "hit": bool(hits),
            "rules": sorted({r.get("ruleId", "") for r in hits}),
            "total": len(results)}


SCANNERS = {"semgrep": run_semgrep, "codeql": run_codeql}


def scanner_version(name: str) -> str:
    """The exact build that produced a number, recorded with the number.

    A comparison against "Semgrep" is not reproducible; a comparison against
    Semgrep 1.136.0 with three named rulesets is. Rulesets are served from a
    registry and change under a stable name, so a result quoted six months from
    now without this line is a claim about a tool nobody can identify.
    """
    try:
        out = subprocess.run((name, "--version"), capture_output=True,
                             text=True, check=False, timeout=30).stdout
    except (OSError, subprocess.SubprocessError):
        return "unknown"
    for line in out.splitlines():
        if line.strip():
            return line.strip()
    return "unknown"


def configuration(name: str) -> str:
    if name == "semgrep":
        return "rulesets " + ", ".join(SEMGREP_CONFIGS)
    return "suite <lang>-security-extended.qls"


def run_case(case: dict, scanner: str) -> dict:
    work = Path(tempfile.mkdtemp(prefix="cmp-{}-".format(case["case_id"]))).resolve()
    row = {"case_id": case["case_id"], "language": case.get("language", "?"),
           "family": case.get("family", "?"), "scanner": scanner}
    try:
        members = {}
        for member in ("safe", "unsafe"):
            repo, _, _ = build_repo(case["_dir"], member, work / member)
            if scanner == "codeql":
                members[member] = run_codeql(repo, case["expected_file"],
                                             case.get("language", ""))
            else:
                members[member] = run_semgrep(repo, case["expected_file"])

        if not all(m["ok"] for m in members.values()):
            failed = next(m for m in members.values() if not m["ok"])
            row["error"] = failed["error"]
            row["unsupported"] = failed.get("unsupported", False)
            return row

        safe_hit = members["safe"]["hit"]
        unsafe_hit = members["unsafe"]["hit"]
        row.update({
            "safe_false_positive": safe_hit,
            "unsafe_recall": unsafe_hit,
            "pair_success": (not safe_hit) and unsafe_hit,
            "unsafe_rules": members["unsafe"]["rules"][:3],
            "safe_rules": members["safe"]["rules"][:3],
        })
        return row
    except Exception as exc:
        row["error"] = "{}: {}".format(type(exc).__name__, exc)
        return row
    finally:
        shutil.rmtree(work, ignore_errors=True)


def report(rows: list, scanner: str) -> None:
    done = [r for r in rows if "pair_success" in r]
    unsupported = [r for r in rows if r.get("unsupported")]
    broken = [r for r in rows if "error" in r and not r.get("unsupported")]

    print("\n" + "=" * 78)
    if unsupported:
        # Named, not folded into the denominator. A tool that cannot analyse a
        # language has not failed those cases; counting them as misses would be
        # the same dishonesty as counting them as passes.
        print("{} case(s) {} cannot analyse here: {}".format(
            len(unsupported), scanner,
            ", ".join(sorted(r["case_id"] for r in unsupported))))
    if broken:
        print("{} case(s) errored:".format(len(broken)))
        for r in broken:
            print("  {:<18} {}".format(r["case_id"], str(r["error"])[:56]))
    if not done:
        print("nothing scorable")
        return

    print("\n{:<18}{:<12}{:<17}{:>8}{:>9}{:>8}".format(
        "case", "language", "family", "safe", "unsafe", "pair"))
    print("-" * 78)
    for r in sorted(done, key=lambda r: (r["language"], r["case_id"])):
        print("{:<18}{:<12}{:<17}{:>8}{:>9}{:>8}".format(
            r["case_id"], r["language"], r["family"],
            "FP" if r["safe_false_positive"] else "quiet",
            "found" if r["unsafe_recall"] else "MISS",
            "pass" if r["pair_success"] else "FAIL"))

    print("\n{:<14}{:>7}{:>16}{:>12}{:>14}".format(
        "language", "pairs", "discrimination", "false pos", "recall"))
    print("-" * 63)
    by_language = defaultdict(list)
    for r in done:
        by_language[r["language"]].append(r)
    for language, group in sorted(by_language.items()):
        n = len(group)
        print("{:<14}{:>7}{:>15.0f}%{:>11.0f}%{:>13.0f}%".format(
            language, n,
            100 * sum(r["pair_success"] for r in group) / n,
            100 * sum(r["safe_false_positive"] for r in group) / n,
            100 * sum(r["unsafe_recall"] for r in group) / n))

    n = len(done)
    print("\n{}: {}/{} pairs discriminated, {} false positive(s), {} miss(es){}".format(
        scanner, sum(r["pair_success"] for r in done), n,
        sum(r["safe_false_positive"] for r in done),
        sum(not r["unsafe_recall"] for r in done),
        " — {} case(s) unsupported".format(len(unsupported)) if unsupported else ""))
    print("  {}  ·  {}".format(scanner_version(scanner), configuration(scanner)))
    print("\nThis is a capability matrix, not a leaderboard. These tools answer "
          "a different question at a different price, and the pairs were written "
          "here — a corpus authored alongside one tool is not a neutral ground "
          "on which to rank another.")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("cases")
    parser.add_argument("--scanner", choices=sorted(SCANNERS), default="semgrep")
    parser.add_argument("--language")
    parser.add_argument("--json", metavar="PATH")
    args = parser.parse_args()

    if not shutil.which(args.scanner):
        sys.exit("{} is not on PATH".format(args.scanner))

    cases = load_cases(Path(args.cases), args.language or "", "")
    if not cases:
        sys.exit("no cases matched")
    print("scoring {} on {} pair(s)\n".format(args.scanner, len(cases)))

    rows = []
    for case in cases:                       # serial: these scanners are CPU-bound
        row = run_case(case, args.scanner)
        rows.append(row)
        print("  {:<18} {}".format(
            row["case_id"],
            row.get("error") or ("pass" if row["pair_success"] else "FAIL")))

    report(rows, args.scanner)
    if args.json:
        Path(args.json).write_text(json.dumps({
            "scanner": args.scanner,
            "version": scanner_version(args.scanner),
            "configuration": configuration(args.scanner),
            "results": rows,
        }, indent=2))
        print("\nraw results written to {}".format(args.json))
    return 0


if __name__ == "__main__":
    started = time.monotonic()
    code = main()
    print("elapsed {:.0f}s".format(time.monotonic() - started))
    sys.exit(code)
