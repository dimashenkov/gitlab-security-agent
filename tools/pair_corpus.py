#!/usr/bin/env python3
"""Score the agent on matched safe/unsafe pairs.

Counting decoys the agent stayed quiet about measures very little. Five true
negatives, all authored by the same person who wrote the prompt, put the upper
bound on the false-positive rate somewhere near half — and repeating the run
measures stability, not sample size.

A pair fixes that. Two versions of the same code differing by one
security-relevant change: the safe member keeps the control, the unsafe member
removes it. Everything else — framework, structure, surrounding code, diff size
— is held constant, so what is being measured is whether the agent can tell the
decisive idiom apart, rather than whether it recognises alarming-looking tokens.

    pair success = safe member produces no target finding
                   AND unsafe member produces the expected one

Reporting both members fails the pair despite perfect recall. Reporting neither
also fails. That is the property that cannot be gamed by flagging everything.

Each case is a directory:

    cases/go-sql-01/
        case.yml        the manifest — family, language, expectations
        safe/           a git repo, or a script that builds one
        unsafe/

Usage:
    tools/pair_corpus.py cases/            run every case
    tools/pair_corpus.py cases/ --family injection --language go
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
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import yaml

# Per million tokens, claude-opus-5.
IN_RATE, OUT_RATE = 5.0, 25.0

# A cache write costs 1.25x the input rate at the five-minute TTL and **2x at
# the one-hour TTL** — and the agent runs with `cache_ttl = "1h"`, so 1.25 was
# the wrong constant and every cost this tool has ever reported was low.
CACHE_WRITE_MULTIPLIER = 2.0
CACHE_READ_MULTIPLIER = 0.1


def cost_of(usage: dict) -> float:
    return (
        usage["input_tokens"] * IN_RATE
        + usage["cache_write_tokens"] * IN_RATE * CACHE_WRITE_MULTIPLIER
        + usage["cache_read_tokens"] * IN_RATE * CACHE_READ_MULTIPLIER
        + usage["output_tokens"] * OUT_RATE
    ) / 1e6


def load_cases(root: Path, language: str = "", family: str = "") -> list:
    cases = []
    for manifest in sorted(root.rglob("case.yml")):
        spec = yaml.safe_load(manifest.read_text(encoding="utf-8")) or {}
        spec["_dir"] = manifest.parent
        spec.setdefault("case_id", manifest.parent.name)
        if language and spec.get("language") != language:
            continue
        if family and spec.get("family") != family:
            continue
        cases.append(spec)
    return cases


def build_repo(case: Path, member: str, work: Path) -> tuple:
    """Materialise one member as a git repository with a reviewable change.

    Returns (repo path, base rev, head rev). The baseline commit holds the
    surrounding code; the second commit is what the agent reviews, so the diff
    the agent sees is the change itself rather than a whole tree appearing at
    once.
    """
    src = case / member
    repo = work / member
    shutil.copytree(src, repo)

    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": str(work),
        "GIT_AUTHOR_NAME": "Corpus", "GIT_AUTHOR_EMAIL": "corpus@example.invalid",
        "GIT_COMMITTER_NAME": "Corpus", "GIT_COMMITTER_EMAIL": "corpus@example.invalid",
    }

    def git(*args):
        subprocess.run(("git", "-C", str(repo), *args),
                       check=True, capture_output=True, env=env)

    def rev_parse() -> str:
        return subprocess.run(("git", "-C", str(repo), "rev-parse", "HEAD"),
                              check=True, capture_output=True, text=True,
                              env=env).stdout.strip()

    git("init", "-q", "-b", "main")

    # Anything under `change/` is the proposed change; the rest is baseline.
    # Paths inside it are repository-relative, not flattened to a basename: a
    # case with `change/src/api/views.py` must land at `src/api/views.py`, or
    # the package structure is destroyed, imports become false, and two files
    # sharing a basename collide. The hand-written corpus happened to be flat,
    # which is why flattening went unnoticed until real repositories arrived.
    change_dir = repo / "change"
    staged = []          # (repository-relative path, holding place)
    if change_dir.is_dir():
        for source in sorted(p for p in change_dir.rglob("*") if p.is_file()):
            relative = source.relative_to(change_dir)
            held = work / "_held" / relative
            held.parent.mkdir(parents=True, exist_ok=True)
            source.rename(held)
            staged.append((relative, held))
        shutil.rmtree(change_dir)

    git("add", "-A")
    git("commit", "-qm", "baseline")
    base = rev_parse()

    for relative, held in staged:
        destination = repo / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        held.rename(destination)
    if staged:
        git("add", "-A")
        # Neutral, and identical on both members. A message that described the
        # change would be a hint, and one that differed between members would
        # be an answer key.
        git("commit", "-qm", "add feature")
    return repo, base, rev_parse()


def review(repo: Path, base: str, head: str, out: Path) -> dict:
    cmd = [
        sys.executable, "-m", "security_agent",
        "--repo", str(repo), "--mode", "diff", "--base", base, "--head", head,
        "--no-comment", "--output-dir", str(out),
    ]
    started = time.monotonic()
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    seconds = time.monotonic() - started
    payload_path = out / "findings.json"
    if not payload_path.is_file():
        return {"ok": False, "seconds": seconds,
                "error": (proc.stderr.strip().splitlines() or ["no output"])[-1]}
    return {"ok": True, "seconds": seconds, "exit_code": proc.returncode,
            "payload": json.loads(payload_path.read_text())}


def hits_target(payload: dict, case: dict) -> bool:
    """Did the review report the finding this case is about?

    Matched on category and file rather than on wording — the same weakness gets
    described differently every run, and grading on prose would measure
    phrasing.
    """
    want_category = case.get("expected_category")
    want_file = case.get("expected_file")
    for finding in payload.get("findings", []):
        if want_category and finding.get("category") != want_category:
            continue
        if want_file and not finding.get("file", "").endswith(want_file):
            continue
        return True
    return False


def run_case(case: dict) -> dict:
    # Resolved, because on macOS the temp directory is reached through a symlink
    # (/var -> /private/var) and the report writer refuses to write through one.
    work = Path(tempfile.mkdtemp(prefix="pair-{}-".format(case["case_id"]))).resolve()
    result = {"case_id": case["case_id"], "language": case.get("language", "?"),
              "family": case.get("family", "?")}
    try:
        members = {}
        for member in ("safe", "unsafe"):
            repo, base, head = build_repo(case["_dir"], member, work / member)
            out = work / (member + "-out")
            members[member] = review(repo, base, head, out)

        if not all(m["ok"] for m in members.values()):
            result["error"] = next(m.get("error") for m in members.values() if not m["ok"])
            return result

        safe_hit = hits_target(members["safe"]["payload"], case)
        unsafe_hit = hits_target(members["unsafe"]["payload"], case)

        # What was actually reported, not just whether. A pair that fails is a
        # question — was that a real false positive, or is the case scored too
        # loosely — and answering it from booleans means paying for the run
        # twice.
        def summarise(payload):
            return [
                {"category": f.get("category"), "file": f.get("file"),
                 "severity": f.get("severity"), "title": f.get("title"),
                 "blocking": f.get("fingerprint") in set(
                     payload.get("verdict", {}).get("blocking_fingerprints", []))}
                for f in payload.get("findings", [])
            ]
        result.update({
            "safe_false_positive": safe_hit,
            "unsafe_recall": unsafe_hit,
            "pair_success": (not safe_hit) and unsafe_hit,
            "safe_exit": members["safe"]["exit_code"],
            "unsafe_exit": members["unsafe"]["exit_code"],
            "size_delta": size_delta(case["_dir"]),
            "safe_findings": summarise(members["safe"]["payload"]),
            "unsafe_findings": summarise(members["unsafe"]["payload"]),
            "cost": sum(cost_of(m["payload"]["usage"]) for m in members.values()),
            "seconds": max(m["seconds"] for m in members.values()),
        })
        return result
    except Exception as exc:                      # a broken case must not stop the run
        result["error"] = "{}: {}".format(type(exc).__name__, exc)
        return result
    finally:
        shutil.rmtree(work, ignore_errors=True)


def size_delta(case_dir: Path) -> float:
    """How much bigger one member's change is than the other's, as a fraction.

    Positive means the safe member is larger, which is the usual direction: a
    security fix adds code. This is a confound that cannot be removed from real
    harvested cases without padding them into unreality, so it is measured and
    reported instead of hidden.
    """
    sizes = {}
    for member in ("safe", "unsafe"):
        change = case_dir / member / "change"
        sizes[member] = sum(
            len(p.read_bytes()) for p in change.rglob("*") if p.is_file()
        ) if change.is_dir() else 0
    total = sizes["safe"] + sizes["unsafe"]
    if not total:
        return 0.0
    return (sizes["safe"] - sizes["unsafe"]) / (total / 2)


# Below this, the two members are close enough in size that "pick the bigger
# one" cannot be what decided the answer. Chosen before seeing any score, so it
# is not a threshold fitted to make a number look better.
BALANCED = 0.10


def _stratified(done: list) -> str:
    """The score on the cases where size cannot have carried it.

    A corpus built from real fixes leaks size: the safe member is the one with
    the fix in it, and a fix is usually more code. Reporting only the headline
    would let that cue stand in for recognition. Reporting the balanced subset
    says what the score is where the cue is unavailable — and if the two numbers
    diverge, the difference is the size of the problem.
    """
    balanced = [r for r in done if abs(r.get("size_delta", 0.0)) < BALANCED]
    if not balanced:
        return ("\nNo case has members within {:.0f}% in size, so every pair "
                "here carries a size cue.".format(100 * BALANCED))
    passed = sum(r["pair_success"] for r in balanced)
    return (
        "\nOn the {} pair(s) whose members are within {:.0f}% in size — where "
        "'pick the larger member' cannot decide it — {} discriminated ({:.0f}%). "
        "Headline was {:.0f}%.".format(
            len(balanced), 100 * BALANCED, passed, 100 * passed / len(balanced),
            100 * sum(r["pair_success"] for r in done) / len(done))
    )


def report(results: list) -> None:
    done = [r for r in results if "pair_success" in r]
    broken = [r for r in results if "error" in r]

    print("\n" + "=" * 78)
    if broken:
        print("{} case(s) could not run:".format(len(broken)))
        for r in broken:
            print("  {:<20} {}".format(r["case_id"], r["error"][:70]))
    if not done:
        print("nothing to score")
        return

    print("\n{:<20}{:<12}{:<16}{:>8}{:>10}{:>9}".format(
        "case", "language", "family", "safe", "unsafe", "pair"))
    print("-" * 78)
    for r in sorted(done, key=lambda r: (r["language"], r["family"], r["case_id"])):
        print("{:<22} {:<11} {:<16}{:>8}{:>10}{:>9}".format(
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
    for language, rows in sorted(by_language.items()):
        n = len(rows)
        print("{:<14}{:>7}{:>15.0f}%{:>11.0f}%{:>13.0f}%".format(
            language, n,
            100 * sum(r["pair_success"] for r in rows) / n,
            100 * sum(r["safe_false_positive"] for r in rows) / n,
            100 * sum(r["unsafe_recall"] for r in rows) / n))

    families = Counter(r["family"] for r in done if not r["pair_success"])
    if families:
        print("\nfailing families: " + ", ".join(
            "{} ({})".format(f, n) for f, n in families.most_common()))

    print(_stratified(done))

    print("\ntotal cost ${:.2f} across {} pairs".format(
        sum(r["cost"] for r in done), len(done)))
    print("\nWith this many pairs the confidence interval is wide. Treat a clean "
          "sheet as 'found no failure', not as a bound on the failure rate.")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("cases", help="directory holding case.yml manifests")
    parser.add_argument("--language")
    parser.add_argument("--family")
    parser.add_argument("--case", action="append", metavar="ID",
                        help="Run only this case; repeatable. Re-running a "
                             "handful after a fix beats re-running the corpus.")
    parser.add_argument("-c", "--concurrency", type=int, default=4)
    parser.add_argument("--json", metavar="PATH")
    args = parser.parse_args()

    cases = load_cases(Path(args.cases), args.language or "", args.family or "")
    if args.case:
        wanted = set(args.case)
        cases = [c for c in cases if c["case_id"] in wanted]
        missing = wanted - {c["case_id"] for c in cases}
        if missing:
            sys.exit("no such case: " + ", ".join(sorted(missing)))
    if not cases:
        sys.exit("no cases matched")
    print("running {} pair(s) across {} worker(s)\n".format(
        len(cases), min(args.concurrency, len(cases))))

    results = []
    with ThreadPoolExecutor(max_workers=max(1, min(args.concurrency, len(cases)))) as pool:
        futures = {pool.submit(run_case, c): c for c in cases}
        for future in as_completed(futures):
            r = future.result()
            results.append(r)
            print("  {:<20} {}".format(
                r["case_id"],
                r.get("error") or ("pass" if r["pair_success"] else "FAIL")))

    # Written before the report. A crash while formatting would otherwise throw
    # away runs already paid for.
    if args.json:
        Path(args.json).write_text(json.dumps(results, indent=2))
        print("\nraw results written to {}".format(args.json))
    report(results)
    return 0


if __name__ == "__main__":
    sys.exit(main())
