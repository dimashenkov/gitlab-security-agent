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

IN_RATE, OUT_RATE = 5.0, 25.0


def cost_of(usage: dict) -> float:
    return (
        usage["input_tokens"] * IN_RATE
        + usage["cache_write_tokens"] * IN_RATE * 1.25
        + usage["cache_read_tokens"] * IN_RATE * 0.1
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
        result.update({
            "safe_false_positive": safe_hit,
            "unsafe_recall": unsafe_hit,
            "pair_success": (not safe_hit) and unsafe_hit,
            "safe_exit": members["safe"]["exit_code"],
            "unsafe_exit": members["unsafe"]["exit_code"],
            "cost": sum(cost_of(m["payload"]["usage"]) for m in members.values()),
            "seconds": max(m["seconds"] for m in members.values()),
        })
        return result
    except Exception as exc:                      # a broken case must not stop the run
        result["error"] = "{}: {}".format(type(exc).__name__, exc)
        return result
    finally:
        shutil.rmtree(work, ignore_errors=True)


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
        print("{:<20}{:<12}{:<16}{:>8}{:>10}{:>9}".format(
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

    print("\ntotal cost ${:.2f} across {} pairs".format(
        sum(r["cost"] for r in done), len(done)))
    print("\nWith this many pairs the confidence interval is wide. Treat a clean "
          "sheet as 'found no failure', not as a bound on the failure rate.")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("cases", help="directory holding case.yml manifests")
    parser.add_argument("--language")
    parser.add_argument("--family")
    parser.add_argument("-c", "--concurrency", type=int, default=4)
    parser.add_argument("--json", metavar="PATH")
    args = parser.parse_args()

    cases = load_cases(Path(args.cases), args.language or "", args.family or "")
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

    report(results)
    if args.json:
        Path(args.json).write_text(json.dumps(results, indent=2))
        print("\nraw results written to {}".format(args.json))
    return 0


if __name__ == "__main__":
    sys.exit(main())
