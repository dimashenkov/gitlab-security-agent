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
from typing import Optional, Sequence

import yaml

# Per million tokens, claude-opus-5.
# Pricing lives in the package, not here. There were three copies of these
# constants and two of them were wrong — a rate copied into a tool is a rate
# nobody updates.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from artifact import is_target as _is_target
from artifact import signature

from security_agent.config import MODEL_PRICING
from security_agent.models import Usage

MODEL = "claude-opus-5"
CACHE_TTL = "1h"

# Bumped whenever a change here alters what a number means, so two results can
# be compared only when they were produced by the same rules. The history so
# far, and why the field exists:
#   1  the original: pair_success = safe quiet AND unsafe found
#   2  a finding in the safe member split out of "false positive" into
#      `safe_target_persistence` plus unadjudicated incidentals
#   3  `hits_target` returns a third state; an incomplete run is unresolved,
#      not a miss; `expected_file` and `expected_category` became lists
SCORER_VERSION = 3


def cost_of(usage: dict) -> float:
    """What a review cost, at the rates and cache TTL the agent actually runs."""
    tally = Usage(
        input_tokens=usage["input_tokens"],
        output_tokens=usage["output_tokens"],
        cache_read_tokens=usage["cache_read_tokens"],
        cache_write_tokens=usage["cache_write_tokens"],
    )
    input_rate, output_rate = MODEL_PRICING[MODEL]
    return tally.cost_usd(input_rate, output_rate, CACHE_TTL)


ADJUDICATIONS = "adjudications.yml"


def load_adjudications(root: Path) -> list:
    """Hand decisions about findings the tool cannot score by itself.

    A finding in the safe member is a claim that the maintainers' fix did not
    close the weakness. That claim can be true — of the first three adjudicated,
    two were — and scoring it as a false positive by construction penalised
    correct work. Nothing automatable decides it, so the decision is recorded
    once, in a file, rather than made silently on every reading of the table.
    """
    path = root / ADJUDICATIONS
    if not path.is_file():
        return []
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return list(data.get("adjudications") or [])


def malformed_cases(root: Path) -> dict:
    """Cases an adjudication has ruled cannot measure anything, and why.

    `py-2cp2` is the example: the advisory is about `instantiate`, the fix IS
    the blocklist, and the reviewer's finding — that a string denylist checked
    before resolution is bypassable — is a correct statement about the fix. A
    pair whose safe member still carries the advisory's own weakness cannot
    discriminate in either direction, and counting it as a failure records the
    corpus's defect against the product.
    """
    return {
        row["case_id"]: row.get("why_malformed", "adjudicated malformed")
        for row in load_adjudications(root) if row.get("case_is_malformed")
    }


def load_cases(root: Path, language: str = "", family: str = "") -> list:
    excluded = malformed_cases(root)
    cases = []
    for manifest in sorted(root.rglob("case.yml")):
        spec = yaml.safe_load(manifest.read_text(encoding="utf-8")) or {}
        spec["_dir"] = manifest.parent
        spec.setdefault("case_id", manifest.parent.name)
        if language and spec.get("language") != language:
            continue
        if family and spec.get("family") != family:
            continue
        if spec["case_id"] in excluded:
            # Named on stderr rather than dropped in silence. A corpus that
            # quietly shrinks is a corpus whose denominator nobody can check.
            print("excluded {}: {}".format(
                spec["case_id"], " ".join(excluded[spec["case_id"]].split())),
                file=sys.stderr)
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


def hits_target(payload: dict, case: dict):
    """Did the review report the finding this case is about?

    Three answers, not two. `None` means the review never reached one — the run
    stopped early, so its empty finding list is an absence of evidence and not
    evidence of absence.

    That distinction was missing and it cost a result. Three of the four
    failures in the six-case harvested run had exit code 2: the review did not
    complete. This function read `payload["findings"]` and never
    `payload["complete"]`, so "the check did not run" was scored as "found
    nothing" — the same confusion the product itself is careful to avoid, in the
    tool that measures the product. A 2-of-6 built partly from runs that never
    happened is not a recall number.

    Matched on category and file rather than on wording: the same weakness gets
    described differently every run, and grading on prose would measure
    phrasing.
    """
    if not payload.get("complete", False):
        return None
    return any(_is_target(f, case) for f in payload.get("findings", []))


def _keep_artifacts(work: Path, result: dict, keep_dir: Optional[Path]) -> None:
    """Copy out the `findings.json` of anything that did not finish cleanly.

    The runner deleted its temp directory unconditionally, so when four
    reviews stopped early the only evidence of why was already gone — the
    diagnosis had to be reconstructed from the product's source, and ended in
    "one of these two causes, cannot tell". `stop_detail` names the limit, and
    it lives in the artifact and nowhere else.

    Only the runs worth keeping. A clean pass has nothing to explain and
    copying every artifact of a 48-case run is a different problem.
    """
    if keep_dir is None:
        return
    if not (result.get("error") or result.get("incomplete")):
        return
    for member in ("safe", "unsafe"):
        source = work / (member + "-out") / "findings.json"
        if not source.is_file():
            continue
        destination = keep_dir / result["case_id"] / member
        destination.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination / "findings.json")


def run_case(case: dict, keep_dir: Optional[Path] = None) -> dict:
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

        # Kept for every case, scored or not. `signature()` already extracts
        # exactly what a later question needs — whether the run finished, why it
        # stopped, what the gate did — and the previous version reduced a paid
        # run to two booleans, so answering "why did it miss" meant paying for
        # the run again.
        result["members"] = {
            member: dict(
                signature(members[member]["payload"], case),
                seconds=members[member]["seconds"],
                cost=cost_of(members[member]["payload"]["usage"]),
                usage=members[member]["payload"].get("usage", {}),
                coverage=members[member]["payload"].get("coverage_accounting", {}),
                refuted=members[member]["payload"].get("refuted", []),
                rejected_claims=members[member]["payload"].get("rejected_claims", []),
            )
            for member in ("safe", "unsafe")
        }

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
        # Four measurements, not one. `safe_false_positive` was the wrong name
        # for what it held: a finding of the target category in the target file
        # of the safe member. That is "the reviewer says the advisory weakness
        # is still there", which is a claim that can be right — a maintainer's
        # fix is not proof of absence, and one of these turned out to be a
        # correct objection that a string denylist checked before resolution is
        # bypassable. Calling it a false positive by construction scored a
        # correct finding as an error.
        #
        # Nothing here decides whether an incidental finding is real. That needs
        # adjudication against the advisory, which is not automatable and is
        # recorded as unresolved rather than guessed.
        if safe_hit is None or unsafe_hit is None:
            # Not a failure and not a pass. Scoring it either way would put a
            # number on a review that did not happen, and the direction it would
            # go — FAIL — is the one that makes the product look worse than the
            # evidence says.
            result["incomplete"] = [
                m for m in ("safe", "unsafe")
                if not members[m]["payload"].get("complete", False)
            ]
            result["cost"] = sum(cost_of(m["payload"]["usage"]) for m in members.values())
            result["seconds"] = max(m["seconds"] for m in members.values())
            return result

        result.update({
            "unsafe_target_recall": unsafe_hit,
            "safe_target_persistence": safe_hit,
            "safe_incidental": [
                f for f in summarise(members["safe"]["payload"])
                if not _is_target(f, case)
            ],
            "unsafe_incidental": [
                f for f in summarise(members["unsafe"]["payload"])
                if not _is_target(f, case)
            ],
            # Kept under the old names so nothing downstream breaks silently,
            # but they are aliases now and the report says what they mean.
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
        _keep_artifacts(work, result, keep_dir)
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


def _progress(row: dict) -> str:
    """One word for a finished case, for every shape a case can finish in."""
    if row.get("error"):
        return str(row["error"])[:60]
    if row.get("incomplete"):
        return "did not complete ({})".format(", ".join(row["incomplete"]))
    if "pair_success" not in row:
        return "no result recorded"
    return "pass" if row["pair_success"] else "FAIL"


def report(results: list, adjudications: Sequence[dict] = ()) -> None:
    verdicts = {
        (row.get("case_id"), row.get("member"), row.get("file")): row.get("verdict", "?")
        for row in adjudications
    }
    done = [r for r in results if "pair_success" in r]
    broken = [r for r in results if "error" in r]
    unresolved = [r for r in results if r.get("incomplete")]

    print("\n" + "=" * 78)
    if broken:
        print("{} case(s) could not run:".format(len(broken)))
        for r in broken:
            print("  {:<20} {}".format(r["case_id"], r["error"][:70]))
    if unresolved:
        # Printed above the score, not below it. A denominator that silently
        # drops the runs that stopped early reads as coverage it does not have.
        print("{} case(s) did not complete and are not scored:".format(len(unresolved)))
        for r in unresolved:
            members = r.get("members", {})
            print("  {:<20} {}".format(r["case_id"], ", ".join(
                "{}: {}".format(m, members.get(m, {}).get("stop_reason") or "no reason recorded")
                for m in r["incomplete"])))
        print("  Their finding lists are empty because the review stopped, not "
              "because it found nothing.")
    if not done:
        print("nothing to score")
        return

    print("\n{:<20}{:<12}{:<16}{:>8}{:>10}{:>9}".format(
        "case", "language", "family", "safe", "unsafe", "pair"))
    print("-" * 78)
    for r in sorted(done, key=lambda r: (r["language"], r["family"], r["case_id"])):
        print("{:<22} {:<11} {:<16}{:>8}{:>10}{:>9}".format(
            r["case_id"], r["language"], r["family"],
            "claims" if r["safe_false_positive"] else "quiet",
            "found" if r["unsafe_recall"] else "MISS",
            "pass" if r["pair_success"] else "FAIL"))

    incidental = [(r["case_id"], side, f)
                  for r in done for side in ("safe", "unsafe")
                  for f in r.get(side + "_incidental", [])]
    if incidental:
        # Reported, never scored. These are weaknesses outside what the advisory
        # was about — some real, some not. Counting them as errors would punish
        # a correct finding; counting them as successes would credit a guess.
        # Neither is decidable here, so each carries its hand decision or the
        # word `unadjudicated`, and the word is the point: it says the number
        # above does not account for these.
        print("\nIncidental findings — outside the advisory:")
        for case_id, side, f in incidental:
            print("  {:<24}{:<7}{:<10}{:<20}{:<14}{}".format(
                case_id, side, f.get("severity") or "?",
                f.get("category") or "?",
                verdicts.get((case_id, side, f.get("file") or ""), "unadjudicated"),
                (f.get("title") or "")[:38]))
        undecided = sum(
            1 for case_id, side, f in incidental
            if (case_id, side, f.get("file") or "") not in verdicts)
        if undecided:
            print("  {} of {} not yet adjudicated. Two of the first three "
                  "adjudicated were real, so treating these as errors would "
                  "understate the product.".format(undecided, len(incidental)))

    print("\n{:<14}{:>7}{:>16}{:>12}{:>14}".format(
        "language", "pairs", "discrimination", "still-there", "recall"))
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
    parser.add_argument("--keep-artifacts", metavar="DIR",
                        help="Copy the findings.json of any case that failed "
                             "or did not complete here. On by default under "
                             "the --json path's directory; the reason a run "
                             "stopped lives in the artifact and nowhere else.")
    args = parser.parse_args()

    keep_dir = Path(args.keep_artifacts) if args.keep_artifacts else (
        Path(args.json).resolve().parent / "incomplete" if args.json else None)
    if keep_dir:
        keep_dir.mkdir(parents=True, exist_ok=True)

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
        futures = {pool.submit(run_case, c, keep_dir): c for c in cases}
        for future in as_completed(futures):
            r = future.result()
            results.append(r)
            # Never index into the row here. This line ran `r["pair_success"]`
            # and a case with an unresolved member has no such key, so the
            # first incomplete run raised KeyError inside the loop — before the
            # `--json` write below — and threw away every case already paid
            # for. The progress line is the least important thing on this
            # screen and it must not be able to end the run.
            print("  {:<20} {}".format(r["case_id"], _progress(r)))

    # Written before the report. A crash while formatting would otherwise throw
    # away runs already paid for.
    if args.json:
        Path(args.json).write_text(json.dumps(results, indent=2))
        print("\nraw results written to {}".format(args.json))
    report(results, load_adjudications(Path(args.cases)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
