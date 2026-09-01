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
import uuid
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Sequence

import yaml

# Per million tokens, claude-opus-5.
# Pricing lives in the package, not here. There were three copies of these
# constants and two of them were wrong — a rate copied into a tool is a rate
# nobody updates.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from artifact import (
    case_digest,
    load_adjudications,
    malformed_cases,
    ruled_incidental,
    signature,
)
from artifact import is_target as _is_target

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


def cost_of(usage: dict) -> Optional[float]:
    """What a review cost, or `None` when the runner reported no usage.

    It used to index the four counts straight out of the block and hand them
    to `Usage`, so a run that reported nothing arrived as four zeros and was
    priced at $0.00 — indistinguishable from a review that genuinely used no
    tokens, which no review ever is. The five `measurements/*.json` batches —
    38 member runs, none of them free — were summed that way, and the corpus
    reported a free measurement.

    `Usage.from_dict` decides it now, so this tool and the artifact writer
    share one rule instead of two that agree until they do not. That includes
    completeness: a stored total covering only some of a review's stages comes
    back `None` here rather than as a figure to add up.
    """
    input_rate, output_rate = MODEL_PRICING[MODEL]
    return Usage.from_dict(usage).cost_usd(input_rate, output_rate, CACHE_TTL)


def add_costs(costs: Sequence[Optional[float]]) -> Optional[float]:
    """The total, or `None` if any part of it is unknown.

    A sum with an unknown addend is unknown. Skipping the unknowns and
    printing the rest as the total is the arithmetic that turned an
    unmeasured batch into a cheap one — the reader sees a figure and has no
    way to tell it accounts for two of five pairs.
    """
    values = list(costs)
    if not values or any(value is None for value in values):
        return None
    return sum(value for value in values if value is not None)


def cost_summary(costs: Sequence[Optional[float]], unit: str = "pair") -> str:
    """One line about spend that never reads as free when it is unknown.

    Three cases and three sentences, because they are three different facts:
    everything measured, nothing measured, and — the one that hides — some
    measured. The partial case names the shortfall in the same sentence as
    the figure, so the number cannot be quoted without it.
    """
    values = list(costs)
    known = [value for value in values if value is not None]
    missing = len(values) - len(known)
    if not values:
        return "no runs to cost"
    if not known:
        # No currency figure anywhere in this sentence, not even to deny one.
        # A line that says "not $0.00" still puts a dollar amount on the page,
        # and the page is skimmed.
        return ("total cost: NOT REPORTED — {} {}s recorded no usage. This run "
                "cannot produce that figure; it is not zero.".format(
                    len(values), unit))
    if missing:
        # "not costable", not "reported no usage". The first go batch showed
        # why the wording matters: all twelve runs reported their review
        # stage's tokens, and this line said five of six pairs "reported no
        # usage" — because the verifier is a second CLI invocation that returns
        # no `Usage` at all, so the pair's total is incomplete and refuses to
        # price itself. Correct arithmetic, and a sentence that named the wrong
        # cause, inside the tool written to stop exactly that.
        return ("total cost ${:.2f} across {} of {} {}s — the other {} could "
                "not be costed, because some stage of each reported nothing; "
                "they are missing from that figure".format(
                    sum(known), len(known), len(values), unit, missing))
    return "total cost ${:.2f} across {} {}s".format(
        sum(known), len(values), unit)


def cost_per_pass(rows: Sequence[dict]) -> str:
    """Spend divided by pairs that actually discriminated, not by pairs run.

    Cost per run answers "what did this cost"; cost per *success* answers "what
    did a working answer cost", and the two move apart exactly when a change
    makes the reviewer cheaper and worse. A version that halves the bill and
    fails a third of the corpus improves the first number and ruins the second,
    and only the second would have said so.

    It refuses to divide by nothing and refuses to price an incomplete total,
    for the same reason `cost_summary` does: a figure produced from partial
    inputs gets quoted without its caveat.
    """
    priced = [(row.get("cost"), bool(row.get("pair_success")))
              for row in rows if row.get("cost") is not None]
    if not priced:
        return ""
    passed = sum(1 for _, ok in priced if ok)
    if not passed:
        return ("cost per discriminating pair: NOT AVAILABLE — none of the {} "
                "costed pair(s) discriminated. The spend bought no answer, "
                "which is a result and not a division.".format(len(priced)))
    total = sum(cost for cost, _ in priced)
    missing = len(rows) - len(priced)
    tail = ("" if not missing else
            " ({} pair(s) could not be costed and are in neither figure)"
            .format(missing))
    return ("cost per discriminating pair: ${:.2f}  —  ${:.2f} over {} of {} "
            "costed pair(s){}".format(
                total / passed, total, passed, len(priced), tail))


def notional_summary(rows: Sequence[dict]) -> str:
    """What the Claude Code CLI priced these runs at, or "" if it never said.

    A second line and never part of the first, because it is a different
    quantity. `provenance.reported_cost_usd` is what a run *would* have cost
    on the API; a two-token reply on a Max plan came back as $0.29, so adding
    it into "total cost" would bill a subscription. It is printed because the
    alternative is reporting "not reported" over runs whose provider did give
    a number — an artifact holds it, and this project takes its figures from
    artifacts.

    Partial by construction: only runs from after the field existed carry it,
    so the count is always stated beside the figure.
    """
    priced, total, seen = 0, 0.0, 0
    for row in rows:
        for member in (row.get("members") or {}).values():
            seen += 1
            figure = ((member or {}).get("provenance") or {}).get("reported_cost_usd")
            if isinstance(figure, (int, float)):
                priced += 1
                total += float(figure)
    if not priced:
        return ""
    return ("the CLI priced {} of those {} runs at ${:.2f} in total "
            "(provenance.reported_cost_usd). That is what they would have cost "
            "on the API, not what was billed — the login was a subscription — "
            "and it is not the figure above.".format(priced, seen, total))


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


def review(repo: Path, base: str, head: str, out: Path,
           provider: str = "", profile: str = "") -> dict:
    """One review of one member.

    `provider` and `profile` are passed through rather than defaulted here, so
    a corpus run costs whatever the operator chose and never silently the paid
    path. The corpus is 24 cases and every case is two reviews: a default that
    billed would make measuring the product an expense nobody agreed to.
    """
    cmd = [
        sys.executable, "-m", "security_agent",
        "--repo", str(repo), "--mode", "diff", "--base", base, "--head", head,
        "--no-comment", "--output-dir", str(out),
    ]
    if provider:
        cmd += ["--provider", provider]
    if profile:
        cmd += ["--profile", profile]
    started = time.monotonic()
    # The package lives in `src/` and is not installed, so the child needs it on
    # the path. Left to the caller's shell before, which worked whenever the
    # corpus was run from a prepared environment and failed with "No module
    # named security_agent" whenever it was not — a run that measures nothing
    # and says so in a truncated line.
    env = dict(os.environ)
    src = str(Path(__file__).resolve().parents[1] / "src")
    env["PYTHONPATH"] = src + os.pathsep + env["PYTHONPATH"] if env.get(
        "PYTHONPATH") else src
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False,
                          env=env)
    seconds = time.monotonic() - started
    payload_path = out / "findings.json"
    if not payload_path.is_file():
        return {"ok": False, "seconds": seconds,
                "error": (proc.stderr.strip().splitlines() or ["no output"])[-1]}
    return {"ok": True, "seconds": seconds, "exit_code": proc.returncode,
            "payload": json.loads(payload_path.read_text())}


def hits_target(payload: dict, case: dict, excused=()):
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
    return any(_is_target(f, case)
               and f.get("fingerprint") not in excused
               for f in payload.get("findings", []))


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


def run_case(case: dict, keep_dir: Optional[Path] = None,
             provider: str = "", profile: str = "",
             adjudications: Optional[Sequence[dict]] = None) -> dict:
    # Resolved, because on macOS the temp directory is reached through a symlink
    # (/var -> /private/var) and the report writer refuses to write through one.
    work = Path(tempfile.mkdtemp(prefix="pair-{}-".format(case["case_id"]))).resolve()
    result = {"case_id": case["case_id"], "language": case.get("language", "?"),
              "family": case.get("family", "?"),
              # Which version of the case this result is about.
              #
              # Nothing recorded it, so a result stayed attached to a case id
              # through any change to the case — and one case had its weakness
              # deleted by a bug in the comment stripper and then repaired,
              # which means a recorded failure for it was a failure at reviewing
              # code that no longer exists. `baseline.py` digests the whole
              # corpus tree, which is the right question for "are these two
              # numbers comparable" and the wrong one here: it would let an edit
              # to one case invalidate the results of the other forty-six.
              "case_digest": case_digest(case["_dir"]),
              # When this ran, so a later run of the same case supersedes an
              # earlier one. Without it the tracker had no order to take the
              # latest by — filename order is not run order and modification
              # time is not a record of anything — so two runs that disagreed
              # left the case unresolved, and a case could never be *fixed* by
              # running it again, only made worse. A re-run that cannot improve
              # anything is a re-run nobody does.
              # Microseconds, not seconds. Two runs of one case started in the
              # same second carried the same stamp, and `stage2.py` and
              # `check_accounted.py` order runs by it to take the latest — so
              # which of the two won was decided by the order of lines in a
              # file. `run_id` below cannot break that tie: it identifies a run
              # and says nothing about when it happened.
              "ran_at": datetime.now(timezone.utc).isoformat(
                  timespec="microseconds"),
              # Which execution this is. `ran_at` orders runs and does not
              # identify them: it is stamped at the *start* of the case, so it
              # answers "when did this begin", and a rule that counted
              # executions by it folded two into one — losing a confirming
              # failure and with it a regression. Microseconds make the
              # collision unlikely; they do not make the field an identifier.
              "run_id": uuid.uuid4().hex}
    try:
        members = {}
        for member in ("safe", "unsafe"):
            repo, base, head = build_repo(case["_dir"], member, work / member)
            out = work / (member + "-out")
            members[member] = review(repo, base, head, out, provider, profile)

        if not all(m["ok"] for m in members.values()):
            result["error"] = next(m.get("error") for m in members.values() if not m["ok"])
            return result

        # A hand decision may rule that a finding matching the coarse key
        # is not this case's weakness after all — a lesser one of the same
        # family in the same file. Without this the only ruling available
        # was to throw the whole case away, so a correct incidental in the
        # safe member failed a pair that discriminated perfectly.
        excused = ruled_incidental(adjudications, case["case_id"], "safe")
        safe_hit = hits_target(members["safe"]["payload"], case,
                               excused=excused)
        unsafe_hit = hits_target(members["unsafe"]["payload"], case)

        # Kept for every case, scored or not. `signature()` already extracts
        # exactly what a later question needs — whether the run finished, why it
        # stopped, what the gate did — and the previous version reduced a paid
        # run to two booleans, so answering "why did it miss" meant paying for
        # the run again.
        result["members"] = {
            member: dict(
                # The same excusals the scorer above used, and only those. A
                # ruling that reached `hits_target` and not this left the two
                # contradicting each other inside one result: the safe member
                # scored as not persisting while the row beside it still named
                # the excused finding as the case's target — which is the field
                # `stability.py` prints and `controls_agree` compares. Only the
                # safe member, because that is where `hits_target` applies them;
                # excusing in the unsafe member here would make the stored row
                # disagree with `unsafe_target_recall` in the other direction.
                signature(members[member]["payload"], case,
                          excused=excused if member == "safe" else ()),
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
                 # The identity a hand ruling names. Absent from this
                 # summary until now, so a decision about one finding
                 # could only be written against its file — which
                 # excuses every finding in that file.
                 "fingerprint": f.get("fingerprint"),
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
            result["cost"] = add_costs(
                [cost_of(m["payload"]["usage"]) for m in members.values()])
            result["seconds"] = max(m["seconds"] for m in members.values())
            return result

        result.update({
            "unsafe_target_recall": unsafe_hit,
            "safe_target_persistence": safe_hit,
            # An excused finding moves here rather than disappearing.
            # The ruling says the pair still discriminates, not that the
            # finding is uninteresting — and a real weakness dropped from
            # the report because a ruling took it out of the score is the
            # opposite of what the ruling said.
            "safe_incidental": [
                f for f in summarise(members["safe"]["payload"])
                if not _is_target(f, case) or f.get("fingerprint") in excused
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
            # `None` when either member reported nothing. A pair's cost is the
            # sum of two runs, and a sum with an unknown half is unknown — not
            # the half that happens to be measurable.
            "cost": add_costs([cost_of(m["payload"]["usage"]) for m in members.values()]),
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

    print("\n" + cost_summary([r.get("cost") for r in done], "pair"))
    per_pass = cost_per_pass(done)
    if per_pass:
        print(per_pass)
    notional = notional_summary(done)
    if notional:
        print(notional)
    print("\nWith this many pairs the confidence interval is wide. Treat a clean "
          "sheet as 'found no failure', not as a bound on the failure rate.")


def _build_parser() -> argparse.ArgumentParser:
    """The command line, separated from running it.

    `.gitlab-ci.yml` holds an invocation of this file that costs 8-15 USD, and
    it was missing `--provider` — a required argument, so the job died on
    argparse having measured nothing, and nothing in `tests/` reads that file.
    A test can only put that line in front of the real parser if the parser can
    be built without starting a single review.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("cases", help="directory holding case.yml manifests")
    parser.add_argument("--language")
    parser.add_argument("--family")
    parser.add_argument("--case", action="append", metavar="ID",
                        help="Run only this case; repeatable. Re-running a "
                             "handful after a fix beats re-running the corpus.")
    parser.add_argument(
        "--provider", choices=("anthropic-api", "claude-cli"), required=True,
        help="Who runs each review. Required, because omitting it selected the "
             "paid path — and this command is 48 reviews. A default that bills "
             "is a bill nobody chose.")
    parser.add_argument(
        "--profile", choices=("probe", "normal", "deep"),
        help="Ceilings for each review. Only the claude-cli provider reads it.")
    parser.add_argument("-c", "--concurrency", type=int, default=4)
    parser.add_argument("--json", metavar="PATH")
    parser.add_argument("--keep-artifacts", metavar="DIR",
                        help="Copy the findings.json of any case that failed "
                             "or did not complete here. On by default under "
                             "the --json path's directory; the reason a run "
                             "stopped lives in the artifact and nowhere else.")
    return parser


def main() -> int:
    args = _build_parser().parse_args()

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
        len(cases), min(args.concurrency, len(cases))), flush=True)

    # Read once, before anything runs. The rulings decide what counts as
    # this case's weakness, so a run that read them afterwards would score
    # against a different question than the one it was given.
    adjudications = load_adjudications(Path(args.cases))

    results = []
    with ThreadPoolExecutor(max_workers=max(1, min(args.concurrency, len(cases)))) as pool:
        futures = {pool.submit(run_case, c, keep_dir,
                               args.provider or "",
                               args.profile or "",
                               adjudications): c for c in cases}
        for future in as_completed(futures):
            r = future.result()
            results.append(r)
            # Never index into the row here. This line ran `r["pair_success"]`
            # and a case with an unresolved member has no such key, so the
            # first incomplete run raised KeyError inside the loop — before the
            # `--json` write below — and threw away every case already paid
            # for. The progress line is the least important thing on this
            # screen and it must not be able to end the run.
            # `flush`, because this is the only thing anybody watching a
            # forty-minute batch can see. Python block-buffers stdout when it
            # is a pipe rather than a terminal, so every one of these lines sat
            # in the buffer until the run ended — a progress report that
            # arrives with the result is not a progress report.
            print("  {:<20} {}".format(r["case_id"], _progress(r)), flush=True)

    # Written before the report. A crash while formatting would otherwise throw
    # away runs already paid for.
    if args.json:
        Path(args.json).write_text(json.dumps(results, indent=2))
        print("\nraw results written to {}".format(args.json))
    report(results, adjudications)
    return 0


if __name__ == "__main__":
    sys.exit(main())
