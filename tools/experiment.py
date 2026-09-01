#!/usr/bin/env python3
"""Two passes over one suite, with the comparison written before either is paid for.

    tools/experiment.py freeze noise-floor
    tools/experiment.py verify noise-floor
    tools/experiment.py run noise-floor a
    tools/experiment.py run noise-floor b
    tools/experiment.py compare noise-floor

## Why this exists rather than freezing two rounds

`round.py` freezes one pass and compares it against the verdicts a case already
had. That is the right shape for "has the product moved since last month" and
the wrong shape for "does the product move on its own": two independently frozen
rounds say nothing about which pass-B row answers which pass-A row, what counts
as a disagreement, or what happens when a case is missing from one side. Those
would then be decided after the results are visible, which is how a rule gets
fitted to the disagreements it is supposed to judge.

    You would then possess 140 valid contemporary reviews but no valid
    stability experiment.

## Why it runs the cases itself

The first version drove `run_queue.py`. Five rounds of adversarial review found
twenty defects in it, and near the end the shape of them stopped looking like a
thinning list of oversights: nearly all came from two machines with separate
lifecycles disagreeing about the same files. The experiment decided what was
admissible; the queue decided what had been executed and how a failure resumed;
a result file was at once an artefact, a checkpoint and a skip signal; two sets
of manifests each held part of the truth.

The last of those defects is the argument in one line. A result produced while
conditions had changed was correctly refused *on the terminal* — and left on
disk, where a later resume counted it as an ordinary verdict.

    The transaction belongs to the experiment and the write belongs to the
    queue.

So the experiment writes its own results, and nothing is published until the
case has run and the conditions have been checked again. What that costs is
windows and resets and the resume machinery, none of which this needs: a pass is
run when the window is open, and re-running the command continues from what was
accepted. What it removes is every intermediate state those two machines could
disagree about.

## What two passes can and cannot answer

They can answer: **does any case give a different verdict with nothing changed,
and which ones.** That is a detection, and one flip is enough for it.

They cannot answer: **how often.** Two throws of a coin that land differently
prove the coin is not glued; they do not estimate how often it lands heads. A
threshold for a regression gate needs the distribution, and the distribution
needs far more passes than a subscription will pay for in a day. Anyone quoting
a rate from this file is quoting something it does not contain.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent))

import round as round_tool
from artifact import case_digest
from sentinel import read_cases

ROOT = Path(__file__).resolve().parents[1]
SUITE = ROOT / "suites" / "sentinel.yml"
PASSES = ("a", "b")


def home(name: str) -> Path:
    return ROOT / "measurements" / "experiment-{}".format(name)


def digest_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()[:16]


def case_rows(cases: List[str]) -> List[Dict[str, Any]]:
    rows = []
    for case_id in cases:
        directory = ROOT / "corpus-real" / case_id
        manifest = directory / "case.yml"
        body = {}
        if manifest.is_file():
            import yaml
            body = yaml.safe_load(manifest.read_text(encoding="utf-8")) or {}
        rows.append({
            "case_id": case_id,
            "language": body.get("language", ""),
            "construction": body.get("construction", ""),
            "case_digest": case_digest(directory),
            # The answer key, digested separately, because `case_digest`
            # deliberately does not cover `case.yml` — and it is right not to,
            # for its own question. It asks "is this result about the code the
            # agent saw", so that correcting a category does not throw away a
            # run whose findings are still on file.
            #
            # This experiment asks something else. `expected_category` and
            # `expected_file` decide whether a finding counts, so editing them
            # between the passes changes the *scoring* while the code the agent
            # saw stays identical — and the flip would be reported as the
            # product moving on its own. Two questions, two digests.
            "answer_key_digest": (digest_file(manifest) if manifest.is_file()
                                  else "absent"),
        })
    return rows


def scorer_digest() -> str:
    """The code that turns findings into `pair_success`.

    `agent_version` covers the reviewer and moves only when somebody bumps it.
    The scorer is a separate thing and is edited far more often: change how a
    finding is matched to a target between the passes and every flip it causes
    reads as the product moving. Nothing in the prompt hashes would show it.
    """
    parts = []
    for name in ("pair_corpus.py", "artifact.py", "check_accounted.py"):
        path = ROOT / "tools" / name
        parts.append("{}:{}".format(
            name, digest_file(path) if path.is_file() else "absent"))
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()[:16]


def reviewer_digest() -> str:
    """The reviewer's own source, not its version string.

    `agent_version` moves when somebody bumps it, and nothing forces that.
    Editing the reviewer between the passes without a bump would run different
    code on each side, and the difference would be reported as the product
    moving on its own — the sentence this experiment exists to produce, arrived
    at for the wrong reason.
    """
    source = ROOT / "src" / "security_agent"
    if not source.is_dir():
        return "absent"
    parts = []
    for path in sorted(source.rglob("*.py")):
        parts.append("{}:{}".format(path.relative_to(source), digest_file(path)))
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()[:16]


def environment_now() -> Dict[str, Any]:
    """What the freeze records and what every check re-computes — one
    definition, because two is how the scorer digest ended up in the manifest
    and not in the check."""
    return dict(round_tool.environment(), scorer=scorer_digest(),
                reviewer=reviewer_digest())


def build(name: str) -> Dict[str, Any]:
    cases = read_cases(SUITE)

    # One order, used by both passes. A different order per pass would mean the
    # two met the subscription's windows differently, and the comparison would
    # carry that difference as if it were the product moving.
    order = list(cases)
    random.Random(name).shuffle(order)

    return {
        "experiment": name,
        "question": (
            "With nothing changed between them, do any cases in this suite "
            "give a different verdict in the second pass than in the first?"),
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "environment": environment_now(),
        "suite": {
            "file": str(SUITE.relative_to(ROOT)),
            "digest": digest_file(SUITE),
            "count": len(cases),
        },
        "protocol": {
            "passes": list(PASSES),
            "order": order,
            "order_seed": name,
            "provider": "claude-cli",
            "profile": "normal",
            "primary_endpoint": (
                "per case, whether pass b's pair_success equals pass a's. "
                "Reported as agreed / flipped, with each flip named and its "
                "direction given."),
            "comparable": (
                "a case counts only if both passes produced a verdict and both "
                "rows carry the case_digest frozen here. A row about a "
                "different version of a case is not an observation of this one."),
            "missing": (
                "any case with no verdict in either pass makes the experiment "
                "incomplete. It is reported and the comparison exits 2; a "
                "partial pair is not evidence of agreement."),
            "not_answerable": (
                "how often a case flips. Two passes detect movement; they do "
                "not estimate its rate, and no threshold may be set from this."),
        },
        "counts": {"cases": len(cases), "reviews": 4 * len(cases)},
        "cases": case_rows(cases),
    }


def freeze(name: str, dry_run: bool) -> int:
    path = home(name) / "manifest.json"
    if path.exists() and not dry_run:
        print("{} already exists. A frozen experiment is not rewritten — that "
              "is what freezing it was for.".format(path.relative_to(ROOT)))
        return 1

    body = build(name)
    counts = body["counts"]
    print("experiment {} · passes {} and {}".format(name, *PASSES))
    print("  {} case(s) per pass, {} review(s) in total".format(
        counts["cases"], counts["reviews"]))
    print("  one order for both passes, seeded by the experiment name")
    print("\n  endpoint: {}".format(body["protocol"]["primary_endpoint"]))
    print("  not answerable: {}".format(body["protocol"]["not_answerable"]))
    if dry_run:
        print("\nNothing written.")
        return 0

    path.parent.mkdir(parents=True, exist_ok=True)

    # A copy of the prompts, taken now and read by every pass.
    #
    # Hashing before a case and again after it compares two snapshots; it does
    # not prove the file was the same in between. An edit made and reverted
    # while a review runs — a branch switch, an editor saving and undoing — is
    # invisible to both checks and visible to the reviewer, which is the one
    # reader that matters. Reading from a copy nobody edits removes the
    # question for the prompts entirely.
    #
    # The reviewer's own source is still read live: the child imports the
    # installed package, and running a pass from a copy of it is a different
    # and larger change. `reviewer_digest` catches an edit that is still there
    # at either check, and an edit reverted mid-case remains a hole. It is
    # named here rather than left for somebody to discover.
    frozen_prompts = home(name) / "prompts"
    try:
        shutil.copytree(ROOT / "prompts", frozen_prompts, dirs_exist_ok=True)
    except OSError as exc:
        print("\ncould not freeze the prompts: {}".format(exc), file=sys.stderr)
        return 2

    if not publish(path, json.dumps(body, indent=2, ensure_ascii=False) + "\n"):
        shutil.rmtree(frozen_prompts, ignore_errors=True)
        return 2

    print("\nWritten to {}.".format(path.relative_to(ROOT)))
    print("Pass a:   tools/experiment.py run {} a".format(name))
    print("Pass b:   tools/experiment.py run {} b".format(name))
    print("Then:     tools/experiment.py compare {}".format(name))
    return 0


def publish(target: Path, text: str) -> bool:
    """Write beside the target and rename, or leave nothing behind.

    The process id is in the staging name because a fixed one lets two runs
    write over each other's staging file and then remove it in each other's
    cleanup. The existence check is immediately before the rename because
    `replace` overwrites, and a check made earlier is a check about an earlier
    moment — the rollback was taught not to delete a file it did not create, and
    publishing had to be taught not to destroy one either.
    """
    temporary = target.with_name("{}.writing.{}".format(target.name, os.getpid()))
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        temporary.write_text(text, encoding="utf-8")
        # `os.link` fails if the target exists, in one operation, which
        # `replace` after an `exists()` check does not: two runs can both see
        # nothing there and the second silently overwrites the first. The
        # window was narrowed to a line and a line is still a window — and the
        # harm is a result quietly replaced, which is the kind that leaves a
        # comparison looking perfectly ordinary.
        os.link(temporary, target)
        temporary.unlink()
        return True
    except OSError as exc:
        temporary.unlink(missing_ok=True)
        print("could not write {}: {}".format(target.relative_to(ROOT), exc),
              file=sys.stderr)
        return False


def drift(body: Dict[str, Any]) -> List[str]:
    """What has moved since the freeze, in words a reader can act on."""
    moved = []
    now = environment_now()
    for key, was in body["environment"].items():
        if now.get(key) != was:
            moved.append("{}: {} -> {}".format(key, was, now.get(key)))
    if digest_file(SUITE) != body["suite"]["digest"]:
        moved.append("the sentinel suite file has been rewritten")
    for row in body["cases"]:
        directory = ROOT / "corpus-real" / row["case_id"]
        manifest = directory / "case.yml"
        if not directory.is_dir():
            moved.append("{}: the case is gone".format(row["case_id"]))
            continue
        if case_digest(directory) != row["case_digest"]:
            moved.append("{}: the case has been edited".format(row["case_id"]))
        key = digest_file(manifest) if manifest.is_file() else "absent"
        if key != row.get("answer_key_digest"):
            moved.append("{}: the answer key in case.yml has been edited — the "
                         "code is unchanged and the scoring is not"
                         .format(row["case_id"]))
    return moved


def load(name: str) -> Optional[Dict[str, Any]]:
    path = home(name) / "manifest.json"
    if not path.is_file():
        print("no experiment {} — freeze it first".format(name), file=sys.stderr)
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def verify(name: str) -> int:
    """Fail closed, and say what moved.

    Checking after the fact proves nothing: a change made and reverted between
    the passes leaves the files looking untouched. This is what runs immediately
    before spending, and its exit code is the permission to spend.
    """
    body = load(name)
    if body is None:
        return 2
    moved = drift(body)
    if moved:
        print("Refusing: {} thing(s) moved since the freeze.".format(len(moved)))
        for line in moved:
            print("  {}".format(line))
        print("\nA pass run now would answer a different question from the one "
              "already paid for. Re-freeze as a new experiment, or put it back.")
        return 2
    print("nothing has moved since the freeze: {} case(s), same prompts, same "
          "schema, same scorer, same reviewer.".format(len(body["cases"])))
    return 0


def accepted(name: str, label: str) -> Dict[str, Any]:
    """The results this pass has already accepted, keyed by case."""
    out = {}
    for path in sorted((home(name) / "pass-{}".format(label)).glob("*.json")):
        try:
            out[path.stem] = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            out[path.stem] = {"unreadable": True}
    return out


def run(name: str, label: str, limit: Optional[int]) -> int:
    """Run the frozen order, publishing a case only after it is still valid.

    The order matters and so does the loop: the conditions are checked before
    the case and again after it, and the result is written only if the second
    check passes. A result produced while something moved underneath it is
    discarded here rather than left on disk to be counted by a later resume,
    which is exactly what the previous design did.
    """
    body = load(name)
    if body is None:
        return 2
    if label not in PASSES:
        print("a pass is one of {}".format(", ".join(PASSES)), file=sys.stderr)
        return 2

    from pair_corpus import load_adjudications, load_cases, run_case

    known = {case["case_id"]: case
             for case in load_cases(ROOT / "corpus-real")}
    # Loaded and passed, not merely hashed. The manifest digests this file and
    # `drift` refuses when it moves — which stated that the rulings were part of
    # the frozen scoring environment while the scoring ignored them, because
    # `run_case` defaults to none. A description of the method that the method
    # does not follow is the shape this project keeps finding in itself.
    rulings = load_adjudications(ROOT / "corpus-real")
    have = accepted(name, label)
    queued = [c for c in body["protocol"]["order"] if c not in have]

    print("experiment {} · pass {}".format(name, label))
    print("  {} accepted, {} to run".format(len(have), len(queued)))
    if not queued:
        print("  nothing left in this pass.")
        return 0

    # Counted rather than enumerated: it is the number of cases this
    # The cases this invocation accepted, not the ones it attempted. The loop
    # returns early on drift without accepting the case it is on, so a counter
    # over the iteration would stop one case late.
    taken = []
    for case_id in queued:
        if limit is not None and len(taken) >= limit:
            print("\nstopping after {} case(s), as asked. {} left; run the "
                  "same command again to continue.".format(
                      len(taken), len(queued) - len(taken)))
            break

        moved = drift(body)
        if moved:
            print("\nstopping before {}: {} thing(s) moved since the freeze:\n"
                  "  {}\n\nWhat has been accepted stays accepted. Put it back "
                  "and run this again.".format(case_id, len(moved),
                                               "\n  ".join(moved)))
            return 2

        case = known.get(case_id)
        if case is None:
            print("\nstopping: {} is in the frozen order and not in the "
                  "corpus.".format(case_id))
            return 2

        print("\n  {} ...".format(case_id), flush=True)
        # The frozen copy, for the duration of this case. `run_case` starts a
        # child process that reads the prompt directory this names.
        os.environ["SECURITY_SCAN_PROMPT_DIR"] = str(home(name) / "prompts")
        result = run_case(case, provider=body["protocol"]["provider"],
                          profile=body["protocol"]["profile"],
                          adjudications=rulings)

        # After, before it is written anywhere. The check before the case
        # leaves the case itself unprotected — the reviewer loads its prompts
        # and its files while it runs — and on the last case of a pass there is
        # no next check at all.
        moved = drift(body)
        if moved:
            print("  discarded: {} thing(s) moved while it ran:\n    {}"
                  .format(len(moved), "\n    ".join(moved)))
            print("\nThat review was paid for and is not part of this "
                  "experiment. Put it back and run this again.")
            return 2

        rendered = json.dumps(result, indent=2, ensure_ascii=False) + "\n"
        if describe(result) in ("no verdict", "error") or result.get("incomplete"):
            # Kept, because it was paid for, and kept *apart*, because an
            # accepted file is also what tells the next run to skip the case.
            # Publishing an errored row as an ordinary result turned a
            # transient provider failure into a case that could never be run
            # again and an experiment that stayed incomplete for ever.
            aside = home(name) / "pass-{}-unfinished".format(label)
            publish(aside / "{}.json".format(case_id), rendered)
            print("  {}: {} — kept aside, not accepted. Run this again to "
                  "retry it.".format(case_id, describe(result)), flush=True)
            return 2

        target = home(name) / "pass-{}".format(label) / "{}.json".format(case_id)
        if not publish(target, rendered):
            return 2
        taken.append(case_id)
        print("  {}: {}".format(case_id, describe(result)), flush=True)

    print("\npass {}: {} accepted of {}.".format(
        label, len(accepted(name, label)), len(body["protocol"]["order"])))
    return 0


def describe(result: Dict[str, Any]) -> str:
    if result.get("incomplete"):
        return "did not conclude ({})".format(", ".join(result["incomplete"]))
    if result.get("error"):
        return "error"
    verdict = result.get("pair_success")
    if verdict is True or verdict is False:
        return "pass" if verdict else "fail"
    return "no verdict"


def verdicts(name: str, label: str, frozen: Dict[str, str]) -> Dict[str, Any]:
    """`case_id -> pass/fail`, refusing anything that is not a verdict.

    One file per case by construction, so the duplicate problem the previous
    design had cannot arise: a second result for a case would have to overwrite
    an accepted one, and `publish` refuses to overwrite.
    """
    out: Dict[str, Any] = {}
    for case_id, row in accepted(name, label).items():
        if case_id not in frozen:
            out["(not in the suite) " + case_id] = "stray"
            continue
        if row.get("unreadable"):
            out[case_id] = "unreadable"
        elif row.get("case_digest") != frozen[case_id]:
            out[case_id] = "wrong-version"
        else:
            verdict = row.get("pair_success")
            if verdict is True or verdict is False:
                out[case_id] = "pass" if verdict else "fail"
            elif verdict is None:
                out[case_id] = "unresolved"
            else:
                # `"false"` is a non-empty string and would read as a pass.
                out[case_id] = "not-a-verdict"
    return out


def compare(name: str) -> int:
    body = load(name)
    if body is None:
        print("It was never frozen, so there is no rule to compare against and "
              "none may be invented now.", file=sys.stderr)
        return 2

    # Checked here as well as before each case. `run` closes the window up to
    # the moment a case finishes; without this, everything the experiment rests
    # on could be edited afterwards and the comparison would still print "no
    # movement observed".
    moved = drift(body)
    if moved:
        print("Refusing to compare: {} thing(s) have moved since the freeze."
              .format(len(moved)), file=sys.stderr)
        for line in moved:
            print("  {}".format(line), file=sys.stderr)
        print("\nThe results may be sound; this comparison is not. Nothing "
              "here can say whether the change came before or after the "
              "passes.", file=sys.stderr)
        return 2

    frozen = {row["case_id"]: row["case_digest"] for row in body["cases"]}
    a = verdicts(name, "a", frozen)
    b = verdicts(name, "b", frozen)

    usable = {"pass", "fail"}
    agreed, flipped, unusable = [], [], []
    for case_id in sorted(frozen):
        first, second = a.get(case_id), b.get(case_id)
        if first not in usable or second not in usable:
            unusable.append("{} (a={}, b={})".format(
                case_id, first or "absent", second or "absent"))
        elif first == second:
            agreed.append(case_id)
        else:
            flipped.append("{}: {} -> {}".format(case_id, first, second))

    stray = sorted(k for k in list(a) + list(b) if k not in frozen)

    print("experiment {} · pass a against pass b".format(name))
    print("  {} case(s) frozen, {} comparable".format(
        len(frozen), len(agreed) + len(flipped)))
    print("  agreed with itself: {}".format(len(agreed)))
    print("  flipped:            {}".format(len(flipped)))
    for line in flipped:
        print("    {}".format(line))
    if unusable:
        print("\n  no comparable pair: {}".format(len(unusable)))
        for line in unusable:
            print("    {}".format(line))
    if stray:
        print("\n  results the frozen suite did not ask for: {}".format(
            ", ".join(stray)))

    print("\n{}".format(body["protocol"]["not_answerable"]))
    if unusable or stray:
        print("\nIncomplete: a case with no verdict on one side is not evidence "
              "of agreement.")
        return 2
    if flipped:
        # Not a failure. Movement is the finding this experiment was bought to
        # produce, and exiting non-zero on it would make the answer look like a
        # broken run.
        print("\nThe suite moves on its own. Any gate threshold has to sit "
              "above this, and this file cannot say how far above.")
    else:
        print("\nNo movement observed in one paired repetition. That is not "
              "'the suite is stable' — it is one observation, and the cases "
              "known to move were deliberately included.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)

    it = sub.add_parser("freeze")
    it.add_argument("name")
    it.add_argument("--dry-run", action="store_true")

    check = sub.add_parser("verify")
    check.add_argument("name")

    go = sub.add_parser("run")
    go.add_argument("name")
    go.add_argument("pass_label", choices=PASSES, metavar="PASS")
    go.add_argument("--cases", type=int, metavar="N",
                    help="stop after N cases; run again to continue")

    done = sub.add_parser("compare")
    done.add_argument("name")

    args = parser.parse_args()
    if args.command == "freeze":
        return freeze(args.name, args.dry_run)
    if args.command == "verify":
        return verify(args.name)
    if args.command == "run":
        return run(args.name, args.pass_label, args.cases)
    return compare(args.name)


if __name__ == "__main__":
    raise SystemExit(main())
