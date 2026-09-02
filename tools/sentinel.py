#!/usr/bin/env python3
"""Choose the sentinel suite by a written rule, not by hand.

The sentinel is the small set of cases that runs on every change able to move
the verdict. Ten pairs of a hundred and five is a sample, and a sample chosen by
the person whose work it will judge is not a control — so the rule is written
here, in code, and the list is whatever the rule produces. Running this tool
twice on the same corpus gives the same suite; there is no seed to record and no
tie to break by preference.

    tools/sentinel.py                     # print the suite the rule selects
    tools/sentinel.py --write suites/sentinel.yml
    tools/sentinel.py --check suites/sentinel.yml   # exit 1 if it has drifted

**The rule.**

1. Eligible: a case in `corpus-real/` whose manifest says
   `construction: regression`, which `pair_corpus` does not call malformed, and
   which has a recorded outcome from a previous run. Regression only, because
   the two constructions measure different things and this project's own
   harvester says never to score them together — mixing them would make the
   suite's single number a blend of two questions.

2. Stratify by language, because that is the axis every claim about the product
   rests on: "it works on Go" is a sentence somebody will say.

3. Within a language take the lexicographically first case with a recorded
   `pass`, the lexicographically first with a recorded `fail`, and *every* case
   whose recorded verdicts disagree with each other. A language with only one
   arm still contributes its one case — a passing case can decline, and that is
   worth catching — so the shortfall is recorded in the manifest rather than
   dropping the language.

   The suite as a whole is different, and is checked: with nothing failing
   there is no case that can be seen to recover, and with nothing passing there
   is nothing that can be seen to decline. Either way half the tripwire is
   missing while the rule was followed exactly, so `refusals()` refuses to
   write it.

4. No target size. The rule fixes the suite; the count is a consequence and is
   recorded. A range — "twenty to forty" — is a decision left to be made after
   the results are in, and this file exists so that decision cannot be made
   there.

**What this rule is not.** It is not blind: step 3 uses outcomes already seen,
which is a deliberate choice and is stated rather than hidden. It is not
representative either — stratifying ten cases over nine languages leaves cells
with one observation and some with none. It is a regression tripwire, and the
only claim it supports is "this version did what that version did on these
cases".
"""

from __future__ import annotations

import argparse
import collections
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from pair_corpus import malformed_cases

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "corpus-real"
MEASUREMENTS = ROOT / "measurements"


def result_files(root: Path = MEASUREMENTS) -> list:
    """Every file a paid run has written, in all four places it writes them.

    Batches at the top level, one file per case under `queue/`, one file per
    case under `experiment-*/pass-*/`, and one file per case under `round-*/`.
    Three readers in this repository have now been found globbing only the
    first one or two of those, and each time the effect was the same: work that
    was paid for read as work that had not happened.
    """
    return (sorted(root.glob("*.json"))
            + sorted((root / "queue").glob("*.json"))
            + sorted(root.glob("experiment-*/pass-*/*.json"))
            + sorted(root.glob("round-*/*.json")))


def rows_in(body) -> list:
    """The rows a result file holds, whichever of the three shapes it is.

    A batch is a list. An experiment writes one row per file, as a bare object.
    And `{"results": [...]}` is accepted by `stage2` and `run_queue` both, so a
    reader that handles only the first two would be the third variation on the
    same mistake. Reading an object as `[]` is the quiet version: the file is
    opened, parsed, and then iterated as nothing.
    """
    if isinstance(body, list):
        return [row for row in body if isinstance(row, dict)]
    if isinstance(body, dict):
        found = body.get("results")
        if isinstance(found, list):
            return [row for row in found if isinstance(row, dict)]
        return [body]
    return []


def recorded_outcomes(root: Path = MEASUREMENTS) -> dict:
    """Each case's recorded verdict: `pass`, `fail`, or `unstable`.

    **There is no "latest".** The first version took the last verdict in file
    name order, on the assumption that names sort chronologically. They do not:
    `cli-batch-10-go-snap.json` sorts before `cli-batch-2.json`, and
    `first-cli-pair.json` is the oldest file and sorts last. `stage2.py` already
    documents the same trap and refuses to guess. Ordering by modification time
    is no better — a fresh clone gives every file the same one.

    So a case measured twice with two different verdicts is not resolved by
    picking one. It is `unstable`, which is a third answer and a true one: the
    run-to-run movement is the thing, not noise around a value. `rb-mx5j` is the
    case in point — False, False, then True, with nothing changed between.

    A row whose `pair_success` is absent, null, or not a boolean is not an
    outcome. It is a run that did not conclude, and it never becomes one here;
    that distinction has already cost this project a withdrawn result. Not
    truthiness: `"false"` is a true string, so a row carrying the *text* "false"
    was recorded as a pass — a typo able to turn a failure into a pass in the
    suite that exists to catch changes in exactly that direction. A row flagged
    `incomplete` is dropped for the same reason, whatever it says beside it.

    **Every place a paid run writes**, not the two most readers know about. The
    stability experiment writes one file per case under
    `experiment-*/pass-*/`, and those are the runs that measure movement — the
    thing this suite's unstable arm is made of. With them unread,
    `go-m6jg-wr9m-cg2f` (True then False) and `rb-g65v-27r3-5p6m` (False then
    True) were both recorded as a settled `fail`, and the arm that holds the
    cases which move on their own was missing two of the five.

    That an experiment row is not allowed to *settle* a case's verdict — the
    rule `tools/check_accounted.py` records, after an experiment's pass B once
    became the production answer — does not apply here and must not be copied
    here. This function does not settle anything. It asks whether the case has
    ever been seen to give two different answers, and a run made from frozen
    prompts is still a run that saw one.

    **Known limitation.** Nothing records *which version* of a case a verdict
    was produced against. An outcome recorded before a case was edited is still
    read as an outcome of the case as it stands. Closing that needs a case
    digest in the measurement rows, which the artifacts do not carry.
    """
    seen = collections.defaultdict(set)
    for path in result_files(root):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        for row in rows_in(data):
            case_id, verdict = row.get("case_id"), row.get("pair_success")
            if not case_id or row.get("incomplete"):
                continue
            if not isinstance(verdict, bool):
                continue
            seen[case_id].add("pass" if verdict else "fail")

    return {case_id: (verdicts.pop() if len(verdicts) == 1 else "unstable")
            for case_id, verdicts in seen.items()}


def manifests(corpus: Path = CORPUS) -> dict:
    """`case_id -> (language, construction)`, read without a YAML parser.

    The three fields wanted are flat scalars at the top level of every manifest
    `check_corpus.py` accepts, and reading them by hand keeps this tool free of
    a dependency the CI job that will run it does not otherwise need.
    """
    found = {}
    for case in sorted(p for p in corpus.iterdir() if p.is_dir()):
        path = case / "case.yml"
        if not path.is_file():
            continue
        fields = {}
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.startswith(("language:", "construction:", "family:")):
                key, _, value = line.partition(":")
                fields[key.strip()] = value.strip().strip("'\"")
        found[case.name] = fields
    return found


def select(corpus: Path = CORPUS, measurements: Path = MEASUREMENTS) -> dict:
    """The rule in the docstring, applied. Deterministic, no seed."""
    outcomes = recorded_outcomes(measurements)
    excluded = set(malformed_cases(corpus))
    cases = manifests(corpus)

    eligible = {
        case_id: fields for case_id, fields in cases.items()
        if fields.get("construction") == "regression"
        and case_id not in excluded
        and case_id in outcomes
    }

    by_language = collections.defaultdict(
        lambda: {"pass": [], "fail": [], "unstable": []})
    for case_id in sorted(eligible):
        by_language[eligible[case_id].get("language", "unknown")][
            outcomes[case_id]].append(case_id)

    chosen, strata = [], []
    for language in sorted(by_language):
        arms = by_language[language]
        # Every known-unstable case, not the first: a case that already moves
        # on its own is the measurement the noise floor is made of, and there
        # are few enough of them that taking them all costs little and skipping
        # any would measure the floor on the cases that never move.
        picked = [arm[0] for arm in (arms["pass"], arms["fail"]) if arm]
        picked += arms["unstable"]
        chosen += picked
        strata.append({
            "language": language,
            "eligible_pass": len(arms["pass"]),
            "eligible_fail": len(arms["fail"]),
            "eligible_unstable": len(arms["unstable"]),
            "chosen": picked,
        })

    return {
        "cases": sorted(chosen),
        "strata": strata,
        "pool": len(eligible),
        "outcomes": {case_id: outcomes[case_id] for case_id in sorted(chosen)},
    }


def refusals(suite: dict) -> list:
    """Why this suite would not be worth running, if it would not be.

    A language with only one arm still contributes — a passing case can decline
    and that is worth catching — so a missing arm is not on its own a reason to
    refuse. A *suite* with only one arm is different: with nothing failing there
    is no case that can be seen to recover, and with nothing passing there is
    nothing that can be seen to decline. Either way half the tripwire is
    missing, and the rule that produced it was followed exactly, which is how
    it would go unnoticed.

    Checked at generation rather than assumed, because the data the rule reads
    changes: one more paid batch can move every case in a language into the
    same arm.
    """
    kinds = set(suite["outcomes"].values())
    problems = []
    if not kinds & {"pass"}:
        problems.append("no case in it passed: nothing here can be seen to "
                        "decline, which is what a regression is")
    if not kinds & {"fail", "unstable"}:
        problems.append("every case in it passed: nothing here can be seen to "
                        "recover, so a fix cannot be told from no change")
    return problems


def render(suite: dict) -> str:
    lines = [
        "# The sentinel suite: the cases that run on every change able to move",
        "# the verdict. Generated by tools/sentinel.py, which holds the rule.",
        "#",
        "# Do not edit the list by hand. Change the rule, regenerate, and say in",
        "# the commit why the rule moved — a suite edited case by case is a suite",
        "# chosen by whoever was looking at the last result.",
        "#",
        "# The recorded outcome beside each case is the value the rule selected",
        "# on, not a claim about the case. It is here so a later reader can see",
        "# what the choice was made from.",
        "",
        "pool: {}".format(suite["pool"]),
        "count: {}".format(len(suite["cases"])),
        "cases:",
    ]
    lines += ["  - {}   # {}".format(case_id, suite["outcomes"][case_id])
              for case_id in suite["cases"]]
    lines += ["", "strata:"]
    for row in suite["strata"]:
        lines.append("  - language: {}".format(row["language"]))
        lines.append("    eligible: {} pass, {} fail, {} unstable".format(
            row["eligible_pass"], row["eligible_fail"],
            row["eligible_unstable"]))
        lines.append("    chosen: [{}]".format(", ".join(row["chosen"])))
    return "\n".join(lines) + "\n"


def read_cases(path: Path) -> list:
    cases = []
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped.startswith("- ") and not stripped.startswith("- language:"):
            cases.append(stripped[2:].split("#")[0].strip())
    return cases


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--corpus", default=str(CORPUS))
    parser.add_argument("--measurements", default=str(MEASUREMENTS))
    parser.add_argument("--write", metavar="PATH",
                        help="write the manifest here")
    parser.add_argument("--check", metavar="PATH",
                        help="exit 1 if the manifest no longer matches the rule")
    args = parser.parse_args()

    suite = select(Path(args.corpus), Path(args.measurements))
    if not suite["cases"]:
        print("the rule selected no case — the corpus or the measurements are "
              "not where this tool expects them", file=sys.stderr)
        return 2

    # Refused rather than written. A suite the rule produced correctly and that
    # cannot show what it exists to show is the worst of the three outcomes:
    # it looks like a control and is not one.
    problems = refusals(suite)
    if problems:
        print("the rule produced a suite that cannot do its job:", file=sys.stderr)
        for problem in problems:
            print("  - {}".format(problem), file=sys.stderr)
        print("\n{} case(s) were selected. Widen the pool or change the rule; "
              "do not write this one.".format(len(suite["cases"])),
              file=sys.stderr)
        return 2

    if args.write:
        Path(args.write).parent.mkdir(parents=True, exist_ok=True)
        Path(args.write).write_text(render(suite), encoding="utf-8")
        print("wrote {} case(s) to {} from a pool of {}".format(
            len(suite["cases"]), args.write, suite["pool"]))
        return 0

    if args.check:
        path = Path(args.check)
        if not path.is_file():
            print("no suite at {}".format(path), file=sys.stderr)
            return 1
        frozen, now = read_cases(path), suite["cases"]
        if frozen == now:
            print("{} case(s); the manifest matches the rule.".format(len(now)))
            return 0
        # Not an error in itself. New measurements change what the rule
        # selects, and the suite is meant to be stable across that — so this
        # says the two have parted and leaves the decision to a person.
        print("The manifest and the rule have parted.")
        print("  only in the manifest: {}".format(
            ", ".join(sorted(set(frozen) - set(now))) or "-"))
        print("  only from the rule:   {}".format(
            ", ".join(sorted(set(now) - set(frozen))) or "-"))
        print("\nA suite that follows the newest measurements is not a "
              "baseline. Re-freeze deliberately, or leave it.")
        return 1

    print(render(suite), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
