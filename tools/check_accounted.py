#!/usr/bin/env python3
"""Is every case accounted for? The end condition, made checkable.

The measurement ends when no failure is left without an outcome — not when a
fraction reaches a number. Every case is exactly one of:

    pass              the pair discriminated, nothing owed
    limitation        it failed and `LIMITATIONS.md` says why it is not fixed
    invalid           `adjudications.yml` rules it unable to measure anything
    not run           in the corpus, no result recorded for it
    unaccounted       none of the above — the work that is left

There is deliberately no `fixed` bucket, and this docstring promised one for a
while. A case that failed, was changed and then measured again lands in `pass`,
where it cannot be told apart from a case that never failed. Nothing records
which case was fixed, so the bucket would have to be filled by hand — and with
zero fixes made so far it would be empty in every case. Said here rather than
implemented: a tally that names an outcome it cannot compute is worse than one
that does not name it.

The report that says the work is done reads like this, and the numbers sum:

    34 cases: 20 pass, 8 fixed and re-measured, 4 limitations, 2 invalid.

That is the whole test. A case with no row is the thing this exists to find,
because a fraction can look finished while a dozen failures sit unexplained
behind it — which is how point 9 accumulated seventeen of them unnoticed.

    tools/check_accounted.py                # exit 1 while anything is unaccounted
    tools/check_accounted.py --construction regression

Why it terminates, and this is the part that is easy to lose: two of the four
outcomes remove a case permanently. A limitation is never re-measured and an
invalid case is never scored, so the pool can only grow if a fix breaks
something else. If a round removes more than it returns, the sequence ends. If
it does not, that is itself the signal to stop — the fixes are not working —
rather than a reason to run another round.
"""

from __future__ import annotations

import argparse
import glob
import json
import re
import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))

from artifact import (
    NO_MEMBERS,
    case_digest,
    instant,
    is_target,
    legacy_case_digest,
    load_adjudications,
    ruled_incidental,
)

ROOT = Path(__file__).resolve().parents[1]


def _adjudications() -> list:
    path = ROOT / "corpus-real" / "adjudications.yml"
    try:
        body = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, ValueError):
        return []
    rows = body if isinstance(body, list) else body.get("adjudications") or []
    return [r for r in rows if isinstance(r, dict)]


def rulings() -> set:
    return {r.get("case_id") for r in _adjudications()
            if r.get("case_is_malformed")}


def known_failures() -> set:
    """Cases whose failure is understood, explained, and **still measured**.

    The fifth outcome, and it exists because D-008's four could not hold this
    one. `rs-8rw6-p7m8-63jp` fails because the reviewer read the code correctly
    and drew a false conclusion about a trust boundary, then blocked a correct
    fix — the expensive failure, and the most useful regression test in the
    corpus for exactly that reason.

    Neither existing outcome fits. `invalid` means the case cannot measure
    anything, and this one measures something precise: whether a semantically
    wrong finding can survive the verifier and gate a merge. `limitation` means
    the case is removed from measurement for good, and removing it closes the
    accounting by discarding the test.

    D-008 folded two independent questions into one — "does this case have an
    explained outcome" and "should it be measured again". Here the answers are
    yes and yes. Recorded in `adjudications.yml` as `known_failure: true`,
    beside a line in `LIMITATIONS.md` saying what the failure is.
    """
    return {r.get("case_id") for r in _adjudications()
            if r.get("known_failure")}


def named_in_limitations() -> set:
    """Cases `LIMITATIONS.md` names, matched on a whole identifier.

    Bounded, not `in`: every snapshot case is its twin's id with `-snap` on the
    end, so a substring test let one sentence account for two different pairs.
    """
    try:
        text = (ROOT / "LIMITATIONS.md").read_text(encoding="utf-8")
    except OSError:
        return set()
    out = set()
    for manifest in (ROOT / "corpus-real").glob("*/case.yml"):
        case_id = manifest.parent.name
        if re.search(r"(?<![\w-])" + re.escape(case_id) + r"(?![\w-])", text):
            out.add(case_id)
    return out


def passed(row: dict, case: dict) -> bool:
    """Did this pair discriminate, judged by the key in force **now**?

    Not the boolean the scorer wrote. Answer keys are corrected when they turn
    out to name the wrong thing, and `php-p2ch-c2c3-4xm5` is the proof: it is
    stored as a failure, and against today's key it passes — the finding is
    `authn-authz` in `Controller.php` and the case expects exactly that. The
    stored value answers the key as it stood that afternoon.

    `stage2.py` learned this and this tool did not, an hour after being written
    beside it. Falls back to the stored boolean only for rows too old to carry
    findings, which cannot be re-judged at all.
    """
    if "safe_findings" not in row or "unsafe_findings" not in row:
        return row.get("pair_success") is True
    excused = ruled_incidental(
        load_adjudications(ROOT / "corpus-real"), row.get("case_id"), "safe")
    found = any(is_target(f, case) for f in row.get("unsafe_findings") or [])
    persists = any(is_target(f, case)
                   and f.get("fingerprint") not in excused
                   for f in row.get("safe_findings") or [])
    return found and not persists


def about_this_version(case_id: str, row: dict) -> bool:
    """Is this row a result about the case as it stands today?

    `tools/stage2.py` has asked this since a case had its weakness deleted by a
    bug and then repaired: the recorded failure was a failure at reviewing code
    that no longer existed, and nothing in the batch said so. The rule is copied
    rather than re-invented — either digest counts, because the definition
    narrowed to the members so a corrected answer key stops discarding the run
    it was corrected for, and the old whole-tree value still means the members
    are unchanged.

    A row with no digest at all predates the record and is not a verdict about
    today's case either.

    A case with no members cannot be certified by anything. Its digest is not a
    hash — see `artifact.NO_MEMBERS` — and the comparison is refused outright
    rather than left to compare two sentinels and answer yes.
    """
    directory = ROOT / "corpus-real" / case_id
    if not (directory / "case.yml").is_file():
        return False
    today = {case_digest(directory), legacy_case_digest(directory)}
    if NO_MEMBERS in today:
        return False
    return row.get("case_digest") in today


def scorable(row) -> bool:
    """Is this row a finished measurement at all?

    One definition for both readers. `executed` required a boolean
    `pair_success` and `verdicts` asked only that the row was not `incomplete`,
    so a finished-looking row carrying `null` there became a canonical verdict
    in one and was invisible to the other — the same row, two answers, and the
    verdict was the false one: `passed()` reads a row with no findings as a
    failure.
    """
    return (isinstance(row, dict)
            and bool(row.get("case_id"))
            and not row.get("incomplete")
            and isinstance(row.get("pair_success"), bool))


def verdicts() -> dict:
    """The latest recorded answer per case, from every batch and the queue.

    Two rows for one case are ordered by `ran_at`. When neither carries one the
    comparison is `"" >= ""`, which is true, so the winner used to be whichever
    file the filesystem handed over last — an ordering nobody chose and nothing
    printed. `rb-mx5j-mp4f-g8jg` had three rows, two failures from before the
    answer key was repaired and one pass from after, and the case was reported
    as failing because of glob order. Rows that are not about today's version of
    the case are dropped first, which removes that comparison in the case that
    provoked it and, where it survives, leaves it between rows that at least
    measured the same thing.

    Experiment results are deliberately **not** here — see `executed`. They
    prove a case was run; they do not settle what its answer is. `experiment.py`
    reads the prompts from a frozen copy and keeps its own identity for the
    scorer, the reviewer and the answer key, none of which `about_this_version`
    checks: it compares `case_digest` and nothing else. Folding those rows in
    made a stability experiment's pass B the production verdict, and it moved
    `rb-g65v-27r3-5p6m` out of `LIMITATIONS.md` on the strength of a row nobody
    had checked against what the limitation actually says.
    """
    seen = {}
    for path in (glob.glob(str(ROOT / "measurements" / "*.json"))
                 + glob.glob(str(ROOT / "measurements" / "queue" / "*.json"))):
        try:
            body = json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        # A batch file is a list of rows; an experiment writes one row per file,
        # as an object. Reading only lists dropped every experiment result
        # silently — the file was opened, parsed, and then iterated as nothing.
        rows = body if isinstance(body, list) else [body]
        for row in rows:
            if not isinstance(row, dict) or not row.get("case_id"):
                continue
            if not scorable(row):
                continue
            case_id = row["case_id"]
            if not about_this_version(case_id, row):
                continue
            seen.setdefault(case_id, []).append((instant(row.get("ran_at")), row))

    out = {}
    for case_id, rows in seen.items():
        manifest = ROOT / "corpus-real" / case_id / "case.yml"
        if not manifest.is_file():
            continue
        case = yaml.safe_load(manifest.read_text(encoding="utf-8")) or {}
        out[case_id] = _standing(rows, case)
    return out


def _standing(rows: list, case: dict) -> bool:
    """The answer that stands for one case, ordered the way `stage2` orders it.

    Three things this replaced, all in one line — `when >= latest[case_id][0]`
    over `row.get("ran_at") or ""`.

    Text, not instants. `…T14:00:00+03:00` is two hours *before*
    `…T12:00:00+00:00` and sorts after it, so a run superseded a later one
    whenever the offsets differed. Latent today — all 78 dated rows on disk are
    `+00:00` — and one run from a machine on local time is all it takes.

    `>=` and `""`. Undated rows all compared equal, and equal meant the last one
    the glob happened to hand over won — an ordering nobody chose and nothing
    printed. Now an undated row answers only when nothing dated does, which is
    `stage2._settle`'s rule.

    And a tie. `pair_corpus` stamps whole seconds, so two rows can share an
    instant; `stage2` calls that unresolved and this tool picked a winner by
    glob order, so the two readers of one measurement stream could report
    opposite things about one case. Disagreement at the latest instant is not a
    pass here — the case then falls to `unaccounted` unless something explains
    it, which is the bucket that asks for a decision rather than making one.
    """
    dated = [(when, row) for when, row in rows if when is not None]
    if dated:
        latest = max(when for when, _row in dated)
        answers = {passed(row, case) for when, row in dated if when == latest}
    else:
        answers = {passed(row, case) for _when, row in rows}
    return answers == {True}


def executed() -> set:
    """Every case some paid run has produced a scorable row for, anywhere.

    A different question from `verdicts`, and separating the two is the point.
    "What is this case's answer" must come from the production stream; "do we
    still owe a measurement for it" must count every review that was actually
    bought, including the ones an experiment wrote under
    `measurements/experiment-*/pass-*/`. Folded into one, the tally either
    lets an experiment overwrite a verdict or asks the owner to pay again for
    a case measured yesterday — and it did the second for two cases before this
    existed, at about a dollar each.
    """
    seen = set()
    for path in (glob.glob(str(ROOT / "measurements" / "*.json"))
                 + glob.glob(str(ROOT / "measurements" / "queue" / "*.json"))
                 + glob.glob(str(ROOT / "measurements" / "experiment-*"
                                  / "pass-*" / "*.json"))):
        try:
            body = json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        for row in (body if isinstance(body, list) else [body]):
            if not isinstance(row, dict) or not row.get("case_id"):
                continue
            if not scorable(row):
                continue
            if about_this_version(row["case_id"], row):
                seen.add(row["case_id"])
    return seen


def account(construction=None) -> dict:
    invalid = rulings()
    understood = known_failures()
    limitations = named_in_limitations()
    answers = verdicts()

    measured = executed()
    buckets = {"pass": [], "limitation": [], "invalid": [], "unaccounted": [],
               "unrun": [], "unadopted": [], "known_failure": []}
    for manifest in sorted((ROOT / "corpus-real").glob("*/case.yml")):
        case_id = manifest.parent.name
        body = yaml.safe_load(manifest.read_text(encoding="utf-8")) or {}
        if construction and body.get("construction") != construction:
            continue
        if case_id in invalid:
            buckets["invalid"].append(case_id)
        elif case_id not in answers and case_id in measured:
            # Bought, but not through the production stream, so it has no
            # verdict here. Not "not run" — that would ask for the same
            # measurement to be paid for twice — and not a pass either, which
            # is what folding experiment rows into `verdicts` produced.
            # Adopting one is free and is a decision, so it stays visible until
            # somebody makes it.
            buckets["unadopted"].append(case_id)
        elif case_id not in answers:
            buckets["unrun"].append(case_id)
        elif answers[case_id]:
            buckets["pass"].append(case_id)
        elif case_id in understood:
            # Asked before `limitations`, because such a case is named in
            # `LIMITATIONS.md` too — the line there says what the failure is,
            # and this bucket says the case stays in the set. Read the other
            # way round it would be filed as removed, which is what the ruling
            # exists to prevent.
            buckets["known_failure"].append(case_id)
        elif case_id in limitations:
            buckets["limitation"].append(case_id)
        else:
            buckets["unaccounted"].append(case_id)
    return buckets


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--construction", choices=("regression", "snapshot"))
    args = parser.parse_args()

    buckets = account(args.construction)
    total = sum(len(v) for v in buckets.values())

    print("{} case(s){}: {} pass, {} known failure(s), {} limitation(s), "
          "{} invalid, {} not run, {} measured but not adopted, "
          "{} unaccounted".format(
              total, " ({})".format(args.construction) if args.construction else "",
              len(buckets["pass"]), len(buckets["known_failure"]),
              len(buckets["limitation"]),
              len(buckets["invalid"]), len(buckets["unrun"]),
              len(buckets["unadopted"]), len(buckets["unaccounted"])))

    if buckets["unaccounted"]:
        print("\nfailed, and nothing says why:")
        for case_id in buckets["unaccounted"]:
            print("  " + case_id)
        print("\nEach needs one of: a fix that is then re-measured, a line in "
              "LIMITATIONS.md, or a ruling that the case cannot measure "
              "anything. There is no fourth.")
    if buckets["unadopted"]:
        print("\n{} case(s) were measured but their result is not the "
              "record:\n  {}\n\nThe rows exist and were paid for; nothing has "
              "said they are this case's answer. Adopting one is free and is a "
              "decision — publish the row into the measurement stream, or rule "
              "that it does not settle the case. Not exit 0: after the unrun "
              "ones are bought this would otherwise announce that everything "
              "is accounted for while two cases have no verdict.".format(
                  len(buckets["unadopted"]), "\n  ".join(buckets["unadopted"])))
    return 1 if (buckets["unaccounted"] or buckets["unrun"]
                 or buckets["unadopted"]) else 0


if __name__ == "__main__":
    sys.exit(main())
