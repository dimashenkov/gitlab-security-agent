#!/usr/bin/env python3
"""The interleaved order for the Sonnet trial, and the ledger that proves it ran.

    tools/sonnet_trial.py freeze NAME --opus EXPERIMENT --sonnet EXPERIMENT
    tools/sonnet_trial.py run NAME [--steps N] [--recover]
    tools/sonnet_trial.py reference NAME --write PATH
    tools/sonnet_trial.py status NAME

D-015 requires that the four passes — two models, two passes each — be
interleaved in an order committed before any result is seen. `experiment.py`
freezes one model per experiment and refuses to run when that model moves, so
running Sonnet means a second experiment, and two experiments run one after the
other. Everything that moves with time — the subscription window, provider
load, an upstream CLI release — then lands entirely on the second arm and is
indistinguishable from the model change, which is the whole quantity being
measured. Grok raised this on 2026-09-06 and nobody else had.

**This file owns the order and nothing else.** Every review still goes through
`experiment.run`, so the drift check before the case, the drift check after it,
the discard-if-something-moved rule, the keep-the-errored-row-aside rule and
`publish` are the same code that has always run them, not a second copy that
will drift from the first.

## What the ledger is for, and what counting could not do

The first version resumed by counting accepted rows per (arm, pass). Codex
refused it on 2026-09-06: a deleted, copied, manually inserted or out-of-order
result rewinds or advances the inferred position, and the run then follows a
*different* interleave while the schedule's digest still passes. A count is not
a history.

So every line of the ledger carries the digest of the line before it, and each
unit is recorded twice — once before it is bought and once after, with the
digest of the bytes it produced. On resume the whole chain is re-checked
against the files on disk, and a result nothing accounts for is as much a
broken history as a missing one.

**Two records per unit, because two files cannot be written at once.** Codex,
2026-09-06: publishing a result and appending its ledger line are separate
writes, and a crash between them leaves a legitimate result indistinguishable
from an injected stray — which would block resume for ever, on a review that
was paid for and is perfectly good. A `prepared` line goes down before the
review is bought and a `done` line after it, so an interrupted step is a state
the ledger can name and recover from rather than a contradiction.

## The reference boundary, stated no wider than it is

D-015 also says the reference must be frozen from the Opus passes "before the
Sonnet ones are looked at". Under a genuinely interleaved order Sonnet rows
exist on disk long before the last Opus row does, so that sentence cannot mean
"before any Sonnet row exists" — read that way the two requirements are jointly
unsatisfiable, and this repository has already shipped one gate whose own rules
contradicted each other.

What this ledger establishes: the reference was frozen at a recorded point in
the sequence, from the Opus arm's directory, and the file compared against
later still has that content.

**What it does not establish, and cannot.** A ledger records writes, not reads.
The challenger's rows sit on disk in plain text, so a history where somebody
read them before the freeze and one where nobody did are indistinguishable
from here. Codex named this on 2026-09-06 after an earlier draft of this
docstring claimed the stronger thing. Enforcing the literal rule would need the
challenger's results to be unreadable until the reference digest is committed,
which is not built and is not claimed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

TOOLS = Path(__file__).resolve().parent
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import experiment  # noqa: E402

ROOT = experiment.ROOT
PASSES = experiment.PASSES
ARMS = ("opus", "sonnet")
# Which of them the baseline is built from. Named rather than indexed out of
# the tuple at four call sites: "the first arm" and "the arm the reference is
# built from" are the same thing today and are not the same statement.
REFERENCE_ARM = "opus"

# Why this tool's spending is authorised. Mapped in `tools/spend_gate.py` to
# D-015, which is the decision that orders the trial; D-013 orders nothing
# about trying a different model.
SPEND_CLASS = "sentinel_trial"

# The one field that is *allowed* to differ between the two arms, because it is
# the thing being changed. Everything else in the frozen environment must
# match, or the two arms are not one experiment with one difference.
#
# **The verifier is not on this list, and that is the experiment.** D-015 is
# Sonnet reviewing and Opus verifying, held against Opus reviewing and Opus
# verifying; the comparator substitutes the challenger into the reviewing role
# only and requires the verifying role unchanged. An arm whose verifier also
# moved would be refused there — after the reviews were bought — so it is
# refused here, before.
ARM_FIELDS = ("model_requested",)

PREPARED, DONE, REFERENCE = "prepared", "done", "reference"


class TrialError(RuntimeError):
    """Raised instead of running. Never caught to run anyway."""


def home(name: str) -> Path:
    return ROOT / "measurements" / "sonnet-trial-{}".format(name)


def digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


def _digest_bytes(raw: bytes) -> str:
    """The digest of bytes already in hand.

    Deliberately *not* `experiment.digest_file`, which opens the path again.
    Codex, 2026-09-06: recording a digest read back from the file blesses
    whatever is at that path by then rather than what this invocation produced
    — and the later check that compares file to digest cannot see the swap,
    because both sides of it moved together. The same rule as the digest of a
    reviewed diff: hash what you had, not what you can fetch again.
    """
    return hashlib.sha256(raw).hexdigest()[:16]


def line_digest(entry: Dict[str, Any]) -> str:
    """The digest a line is referred to by. Over the canonical rendering, so
    two readers of the same line always compute the same value."""
    return digest(json.dumps(entry, sort_keys=True))


def units(cases: List[str], seed: str) -> List[Dict[str, Any]]:
    """Every unit of work, named rather than derived.

    A unit is one case, in one arm, in one pass: 13 x 2 x 2 = 52 of them, each
    a pair review. The case is written into the unit because "the next unrun
    case in that arm's order" is a position, and a position is exactly what a
    tampered or missing result file moves.
    """
    out = [{"index": None, "case_id": case_id, "arm": arm, "pass": label}
           for case_id in cases for arm in ARMS for label in PASSES]
    random.Random(seed).shuffle(out)
    for index, unit in enumerate(out):
        unit["index"] = index
    return out


def _environment_mismatch(a: Dict[str, Any], b: Dict[str, Any]) -> List[str]:
    """Where the two arms' frozen environments disagree about anything but the
    model. Both directions, because a key present in one and absent in the
    other is a difference and reading only one side would miss half of them."""
    problems = []
    for key in sorted(set(a) | set(b)):
        if key in ARM_FIELDS:
            continue
        if a.get(key) != b.get(key):
            problems.append("{}: {!r} in the opus arm, {!r} in the sonnet arm"
                            .format(key, a.get(key), b.get(key)))
    return problems


def _already_run(name: str) -> List[str]:
    """Accepted rows in an arm, if any. A schedule committed after a result
    exists is not a schedule committed before the results."""
    found = []
    for label in PASSES:
        found += ["{} pass {}: {}".format(name, label, case_id)
                  for case_id in sorted(experiment.accepted(name, label))]
    return found


def build(name: str, opus: str, sonnet: str) -> Dict[str, Any]:
    """The schedule, or `TrialError` saying which condition is not met."""
    bodies = {}
    for arm, experiment_name in (("opus", opus), ("sonnet", sonnet)):
        body = experiment.load(experiment_name)
        if body is None:
            raise TrialError(
                "the {} arm names the experiment {!r}, and there is no frozen "
                "manifest for it. Freeze it first, with that arm's "
                "SECURITY_SCAN_MODEL set".format(arm, experiment_name))
        bodies[arm] = body

    # **The two arms have to be the same suite, not the same sequence.**
    #
    # This compared `protocol.order` element by element, and no pair the tools
    # can produce ever satisfied it: `experiment.build` shuffles with
    # `random.Random(name)` and the two arms must have two names, so two
    # orders. The trial refused every input it could be given, and had done
    # since it was written. Found 2026-09-07 while trying to run it.
    #
    # The sequence is also not what makes two arms comparable. `_buy` calls
    # `experiment.run(..., only=unit["case_id"])`, so the arm's own order is
    # checked for membership and then filtered to that one case; the run
    # ledger, the reference and the comparator all follow the trial's own
    # `units`. What has to match is the suite and the frozen cases, and both
    # are recorded.
    #
    # Codex, adjudicating on 2026-09-07, required this to be *stronger* than
    # the set comparison I proposed: same suite file, digest and count; the
    # same case ids **with** their `case_digest` and `answer_key_digest`, so
    # two arms carrying equal ids over different content are refused; and
    # duplicates rejected rather than collapsed by a set.
    missing = [arm for arm in ARMS if not bodies[arm].get("suite")]
    if missing:
        # Not "they match": a manifest with no suite block cannot establish
        # that the two arms measure one thing, and a `KeyError` raised from
        # here is a failure reported far from its cause.
        raise TrialError(
            "the {} arm records no suite, so there is nothing to compare the "
            "other against. Freeze it with a current `experiment.py freeze`"
            .format(" and ".join(missing)))
    suite_a = bodies["opus"]["suite"]
    suite_b = bodies["sonnet"]["suite"]
    if suite_a != suite_b:
        raise TrialError(
            "the two arms were frozen over different suites, so they are not "
            "two measurements of one thing:\n  opus:   {}\n  sonnet: {}"
            .format(json.dumps(suite_a, sort_keys=True),
                    json.dumps(suite_b, sort_keys=True)))

    def case_map(arm: str) -> Dict[str, Dict[str, Any]]:
        rows = bodies[arm]["cases"]
        seen: Dict[str, Dict[str, Any]] = {}
        for row in rows:
            case_id = row.get("case_id")
            if case_id in seen:
                raise TrialError(
                    "the {} arm names {} twice. A duplicate is not two cases, "
                    "and collapsing it silently makes the counts disagree with "
                    "the schedule".format(arm, case_id))
            seen[case_id] = row
        return seen

    cases_a = case_map("opus")
    cases_b = case_map("sonnet")
    if cases_a != cases_b:
        only_a = sorted(set(cases_a) - set(cases_b))
        only_b = sorted(set(cases_b) - set(cases_a))
        moved = sorted(k for k in set(cases_a) & set(cases_b)
                       if cases_a[k] != cases_b[k])
        raise TrialError(
            "the two arms were frozen over different cases, so a difference "
            "between them is not attributable to the model:\n"
            "  only in opus:   {}\n  only in sonnet: {}\n  changed:        {}"
            .format(only_a or "none", only_b or "none", moved or "none"))

    # **Canonical, so the schedule depends on the cases and the trial seed and
    # on nothing else.** `units` shuffles a list it is given, so the incoming
    # sequence changes the result — and the incoming sequence used to be
    # whichever arm was named first on the command line. Sorted ids remove
    # that: the same two arms produce the same schedule whichever order they
    # are passed in.
    order_a = sorted(cases_a)

    mismatch = _environment_mismatch(bodies["opus"]["environment"],
                                     bodies["sonnet"]["environment"])
    if mismatch:
        raise TrialError(
            "the two arms differ in {} thing(s) besides the model, so a "
            "difference between them is not attributable to the model:\n  {}"
            .format(len(mismatch), "\n  ".join(mismatch)))

    models = {arm: bodies[arm]["environment"].get("model_requested")
              for arm in ARMS}
    if models["opus"] == models["sonnet"]:
        raise TrialError(
            "both arms request {!r}. A trial whose two arms are the same model "
            "measures the suite's own movement and calls it a model "
            "comparison".format(models["opus"]))

    ran = _already_run(opus) + _already_run(sonnet)
    if ran:
        raise TrialError(
            "{} result(s) already exist in these experiments, so an order "
            "written now is written after some of the answers:\n  {}".format(
                len(ran), "\n  ".join(ran[:5])
                + ("\n  ..." if len(ran) > 5 else "")))

    return {
        "trial": name,
        "seed": name,
        "arms": {arm: {"experiment": experiment_name, "model": models[arm],
                       # The same in both arms, and written into each so the
                       # runner sets it from the schedule rather than assuming
                       # the verifier follows the reviewer. It does not: this
                       # trial is Sonnet reviewing and Opus verifying.
                       "verifier": bodies[arm]["environment"].get(
                           "verifier_requested")}
                 for arm, experiment_name in (("opus", opus),
                                              ("sonnet", sonnet))},
        "cases": order_a,
        "units": units(order_a, name),
        "committed": (
            "this file is written before the first review and its digest is "
            "the trial's identity. The order in `units` is the order the "
            "reviews are bought in, and a run that departs from it is refused "
            "rather than recorded."),
    }


def freeze(name: str, opus: str, sonnet: str) -> int:
    path = home(name) / "schedule.json"
    if path.exists():
        print("{} is already frozen ({}). A schedule rewritten after a result "
              "is not a schedule committed before them.".format(
                  path.relative_to(ROOT), experiment.digest_file(path)))
        return 2
    try:
        body = build(name, opus, sonnet)
    except TrialError as exc:
        print("refusing to freeze: {}".format(exc), file=sys.stderr)
        return 2
    rendered = json.dumps(body, indent=2, sort_keys=True) + "\n"
    if not experiment.publish(path, rendered):
        return 2
    print("frozen {} · {}".format(path.relative_to(ROOT),
                                  experiment.digest_file(path)))
    print("  {} unit(s) over {} case(s), arms {} and {}".format(
        len(body["units"]), len(body["cases"]),
        body["arms"]["opus"]["model"], body["arms"]["sonnet"]["model"]))
    first = ", ".join("{}/{}".format(u["arm"], u["pass"])
                      for u in body["units"][:6])
    print("  the order starts {} ...".format(first))
    return 0


def load_schedule(name: str) -> Tuple[Dict[str, Any], str]:
    path = home(name) / "schedule.json"
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise TrialError("no schedule for {} ({})".format(name, exc)) from exc
    try:
        body = json.loads(text)
    except ValueError as exc:
        raise TrialError(
            "the schedule for {} is not readable JSON ({}), so nothing here "
            "says what order was committed".format(name, exc)) from exc
    if not isinstance(body, dict) or not isinstance(body.get("units"), list):
        raise TrialError(
            "the schedule for {} records no list of units, so there is no "
            "committed order to hold a run to".format(name))
    # Every unit asked what it is before anything indexes into it. Codex,
    # 2026-09-06: the checks below read `unit["index"]`, `unit["arm"]` and the
    # arm's experiment name, so a schedule shaped wrongly crashed the function
    # whose whole job is to report what is wrong.
    for position, unit in enumerate(body["units"]):
        if not isinstance(unit, dict):
            raise TrialError(
                "unit {} of the schedule is {}, where an object naming one "
                "case, arm and pass is required".format(
                    position, type(unit).__name__))
        if unit.get("index") != position:
            raise TrialError(
                "unit {} of the schedule records index {!r}. The order is read "
                "by position, and a unit that disagrees with its own place "
                "cannot be held to".format(position, unit.get("index")))
        if not isinstance(unit.get("case_id"), str) or not unit["case_id"]:
            raise TrialError(
                "unit {} of the schedule names no case".format(position))
        if unit.get("arm") not in ARMS or unit.get("pass") not in PASSES:
            raise TrialError(
                "unit {} of the schedule names arm {!r} and pass {!r}, and one "
                "of them is not a thing this trial has".format(
                    position, unit.get("arm"), unit.get("pass")))
    arms = body.get("arms")
    if not isinstance(arms, dict) or set(arms) != set(ARMS) or not all(
            isinstance(arms[arm], dict)
            and isinstance(arms[arm].get("experiment"), str)
            for arm in ARMS):
        raise TrialError(
            "the schedule for {} does not name an experiment for each of {}, "
            "so there is nowhere to look for a result".format(
                name, " and ".join(ARMS)))
    return body, digest(text)


def ledger_path(name: str) -> Path:
    return home(name) / "ledger.jsonl"


def read_ledger(name: str) -> List[Dict[str, Any]]:
    """The recorded history, refusing a line it cannot read.

    Not "the lines it could parse". A ledger with an unreadable line in the
    middle is a history with a hole, and continuing past it would resume onto
    an order nobody can check.
    """
    path = ledger_path(name)
    if not path.exists():
        return []
    # **Every physical line, blanks included.** Codex, 2026-09-06: skipping
    # blank lines meant `append(after=N)` compared N against the number of
    # *records*, not the file's length — so a blank line inserted between the
    # read and the write mutated the ledger and the conditional append still
    # passed, chaining onto a file that had moved. A ledger is a file, and a
    # rule about its length has to be about the file.
    text = path.read_text(encoding="utf-8")
    if text and not text.endswith("\n"):
        # Same hole, one byte along. Codex, 2026-09-06, fifth round:
        # `splitlines()` gives the same record count whether the last line ends
        # or not, so `after=N` passed — and then append mode wrote the next
        # object straight against the previous one, `}{`, corrupting the file
        # the next reader has to parse.
        raise TrialError(
            "the ledger does not end with a newline, so a line has been cut "
            "short or something wrote to it without finishing. Appending now "
            "would join two records into one")
    lines = text.splitlines()
    out = []
    for number, line in enumerate(lines, start=1):
        if not line.strip():
            raise TrialError(
                "line {} of the ledger is blank. Nothing this tool writes "
                "produces one, so the file has been edited by something else "
                "and its length no longer means what the chain assumes"
                .format(number))
        try:
            entry = json.loads(line)
        except ValueError as exc:
            raise TrialError(
                "line {} of the ledger is not readable JSON ({}). The history "
                "cannot be checked past it, and a run that continues anyway "
                "is a run following an order nobody verified".format(
                    number, exc)) from exc
        if not isinstance(entry, dict):
            raise TrialError(
                "line {} of the ledger is {}, where an object recording one "
                "step is required".format(number, type(entry).__name__))
        out.append(entry)
    return out


def _result_path(schedule: Dict[str, Any], unit: Dict[str, Any]) -> Path:
    arm = schedule["arms"][unit["arm"]]["experiment"]
    return experiment.home(arm) / "pass-{}".format(unit["pass"]) / \
        "{}.json".format(unit["case_id"])


def _where(position: int) -> str:
    """Which line, counted by the reader and never by the line itself.

    Codex, 2026-09-06: the message used `entry.get("seq", "?") + 1`, so a line
    whose `seq` was a string raised `TypeError` out of the middle of the check
    that exists to *report* such a line. A diagnostic that crashes on the input
    it is diagnosing is the check not existing.
    """
    return "ledger line {}".format(position + 1)


def _chain(entries: List[Dict[str, Any]]) -> List[str]:
    """Every line's `seq` and `previous`, checked in file order.

    The chain covers *all* lines, not only the unit ones: a reference record
    removed from the middle would otherwise leave no trace, and when the
    reference was frozen is exactly what this ledger exists to say.
    """
    problems = []
    for position, entry in enumerate(entries):
        where = _where(position)
        if entry.get("seq") != position:
            problems.append(
                "{}: records seq {!r}, and a ledger is read by its order"
                .format(where, entry.get("seq")))
            continue
        expected = line_digest({k: v for k, v in entries[position - 1].items()
                                if k != "previous"}) if position else None
        if entry.get("previous") != expected:
            problems.append(
                "{}: follows {!r} and the line before it hashes to {!r}. The "
                "chain is what says no line was removed or inserted".format(
                    where, entry.get("previous"), expected))
    return problems


def _units_recorded(schedule: Dict[str, Any],
                    entries: List[Dict[str, Any]]) -> List[str]:
    """The unit records against the committed order.

    `prepared` and `done` alternate, one pair per unit, in the schedule's own
    order. Anything else — a `done` with no `prepared`, two `prepared` in a
    row, a pair for the wrong case — is a history that did not follow the
    order it claims to have followed.
    """
    problems: List[str] = []
    expected_index = 0
    open_unit: Optional[Dict[str, Any]] = None
    for position, entry in enumerate(entries):
        kind = entry.get("kind")
        if kind not in (PREPARED, DONE):
            continue
        where = _where(position)
        if kind == PREPARED:
            if open_unit is not None:
                problems.append(
                    "{}: opens unit {} while unit {} is still open. A step "
                    "that never recorded its result cannot be stepped over"
                    .format(where, entry.get("index"), open_unit.get("index")))
                continue
            if expected_index >= len(schedule["units"]):
                problems.append(
                    "{}: the schedule commits {} unit(s) and this opens one "
                    "past the end".format(where, len(schedule["units"])))
                continue
            unit = schedule["units"][expected_index]
            if (entry.get("index"), entry.get("case_id"), entry.get("arm"),
                    entry.get("pass")) != (unit["index"], unit["case_id"],
                                           unit["arm"], unit["pass"]):
                problems.append(
                    "{}: opens {}/{}/{} where the committed order says "
                    "{}/{}/{}".format(where, entry.get("arm"),
                                      entry.get("pass"), entry.get("case_id"),
                                      unit["arm"], unit["pass"],
                                      unit["case_id"]))
                continue
            open_unit = entry
            continue
        # DONE
        if open_unit is None:
            problems.append(
                "{}: records a result for unit {!r} that nothing opened"
                .format(where, entry.get("index")))
            continue
        if entry.get("index") != open_unit.get("index"):
            problems.append(
                "{}: closes unit {!r} while unit {!r} is the one open".format(
                    where, entry.get("index"), open_unit.get("index")))
            continue
        unit = schedule["units"][open_unit["index"]]
        path = _result_path(schedule, unit)
        if not path.exists():
            problems.append(
                "{}: records a result for {} and {} is not there. A completed "
                "step with no result is not completed".format(
                    where, unit["case_id"], path.relative_to(ROOT)))
        elif experiment.digest_file(path) != entry.get("result_digest"):
            problems.append(
                "{}: {} is on disk with a different content than the step "
                "recorded. What was measured and what is kept are not the "
                "same file".format(where, path.relative_to(ROOT)))
        open_unit = None
        expected_index += 1
    return problems


def _strays(schedule: Dict[str, Any],
            entries: List[Dict[str, Any]]) -> List[str]:
    """Accepted results no ledger line accounts for.

    The other direction, and it matters as much: a row nobody opened a step
    for was bought outside the committed order, and a resume that counted rows
    would have taken it for progress.

    A unit that is *open* — `prepared` with no `done` — is not a stray. Codex,
    2026-09-06: publishing the result and appending the line are two writes,
    and a crash between them leaves a paid, perfectly good review that this
    check would otherwise condemn for ever.

    **But it is not accepted on its own either.** Same round, same reviewer:
    "any valid `prepared` record accounts for a result file, even without a
    matching `done`. Anyone can place a fabricated row at that unit's expected
    path after preparation." Nothing in a JSON file binds it to the process
    that was supposed to have written it. So the open unit's row is reported
    and left for a person to accept with `--recover`, and the acceptance is
    itself a ledger line. Trusted deliberately and recorded, rather than
    trusted silently.
    """
    accounted = set()
    for entry in entries:
        if entry.get("kind") not in (PREPARED, DONE):
            continue
        index = entry.get("index")
        if isinstance(index, int) and 0 <= index < len(schedule["units"]):
            accounted.add(str(_result_path(schedule,
                                           schedule["units"][index])))
    problems = []
    for arm in ARMS:
        experiment_name = schedule["arms"][arm]["experiment"]
        for label in PASSES:
            directory = experiment.home(experiment_name) / \
                "pass-{}".format(label)
            for path in sorted(directory.glob("*.json")):
                if str(path) not in accounted:
                    problems.append(
                        "{} is an accepted result no ledger step accounts "
                        "for. It was not bought by this trial's committed "
                        "order".format(path.relative_to(ROOT)))
    return problems


def _reference_still_there(entries: List[Dict[str, Any]]) -> List[str]:
    """The frozen baseline, checked against the line that recorded it.

    Codex, 2026-09-06, eighth round: the ledger recorded a path and a digest
    and nothing ever compared them again. The whole point of writing the digest
    down is that the file compared against later is the one that was frozen —
    a reference edited or replaced after the freeze would have passed every
    check in this file, and the comparison the trial exists for would have run
    against a baseline nobody recorded.
    """
    problems = []
    for position, entry in enumerate(entries):
        if entry.get("kind") != REFERENCE:
            continue
        where = _where(position)
        path = entry.get("path")
        if not isinstance(path, str) or not path:
            problems.append(
                "{}: records a frozen reference and no path to it".format(
                    where))
            continue
        target = Path(path)
        if not target.exists():
            problems.append(
                "{}: the reference frozen here is not at {} any more. The "
                "comparison has nothing to run against".format(where, path))
            continue
        try:
            now = experiment.digest_file(target)
        except OSError as exc:
            problems.append(
                "{}: {} could not be read ({})".format(where, path, exc))
            continue
        if now != entry.get("reference_digest"):
            problems.append(
                "{}: {} is on disk with a different content than the freeze "
                "recorded. A baseline that changed after it was frozen is not "
                "a baseline".format(where, path))
    return problems


def verify(name: str) -> Tuple[Dict[str, Any], str,
                               List[Dict[str, Any]], List[str]]:
    """The schedule, its digest, the ledger, and everything wrong with them.

    **The digest travels with the schedule.** Codex, 2026-09-06, eighth round:
    `run` used the schedule object this function read and then re-read the file
    for its digest alone, so a schedule rewritten in between let an old unit be
    recorded against the new digest — and the mismatch that would have caught
    it was the very thing being recomputed. One read, one digest, and if the
    file moves afterwards the recorded digest no longer matches it, which is a
    refusal the next run makes.
    """
    schedule, schedule_digest = load_schedule(name)
    entries = read_ledger(name)

    problems = _chain(entries)
    for position, entry in enumerate(entries):
        if entry.get("kind") in (PREPARED, DONE) and \
                entry.get("schedule_digest") != schedule_digest:
            problems.append(
                "{}: recorded against schedule {} and the schedule on disk is "
                "{}. Either the schedule was rewritten after this step ran, or "
                "this ledger belongs to another trial".format(
                    _where(position), entry.get("schedule_digest"),
                    schedule_digest))
    if problems:
        # The chain and the identity come first: with either broken, the
        # unit-by-unit reading is a reading of a document that is not this
        # trial's history, and its findings would be about nothing.
        return schedule, schedule_digest, entries, problems

    problems += _units_recorded(schedule, entries)
    problems += _strays(schedule, entries)
    problems += _reference_still_there(entries)
    return schedule, schedule_digest, entries, problems


def committed_prefix(name: str) -> Tuple[str, str]:
    """Is the ledger on disk an extension of the one git has, or a rewrite.

    Codex, 2026-09-06: *"the hash chain cannot prove the recorded interleave.
    It has no externally committed head. A suffix can be removed undetectably
    ... or the entire ledger can be rewritten with recalculated hashes."* True
    of any chain whose head lives in the same file as the chain. The anchor
    available here is git: a ledger committed as the trial proceeds has a head
    outside the working tree, and a rewrite that recomputes every hash still
    contradicts what was committed.

    Three answers, not two. `unknown` is returned when git cannot be asked or
    the file has never been committed — that is "I could not check", and it is
    not "the history is sound".
    """
    path = ledger_path(name)
    try:
        relative = path.relative_to(ROOT)
    except ValueError:
        return "unknown", "the ledger is outside the repository"
    try:
        done = subprocess.run(
            ["git", "-C", str(ROOT), "show", "HEAD:{}".format(relative)],
            capture_output=True, text=True, check=False)
    except OSError as exc:
        return "unknown", "git could not be asked ({})".format(exc)
    if done.returncode != 0:
        return "unknown", ("no committed copy of {} — commit it as the trial "
                           "proceeds and the chain gains a head outside this "
                           "working tree".format(relative))
    try:
        current = path.read_text(encoding="utf-8")
    except OSError as exc:
        return "unknown", "the ledger could not be read ({})".format(exc)
    if current.startswith(done.stdout):
        return "extends", "the ledger extends the one committed in git"
    return "diverged", (
        "the ledger on disk is not an extension of the committed one. Lines "
        "that were recorded have been changed or removed, whatever the chain "
        "inside the file recomputes to")


def position(schedule: Dict[str, Any],
             entries: List[Dict[str, Any]]) -> Tuple[int, Optional[int]]:
    """Where a resume would continue, and which unit is left open, if any."""
    done = sum(1 for e in entries if e.get("kind") == DONE)
    opened = [e for e in entries if e.get("kind") == PREPARED]
    open_index = opened[-1]["index"] if len(opened) > done else None
    return done, open_index


def ledger_state(name: str) -> str:
    """What the ledger *is*, as one short string, or `"empty"`.

    The bytes, not the record count. Codex, 2026-09-06, after being asked to
    enumerate every byte mutation that leaves the parsed count unchanged: the
    list came back with a whole class still open — whitespace, key order, JSON
    escape spelling, CRLF, a trailing space before the newline, or a field
    nothing reads changed in the last line. Every one of those moves the file
    while `len(entries)` says it did not, and the writer was comparing counts.

    A digest of the whole file answers all of them at once, which is why this
    replaced the counter rather than being added beside it.
    """
    path = ledger_path(name)
    if not path.exists():
        return "empty"
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise TrialError(
            "the ledger could not be read ({}), so nothing here says whether "
            "it is the one this was written against".format(exc)) from exc
    if not raw:
        return "empty"
    return "{} byte(s) · {}".format(
        len(raw), hashlib.sha256(raw).hexdigest()[:16])


def append(name: str, entry: Dict[str, Any],
           after: Optional[str] = None) -> Dict[str, Any]:
    """One ledger line, chained to the one before it, flushed before returning.

    Appended rather than rewritten: a file that is only ever added to is one
    whose earlier lines a crash cannot damage.

    **`after` is the line count the caller believes it is extending**, and a
    ledger that has grown since is refused. Codex, 2026-09-06, after finding
    the same missing guard three times in this file and then being asked to
    enumerate every writer instead: *"`append()` supplies neither locking nor
    conditional append semantics, these are real race windows"*. Every caller
    was depending on a check it had made minutes earlier, and each of them was
    fixed one at a time until it became obvious the check belongs here — one
    writer, one rule, rather than six callers that must each remember it.

    The read and the write are held under a lock file for the same reason: two
    processes that both read a length of 7 would otherwise both pass the
    conditional and both write line 8.
    """
    path = ledger_path(name)
    path.parent.mkdir(parents=True, exist_ok=True)
    lock = path.with_suffix(".lock")
    try:
        handle = os.open(str(lock), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    except FileExistsError as exc:
        raise TrialError(
            "another process is writing this trial's ledger ({} exists). If "
            "nothing else is running, that file is left over from a killed "
            "run and can be removed.".format(lock.name)) from exc
    os.close(handle)
    try:
        entries = read_ledger(name)
        if after is not None and ledger_state(name) != after:
            raise TrialError(
                "the ledger is {} and this was written against {}. Something "
                "else wrote to it while this was working, and chaining onto a "
                "history that moved is how two runs record the same unit "
                "twice".format(ledger_state(name), after))
        entry = dict(entry, seq=len(entries))
        entry["previous"] = line_digest(
            {k: v for k, v in entries[-1].items() if k != "previous"}
        ) if entries else None
        with path.open("a", encoding="utf-8") as writer:
            writer.write(json.dumps(entry, sort_keys=True) + "\n")
            writer.flush()
            os.fsync(writer.fileno())
    finally:
        lock.unlink(missing_ok=True)
    return entry


def _buy(schedule: Dict[str, Any], unit: Dict[str, Any]) -> int:
    """One unit, through `experiment.run` and nothing else.

    The drift check before the case, the drift check after it, the discard rule
    and `publish` are that function's, not a second copy here. The model for
    this unit's arm is put in the environment first, because `experiment.run`
    checks the shell it is in against the arm's frozen manifest and refuses if
    they disagree — which is the check that makes the arm real rather than a
    label in a schedule.
    """
    arm = schedule["arms"][unit["arm"]]
    os.environ["SECURITY_SCAN_MODEL"] = arm["model"]
    # From the schedule, not from `arm["model"]`. Setting the verifier to the
    # reviewer's model would have bought Sonnet-reviews/**Sonnet**-verifies —
    # a different instrument from the one D-015 approved, and one the
    # comparator refuses after the money is gone rather than before.
    os.environ["SECURITY_SCAN_VERIFY_MODEL"] = arm["verifier"]
    return experiment.run(arm["experiment"], unit["pass"], limit=1,
                          only=unit["case_id"], spend_class=SPEND_CLASS)


def run(name: str, steps: Optional[int], recover: bool) -> int:
    """Walk the committed order, one unit at a time, recording both ends."""
    if steps is not None and steps < 0:
        print("--steps is a number of units to buy, and {} is not one"
              .format(steps), file=sys.stderr)
        return 2
    try:
        schedule, schedule_digest, entries, problems = verify(name)
    except TrialError as exc:
        print("cannot run: {}".format(exc), file=sys.stderr)
        return 2
    if problems:
        print("refusing to run: {} thing(s) wrong with the recorded "
              "history:".format(len(problems)), file=sys.stderr)
        for problem in problems:
            print("  - {}".format(problem), file=sys.stderr)
        return 2

    # **"I could not check" is not "it is sound", including here.** Codex,
    # 2026-09-06, on the version that refused only `diverged`: `committed_prefix`
    # says `unknown` means the anchor could not be asked, and this function then
    # spent on that answer. An uncommitted ledger can be rewritten whole with
    # every hash recomputed and resumed, and the chain inside the file agrees
    # with itself the entire time.
    #
    # An *empty* ledger is the one exception, and it is not a weakening: there
    # is no history to rewrite before the first line exists. One place for the
    # rule, because `reference` appends too and a rule enforced in one writer
    # is a rule with a way round it.
    refusal = _anchor_refusal(name, entries)
    if refusal:
        print("refusing to run: {}".format(refusal), file=sys.stderr)
        return 2
    anchor, why = committed_prefix(name)
    print("ledger: {}".format(why))
    if anchor == "unknown":
        # **One unit, and then stop.** Codex, 2026-09-06, sixth round: the
        # exception above is read once, while the ledger is still empty, and
        # with no `--steps` the loop below then bought every remaining unit —
        # the whole trial under an anchor that says "I could not check". The
        # exception exists for the *first* line, not for a run that creates
        # fifty-two of them. My own regression test hid this by passing
        # `--steps 1`, which is the shape of a test written to the fix rather
        # than to the defect.
        #
        # A **cap**, not an assignment. Codex, seventh round, same day:
        # `steps = 1` raised an explicit `--steps 0` to one, so the operator
        # who asked to buy nothing bought a review — the very contract this
        # branch was added beside. The two rules had a test each and their
        # intersection had none, which is how a defect survives a file of
        # tests written against it.
        if steps is None or steps > 1:
            print("  and unanchored, so this invocation buys one unit and "
                  "stops. Commit the ledger, then run again.")
        steps = 1 if steps is None else min(steps, 1)

    done, open_index = position(schedule, entries)
    bought = 0
    # The ledger length this invocation believes it is extending. Every append
    # below is conditional on it, so a rival process that appended while a
    # review was being bought stops this one instead of chaining onto a history
    # that moved. Kept as a counter rather than re-read, because re-reading is
    # exactly the check that would pass over the other process's line.
    recorded = ledger_state(name)
    if open_index is not None:
        unit = schedule["units"][open_index]
        path = _result_path(schedule, unit)
        # **Before either branch.** Codex, 2026-09-06, three rounds running on
        # the same shape: the zero-step guard sat inside the "nothing was
        # written" branch only, so `--steps 0 --recover` walked past it and
        # appended a `DONE`. `--steps 0` means this invocation changes nothing
        # — not "buys nothing but may still accept a row and move the trial on
        # a unit". The two rules had a test each and their intersection had
        # none. Again.
        if steps is not None and steps < 1:
            print("unit {} ({}/{}/{}) is open, and --steps {} says to do "
                  "nothing. Nothing was bought and nothing was recorded."
                  .format(open_index, unit["arm"], unit["pass"],
                          unit["case_id"], steps))
            return 0
        if path.exists():
            # **Not accepted on its own.** A `prepared` line makes a file at
            # that path expected, and expected is not the same as written by
            # the review this trial paid for. Codex, 2026-09-06. So a person
            # says so, and the saying is a line in the ledger.
            if not recover:
                print("unit {} ({}/{}/{}) was opened and never closed, and {} "
                      "is on disk.\nNothing here can show that row came from "
                      "the review this trial bought rather than from "
                      "somewhere else.\nLook at it, and if it is the paid "
                      "result, run this again with --recover.".format(
                          open_index, unit["arm"], unit["pass"],
                          unit["case_id"], path.relative_to(ROOT)),
                      file=sys.stderr)
                return 2
            append(name, {"kind": DONE, "index": open_index,
                          "result_digest": experiment.digest_file(path),
                          "schedule_digest": schedule_digest,
                          "recovered": True}, after=recorded)
            recorded = ledger_state(name)
            print("  unit {} recovered: {} accepted by hand".format(
                open_index, path.relative_to(ROOT)))
            done += 1
            # Against the budget as well. Recovering costs nothing, but an
            # invocation that recovers one unit and then buys another has done
            # two units' work where the operator asked for one.
            bought += 1
        else:
            # Opened, nothing written. The unit simply did not happen, and it
            # is bought now under the line that already opened it.
            #
            # **Under the same budget as any other unit.** Codex, 2026-09-06:
            # `--steps` was checked only in the loop below, so `--steps 0` —
            # an operator saying "buy nothing, just tell me where I am" — went
            # straight past it and bought this review. A limit that holds
            # except on the resume path is a limit that fails exactly when
            # somebody is being careful. The guard stands in front of both
            # branches now, above, because putting it here left `--steps 0
            # --recover` walking past it.
            code = _buy(schedule, unit)
            if code != 0 or not path.exists():
                print("\nunit {} did not conclude. It stays open; run this "
                      "again.".format(open_index))
                return code or 2
            append(name, {"kind": DONE, "index": open_index,
                          "result_digest": experiment.digest_file(path),
                          "schedule_digest": schedule_digest}, after=recorded)
            recorded = ledger_state(name)
            done += 1
            bought += 1

    while done < len(schedule["units"]):
        if steps is not None and bought >= steps:
            print("\nstopping after {} unit(s), as asked. {} left.".format(
                bought, len(schedule["units"]) - done))
            return 0
        unit = schedule["units"][done]
        print("\nunit {} of {} · {}/{} · {}".format(
            done + 1, len(schedule["units"]), unit["arm"], unit["pass"],
            unit["case_id"]), flush=True)
        append(name, {"kind": PREPARED, "index": done,
                      "case_id": unit["case_id"], "arm": unit["arm"],
                      "pass": unit["pass"],
                      "schedule_digest": schedule_digest}, after=recorded)
        recorded = ledger_state(name)
        code = _buy(schedule, unit)
        path = _result_path(schedule, unit)
        if code != 0 or not path.exists():
            print("\nunit {} did not conclude. It stays open; run this again "
                  "once whatever stopped it is dealt with.".format(done))
            return code or 2
        append(name, {"kind": DONE, "index": done,
                      "result_digest": experiment.digest_file(path),
                      "schedule_digest": schedule_digest}, after=recorded)
        recorded = ledger_state(name)
        done += 1
        bought += 1

    print("\nall {} unit(s) recorded.".format(len(schedule["units"])))
    return 0


def _anchor_refusal(name: str, entries: List[Dict[str, Any]]) -> Optional[str]:
    """Why the anchor forbids writing to this ledger, or `None`.

    One place, because `run` and `reference` both append and a rule enforced in
    one of them is a rule with a way round it.
    """
    anchor, why = committed_prefix(name)
    if anchor == "diverged":
        return why
    if anchor == "unknown" and entries:
        return ("{} line(s) are recorded and {}. Commit the ledger — until it "
                "is, the chain has no head outside the file it is in".format(
                    len(entries), why))
    return None


def _build_reference(schedule: Dict[str, Any]) -> Dict[str, Any]:
    """The baseline, built from the reference arm and refused otherwise.

    Rebinding `sentinel_reference.EXPERIMENT` is not enough, and Codex said so
    on 2026-09-06: `build()` takes its case list from the live `SUITE` and
    checks every row's digest against the live `CORPUS`, neither of which is
    the frozen arm. A suite edited since the arm ran would shape the reference
    — or refuse it — for a reason that has nothing to do with the rows that
    were paid for.

    `experiment.drift` already answers exactly this question about an arm, so
    it is asked rather than reimplemented: it compares the frozen manifest
    against the suite, the prompts, the schema, the scorer, the reviewer and
    the model as they stand now. The arm's own model goes into the environment
    first, because that is one of the things it compares and this shell is not
    the shell that ran the arm.
    """
    import sentinel_reference

    arm = schedule["arms"][REFERENCE_ARM]
    source = experiment.home(arm["experiment"])
    body = experiment.load(arm["experiment"])
    if body is None:
        raise TrialError(
            "the {} arm's manifest could not be read, so nothing says what "
            "case set its rows were bought under".format(REFERENCE_ARM))

    before = (os.environ.get("SECURITY_SCAN_MODEL"),
              os.environ.get("SECURITY_SCAN_VERIFY_MODEL"))
    os.environ["SECURITY_SCAN_MODEL"] = arm["model"]
    os.environ["SECURITY_SCAN_VERIFY_MODEL"] = arm["verifier"]
    try:
        moved = experiment.drift(body)
    except Exception as exc:
        # A manifest `drift` cannot read is not a manifest that agrees. It
        # indexes keys a manifest frozen by an older version may not carry, and
        # a `KeyError` out of the check that authorises this build would be
        # "I could not look" arriving as a crash.
        raise TrialError(
            "the {} arm's manifest could not be checked against what is on "
            "disk now ({}: {}), and could-not-check is not agreement".format(
                REFERENCE_ARM, type(exc).__name__, exc)) from exc
    finally:
        for key, value in zip(("SECURITY_SCAN_MODEL",
                               "SECURITY_SCAN_VERIFY_MODEL"), before):
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
    if moved:
        raise TrialError(
            "{} thing(s) have moved since the {} arm was frozen, and the "
            "builder reads them as they are now rather than as they were:\n  "
            "{}".format(len(moved), REFERENCE_ARM, "\n  ".join(moved)))

    # Rebound, exactly as `sentinel_reference --from` does it: every reader in
    # that module goes through the module name, and threading a path through
    # them is how one gets missed and a "fresh" reference comes out half old.
    original = sentinel_reference.EXPERIMENT
    try:
        sentinel_reference.EXPERIMENT = source
        built = sentinel_reference.build()
    except sentinel_reference.ReferenceError as exc:
        raise TrialError(
            "the {} arm's rows do not make a baseline ({})".format(
                REFERENCE_ARM, exc)) from exc
    finally:
        sentinel_reference.EXPERIMENT = original

    if built.get("missing"):
        raise TrialError(
            "{} case(s) are not in the {} arm's run: {}".format(
                len(built["missing"]), REFERENCE_ARM,
                ", ".join(built["missing"][:5])))
    return built


def _moved_since(name: str, entries: List[Dict[str, Any]]) -> Optional[str]:
    """What changed under this invocation while it was busy, or `None`.

    Read immediately before the write, because every other check in
    `reference()` happens before a build that reads dozens of files. Another
    process appending a unit, freezing its own reference, or moving the git
    anchor in that window would otherwise be published straight over.
    """
    try:
        _, _, now, problems = verify(name)
    except TrialError as exc:
        return "the history stopped being readable ({})".format(exc)
    if problems:
        return "{} thing(s) went wrong with the recorded history".format(
            len(problems))
    if len(now) != len(entries):
        return "{} ledger line(s) were appended".format(
            len(now) - len(entries))
    refusal = _anchor_refusal(name, now)
    if refusal:
        return refusal
    return None


def reference(name: str, write_to: str, recover: bool = False) -> int:
    """Freeze the baseline from the Opus arm, and record where in the order.

    The boundary D-015 asks for, as far as it can be drawn. The reference is
    built from the reference arm's directory and from nothing else; it is
    frozen once; and the ledger says at which point in the sequence, so a file
    compared against later either is that one or is refused.

    What this cannot do is stated in `LIMITATIONS.md` rather than implied here:
    a ledger records writes, not reads, and the challenger's rows are on disk
    in plain text throughout.
    """
    try:
        schedule, _, entries, problems = verify(name)
    except TrialError as exc:
        print("cannot freeze a reference: {}".format(exc), file=sys.stderr)
        return 2
    if problems:
        print("refusing: {} thing(s) wrong with the recorded history".format(
            len(problems)), file=sys.stderr)
        for problem in problems:
            print("  - {}".format(problem), file=sys.stderr)
        return 2

    refusal = _anchor_refusal(name, entries)
    if refusal:
        print("refusing: {}".format(refusal), file=sys.stderr)
        return 2

    if any(e.get("kind") == REFERENCE for e in entries):
        print("refusing: this trial already froze a reference. Freezing a "
              "second one is choosing which baseline the challenger is held "
              "to, after some of the challenger's answers are known.",
              file=sys.stderr)
        return 2

    # **Every unit of the reference arm, not most of them.** A baseline built
    # from part of its own arm is a baseline about a smaller experiment, and
    # nothing downstream would say which cases it left out.
    done_units = {e["index"] for e in entries if e.get("kind") == DONE}
    outstanding = [u for u in schedule["units"]
                   if u["arm"] == REFERENCE_ARM and u["index"] not in done_units]
    if outstanding:
        print("refusing: {} of the {} arm's unit(s) have not been recorded, "
              "so a reference frozen now is built from part of it:\n  {}"
              .format(len(outstanding), REFERENCE_ARM,
                      "\n  ".join("unit {} · {} pass {}".format(
                          u["index"], u["case_id"], u["pass"])
                          for u in outstanding[:5])
                      + ("\n  ..." if len(outstanding) > 5 else "")),
              file=sys.stderr)
        return 2

    target = Path(write_to)
    if target.exists():
        # **The same two-writes problem the units have**, and it needs the same
        # answer rather than a dead end. Writing the file and appending its
        # ledger line cannot be one operation, so a crash between them leaves a
        # reference on disk that no line records — and the checks above pass,
        # because no `REFERENCE` line exists. Without this the trial could
        # never freeze a reference again: the file is there and refuses to be
        # rewritten, and nothing records it.
        #
        # Recorded on a person's word, like the unit recovery, because nothing
        # in the file says which run wrote it.
        if not recover:
            print("refusing: {} already exists and no ledger line records "
                  "it.\nEither a freeze was interrupted between writing the "
                  "file and recording it, or this file came from somewhere "
                  "else.\nRun this again with --recover: it rebuilds the "
                  "baseline and records the file only if the two "
                  "match.".format(target), file=sys.stderr)
            return 2
        # The ledger as it stands before the rebuild, which is what the append
        # below is conditional on. Read here rather than beside the append: a
        # digest taken immediately before writing agrees with itself whatever
        # happened in between, which is a check of nothing.
        seen = ledger_state(name)
        # **Verified, not taken on trust.** Codex, 2026-09-06: the first
        # version recorded whatever digest the file happened to have, so an
        # operator's slip could permanently bless an unrelated reference. The
        # baseline is rebuilt from the arm and compared; `--recover` says "I
        # mean to record this one", not "believe it".
        try:
            rebuilt = _build_reference(schedule)
        except TrialError as exc:
            print("refusing: {}".format(exc), file=sys.stderr)
            return 2
        try:
            # The bytes, kept. Codex, 2026-09-06, ninth round: the digest was
            # taken by reading the path *again* after the comparison, so a
            # replacement in between was recorded as the validated content —
            # and `_reference_still_there` cannot see it, because the digest it
            # checks against already belongs to the substituted file.
            raw = target.read_bytes()
            on_disk = json.loads(raw.decode("utf-8"))
        except (OSError, ValueError, UnicodeDecodeError) as exc:
            print("refusing: {} could not be read ({}), so there is nothing to "
                  "compare the rebuilt baseline against".format(target, exc),
                  file=sys.stderr)
            return 2
        if on_disk != rebuilt:
            print("refusing: {} is not what this arm's rows build. Recording "
                  "it would bless a baseline the reference arm did not "
                  "produce.".format(target), file=sys.stderr)
            return 2
        # The same re-check as the ordinary path, because this branch appends
        # too. Codex, 2026-09-06: I put the guard in front of one of the two
        # writers and the other went on recording a stale `after_units` and a
        # second reference — the identical shape as the `--steps 0 --recover`
        # round two hours earlier, in the same file.
        stale = _moved_since(name, entries)
        if stale:
            print("refusing: {} while the baseline was being rebuilt. Nothing "
                  "was recorded.".format(stale), file=sys.stderr)
            return 2
        append(name, {"kind": REFERENCE,
                      "after_units": len(done_units),
                      "built_from": str(
                          experiment.home(
                              schedule["arms"][REFERENCE_ARM]["experiment"]
                          ).relative_to(ROOT)),
                      "path": str(target),
                      "reference_digest": _digest_bytes(raw),
                      "recovered": True}, after=seen)
        print("recorded {} · {} — it matches what the {} arm's rows build"
              .format(target, _digest_bytes(raw), REFERENCE_ARM))
        return 0

    source = experiment.home(schedule["arms"][REFERENCE_ARM]["experiment"])
    # Before the build, which is the long operation. Codex, 2026-09-06,
    # seventh round: taken afterwards it hashes a file that has *already* been
    # rewritten, so `append(after=seen)` agrees with a ledger nobody here ever
    # read — the exact time-of-check defect the byte-state contract replaced
    # the counter to remove, put back by reading the state one line too late.
    seen = ledger_state(name)
    try:
        body = _build_reference(schedule)
    except TrialError as exc:
        print("refusing: {}".format(exc), file=sys.stderr)
        return 2

    rendered = json.dumps(body, indent=1) + "\n"

    # **Everything checked again, immediately before the write.** Codex,
    # 2026-09-06: every check above happens before a build that reads dozens of
    # files, and another process can append units, freeze its own reference or
    # move the git anchor while it runs. The first version then published and
    # appended against `entries` and `done_units` read minutes earlier — a
    # second reference recorded, an `after_units` that was never true, and the
    # shared anchor rule bypassed by ordering alone.
    stale = _moved_since(name, entries)
    if stale:
        print("refusing: {} while the reference was being built. Nothing was "
              "written.".format(stale), file=sys.stderr)
        return 2

    if not experiment.publish(target, rendered):
        return 2
    # The digest of the bytes this invocation produced, not of a file read
    # back afterwards. Same round, same finding: re-reading blesses whatever
    # is at the path by then, which is the one thing the digest exists to rule
    # out.
    append(name, {"kind": REFERENCE,
                  "after_units": len(done_units),
                  "built_from": str(source.relative_to(ROOT)),
                  "path": str(target),
                  "reference_digest": _digest_bytes(rendered.encode("utf-8"))},
           after=seen)
    print("frozen {} · {}".format(target,
                                  _digest_bytes(rendered.encode("utf-8"))))
    print("  built from {} after {} unit(s), recorded in the ledger".format(
        source.relative_to(ROOT), len(done_units)))
    return 0


def status(name: str) -> int:
    try:
        schedule, _, entries, problems = verify(name)
    except TrialError as exc:
        print("cannot say where this trial is: {}".format(exc), file=sys.stderr)
        return 2
    done, open_index = position(schedule, entries)
    frozen = [e for e in entries if e.get("kind") == REFERENCE]
    print("trial {} · {} of {} unit(s) completed".format(
        name, done, len(schedule["units"])))
    print("  ledger: {}".format(committed_prefix(name)[1]))
    print("  arms: {} and {}".format(schedule["arms"]["opus"]["model"],
                                     schedule["arms"]["sonnet"]["model"]))
    if open_index is not None:
        unit = schedule["units"][open_index]
        path = _result_path(schedule, unit)
        print("  unit {} ({}/{}/{}) was opened and never closed — {}".format(
            open_index, unit["arm"], unit["pass"], unit["case_id"],
            "its result is on disk and a resume will record it"
            if path.exists() else "no result was written; a resume re-runs it"))
    if frozen:
        print("  reference frozen after {} unit(s) · {}".format(
            frozen[-1].get("after_units"), frozen[-1].get("reference_digest")))
    else:
        print("  reference: not frozen. The comparison cannot be run, and "
              "when it is frozen that is recorded here.")
    if problems:
        print("\n{} thing(s) wrong with the recorded history:".format(
            len(problems)))
        for problem in problems:
            print("  - {}".format(problem))
        return 2
    print("  the recorded history matches the committed order.")
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)

    it = sub.add_parser("freeze", help="commit the interleaved order")
    it.add_argument("name")
    it.add_argument("--opus", required=True, metavar="EXPERIMENT")
    it.add_argument("--sonnet", required=True, metavar="EXPERIMENT")

    go = sub.add_parser("run", help="buy the next unit(s) of the order")
    go.add_argument("name")
    go.add_argument("--steps", type=int, metavar="N",
                    help="stop after N unit(s); the rest wait for the next "
                         "invocation")
    go.add_argument("--recover", action="store_true",
                    help="accept the result of a unit that was opened and "
                         "never closed. Look at the row first: nothing here "
                         "can show it came from the review this trial bought")

    base = sub.add_parser(
        "reference", help="freeze the baseline from the reference arm")
    base.add_argument("name")
    base.add_argument("--write", required=True, metavar="PATH")
    base.add_argument("--recover", action="store_true",
                      help="record a reference file that is already on disk "
                           "and that no ledger line accounts for. Look at it "
                           "first: nothing here can show which run wrote it")

    where = sub.add_parser("status", help="check the recorded history")
    where.add_argument("name")

    args = parser.parse_args(argv)
    # A `TrialError` is a refusal, and a refusal leaves by the door refusals
    # leave by. `append` raises one from deep inside a run — a ledger that
    # moved, a lock nobody released — and a traceback out of a tool that has
    # just spent money on a review reads as a crash rather than as the check
    # working. Exit 2 throughout: this repository does not answer "could not
    # establish" with the code for anything else.
    try:
        if args.command == "freeze":
            return freeze(args.name, args.opus, args.sonnet)
        if args.command == "run":
            return run(args.name, args.steps, args.recover)
        if args.command == "reference":
            return reference(args.name, args.write, args.recover)
        return status(args.name)
    except TrialError as exc:
        print("refusing: {}".format(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
