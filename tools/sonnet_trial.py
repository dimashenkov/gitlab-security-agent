#!/usr/bin/env python3
"""The interleaved order for the Sonnet trial, and the ledger that proves it ran.

    tools/sonnet_trial.py freeze NAME --opus EXPERIMENT --sonnet EXPERIMENT
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

    order_a = list(bodies["opus"]["protocol"]["order"])
    order_b = list(bodies["sonnet"]["protocol"]["order"])
    if order_a != order_b:
        raise TrialError(
            "the two arms were frozen with different case orders, so they are "
            "not two measurements of one suite. Freeze both from the same "
            "suite file")

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
    lines = [line for line in path.read_text(encoding="utf-8").splitlines()
             if line.strip()]
    out = []
    for number, line in enumerate(lines, start=1):
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


def verify(name: str) -> Tuple[Dict[str, Any], List[Dict[str, Any]],
                               List[str]]:
    """The schedule, the ledger, and everything wrong with the history."""
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
        return schedule, entries, problems

    problems += _units_recorded(schedule, entries)
    problems += _strays(schedule, entries)
    return schedule, entries, problems


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


def append(name: str, entry: Dict[str, Any]) -> Dict[str, Any]:
    """One ledger line, chained to the one before it, flushed before returning.

    Appended rather than rewritten: a file that is only ever added to is one
    whose earlier lines a crash cannot damage.
    """
    entries = read_ledger(name)
    entry = dict(entry, seq=len(entries))
    entry["previous"] = line_digest(
        {k: v for k, v in entries[-1].items() if k != "previous"}
    ) if entries else None
    path = ledger_path(name)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry, sort_keys=True) + "\n")
        handle.flush()
        os.fsync(handle.fileno())
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
        schedule, entries, problems = verify(name)
    except TrialError as exc:
        print("cannot run: {}".format(exc), file=sys.stderr)
        return 2
    if problems:
        print("refusing to run: {} thing(s) wrong with the recorded "
              "history:".format(len(problems)), file=sys.stderr)
        for problem in problems:
            print("  - {}".format(problem), file=sys.stderr)
        return 2

    anchor, why = committed_prefix(name)
    if anchor == "diverged":
        print("refusing to run: {}".format(why), file=sys.stderr)
        return 2
    if anchor == "unknown" and entries:
        # **"I could not check" is not "it is sound", including here.** Codex,
        # 2026-09-06, on the version that refused only `diverged`: this
        # function's own docstring says `unknown` means the anchor could not be
        # asked, and then it spent on that answer. An uncommitted ledger can be
        # rewritten whole with every hash recomputed and resumed, and the chain
        # inside the file agrees with itself the entire time.
        #
        # An *empty* ledger is the one exception, and it is not a weakening:
        # there is no history to rewrite before the first line exists. From the
        # first line on, the head lives in git or the run stops.
        print("refusing to run: {} line(s) are recorded and {}.\nCommit the "
              "ledger and run this again — until it is committed, the chain "
              "has no head outside the file it is in.".format(
                  len(entries), why), file=sys.stderr)
        return 2
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
    if open_index is not None:
        unit = schedule["units"][open_index]
        path = _result_path(schedule, unit)
        _, schedule_digest = load_schedule(name)
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
                          "recovered": True})
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
                          "schedule_digest": schedule_digest})
            done += 1
            bought += 1

    _, schedule_digest = load_schedule(name)
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
                      "schedule_digest": schedule_digest})
        code = _buy(schedule, unit)
        path = _result_path(schedule, unit)
        if code != 0 or not path.exists():
            print("\nunit {} did not conclude. It stays open; run this again "
                  "once whatever stopped it is dealt with.".format(done))
            return code or 2
        append(name, {"kind": DONE, "index": done,
                      "result_digest": experiment.digest_file(path),
                      "schedule_digest": schedule_digest})
        done += 1
        bought += 1

    print("\nall {} unit(s) recorded.".format(len(schedule["units"])))
    return 0


def status(name: str) -> int:
    try:
        schedule, entries, problems = verify(name)
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

    where = sub.add_parser("status", help="check the recorded history")
    where.add_argument("name")

    args = parser.parse_args(argv)
    if args.command == "freeze":
        return freeze(args.name, args.opus, args.sonnet)
    if args.command == "run":
        return run(args.name, args.steps, args.recover)
    return status(args.name)


if __name__ == "__main__":
    raise SystemExit(main())
