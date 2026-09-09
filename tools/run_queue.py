#!/usr/bin/env python3
"""Run corpus pairs as a queue that survives the subscription's session limit.

Three windows were exhausted in two days, and each time the answer was a rule
built on a number that measures something else: batch size against the *weekly*
limit, then notional API cost against quota. There is no number for remaining
session capacity — no CLI subcommand exposes it and nothing caches it under
`~/.claude`. So this does not predict.

What is observable is the refusal itself, and it carries the reset time:

    You've hit your session limit · resets 7:20pm (Europe/Sofia).

So the queue treats a refusal as a pause rather than a failure: it checkpoints
after every pair, sleeps until the stated reset, and picks the same case up
again. A refused run costs a re-run and never a measurement — `pair_corpus`
already records it as incomplete and refuses to score it as clean.

    tools/run_queue.py --language go --construction snapshot   # unattended
    tools/run_queue.py --language go --pairs 4                 # attended
    tools/run_queue.py --construction snapshot --wait-for-reset
    tools/run_queue.py --language php --dry-run     # what it would run

Two ways to run it, and the difference is about the person, not the quota.
**Unattended** runs to refusal, sleeps until the reset the message names, and
resumes — the whole corpus, overnight, without anybody watching. **Attended**
takes `--pairs N`, runs that many and stops, so there is room left in the
window to keep working interactively.

`--pairs` is not a cap and nothing may be derived from it. Refusals cost twelve
seconds and no tokens, and the subscription is paid either way; what the number
reserves is interactive capacity, not allowance. Three separate rules were once
built by reading a number like this as a measurement of the limit, and each was
wrong. The ledger tags every window with how it ended for exactly that reason:
a window stopped early says only that the limit was above that number, and must
never be mixed with one that ran to refusal.

One pair in flight at a time, so a refusal at the boundary loses at most one.
Results land in `measurements/queue/<case>.json` as they finish, and the queue
skips any case already recorded there or in an existing batch file — so
stopping it and starting it again resumes rather than repeats.

`measurements/queue/log.jsonl` records one line per attempt with the raw fields
and nothing derived: duration, the four token counts, the notional cost clearly
labelled as notional, the outcome, and which window it ran in. Codex's
condition for the log being worth keeping: record the raw fields and weight
nothing until there is enough data to say which of them predicts a refusal.
Until then they are candidate correlates, not measurements of quota.
"""

from __future__ import annotations

import argparse
import fcntl
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List, Optional

import yaml

import pair_corpus
import stop_rule
from artifact import answer_key_digest, case_digest, legacy_case_digest
from check_accounted import about_this_version, scorable

ROOT = Path(__file__).resolve().parents[1]
QUEUE = ROOT / "measurements" / "queue"
# Why this tool's spending is authorised, passed down to `pair_corpus.py`
# rather than left to its default. Mapped in `tools/spend_gate.py`.
SPEND_CLASS = "run_queue"
LOG = QUEUE / "log.jsonl"
# Where a run of a model other than the product goes:
# `queue/by-model/<model>/<case>.json`. A reserved segment, so a model name
# can never collide with `log.jsonl`, `manifest.json` or a case result file.
BY_MODEL = "by-model"

# The refusal, and the reset it names. Matched on the sentence rather than on a
# status code because the CLI reports it as an ordinary error: exit 1 with the
# message in its terminal object.
LIMIT = re.compile(r"hit your (session|usage) limit", re.I)
# Failures already seen and understood: the CLI exiting non-zero while printing
# a success object, and a review killed by its own wall clock. Anything else is
# `unknown`, and the queue stops rather than guessing which of the two it is.
KNOWN_ERROR = re.compile(
    r"reported '\(no subtype\)'|wall.?clock|timed out", re.I)
# Told apart from the rest because it is the one failure where a replay is not
# obviously free: the process may have submitted work before dying, and nothing
# it left behind says whether it did.
NO_ARTIFACT = re.compile(r"did not write its session|no session document", re.I)
RESET = re.compile(r"resets\s+(\d{1,2})(?::(\d{2}))?\s*(am|pm)", re.I)

# A pause when the refusal names no time it could parse. Long enough not to
# hammer the API, short enough that an unattended queue is not asleep for an
# afternoon after a transient wording change.
BLIND_WAIT = timedelta(minutes=30)


def malformed() -> set:
    """Cases a ruling has taken out of the score.

    `pair_corpus` excludes them at the start of a run, so a queue that asked
    for one got an empty result file back — and an empty payload read as a
    pair that discriminated nothing, which this would have written down as a
    failure. A case ruled unable to measure anything, recorded as a case that
    measured the wrong thing, in the tool built to keep those two apart.
    """
    path = ROOT / "corpus-real" / "adjudications.yml"
    try:
        body = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, ValueError):
        return set()
    rows = body if isinstance(body, list) else body.get("adjudications") or []
    # **`is True`, and a reason.** The same terms `artifact.malformed_cases`
    # and `check_accounted.rulings` use — whose docstring names this exact
    # defect, because it was repaired at two of the three sites and not here.
    # `case_is_malformed: "false"` is truthy, and a `true` with no reason is a
    # ruling nobody wrote down; either one dropped the case from every sweep
    # for ever while the accounting kept reporting it as not run. And a ruling
    # with no `case_id` put `None` in the set, inflating the printed count by
    # one.
    return {r["case_id"] for r in rows
            if isinstance(r, dict) and r.get("case_id")
            and r.get("case_is_malformed") is True
            and isinstance(r.get("why_malformed"), str)
            and r["why_malformed"].strip()}


def cases(args) -> List[str]:
    """Every case the queue would run, in a stable order.

    Named cases are taken as given — asking for one by hand is a decision —
    but a language sweep drops the ruled-out ones, because sweeping is not.
    """
    excluded = malformed()
    if args.case:
        return list(args.case)

    chosen = []
    for manifest in sorted((ROOT / "corpus-real").glob("*/case.yml")):
        if manifest.parent.name in excluded:
            continue
        body = yaml.safe_load(manifest.read_text(encoding="utf-8")) or {}
        if args.language and body.get("language") != args.language:
            continue
        if args.construction and body.get("construction") != args.construction:
            continue
        chosen.append(manifest.parent.name)
    return chosen


def already_run(case_id: str, repeat: bool = False) -> bool:
    """Recorded anywhere, so stopping and restarting resumes.

    Both the queue's own per-case files and the batch files written by
    `pair_corpus` directly, because the corpus has been measured both ways and
    paying twice for one answer is the thing this is here to avoid.

    Recorded *about today's version of the case*, which the first version did
    not ask. `cli-batch-1` and `cli-batch-2` predate `case_digest` and carry
    none, so `check_accounted` correctly refuses them as verdicts — while this
    counted them and skipped the case. Three cases sat in exactly that state on
    2026-09-02: the accounting said "not run", the queue said "already
    recorded", and a run of the twelve would have bought nine and reported
    twelve. The queue skipping a case is how "not measured" becomes invisible,
    which is the same failure as a green gate over unread code.

    `repeat` is for a round that means to run the corpus again: it consults
    only this round's own directory, so the round still resumes after a refusal
    while earlier results do not silence it. Without it `--round` would queue
    nothing at all, because every case is recorded from the first pass — the
    skip that makes the queue resumable is the same skip that makes it unable
    to repeat.

    **And recorded about the model this run is buying.** A row from another
    model is a real charge — that is why `spend` and `stage2`'s billing probe
    count it — but it is not this run's answer, so skipping the case on it
    buys nothing and loses the measurement that was wanted. Nothing here would
    ever go back and buy it: `already_run` would keep saying yes.

    **Which model, though, is the environment's, not a constant.** Codex,
    2026-09-09, on the version that asked for Opus by name: a queue started
    with `SECURITY_SCAN_MODEL=claude-sonnet-5` writes Sonnet rows into
    `QUEUE/<case>.json`, and on restart with the same environment, case and
    corpus version this reader answered `False` on its own finished row. The
    case was queued and bought a second time for the same answer, overwriting
    the first — a real double payment, introduced by the line that was meant
    to prevent one. `stop_rule.queue_model` resolves it the way `Config` does.

    The trial's own 52 rows never reached here, and the first version of this
    docstring said they did. They are under `measurements/experiment-*/pass-*/`
    and this reader globs neither that nor `round-*/`, which is a separate gap
    recorded in `LIMITATIONS.md`. The reachable path is the exported variable
    above.

    `why_not_row_for` is the one spelling of the question, shared with
    `stop_rule.latest_rows`, `sentinel.recorded_outcomes`, `check_accounted`
    and `stage2` — those four ask it with the product's fixed name, because
    what the project owes is measured against the model it ships and an
    exported variable must not move those numbers. A row with no `members` key
    predates the field and is read.
    """
    # **Every file the queue holds for this case, not the one path this
    # invocation would write.** Codex, 2026-09-09: `result_path` gives a
    # non-product run a model-qualified name, so a Sonnet result written under
    # the old universal `<case>.json` became invisible the moment the naming
    # changed — the case bought again over a valid, current-digest row sitting
    # right there. Which model a row belongs to is decided by reading it, and
    # a file name is a place to look rather than an answer, so the search is
    # by content and the migration needs nothing.
    wanted = stop_rule.queue_model()
    # **Every file the queue holds, and the row inside decides.** Codex,
    # 2026-09-09: the search was still keyed on the file name — first the one
    # path this invocation would write, then two name patterns — while the
    # comment beside it claimed the opposite. Any layout the queue has ever
    # written, or ever will, is read here: `<case>.json` from before models
    # were distinguished, `<model>/<case>.json` now, and the
    # `<case>.<model>.json` that existed in between. A file name is a place to
    # look; `case_id` is in the row.
    for own in sorted(set(QUEUE.glob("*.json"))
                      | set(QUEUE.glob(BY_MODEL + "/*/*.json"))):
        if own.name == "manifest.json" or own.name == "log.jsonl":
            continue
        # The file existing is not the same as the case having been measured.
        # A pair whose review stopped early leaves a row saying so, and reading
        # its presence as "done" is this project's founding error — "did not
        # check" read as "checked" — inside the queue built to avoid it. It
        # cost `js-q4gh-4ffp-5cg8-snap` a silent skip: recorded, never run.
        try:
            rows = json.loads(own.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        # The same three questions as the batch branch below, and this branch
        # asked none of them: not whether the row is about *this* case, not
        # whether it is about today's version of it, not whether it carries a
        # result. A case edited after its queue file was written would have
        # been skipped for ever through the shorter path — the defect this
        # function was just fixed for, still live on the more direct route.
        if any(scorable(r) and r["case_id"] == case_id
               and about_this_version(case_id, r)
               and stop_rule.why_not_row_for(r, wanted) is None
               for r in (rows if isinstance(rows, list) else [])):
            return True
    # **And no early `False` when a file merely exists.** Codex, 2026-09-09,
    # against the guard the line above used to hold: a queue file carrying an
    # Opus row stopped the search before the batches, so a valid current
    # Sonnet row in a batch was never seen and Sonnet was bought again. The
    # question is whether *this model's* measurement of the case exists
    # anywhere, and a queue file that answers for some other model — or for
    # none, because the run did not finish — says nothing about that. It is
    # one more place to look, not an authority. The original branch returned
    # early too and the guard preserved that shape; the shape was wrong.
    if repeat:
        # Nothing outside this round counts. A previous answer is what the
        # round exists to compare against, so it must not prevent the run that
        # produces the second one.
        return False
    wanted = stop_rule.queue_model()
    for path in (ROOT / "measurements").glob("*.json"):
        try:
            body = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        rows = body if isinstance(body, list) else body.get("results") or []
        for row in rows if isinstance(rows, list) else ():
            if scorable(row) and row["case_id"] == case_id \
                    and about_this_version(case_id, row) \
                    and stop_rule.why_not_row_for(row, wanted) is None:
                return True
    return False


def reset_at(detail: str, now: datetime) -> Optional[datetime]:
    """The moment the refusal says the window reopens, in local time.

    `resets 7:20pm` with no date: it is the next such time, which may be
    tomorrow if the refusal arrives after it. Returns None when the sentence
    carries no time this can read, and the caller waits blind rather than
    guessing a moment.
    """
    match = RESET.search(detail or "")
    if not match:
        return None
    hour = int(match.group(1)) % 12
    if match.group(3).lower() == "pm":
        hour += 12
    when = now.replace(hour=hour, minute=int(match.group(2) or 0),
                       second=0, microsecond=0)
    return when if when > now else when + timedelta(days=1)


def classify(payload: list) -> tuple:
    """`(kind, detail)` for how this pair ended.

    More states than the three it started with, because "unknown" was doing
    the work of half a dozen different endings and only one of them may enter
    the reset logic. Codex's list, and each is a different decision:

        refused        an explicit, validated limit message — the only ending
                       that may lead to sleeping until a reset
        failed-known   a failure already understood: the CLI exiting non-zero
                       while printing a success object, a wall-clock kill.
                       Record it and carry on; one broken case is not a reason
                       to stop a queue
        no-artifact    the process left no session document at all. It may
                       have submitted work before dying, so a replay is not
                       obviously free
        unknown        an ending this cannot name. It might be a refusal in
                       new words, and treating it as an ordinary failure would
                       work through the corpus being turned away while every
                       line in the log looked healthy

    An `unknown` does *not* mean "the wording changed". It may equally be a
    timeout, a truncated document, a parser defect, a lost connection or a
    local crash — which is exactly why it stops rather than guessing.
    """
    unknown = known = missing = None
    for row in payload if isinstance(payload, list) else ():
        for member in (row.get("members") or {}).values():
            detail = str(member.get("stop_detail") or "")
            if LIMIT.search(detail):
                return "refused", detail
            if member.get("stop_reason") != "error":
                continue
            if NO_ARTIFACT.search(detail):
                missing = detail
            elif KNOWN_ERROR.search(detail):
                known = detail
            else:
                unknown = detail or "an error with no detail recorded"
    if unknown:
        return "unknown", unknown
    if missing:
        return "no-artifact", missing
    return ("failed-known", known) if known else ("ok", None)


def sleep_until(target: datetime) -> None:
    """Wait for a wall-clock moment, not for a duration.

    `time.sleep(three hours)` counts on a monotonic clock, and on macOS that
    clock does not advance while the machine is asleep. A queue that computed
    the right wake-up — 09:47 refused, 12:50 stated, both correct — was still
    asleep at 15:32, because the laptop had been shut for most of the interval
    and its sleep had been added to the queue's.

    Short steps against the actual time instead, so a suspended machine costs
    at most one step of overshoot rather than however long it was closed. The
    step is a minute: long enough not to spin, short enough that waking late is
    measured in minutes.

    What this does *not* do, and it matters for overnight runs: nothing here
    executes while the machine is suspended. Waking on time means waking when
    the machine is awake. A queue left to run through the night finishes at
    whatever hour the lid is opened unless something keeps the machine up —
    `caffeinate -dimsu` does, an open lid on mains power does, and a closed lid
    does not, whatever `caffeinate` is asked. The fix removes the overshoot;
    it cannot make a sleeping computer run code.
    """
    while True:
        remaining = (target - datetime.now().astimezone()).total_seconds()
        if remaining <= 0:
            return
        time.sleep(min(60.0, remaining))


def wait_for_fresh_window(args, eligible, spent) -> None:
    """Start at the top of a window rather than in the tail of a spent one.

    One probe: ask for a case the queue is not going to run anyway. If the
    account is refusing, the message names the reset and this waits for it, so
    an unattended run launched at any hour begins with a full window instead of
    being turned away on its first real pair.

    A convenience, not a fix. Refusals cost twelve seconds either way; what
    this buys is that an overnight run does not spend its first hours asleep
    for a window that had minutes left in it.
    """
    # **The run's own list, not the whole corpus.** The first version cleared
    # `case`, `language` and `construction` before asking `cases()`, so
    # `--language go` bought a C# pair — the alphabetically first case of the
    # corpus — and `--round N` bought a case its manifest does not name,
    # after every frozen condition had been enforced. `repeat` too, because a
    # round asks a different question of `already_run`.
    #
    # The probe is a real, paid pair. It has to be one of the pairs the run
    # was going to buy anyway, or it is an extra purchase wearing the name of
    # a check.
    repeat = getattr(args, "round", None) is not None
    remaining = [c for c in eligible if not already_run(c, repeat)]
    if not remaining:
        return
    _payload, kind, detail = run_one(remaining[0], args)
    if kind != "refused":
        # **Counted only when something was bought.** Codex, 2026-09-09: a
        # refusal costs twelve seconds and no tokens, and recording it as
        # spent removed the case from the queue and ate the whole of
        # `--pairs 1` — so the command slept out the reset and then exited
        # successfully without ever measuring the one case it was asked for.
        # The probe exists to find a spent window; finding one must not
        # consume the allowance it was checking for.
        spent.append(remaining[0])
        return
    now = datetime.now().astimezone()
    when = reset_at(str(detail), now) or (now + BLIND_WAIT)
    print("the window is already spent · sleeping until {} before starting"
          .format(when.strftime("%H:%M")), flush=True)
    sleep_until(when + timedelta(minutes=1))


def close_window(window: str, termination: str, done: int, left: int,
                 mode: str) -> None:
    """Write how a window ended, so a later reader cannot mistake one for the
    other.

    `refused` is a measurement of where the limit fell, under that window's
    mixed load. `stopped_early` is not — it says the limit was above that
    number and nothing else, and a cluster built from both would fall apart the
    way the last one did, except deliberately.

    Nothing is computed from this here on purpose. It exists so the filter can.
    """
    # Which compaction behaviour this window ran under. Windows compacted at
    # different thresholds are not comparable, and mixing them silently would
    # break the next recut exactly as the uncounted subagents broke the last —
    # except self-inflicted. Read from the environment rather than declared, so
    # a variable that is set and ignored is recorded as what it is.
    note({"kind": "window", "window": window,
          "window_termination": termination, "mode": mode,
          "pairs_completed": done, "pairs_left": left,
          "autocompact_pct": os.environ.get(
              "CLAUDE_AUTOCOMPACT_PCT_OVERRIDE", "default"),
          "closed_at": datetime.now(timezone.utc).isoformat(timespec="seconds")})


def note(entry: dict) -> None:
    QUEUE.mkdir(parents=True, exist_ok=True)
    with LOG.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry, ensure_ascii=False) + "\n")


def raw_rows(payload: list, started_at: str, finished_at: str) -> list:
    """One row per invocation, carrying only what the provider said.

    Per member, not per pair, and nothing summed. Today's analysis tripped over
    exactly one pre-summed figure: the four token counts added together are
    99% cache reads, so any total including them says "the conversation
    dominates" whatever else is true. A row is cheap; a sum somebody has to
    unpick later is not.

    No derived fields. `notional_api_cost` is the provider's own
    `total_cost_usd` under a name that says what it is — the price this work
    would have carried on the API, on a login that was a subscription. It is
    here to be looked at, never to be reasoned from towards quota.
    """
    rows = []
    for row in payload if isinstance(payload, list) else ():
        for name, member in (row.get("members") or {}).items():
            usage = member.get("usage") or {}
            rows.append({
                "kind": "review",
                "case_id": row.get("case_id"), "member": name,
                "started_at": started_at, "finished_at": finished_at,
                "seconds": member.get("seconds"),
                "stop_reason": member.get("stop_reason"),
                "usage_reported": bool(usage.get("reported")),
                "input_tokens": usage.get("input_tokens"),
                "output_tokens": usage.get("output_tokens"),
                "cache_read_tokens": usage.get("cache_read_tokens"),
                "cache_write_tokens": usage.get("cache_write_tokens"),
                # Named, and sourced. Claude Code emits `total_cost_usd`; it
                # is the price this work would have carried on the API, and
                # the login was a subscription. Saying where it came from is
                # what keeps it from being read as a bill or as quota — both
                # of which have already happened.
                "notional_api_cost": (member.get("provenance") or {}).get(
                    "reported_cost_usd"),
                "notional_api_cost_source": "claude-code total_cost_usd",
                # Who paid, from the same provenance block the cost comes from.
                # Without these the cost is unclassifiable: `tools/spend.py`
                # reported all 44 stored rows as "billing not established",
                # because `claude-cli` says how a run was launched and not how
                # its login is billed. `claude.ai` plus a plan is a
                # subscription; `api-key` or `console` is charged; empty is the
                # CLI declining to say, and stays unknown rather than being
                # read as the cheaper answer.
                "auth_method": (member.get("provenance") or {}).get("auth_method"),
                "auth_subscription": (member.get("provenance") or {}).get(
                    "auth_subscription"),
            })
    return rows


def result_path(case_id: str) -> Path:
    """Where this invocation's result for `case_id` goes.

    **One file per case *and model*, not per case.** Codex, 2026-09-09,
    against the version that kept the bare name for every model: `already_run`
    correctly refuses a row from another model, but `run_one` overwrote the
    sole artifact, so alternating `SECURITY_SCAN_MODEL` between two models
    bought each of them again on every switch — Sonnet, then Opus over the top
    of it, then Sonnet again because the Sonnet row no longer existed. The
    filter that stopped one duplicate purchase created another, and it repeats
    indefinitely.

    The product keeps the bare `<case>.json`. That is not cosmetic: every file
    already on disk is the product's, every reader globs `queue/*.json`, and
    renaming them would rewrite the record to fix a path. Any other model gets
    a **directory**, `queue/<model>/<case>.json`.

    **A directory, not a suffix.** Codex, 2026-09-09, against the first
    version, which wrote `<case>.<model>.json`: that name does not uniquely
    encode the pair. A product run of a case literally called
    `a-case.claude-sonnet-5` and a Sonnet run of `a-case` both land on
    `a-case.claude-sonnet-5.json`, so one overwrites the other; on restart
    `already_run` reads the file, rejects the `case_id` inside it, and buys
    the case again — the very defect the qualified name was introduced to
    prevent, back through an ambiguity in the name. Case ids are directory
    names and nothing forbids a dot in one.

    **Under a reserved segment, `queue/by-model/<model>/<case>.json`.** Codex,
    2026-09-09, against `queue/<model>/<case>.json`: a model directory placed
    directly in the queue shares that namespace with the queue's own files,
    and `SECURITY_SCAN_MODEL` takes any non-empty string. `log.jsonl`,
    `manifest.json` or the name of an existing result all make `mkdir` run
    beneath a file, and the run dies before it starts. `by-model` is not a
    case id — every one of those is `<lang>-<four>-<four>-<four>` — so nothing
    the queue writes can land on it.

    A separator in the model name is refused rather than sanitised: a
    sanitised name is a different name, and it would then look like a
    different model.
    """
    model = stop_rule.queue_model()
    if model == stop_rule.PRODUCT_MODEL:
        return QUEUE / (case_id + ".json")
    if ("/" in model or os.sep in model or model.startswith(".")
            or model in (os.curdir, os.pardir)):
        raise SystemExit(
            "SECURITY_SCAN_MODEL={!r} cannot be a directory name".format(model))
    return QUEUE / BY_MODEL / model / (case_id + ".json")


class ClaimUnavailable(Exception):
    """The claim could not be taken, and not because another queue holds it.

    A read-only directory, a `.claim` path occupied by a directory, a
    filesystem with no `flock`. Told apart from a held case because they are
    different answers: one means wait for the other queue, the other means
    something is wrong here and nothing about this case has been established.
    """


def _claim_path(target: Path) -> Path:
    return target.with_name(target.name + ".claim")


def _take_claim(target: Path):
    """Reserve this case, or `None` if another queue holds it.

    **An advisory lock held on an open descriptor**, not a file whose presence
    means something. Codex, 2026-09-09, twice:

    * Unique attempt paths stopped two queues corrupting each other's
      temporary files and did nothing about the purchase — both evaluate
      `already_run`, both see no result, both buy the same pair, and the later
      promotion silently discards the earlier paid one. Four reviews for two,
      one thrown away.
    * The first repair was a claim *file* with an age at which it could be
      taken over, and that age is a guess about a live process. A queue past
      the ceiling had its claim removed by a second, then finished and
      unlinked the second's claim on its way out, and a third took the case
      while the second was still running. The takeover put back exactly the
      double purchase it was there to prevent.

    `flock` removes the question rather than answering it: the kernel releases
    the lock when the process ends, however it ends, so there is no age to
    guess and nothing to take over. The file is left behind on purpose — it is
    a lock, not a record, and unlinking it is what created the defect above.

    Advisory and per-filesystem: this is `measurements/`, a local directory
    that one machine writes. A queue run against a network filesystem that
    does not carry `flock` would not be serialised, and would be back to the
    defect this closes.
    """
    path = _claim_path(target)
    try:
        handle = os.open(str(path), os.O_CREAT | os.O_RDWR, 0o644)
    except OSError as exc:
        # **Not "somebody holds it".** A read-only directory, a `.claim` path
        # occupied by a directory, a filesystem that cannot lock — each was
        # answered with the sentence about another queue, and the window
        # ledger then recorded `held_elsewhere` as a fact. "I could not check"
        # read as an answer, which is the one confusion this project exists to
        # refuse.
        raise ClaimUnavailable(
            "the claim file for {} cannot be opened: {}".format(
                target.name, exc)) from None
    try:
        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        # The one case that really is another queue.
        os.close(handle)
        return None
    except OSError as exc:
        os.close(handle)
        raise ClaimUnavailable(
            "the claim for {} cannot be locked: {}".format(
                target.name, exc)) from None
    # For a person reading the directory, not for any decision here.
    try:
        os.ftruncate(handle, 0)
        os.write(handle, json.dumps({
            "pid": os.getpid(),
            "at": datetime.now(timezone.utc).isoformat()}).encode("utf-8"))
    except OSError:
        pass
    return handle


def _release_claim(handle) -> None:
    """Drop the lock. The file stays; the lock is what meant anything."""
    try:
        fcntl.flock(handle, fcntl.LOCK_UN)
    except OSError:
        pass
    try:
        os.close(handle)
    except OSError:
        pass


def run_one(case_id: str, args) -> tuple:
    """`(payload, kind, detail)`. The payload is kept unless it was refused.

    **The child writes beside the target, not to it.** Two rounds of review
    went into that, both from Codex on 2026-09-09. Writing to the target
    meant, first, that a crashed run left the *previous* row in place and
    `run_one` read it as this run's result — "did not check" as "checked",
    inside the queue built to avoid it. A modification stamp told them apart,
    then a stamp and an inode. And then the refusal branch, which deletes the
    file because a refused pair has measured nothing, was deleting the earlier
    measurement instead: by then the target had already been replaced.

    An attempt path removes both questions rather than answering them. The
    file exists only if this run wrote it; it becomes the case's result only
    when it is one; and the previous artifact is never touched until an
    `os.replace` puts a complete new one over it.
    """
    target = result_path(case_id)
    target.parent.mkdir(parents=True, exist_ok=True)
    # **A ruled-out case never reaches the child.** `pair_corpus.load_cases`
    # drops it and `pair_corpus.main` then exits "no such case" before writing
    # anything — so the queue saw an empty attempt, called it `no-artifact`,
    # printed "no session document was written", and stopped the whole
    # unattended run at that case with a message asserting a provider failure
    # that did not happen. The ruling is applied on a sweep and not to a named
    # case or a frozen round's list, which is where this arrives from.
    if case_id in malformed():
        return None, "ruled-out", (
            "a ruling in adjudications.yml says this case cannot measure "
            "anything, so nothing was bought for it")
    try:
        claim = _take_claim(target)
    except ClaimUnavailable as exc:
        # `unknown`, which stops the queue. Not `held`, which moves past — the
        # case would be deferred for ever against a condition no other queue
        # is going to clear.
        return None, "unknown", str(exc)
    if claim is None:
        return None, "held", (
            "another queue holds {}; it is being measured elsewhere".format(
                case_id))
    # **Unique to this invocation.** Codex, 2026-09-09: a deterministic
    # `<case>.json.attempt` is shared by two queues running the same case, and
    # they can unlink, read or promote each other's file. One completes a
    # valid result; the other replaces it with a refusal before the first
    # reads it; the first reads the refusal and deletes it, the second finds
    # nothing, and a paid measurement is gone with the case still queued. The
    # reverse order promotes one invocation's result and tells the other it
    # succeeded. `mkstemp` in the target's own directory, so the promotion
    # stays a rename on one filesystem.
    handle, attempt_name = tempfile.mkstemp(
        dir=str(target.parent), prefix=target.name + ".", suffix=".attempt")
    os.close(handle)
    attempt = Path(attempt_name)
    # **And the mode the finished artifact should carry, now.** Codex,
    # 2026-09-09: `mkstemp` creates at `0600`, `write_results` preserves the
    # mode of the file it replaces — which is this attempt, not the target —
    # and the promotion then carried `0600` onto the result. Two repairs, each
    # right alone, composing into the defect the second one was for. Setting
    # it here means the mode travels with the file through both renames, and
    # a mode somebody set on the target by hand is what it is read from.
    os.chmod(attempt, pair_corpus.intended_mode(target))
    promoted = False
    try:
        # **Asked again, under the claim.** The list was built before this run
        # started, and the queue that held the case may have finished it in
        # between. Without this the claim would only serialise the two
        # purchases rather than prevent the second.
        # `repeat` from the caller's own flag, not `False`. Codex,
        # 2026-09-09: a frozen round queues a case *because* `repeat=True`
        # ignores the production baseline, and this re-check asked with
        # `False` — so it found that baseline and answered "already", and the
        # round could not re-measure precisely the cases its stability
        # denominator is made of. The mechanism, disabled by the guard added
        # to protect it.
        if already_run(case_id, repeat=getattr(args, "round", None) is not None):
            return None, "already", "measured while this run was waiting"
        # Its own class, not `pair_corpus`'s. A queue measurement and a direct
        # corpus run reach the same `review` and can be ordered differently,
        # so the reason for spending travels with the caller that has it.
        # Codex, 2026-09-05.
        command = [sys.executable, "-u", str(ROOT / "tools" / "pair_corpus.py"),
                   str(ROOT / "corpus-real"), "--provider", args.provider,
                   "--profile", args.profile, "-c", "2",
                   "--spend-class", SPEND_CLASS,
                   "--case", case_id, "--json", str(attempt)]
        proc = subprocess.run(command, cwd=ROOT, check=False)
        # `mkstemp` created the file, so its *existence* says nothing. Empty
        # is what a child that wrote nothing leaves, and it is the same answer
        # as no file at all.
        if not attempt.is_file() or attempt.stat().st_size == 0:
            # Three, like every other return here. Two of them unpacked into a
            # three-name assignment and this line raised `ValueError` — on the
            # one path where `pair_corpus` wrote nothing at all, which is
            # exactly the path a broken CLI takes. `no-artifact` rather than
            # `unknown`: what is known is that no session document exists, and
            # whether the call was submitted before it died is not.
            return None, "no-artifact", "pair_corpus wrote no result file"
        try:
            payload = json.loads(attempt.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            # `pair_corpus.write_results` replaces the path atomically, so
            # this should not be reachable through it. It is here because the
            # queue crashing on an unreadable file is the worst of the three
            # answers: the run is over either way, and a traceback abandons
            # the rest of the corpus. Codex, 2026-09-09.
            return None, "no-artifact", (
                "the result file cannot be read: {}".format(exc))
        kind, detail = classify(payload)
        if kind != "refused":
            # Promoted only now, and atomically. A refused pair has measured
            # nothing, and promoting it would make `already_run` skip the case
            # for ever — so it simply is not promoted, and the earlier
            # artifact, which somebody paid for, is never touched.
            #
            # **`promoted` is set first.** It guards the `finally`, and setting
            # it after the rename leaves a window in which an exception from
            # `os.replace` — a sticky-bit directory, an ACL, the target
            # occupied by a directory — sends the cleanup at the payload this
            # run has just paid for. The flag says "this attempt is no longer
            # mine to delete", which is true from the moment the rename is
            # attempted: either it moved, or it is in a state nothing here
            # should be tidying up blind.
            promoted = True
            os.replace(str(attempt), str(target))
        # The return code is deliberately not read. `pair_corpus` exits
        # non-zero when a pair fails to discriminate, which is a result and
        # not an error; what matters here is whether the row says the account
        # was refused.
        del proc
        return payload, kind, detail
    finally:
        if not promoted:
            try:
                attempt.unlink()
            except OSError:
                pass
        _release_claim(claim)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--language")
    parser.add_argument("--construction", choices=("regression", "snapshot"))
    parser.add_argument("--case", action="append", default=[])
    parser.add_argument("--provider", default="claude-cli",
                        choices=("claude-cli", "anthropic-api"))
    parser.add_argument("--profile", default="normal",
                        choices=("probe", "normal", "deep"))
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument(
        "--pairs", type=int, metavar="N",
        help="run N pairs and stop cleanly — attended mode. This reserves "
             "room for you to keep working in the same window; it is not a "
             "quota measure and nothing may be derived from it.")
    parser.add_argument(
        "--wait-for-reset", action="store_true",
        help="if a refusal is already in force, wait for the next window "
             "before starting rather than walking into a spent one")
    parser.add_argument("--max-waits", type=int, default=4,
                        help="how many resets to sit through before giving up")
    parser.add_argument(
        "--round", type=int, metavar="N",
        help="run the corpus again into measurements/round-N/, ignoring "
             "results from earlier passes. Written to its own directory so a "
             "repeat cannot overwrite the answer it is being compared against, "
             "and left out of the globs `check_accounted` and `stage2` read, so "
             "a second opinion does not silently become the record.")
    args = parser.parse_args()

    if args.round is not None:
        if args.round < 1:
            sys.exit("--round is numbered from 1")
        # A round redirects every later write in this process to its own
        # directory, and the writers read these two names at module level. The
        # rule against `global` is right about state that several callers
        # mutate; this is one assignment, made once, before any work starts, so
        # that a round cannot be half-written into the previous round's files.
        global QUEUE, LOG  # noqa: PLW0603
        QUEUE = ROOT / "measurements" / "round-{}".format(args.round)
        LOG = QUEUE / "log.jsonl"
        print("round {}: writing to {}, ignoring earlier results"
              .format(args.round, QUEUE.relative_to(ROOT)), flush=True)

    repeat = args.round is not None
    eligible = cases(args)
    if repeat:
        # The frozen list and the frozen order, or nothing. A round whose queue
        # picks its own cases alphabetically has a manifest that describes a run
        # that did not happen — and the order is half of what the manifest is
        # for: alphabetical puts each language in its own window and confounds
        # the language with the reset.
        manifest = QUEUE / "manifest.json"
        if not manifest.is_file():
            sys.exit(
                "round {} has no manifest. Freeze it first:\n"
                "  tools/round.py freeze {}\n"
                "Running without one produces reviews and no experiment: "
                "nothing records which earlier row each new one answers."
                .format(args.round, args.round))
        try:
            frozen = json.loads(manifest.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            sys.exit("round {} manifest is unreadable: {}".format(args.round, exc))
        order = frozen.get("protocol", {}).get("order") or []
        if not order:
            sys.exit("round {} manifest carries no order".format(args.round))
        if args.language or args.construction or args.case:
            sys.exit("a frozen round runs what it froze; --language, "
                     "--construction and --case would narrow it after the fact")

        # The provider and the profile are half of what "the same conditions"
        # means, and they were frozen and then not enforced: `--round 2` and
        # `--round 3 --profile deep` both ran happily, and the comparison
        # afterwards would have called the difference between them the product
        # moving on its own. Frozen means frozen.
        protocol = frozen.get("protocol", {})
        # **The model, before anything is bought.** Codex, 2026-09-09: the
        # model was the one frozen condition that was neither written down nor
        # enforced, so a round frozen for the product ran happily under
        # `SECURITY_SCAN_MODEL=claude-sonnet-5` — and `round.compare` then
        # reported Sonnet against Opus as the product moving on its own, which
        # is the number every gate threshold sits above. A manifest frozen
        # before the field existed names no model, and then the product is
        # what it meant: every round so far was bought with it.
        # **And the manifest is not authoritative about which model.** Codex,
        # 2026-09-09: closing `freeze` stopped new manifests naming another
        # model and did nothing about one already on disk — hand-edited, or
        # written by an earlier revision of this very change. Such a manifest
        # matched a Sonnet environment, the round was bought with Sonnet, and
        # `compare` put those rows against the Opus baselines `baselines()`
        # draws from the product's own verdicts: "0 agreed, 1 flipped", exit
        # 0, one model reported as the other moving on its own. A round is a
        # measurement of the product wherever the claim is written down.
        #
        # Absence still means the product, because every round frozen before
        # the field existed was bought with it.
        named = protocol.get("model")
        if named is not None and named != stop_rule.PRODUCT_MODEL:
            sys.exit(
                "round {} has a manifest naming model {!r}. A round is a "
                "measurement of {} — its baselines are the product's own "
                "verdicts — so a pass bought from another model would be "
                "compared against them and the difference reported as the "
                "product moving on its own. Re-freeze the round, or use "
                "tools/experiment.py, which is what compares two models."
                .format(args.round, named, stop_rule.PRODUCT_MODEL))
        frozen_model = named or stop_rule.PRODUCT_MODEL
        running_model = stop_rule.queue_model()
        if running_model != frozen_model:
            sys.exit(
                "round {} froze model {!r} and this run would buy {!r}. "
                "Unset SECURITY_SCAN_MODEL, or re-freeze as a new experiment "
                "if the change is deliberate — a pass bought from a different "
                "model is not a repetition of the other one, and comparing "
                "them measures the models rather than the product."
                .format(args.round, frozen_model, running_model))
        for chosen, name in ((args.provider, "provider"),
                             (args.profile, "profile")):
            want = protocol.get(name)
            if want and chosen != want:
                sys.exit(
                    "round {} froze {} {!r} and this run asks for {!r}. A pass "
                    "run under different conditions is not a repetition of the "
                    "other one; re-freeze as a new experiment if the change is "
                    "deliberate.".format(args.round, name, want, chosen))

        # **And the cases themselves, before anything is bought.** Codex,
        # 2026-09-09: `round.compare` now refuses a row about a different
        # version of its case — correctly — but nothing stopped the queue
        # buying it first. Edit a member after the freeze and the case was
        # purchased normally, its row recorded the new digest, and `compare`
        # then reported it as "not yet run" and could exit 2 having measured
        # nothing. The money was spent on a row thrown away at the other end.
        #
        # A manifest from before `freeze` stored digests records none, and
        # such a case is not checked rather than refused — the same rule
        # `compare` applies, so the two ends agree about which rounds are
        # checkable at all.
        # **And the two lists have to be the same list.** Codex, 2026-09-09:
        # the manifest carries `protocol.order`, which decides what is bought,
        # and `cases`, which carries the digests and is what `compare` reads.
        # Nothing checked that they agree, so a case named in `order` and
        # absent from `cases` was bought without any digest check and then
        # ignored by `compare` — money spent on a row the comparison never
        # looks at, while the case it does look at is reported as never run.
        # A repeated id in `order` bought the same case twice for the same
        # reason: `queued` is computed once, before anything is written.
        #
        # `freeze` builds both from one list, so a genuine manifest passes.
        # This refuses a hand-edited one, and a future `freeze` that lets them
        # drift.
        named = [entry.get("case_id") for entry in (frozen.get("cases") or [])
                 if isinstance(entry, dict) and entry.get("case_id")]
        if sorted(order) != sorted(named) or len(set(order)) != len(order):
            sys.exit(
                "round {} has a manifest whose order and case list disagree: "
                "{} in the order, {} in the cases. What gets bought and what "
                "gets compared are then two different sets, and a case bought "
                "outside the case list is never checked against a frozen "
                "digest nor read by `round.py compare`. Re-freeze the round."
                .format(args.round, len(order), len(named)))

        changed = []
        for entry in frozen.get("cases") or []:
            if not isinstance(entry, dict) or not entry.get("case_id"):
                continue
            wanted = {d for d in (entry.get("case_digest"),
                                  entry.get("legacy_case_digest")) if d}
            frozen_key = entry.get("answer_key_digest")
            if not wanted and not frozen_key:
                # A manifest from before either field existed. Nothing to
                # check rather than nothing to refuse.
                continue
            directory = ROOT / "corpus-real" / entry["case_id"]
            if not directory.is_dir():
                changed.append("{}: the case is no longer in the corpus"
                               .format(entry["case_id"]))
                continue
            # **Asked even when the members carry no digest.** The first
            # version returned early on an empty `wanted`, so an entry with a
            # frozen key and no `case_digest` skipped this check entirely —
            # `compare` refused the round afterwards and the pairs had already
            # been bought. The two ends of one rule disagreeing, and this end
            # is the one that spends.
            if frozen_key and answer_key_digest(directory) != frozen_key:
                # The members are untouched and what a pass *means* is not.
                # Codex, 2026-09-09: `case_digest` covers the members only, so
                # editing the expectation alone was bought and then scored
                # against the new key, and the flip read as instability.
                changed.append("{}: its answer key changed since the freeze"
                               .format(entry["case_id"]))
                continue
            if not wanted:
                continue
            now = {case_digest(directory), legacy_case_digest(directory)}
            if not (now & wanted):
                changed.append("{}: frozen at {}, now {}".format(
                    entry["case_id"], sorted(wanted)[0],
                    case_digest(directory)))
        if changed:
            sys.exit(
                "round {} was frozen over cases that have changed since:\n  {}"
                "\nA pass bought over edited code answers a different question "
                "from the baseline it would be compared against, and "
                "`round.py compare` would throw those rows away — after they "
                "were paid for. Re-freeze as a new round if the change is "
                "deliberate.".format(args.round, "\n  ".join(changed)))

        # Refused here, not recommended here. The first version printed
        # "verify before spending" and then spent: every frozen condition
        # except the provider and the profile was a suggestion, and the whole
        # point of freezing them is that a pass run under changed conditions is
        # not a repetition of the other one.
        eligible = list(order)
    # **Each case once.** Codex, 2026-09-09: `--case` is `action="append"`, so
    # naming one twice put it in `eligible` twice — and `queued` is computed
    # here, once, before anything runs. The first run wrote a valid result and
    # the second entry was still in the list, so `already_run` was never asked
    # again: the identical pair was bought a second time and the first
    # artifact overwritten. The frozen-round manifest gained a duplicate check
    # two rounds earlier and this path, the ordinary one, did not.
    #
    # Order is preserved, because for a frozen round it is the experiment's
    # order and `dict.fromkeys` keeps first appearance.
    unique = list(dict.fromkeys(eligible))
    queued = [c for c in unique if not already_run(c, repeat)]
    # Reported, not applied. `cases()` drops these on a sweep and the count is
    # printed here so a saved window is visible rather than implicit — the
    # first version of this line filtered a second time and claimed a flag
    # could restore them, which `cases()` had already made impossible.
    ruled_out = 0 if args.case else len(malformed())
    print("{} case(s) queued, {} already recorded, {} ruled unable to measure "
          "anything and not swept".format(
              # **Against the deduplicated list.** Codex, 2026-09-09: the
              # difference was taken from `eligible`, so the duplicate the
              # line above removes was counted as a case "already recorded" —
              # a claim that a measurement exists, made about a repetition
              # that never was one. The whole point of this tool is not to say
              # that.
              len(queued), len(unique) - len(queued), ruled_out), flush=True)
    if args.dry_run or not queued:
        for case_id in queued:
            print("  " + case_id, flush=True)
        return 0

    mode = "attended" if args.pairs is not None else "unattended"
    # What the probe bought, if it bought anything. Its pair is a pair: it
    # consumed the window and it is on the bill, so it comes off `queued` and
    # counts towards `--pairs`. The first version left it out of both, so
    # `--pairs 1` bought two and the case was then bought a second time.
    probe_spent: List[str] = []
    if args.wait_for_reset:
        wait_for_fresh_window(args, queued, probe_spent)
        for case_id in probe_spent:
            if case_id in queued:
                queued.remove(case_id)
    done = len(probe_spent)
    window = datetime.now(timezone.utc).isoformat(timespec="seconds")
    waits = 0
    # How this window ended, written when it does. A window stopped early is
    # not a measurement of the limit — it says only that the limit was above
    # that number — and a window that ran to refusal is. Mixing the two is how
    # the last cluster fell apart, and doing it deliberately would be worse.
    # Nothing here computes anything from it; it exists so that a later
    # analysis can filter, and so a `stopped_early` window can never be
    # mistaken for evidence about where the limit falls.
    termination = "interrupted"

    # Refusals since the last pair that completed. Two of them mean the queue
    # woke after a reset, ran a pair, and was refused again — which is the
    # observation, not merely the alarm. Whether a reset restores an allowance
    # or only admits one more call is the open question the whole plan turns
    # on, and this is the only place it can be answered: the second refusal
    # *is* the answer, so the queue must run that pair before it stops.
    #
    # Hence the order below — sleep, run, and only then decide — rather than
    # stopping at the first sign of trouble and never finding out.
    since_progress = 0

    # How many cases in a row came back held. A full lap means every case
    # left belongs to another queue and this one has nothing to do.
    held_in_a_row = 0
    while queued:
        if args.pairs is not None and done >= args.pairs:
            termination = "stopped_early"
            print("\nstopped after {} pair(s), as asked. {} left. This is "
                  "room reserved for you to work in, not a quota decision — "
                  "a refusal costs twelve seconds and nothing else.".format(
                      done, len(queued)), flush=True)
            break
        case_id = queued[0]
        # The raw stamp, on every line. Today's "the limit counts loops" came
        # from three windows cut at gaps between batches — a boundary somebody
        # chose — and moving it turned 25·34·26 into 32·38·43. Every number in
        # this log carries its own time so the next analysis can cut where it
        # likes, and so a later disagreement is distinguishable from a real
        # change rather than from a different choice of edge.
        started_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
        started = time.monotonic()
        payload, kind, detail = run_one(case_id, args)
        elapsed = round(time.monotonic() - started, 1)

        if kind == "ruled-out":
            # Moved past, like `already`: nothing is wrong, nothing was
            # bought, and the case is not owed a run. Recorded so the reason
            # is visible rather than the case simply disappearing.
            note({"case_id": case_id, "window": window, "outcome": kind,
                  "started_at": started_at, "finished_at":
                      datetime.now(timezone.utc).isoformat(timespec="seconds"),
                  "detail": str(detail)[:200], "wall_seconds": elapsed})
            print("  {}: {}".format(case_id, detail), flush=True)
            held_in_a_row = 0
            queued.pop(0)
            continue

        if kind == "held":
            # **Deferred, not dropped.** Codex, 2026-09-09: popping it meant
            # this queue reported completion over a case nobody measured — the
            # lock owner may crash, be refused, or write nothing, and a frozen
            # round could finish "successfully" with a result missing. "Did
            # not check" reported as "checked", which is the whole of what
            # this project exists to catch, in the branch added to prevent a
            # double purchase.
            note({"case_id": case_id, "window": window, "outcome": kind,
                  "started_at": started_at, "finished_at":
                      datetime.now(timezone.utc).isoformat(timespec="seconds"),
                  "detail": str(detail)[:200], "wall_seconds": elapsed})
            print("  {}: {}".format(case_id, detail), flush=True)
            queued.append(queued.pop(0))
            held_in_a_row += 1
            if held_in_a_row >= len(queued):
                # A whole lap and every case is held. Waiting here would be a
                # spin, and finishing would be the lie above, so it stops and
                # says which cases nobody has a result for.
                print("\n{} case(s) are held by another queue and none could "
                      "be run: {}.\nNothing here says they were measured — "
                      "another queue has them, and this one has nothing left "
                      "to do.".format(len(queued), ", ".join(sorted(queued))),
                      flush=True)
                close_window(window, "held_elsewhere", done, len(queued), mode)
                return 5
            continue

        held_in_a_row = 0
        if kind == "already":
            # Not a result and not a failure: another queue has the case, or
            # finished it while this one was working through the list. Moved
            # past rather than stopped on — nothing is wrong, and nothing was
            # bought. Recorded so that a person reading the log later can see
            # a second queue was running, which is a thing this project has
            # been bitten by.
            note({"case_id": case_id, "window": window, "outcome": kind,
                  "started_at": started_at, "finished_at":
                      datetime.now(timezone.utc).isoformat(timespec="seconds"),
                  "detail": str(detail)[:200], "wall_seconds": elapsed})
            # Popped, because this one *is* a result: the case was measured
            # while this run was working through its list, and the row is on
            # disk. Only `held` is deferred — nobody has a result for that
            # one yet.
            print("  {}: {}".format(case_id, detail), flush=True)
            queued.pop(0)
            continue

        if kind in ("unknown", "no-artifact"):
            # Neither slept on nor moved past. The refusal is matched on a
            # sentence the provider can reword, so an ending this cannot name
            # might be a refusal in new words — and treating it as an ordinary
            # failure would work through the whole corpus being turned away.
            note({"case_id": case_id, "window": window, "outcome": kind,
                  "started_at": started_at, "finished_at":
                      datetime.now(timezone.utc).isoformat(timespec="seconds"),
                  "detail": str(detail)[:200], "wall_seconds": elapsed})
            # **And the pair itself, when there was one.** An `unknown` is a
            # *paid* pair: one member can complete and the other error out, so
            # the payload exists and is promoted. The refused and success
            # branches both write `kind: "review"` rows and this one did not,
            # so `spend.py --source queue` — which filters on exactly that
            # field — could not see it. A purchase off the bill.
            if payload:
                for entry in raw_rows(payload, started_at,
                                      datetime.now(timezone.utc)
                                      .isoformat(timespec="seconds")):
                    note(dict(entry, window=window, outcome=kind))
            # Both stop, for the same reason and not the same evidence.
            # `unknown` may be a refusal in new words. `no-artifact` may have
            # submitted work before dying, so advancing would launch another
            # pair while the account or the process path may still be unwell —
            # and nothing it left behind says how far it got. Carrying on is a
            # decision that needs evidence neither of them provides.
            # Which of the two, said exactly. `unknown` promoted a payload
            # and it is at the case's own path; `no-artifact` means nothing
            # was written and the attempt is gone, so telling the operator to
            # go and look at a file is telling them to look at nothing. The
            # first version said "the result file, if any" for both.
            where = ("the result is at {}, left for a person to look at "
                     "rather than resumed past".format(
                         result_path(case_id).relative_to(ROOT))
                     if kind == "unknown" else
                     "nothing was written, so there is no file to look at")
            print("\nstopped at {}: {}.\n  {}\n\n{} case(s) left. {}.".format(
                      case_id,
                      "the ending could not be classified" if kind == "unknown"
                      else "no session document was written",
                      str(detail)[:160], len(queued), where), flush=True)
            close_window(window, "interrupted", done, len(queued), mode)
            return 3

        if kind == "refused":
            # The raw rows too, not just the fact of the refusal. "A refusal
            # costs one re-run" was asserted before it was checked; it turned
            # out true — five refusals were turned away at the handshake, 12.5
            # seconds and no tokens — but it is a property of five attempts,
            # not a law. Written as a field, it re-measures itself every time,
            # and the day a refusal lands mid-loop the log will say so instead
            # of the plan continuing to claim otherwise.
            refused_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
            for entry in raw_rows(payload or [], started_at, refused_at):
                note(dict(entry, window=window, pair_outcome="refused"))
            note({"case_id": case_id, "window": window, "outcome": "refused",
                  "started_at": started_at, "finished_at": refused_at,
                  "detail": str(detail)[:200], "wall_seconds": elapsed})
            waits += 1
            since_progress += 1
            if since_progress >= 2:
                # Recorded as its own kind. This is the measurement, and a
                # later reader must be able to find it without inferring it
                # from two adjacent "refused" lines.
                note({"case_id": case_id, "window": window,
                      "outcome": "refused-after-reset",
                      "detail": str(detail)[:200],
                      "observation": "a pair run after the stated reset was "
                                     "refused; the reset did not restore an "
                                     "allowance this queue could use"})
                print("\nstopped: woke at the stated reset, ran one pair, and "
                      "was refused again. That is the observation this was "
                      "waiting for — the reset did not restore an allowance "
                      "this queue can use, so sleeping again would buy nothing "
                      "measurable. {} case(s) left.".format(len(queued)),
                      flush=True)
                close_window(window, "refused", done, len(queued), mode)
                return 4
            if waits > args.max_waits:
                print("refused {} times; stopping with {} case(s) left".format(
                    waits, len(queued)), flush=True)
                close_window(window, "refused", done, len(queued), mode)
                return 2
            now = datetime.now().astimezone()
            when = reset_at(str(detail), now)
            if when is None:
                when = now + BLIND_WAIT
                print("refused, and the message names no time this can read — "
                      "waiting {} minutes".format(int(BLIND_WAIT.total_seconds() // 60)),
                      flush=True)
            else:
                print("refused · {} · sleeping until {}".format(
                    str(detail).strip()[:80], when.strftime("%H:%M")), flush=True)
            # A minute past, because a reset at the stated minute is not a
            # promise about the second.
            sleep_until(when + timedelta(minutes=1))
            window = datetime.now(timezone.utc).isoformat(timespec="seconds")
            continue

        queued.pop(0)
        done += 1
        since_progress = 0
        if not payload:
            # No row came back. `pair_corpus` writes an empty list when every
            # case it was given is excluded by a ruling, and reading that as a
            # pair that failed to discriminate would put a case ruled
            # unmeasurable into the score as a miss.
            note({"case_id": case_id, "window": window, "outcome": "no-result",
                  "started_at": started_at, "wall_seconds": elapsed,
                  "detail": "the scorer returned no row for this case"})
            print("  {:<26} {:<10} {} left".format(
                case_id, "no-result", len(queued)), flush=True)
            continue
        row = payload[0]
        outcome = ("incomplete" if row.get("incomplete")
                   else "pass" if row.get("pair_success") else "fail")
        finished_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
        for entry in raw_rows(payload or [], started_at, finished_at):
            note(dict(entry, window=window, pair_outcome=outcome))
        print("  {:<26} {:<10} {} left".format(case_id, outcome, len(queued)),
              flush=True)

    if termination == "interrupted" and not queued:
        # The queue drained. Not a measurement either: the work ran out before
        # the limit did, which says nothing about where the limit is.
        termination = "work_exhausted"
    close_window(window, termination, done, len(queued), mode)
    print("\n{} case(s) run, {} reset(s) waited out. Raw fields per attempt in "
          "{}.".format(done, waits, LOG.relative_to(ROOT)), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
