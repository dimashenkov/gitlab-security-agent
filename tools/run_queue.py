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
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List, Optional

import yaml

ROOT = Path(__file__).resolve().parents[1]
QUEUE = ROOT / "measurements" / "queue"
LOG = QUEUE / "log.jsonl"

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
    return {r.get("case_id") for r in rows
            if isinstance(r, dict) and r.get("case_is_malformed")}


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

    `repeat` is for a round that means to run the corpus again: it consults
    only this round's own directory, so the round still resumes after a refusal
    while earlier results do not silence it. Without it `--round` would queue
    nothing at all, because every case is recorded from the first pass — the
    skip that makes the queue resumable is the same skip that makes it unable
    to repeat.
    """
    own = QUEUE / (case_id + ".json")
    if own.is_file():
        # The file existing is not the same as the case having been measured.
        # A pair whose review stopped early leaves a row saying so, and reading
        # its presence as "done" is this project's founding error — "did not
        # check" read as "checked" — inside the queue built to avoid it. It
        # cost `js-q4gh-4ffp-5cg8-snap` a silent skip: recorded, never run.
        try:
            rows = json.loads(own.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return False
        return any(isinstance(r, dict) and not r.get("incomplete")
                   for r in rows if isinstance(rows, list))
    if repeat:
        # Nothing outside this round counts. A previous answer is what the
        # round exists to compare against, so it must not prevent the run that
        # produces the second one.
        return False
    for path in (ROOT / "measurements").glob("*.json"):
        try:
            body = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        rows = body if isinstance(body, list) else body.get("results") or []
        for row in rows if isinstance(rows, list) else ():
            if isinstance(row, dict) and row.get("case_id") == case_id \
                    and not row.get("incomplete"):
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


def wait_for_fresh_window(args) -> None:
    """Start at the top of a window rather than in the tail of a spent one.

    One probe: ask for a case the queue is not going to run anyway. If the
    account is refusing, the message names the reset and this waits for it, so
    an unattended run launched at any hour begins with a full window instead of
    being turned away on its first real pair.

    A convenience, not a fix. Refusals cost twelve seconds either way; what
    this buys is that an overnight run does not spend its first hours asleep
    for a window that had minutes left in it.
    """
    probe = argparse.Namespace(**vars(args))
    probe.case, probe.language, probe.construction = [], None, None
    remaining = [c for c in cases(probe) if not already_run(c)]
    if not remaining:
        return
    _payload, kind, detail = run_one(remaining[0], args)
    if kind != "refused":
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


def run_one(case_id: str, args) -> tuple:
    """`(payload, kind, detail)`. The payload is kept unless it was refused."""
    target = QUEUE / (case_id + ".json")
    QUEUE.mkdir(parents=True, exist_ok=True)
    command = [sys.executable, "-u", str(ROOT / "tools" / "pair_corpus.py"),
               str(ROOT / "corpus-real"), "--provider", args.provider,
               "--profile", args.profile, "-c", "2",
               "--case", case_id, "--json", str(target)]
    proc = subprocess.run(command, cwd=ROOT, check=False)
    if not target.is_file():
        # Three, like every other return here. Two of them unpacked into a
        # three-name assignment and this line raised `ValueError` — on the one
        # path where `pair_corpus` wrote nothing at all, which is exactly the
        # path a broken CLI takes. `no-artifact` rather than `unknown`: what is
        # known is that no session document exists, and whether the call was
        # submitted before it died is not.
        return None, "no-artifact", "pair_corpus wrote no result file"
    payload = json.loads(target.read_text(encoding="utf-8"))
    kind, detail = classify(payload)
    if kind == "refused":
        # Not kept. A refused pair has measured nothing, and leaving the file
        # behind would make `already_run` skip it for ever.
        target.unlink()
    # The return code is deliberately not read. `pair_corpus` exits non-zero
    # when a pair fails to discriminate, which is a result and not an error;
    # what matters here is whether the row says the account was refused.
    del proc
    return payload, kind, detail


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
        for chosen, name in ((args.provider, "provider"),
                             (args.profile, "profile")):
            want = protocol.get(name)
            if want and chosen != want:
                sys.exit(
                    "round {} froze {} {!r} and this run asks for {!r}. A pass "
                    "run under different conditions is not a repetition of the "
                    "other one; re-freeze as a new experiment if the change is "
                    "deliberate.".format(args.round, name, want, chosen))

        # Refused here, not recommended here. The first version printed
        # "verify before spending" and then spent: every frozen condition
        # except the provider and the profile was a suggestion, and the whole
        # point of freezing them is that a pass run under changed conditions is
        # not a repetition of the other one.
        eligible = list(order)
    queued = [c for c in eligible if not already_run(c, repeat)]
    # Reported, not applied. `cases()` drops these on a sweep and the count is
    # printed here so a saved window is visible rather than implicit — the
    # first version of this line filtered a second time and claimed a flag
    # could restore them, which `cases()` had already made impossible.
    ruled_out = 0 if args.case else len(malformed())
    print("{} case(s) queued, {} already recorded, {} ruled unable to measure "
          "anything and not swept".format(
              len(queued), len(eligible) - len(queued), ruled_out), flush=True)
    if args.dry_run or not queued:
        for case_id in queued:
            print("  " + case_id, flush=True)
        return 0

    mode = "attended" if args.pairs is not None else "unattended"
    if args.wait_for_reset:
        wait_for_fresh_window(args)
    window = datetime.now(timezone.utc).isoformat(timespec="seconds")
    waits = 0
    done = 0
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

        if kind in ("unknown", "no-artifact"):
            # Neither slept on nor moved past. The refusal is matched on a
            # sentence the provider can reword, so an ending this cannot name
            # might be a refusal in new words — and treating it as an ordinary
            # failure would work through the whole corpus being turned away.
            note({"case_id": case_id, "window": window, "outcome": kind,
                  "started_at": started_at, "finished_at":
                      datetime.now(timezone.utc).isoformat(timespec="seconds"),
                  "detail": str(detail)[:200], "wall_seconds": elapsed})
            # Both stop, for the same reason and not the same evidence.
            # `unknown` may be a refusal in new words. `no-artifact` may have
            # submitted work before dying, so advancing would launch another
            # pair while the account or the process path may still be unwell —
            # and nothing it left behind says how far it got. Carrying on is a
            # decision that needs evidence neither of them provides.
            print("\nstopped at {}: {}.\n  {}\n\n{} case(s) left. The result "
                  "file, if any, is left in place for a person to look at "
                  "rather than resumed past.".format(
                      case_id,
                      "the ending could not be classified" if kind == "unknown"
                      else "no session document was written",
                      str(detail)[:160], len(queued)), flush=True)
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
