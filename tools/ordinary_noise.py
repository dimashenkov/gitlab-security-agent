#!/usr/bin/env python3
"""How often the reviewer alarms on a change with nothing to find.

    tools/ordinary_noise.py run --clones /tmp/ordinary-clones --out DIR
    tools/ordinary_noise.py score --results DIR

The one number the prototype was missing. Recall says the reviewer finds the
weakness in a vulnerable file; the corpus's other figure — 26% — is the alarm
rate on the *patched twin* of a vulnerable file, which is the hardest possible
negative and not a false-alarm rate on ordinary work. This measures the
ordinary case.

## What it may be called, and what it may not

**D-014, decided 2026-09-06 before any review was run**, because a rule chosen
after the outcome is not a rule. Grok ruled 3 of the sealed 30 `not_ordinary` —
they are security fixes, confirmed against the commit and the advisory — and an
alarm on one of those is *correct*. So the three are excluded and the number is
computed over the 27:

> the observed reviewer alarm rate on the 27 changes Grok classified as
> ordinary in the sealed pilot sample

It is **not** a false-alarm rate, not a figure over all thirty, not an estimate
for the 1361-change frame, not human-audited, and not completion of any D-013
step. The 27 carry one unaudited third-party-model adjudication, so further
security fixes may remain among them and an alarm inside the 27 cannot
confidently be called false either.

## Two alarms, reported apart

| | |
|---|---|
| **blocked** | `verdict.blocked` — the gate would have stopped the merge |
| **reported** | at least one finding, whether or not it blocked |

Never merged into one figure. Blocking is what makes somebody turn the tool
off; a non-blocking finding is something a person still has to read. A single
number would hide which of the two was happening.

## Incomplete is not clean

A review that did not finish is an **unknown outcome inside** the denominator,
not a case dropped out of it. The denominator is always the whole admitted
sample, and every unknown is counted first as quiet and then as an alarm — so
the figure is a range with the truth inside. Dividing by the reviews that
worked would print a rate over a smaller sample under a name that says 27, and
if the missing one would have alarmed, that rate is better than the truth.

Its empty finding list is an absence of evidence, and this repository has
already paid for confusing the two: three of four failures in an early run had
exit code 2 and were scored as "found nothing".
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from pair_corpus import cost_of, review  # noqa: E402

SEAL = ROOT / "measurements" / "ordinary-v1" / "sample-30.seal.json"
ADJUDICATION = ROOT / "measurements" / "ordinary-v1" / "grok-adjudication.json"

# Why this spending is authorised: D-014, which is a decision about this
# measurement and not a step of D-013's ordering. The broker knows the name.
SPEND_CLASS = "ordinary_noise"

# The one verdict D-014 admits into the denominator. Anything else is refused
# by name rather than filtered quietly — a case dropped in silence is how a
# denominator shrinks toward whatever makes the number look better.
ADMITTED = "ordinary"

# The whole enum the adjudication may use, and the split D-014 was written
# against. Both are asserted rather than assumed: a value outside the enum, or
# a sample that has since changed shape, is a different sample from the one the
# decision governs — and D-014 exists to stop the denominator being chosen
# after the fact.
VERDICTS = frozenset({"ordinary", "not_ordinary", "unclear"})
SPLIT = (27, 3)

# **The same configuration the 78% and the 26% were measured with**, read off
# the corpus artifacts rather than chosen here: `provider: claude-cli`, and no
# profile, which is what those runs recorded. A noise figure measured under a
# different configuration is a number about a different system, and putting it
# beside the recall figure would invite exactly the comparison it cannot bear.
#
# `claude-cli` is also the only permitted path: the owner decided on
# 2026-08-30 that an API key is never used, and `review()` refuses to default a
# provider precisely so a corpus run cannot silently take the billed one. The
# first attempt here passed none and died on "no Anthropic credentials found"
# in 0.6 seconds, which is the refusal working.
PROVIDER = "claude-cli"
PROFILE = ""

# The reviewer this measurement is about, named so `--resume` can refuse rows
# that were not made by it. Not passed to `review()` — the model comes from the
# environment, as it does for every other measurement here — so this is what
# the rows are *checked against*, and a run whose environment says otherwise
# will be caught by the resume check on the next invocation rather than
# silently mixed in.
MODEL = "claude-opus-5"


class Refused(Exception):
    """The inputs cannot answer the question."""


def sample() -> List[Dict[str, Any]]:
    """The 27, with the excluded three named.

    Both files are required. Reading the seal alone would give thirty cases
    and no way to tell which three D-014 excludes; reading the adjudication
    alone would give verdicts with no sealed draw behind them.
    """
    try:
        seal = json.loads(SEAL.read_text(encoding="utf-8"))
        adj = json.loads(ADJUDICATION.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise Refused("{}: {}".format(type(exc).__name__, exc)) from exc

    verdicts = {}
    for case_id, attempt in (adj.get("cases") or {}).items():
        if not isinstance(attempt, dict):
            raise Refused("{}: the adjudication holds {} for this case".format(
                case_id, type(attempt).__name__))
        verdicts[case_id] = attempt.get("verdict")

    selected = seal.get("selected")
    if not isinstance(selected, list) or not selected:
        raise Refused("the seal records no `selected` list")

    admitted, excluded, unjudged, unknown = [], [], [], []
    for entry in selected:
        case_id = entry.get("case_id")
        verdict = verdicts.get(case_id)
        # Absent **and** null, and an unknown string too. Codex, 2026-09-06:
        # the first version checked only whether the key was there, so a
        # `verdict: null` and a verdict nobody has heard of both fell quietly
        # into the excluded pile — an open-ended rule under which a malformed
        # value shrinks the denominator. D-014 authorises one enum and no
        # other, and a value outside it is a refusal rather than an exclusion.
        if case_id not in verdicts or verdict is None:
            unjudged.append(case_id)
        elif verdict not in VERDICTS:
            unknown.append((case_id, verdict))
        elif verdict == ADMITTED:
            admitted.append(dict(entry, verdict=verdict))
        else:
            excluded.append((case_id, verdict))

    if unjudged:
        # Not skipped. A sealed case with no verdict is a hole in the sample,
        # and deciding what to do with it after the fact is the thing D-014
        # exists to prevent.
        raise Refused(
            "{} sealed case(s) carry no verdict: {}. The denominator cannot "
            "be chosen now".format(len(unjudged), ", ".join(sorted(
                str(c) for c in unjudged))))
    if unknown:
        raise Refused(
            "{} sealed case(s) carry a verdict outside {}: {}".format(
                len(unknown), " | ".join(sorted(VERDICTS)),
                ", ".join("{}={!r}".format(c, v) for c, v in sorted(unknown))))
    if not admitted:
        raise Refused("no case carries the verdict {!r}".format(ADMITTED))

    # The split D-014 was written against, asserted rather than assumed. A
    # sample that has since changed shape is a different sample, and the
    # decision names this one.
    if (len(admitted), len(excluded)) != SPLIT:
        raise Refused(
            "D-014 governs a sample of {} admitted and {} excluded, and this "
            "one holds {} and {}. A sample that changed shape is a different "
            "sample".format(SPLIT[0], SPLIT[1], len(admitted), len(excluded)))
    return admitted, excluded


def repo_for(clones: Path, entry: Dict[str, Any]) -> Path:
    """The clone this case's commit lives in, verified rather than assumed."""
    name = str(entry.get("repo", "")).split("/")[-1]
    path = clones / name
    if not path.is_dir():
        raise Refused("{}: no clone at {}".format(entry.get("case_id"), path))
    commit = str(entry.get("commit", ""))
    probe = subprocess.run(
        ["git", "-C", str(path), "cat-file", "-e", commit + "^{commit}"],
        capture_output=True, check=False)
    if probe.returncode:
        raise Refused("{}: {} does not hold commit {}".format(
            entry.get("case_id"), path, commit[:12]))
    parents = subprocess.run(
        ["git", "-C", str(path), "rev-list", "--parents", "-n", "1", commit],
        capture_output=True, text=True, check=False)
    if parents.returncode or len(parents.stdout.split()) < 2:
        # A root commit has no parent and no diff to review. Named rather than
        # reviewed against the empty tree, which would be a different question.
        raise Refused("{}: {} has no parent, so there is no change to review"
                      .format(entry.get("case_id"), commit[:12]))
    return path


def one(entry: Dict[str, Any], clones: Path) -> Dict[str, Any]:
    repo = repo_for(clones, entry)
    commit = str(entry["commit"])
    work = Path(tempfile.mkdtemp(prefix="ordinary-noise-")).resolve()
    try:
        result = review(repo, commit + "^", commit, work / "out",
                        provider=PROVIDER, profile=PROFILE,
                        spend_class=SPEND_CLASS)
        row: Dict[str, Any] = {
            # `.get` for everything the seal supplies but this function does
            # not need: a row missing an optional field must not turn a paid
            # review into a `KeyError` after the model has already answered.
            "case_id": entry["case_id"], "repo": entry.get("repo"),
            "commit": commit, "language": entry.get("language"),
            "stratum": entry.get("stratum"), "seconds": result.get("seconds"),
        }
        if not result.get("ok"):
            row["complete"] = False
            row["error"] = result.get("error", "review failed")
            return row
        body = result["payload"]
        verdict = body.get("verdict") or {}
        # `is True`, not truthiness: a missing `complete` must not read as a
        # finished review, and a missing `blocked` must not read as a quiet one.
        row["complete"] = body.get("complete") is True
        # The raw value, not coerced. Codex, 2026-09-06: `is True` turned a
        # missing or malformed `blocked` into a clean non-block and the scorer
        # then counted it in the blocking denominator — the comment above said
        # the opposite of what the line did. The scorer decides what an
        # unreadable one means; this records what was there.
        row["blocked"] = verdict.get("blocked")
        row["exit_code"] = verdict.get("exit_code")
        findings = body.get("findings")
        row["findings"] = len(findings) if isinstance(findings, list) else None
        row["cost_usd"] = cost_of(body.get("usage") or {})
        row["provenance"] = body.get("provenance") or {}
        return row
    finally:
        shutil.rmtree(work, ignore_errors=True)


def check_configuration(rows: List[Dict[str, Any]], where: str) -> None:
    """Every completed row was produced by the configuration this run names.

    **Kept rows and new rows alike.** Codex, 2026-09-06, three rounds running:
    first the check compared the kept rows only with each other, so rows
    uniformly on another model passed; then it discarded a missing field, so a
    row carrying one of the two passed; then it was applied to the resumed
    rows and not to the ones this process had just produced, so a fresh run
    could carry any provenance at all and still exit as the measurement.

    Both fields are required. A row that cannot say what produced it puts an
    unattributable review inside a figure about one configuration.
    """
    done = [r for r in rows if r.get("complete") is True]
    if not done:
        return
    for name, field, expected in (
            ("reviewer model", "model_requested", MODEL),
            ("provider", "provider", PROVIDER)):
        missing = [r["case_id"] for r in done
                   if not (r.get("provenance") or {}).get(field)]
        if missing:
            raise Refused(
                "{} {} row(s) record no {} ({}), so nothing says which "
                "configuration produced them".format(
                    len(missing), where, name, ", ".join(sorted(missing)[:3])))
        seen = {r["provenance"][field] for r in done}
        if seen != {expected}:
            raise Refused(
                "the {} rows record {} {} and this run uses {!r}. Mixing "
                "configurations makes two measurements into one".format(
                    where, name, ", ".join(sorted(map(repr, seen))), expected))

    # **Requested is not served.** Codex, 2026-09-06: the check compared
    # `model_requested` only, so a row could ask for Opus, record
    # `model_substituted: true`, be answered by something else, and still print
    # the official measurement. This is the same lesson that retired the
    # sentinel baseline — a run answered by another model did not measure the
    # model it names — and the fix there was to read what *served* it.
    substituted = [r["case_id"] for r in done
                   if (r["provenance"]).get("model_substituted") is not False]
    if substituted:
        raise Refused(
            "{} {} row(s) do not record `model_substituted: false` ({}), so "
            "nothing says the provider answered with the model that was "
            "asked for".format(len(substituted), where,
                               ", ".join(sorted(substituted)[:3])))
    # A **list**, checked before it is walked. Codex, 2026-09-06: a mapping
    # like `{"claude-opus-5": false}` iterates over its keys and normalised to
    # exactly the expected tuple, so a malformed value passed as the right
    # answer. This repository has found the same class a dozen times today —
    # a container read for its contents before anything asked what it is.
    shapes = [r["case_id"] for r in done
              if not isinstance((r["provenance"]).get("models_served"), list)]
    if shapes:
        raise Refused(
            "{} {} row(s) record something other than a list for "
            "`models_served` ({}), so nothing says what answered them".format(
                len(shapes), where, ", ".join(sorted(shapes)[:3])))
    served = {tuple(sorted(r["provenance"]["models_served"])) for r in done}
    if served != {(MODEL,)}:
        raise Refused(
            "the {} rows were served by {} and this measurement is about "
            "{!r} alone".format(
                where,
                "; ".join(sorted(str(list(s)) for s in served)) or "nothing",
                MODEL))


def cmd_run(args: argparse.Namespace) -> int:
    admitted, excluded = sample()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    clones = Path(args.clones)

    # Every clone checked before the first review, so a missing one costs
    # nothing rather than surfacing after twenty runs.
    for entry in admitted:
        repo_for(clones, entry)

    # **Work already done is not thrown away.** A run of twenty-seven takes
    # most of an hour and this one was stopped at ten; starting over would
    # spend the subscription's capacity again on reviews that already happened,
    # and this repository's own rule is that what is paid for is paid for.
    #
    # Only *completed* rows are kept. An unfinished one is not a result, and
    # carrying it forward would freeze a failure into the record where a rerun
    # might have got an answer.
    kept: List[Dict[str, Any]] = []
    if args.resume:
        try:
            previous = json.loads(
                (out / "rows.json").read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise Refused(
                "--resume was asked for and {} could not be read: {}".format(
                    out / "rows.json", exc)) from exc
        wanted = {e["case_id"] for e in admitted}
        kept = [r for r in previous
                if isinstance(r, dict) and r.get("complete") is True
                and r.get("case_id") in wanted]
        # The configuration each kept row ran under, against **the one this run
        # will use** — not merely against each other. Codex, 2026-09-06: the
        # first version compared the kept rows among themselves, so twenty-seven
        # rows all made by Sonnet agreed perfectly and the new ones would then
        # be made by the Opus this file hard-codes: one mixed measurement, with
        # nothing in the artifact saying so. And `str(...)` before subtracting
        # `{None}` meant a missing model was compared as the string `"None"`
        # and never removed, so the absence never showed.
        # **Required, and compared against what this run will do.** Codex,
        # 2026-09-06, twice: the reviewer field was compared only with itself,
        # so rows uniformly marked with another model were accepted while the
        # new ones used the model this file hard-codes; and discarding a
        # missing value meant a row carrying only `provider` passed the
        # comparison and the empty-provenance check, because that check
        # rejected only a wholly empty mapping.
        check_configuration(kept, "kept")
        print("resuming: {} completed row(s) kept from {}".format(
            len(kept), out / "rows.json"))

    done_ids = {r["case_id"] for r in kept}
    order = [e for e in admitted if e["case_id"] not in done_ids]
    if args.limit:
        order = order[:args.limit]
    print("{} case(s) admitted, {} excluded by D-014, running {}".format(
        len(admitted), len(excluded), len(order)))
    rows = list(kept)
    for index, entry in enumerate(order, start=1):
        row = one(entry, clones)
        rows.append(row)
        print("  {:>2}/{}  {:<24} {}".format(
            index, len(order), row["case_id"],
            "did not complete" if not row.get("complete")
            else "BLOCKED" if row.get("blocked")
            else "{} finding(s)".format(row.get("findings"))))
        # Checked before it is written, so a run under the wrong configuration
        # stops at the first case rather than after twenty-seven.
        check_configuration([row], "new")
        # Written after every case, not at the end: a crash on case 20 must
        # not throw away the nineteen reviews already paid for in capacity.
        (out / "rows.json").write_text(
            json.dumps(rows, indent=2, sort_keys=True) + "\n",
            encoding="utf-8")

    record = {
        "schema": "ordinary-noise/1",
        "decision": "D-014",
        "estimand": ("the observed reviewer alarm rate on the changes Grok "
                     "classified as ordinary in the sealed pilot sample"),
        "not_a": ["a false-alarm rate", "a figure over all thirty",
                  "an estimate for the 1361-change frame",
                  "human-audited", "completion of any D-013 step"],
        # `len(rows)`, not `len(order)`. `ran` means how many cases this record
        # covers, and with `--resume` the newly-run ones are only part of that
        # — the first version wrote 17 into a record holding 27, the scorer
        # refused it as a prefix, and it was right to: the two numbers
        # disagreed and one of them was wrong.
        "admitted": len(admitted), "ran": len(rows),
        "newly_run": len(order), "resumed": len(kept),
        # The ids, not only the count. Codex, 2026-09-06: reconciling the
        # number of rows against the number of cases let twenty-seven copies of
        # one quiet case pass as a whole run, and let cases outside the sample
        # stand in for cases inside it. A count is not an identity.
        "admitted_case_ids": sorted(e["case_id"] for e in admitted),
        "excluded": [{"case_id": c, "verdict": v} for c, v in excluded],
        "finished_at": datetime.now(timezone.utc).isoformat(),
        "rows": rows,
    }
    (out / "ordinary-noise.json").write_text(
        json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("\nwritten to {}".format(out / "ordinary-noise.json"))
    return score(record, [e["case_id"] for e in admitted])


def is_count(value: Any) -> bool:
    """A whole number of findings, and `False` is not one.

    Codex, 2026-09-06: `isinstance(value, int)` accepts booleans, because
    `bool` subclasses `int` — so `"findings": false` entered the reporting
    denominator as a review that found nothing, which is the optimistic
    direction. A negative count is not one either.
    """
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def wilson(hits: int, total: int) -> tuple:
    """A 95% interval, because a proportion over 27 is not a point."""
    if not total:
        return (0.0, 1.0)
    z = 1.96
    p = hits / total
    d = 1 + z * z / total
    centre = (p + z * z / (2 * total)) / d
    half = z * ((p * (1 - p) / total + z * z / (4 * total * total)) ** 0.5) / d
    return (max(0.0, centre - half), min(1.0, centre + half))


def score(record: Dict[str, Any], admitted_ids: Optional[List[str]]) -> int:
    """Report the figure, with the denominator supplied by the caller.

    `admitted_ids` comes from the seal, through the caller that read it — the
    scorer does not fetch it. Codex, 2026-09-06: taking the ids off the record
    let a file define its own denominator, swapping an admitted case for a
    quieter one outside the sample and updating its own list to match, so every
    check agreed with every other. A file cannot be its own authority about
    which sample it is about.

    `None` means the caller could not establish them, and that is `partial` —
    an unverifiable denominator is not a verified one.
    """
    rows = record.get("rows") or []
    done = [r for r in rows if r.get("complete") is True]
    broken = [r for r in rows if r.get("complete") is not True]

    # **A denominator each.** Codex, 2026-09-06: both figures divided by every
    # completed row, so a row whose finding count could not be read counted as
    # one that reported nothing — the optimistic direction, and it narrowed the
    # interval as well. A row is in a figure's denominator only when its own
    # field could be read.
    can_block = [r for r in done if isinstance(r.get("blocked"), bool)]
    blocked = [r for r in can_block if r["blocked"] is True]
    unreadable_block = [r for r in done
                        if not isinstance(r.get("blocked"), bool)]

    can_report = [r for r in done if is_count(r.get("findings"))]
    reported = [r for r in can_report if r["findings"] > 0]
    unreadable = [r for r in done if not is_count(r.get("findings"))]

    print("\n{}".format(record["estimand"]))
    print("-" * 70)

    # A run that did not cover the whole admitted sample is not the
    # measurement, whatever its rows say. Codex, 2026-09-06: `--limit` produced
    # an artifact carrying the full estimand and exiting 0, so a favourable
    # prefix of one case could be mistaken for the answer.
    ran, admitted = record.get("ran"), record.get("admitted")
    # Reconciled against the rows, not taken on the record's word. Codex,
    # 2026-09-06: an artifact declaring `ran=27, admitted=27` while holding one
    # row printed `0 of 1` under the full estimand and exited 0 — the counts
    # were metadata about the run and the rows are the run. Malformed or
    # missing counts are `partial` too, because a record that cannot say how
    # much it covered has not said it covered everything.
    counts_agree = (is_count(ran) and is_count(admitted)
                    and len(rows) == ran == admitted)

    # And the identities, not only the count. Codex, 2026-09-06: twenty-seven
    # copies of one quiet case reconciled perfectly, and so did twenty-seven
    # cases from outside the sample. Exactly one row for every admitted id.
    #
    # **The ids come from the seal, not from the record.** Codex the same day,
    # one round later: taking `admitted_case_ids` on the record's word let it
    # define its own denominator — swap an admitted case for a quieter one
    # outside the sample, update the list to match, and every check agreed with
    # every other. A file cannot be its own authority about which sample it is
    # about. When the seal cannot be read the answer is `partial`, because an
    # unverifiable denominator is not a verified one.
    wanted = sorted(admitted_ids) if admitted_ids else None
    seen = [r.get("case_id") for r in rows]
    identities_agree = (
        isinstance(wanted, list) and bool(wanted)
        and len(seen) == len(set(seen))
        and sorted(seen) == sorted(wanted))

    partial = not (counts_agree and identities_agree)
    if partial:
        print("\n  PARTIAL: the record says {} of {} admitted case(s) and "
              "holds {} row(s).\n  This is not the measurement the name above "
              "describes — a prefix of the\n  sample is a different sample, "
              "and a favourable one is the easiest to\n  stop at."
              .format(ran, admitted, len(rows)))
        if not identities_agree:
            extra = sorted(set(seen) - set(wanted or ()))
            absent = sorted(set(wanted or ()) - set(seen))
            repeats = sorted({c for c in seen if seen.count(c) > 1})
            print("  The rows are not one per admitted case: {}".format(
                "; ".join(filter(None, [
                    "{} repeated".format(", ".join(repeats[:3]))
                    if repeats else "",
                    "{} not in the sample".format(", ".join(extra[:3]))
                    if extra else "",
                    "{} missing".format(", ".join(absent[:3]))
                    if absent else "",
                    "" if wanted else
                    "the sealed sample could not be read, so no denominator "
                    "is verified"]))))


    if not done:
        print("\n  No review completed. That is not an alarm rate of zero.")
        return 2

    # **No figure at all when the sample is not the sample.** Codex,
    # 2026-09-06, the last of six rounds on this function: the rates were
    # printed first and the PARTIAL line came after, so a missing noisy case
    # produced a visibly better "0 of 26" and only then the warning. A number
    # somebody has read is not unread because a line beneath it says not to
    # trust it.
    if partial:
        print("\n  No figure is printed. A rate over a sample that is not the "
              "sample\n  reads as the answer whatever is written under it.")
        return 2

    # **The denominator is the whole admitted sample, always**, and a case
    # nobody could read is shown as a range rather than dropped. Codex,
    # 2026-09-06: dividing by the completed rows printed a rate over 26 under a
    # name that says 27, and if the missing one would have alarmed the figure
    # came out better than the truth. His remedy was to print nothing at all;
    # that would let one failed review leave the whole measurement with no
    # answer, so the number is bounded instead — every unknown counted first as
    # quiet and then as an alarm, and the truth is inside.
    total = len(wanted)
    for name, hits, pool in (("blocked the change", blocked, can_block),
                             ("reported at least one finding", reported,
                              can_report)):
        unknown = total - len(pool)
        low_n, high_n = len(hits), len(hits) + unknown
        if not pool:
            print("  {:<32} no row recorded a readable value; the rate is "
                  "anywhere in 0–100%".format(name))
            continue
        if unknown:
            lo_a, _ = wilson(low_n, total)
            _, hi_b = wilson(high_n, total)
            print("  {:<32} {:>2}–{} of {:<3} {:>4.0f}–{:.0f}%   95% CI "
                  "{:.0f}–{:.0f}%".format(
                      name, low_n, high_n, total,
                      100 * low_n / total, 100 * high_n / total,
                      100 * lo_a, 100 * hi_b))
        else:
            low, high = wilson(len(hits), total)
            print("  {:<32} {:>2} of {:<3} {:>5.0f}%   95% CI "
                  "{:.0f}–{:.0f}%".format(
                      name, len(hits), total, 100 * len(hits) / total,
                      100 * low, 100 * high))
    if len(can_block) < total or len(can_report) < total:
        print("\n  A range, not a point: the cases nobody could read are "
              "counted first as\n  quiet and then as alarms, so the truth is "
              "inside. Dividing by the rows\n  that worked would print a rate "
              "over a smaller sample under a name that\n  says {}."
              .format(total))

    print("\n  The two are reported apart and never added: blocking is what "
          "makes\n  somebody turn the tool off, and a finding that does not "
          "block is still\n  something a person has to read.")

    if broken:
        print("\n  {} review(s) did not complete. They are inside the "
              "denominator and\n  outside the count, which is what the range "
              "above is: {}".format(
                  len(broken), ", ".join(sorted(r["case_id"] for r in broken))))
        print("  An unfinished review found nothing because it stopped, not "
              "because there\n  was nothing there.")
    if unreadable:
        print("\n  {} completed review(s) recorded no readable finding "
              "count. Unknown\n  outcomes inside the second range, not "
              "excluded from it.".format(len(unreadable)))
    if unreadable_block:
        print("\n  {} completed review(s) recorded no readable `blocked` "
              "verdict. Unknown\n  outcomes inside the first range, not "
              "excluded from it.".format(len(unreadable_block)))

    if record.get("excluded"):
        print("\n  {} case(s) excluded by D-014 before the run, because an "
              "alarm on them\n  would be correct: {}".format(
                  len(record["excluded"]),
                  ", ".join(sorted(e["case_id"]
                                   for e in record["excluded"]))))
    print("\n  Not " + "; not ".join(record["not_a"]) + ".")

    costs = [r.get("cost_usd") for r in done
             if isinstance(r.get("cost_usd"), (int, float))]
    if costs:
        print("\n  {} run(s) reported a notional cost totalling ${:.2f} — API "
              "list price\n  on a subscription, charged to nobody. "
              "`tools/spend.py` is the answer to\n  what this cost."
              .format(len(costs), sum(costs)))
    # 2 whenever anything is missing from a denominator, or the run did not
    # cover the admitted sample. The figure is then a statement about fewer
    # cases than the sample holds, and exit 0 is for the one that is not.
    return 2 if (broken or unreadable or unreadable_block or partial) else 0


def cmd_score(args: argparse.Namespace) -> int:
    path = Path(args.results)
    if path.is_dir():
        path = path / "ordinary-noise.json"
    try:
        record = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        print("{} could not be read: {}".format(path, exc), file=sys.stderr)
        return 2
    # The seal, read here rather than trusted from the record. If it cannot be
    # read the scorer is told so and reports `partial` — it does not fall back
    # to whatever the file claims about itself.
    try:
        admitted_ids = [e["case_id"] for e in sample()[0]]
    except Refused as exc:
        print("the sealed sample could not be read: {}".format(exc),
              file=sys.stderr)
        admitted_ids = None

    # The same validator the runner uses. Codex, 2026-09-06, the fourth round
    # on this: the checks protected only artifacts made by the current
    # invocation, so a saved file whose rows carried another model — or none —
    # printed the official measurement and exited 0 through this path.
    try:
        check_configuration(record.get("rows") or [], "recorded")
    except Refused as exc:
        print("Refusing: {}".format(exc), file=sys.stderr)
        return 2
    return score(record, admitted_ids)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)

    r = sub.add_parser("run", help="review every admitted case")
    r.add_argument("--clones", required=True)
    r.add_argument("--out", required=True)
    r.add_argument("--resume", action="store_true",
                   help="keep the completed rows already in the output "
                        "directory and run only what is missing. What is "
                        "spent is spent; an unfinished row is not kept, "
                        "because it is not a result")
    r.add_argument("--limit", type=int, default=0,
                   help="stop after N cases; the report then covers N and "
                        "says so")
    r.set_defaults(fn=cmd_run)

    s = sub.add_parser("score", help="report from a finished run")
    s.add_argument("--results", required=True)
    s.set_defaults(fn=cmd_score)

    args = parser.parse_args(argv)
    try:
        return args.fn(args)
    except Refused as exc:
        print("Refusing: {}".format(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
