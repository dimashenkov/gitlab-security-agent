#!/usr/bin/env python3
"""Apply `D-013` to the artifacts on disk: does this configuration stop?

    tools/stop_rule.py            # the two rates and the verdict
    tools/stop_rule.py --rows     # every case that contributes, and how

## Why this exists

`D-013` names two thresholds — recall below 65%, or an alert on the patched
member above 40% — and the numbers it was written against came out of a
throwaway script. A stop rule whose numbers nobody can recompute is not a stop
rule; it is a sentence. This is the rule as code, so the same question asked in
three months gets the same answer from the same files.

## What it deliberately does not do

**It cannot say "pass".** There is no such branch, because 78 pairs cannot
carry one — see `D-013`. The verdict is `stop` or `no catastrophe`, and the
second is not an endorsement. Anyone quoting this as evidence of acceptance is
quoting something it does not contain.

**It does not compute precision.** The corpus is a 50/50 mixture of vulnerable
and patched members, and a precision drawn from that balance is not a statement
about what a reader in a pipeline experiences. `D-013` withdrew that number for
exactly this reason and this tool will not print it.
"""

from __future__ import annotations

import argparse
import glob
import json
import math
import sys
from pathlib import Path
from typing import Dict, Optional, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent))

from artifact import (
    independence,
    instant,
    load_adjudications,
    malformed_cases,
)

ROOT = Path(__file__).resolve().parents[1]

# From `D-013`. Constants, not literals buried in a branch: the rule is
# supposed to be readable without following the code that applies it.
RECALL_FLOOR = 0.65
PATCHED_ALERT_CEILING = 0.40


def wilson(hits: int, total: int, z: float = 1.96) -> Tuple[float, float]:
    """A confidence interval that behaves at the edges.

    Wilson rather than the textbook normal approximation, which gives an
    interval running past 100% — or a width of zero — exactly where a small
    corpus lands most often. With 78 cases that is not an academic point.
    """
    if not total:
        return (0.0, 0.0)
    p = hits / total
    denominator = 1 + z * z / total
    centre = (p + z * z / (2 * total)) / denominator
    spread = z * math.sqrt(p * (1 - p) / total + z * z / (4 * total * total))
    spread /= denominator
    return (max(0.0, centre - spread), min(1.0, centre + spread))


PRODUCT_MODEL = "claude-opus-5"

# What the provider serves *beside* the model that was asked for. Not a policy
# and not a guess: every one of the 97 member records on disk flagged
# `model_substituted` records `{"claude-haiku-4-5-20251001", "claude-opus-5"}`
# as having reviewed it, and they are genuine paid Opus measurements. Nothing
# else has ever appeared in that position.
#
# **By family, not by the dated identifier.** The first version held
# `claude-haiku-4-5-20251001` exactly, while `config.py` spells the same model
# `claude-haiku-4-5` — so the configured alias, or the next dated revision of
# the same helper, would have made `latest_rows` and
# `sentinel.recorded_outcomes` discard paid Opus rows and quietly fall back to
# older ones. Codex, 2026-09-09: a transient response identifier written down
# as permanent provenance policy.
#
# A name outside the families still refuses the row rather than being waved
# through, and that remains the direction to be wrong in. What it costs is
# recorded in `LIMITATIONS.md`: the refusal is silent, so a genuinely new
# helper family shows up as headline numbers falling back to older rows with
# nothing saying why.
PROVIDER_HELPER_FAMILIES = ("claude-haiku-",)

# Why rows were skipped on the last pass, and how many for each reason. Filled
# by `latest_rows` and by `sentinel.recorded_outcomes`, cleared at the start of
# each; read by both command lines so a skipped row is visible rather than
# merely absent.
#
# A refusal nobody can see is a refusal nobody will diagnose: both readers fell
# back to an older measurement and the failure looked like headline numbers
# quietly moving. Recorded in `LIMITATIONS.md` on 2026-09-09 and built the
# same day.
SKIPPED: Dict[str, int] = {}


def skipped_line() -> str:
    """One line naming what the last pass did not read, or empty if it read
    everything. Empty means nothing was skipped — not that nobody looked."""
    if not SKIPPED:
        return ""
    return "{} row(s) did not answer for {}: {}".format(
        sum(SKIPPED.values()), PRODUCT_MODEL,
        "; ".join("{} {}".format(n, why)
                  for why, n in sorted(SKIPPED.items(),
                                       key=lambda kv: (-kv[1], kv[0]))))


def _is_helper(name: str) -> bool:
    """A name in a helper family, followed by a version and nothing else.

    A bare prefix test accepted `claude-haiku-`, `claude-haiku-sonnet-5` and
    `claude-haiku-not-a-model` — Codex, 2026-09-09 — so a forged row could put
    any string it liked behind the prefix and be read as a paid Opus
    measurement, in the predicate whose comment says unknown responders are
    refused.

    The remainder has to start with a digit, which is what every real name in
    this family does: `claude-haiku-4-5`, `claude-haiku-4-5-20251001`. That is
    narrow, and narrow is the direction to be wrong in here — a family whose
    naming changes refuses rows visibly rather than admitting a stranger
    quietly.
    """
    for prefix in PROVIDER_HELPER_FAMILIES:
        if name.startswith(prefix):
            rest = name[len(prefix):]
            if rest and rest[0].isdigit():
                return True
    return False


def reviewing_models(row: dict) -> set:
    """Every model a member of this row asked to review with."""
    asked = set()
    for block in (row.get("members") or {}).values():
        name = ((block or {}).get("provenance") or {}).get("model_requested")
        if name:
            asked.add(name)
    return asked


def _names(value) -> Optional[list]:
    """`value` as a list of model names, or `None` if it is not one.

    Codex, 2026-09-09: `set(prov.get("models_verified") or ())` ran before
    anything had looked at the contents, so a row recording
    `"models_verified": [{}]` raised `TypeError` on an unhashable member and
    took down `latest_rows` and `sentinel.recorded_outcomes` both — a malformed
    artifact crashing every reader that globs the measurements directory.

    "I could not read it" is not "it agrees" and it is not a crash either. The
    row is refused.
    """
    # **`None` is refused, and absence is handled by the caller.** Codex,
    # 2026-09-09: mapping `None` to `[]` here made an absent field and an
    # explicit `"models_verified": null` the same answer, because `.get()`
    # returns `None` for both. One is a legacy row that predates the field;
    # the other is malformed. `reviewed` asks with `prov.get(field, [])`, so
    # the two arrive here as `[]` and `None` and are told apart.
    #
    # A test in `test_model_list_predicates.py` called this difference
    # deliberate. It was not — it was a predicate that could not see the
    # distinction it was credited with making.
    if not isinstance(value, list) or any(
            not isinstance(m, str) or not m.strip() for m in value):
        return None
    if len(set(value)) != len(value):
        # `note_served` deduplicates, so a repeated name is a shape production
        # does not write. Collapsing it into a set here would normalise a
        # malformed artifact into agreement, which is the refusal this file is
        # about.
        return None
    return value


def reviewed(prov: dict) -> Optional[set]:
    """The models that answered the *review* in one member's provenance.

    The third spelling of `Provenance.review_models` and
    `sentinel_compare._reviewing`, and it exists because this file cannot
    import either: `models.py` builds a dataclass from a live run and
    `sentinel_compare` is the comparator. The rule is theirs, and the tests
    pin the three against the same shapes.

    Verification is excluded by subtraction, which would empty the list when
    one model did both jobs — so the requested model is kept in that case.

    Returns `None` when either list is not a list of distinct model names.
    That is a third answer and it has to be one: an empty set means "nothing
    reviewed", which is a fact about the run, and a row nobody can read has
    stated no such fact.
    """
    # `prov.get(field, [])` and not `prov.get(field)`: a key that is absent
    # returns the default, while a key present and `null` returns `None`. That
    # is the whole of the distinction between a legacy row and a malformed one.
    served = _names(prov.get("models_served", []))
    verified = _names(prov.get("models_verified", []))
    if served is None or verified is None:
        return None
    reviewing = [m for m in served if m not in set(verified)]
    requested = prov.get("model_requested")
    if requested in served and not reviewing:
        return {requested}
    return set(reviewing)


def is_product_row(row: dict) -> bool:
    """Whether this row is a measurement of the product rather than of some
    other model.

    One spelling, called from every reader that settles a question about *this*
    model's behaviour — `latest_rows` here and `sentinel.recorded_outcomes`.
    Two spellings of one rule drift, and this rule is now load-bearing in two
    places that answer different questions from the same files.

    Not for the readers whose question is "what was bought": a run on another
    model is a real charge and `spend`, `stage2`'s billing probe and
    `window_recut` count it on purpose.

    **Every member, one at a time.** Codex, 2026-09-09: comparing the *union*
    of the members' names against `{PRODUCT_MODEL}` accepted a pair whose safe
    member named Opus and whose unsafe member named nothing — the union is
    `{"claude-opus-5"}` and the row supersedes a fully identified one. The
    check the change exists to add, switched off by an omission, inside the
    line that added it.

    **Exactly the two members, and each an object.** Codex again, the same day:
    `all()` over whatever members happened to be present accepted a row
    carrying only `safe`, and a member stored as a string or a number reached
    `.get()` and crashed both readers instead of dropping the row. A pair is a
    safe member and an unsafe one; anything else is not a pair and cannot say
    it was measured by this model.
    """
    return why_not_product_row(row) is None


def why_not_product_row(row: dict) -> Optional[str]:
    """Why this row does not answer for the product, or `None` if it does.

    The boolean above is this, read as a yes or no. It is split out because a
    row that is skipped and nothing said about it is a row whose absence is
    invisible: `latest_rows` and `sentinel.recorded_outcomes` both fell back to
    an older measurement, and the failure looked like headline numbers quietly
    moving. Recorded in `LIMITATIONS.md` on 2026-09-09 and built the same day.

    The reason is a short phrase and not a sentence about one row, because the
    callers count reasons rather than printing one line per skipped row —
    fifty-two rows from one experiment arm should say "52 reviewed by another
    model", not fifty-two lines.
    """
    if "members" not in row:
        return None
    members = row.get("members")
    if not isinstance(members, dict):
        return "`members` is not an object"
    if set(members) != {"safe", "unsafe"}:
        return "not a pair of a safe and an unsafe member"
    for block in members.values():
        if not isinstance(block, dict):
            return "a member is not an object"
        prov = block.get("provenance")
        if not isinstance(prov, dict):
            return "a member records no readable provenance"
        if prov.get("model_requested") != PRODUCT_MODEL:
            return "asked for {}".format(prov.get("model_requested"))
        # **What was asked for is not what answered.** Codex, 2026-09-09: a row
        # asking for Opus and served Sonnet carries `model_substituted: true`
        # and `models_served: ["claude-sonnet-5"]`, and reading only
        # `model_requested` reported Sonnet's behaviour as Opus's.
        #
        # Membership, not equality, and that is not the union mistake made two
        # paragraphs above: the provider serves part of the *review* with a
        # smaller model exactly as it does the verification. All 97 member
        # records flagged `model_substituted` have `_reviewing` equal to
        # `{"claude-haiku-4-5-20251001", "claude-opus-5"}` — genuine paid Opus
        # measurements, every one — so demanding the product alone would throw
        # away 97 records to catch a shape that has never occurred.
        #
        # So: the product must be among what reviewed, and everything else
        # must be a helper the provider is known to serve alongside it.
        #
        # The first version stopped at the first clause and the comment here
        # admitted the gap rather than closing it — `["claude-opus-5",
        # "claude-sonnet-5"]` passed as an Opus measurement on the grounds that
        # a single review does not produce that shape. Codex, 2026-09-09: a
        # shape production does not write is exactly the shape a malformed or
        # forged row has, and this predicate is what stands between such a row
        # and the product's headline numbers. Requiring the known is not the
        # same as trusting that the unknown cannot occur.
        answered = reviewed(prov)
        if answered is None:
            return "a member's model list cannot be read"
        if PRODUCT_MODEL not in answered:
            return "reviewed by {}".format(
                ", ".join(sorted(answered)) or "nothing")
        strangers = sorted(name for name in answered - {PRODUCT_MODEL}
                           if not _is_helper(name))
        if strangers:
            return "also reviewed by {}".format(", ".join(strangers))
    return None


def latest_rows() -> Dict[str, dict]:
    """The most recent row per case, from every measurement file.

    Ordered by `artifact.instant`, the same reader `check_accounted` and
    `stage2` use. Not by string: `…T14:00:00+03:00` sorts after
    `…T12:00:00+00:00` and is two hours earlier. Not by filename either —
    `round.compare` settled a case that way until 2026-09-03, and renaming two
    files moved its answer.

    **A row reviewed by another model does not answer for this one.** The glob
    reads everything under `measurements/`, and on 2026-09-09 that included the
    52 rows of the Sonnet trial. Six cases were then answered by the arm of a
    model this repository had just rejected, one of them contributing a false
    alarm that Opus never raised — so the alarm codebook, `check_accounted` and
    `stage2` were reporting Sonnet's behaviour as the product's. The rejected
    model's own rows moving the product's headline numbers is the exact defect
    this repository exists to catch, arrived at from the inside.

    The filter is on what the row says, not on where it sits: experiment
    directories hold legitimate measurements of *this* model, and
    `check_accounted` and `stage2` include them on purpose.

    **A row from before pairs existed is still read, and only that.** 27 rows
    predate `model_requested`, all in `ordinary-noise`, and dropping them would
    throw away the whole ordinary-code pilot. The exception is granted by
    schema and not by the absence of a name: a row that carries `members` has
    to say who reviewed them, and a row that carries none is not a pair and
    holds no member-level evidence to withhold.

    Codex, 2026-09-09: the first version granted the exception to any row that
    named nothing, anywhere under `measurements/`, so a newer Sonnet row could
    drop its `provenance` and supersede a genuine Opus row on `ran_at` alone.
    Checked on disk: 178 rows carry `members`, all 356 of their member records
    name a model and record a non-empty `models_served`, and the 27 rows that
    name none are exactly the 27 with no `members` key. The two populations do
    not overlap, so the schema separates them cleanly.

    It is still a tolerance rather than a judgement — an unnamed row is not
    evidence that Opus produced it — and it ends when those rows are
    re-measured.
    """
    SKIPPED.clear()
    best: Dict[str, Tuple[Optional[object], dict]] = {}
    for path in glob.glob(str(ROOT / "measurements" / "**" / "*.json"),
                          recursive=True):
        if Path(path).name == "manifest.json":
            continue
        try:
            stored = json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        # A batch file is a list of rows; an experiment writes one row per
        # file, as an object. Reading only lists opened the file, parsed it,
        # and iterated it as nothing.
        for row in (stored if isinstance(stored, list) else [stored]):
            if not isinstance(row, dict):
                continue
            case_id = row.get("case_id")
            if not case_id:
                continue
            why = why_not_product_row(row)
            if why is not None:
                SKIPPED[why] = SKIPPED.get(why, 0) + 1
                continue
            when = instant(row.get("ran_at"))
            held = best.get(case_id)
            if held is None:
                best[case_id] = (when, row)
                continue
            kept_when, _kept = held
            # An undated row answers only when nothing dated does — the rule
            # `stage2._settle` follows. Two undated rows used to be settled by
            # whichever the glob handed over last.
            if when is not None and (kept_when is None or when > kept_when):
                best[case_id] = (when, row)
    return {case_id: row for case_id, (_when, row) in best.items()}


def rates(rows: Dict[str, dict]) -> dict:
    """The two numbers `D-013` thresholds, and the counts behind them.

    `is True` / `is False`, never `bool(...)`. `pair_corpus` writes these only
    on the success path, so a review that crashed carries neither — and
    `bool(None)` is `False`, which would score a run that never happened as a
    miss. A stored `"false"` would go the other way and read as a hit.
    """
    found = missed = fired = quiet = 0
    for row in rows.values():
        recall = row.get("unsafe_recall")
        if recall is True:
            found += 1
        elif recall is False:
            missed += 1
        alert = row.get("safe_false_positive")
        if alert is True:
            fired += 1
        elif alert is False:
            quiet += 1
    return {
        "found": found, "missed": missed, "fired": fired, "quiet": quiet,
        "unsafe_total": found + missed, "safe_total": fired + quiet,
    }


def without_malformed(rows: Dict[str, dict]) -> Dict[str, dict]:
    """The rows left after the cases a ruling says cannot measure anything.

    `pair_corpus`, `stage2` and `check_accounted` all drop these; this tool
    counted them, so four readers of one corpus used two denominators and the
    one that authorises stopping used the larger. Thirteen cases are ruled
    malformed and nine of them have a stored row.
    """
    ruled = malformed_cases(ROOT / "corpus-real")
    return {case_id: row for case_id, row in rows.items()
            if case_id not in ruled}


def verdict(counts: dict) -> Tuple[str, list]:
    """`stop`, `no catastrophe`, or `cannot say` — never `pass`.

    "Cannot say" is a real answer and gets its own exit code. A corpus with no
    usable rows must not read as one that found no catastrophe: this is the
    tool that decides whether a configuration is abandoned, and the difference
    between "nothing is wrong" and "nothing was measured" is the whole subject
    of this repository.
    """
    reasons = []
    if not counts["unsafe_total"] or not counts["safe_total"]:
        return "cannot say", ["no usable rows on one side of the pair"]

    recall = counts["found"] / counts["unsafe_total"]
    alert = counts["fired"] / counts["safe_total"]
    if recall < RECALL_FLOOR:
        reasons.append("recall {:.0%} is below the {:.0%} floor".format(
            recall, RECALL_FLOOR))
    if alert > PATCHED_ALERT_CEILING:
        reasons.append(
            "the fixed member still carries a finding of the target category "
            "in {:.0%} of cases, over the {:.0%} ceiling — this is not a "
            "false-alarm rate, see D-013".format(alert, PATCHED_ALERT_CEILING))
    return ("stop" if reasons else "no catastrophe"), reasons


def render_without_verdict(counts: dict) -> str:
    """The rates, and deliberately no answer.

    A reading that rests on rulings the reviewer's own model made is worth
    printing and must not carry a verdict — `LIMITATIONS.md` says no threshold
    may be computed through them. Rendering it through `render()` would attach
    "verdict: no catastrophe" to it, and a line saying "not evidence" printed
    beside a verdict loses to the verdict every time.
    """
    return _table(counts)


def _table(counts: dict) -> str:
    lines = ["{} case(s) with a usable latest row".format(
        max(counts["unsafe_total"], counts["safe_total"])), ""]
    lines.append("                     alerts   quiet")
    lines.append("  vulnerable      {:>8} {:>7}".format(
        counts["found"], counts["missed"]))
    lines.append("  patched         {:>8} {:>7}".format(
        counts["fired"], counts["quiet"]))
    lines.append("")
    for name, hits, total, floor, ceiling in (
            ("recall", counts["found"], counts["unsafe_total"],
             RECALL_FLOOR, None),
            # Not "false alarms". `is_target` compares category and file and
            # makes no judgement about whether the finding is correct, so this
            # counts "the fixed file still carries a finding of this category"
            # — which a correct reviewer produces too. Naming it a false-alarm
            # rate is how the 40% ceiling came to be read as one.
            ("category still in fix", counts["fired"], counts["safe_total"],
             None, PATCHED_ALERT_CEILING)):
        if not total:
            lines.append("  {:<22} no usable rows".format(name))
            continue
        low, high = wilson(hits, total)
        bound = ("floor {:.0%}".format(floor) if floor is not None
                 else "ceiling {:.0%}".format(ceiling))
        lines.append("  {:<22} {:>3}/{:<3} = {:>3.0%}   95% CI {:.0%}–{:.0%}"
                     "   {}".format(name, hits, total, hits / total,
                                    low, high, bound))
    return "\n".join(lines)


def render(counts: dict, decision: str, reasons: list) -> str:
    lines = [_table(counts), ""]
    lines.append("  verdict: {}".format(decision))
    for reason in reasons:
        lines.append("    {}".format(reason))
    if decision == "no catastrophe":
        lines.append("    Not a pass. This rule has no pass branch — see "
                     "D-013 — and cannot see a drop under 13 points.")
    return "\n".join(lines)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--rows", action="store_true",
                        help="list every contributing case")
    args = parser.parse_args(argv)

    rows = latest_rows()
    counts = rates(rows)
    decision, reasons = verdict(counts)

    # The rulings are read *before* anything is printed. They do not touch the
    # verdict — that comes from the raw rows and from nothing else — but
    # `load_adjudications` raises on unreadable or invalid YAML, and printing
    # first meant the exception left stdout saying "no catastrophe" while the
    # process exited 1, the code this tool documents as `stop`. Two answers
    # from one run, and the louder one wrong.
    unreadable = ruled_rows = report = ruled_counts = None
    try:
        # `without_malformed` reads the same file, so it belongs inside the
        # same attempt. Leaving it outside was the first version of this fix
        # and moved the crash three lines up without removing it.
        ruled_rows = without_malformed(rows)
        stored = load_adjudications(ROOT / "corpus-real")
    except Exception as exc:                       # noqa: BLE001 — see below
        # Deliberately broad — whatever a malformed rulings file does to the
        # parser, the answer is the same. Narrow in *extent* instead: only the
        # two calls that read the file are inside it. Wrapping the arithmetic
        # too would have reported a bug in `rates` as "the rulings could not be
        # read", which is a true-sounding sentence about the wrong thing.
        unreadable = "{}: {}".format(type(exc).__name__, exc)
    else:
        # Only the rulings that *dropped* a case from this denominator.
        # Filtering on the case id alone was the first version and counted
        # every ruling about a dropped case — including excusals, which have
        # nothing to do with which cases are here. Measured: one dropped case
        # with a second, incidental ruling beside it reported "0 of 2".
        dropped = set(rows) - set(ruled_rows)
        report = independence([r for r in stored
                               if r.get("case_id") in dropped
                               and r.get("case_is_malformed") is True])
        ruled_counts = rates(ruled_rows)

    # The second reading is printed because four tools disagreeing over one
    # corpus is worth seeing, and it decides nothing. An earlier version let it
    # decide: it removed the cases a ruling had dropped and could return `stop`
    # on what was left, while `LIMITATIONS.md` two files away said no threshold
    # may be computed through those rulings. A prohibition written down and
    # stepped over in the same change is worse than one never written.
    print(render(counts, decision, reasons))

    # What was on disk and did not count. Printed under the verdict rather than
    # withheld: a row skipped for its reviewer used to leave no trace, so an
    # older measurement answered in its place and the only visible effect was
    # the numbers moving. Silence here means every row was read, which is a
    # different statement from silence about whether anybody looked.
    line = skipped_line()
    if line:
        print()
        print("  {}".format(line))

    if unreadable is not None:
        # The verdict stands. The rulings feed the second reading and the
        # second reading decides nothing, so a broken rulings file cannot
        # unmake an answer that was computed without it. Turning this into
        # `cannot say` was the first version of this fix, and it was worse than
        # the crash it replaced: it could mask a raw `stop` behind exit 2.
        print()
        print("  the rulings could not be read: {}".format(unreadable))
        print("  Only the second reading is missing. The verdict above was "
              "computed\n  without the rulings and is unaffected.")
    else:
        print()
        print("  and with the {} case(s) a ruling dropped as malformed removed"
              " — the\n  denominator stage2 and check_accounted use:".format(
                  len(rows) - len(ruled_rows)))
        print(render_without_verdict(ruled_counts))
        print("    No verdict from this reading. {} of {} rulings were made by "
              "somebody who\n    did not produce the findings; see "
              "LIMITATIONS.md.".format(report["independent"], report["total"]))
        if verdict(ruled_counts)[0] != decision:
            print("    It disagrees with the reading above. That is a question "
                  "about the\n    corpus, not a second answer about the "
                  "product.")

    if args.rows:
        print()
        for case_id in sorted(rows):
            row = rows[case_id]
            print("  {:<24} recall={!r:<6} alert={!r:<6} {}".format(
                case_id, row.get("unsafe_recall"),
                row.get("safe_false_positive"), row.get("ran_at") or "undated"))

    # 1 is "stop", the same code the product uses for "there is something
    # blocking". 2 is "could not answer", never 0 — a crash must not exit like
    # a clean result.
    return {"stop": 1, "no catastrophe": 0, "cannot say": 2}[decision]


if __name__ == "__main__":
    raise SystemExit(main())
