#!/usr/bin/env python3
"""Freeze what the sentinel cases did under the current model, before changing it.

A comparison needs something to compare against, and assembling one out of the
newest row per case does not produce it. Those rows come from different days and
different versions of the reviewer — the sentinel's thirteen span 2026-08-28 to
2026-09-01, and three carry no timestamp at all — so the "reference" would be a
patchwork of systems, and a delta measured against it would be a delta against
no version in particular.

`experiment-noise-floor-2` is one frozen system: thirteen cases, two passes, the
same prompts, schema, scorer and adjudications throughout, all on
`claude-opus-5`. That is what a reference has to be.

## Both passes, not the later one

The two passes disagree on two cases. Taking either as *the* answer picks a side
of the noise and hides that the disagreement exists — and then a model change
that flips one of those cases reads as an effect.

So the reference records both outcomes per case. A case where the reference
disagreed with itself is marked `unstable_under_reference`, and a threshold
counted over the others is a threshold over cases the current model answers the
same way twice.

    tools/sentinel_reference.py --write measurements/reference/sentinel-opus.json
    tools/sentinel_reference.py --check measurements/reference/sentinel-opus.json

Written under `measurements/reference/` rather than beside the batches: every
reader of `measurements/*.json` expects a list of result rows, and a file
shaped otherwise in that glob broke one of them the moment it appeared.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from artifact import case_digest, legacy_case_digest  # noqa: E402

CORPUS = ROOT / "corpus-real"
EXPERIMENT = ROOT / "measurements" / "experiment-noise-floor-2"
SUITE = ROOT / "suites" / "sentinel.yml"
PASSES = ("pass-a", "pass-b")
# What this reference is about, and what the rows must show. Declared here and
# then *checked* against every row, rather than written into the output and
# believed.
MODEL = "claude-opus-5"
VERIFIER = "claude-opus-5"


class ReferenceError(Exception):
    """A row that cannot be trusted to say what it says."""


def _row_of(path: Path, case_id: str) -> dict:
    """One row, or a refusal. Never a guess.

    Every line here replaces a silent coercion. A file holding a list had its
    first element taken and the rest ignored; a row whose own `case_id` named a
    different case was accepted because the filename matched; and the verdict
    was read as `bool(row.get("pair_success"))`, which turns the string
    "false" into True and a missing field into a valid failure. A reference
    assembled that way is wrong in the direction nobody checks.
    """
    body = json.loads(path.read_text(encoding="utf-8"))
    rows = body if isinstance(body, list) else [body]
    # Counted before the non-dicts are dropped. Filtering first accepted
    # `[valid_row, garbage]` as one row and said nothing about the garbage.
    if len(rows) != 1 or not isinstance(rows[0], dict):
        raise ReferenceError("{}: holds {} row(s), and a reference needs "
                             "exactly one".format(path.name, len(rows)))
    row = rows[0]

    # What produced the row, proved rather than declared. The builder wrote
    # `"model": "claude-opus-5"` and `"verifier_model": "claude-opus-5"` into
    # the reference unconditionally, while checking nothing about the rows it
    # was built from — so a directory of Sonnet rows, or of runs with
    # verification off, would still have produced a reference claiming "Opus,
    # verified by Opus". The comparator then holds a challenger to a contract
    # the reference itself never met.
    members = row.get("members") or {}
    if set(members) != {"safe", "unsafe"}:
        raise ReferenceError("{}: a pair is a safe and an unsafe member".format(
            path.name))
    for name, block in sorted(members.items()):
        prov = (block or {}).get("provenance") or {}
        settings = (block or {}).get("settings") or {}
        if prov.get("model_requested") != MODEL:
            raise ReferenceError(
                "{}: the {} member asked for {!r} and this reference is about "
                "{}".format(path.name, name, prov.get("model_requested"),
                            MODEL))
        served = prov.get("models_served")
        if not served:
            raise ReferenceError(
                "{}: the {} member records no served model".format(
                    path.name, name))
        if settings.get("verify", True) is not True:
            raise ReferenceError(
                "{}: verification is {!r} in the {} member, and a reference "
                "with a layer missing cannot hold a challenger to it".format(
                    path.name, settings.get("verify"), name))

    if row.get("case_id") != case_id:
        raise ReferenceError("{}: the row inside is about {!r}".format(
            path.name, row.get("case_id")))
    if not isinstance(row.get("pair_success"), bool):
        raise ReferenceError("{}: `pair_success` is {!r}, not a verdict".format(
            path.name, row.get("pair_success")))
    return row


def _rows(case_id: str) -> dict:
    out = {}
    for label in PASSES:
        path = EXPERIMENT / label / (case_id + ".json")
        if not path.is_file():
            continue
        out[label] = _row_of(path, case_id)
    return out


def _shape(row: dict) -> dict:
    """How it failed, in the two ways that are not the same failure.

    `[safe_exit, unsafe_exit]` was the first version and it cannot carry the
    rule it was written for. Two exit codes order nothing, and "a worse shape
    counts downward" needs an order. So the two failures are named instead:

        missed        the weakness was not found in the unsafe member
        false_alarm   the fixed member was flagged anyway

    Recorded separately and **not** summed. Missing a vulnerability and
    shouting about a fix are different harms with different costs, and one
    number that lets either offset the other hides whichever the reader cares
    about. A rule over them has to say which one it ranks, out loud.
    """
    out = {}
    for field, kind in (("unsafe_recall", "missed"),
                        ("safe_false_positive", "false_alarm")):
        value = row.get(field)
        if not isinstance(value, bool):
            # The comparator refuses these already; the freezer could still
            # build them into the reference, where a missing `unsafe_recall`
            # became a confirmed miss and the string "false" became a
            # confirmed false alarm.
            raise ReferenceError("{}: `{}` is {!r}, not a verdict".format(
                row.get("case_id"), field, value))
        out[kind] = (not value) if kind == "missed" else value
    out["exits"] = [row.get("safe_exit"), row.get("unsafe_exit")]
    return out


def observed() -> dict:
    """Every model that answered anything, by member, across the reference.

    Read from the rows rather than declared. The reference used to state which
    model verified it and check nothing; this is what actually served.
    """
    seen: dict = {}
    cases = yaml.safe_load(SUITE.read_text(encoding="utf-8"))["cases"]
    for case_id in cases:
        for row in _rows(case_id).values():
            for name, block in (row.get("members") or {}).items():
                prov = (block or {}).get("provenance") or {}
                seen.setdefault(name, set()).update(
                    prov.get("models_served") or [])
    return {name: sorted(models) for name, models in sorted(seen.items())}


def build() -> dict:
    cases = yaml.safe_load(SUITE.read_text(encoding="utf-8"))["cases"]
    manifest = json.loads((EXPERIMENT / "manifest.json").read_text(encoding="utf-8"))

    entries, missing, unstable = {}, [], []
    for case_id in cases:
        rows = _rows(case_id)
        if len(rows) != len(PASSES):
            missing.append(case_id)
            continue
        outcomes = {label: bool(row.get("pair_success"))
                    for label, row in rows.items()}
        # One digest across both passes and the corpus as it stands, not
        # whatever pass A happened to carry. Taking one pass's word for it let
        # a row about an older version of the case become the reference the
        # whole comparison is measured against.
        digests = {row.get("case_digest") for row in rows.values()}
        if len(digests) != 1 or None in digests:
            raise ReferenceError(
                "{}: the passes disagree about which version of the case they "
                "measured ({})".format(case_id, sorted(map(str, digests))))
        digest = digests.pop()
        directory = CORPUS / case_id
        if digest not in (case_digest(directory),
                          legacy_case_digest(directory)):
            raise ReferenceError(
                "{}: the reference measured a version of the case that is no "
                "longer on disk".format(case_id))

        entry = {
            "outcomes": outcomes,
            "shape": {label: _shape(row) for label, row in rows.items()},
            "case_digest": digest,
            "unstable_under_reference": len(set(outcomes.values())) > 1,
        }
        if entry["unstable_under_reference"]:
            unstable.append(case_id)
        entries[case_id] = entry

    return {
        "reference": "experiment-noise-floor-2",
        "model": MODEL,
        # The verifier followed the reviewer here, and the artifacts of that run
        # do not say so: `verify_model` was added to the recorded settings on
        # 2026-09-02, after these rows were written. Stated rather than derived,
        # so a later reader is not left to infer it from an absent field.
        "verifier_model": VERIFIER,
        # What the machinery *did*, beside what it was asked for. Requiring the
        # served models to be the requested one refused this reference's own
        # rows: every unsafe member of all twenty-six carries Haiku beside
        # Opus, and every safe member does not — Haiku appears exactly where
        # there was a finding to verify. The CLI serves part of the
        # verification with a smaller model, always, and demanding a purity
        # neither run has would have refused the challenger for the same reason.
        #
        # So it is recorded as an observation and the comparator requires the
        # challenger to have observed the same thing. That keeps the measuring
        # instrument constant, which is the property that matters, instead of
        # insisting it be something it is not.
        "observed_models": observed(),
        "environment": manifest["environment"],
        # How this reference relates to the code as it stands, in the words
        # that survive being quoted. Three of the seven digests moved after it
        # was frozen, and leaving that implicit would have let a later reader
        # take the comparison for one made under identical conditions.
        #
        # Two of the three were *measured*: the stored rows were re-scored
        # under today's scorer and adjudications and nothing moved. The third
        # was *argued*: the reviewer's diff over that range touches provenance
        # attribution, comparability identity, telemetry and report
        # serialisation, and no input, prompt, tool path, candidate
        # construction, verification decision or gate. Buying a fresh Opus
        # reference would cost about $26 and would mostly measure a new
        # stochastic sample of the same model.
        "environment_equivalence": {
            "reviewer": {
                "status": "accepted_by_static_analysis",
                "reference_digest": "aa3d401c17640eed",
                # A named commit, not `HEAD`: the range was written as
                # `fa05463..HEAD` and its meaning changed with every commit
                # after it, so the record would have claimed a reading of code
                # nobody read.
                "commit_range": "fa05463..79a7cb7",
                "rerun": False,
                "scope": "fresh review finding and decision path",
                "reading": "Accepted as a grandfathered baseline, not as an "
                           "empirically identical rerun.",
            },
            "scorer_and_adjudications": {
                "status": "rescored",
                "rows": 26,
                "changed_verdicts": 0,
                "reading": "Equivalence for these stored rows under "
                           "`hits_target`, not general equivalence of the "
                           "scorer.",
            },
            "not_established": "Provider-side drift. Neither this reference "
                               "nor a freshly bought one rules it out; a new "
                               "one would only move the question to today.",
        },
        "cases": entries,
        "missing": missing,
        "unstable_under_reference": unstable,
        "comparable": sorted(set(entries) - set(unstable)),
        # Written before any challenger has been run, which is the only time
        # this is worth anything — and written as **numbers the comparator
        # reads**, not as a sentence it paraphrases. The first version was
        # prose, and the comparator then carried its own copy of the rule:
        # two things that can drift apart, which is what putting the rule in
        # code was supposed to stop.
        "threshold": {
            "reject_at_net": 2,
            "confirmations_required": 2,
            # Versioned, not described by flags. Three booleans stood here
            # saying what the comparison does and nothing read them — a
            # setting nobody applies is a claim, and a claim in a frozen file
            # reads as configuration. The comparator refuses a version it does
            # not implement, so a changed rule is a different question rather
            # than a silent one.
            "rule_version": 1,
            # The prose stays, for a person. The numbers above are what runs.
            "in_words": "A case counts as regressed when it gives the worse "
                        "result in `confirmations_required` separate runs of "
                        "the challenger under one system identity. Net is "
                        "confirmed regressions minus confirmed improvements. "
                        "At `reject_at_net` the change is rejected; at one, "
                        "nothing is decided and the sample is widened; at "
                        "zero it passes this gate, which is grounds to buy "
                        "wider confirmation and not a verdict about the "
                        "corpus. A case still failing counts downward only "
                        "when a kind of failure it did not have appears; "
                        "trading one kind for the other decides nothing. "
                        "Cases the reference itself answered two ways are "
                        "not counted.",
        },
        "not_answerable": "Thirteen cases are a tripwire, not a sample. "
                          "Passing says the wider measurement is worth buying; "
                          "it says nothing about the other sixty-nine cases.",
    }


def render(body: dict) -> str:
    lines = ["sentinel reference · {} case(s) from {}".format(
        len(body["cases"]), body["reference"])]
    lines.append("  model {} · verifier {}".format(
        body["model"], body["verifier_model"]))
    for case_id in sorted(body["cases"]):
        entry = body["cases"][case_id]
        outcomes = entry["outcomes"]
        lines.append("  {:<24}{:<6}{:<6}{}".format(
            case_id,
            "pass" if outcomes["pass-a"] else "fail",
            "pass" if outcomes["pass-b"] else "fail",
            "  ← unstable under the reference"
            if entry["unstable_under_reference"] else ""))
    lines.append("")
    lines.append("  {} comparable, {} unstable, {} missing".format(
        len(body["comparable"]), len(body["unstable_under_reference"]),
        len(body["missing"])))
    threshold = body["threshold"]
    lines.append("  reject at net {} · {} confirmation(s) per case".format(
        threshold["reject_at_net"], threshold["confirmations_required"]))
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", metavar="PATH")
    parser.add_argument("--check", metavar="PATH")
    args = parser.parse_args()

    body = build()
    print(render(body))

    if body["missing"]:
        print("\n{} case(s) are not in the reference run and cannot be "
              "compared:\n  {}".format(len(body["missing"]),
                                       "\n  ".join(body["missing"])),
              file=sys.stderr)
        return 2

    if args.check:
        frozen = json.loads(Path(args.check).read_text(encoding="utf-8"))
        if frozen != body:
            print("\n{} does not match what the reference run says today. A "
                  "frozen reference that drifts is not a reference.".format(
                      args.check), file=sys.stderr)
            return 2
        print("\n{} matches.".format(args.check))
    if args.write:
        target = Path(args.write)
        if target.exists():
            print("\n{} already exists. A frozen reference is not "
                  "rewritten.".format(args.write), file=sys.stderr)
            return 1
        target.write_text(json.dumps(body, indent=1) + "\n", encoding="utf-8")
        print("\nWritten to {}.".format(args.write))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
