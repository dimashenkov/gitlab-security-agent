#!/usr/bin/env python3
"""What caused each alarm on the fixed member, coded by a third vendor.

    tools/classify_alarms.py --out DIR [--limit N] [--seed N]

D-013 step 4. Twenty alarms, each already named in
`measurements/alarm-codebook/identities.yml`, each now given a cause.

## What this is, said before the numbers

**A post-hoc exploratory codebook, not a precommitted vocabulary.** Codex ruled
that out on 2026-09-04: nobody who has read the cases can write a blind
vocabulary, and one written afterwards is written to fit. So the counts here
**describe** and do not confirm. They do not establish that a cause is broadly
or independently repeated, and they do not authorise step 5.

**Four fields, not one label.** An earlier design put everything in one field
and it mixed levels: whether the *metric* misfired is not a way the *reviewer*
failed, and "the reviewer made a wrong claim" is not a sibling of "the reviewer
was wrong" but a way of being it. So attribution and mechanism are separate,
and one can be `not_applicable` while the other is answered.

**No precedence rules.** Independent dimensions do not need them, and the ones
first written were conclusions wearing a tie-break: "a metric artefact explains
the alarm without any claim about the reviewer" assumed metric attribution
extinguishes reviewer attribution, when `both` is a permitted value precisely
because they can hold together.

**Evidence is references plus reasoning, not eloquence.** A required non-empty
paragraph validates prose. `evidence_refs` names artifacts a checker can look
for; `missing_context` says what was not available. What no checker can do is
confirm that a cited line proves the classification — that stays adjudication
and is never reported as machine-validated.

## The protocol, which is step 2's copied and not inherited

One `grok -p` per finding: a new process, one user message, no session, order
shuffled from a recorded seed. Codex was explicit that step 2's authorisation
does not carry here — a different question, input, schema and unit — so the
provenance is recorded again rather than pointed at.

The classifier sees the ruling and nothing else: not the case id, not the
stratum, not which findings share a case, not its own earlier answers.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import alarm_identities as ai  # noqa: E402

SCHEMA_VERSION = "alarm-codebook/1"
MODEL = "grok-4.6"
VENDOR = "xai"


ALARM_SOURCE = ["metric", "reviewer", "both", "other", "unclear"]
REVIEWER_ERROR = ["wrong_location", "wrong_semantics", "unsupported_escalation",
                  "other", "unclear", "not_applicable"]
CONFIDENCE = ["high", "medium", "low"]

CODEBOOK_SCHEMA = {
    "type": "object",
    "properties": {
        "alarm_source": {"type": "string", "enum": ALARM_SOURCE},
        "reviewer_error": {"type": "string", "enum": REVIEWER_ERROR},
        "confidence": {"type": "string", "enum": CONFIDENCE},
        "evidence_refs": {"type": "array", "items": {"type": "string"}},
        "evidence_assessment": {"type": "string"},
        "missing_context": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["alarm_source", "reviewer_error", "confidence",
                 "evidence_refs", "evidence_assessment", "missing_context"],
    "additionalProperties": False,
}

# The fields `_coding_problems` actually reads. Written out rather than derived
# from the schema above: deriving it would mean a field added to the schema is
# accepted the moment it is declared, by a checker that has never read it —
# the declaration standing in for the behaviour. The two are kept level by
# `test_the_schema_and_the_checker_name_the_same_fields`, which fails if either
# side gains a field alone.
_CODING_FIELDS = frozenset({"alarm_source", "reviewer_error", "confidence",
                            "evidence_refs", "evidence_assessment",
                            "missing_context"})

RUBRIC = """\
A security reviewer examined a change that had already been fixed, and reported \
a finding of the advisory's own category in the advisory's own file. A separate \
adjudication of that finding is given below. Decide what produced the alarm.

alarm_source — who the disagreement is with.
  metric: the finding is sound, and the scoring key matched it to this case \
when it is about something else. Nothing here is a reviewer failure.
  reviewer: the finding itself is wrong.
  both: the key matched loosely AND the finding is also wrong.
  other: neither describes it. Say what in the assessment.
  unclear: the material does not decide it.

reviewer_error — how the reviewer went wrong. not_applicable when \
alarm_source is metric.
  wrong_location: right kind of problem, wrong place.
  wrong_semantics: the code was read incorrectly.
  unsupported_escalation: the description is accurate and the security \
conclusion is not supported by it.
  other, unclear: as above.

confidence — high, medium or low, in this assignment as a whole. It is not a \
fourth way of saying unclear: you may be confident that a field is unclear.

evidence_refs — the artifacts you used. A file and a symbol or line, the \
adjudication itself, an advisory. Name what you actually read.
missing_context — what was not available and would have decided it. Empty \
when nothing was missing. Do not invent a decisive line that is not there.
evidence_assessment — your reasoning, grounded in those references.

--- the adjudication ---
{ruling}
"""


def digest_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


def material(identities: Dict[str, Any], rulings: List[Dict[str, Any]],
             resolved: Dict[str, str]) -> List[Dict[str, Any]]:
    """One item per finding, carrying the ruling text the classifier sees.

    Superseded rulings are dropped here rather than shown: the identities file
    decided which row a finding is, and handing the classifier both would ask
    it to re-decide something already frozen.
    """
    superseded = set()
    for entry in identities["findings"]:
        if entry.get("same_finding_as") == "revision":
            kept = entry.get("fingerprint")
            for row in entry.get("rulings") or []:
                if row.get("fingerprint") != kept:
                    superseded.add((entry["case_id"],
                                    row.get("adjudicated_on")))

    by_case: Dict[str, List[Dict[str, Any]]] = {}
    for ruling in rulings:
        key = (ruling.get("case_id"), ruling.get("adjudicated_on"))
        if key in superseded:
            continue
        by_case.setdefault(ruling["case_id"], []).append(ruling)

    out = []
    for case, finding_id in sorted(resolved.items()):
        rows = by_case.get(case, [])
        if len(rows) != 1:
            raise SystemExit(
                "finding {!r} resolves to {} ruling(s) after supersession; one "
                "is required, and guessing which would undo a decision the "
                "identities file already froze".format(finding_id, len(rows)))
        row = rows[0]
        # What the classifier is shown. The case id is absent on purpose: it
        # encodes the language, and the stratum and the reviewer's own output
        # are absent for the same reason — they are the answer.
        shown = {key: row[key] for key in
                 ("file", "claim", "evidence", "verdict", "severity_reported",
                  "why_not_the_target", "why_malformed", "incidental",
                  "not_verifiable", "fix_review_outcome")
                 if row.get(key) is not None}
        out.append({"finding_id": finding_id, "case_id": case,
                    "ruling": json.dumps(shown, indent=2, sort_keys=True)})
    return out


def ask(ruling_text: str, timeout: int) -> Dict[str, Any]:
    """One finding, one process, one user message. Never retried.

    Not "one turn": see `_evidence_problems` for why that was the wrong test.
    """
    prompt = RUBRIC.format(ruling=ruling_text)
    command = [
        "grok", "-p", prompt,
        "--model", MODEL,
        "--sandbox", "read-only",
        "--disallowed-tools", "bash,edit,write,read,web_search,web_fetch",
        # `--max-turns 1` was tried on 2026-09-05 and returns "max turns
        # reached": the model needs a step to work and a step to answer. What
        # the protocol asks for is one *user message*, which `-p` gives by
        # construction, and these two stop the call from becoming an agentic
        # session of its own.
        "--no-plan",
        "--no-subagents",
        "--json-schema", json.dumps(CODEBOOK_SCHEMA),
        "--output-format", "json",
    ]
    shape = ["<prompt>" if part is prompt else part for part in command]
    started = time.time()
    try:
        done = subprocess.run(command, capture_output=True, text=True,
                              timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        return {"failed": "timed out after {}s".format(timeout),
                "command": shape, "prompt_digest": digest_text(prompt)}

    attempt = {"exit_code": done.returncode, "command": shape,
               "prompt_digest": digest_text(prompt),
               "seconds": round(time.time() - started, 1)}
    if done.returncode != 0:
        attempt["failed"] = (done.stderr or "").strip()[:400] or "non-zero exit"
        return attempt
    try:
        body = json.loads(done.stdout)
    except ValueError as exc:
        attempt["failed"] = "the CLI did not return JSON: {}".format(exc)
        return attempt
    if not isinstance(body, dict):
        attempt["failed"] = "the reply is {}, not an object".format(
            type(body).__name__)
        return attempt

    attempt.update({
        "session_id": body.get("sessionId"),
        "request_id": body.get("requestId"),
        "turns": body.get("num_turns"),
        "stop_reason": body.get("stopReason"),
        "model_served": sorted(body["modelUsage"].keys())
        if isinstance(body.get("modelUsage"), dict) else None,
        "cost_usd": body.get("total_cost_usd"),
    })
    problems = _evidence_problems(attempt)
    if problems:
        attempt["failed"] = "; ".join(problems)
        return attempt

    coded = body.get("structuredOutput")
    problems = _coding_problems(coded)
    if problems:
        attempt["failed"] = "; ".join(problems)
        return attempt
    attempt["coding"] = coded
    return attempt


def _evidence_problems(attempt: Dict[str, Any]) -> List[str]:
    """The same protocol evidence step 2 requires, checked the same way."""
    problems = []
    for field, what in (("session_id", "session id"),
                        ("request_id", "provider response id")):
        value = attempt.get(field)
        if not isinstance(value, str) or not value.strip():
            problems.append("no {} in the reply".format(what))
    # `num_turns` is **not** freshness evidence, and saying it was conflated
    # three things: a fresh invocation (a new process with no resume or
    # session argument), a fresh provider context (a distinct session id, not
    # reused across cases), and how much internal work the model did. Only the
    # first two bear on contamination. Codex, 2026-09-05, correcting the
    # frozen protocol's ambiguous word "single-turn", which this tool had read
    # as `num_turns == 1`.
    #
    # Recorded and not capped. A ceiling was tried at 12 — one above the
    # eleven observed once — and Codex struck it out: that is a threshold from
    # a single observation, the timeout already bounds the resource
    # prospectively, and refusing a finished thirteen-turn answer throws away
    # evidence without saving anything.
    turns = attempt.get("turns")
    if isinstance(turns, bool) or not isinstance(turns, int) or turns < 1:
        problems.append("{!r} turn(s); the reply reports no usable turn "
                        "count".format(turns))

    served = attempt.get("model_served")
    if not isinstance(served, list) or not any(
            isinstance(name, str) and name.strip() for name in served):
        problems.append("the reply names no model")

    # Require the ending we need rather than listing the ones we can imagine.
    # A call that stopped for any other reason — a turn limit, an
    # interruption, an error — did not finish answering, and its structured
    # output is whatever had been assembled by then. `stopReason` was recorded
    # and never read, which is the same defect as the identifiers were, and
    # the instruction in `docs/grok-on-this-machine.md` asserted a check that
    # did not exist. Codex, 2026-09-05.
    stop = attempt.get("stop_reason")
    if stop != "end_turn":
        problems.append("the call stopped on {!r} rather than finishing its "
                        "answer".format(stop))
    return problems


def _coding_problems(coded: Any) -> List[str]:
    """The vocabulary, then the cross-field rules the schema cannot express.

    `metric` means the reviewer did nothing wrong, so naming an error would
    contradict the attribution. `reviewer` and `both` mean it did, so
    `not_applicable` would leave the mechanism unstated. `other` and `unclear`
    permit either, with the assessment saying why.

    The vocabulary is checked here and not left to `--json-schema`. That flag
    is the vendor's promise about its own output; this file's counts are ours.
    `grok_adjudicate.py` has always checked its three verdicts against the
    list, and this newer tool had lost the check: a coding naming three
    invented values passed every rule below, was counted in the denominator,
    appeared in no bucket, and a coding with `confidence` absent altogether
    reached the aggregation and raised `KeyError` — a crash where a refusal
    belongs. Demonstrated live, then fixed. Codex, 2026-09-05.
    """
    if not isinstance(coded, dict):
        return ["no structured coding in the response"]
    problems = []
    for field, vocabulary in (("alarm_source", ALARM_SOURCE),
                              ("reviewer_error", REVIEWER_ERROR),
                              ("confidence", CONFIDENCE)):
        if coded.get(field) not in vocabulary:
            problems.append("{} is {!r}, which is not one of {}".format(
                field, coded.get(field), ", ".join(vocabulary)))
    extra = sorted(set(coded) - _CODING_FIELDS)
    if extra:
        problems.append("the coding carries {}, which the codebook does not "
                        "define".format(", ".join(extra)))
    source = coded.get("alarm_source")
    error = coded.get("reviewer_error")
    if source == "metric" and error != "not_applicable":
        problems.append(
            "alarm_source `metric` says the reviewer did nothing wrong and "
            "reviewer_error is {!r}".format(error))
    if source in ("reviewer", "both") and error == "not_applicable":
        problems.append(
            "alarm_source {!r} says the reviewer was wrong and names no "
            "mechanism".format(source))
    # Checked item by item, not with `any`. `any` asks whether the list holds
    # one usable entry and answers yes for `["a.py:1", 7]`, so a reference
    # this file cannot read travelled with one it could. Codex, 2026-09-05.
    refs = coded.get("evidence_refs")
    if not isinstance(refs, list) or not refs:
        problems.append("no evidence references")
    elif not all(isinstance(r, str) and r.strip() for r in refs):
        problems.append("an evidence reference is blank or is not text")

    if not isinstance(coded.get("evidence_assessment"), str) or \
            not coded["evidence_assessment"].strip():
        problems.append("no assessment")

    named = coded.get("missing_context")
    if not isinstance(named, list):
        problems.append("missing_context is not a list")
    elif not all(isinstance(m, str) and m.strip() for m in named):
        problems.append("something named as missing is blank or is not text")
    # `unclear` on either dimension has to say what was missing, or it is a
    # shrug with a field name on it. Emptiness is not the only way to say
    # nothing: `not [""]` is False in Python, so a list holding one empty
    # string passed this as though something had been named — the defect this
    # whole repository is about, in a checker written against it.
    elif "unclear" in (source, error) and not named:
        problems.append(
            "something is `unclear` and nothing is named as missing")
    return problems


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--identities", default=str(
        ROOT / "measurements" / "alarm-codebook" / "identities.yml"))
    parser.add_argument("--corpus", default=str(ROOT / "corpus-real"))
    parser.add_argument("--out", required=True)
    parser.add_argument("--seed", type=int, default=None)
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--timeout", type=int, default=300)
    args = parser.parse_args(argv)

    identities_path = Path(args.identities)
    try:
        identities = ai.load_identities(identities_path)
    except ai.IdentityError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    alarming, rulings = ai.alarms_and_rulings(Path(args.corpus))
    outcome = ai.resolve(alarming, rulings, identities)
    if outcome["problems"] or outcome["unresolved"]:
        for line in outcome["problems"]:
            print("  " + line, file=sys.stderr)
        print("identities do not resolve; classifying against unnamed findings "
              "would record a cause for something nobody named", file=sys.stderr)
        return 2

    items = material(identities, rulings, outcome["resolved"])
    seed = args.seed if args.seed is not None else int(time.time())
    random.Random(seed).shuffle(items)
    # `if args.limit:` made `--limit 0` mean "no limit", so the flag whose only
    # purpose is to spend less turned into the full paid run, and `--limit -1`
    # paid for all but the tail. Codex, 2026-09-05.
    if args.limit is not None:
        if args.limit < 0:
            raise SystemExit(
                "--limit {} asks for a negative number of findings; it would "
                "silently drop the tail and pay for the rest".format(
                    args.limit))
        items = items[:args.limit]

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    record = {
        "schema": SCHEMA_VERSION,
        "started_at": datetime.now(timezone.utc).isoformat(),
        "coded_by": "model",
        "vendor": VENDOR,
        "model_requested": MODEL,
        "cli_version": subprocess.run(
            ["grok", "--version"], capture_output=True, text=True,
            check=False).stdout.strip(),
        "identities": {"path": str(identities_path),
                       "digest": digest_text(
                           identities_path.read_text(encoding="utf-8"))},
        # The denominator is what was *asked*, which `--limit` changes.
        # It was taken from the resolution before truncation, so `--limit 1`
        # coded one finding and reported a denominator of twenty: counts over
        # one presented as a rate over twenty. The full population is kept
        # too, under a name that cannot be mistaken for it. Codex, 2026-09-05.
        "denominator": len(items),
        "population_denominator": outcome["denominator"],
        "limit": args.limit,
        "rubric_digest": digest_text(RUBRIC),
        "schema_digest": digest_text(json.dumps(CODEBOOK_SCHEMA,
                                                sort_keys=True)),
        "order_seed": seed,
        "order": [item["finding_id"] for item in items],
        "findings": {},
        "what_this_is_not": (
            "A post-hoc exploratory codebook. The counts describe and do not "
            "confirm: they do not establish that a cause is broadly or "
            "independently repeated, and they do not authorise step 5. No "
            "checker confirms that a cited line proves a classification."),
    }

    for index, item in enumerate(items, start=1):
        print("[{}/{}] {} ...".format(index, len(items), item["finding_id"]),
              flush=True)
        attempt = ask(item["ruling"], args.timeout)
        attempt["ruling_digest"] = digest_text(item["ruling"])
        attempt["asked_at"] = datetime.now(timezone.utc).isoformat()
        record["findings"][item["finding_id"]] = attempt
        coding = attempt.get("coding")
        print("      {}".format(
            "{} / {} ({})".format(coding["alarm_source"],
                                  coding["reviewer_error"],
                                  coding["confidence"])
            if coding else "NO CODING: " + str(attempt.get("failed"))),
            flush=True)

    record["finished_at"] = datetime.now(timezone.utc).isoformat()
    coded = [f["coding"] for f in record["findings"].values() if f.get("coding")]
    record["counts"] = {
        "alarm_source": {name: sum(1 for c in coded
                                   if c["alarm_source"] == name)
                         for name in ALARM_SOURCE},
        "reviewer_error": {name: sum(1 for c in coded
                                     if c["reviewer_error"] == name)
                           for name in REVIEWER_ERROR},
        "confidence": {name: sum(1 for c in coded if c["confidence"] == name)
                       for name in CONFIDENCE},
        "no_coding": len(record["findings"]) - len(coded),
    }
    # Over **every attempt**, not only the ones that produced a coding. A call
    # that failed validation still went to the vendor and still carries its
    # identifiers, and reuse there is the same contamination. Codex,
    # 2026-09-05.
    attempts = list(record["findings"].values())
    ids = [f.get("session_id") for f in attempts
           if isinstance(f.get("session_id"), str) and f["session_id"].strip()]
    requests = [f.get("request_id") for f in attempts
                if isinstance(f.get("request_id"), str)
                and f["request_id"].strip()]
    # `bool(judged) and ...` made a run with nothing to compare report
    # `sessions_distinct: false`, and the tool then said two or more calls
    # shared a session id when no call had been made. "I could not check" is
    # not "it is contaminated", and this repository keeps the two apart.
    # `null` is the third answer; the counts beside it say why.
    # Found by the `--limit 0` test, 2026-09-05.
    record["calls_made"] = len(attempts)
    # Two counts, because there are two comparisons. One `calls_compared`
    # stood for both, so an attempt with a session id and no response id was
    # reported as compared. Codex, 2026-09-05.
    record["sessions_compared"] = len(ids)
    record["responses_compared"] = len(requests)
    record["every_call_compared"] = bool(attempts) and \
        len(ids) == len(requests) == len(attempts)
    record["sessions_distinct"] = (len(set(ids)) == len(ids)
                                   if ids else None)
    record["responses_distinct"] = (len(set(requests)) == len(requests)
                                    if requests else None)
    # Reuse across findings is the contamination this looks for; see the same
    # note in `grok_adjudicate.py`.
    record["identifier_reuse"] = (record["sessions_distinct"] is False
                                  or record["responses_distinct"] is False)

    path = out / "codebook.json"
    path.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8")
    print()
    print("{} finding(s) into {}".format(len(record["findings"]), path))
    print("  alarm_source  : {}".format(
        {k: v for k, v in record["counts"]["alarm_source"].items() if v}))
    print("  reviewer_error: {}".format(
        {k: v for k, v in record["counts"]["reviewer_error"].items() if v}))
    # The line used to say "every call" over the calls that were compared,
    # which is a claim about the run made from a subset of it.
    print("  of {} call(s): {} carried a session id (distinct: {}), {} "
          "carried a response id (distinct: {})".format(
              record["calls_made"], record["sessions_compared"],
              record["sessions_distinct"], record["responses_compared"],
              record["responses_distinct"]))
    if record["identifier_reuse"]:
        shared = ("session" if record["sessions_distinct"] is False
                  else "response")
        print("  two or more calls share a {} id. A repeated session id means "
              "they were not separate contexts; a repeated response id means "
              "one answer was counted twice. Either way they are not "
              "independent observations".format(shared), file=sys.stderr)
    return 2 if (record["counts"]["no_coding"]
                 or record["identifier_reuse"]) else 0


if __name__ == "__main__":
    raise SystemExit(main())
