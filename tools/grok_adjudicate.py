#!/usr/bin/env python3
"""The answer key for D-013 step 2, written by a third vendor.

    tools/grok_adjudicate.py --seal S --candidates C --out DIR [--limit N]

## Why this exists and what it is not

Step 2 said the thirty ordinary changes are adjudicated "by hand, without a
single model call". The owner amended it on 2026-09-04 to permit **one model
call per case, to a third vendor**, and audits six of the thirty blind. The
whole reasoning is in D-013 under "The adjudicator for step 2"; the part that
governs this file:

* `independent` here means independent **of the model that produced the
  findings**, which will be Claude. Grok is a different vendor, and it did not
  help write `ordinary`, `unclear` or the stopping rule — Codex did, which is
  why Codex ruled *against itself* when asked to take this role.
* A Claude subagent is not permitted at all. Same family as the reviewer.

**This is structured third-vendor measurement, not human ground truth.** Grok is
less accountable than a person, may share systematic biases with other models,
and its independence is only partly auditable: this tool can show that each call
was a separate process carrying one message, and cannot show what the provider
keeps on its own side. The record says so and the number must never be quoted as
a human-adjudicated rate.

## What the protocol requires, and how each part is met

| Requirement | How |
|---|---|
| one model call per case | one `subprocess.run` per case, no reuse |
| no session, no memory | `-p` single-turn; no `--resume`, no `--session-id` |
| fresh context provable | the distinct `sessionId` and `num_turns` are recorded |
| randomised order | a recorded seed shuffles the cases before the first call |
| blind to everything else | the prompt carries the diff and nothing else |
| the served model recorded | `modelUsage` names it; it reports `grok-4.6-build` |

**It is told nothing but the change.** Not the case id, not the stratum, not why
it was sampled, not what any reviewer said, not the other cases, and not its own
earlier verdicts. The stratum in particular would be a direct hint: it is the
label the sampling rules already applied.

**Refusals are refusals, not verdicts.** A call that fails, times out, or
returns something the schema does not admit is recorded as an attempt with no
verdict. It is never retried — a second ask is a second sample of a coin, and
the protocol forbids re-rolling a case until it agrees.
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

sys.path.insert(0, str(Path(__file__).resolve().parent))

import ordinary_corpus as oc

SCHEMA_VERSION = "grok-adjudication/1"
MODEL = "grok-4.6"
VENDOR = "xai"

# The verdict schema, handed to the CLI so the answer comes back structured
# rather than as prose to parse. `unclear` is a real answer and is named in the
# enum for that reason: a model with only two options will pick one.
VERDICT_SCHEMA = {
    "type": "object",
    "properties": {
        "verdict": {"type": "string",
                    "enum": ["ordinary", "not_ordinary", "unclear"]},
        "rationale": {"type": "string"},
    },
    "required": ["verdict", "rationale"],
    "additionalProperties": False,
}

# Codex wrote this question, and the wording is load-bearing. It asks what the
# change *does*, not whether the code is safe: a reviewer alarming on a change
# is the thing being measured, so the answer key must be about the change.
RUBRIC = """\
Considering only the supplied repository change, decide whether the change \
itself fixes, removes, mitigates, or responds to a security vulnerability that \
existed before it.

ordinary: no such security purpose or effect is supported. Refactors, renames, \
tests, documentation, dependency work and non-security bug fixes are ordinary.
not_ordinary: the evidence supports that the change addresses a pre-existing \
security weakness, whether or not it is labelled as one.
unclear: the supplied evidence is insufficient, conflicting, truncated, or \
needs history and context that are not here. Do not guess.

Return one verdict and a concise rationale grounded in the diff you were given.

--- the change ---
{diff}
"""


def digest_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


def load_material(seal: Dict[str, Any], candidates: Path) -> List[Dict[str, Any]]:
    """Each selected case with the diff that will be shown for it.

    Joined through `ordinary_corpus.identity`, never on the raw strings. The
    manifest folds a repository path to lower case on purpose — one project
    written several ways would otherwise be several projects to the cap — so
    `github.com/automapper/automapper` in the seal is
    `github.com/AutoMapper/AutoMapper` in the pool, and a raw join silently
    loses those two cases. Measured, not guessed: it lost exactly two of thirty.
    """
    pool = json.loads(candidates.read_text(encoding="utf-8"))
    by_identity = {}
    for record in pool:
        key = oc.identity(record.get("repo"), record.get("commit"))
        if key is not None:
            by_identity[key] = record

    # Refused before the first call, not deduplicated after it. A repeated
    # `case_id` would overwrite the earlier attempt in the record, hiding a
    # call that was made and paid for; a repeated identity would ask about one
    # change twice under two names and count it twice. Codex, 2026-09-04.
    seen_ids, seen_identities, repeated = set(), set(), []
    for row in seal["selected"]:
        case_id = row.get("case_id")
        if case_id in seen_ids:
            repeated.append("case_id {!r}".format(case_id))
        seen_ids.add(case_id)
        key = oc.identity(row.get("repo"), row.get("commit"))
        if key is not None and key in seen_identities:
            repeated.append("{}@{}".format(*key))
        if key is not None:
            seen_identities.add(key)
    if repeated:
        raise SystemExit(
            "the sample names {} twice: {}. One change adjudicated twice is "
            "counted twice, and the second answer overwrites the first".format(
                "something" if len(repeated) == 1 else "things",
                ", ".join(sorted(set(repeated)))))

    material = []
    missing = []
    for row in seal["selected"]:
        key = oc.identity(row.get("repo"), row.get("commit"))
        record = by_identity.get(key) if key else None
        diff = (record or {}).get("diff_text")
        if not isinstance(diff, str) or not diff.strip():
            missing.append(row.get("case_id"))
            continue
        material.append({"case_id": row["case_id"], "diff": diff,
                         "truncated": bool(record.get("diff_truncated"))})

    if missing:
        raise SystemExit(
            "no diff for {} case(s): {}. Adjudicating a subset silently would "
            "produce a rate over a denominator nobody chose".format(
                len(missing), ", ".join(sorted(str(m) for m in missing))))
    return material


def ask(diff: str, timeout: int) -> Dict[str, Any]:
    """One case, one process, one turn. Never retried."""
    prompt = RUBRIC.format(diff=diff)
    command = [
        "grok", "-p", prompt,
        "--model", MODEL,
        "--sandbox", "read-only",
        "--disallowed-tools", "bash,edit,write,read,web_search,web_fetch",
        "--json-schema", json.dumps(VERDICT_SCHEMA),
        "--output-format", "json",
    ]
    # The command as it is run, with the prompt replaced by its digest: the
    # protocol asks for the command shape, and a 26 KB diff inlined into every
    # record would make the artifact unreadable without adding anything the
    # digest does not already fix.
    shape = ["<prompt>" if part is prompt else part for part in command]

    started = time.time()
    try:
        done = subprocess.run(command, capture_output=True, text=True,
                              timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        return {"failed": "timed out after {}s".format(timeout),
                "seconds": round(time.time() - started, 1),
                "command": shape,
                "prompt_digest": digest_text(prompt)}

    attempt = {"exit_code": done.returncode,
               "seconds": round(time.time() - started, 1),
               "command": shape,
               "prompt_digest": digest_text(prompt)}
    if done.returncode != 0:
        attempt["failed"] = (done.stderr or "").strip()[:400] or "non-zero exit"
        return attempt
    try:
        body = json.loads(done.stdout)
    except ValueError as exc:
        attempt["failed"] = "the CLI did not return JSON: {}".format(exc)
        return attempt

    # Decoded is not the same as shaped. A reply of `[]` or `"ok"` parses
    # fine and then raises on the first `.get`, which killed the whole run
    # without recording the attempt or writing the artifact — a crash where a
    # refusal belongs. Codex, 2026-09-04.
    if not isinstance(body, dict):
        attempt["failed"] = "the reply is {}, not an object".format(
            type(body).__name__)
        return attempt

    attempt.update({
        "session_id": body.get("sessionId"),
        "request_id": body.get("requestId"),
        "turns": body.get("num_turns"),
        "stop_reason": body.get("stopReason"),
        # The model that *answered*, not the one asked for. They differ:
        # `grok-4.6` is requested and `grok-4.6-build` answers, and this
        # repository has already been bitten once by recording the request.
        # A mapping is expected and anything else is refusal evidence, not
        # a crash: `{"modelUsage": "x"}` raised on `.keys()`.
        "model_served": sorted(body["modelUsage"].keys())
        if isinstance(body.get("modelUsage"), dict) else None,
        "cost_usd": body.get("total_cost_usd"),
    })

    # **Checked, not merely recorded.** The first version wrote all of the
    # above into the artifact and tested none of it, so a reply with
    # `num_turns: 2` — which is not the single-turn call the protocol
    # requires — still produced a verdict and exit 0. Recording evidence and
    # not reading it is a claim nothing enforces, which is the defect this
    # whole project is about. Codex, 2026-09-04.
    missing = _evidence_problems(attempt)
    if missing:
        attempt["failed"] = "; ".join(missing)
        return attempt

    structured = body.get("structuredOutput")
    if not isinstance(structured, dict):
        attempt["failed"] = "no structured output in the response"
        return attempt
    verdict = structured.get("verdict")
    if verdict not in ("ordinary", "not_ordinary", "unclear"):
        attempt["failed"] = "verdict {!r} is not one of the three".format(verdict)
        return attempt
    # The schema asks for a rationale, and the schema is the vendor's promise
    # rather than ours. A verdict with no reasoning behind it is a coin flip
    # with a label, and it must not be counted as an adjudication.
    rationale = structured.get("rationale")
    if not isinstance(rationale, str) or not rationale.strip():
        attempt["failed"] = "a verdict with no rationale is not an adjudication"
        return attempt
    attempt["verdict"] = verdict
    attempt["rationale"] = rationale
    return attempt


def _evidence_problems(attempt: Dict[str, Any]) -> List[str]:
    """Everything the protocol demands the reply demonstrate.

    Required, not forbidden. `if turns and turns != 1` would pass a reply that
    reports no turn count at all, and a missing field is exactly how this
    repository's recurring defect arrives.
    """
    problems = []
    for field, what in (("session_id", "session id"),
                        ("request_id", "provider response id")):
        value = attempt.get(field)
        if not isinstance(value, str) or not value.strip():
            problems.append(
                "no {} in the reply, so this call cannot be shown to be its "
                "own".format(what))
    # `turns == 1` alone accepts JSON `true`, because `True == 1` in Python.
    # A boolean where a count belongs is a reply this tool cannot read, not a
    # single-turn call.
    turns = attempt.get("turns")
    if isinstance(turns, bool) or not isinstance(turns, int) or turns != 1:
        problems.append(
            "{!r} turn(s); the protocol requires exactly one, and more than "
            "one means the context was not fresh".format(turns))
    # `not [""]` is False, so a list holding an empty name passed as evidence
    # that a model was named. Both edges found by Codex probing the checker
    # rather than by reading it.
    served = attempt.get("model_served")
    if not isinstance(served, list) or not any(
            isinstance(name, str) and name.strip() for name in served):
        problems.append(
            "the reply names no model, so what answered is not recorded")
    return problems


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--seal", required=True)
    parser.add_argument("--candidates", required=True)
    parser.add_argument("--out", required=True, help="directory for the record")
    parser.add_argument("--seed", type=int, default=None,
                        help="order seed; one is chosen and recorded if absent")
    parser.add_argument("--limit", type=int, default=None,
                        help="stop after N cases, for a dry run")
    parser.add_argument("--timeout", type=int, default=300)
    args = parser.parse_args(argv)

    seal_path, out = Path(args.seal), Path(args.out)
    seal = json.loads(seal_path.read_text(encoding="utf-8"))
    material = load_material(seal, Path(args.candidates))

    # Chosen before the first call and recorded, so the order is reproducible
    # and was not adjusted once answers started arriving.
    seed = args.seed if args.seed is not None else int(time.time())
    order = list(material)
    random.Random(seed).shuffle(order)
    if args.limit:
        order = order[:args.limit]

    out.mkdir(parents=True, exist_ok=True)
    record = {
        "schema": SCHEMA_VERSION,
        "started_at": datetime.now(timezone.utc).isoformat(),
        "adjudicated_by": "model",
        "vendor": VENDOR,
        "model_requested": MODEL,
        "cli_version": subprocess.run(
            ["grok", "--version"], capture_output=True, text=True,
            check=False).stdout.strip(),
        "seal": {"path": str(seal_path), "digest": oc.digest_file(seal_path)},
        "rubric_digest": digest_text(RUBRIC),
        "schema_digest": digest_text(json.dumps(VERDICT_SCHEMA, sort_keys=True)),
        "order_seed": seed,
        "order": [c["case_id"] for c in order],
        "cases": {},
        # Said in the artifact, not only in the decision, because the artifact
        # is what a later reader opens.
        "what_this_is_not": (
            "Structured third-vendor measurement, not human ground truth. The "
            "record shows each call was a separate process carrying one "
            "message; it cannot show what the provider keeps on its own side, "
            "and it cannot establish that this model never saw D-013."),
    }

    for index, case in enumerate(order, start=1):
        print("[{}/{}] {} ...".format(index, len(order), case["case_id"]),
              flush=True)
        attempt = ask(case["diff"], args.timeout)
        attempt["diff_digest"] = digest_text(case["diff"])
        attempt["diff_truncated"] = case["truncated"]
        attempt["asked_at"] = datetime.now(timezone.utc).isoformat()
        record["cases"][case["case_id"]] = attempt
        print("      {}".format(attempt.get("verdict")
                                or "NO VERDICT: " + str(attempt.get("failed"))),
              flush=True)

    record["finished_at"] = datetime.now(timezone.utc).isoformat()
    verdicts = [c.get("verdict") for c in record["cases"].values()]
    record["counts"] = {
        name: verdicts.count(name)
        for name in ("ordinary", "not_ordinary", "unclear")
    }
    record["counts"]["no_verdict"] = sum(1 for v in verdicts if v is None)
    # Over the cases that produced a verdict, and counted without dropping
    # the ones that carry no id. The first version filtered those out first,
    # so a run where *every* reply lacked a session id reported
    # `sessions_distinct: True` — the absence certifying the property it was
    # meant to demonstrate. An id is required for a verdict now, so this is a
    # second reading of the same fact rather than the only one.
    judged = [c for c in record["cases"].values() if c.get("verdict")]
    ids = [c.get("session_id") for c in judged]
    requests = [c.get("request_id") for c in judged]
    record["sessions_distinct"] = bool(judged) and len(set(ids)) == len(ids)
    record["responses_distinct"] = bool(judged) and \
        len(set(requests)) == len(requests)

    path = out / "grok-adjudication.json"
    path.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8")
    print()
    print("{} case(s) into {}".format(len(record["cases"]), path))
    print("  {}".format(record["counts"]))
    print("  every call its own session: {}".format(record["sessions_distinct"]))
    # Exit 2 when anything failed to produce a verdict: a partial answer key is
    # not an answer key, and this repository never returns success for "I could
    # not check".
    return 2 if record["counts"]["no_verdict"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
