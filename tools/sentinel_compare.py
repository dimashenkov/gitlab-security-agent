#!/usr/bin/env python3
"""Apply the frozen threshold to a challenger's runs. The rule, as code.

The reference was frozen with a threshold written into it, and a threshold
written in prose is a threshold nothing applies. This is the code that applies
it — written *before* the challenger's runs are bought, so it cannot be shaped
by what they turn out to say, and exercised against synthetic files of the shape
those runs will have.

    tools/sentinel_compare.py measurements/reference/sentinel-opus.json \\
        run-1.json run-2.json

## What it counts, and what it refuses to count

A **confirmed regression** is one case answering worse in *two* separate
challenger runs of the same system identity. One run is never enough: the
reference itself disagreed with itself on two of thirteen cases, so a single
`pass -> fail` is as likely to be the suite moving as the model being worse.

**Net** is the count of confirmed regressions. Improvements are reported beside
them and do not cancel them: finding a weakness in one case does not put back
the weakness missed in another.

Rule 1 did subtract, and this paragraph used to say so — two worse and two
better was a net of zero and, the code decided, "passes the gate". The
reference answers exactly two of its eleven cases with a failure, so exactly two
improvements existed to buy exactly two regressions; the permissive path was the
rule's whole width, not a corner of it. It also contradicted the paragraph below:
this file refuses to order a missed weakness against a false alarm *inside* one
case, then netted the same two harms across cases as interchangeable. Nothing
here weighs them, so nothing here trades them. That is a policy choice a
security gate is allowed, not a statistical claim.

**Worse** is not one number. A case can fail by missing the weakness or by
flagging the fix, and those are different harms; summing them lets one hide the
other. So a `fail -> fail` case counts downward only when a failure it did not
have appears — never by trading one for the other, which is reported as
`traded` and decides nothing on its own.

## What makes it refuse

Anything it cannot read as a verdict about the case in front of it: a missing
case, a duplicate, a row about another case, a `pair_success` that is not a
boolean, a case digest that does not match the reference, or two challenger
runs whose system identity differs. Every one of those has a way of becoming a
quiet zero, and a quiet zero here reads as "the cheaper model is fine".
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))


class ComparisonError(Exception):
    """The inputs cannot answer the question."""


# One definition of "the same system", not a second one written here. The first
# version of this file carried its own, and it left out the schema, the agent
# version, the provider and almost every setting — so two runs that differed in
# any of those confirmed each other. Two definitions of the same idea in one
# repository is a defect by construction: they drift, and the weaker one is the
# one that decides.
from baseline import _system_identity  # noqa: E402

# 2, because the arithmetic changed. Rule 1 computed `regressions -
# improvements`; rule 2 counts regressions and reports improvements beside
# them. A reference frozen under rule 1 is refused rather than re-decided —
# its numbers were agreed to under different arithmetic, and applying today's
# to yesterday's frozen file is how a threshold gets fitted to the result it
# is supposed to judge.
RULE_VERSION = 2

# What the reference's `environment` has to say, and what the comparison reads
# out of it — one list, so a field required in one place and ignored in the
# other cannot happen. Each maps to the provenance field a challenger row must
# match it against.
ENVIRONMENT_FIELDS = (
    ("system_prompt", "system_prompt_sha"),
    ("verifier_prompt", "verifier_prompt_sha"),
    ("findings_schema", "schema_sha"),
    ("agent_version", "agent_version"),
)


def _shape(row: dict, where: str) -> dict:
    """The two kinds of failure, and neither of them coerced.

    `bool(row.get(...))` read a missing `safe_false_positive` as "no false
    alarm" and the string "false" as one. Either quietly moves a case between
    counted and not counted, and the direction nobody checks is the one that
    hides a gained failure.
    """
    out = {}
    for field, kind in (("unsafe_recall", "missed"),
                        ("safe_false_positive", "false_alarm")):
        value = row.get(field)
        if not isinstance(value, bool):
            raise ComparisonError(
                "{}: `{}` is {!r}, which is not a verdict".format(
                    where, field, value))
        out[kind] = (not value) if kind == "missed" else value
    return out


def _is_name_list(value) -> bool:
    """A list of non-blank names, and a `str` is not one.

    Written once because the same predicate is needed in four places and got
    it wrong differently each time. The `str` exclusion is the point: Python
    iterates a string into characters, so `"claude-opus-5"` passes any check
    that only asks whether the value can be walked, and the comparison then
    runs against thirteen one-letter model names instead of refusing.
    """
    return (isinstance(value, (list, tuple))
            and all(isinstance(m, str) and m.strip() for m in value))


def _reference_shape(entry: dict, case_id: str) -> dict:
    """How the reference failed — and only when both its passes agree.

    Reading `shape["pass-a"]` picked one pass by position. A reference stable
    on `pair_success` can still fail two different ways across its passes, and
    then "did a new kind of failure appear" has no answer to be measured
    against. Refusing is the answer; guessing which pass to believe is not.
    """
    shapes = entry.get("shape") or {}
    kinds = {k: {shape.get(k) for shape in shapes.values()}
             for k in ("missed", "false_alarm")}
    disagreed = [k for k, values in kinds.items() if len(values) != 1]
    if disagreed:
        raise ComparisonError(
            "{}: the reference failed differently in its two passes ({}), so "
            "there is nothing to measure a change of shape against".format(
                case_id, ", ".join(sorted(disagreed))))
    return {k: values.pop() for k, values in kinds.items()}


def _rows_at(path: Path) -> list:
    """The rows of one run, whether it is a file or a directory of files.

    `experiment.py` writes one file per case under a pass directory, and this
    tool first accepted only a single file holding the whole pass. Pointed at
    the real layout it read each case file as a separate run and refused for
    missing cases — so the paid results could not be handed to the thing that
    was built to read them, which is a worse failure than reading them wrongly
    because it looks like the tool is broken rather than the input.
    """
    path = Path(path)
    if path.is_dir():
        files = sorted(path.glob("*.json"))
        if not files:
            raise ComparisonError("{}: no result files in it".format(path))
        rows = []
        for one in files:
            body = json.loads(one.read_text(encoding="utf-8"))
            rows.extend(body if isinstance(body, list) else [body])
        return rows
    body = json.loads(path.read_text(encoding="utf-8"))
    return body if isinstance(body, list) else [body]


def _check_row_shape(case_id: str, row: dict) -> None:
    """The structural contract of one challenger row, checked at the boundary.

    Codex, 2026-09-05, after twenty-four review rounds on one change, each
    finding a different nested field escaping through a different path — a
    `models_served` that was a bare string, a `settings` erased by `or {}`, a
    `run_id` that was a list, a `model_substituted` that said `true` and passed
    a check documented as requiring `false`:

    > 24 rounds of malformed nested fields escaping through different paths is
    > strong evidence that these documents need structural schema validation
    > immediately after parsing. Semantic checks — cross-run uniqueness, model
    > consistency, threshold feasibility — still belong in code, but container
    > types, required keys, booleans and non-blank strings should be enforced
    > once at the boundary. Field-by-field guards are demonstrably not
    > converging reliably enough on their own.

    So this runs for **every** row of every run, not for the comparable ones
    only: the last defect of the series was that rows belonging to
    `unstable_under_reference` skipped the guards entirely and still fed the
    provenance and system-identity comparisons.
    """
    stamp = row.get("run_id")
    if not isinstance(stamp, str) or not stamp.strip():
        raise ComparisonError(
            "{}: a row records {!r} for `run_id`, so nothing names which "
            "execution it is".format(case_id, stamp))

    members = row.get("members")
    if not isinstance(members, dict):
        raise ComparisonError(
            "{}: the run records {} for `members`, where the safe and unsafe "
            "blocks are required".format(case_id, type(members).__name__))

    # The pair, by name, at the boundary. It was checked in `compare()` and
    # formatted its complaint with `", ".join(sorted(members))`, which crashes
    # on a key that is not a string — so a row with a non-string member key
    # passed this function and raised `TypeError` where a refusal belonged.
    # Codex, 2026-09-05. JSON cannot produce such a key; an in-process caller
    # can, and the contract belongs in one place either way.
    if set(members) != {"safe", "unsafe"}:
        raise ComparisonError(
            "{}: a pair is a safe and an unsafe member, and this row has "
            "{}".format(case_id,
                        ", ".join(sorted(repr(k) for k in members)) or
                        "neither"))

    for label, block in members.items():
        if not isinstance(block, dict):
            raise ComparisonError(
                "{}: the run records {} for its {} member, where a block with "
                "`provenance` is required".format(
                    case_id, type(block).__name__, label))
        prov = block.get("provenance")
        if not isinstance(prov, dict):
            raise ComparisonError(
                "{}: the {} member records {} for `provenance`, so nothing "
                "says what answered it".format(
                    case_id, label, type(prov).__name__))

        # `is not False`, not `is not None`. The comment that stood over this
        # check said "required to be false and present, not merely not-true"
        # while the code implemented "not absent", so a run recording
        # `model_substituted: true` — the provider saying in as many words
        # that it answered with a different model — went through.
        substituted = prov.get("model_substituted")
        if substituted is not False:
            raise ComparisonError(
                "{}: `model_substituted` is {!r}. The run has to say the "
                "provider did *not* substitute the model — {}".format(
                    case_id, substituted,
                    "and this run says it did" if substituted is True else
                    "absent and unreadable are both 'nobody checked', and "
                    "this experiment is about which model was asked"))

        served = prov.get("models_served")
        if not served:
            raise ComparisonError(
                "{}: the run records no served model, so nothing says which "
                "model answered".format(case_id))
        if not _is_name_list(served):
            raise ComparisonError(
                "{}: the run records {} for `models_served`, where a list of "
                "model names is required".format(
                    case_id, type(served).__name__))

        # Absence means `[]` because absence here has a defined meaning — the
        # verifier only fires when there is something to verify. A value that
        # is present and cannot be read has no such meaning, and `or []` used
        # to turn `0`, `""` and `{}` into "nothing was verified", which this
        # file then acts on.
        verified = prov.get("models_verified", [])
        if not _is_name_list(verified):
            raise ComparisonError(
                "{}: the run records {} for `models_verified`, where a list of "
                "model names is required".format(
                    case_id, type(verified).__name__))

        settings = block.get("settings", {})
        if not isinstance(settings, dict):
            raise ComparisonError(
                "{}: a member records {} for `settings`, where an object is "
                "required".format(case_id, type(settings).__name__))


def read_run(path: Path, expected: dict) -> dict:
    """One challenger run: case id to row, refusing anything ambiguous."""
    rows = _rows_at(path)
    out = {}
    for row in rows:
        if not isinstance(row, dict):
            raise ComparisonError("{}: holds something that is not a row"
                                  .format(path))
        case_id = row.get("case_id")
        if case_id not in expected:
            raise ComparisonError(
                "{}: {!r} is not in the reference. A run of other cases cannot "
                "be compared against it.".format(path, case_id))
        if case_id in out:
            raise ComparisonError(
                "{}: {} appears twice, and one file is one run".format(
                    path, case_id))
        if not isinstance(row.get("pair_success"), bool):
            raise ComparisonError(
                "{}: {} has `pair_success` {!r}, which is not a verdict"
                .format(path, case_id, row.get("pair_success")))
        if row.get("case_digest") != expected[case_id]["case_digest"]:
            raise ComparisonError(
                "{}: {} measured a different version of the case than the "
                "reference did".format(path, case_id))
        _check_row_shape(case_id, row)
        out[case_id] = row
    return out


REF_USABLE = "usable"
REF_RETIRED = "retired"
REF_UNUSABLE = "unusable"
REF_CANNOT_TELL = "cannot tell"

REF_STATES = (REF_USABLE, REF_RETIRED, REF_UNUSABLE, REF_CANNOT_TELL)


class ReferenceState:
    """Everything about a baseline that can be established without runs.

    Extracted from `compare()` on 2026-09-05 so that a second reader — the
    D-013 order tool, which reports whether the Sonnet gate can be attempted at
    all — asks this file rather than reimplementing its rules. Codex, the same
    day: the comparator owns considerably more than the `retired` key (rule
    compatibility, thresholds, missing cases, duplicate comparable entries,
    environment presence, two-pass shapes, partition integrity, enough passing
    cases to detect the threshold), and a second implementation of that list
    would be the weaker one, deciding.

    It carries the parsed body and its digest so the two readers speak about
    the same bytes. `compare()` consumes `.reference` and does not reopen the
    path — Codex again: sharing a validator is not sharing an input, and a file
    can change between one read and the next.

    No truth value. `usable`, `retired`, `unusable` and `cannot tell` are four
    answers, and the last is not the third.
    """

    __slots__ = ("digest", "path", "reference", "state", "why")

    def __init__(self, state, why, path, reference=None, digest=None):
        if state not in REF_STATES:
            raise ValueError("unknown reference state {!r}".format(state))
        self.state = state
        self.why = why
        self.path = path
        self.reference = reference
        self.digest = digest

    def __bool__(self):
        raise TypeError(
            "a reference state is not a boolean: it is {!r}. A retired "
            "baseline and one that could not be read are different answers, "
            "and neither is usable.".format(self.state))

    def __repr__(self):
        return "ReferenceState({!r}, {!r})".format(self.state, str(self.path))


def validate_reference(reference_path) -> ReferenceState:
    """The baseline, judged on its own — no challenger runs involved.

    Never raises for a bad reference: it reports. A caller that wants the old
    behaviour asks for `.state` and raises itself, which `compare()` does.
    """
    path = Path(reference_path)
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        return ReferenceState(REF_CANNOT_TELL, (
            "the reference at {} could not be read ({}: {}), which is not the "
            "same as there being nothing wrong with it".format(
                path, type(exc).__name__, exc)), path)
    try:
        reference = json.loads(text)
    except ValueError as exc:
        return ReferenceState(REF_CANNOT_TELL, (
            "the reference at {} is not readable JSON ({}), so none of its "
            "fields were interpreted".format(path, exc)), path)
    if not isinstance(reference, dict):
        return ReferenceState(REF_CANNOT_TELL, (
            "the reference at {} holds {} where an object is required".format(
                path, type(reference).__name__)), path)

    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()

    def refuse(state, why):
        return ReferenceState(state, why, path, reference, digest)

    try:
        _reference_problems(reference)
    except ComparisonError as exc:
        state = REF_RETIRED if str(exc).startswith("this reference is retired") \
            else REF_UNUSABLE
        return refuse(state, str(exc))
    except Exception as exc:
        # The promise in this function's docstring, kept rather than asserted.
        # Every shape a reference can be wrong in is meant to leave here as a
        # `ComparisonError`; anything that does not is a hole in that list, and
        # a hole means the reference was not judged — which is `cannot tell`,
        # never `usable`. A traceback out of the CLI is the same information
        # delivered as a crash.
        return refuse(REF_CANNOT_TELL, (
            "judging the reference at {} raised {}: {} — the baseline was not "
            "established either way, and this is a gap in the checks above "
            "rather than a verdict about the file".format(
                path, type(exc).__name__, exc)))
    return refuse(REF_USABLE, (
        "the baseline at {} describes a comparison: {} comparable case(s), "
        "rule version {}, {} confirmation(s) required".format(
            path, len(reference["comparable"]),
            reference["threshold"]["rule_version"],
            reference["threshold"]["confirmations_required"])))


def _reference_problems(reference: dict) -> None:
    """Raise the first thing wrong with the baseline, or return.

    The body of what `compare()` used to do inline before it opened a single
    run. Kept as raise-on-first rather than a list because every one of these
    makes the ones after it meaningless — a reference with no `threshold` has
    nothing for the threshold checks to say.
    """
    # Asked first, and asked of the reference rather than of the runs. A
    # retired reference is one somebody has already established cannot answer
    # the question, and every check below it would then report a *reason* — a
    # served-model set, a verifier — for a file that is not a baseline at all,
    # sending the reader to fix the symptom.
    #
    # It is also the first thing *read*, which it was not: `cases` and
    # `comparable` were indexed above it, so `{"retired": true}` raised
    # `KeyError('cases')` — a traceback out of the CLI where a refusal belongs.
    # Codex, 2026-09-05.
    # **Presence, not truthiness.** Codex, 2026-09-05: `if retired:` treats
    # `false`, `null`, `0`, `""`, `[]` and `{}` exactly as it treats a file
    # that never mentioned retirement, so a reference carrying a malformed
    # retirement marker was classified usable. That is this repository's own
    # recurring defect — an absence read as agreement — sitting on the field
    # that decides whether a baseline is a baseline at all.
    #
    # The only accepted way to say "not retired" is to omit the key. A present
    # `retired` must be an object naming why, and anything else is refused with
    # instructions rather than resolved in the file's favour.
    if "retired" in reference:
        retired = reference["retired"]
        if not isinstance(retired, dict) or not retired:
            raise ComparisonError(
                "this reference declares `retired` as {!r}, which says neither "
                "that it is a baseline nor why it is not. Omit the key to say "
                "the reference is live, or give an object with a `why` — a "
                "marker nobody can read is refused rather than guessed"
                .format(retired))
        raise ComparisonError(
            "this reference is retired and is not a baseline: {}".format(
                retired.get("why", "no reason recorded")))

    # The shapes, before anything indexes them. `validate_reference` promises
    # its callers that a bad reference is reported rather than raised, and that
    # promise was only true for the files that happened to have these keys.
    for name, kind, what in (("cases", dict, "an object of case records"),
                             ("comparable", list, "a list of case ids"),
                             ("threshold", dict, "an object")):
        if not isinstance(reference.get(name), kind):
            raise ComparisonError(
                "the reference has no usable `{}`: it holds {} where {} is "
                "required, so nothing below could be checked".format(
                    name, type(reference.get(name)).__name__, what))

    cases = reference["cases"]
    comparable = list(reference["comparable"])
    threshold = reference["threshold"]

    # The rule is versioned rather than described by flags. Three booleans sat
    # in the frozen file saying what the comparison does, and nothing read
    # them: a setting nobody applies is a claim, and a claim in a frozen file
    # is worse than none because it reads as configuration.
    if threshold.get("rule_version") != RULE_VERSION:
        raise ComparisonError(
            "the reference was frozen under rule version {!r} and this "
            "comparator implements {}. A rule that changed is a different "
            "question.".format(threshold.get("rule_version"), RULE_VERSION))

    # A reference that does not describe a comparison cannot produce a verdict,
    # and every one of these ends as a quiet `net: 0` — which reads as the
    # cheaper model being fine.
    #
    # The first version checked the challenger's rows strictly and took the
    # reference on trust, which is backwards: the reference decides what the
    # challenger is measured against.
    for name in ("reject_at_net", "confirmations_required"):
        value = threshold.get(name)
        if not isinstance(value, int) or isinstance(value, bool) or value < 1:
            raise ComparisonError(
                "the frozen `{}` is {!r}; a threshold has to be a whole "
                "number of cases".format(name, value))
    # Five places below read a field without first asking what it is, and
    # Codex found them one per round on 2026-09-05 — `outcomes` as a list whose
    # `set()` has the right names and whose `.items()` does not exist, `missing`
    # as a number `sorted()` cannot walk, a case id that is itself a list and so
    # cannot be looked up, `unstable_under_reference` as a scalar `set()`
    # refuses, `environment` as anything at all provided it is truthy. Every
    # one became an `AttributeError` or a `TypeError` that the catch-all in
    # `validate_reference` reported as "could not tell" about a file whose
    # defect has a name.
    #
    # Repaired together rather than one per round: the class is "a container
    # read for its contents before anything asked whether it is that
    # container", and fixing the instance leaves the class.
    if "missing" in reference:
        missing = reference["missing"]
        if not _is_name_list(missing):
            raise ComparisonError(
                "the reference records `missing` as {}, where a list of case "
                "ids is required".format(type(missing).__name__))
        if missing:
            raise ComparisonError(
                "the reference is missing {}, so it describes a narrower suite "
                "than the one it names".format(", ".join(sorted(missing))))

    bad_ids = [] if _is_name_list(comparable) else [
        c for c in comparable if not isinstance(c, str) or not c.strip()]
    if bad_ids:
        raise ComparisonError(
            "the comparable list holds {!r}, where case ids are required — a "
            "value that is not a name cannot be looked up in `cases`".format(
                bad_ids[0]))
    if len(comparable) != len(set(comparable)):
        raise ComparisonError(
            "a case is listed twice among the comparable ones, which counts "
            "one measurement more than once")
    # Asked here rather than after the per-case loops: an empty comparable list
    # makes every complaint below it a detail of a file that could not have
    # answered the question anyway, and the reader would be sent to fix the
    # detail.
    if not comparable:
        raise ComparisonError(
            "the reference has no comparable cases, so there is nothing this "
            "comparison could have found")

    # Required, not merely well-shaped when present. The first version of this
    # very check wrote `if unstable is not None and ...`, which exempted both
    # `null` and an absent key — and `compare()` calls `len()` on the field a
    # hundred lines later. Codex, 2026-09-05, on the sweep that was written to
    # end this class: the exemption is the class, reintroduced inside the fix
    # for it. A reference that never says which cases were unstable has not
    # said none were.
    unstable = reference.get("unstable_under_reference")
    if not _is_name_list(unstable):
        raise ComparisonError(
            "the reference records `unstable_under_reference` as {}, where a "
            "list of case ids is required — a reference that does not say "
            "which cases were unstable has not said that none were".format(
                type(unstable).__name__))
    # The same rule the comparable list carries, and it was missing here:
    # `set()` a hundred lines below collapses a repeat silently, while the
    # number this file *prints* for how many cases were unstable counts the
    # list. Codex, 2026-09-05.
    if len(unstable) != len(set(unstable)):
        raise ComparisonError(
            "a case is listed twice among the unstable ones, which reports one "
            "exclusion as two")

    if not isinstance(reference.get("environment"), dict) or \
            not reference["environment"]:
        raise ComparisonError(
            "the reference records no environment, so there is nothing for a "
            "challenger to be held against")
    # And the fields the comparison actually reads. Codex, 2026-09-05:
    # `{"host": "x"}` satisfied "records an environment" while recording none
    # of them, and the loop that holds a challenger to the environment skipped
    # every field the reference left out — so a baseline with an environment
    # object full of nothing gave every challenger a free pass on the prompts,
    # the schema and the agent version, and the run that changed all four
    # would have been reported as a model comparison.
    for field, _ in ENVIRONMENT_FIELDS:
        value = reference["environment"].get(field)
        if not isinstance(value, str) or not value.strip():
            raise ComparisonError(
                "the reference's environment records {!r} for `{}`. A "
                "challenger is held to every part of it that is written down, "
                "so a part left out is a part nobody checks".format(
                    value, field))

    # `observed_models` is read with `.items()` a hundred lines below and was
    # validated nowhere, so a truthy non-mapping crashed the comparator *after*
    # `validate_reference` had called the baseline usable. Codex, 2026-09-05:
    # the sweep validated the containing mappings and not the nested ones.
    # The models the baseline is *about*, checked here rather than a hundred
    # lines into the comparison. Codex, 2026-09-05: `compare()` refuses a
    # reference that names no `verifier_model`, but only once challenger runs
    # are in hand — so `validate_reference` called such a baseline usable and
    # the order tool reported the Sonnet gate's inputs as established for a
    # file the comparison was certain to reject. The same precondition-only-on-
    # the-spending-path defect as the two-pass agreement check, one field over.
    for name in ("model", "verifier_model"):
        value = reference.get(name)
        if not isinstance(value, str) or not value.strip():
            raise ComparisonError(
                "the reference records {!r} for `{}`, so it does not say which "
                "model it is a baseline for and a challenger cannot be held to "
                "it".format(value, name))

    observed = reference.get("observed_models")
    if observed is not None:
        if not isinstance(observed, dict):
            raise ComparisonError(
                "the reference records `observed_models` as {}, where an "
                "object naming the models each member was answered by is "
                "required".format(type(observed).__name__))
        # And its values, not only the outer mapping. Codex, 2026-09-05:
        # `{"safe": 3}` passed and crashed at `for m in expected`, and
        # `{"safe": "claude-opus-5"}` was worse — a string walks into
        # characters, so the comparison ran against thirteen one-letter model
        # names and produced an answer instead of a refusal.
        for member, names in sorted(observed.items()):
            if not _is_name_list(names):
                raise ComparisonError(
                    "the reference records {} for `observed_models[{!r}]`, "
                    "where a list of model names is required".format(
                        type(names).__name__, member))
    for case_id in comparable:
        if case_id not in cases:
            raise ComparisonError(
                "{}: listed among the comparable cases and absent from "
                "`cases`, so the reference names a case it does not "
                "hold".format(case_id))

    # **Every** record, not the comparable ones only. Codex, 2026-09-05, the
    # mirror image of the defect that moved the challenger checks to the
    # boundary: `read_run` reads `expected[case_id]["case_digest"]` for every
    # case the reference holds, unstable ones included, and this loop covered
    # `comparable`. So a record missing its digest passed `validate_reference`
    # as usable and raised `KeyError` from `read_run` instead of a refusal.
    #
    # The agreement check further down stays comparable-only, and for a
    # reason: an unstable case is *defined* by its two passes disagreeing, so
    # asking it to agree would refuse every reference that records one.
    for case_id, entry in sorted(cases.items()):
        # The record itself, before anything reads a field off it. Codex,
        # 2026-09-05: `cases[case_id]` raised `KeyError` for a comparable id
        # the `cases` block does not hold, and `entry.get(...)` raised
        # `AttributeError` for a record that is `null` or a list — both
        # absorbed by the catch-all in `validate_reference` and reported as
        # "could not tell". These are shapes with names; a named shape belongs
        # in the list, or the catch-all starts answering questions that had an
        # answer.
        if not isinstance(entry, dict):
            raise ComparisonError(
                "{}: the reference holds {} for this case, where a record with "
                "`outcomes` and `shape` is required".format(
                    case_id, type(entry).__name__))
        # Both passes, named. A reference carrying one outcome is a reference
        # that never checked itself for stability, and the whole exclusion of
        # unstable cases rests on having two.
        outcomes = entry.get("outcomes")
        # `isinstance` first, and then the names. `["pass-a", "pass-b"]` has
        # exactly the right `set()` and no `.items()` at all, so the name check
        # passed and the loop below raised.
        if not isinstance(outcomes, dict) or \
                set(outcomes) != {"pass-a", "pass-b"}:
            raise ComparisonError(
                "{}: the reference records {} outcome(s), and it takes two to "
                "know whether it agreed with itself".format(
                    case_id,
                    len(outcomes) if isinstance(outcomes, dict) else
                    "no usable"))
        for label, verdict in outcomes.items():
            if not isinstance(verdict, bool):
                raise ComparisonError(
                    "{}: the reference records {!r} for {}, which is not a "
                    "verdict".format(case_id, verdict, label))
        # Both passes, by name, exactly as `outcomes` above demands them.
        # Codex, 2026-09-05: `_reference_shape` reduces the shapes it finds to
        # a set and accepts any set of size one, so a case recording *one*
        # shape passed as two passes agreeing — the missing pass supplying the
        # agreement. Arbitrary labels passed too, as long as their values
        # matched. Require the pair; do not infer it from what is there.
        shapes = entry.get("shape")
        if not isinstance(shapes, dict) or set(shapes) != {"pass-a", "pass-b"}:
            raise ComparisonError(
                "{}: the reference records shapes for {}, and agreement about "
                "how a case failed takes both passes by name".format(
                    case_id,
                    ", ".join(sorted(map(repr, shapes))) if isinstance(
                        shapes, dict) and shapes else "nothing"))
        for label, shape in shapes.items():
            # The pass itself, before its fields. Codex, 2026-09-05:
            # `"pass-a": null` reached `shape.get(...)`, raised
            # `AttributeError`, and the catch-all in `validate_reference`
            # turned a known-malformed reference into "I could not tell" — the
            # two answers this repository keeps apart everywhere else.
            if not isinstance(shape, dict):
                raise ComparisonError(
                    "{}: the reference records {} for {}, where an object with "
                    "`missed` and `false_alarm` is required".format(
                        case_id, type(shape).__name__, label))
            for kind in ("missed", "false_alarm"):
                if not isinstance(shape.get(kind), bool):
                    raise ComparisonError(
                        "{}: the reference records {!r} for {} in {}, which "
                        "is not a verdict".format(
                            case_id, shape.get(kind), kind, label))
        # `read_run` compares every challenger row against this digest, for
        # every case the reference holds — so it is required here, for every
        # case, rather than assumed. Without it that comparison raised
        # `KeyError` from inside a function whose caller had already been told
        # the baseline was usable.
        digest = entry.get("case_digest")
        if not isinstance(digest, str) or not digest.strip():
            raise ComparisonError(
                "{}: the reference records {!r} for `case_digest`, so nothing "
                "says which version of the case it measured".format(
                    case_id, digest))

        # The same fact is written twice — once as this flag and once by
        # membership of the top-level list — and only the list was checked.
        # Codex, 2026-09-05: so a stable case could carry the flag while
        # sitting in `comparable`, and the invariant held for one
        # representation of the fact and not for the other. Two spellings of
        # one thing must agree or one of them is decoration.
        flag = entry.get("unstable_under_reference")
        listed = case_id in set(reference["unstable_under_reference"])
        if not isinstance(flag, bool) or flag != listed:
            raise ComparisonError(
                "{}: the record says `unstable_under_reference` is {!r} and "
                "the reference's own list says {}. The same fact written two "
                "ways has to say the same thing".format(
                    case_id, flag, listed))

    # Whether the two passes agree about *how* the case failed is a fact about
    # the reference alone, and it was only asked inside the comparison loop.
    # Codex, 2026-09-05: so `validate_reference` could answer `usable` — and
    # the order tool could report the Sonnet gate's inputs as established — for
    # a baseline `compare()` was certain to refuse before it looked at a single
    # challenger row. A precondition checked only on the path that spends is
    # not a precondition.
    #
    # Comparable only, deliberately: an unstable case is the one whose passes
    # disagree, and demanding agreement of it would refuse every reference that
    # honestly records one.
    for case_id in comparable:
        _reference_shape(cases[case_id], case_id)

    # And the other side of the same label. Codex, 2026-09-05: the validator
    # proved the comparable cases agree with themselves and never proved the
    # unstable ones disagree — so a perfectly stable case could be listed as
    # unstable, pass the partition check below, and be dropped from the
    # comparison. A sample narrowed by a word, which is the shape this file
    # refuses under the name "a case dropped from both".
    #
    # The condition is the one `sentinel_reference.py` uses when it writes the
    # label: `len(set(outcomes.values())) > 1`. Written as the same test rather
    # than a similar one, because the builder and the reader disagreeing about
    # what the word means is how the label stops meaning anything.
    for case_id in reference["unstable_under_reference"]:
        if case_id not in cases:
            raise ComparisonError(
                "{}: listed as unstable and absent from `cases`, so the "
                "reference excludes a case it does not hold".format(case_id))
        verdicts = set(cases[case_id]["outcomes"].values())
        if len(verdicts) <= 1:
            raise ComparisonError(
                "{}: listed as unstable and its two passes agree ({}). A case "
                "excluded from the comparison for instability it does not have "
                "narrows the sample by a word".format(
                    case_id, verdicts.pop() if verdicts else "no outcomes"))

    unstable = set(reference.get("unstable_under_reference") or ())
    if set(comparable) | unstable != set(cases) or set(comparable) & unstable:
        raise ComparisonError(
            "the reference's comparable cases and its unstable ones do not "
            "add up to the cases it holds; a case dropped from both is a "
            "sample quietly narrowed")
    steady_passes = sum(1 for c in comparable
                        if all(cases[c]["outcomes"].values()))
    if steady_passes < threshold["reject_at_net"]:
        raise ComparisonError(
            "only {} comparable case(s) passed under the reference, and the "
            "threshold needs {} regressions to reject. A reference with "
            "nothing to lose cannot detect a `pass -> fail` at all.".format(
                steady_passes, threshold["reject_at_net"]))


def compare(reference_path, run_paths: list) -> dict:
    """The comparison itself. The baseline is judged first, by the function the
    order tool also calls, and its already-parsed body is used from here on —
    reopening the path would let the two readers speak about different bytes."""
    state = validate_reference(reference_path)
    if state.state != REF_USABLE:
        raise ComparisonError(state.why)
    reference = state.reference
    cases = reference["cases"]
    comparable = list(reference["comparable"])
    threshold = reference["threshold"]

    if len(run_paths) < threshold["confirmations_required"]:
        raise ComparisonError(
            "{} run(s) given, and the frozen threshold needs {}. The reference "
            "disagreed with itself on {} of {} cases — one run cannot tell a "
            "worse model from the suite moving.".format(
                len(run_paths), threshold["confirmations_required"],
                len(reference["unstable_under_reference"]), len(cases)))

    runs = [read_run(Path(p), cases) for p in run_paths]

    # Two files are not two executions — and `run_id` is stamped **per case**,
    # not per pass: `pair_corpus.run_case` gives every case its own uuid. The
    # first version of this check demanded one stamp per file, which no
    # producer here writes, so the real pass directories would have been
    # refused on the first case. The test passed only because it hand-wrote a
    # shape the code never emits, which is the defect it was written against.
    #
    # What "two executions" means is that no case was measured once and counted
    # twice: for each case, its stamps across the runs must all differ.
    # Whether each stamp *is* a name is settled at the boundary, for every row
    # of every run. What is left here is the one thing that needs more than one
    # row to answer: no case was measured once and counted twice.
    for case_id in comparable:
        stamps = [run[case_id]["run_id"] for run in runs if case_id in run]
        if len(set(stamps)) != len(stamps):
            raise ComparisonError(
                "{}: the same execution appears in two of the files. A "
                "repetition has to be repeated.".format(case_id))

    # A substitution is a fact about the run, checked by name. It used to be
    # smuggled into the identity through `models_served`, where it split cases
    # from one run into two systems — because the verifier only fires when
    # there is something to verify. It says the plain thing instead: a review
    # the provider answered with another model did not measure the model it
    # names, and this whole experiment is about which model was asked.
    #
    # That check, and every other structural one over a challenger row, now
    # lives in `_check_row_shape` and runs from `read_run` — for every row,
    # including the ones belonging to `unstable_under_reference`, which is how
    # the last of them escaped. Two copies of one contract drift, and the
    # weaker copy is the one that decides, so there is one.
    for run in runs:
        for case_id, row in run.items():
            # Plain access, not `or {}`. `read_run` has already refused every
            # row whose `members` is not a mapping of mappings, so a tolerant
            # read here would only hide a change to that guarantee.
            members = row["members"]
            for block in members.values():
                prov = block["provenance"]
                # The unmodified value, then the check. Codex, 2026-09-05: this
                # was written `block.get("settings") or {}` **inside the fix
                # for this class** — the tolerant read turns `null` into an
                # empty object before anything can refuse it, so the malformed
                # container is erased by the line that was supposed to catch
                # it. An absent `settings` is a different matter and stays
                # allowed, because `verify_model` falls back to the requested
                # model; a `settings` that is present and is not an object has
                # said something, and what it said cannot be read.
                settings = block.get("settings", {})
                if not isinstance(settings, dict):
                    raise ComparisonError(
                        "{}: a member records {} for `settings`, where an "
                        "object is required".format(
                            case_id, type(settings).__name__))
                wanted = settings.get("verify_model") or prov.get(
                    "model_requested")
                # Validated before it is defaulted, which is the whole of this
                # class: `or []` turns `0`, `""` and `{}` into an empty list,
                # so a malformed field arrives as "nothing was verified" — a
                # meaningful answer this file acts on. And a bare string walks
                # into characters below. Absence still means `[]`, because
                # absence here has a defined meaning; a present value that
                # cannot be read does not. Codex, 2026-09-05.
                verified = prov.get("models_verified", [])
                if not _is_name_list(verified):
                    raise ComparisonError(
                        "{}: the run records {} for `models_verified`, where a "
                        "list of model names is required".format(
                            case_id, type(verified).__name__))

                # The verifier the reference names is the verifier this run has
                # to have been configured with. Only the *observed* verifier was
                # compared, and only against what the challenger itself had
                # recorded — so forgetting `SECURITY_SCAN_VERIFY_MODEL` let the
                # verifier follow the reviewer down to Sonnet, both passes
                # agreed with each other, and a quiet `net: 0` came back for a
                # run that changed both models at once. The experiment would
                # have measured "Sonnet judged by Sonnet" and reported it as
                # "Sonnet against Opus" — the wrong causality, arrived at by
                # omission.
                # Required, not merely permitted. The check forbade the
                # impossible combination — verification off with a model
                # recorded as having verified — and never asked for the thing
                # itself, so a challenger with verification *switched off* and
                # `verify_model` still written down sailed through: both passes
                # agreed, and a quiet `net: 0` came back for "Sonnet with no
                # verifier" measured against "Opus with one". Absent is not
                # true either; nothing about a missing field says the layer ran.
                if settings.get("verify") is not True:
                    raise ComparisonError(
                        "{}: verification is {!r} in this run and the "
                        "reference was produced with it on. Removing a layer "
                        "measures a different question.".format(
                            case_id, settings.get("verify")))

                wanted_verifier = reference.get("verifier_model")
                if not wanted_verifier:
                    raise ComparisonError(
                        "the reference does not name the verifier it was "
                        "produced with, so a challenger cannot be held to it")
                configured = settings.get("verify_model")
                if not configured:
                    raise ComparisonError(
                        "{}: the run records no `verify_model`, so nothing "
                        "says the verifier was held at {}.".format(
                            case_id, wanted_verifier))
                if configured != wanted_verifier:
                    raise ComparisonError(
                        "{}: the reference was verified by {} and this run "
                        "was configured to verify with {}. Changing the "
                        "verifier as well measures a different question."
                        .format(case_id, wanted_verifier, configured))
                if verified and settings.get("verify") is False:
                    # An artifact that cannot be true. Verification was off, so
                    # nothing verified — a row saying otherwise is describing a
                    # run that did not happen, and accepting it means accepting
                    # whatever else it says.
                    raise ComparisonError(
                        "{}: verification is off and the row still names {} as "
                        "having verified. That run did not happen.".format(
                            case_id, ", ".join(sorted(set(verified)))))
                served = [m for m in verified if m != wanted]
                if served:
                    raise ComparisonError(
                        "{}: the verification ran on {} and the run asked for "
                        "{}. A challenger measured by a different verifier is "
                        "not the comparison this reference describes.".format(
                            case_id, ", ".join(sorted(set(served))), wanted))

    # And the challenger has to differ from the reference in the model *only*.
    # The comparator asked whether the two challenger passes agreed with each
    # other and never whether either agreed with the reference — so a run with
    # an edited prompt, a changed schema or a different effort could be
    # compared against the Opus reference and the whole difference attributed
    # to the model. That is the error this repository exists against, arrived
    # at through the tool built to prevent it.
    #
    # The reference's `environment` names what produced it. Everything in it
    # except the model has to still be true of the challenger.
    environment = reference.get("environment") or {}
    for run in runs:
        for case_id, row in run.items():
            for block in (row.get("members") or {}).values():
                prov = (block or {}).get("provenance") or {}
                for field, source in ENVIRONMENT_FIELDS:
                    recorded = prov.get(source)
                    # No `continue` for a field the reference left out: the
                    # reference is required to carry all four now, so a skip
                    # here could only ever mean the guarantee had changed
                    # without this line noticing.
                    expected = environment[field]
                    # Absence is not agreement. `if expected and recorded`
                    # let a row that recorded nothing pass the contract, and
                    # `_system_identity` asks only for a prompt and a model —
                    # so two rows missing the same digests confirmed each
                    # other and walked around the reference entirely.
                    if not recorded:
                        raise ComparisonError(
                            "{}: the run records no {}, so it cannot be shown "
                            "to match the reference's {}.".format(
                                case_id, field, expected))
                    if recorded != expected:
                        raise ComparisonError(
                            "{}: the reference was produced with {} {} and "
                            "this run used {}. Only the model may differ, or "
                            "the difference cannot be attributed to it."
                            .format(case_id, field, expected, recorded))

    # And the challenger has to actually *be* a challenger. Forget the
    # environment variable and both passes run the reference's own model,
    # everything matches, and the comparison reports "passes the gate" for a
    # change that never happened — then licenses buying the wider run on the
    # strength of it. The one difference the reference permits is also the one
    # it requires.
    asked = {(block or {}).get("provenance", {}).get("model_requested") or None
             for run in runs for row in run.values()
             for block in (row.get("members") or {}).values()}
    # Fail closed on all three shapes. Discarding `None` first meant a run that
    # recorded no model at all left an empty set and skipped the check
    # entirely; and a run mixing Opus and Sonnet across members produced a set
    # of two, which is not the reference's model either, so it also passed —
    # while `_system_identity` saw one consistent system and let it through.
    if None in asked:
        raise ComparisonError(
            "a member records no `model_requested`, so nothing says which "
            "model this run is a challenger for")
    if len(asked) != 1:
        raise ComparisonError(
            "the runs asked for {} different models ({}). A comparison "
            "against one reference measures one challenger.".format(
                len(asked), ", ".join(sorted(asked))))
    if asked == {reference.get("model")}:
        raise ComparisonError(
            "the runs asked for {}, which is the reference's own model. There "
            "is no change here to measure.".format(reference.get("model")))

    # What served, compared with what served the reference — not required to be
    # the requested model alone. Every unsafe member of the reference carries
    # Haiku beside Opus and every safe member does not: the CLI serves part of
    # the verification with a smaller model wherever there is a finding. A rule
    # demanding purity would refuse the challenger for the same reason it
    # refuses the reference, and a rule ignoring it would let the measuring
    # instrument change underneath the comparison.
    expected_models = reference.get("observed_models") or {}
    if expected_models:
        seen: dict = {}
        for run in runs:
            for row in run.values():
                for name, block in (row.get("members") or {}).items():
                    prov = (block or {}).get("provenance") or {}
                    seen.setdefault(name, set()).update(
                        prov.get("models_served") or [])
        for name, expected in expected_models.items():
            # The challenger's own model replaces the reference's wherever it
            # appears; everything else — the models the CLI brings along — has
            # to match, or the instrument moved as well as the subject.
            challenger = next(iter(asked))
            substituted_expectation = {
                challenger if m == reference.get("model") else m
                for m in expected}
            if seen.get(name, set()) != substituted_expectation:
                raise ComparisonError(
                    "the {} member was served {} and the reference was served "
                    "{}. Beside the model under test, the machinery has to be "
                    "the same or the comparison measures two changes.".format(
                        name, sorted(seen.get(name, set())) or "nothing",
                        sorted(substituted_expectation)))

    # And the verifier that actually ran has to be the one the run asked for.
    # `model_substituted` above says the *reviewer* was answered by something
    # else; nothing said it about the verifier, and holding the verifier still
    # while the reviewer changes is the whole shape of this experiment. A
    # provider swapping Opus for something smaller here would have produced a
    # quiet `net: 0` — the cheaper reviewer looking fine because the comparison
    # it was measured by had also been made cheaper.
    #
    # An empty `models_verified` stays allowed: the verifier only runs where
    # there is a finding, and a case with none verified nothing.

    identities = {_system_identity(row) for run in runs for row in run.values()}
    if "" in identities:
        raise ComparisonError(
            "a row does not record enough to say what produced it, and two "
            "rows that cannot say are not thereby the same system")
    if len(identities) > 1:
        raise ComparisonError(
            "the runs come from {} different systems. Repetition confirms "
            "nothing unless it repeats the same experiment.".format(
                len(identities)))

    missing = [c for c in comparable
               for run in runs if c not in run]
    if missing:
        raise ComparisonError(
            "not every comparable case is in every run; missing: {}".format(
                ", ".join(sorted(set(missing)))))

    needed = threshold["confirmations_required"]

    regressed, improved, traded, steady = [], [], [], []
    for case_id in sorted(comparable):
        before = all(cases[case_id]["outcomes"].values())
        after = [run[case_id]["pair_success"] for run in runs]
        shapes = [_shape(run[case_id], case_id) for run in runs]
        was_shape = _reference_shape(cases[case_id], case_id)

        # Counted, not required unanimously. `all()` and `not any()` demanded
        # every run agree, so three runs reading `fail, fail, pass` were not a
        # confirmed regression — while the rule says two. The stricter-looking
        # reading was the more permissive one: it produced a green result from
        # two reproductions of the same failure.
        failures = sum(1 for verdict in after if not verdict)
        passes = sum(1 for verdict in after if verdict)

        # Both directions confirmed is not an improvement, whichever branch
        # is written first. With four runs a failing case can show two passes
        # and two failures, and the improvement branch won by position — a
        # case that reproduced its failure twice reported as fixed.
        if failures >= needed and passes >= needed:
            traded.append(case_id)
        elif before and failures >= needed:
            regressed.append(case_id)
        elif not before and passes >= needed:
            improved.append(case_id)
        elif not before:
            # Still failing. Worse only if a kind of failure it did not have
            # appears in `needed` runs — never by swapping one kind for the
            # other.
            gained = [k for k in ("missed", "false_alarm")
                      if sum(1 for s in shapes if s[k]) >= needed
                      and not was_shape[k]]
            lost = [k for k in ("missed", "false_alarm")
                    if sum(1 for s in shapes if not s[k]) >= needed
                    and was_shape[k]]
            if gained and not lost:
                regressed.append(case_id)
            elif gained or lost:
                traded.append(case_id)
            else:
                steady.append(case_id)
        else:
            steady.append(case_id)

    # Rule 2 does not subtract. Rule 1 computed `len(regressed) -
    # len(improved)` and rejected at 2, so two confirmed regressions paid for
    # by two confirmed improvements came back as "passes the gate" — and the
    # reference answers exactly two of its eleven cases with a failure, so
    # exactly two improvements are available to buy exactly two regressions.
    #
    # It was also inconsistent with the code twenty lines above, which refuses
    # to order a missed weakness against a false alarm *inside* one case and
    # calls the exchange `traded`. Netting then treated the same two harms as
    # perfectly fungible *across* cases. Nothing in this repository weighs them,
    # so the honest rule weighs neither: a confirmed regression counts, an
    # improvement elsewhere is reported and does not cancel it.
    #
    # This is an asymmetric policy choice, not a statistical claim. A security
    # gate is allowed one: finding a weakness in case A does not put back the
    # weakness missed in case B.
    # `RULE_VERSION` is checked against the reference far above, so reaching
    # here means the file was frozen under this arithmetic and no other.
    net = len(regressed)
    reject_at = threshold["reject_at_net"]
    return {
        "comparable": comparable,
        "regressed": regressed,
        "improved": improved,
        "traded": traded,
        "steady": steady,
        "net": net,
        # From the frozen number, not from one written here. Prose in the
        # reference and a constant in the comparator are two rules that can
        # disagree, and the code's copy is the one that would decide.
        # "passes the gate" is a statement about the threshold, not about the
        # models being equal — and with traded cases present it was reading as
        # the second. A case that swapped one kind of failure for the other
        # changed, and the rule declines to order the two; saying so is more
        # honest than a word that sounds like equivalence.
        "verdict": ("reject" if net >= reject_at
                    else "no decision" if net > 0
                    else "below the threshold, and cases changed" if traded
                    else "passes the gate"),
        "threshold": threshold,
    }


def render(result: dict) -> str:
    lines = ["{} comparable case(s)".format(len(result["comparable"]))]
    for label in ("regressed", "improved", "traded", "steady"):
        if result[label]:
            lines.append("  {:<12}{}".format(label + ":",
                                             ", ".join(result[label])))
    lines.append("")
    lines.append("  net {} · {}".format(result["net"], result["verdict"]))
    if result["traded"]:
        lines.append("  a traded case swapped one kind of failure for the "
                     "other and decides nothing on its own")
    lines.append("")
    lines.append("  reject at net {} · {} confirmation(s) per case · rule "
                 "version {}".format(
                     result["threshold"]["reject_at_net"],
                     result["threshold"]["confirmations_required"],
                     result["threshold"]["rule_version"]))
    lines.append("  " + result["threshold"]["in_words"])
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("reference")
    parser.add_argument("run", nargs="+",
                        help="one file per challenger run; two are the "
                             "minimum, because one cannot confirm anything")
    args = parser.parse_args()

    try:
        result = compare(Path(args.reference), args.run)
    except (ComparisonError, OSError, ValueError) as exc:
        print("Refusing to compare: {}".format(exc), file=sys.stderr)
        return 2

    print(render(result))
    return 1 if result["verdict"] == "reject" else 0


if __name__ == "__main__":
    raise SystemExit(main())
