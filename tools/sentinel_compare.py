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
        out[case_id] = row
    return out


def compare(reference_path: Path, run_paths: list) -> dict:
    reference = json.loads(Path(reference_path).read_text(encoding="utf-8"))
    cases = reference["cases"]
    comparable = list(reference["comparable"])
    # Asked first, and asked of the reference rather than of the runs. A
    # retired reference is one somebody has already established cannot answer
    # the question, and every check below it would then report a *reason* — a
    # served-model set, a verifier — for a file that is not a baseline at all,
    # sending the reader to fix the symptom.
    retired = reference.get("retired")
    if retired:
        raise ComparisonError(
            "this reference is retired and is not a baseline: {}".format(
                retired.get("why", "no reason recorded")))

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
    if reference.get("missing"):
        raise ComparisonError(
            "the reference is missing {}, so it describes a narrower suite "
            "than the one it names".format(
                ", ".join(sorted(reference["missing"]))))
    if len(comparable) != len(set(comparable)):
        raise ComparisonError(
            "a case is listed twice among the comparable ones, which counts "
            "one measurement more than once")
    if not (reference.get("environment") or {}):
        raise ComparisonError(
            "the reference records no environment, so there is nothing for a "
            "challenger to be held against")
    for case_id in comparable:
        entry = cases[case_id]
        # Both passes, named. A reference carrying one outcome is a reference
        # that never checked itself for stability, and the whole exclusion of
        # unstable cases rests on having two.
        outcomes = entry.get("outcomes") or {}
        if set(outcomes) != {"pass-a", "pass-b"}:
            raise ComparisonError(
                "{}: the reference records {} outcome(s), and it takes two to "
                "know whether it agreed with itself".format(
                    case_id, len(outcomes)))
        for label, verdict in (entry.get("outcomes") or {}).items():
            if not isinstance(verdict, bool):
                raise ComparisonError(
                    "{}: the reference records {!r} for {}, which is not a "
                    "verdict".format(case_id, verdict, label))
        for label, shape in (entry.get("shape") or {}).items():
            for kind in ("missed", "false_alarm"):
                if not isinstance(shape.get(kind), bool):
                    raise ComparisonError(
                        "{}: the reference records {!r} for {} in {}, which "
                        "is not a verdict".format(
                            case_id, shape.get(kind), kind, label))
    if not comparable:
        raise ComparisonError(
            "the reference has no comparable cases, so there is nothing this "
            "comparison could have found")
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
    for case_id in comparable:
        stamps = [run[case_id].get("run_id") for run in runs
                  if case_id in run]
        if any(stamp is None for stamp in stamps):
            raise ComparisonError(
                "{}: a row carries no `run_id`, so nothing says which "
                "execution it is".format(case_id))
        if len(set(stamps)) != len(stamps):
            raise ComparisonError(
                "{}: the same execution appears in two of the files. A "
                "repetition has to be repeated.".format(case_id))

    # A substitution is a fact about the run, checked by name. It used to be
    # smuggled into the identity through `models_served`, where it split cases
    # from one run into two systems — because the verifier only fires when
    # there is something to verify. Here it says the plain thing: a review the
    # provider answered with another model did not measure the model it names,
    # and this whole experiment is about which model was asked.
    # Required to be false and present, not merely not-true. A row that never
    # recorded the flag, and was answered by another model, would otherwise
    # pass — a green result for a change that was not executed.
    for run in runs:
        for case_id, row in run.items():
            for block in (row.get("members") or {}).values():
                prov = (block or {}).get("provenance") or {}
                if prov.get("model_substituted") is None:
                    raise ComparisonError(
                        "{}: the run does not record whether the provider "
                        "substituted the model".format(case_id))
                served = prov.get("models_served")
                if not served:
                    raise ComparisonError(
                        "{}: the run records no served model, so nothing says "
                        "which model answered".format(case_id))
    for run in runs:
        for case_id, row in run.items():
            members = row.get("members") or {}
            if set(members) != {"safe", "unsafe"}:
                # A pair is two members. One of them missing would otherwise be
                # reported as a model or identity complaint, which sends the
                # reader to the wrong question.
                raise ComparisonError(
                    "{}: a pair is a safe and an unsafe member, and this row "
                    "has {}".format(case_id, ", ".join(sorted(members)) or
                                    "neither"))
            for block in members.values():
                prov = (block or {}).get("provenance") or {}
                wanted = ((block or {}).get("settings") or {}).get(
                    "verify_model") or prov.get("model_requested")
                verified = prov.get("models_verified") or []
                settings = (block or {}).get("settings") or {}

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
                for field, recorded in (
                        ("system_prompt", prov.get("system_prompt_sha")),
                        ("verifier_prompt", prov.get("verifier_prompt_sha")),
                        ("findings_schema", prov.get("schema_sha")),
                        ("agent_version", prov.get("agent_version"))):
                    expected = environment.get(field)
                    if not expected:
                        continue
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
