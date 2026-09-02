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

**Net** is confirmed regressions minus confirmed improvements. Two cases that
got worse and two that got better is a net of zero and no decision — not a
tidy cancellation, a signal that the sample is too small to say.

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

RULE_VERSION = 1


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
    for case_id in comparable:
        entry = cases[case_id]
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
    substituted = sorted({
        case_id for run in runs for case_id, row in run.items()
        for block in (row.get("members") or {}).values()
        if (block or {}).get("provenance", {}).get("model_substituted")})
    if substituted:
        raise ComparisonError(
            "the provider answered with another model in {}. A run that did "
            "not use the model it names cannot measure that model.".format(
                ", ".join(substituted)))

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
    for run in runs:
        for case_id, row in run.items():
            for block in (row.get("members") or {}).values():
                prov = (block or {}).get("provenance") or {}
                wanted = ((block or {}).get("settings") or {}).get(
                    "verify_model") or prov.get("model_requested")
                verified = prov.get("models_verified") or []
                settings = (block or {}).get("settings") or {}
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
                    if expected and recorded and recorded != expected:
                        raise ComparisonError(
                            "{}: the reference was produced with {} {} and "
                            "this run used {}. Only the model may differ, or "
                            "the difference cannot be attributed to it."
                            .format(case_id, field, expected, recorded))

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

        if before and failures >= needed:
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

    net = len(regressed) - len(improved)
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
