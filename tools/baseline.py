#!/usr/bin/env python3
"""Freeze a result so a later one can be compared to it — or refuse to compare.

A baseline is not a number. It is a number plus the identity of everything that
produced it — and that identity is two things, not one.

**The test** is the corpus contents, which cases were excluded, the scoring
protocol and the adjudications. Move any of those and the two figures answer
different questions, so `compare` refuses and names what moved. That is not
hypothetical: over two days the completeness rule, the target-file definitions,
the corpus membership and the response-limit behaviour all changed at once, and
a 2-of-6 could then be neither defended nor improved — only withdrawn, because
no part of it was attributable to any of the four.

**The system under test** is the prompts, the model and the settings. Those are
*meant* to move; a comparison exists to say what happened when they did. The
first version of this file held all seven fields in one tuple and so refused
its own main use — freeze, change a prompt, re-run, read the difference — with
"prompts changed". The only comparison it permitted was one in which nothing
worth measuring had happened.

So: a changed test refuses, a changed system is named as the cause, and a run
where *nothing* changed is named too — that one is the noise floor, and reading
it as an effect is the error this tool exists to prevent.

    tools/baseline.py freeze corpus-result.json --out baseline.json
    tools/baseline.py compare corpus-result.json --baseline baseline.json

Exit 0 means compared and no regression, 1 means a regression, 2 means the
comparison could not be made — the same three states as everything else here.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Sequence

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from pair_corpus import SCORER_VERSION, load_adjudications, malformed_cases

# Two identities, and keeping them apart is the whole design.
#
# The first version had one tuple holding all seven fields, and it made the
# tool refuse its own main use. The regime it exists for is: freeze a baseline,
# change a prompt, re-run the same cases, read the difference. With one tuple
# step two disqualifies step four — `compare` returns 2, "prompts changed" —
# so the only comparison it allowed was one where nothing worth measuring had
# happened.
#
# What has to be equal is the *test*: the cases, which of them are excluded,
# the scoring protocol, and the adjudications. Move any of those and the two
# figures are about different questions, and no amount of care makes them
# subtractable.
#
# What is *allowed* to differ is the system being tested: the prompts, the
# model, the settings. That difference is not a threat to the comparison — it
# is the thing the comparison is for. It is recorded and named in the output
# rather than used to refuse.
SUITE_IDENTITY = ("cases", "corpus", "excluded", "scorer_version",
                  "adjudications")
SYSTEM_IDENTITY = ("prompts", "model", "settings")
IDENTITY = SUITE_IDENTITY + SYSTEM_IDENTITY


def digest_tree(root: Path, cases: Sequence[str] = ()) -> str:
    """One hash over every file that reaches the agent, paths included.

    Paths are hashed as well as contents: moving a case between directories
    changes which repository the agent is handed, and a content-only digest
    would call that the same corpus.

    `cases` narrows it to named case directories, and a suite of ten run out of
    a directory of eighty-two needs that narrowing to mean anything. Hashing
    the whole tree makes an edit to a case the suite never touches read as a
    changed test, so the comparison refuses over a case that was not in it —
    and the more the corpus grows, the more often the sentinel refuses for
    reasons that have nothing to do with the sentinel.

    A named case that is not on disk hashes as absent rather than being skipped.
    A suite whose case has been deleted is a different suite, and silence there
    would be the comparison quietly shrinking.
    """
    sha = hashlib.sha256()
    roots = [root / case for case in sorted(cases)] if cases else [root]
    for base in roots:
        if cases:
            sha.update(str(base.relative_to(root)).encode("utf-8"))
            sha.update(b"\0")
            if not base.is_dir():
                sha.update(b"absent\0")
                continue
        for path in sorted(p for p in base.rglob("*") if p.is_file()):
            sha.update(str(path.relative_to(root)).encode("utf-8"))
            sha.update(b"\0")
            sha.update(path.read_bytes())
            sha.update(b"\0")
    return sha.hexdigest()[:16]


def digest_json(value) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, default=str).encode("utf-8")
    ).hexdigest()[:16]


def identity_of(results: list, corpus: Path, cases: Sequence[str] = ()) -> dict:
    """What produced this result, in the form a later run can be checked against.

    Read from the artifact rather than from the current tree wherever possible:
    the prompts that produced a result are the ones recorded in it, not the ones
    on disk when someone gets around to freezing it.

    `cases` is the suite: the exact case list this identity is about. At freeze
    time it comes from the result being frozen; at compare time it comes from
    the baseline, so the question asked is "are *these* cases still what they
    were", not "has anything anywhere in the corpus been touched".
    """
    members = [m for row in results for m in (row.get("members") or {}).values()]
    provenance = [m.get("provenance") or {} for m in members]
    settings = [m.get("settings") or {} for m in members]

    prompts = sorted({
        "{}|{}|{}|{}".format(
            p.get("system_prompt_sha", ""), p.get("verifier_prompt_sha", ""),
            p.get("schema_sha", ""), p.get("agent_version", ""))
        for p in provenance
    })
    models = sorted({
        model
        for p in provenance
        for model in (p.get("models_served") or [p.get("model_requested", "")])
        if model
    })

    return {
        "cases": sorted(cases),
        "corpus": digest_tree(corpus, cases),
        "excluded": sorted(malformed_cases(corpus)),
        # A list, not a value. A server-side fallback can substitute a model
        # mid-review, and a baseline that records only the requested one would
        # compare a run against a different model without saying so.
        "model": models,
        "prompts": prompts,
        "settings": sorted({digest_json(s) for s in settings}),
        "scorer_version": SCORER_VERSION,
        "adjudications": digest_json(load_adjudications(corpus)),
    }


def outcomes_of(results: list) -> dict:
    """The per-case result, keyed by case. Unresolved cases are kept as such."""
    out = {}
    for row in results:
        case_id = row.get("case_id")
        if not case_id:
            continue
        if row.get("incomplete"):
            out[case_id] = {"outcome": "unresolved",
                            "incomplete": sorted(row["incomplete"])}
        elif row.get("error"):
            out[case_id] = {"outcome": "error"}
        elif "pair_success" in row:
            out[case_id] = {
                "outcome": "pass" if row["pair_success"] else "fail",
                "unsafe_target_recall": bool(row.get("unsafe_recall")),
                "safe_target_persistence": bool(row.get("safe_false_positive")),
                # The shape of the failure, not just its existence.
                #
                # `pair_success` is `(not safe_hit) and unsafe_hit` — one bit —
                # so a pair that already fails can get worse in every way that
                # matters and still read `fail -> fail`. Missing the weakness
                # is one failure; missing it *and* blocking the fixed member is
                # another, and the second is the one that gets a tool switched
                # off. The exit codes separate them, and the corpus has already
                # shown a case moving from (0,0) to (0,1) between two runs with
                # the verdict unchanged both times.
                "shape": [row.get("safe_exit"), row.get("unsafe_exit")],
            }
    return out


def drifted(baseline: dict, current: dict, fields=IDENTITY) -> list:
    """Which of `fields` differ between the frozen identity and this one.

    The default is every field, so a caller that wants the old all-or-nothing
    reading still gets it. The two callers that matter pass one half each.
    """
    return [field for field in fields
            if baseline.get("identity", {}).get(field) != current.get(field)]


def freeze(result_path: Path, corpus: Path, out: Path) -> int:
    results = json.loads(result_path.read_text(encoding="utf-8"))
    outcomes = outcomes_of(results)
    if not outcomes:
        print("no scorable case in {} — nothing to freeze".format(result_path),
              file=sys.stderr)
        return 2

    unresolved = [c for c, o in outcomes.items() if o["outcome"] != "pass"
                  and o["outcome"] in ("unresolved", "error")]
    baseline = {
        # The suite is whatever this result covers. A baseline that named the
        # directory instead would grow a case every time somebody harvested one
        # and call the enlarged thing the same suite.
        "identity": identity_of(results, corpus, sorted(outcomes)),
        "outcomes": outcomes,
        "passed": sum(1 for o in outcomes.values() if o["outcome"] == "pass"),
        "scored": sum(1 for o in outcomes.values()
                      if o["outcome"] in ("pass", "fail")),
    }
    out.write_text(json.dumps(baseline, indent=2, sort_keys=True) + "\n",
                   encoding="utf-8")

    print("froze {} case(s): {} passed of {} scored.".format(
        len(outcomes), baseline["passed"], baseline["scored"]))
    if unresolved:
        print("{} case(s) are unresolved in this baseline and cannot be "
              "regressed against: {}".format(len(unresolved), ", ".join(unresolved)))
    print("\nThis is a regression baseline, not a recall figure. It supports "
          "'this version did what that version did on this frozen suite', and "
          "nothing about code outside it.")
    return 0


def compare(result_path: Path, corpus: Path, baseline_path: Path,
            force: bool) -> int:
    baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
    results = json.loads(result_path.read_text(encoding="utf-8"))
    # The baseline's case list, not this run's. The question is whether these
    # cases are still what they were; a run that covered a different set says
    # so through `cases` rather than through a corpus digest nobody can read.
    # An older baseline, frozen before the suite was a first-class thing, has
    # no list and falls back to the whole tree — the behaviour it was written
    # under, so it neither breaks nor silently changes meaning.
    frozen_identity = baseline.get("identity", {})
    # A baseline frozen before the suite was a first-class field has no case
    # list, and its corpus digest is over the whole tree. Comparing a scoped
    # digest against a whole-tree one would report a changed corpus on every
    # old baseline, and comparing a present `cases` against an absent one would
    # refuse every old baseline outright — which is what the first version of
    # this did while its comment promised a fallback.
    legacy = "cases" not in frozen_identity
    suite_fields = (tuple(f for f in SUITE_IDENTITY if f != "cases")
                    if legacy else SUITE_IDENTITY)

    frozen_cases = frozen_identity.get("cases") or []
    run_cases = sorted(outcomes_of(results))

    # Compared explicitly rather than through the digest, because "the suite
    # changed" and "a case in the suite was edited" want different sentences.
    #
    # Reported before `force` is consulted, and not skipped by it. The first
    # version returned early only when `force` was false, so a forced run over
    # a *different* set of cases printed one line about a new case, matched no
    # exit condition, and returned 0 — a green regression gate over a
    # comparison between two different suites.
    if not legacy and sorted(frozen_cases) != run_cases:
        print("{}: this run is not the frozen suite.".format(
            "WARNING" if force else "Refusing to compare"))
        gone = sorted(set(frozen_cases) - set(run_cases))
        extra = sorted(set(run_cases) - set(frozen_cases))
        if gone:
            print("  in the baseline, absent here: {}".format(", ".join(gone)))
        if extra:
            print("  in this run, not in the baseline: {}".format(", ".join(extra)))
        if not force:
            print("\nA suite is the cases it names. Freeze a baseline for this "
                  "set, or run the set the baseline was frozen for.")
            return 2

    current_identity = identity_of(
        results, corpus, () if legacy else (frozen_cases or run_cases))
    if legacy:
        # Nothing to compare it against, and leaving an empty list in would
        # read as "this run covered no cases".
        current_identity.pop("cases", None)
    else:
        # The frozen list is what the corpus digest is *about* — has this suite
        # been edited — but the `cases` field has to say what this run actually
        # covered, or a forced comparison would print an identity claiming the
        # suite matched when it did not.
        current_identity["cases"] = run_cases

    moved = drifted(baseline, current_identity, suite_fields)
    if moved and not force:
        print("Refusing to compare: {} changed since the baseline was frozen."
              .format(", ".join(moved)))
        for field in moved:
            print("\n  {}\n    was: {}\n    now: {}".format(
                field, baseline.get("identity", {}).get(field),
                current_identity.get(field)))
        print("\nThat is the test itself, not the thing under test. A delta "
              "across a changed {} is a delta between two different questions. "
              "Re-freeze, or pass --force and say in writing what moved."
              .format(moved[0]))
        return 2
    if moved:
        print("WARNING: comparing across a changed {}. The two runs are not "
              "answering the same question.\n".format(", ".join(moved)))

    # The other half, and it does not refuse. A changed prompt, model or
    # setting is the reason a comparison is being made at all; naming it is how
    # the delta below acquires a cause. Naming its *absence* matters just as
    # much — a difference in outcomes with nothing changed is the noise floor,
    # and reading it as an effect is the mistake this whole tool exists against.
    under_test = drifted(baseline, current_identity, SYSTEM_IDENTITY)
    if under_test:
        print("Under test — {} changed since the baseline:".format(
            ", ".join(under_test)))
        for field in under_test:
            print("  {}\n    was: {}\n    now: {}".format(
                field, baseline.get("identity", {}).get(field),
                current_identity.get(field)))
        print()
    else:
        print("Nothing under test changed: same prompts, model and settings as "
              "the baseline. Any difference below is run-to-run variation, not "
              "an effect.\n")

    before, after = baseline.get("outcomes", {}), outcomes_of(results)
    regressed, fixed, unresolved, errored, missing = [], [], [], [], []
    reshaped = []
    for case_id, was in sorted(before.items()):
        now = after.get(case_id)
        if now is None:
            missing.append(case_id)
        elif now["outcome"] == "error":
            # This branch did not exist. `outcomes_of` has written `error`
            # since it was added, and the state machine below knew only
            # `unresolved` — so a case whose run blew up matched nothing, fell
            # past every arm, and the comparison printed "No regression against
            # the frozen suite" and exited 0.
            #
            # That is the product's own failure inside the tool that measures
            # it: a check that did not run, reported as a check that passed.
            errored.append(case_id)
        elif now["outcome"] == "unresolved":
            unresolved.append(case_id)
        elif was["outcome"] == "pass" and now["outcome"] == "fail":
            regressed.append(case_id)
        elif was["outcome"] == "fail" and now["outcome"] == "pass":
            fixed.append(case_id)
        elif (was["outcome"] == now["outcome"] == "fail"
                and "shape" in was and was.get("shape") != now.get("shape")):
            # Still failing, failing differently. Not called a regression: the
            # two shapes are not ordered, and inventing an order would be the
            # gate deciding which way of being wrong is worse. Named, because a
            # binary endpoint reported this as "no change" and it is not one.
            reshaped.append("{} {} -> {}".format(
                case_id, was.get("shape"), now.get("shape")))
    added = sorted(set(after) - set(before))

    print("{} case(s) in the baseline, {} in this run.".format(len(before), len(after)))
    for label, cases in (("regressed", regressed), ("fixed", fixed),
                         ("still failing, differently", reshaped),
                         ("no longer completes", unresolved),
                         ("errored", errored),
                         ("absent from this run", missing),
                         ("new since the baseline", added)):
        if cases:
            print("  {:<24}{}".format(label + ":", ", ".join(cases)))

    if unresolved or errored:
        # Deliberately not a regression. A case that stopped early did not
        # fail; treating the two the same is the confusion that made a 2-of-6
        # out of three reviews that never ran.
        #
        # Named apart, though, because they need different next actions: a case
        # that stopped early wants its artifact read, and one that errored
        # wants the error read. Folding them into one word would answer both
        # with the same shrug.
        print("\nA case with no result is not a case that regressed. It needs "
              "the artifact read before it means anything.")
    if regressed:
        return 1
    if unresolved or errored or missing:
        return 2
    print("\nNo regression against the frozen suite.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", default="corpus-real",
                        help="the case directory the result was produced from")
    sub = parser.add_subparsers(dest="command", required=True)

    freezer = sub.add_parser("freeze")
    freezer.add_argument("result")
    freezer.add_argument("--out", default="baseline.json")

    comparer = sub.add_parser("compare")
    comparer.add_argument("result")
    comparer.add_argument("--baseline", default="baseline.json")
    comparer.add_argument("--force", action="store_true",
                          help="compare anyway across a changed identity, and "
                               "own the fact that the delta is not attributable")

    args = parser.parse_args()
    corpus = Path(args.corpus)
    if not corpus.is_dir():
        print("no such corpus: {}".format(corpus), file=sys.stderr)
        return 2
    result = Path(args.result)
    if not result.is_file():
        print("no such result: {}".format(result), file=sys.stderr)
        return 2

    if args.command == "freeze":
        return freeze(result, corpus, Path(args.out))
    baseline = Path(args.baseline)
    if not baseline.is_file():
        print("no baseline at {} — freeze one first".format(baseline), file=sys.stderr)
        return 2
    return compare(result, corpus, baseline, args.force)


if __name__ == "__main__":
    sys.exit(main())
