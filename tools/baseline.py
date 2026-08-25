#!/usr/bin/env python3
"""Freeze a result so a later one can be compared to it — or refuse to compare.

A baseline is not a number. It is a number plus the identity of everything that
produced it: the corpus contents, which cases were excluded, the prompt and
schema hashes, the model, the gate settings, the scorer version, and the
adjudications. Change any one and the two figures are about different things.

That is not hypothetical. Over two days the completeness rule, the target-file
definitions, the corpus membership and the response-limit behaviour all changed
at once, and the result was that a 2-of-6 could be neither defended nor
improved — only withdrawn, because no part of it could be attributed to any of
the four.

So `compare` refuses by default when the identity has moved, and names what
moved. A comparison that quietly proceeds across a prompt edit is worse than no
comparison: it produces a delta that reads as a change in the reviewer.

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

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from pair_corpus import SCORER_VERSION, load_adjudications, malformed_cases

# Everything that has to be equal before two runs can be subtracted. Each entry
# is here because changing it silently changes what the score means.
IDENTITY = ("corpus", "excluded", "prompts", "model", "settings",
            "scorer_version", "adjudications")


def digest_tree(root: Path) -> str:
    """One hash over every file that reaches the agent, paths included.

    Paths are hashed as well as contents: moving a case between directories
    changes which repository the agent is handed, and a content-only digest
    would call that the same corpus.
    """
    sha = hashlib.sha256()
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        sha.update(str(path.relative_to(root)).encode("utf-8"))
        sha.update(b"\0")
        sha.update(path.read_bytes())
        sha.update(b"\0")
    return sha.hexdigest()[:16]


def digest_json(value) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, default=str).encode("utf-8")
    ).hexdigest()[:16]


def identity_of(results: list, corpus: Path) -> dict:
    """What produced this result, in the form a later run can be checked against.

    Read from the artifact rather than from the current tree wherever possible:
    the prompts that produced a result are the ones recorded in it, not the ones
    on disk when someone gets around to freezing it.
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
        "corpus": digest_tree(corpus),
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
            }
    return out


def drifted(baseline: dict, current: dict) -> list:
    return [field for field in IDENTITY
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
        "identity": identity_of(results, corpus),
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
    current_identity = identity_of(results, corpus)

    moved = drifted(baseline, current_identity)
    if moved and not force:
        print("Refusing to compare: {} changed since the baseline was frozen."
              .format(", ".join(moved)))
        for field in moved:
            print("\n  {}\n    was: {}\n    now: {}".format(
                field, baseline.get("identity", {}).get(field),
                current_identity.get(field)))
        print("\nA delta across a changed {} is not a change in the reviewer, "
              "and it reads exactly like one. Re-freeze, or pass --force and "
              "say in writing what moved.".format(moved[0]))
        return 2
    if moved:
        print("WARNING: comparing across changed {}. The delta below is not "
              "attributable to the reviewer.\n".format(", ".join(moved)))

    before, after = baseline.get("outcomes", {}), outcomes_of(results)
    regressed, fixed, unresolved, missing = [], [], [], []
    for case_id, was in sorted(before.items()):
        now = after.get(case_id)
        if now is None:
            missing.append(case_id)
        elif now["outcome"] == "unresolved":
            unresolved.append(case_id)
        elif was["outcome"] == "pass" and now["outcome"] == "fail":
            regressed.append(case_id)
        elif was["outcome"] == "fail" and now["outcome"] == "pass":
            fixed.append(case_id)
    added = sorted(set(after) - set(before))

    print("{} case(s) in the baseline, {} in this run.".format(len(before), len(after)))
    for label, cases in (("regressed", regressed), ("fixed", fixed),
                         ("no longer completes", unresolved),
                         ("absent from this run", missing),
                         ("new since the baseline", added)):
        if cases:
            print("  {:<24}{}".format(label + ":", ", ".join(cases)))

    if unresolved:
        # Deliberately not a regression. A case that stopped early did not
        # fail; treating the two the same is the confusion that made a 2-of-6
        # out of three reviews that never ran.
        print("\nA case that no longer completes is not a case that regressed. "
              "It is a case with no result, and it needs the artifact read "
              "before it means anything.")
    if regressed:
        return 1
    if unresolved or missing:
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
