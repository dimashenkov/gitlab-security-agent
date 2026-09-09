#!/usr/bin/env python3
"""Freeze what a repeat run is, before it is bought — then read it afterwards.

    tools/round.py freeze 1 --scope approved
    tools/round.py freeze 1 --scope approved --dry-run
    tools/round.py compare 1

## Why this exists rather than just running the queue again

Codex's objection to buying 140 reviews without it, and it is the whole point:

> You would then possess 140 valid contemporary reviews but no valid stability
> experiment.

A second pass answers "did the verdict move" only if it is decided **in
advance** which pass-2 row each pass-1 row is comparable to, and under what
rule they count as agreeing. Deciding either afterwards — once the
disagreements are visible — produces a number chosen to fit them. So the case
list, the order, the environment and the endpoints are written once, before
anything is spent, and the file refuses to be overwritten.

## Three things the manifest fixes that would otherwise be decided later

**Which cases have a comparable baseline.** Fourteen of the sixty-two have
never run, so they cannot contribute to stability at all — they contribute a
first observation of recall and nothing else. Left implicit, they would quietly
join a denominator they do not belong in.

**The order.** The queue runs alphabetically, which puts every `cs-` case in
the first window and every `ts-` case in the last. Language would then be
confounded with the window, the reset, and whatever the plan does at its
boundary, and no amount of care afterwards separates them. The order here is a
shuffle seeded by the round number: reproducible, recorded, and not
alphabetical.

**What "the same" means.** `case_digest` per case, the prompt and schema
hashes, the adjudication file's hash, the model and profile. If any of them
moves between the passes, the comparison is between two different questions and
the file says so rather than a reader having to notice.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, ClassVar, Dict, List, Optional

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "src"))

import check_accounted  # noqa: E402
import run_queue  # noqa: E402
import stop_rule  # noqa: E402
from artifact import (  # noqa: E402
    answer_key_digest,
    case_digest,
    instant,
    legacy_case_digest,
)

FIVE_LANGUAGES = ("go", "php", "py", "ts", "js")


class Sweep:
    """The shape `run_queue.cases` expects, with nothing selected."""

    # A stand-in for the parsed arguments `run_queue.cases` reads, with
    # nothing selected. It is never mutated and never instantiated twice,
    # so the shared-default hazard the rule warns about cannot arise —
    # but the rule is right in general, so the exemption is written here
    # rather than switched off for the file.
    case: ClassVar[List[str]] = []
    language = None
    construction = None


def digest_of(path: Path) -> str:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()[:16]
    except OSError:
        return ""


def environment() -> Dict[str, Any]:
    """Everything that would make two passes answer different questions."""
    return {
        "agent_version": (ROOT / "src" / "security_agent" / "__init__.py")
        .read_text(encoding="utf-8").split('__version__ = "')[1].split('"')[0],
        "system_prompt": digest_of(ROOT / "prompts" / "system.md"),
        "verifier_prompt": digest_of(ROOT / "prompts" / "verifier.md"),
        "findings_schema": digest_of(ROOT / "prompts" / "findings.schema.json"),
        # Not part of what the reviewer sees, and part of what its answer means:
        # a ruling added between the passes rescores a verdict without rerunning
        # anything.
        "adjudications": digest_of(ROOT / "corpus-real" / "adjudications.yml"),
    }


def baselines() -> Dict[str, Dict[str, Any]]:
    """The verdict each case already has, and where it came from.

    Taken from `check_accounted.verdicts()`, which only counts a row that says
    which version of the case it saw. A case whose only rows predate that record
    has no comparable baseline, and saying so here is the difference between a
    stability denominator and a wish.
    """
    # One walk for both. `check_accounted.walk` exists because two walks are
    # two snapshots of a directory a running queue writes into, and this
    # caller was making two — so a result landing between them raised the
    # "key not recorded" caveat for a row that records it, and froze that into
    # a manifest nothing rewrites.
    rows = check_accounted.walk()
    keys = check_accounted.baseline_keys(rows)
    return {case_id: {"pair_success": passed,
                      # The key the baseline was scored against, or `None`
                      # where the row does not say — which is every row
                      # written before 2026-09-09. A round comparing that
                      # baseline against a new run cannot tell a product
                      # change from a change in what a pass means, and the
                      # figure has to carry that rather than imply either
                      # answer.
                      "answer_key_digest": keys.get(case_id)}
            for case_id, passed in check_accounted.verdicts(rows).items()}


def scope_cases(scope: str) -> List[str]:
    eligible = run_queue.cases(Sweep())
    if scope == "all":
        return sorted(eligible)
    if scope == "five":
        return sorted(c for c in eligible
                      if c.split("-")[0] in FIVE_LANGUAGES)
    if scope == "approved":
        # What the owner agreed to on 2026-08-31: the five languages, plus every
        # case that has never run, plus rb-g65v — whose ruling is correct and
        # excuses nothing until the row carries a fingerprint.
        five = {c for c in eligible if c.split("-")[0] in FIVE_LANGUAGES}
        unrun = set(check_accounted.account().get("unrun", [])) & set(eligible)
        held = {"rb-g65v-27r3-5p6m", "rb-g65v-27r3-5p6m-snap"} & set(eligible)
        return sorted(five | unrun | held)
    if scope == "sentinel":
        # The frozen suite in `suites/sentinel.yml`, chosen by the rule in
        # `tools/sentinel.py` rather than named here. Naming the cases in this
        # file would give the suite two definitions that agree until they do
        # not, and the one a run used would be whichever this function said.
        #
        # Intersected with what the queue considers eligible, and any shortfall
        # is refused rather than run: a suite that quietly shrinks between the
        # freeze and the run is the sample changing after the question was set.
        from sentinel import read_cases

        wanted = read_cases(ROOT / "suites" / "sentinel.yml")
        missing = sorted(set(wanted) - set(eligible))
        if missing:
            raise SystemExit(
                "the sentinel suite names {} case(s) the queue will not run: "
                "{}. Fix the suite or the queue; do not run the remainder."
                .format(len(missing), ", ".join(missing)))
        return sorted(wanted)
    raise SystemExit("unknown scope {!r}".format(scope))


def manifest_path(number: int) -> Path:
    return ROOT / "measurements" / "round-{}".format(number) / "manifest.json"


def build(number: int, scope: str) -> Dict[str, Any]:
    chosen = scope_cases(scope)
    known = baselines()

    rows = []
    for case_id in chosen:
        directory = ROOT / "corpus-real" / case_id
        body = {}
        manifest = directory / "case.yml"
        if manifest.is_file():
            import yaml
            body = yaml.safe_load(manifest.read_text(encoding="utf-8")) or {}
        rows.append({
            "case_id": case_id,
            "language": body.get("language", ""),
            "construction": body.get("construction", ""),
            "case_digest": case_digest(directory),
            "legacy_case_digest": legacy_case_digest(directory),
            # The answer key, which `case_digest` deliberately excludes. For a
            # row that exclusion is right — a corrected category does not
            # invalidate evidence about the same code. For a round it is not:
            # what a pass *means* is one of the conditions being frozen.
            "answer_key_digest": answer_key_digest(directory),
            # The half that decides what this case can answer.
            "baseline": known.get(case_id),
            "contributes_to": (["stability", "recall"] if case_id in known
                               else ["recall"]),
        })

    # Seeded by the round number so it is reproducible from the file alone, and
    # shuffled so no language sits entirely inside one window.
    order = [r["case_id"] for r in rows]
    random.Random(number).shuffle(order)

    comparable = [r for r in rows if r["baseline"] is not None]
    return {
        "round": number,
        "scope": scope,
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "environment": environment(),
        "protocol": {
            "provider": "claude-cli",
            "profile": "normal",
            # **The model, frozen like the provider and the profile.** This
            # file's own docstring has always listed the model among what a
            # round freezes, and it was the one item that was neither written
            # down nor enforced. Codex, 2026-09-09: freeze a round, run it
            # with `SECURITY_SCAN_MODEL=claude-sonnet-5`, and the queue
            # accepted it — then `compare` read both models' rows and reported
            # Sonnet against Opus as the product moving on its own. That
            # number is what every gate threshold sits above.
            #
            # `PRODUCT_MODEL`, not `queue_model()`: `freeze` refuses to run
            # under anything else, so the two are equal here by construction
            # — and writing the constant says which of the two facts the
            # manifest is recording. The queue then compares what it would buy
            # against this, through the same reader.
            "model": stop_rule.PRODUCT_MODEL,
            "order": order,
            "order_seed": number,
            # Written down because choosing it after seeing the disagreements is
            # how a threshold gets fitted to them.
            "primary_endpoint":
                "per case, whether pair_success is the same as the baseline's. "
                "Reported as agreed / flipped, over the cases that have a "
                "baseline and nothing else.",
            "secondary_endpoints": [
                "recall in this pass, over every case in the round",
                "agreement on which findings match the case's target",
            ],
            "excluded_from_stability":
                "cases with no baseline — they have never run, so there is "
                "nothing to have moved",
        },
        "counts": {
            "cases": len(rows),
            "reviews": 2 * len(rows),
            "with_baseline": len(comparable),
            "without_baseline": len(rows) - len(comparable),
        },
        "cases": rows,
    }


def freeze(number: int, scope: str, dry_run: bool) -> int:
    # **A round is a measurement of the product, so it is frozen for the
    # product.** Codex, 2026-09-09, against the version that froze whatever
    # `queue_model()` resolved to: freezing under
    # `SECURITY_SCAN_MODEL=claude-sonnet-5` made the round internally
    # consistent and the comparison still wrong, because `baselines()` comes
    # from `check_accounted.verdicts()`, which is the *product's* answers and
    # nothing else. The pass then printed "0 agreed, 1 flipped" and exited 0
    # over Sonnet against an Opus baseline — the cross-model comparison the
    # round before this one was repaired to prevent, arriving through the
    # freeze instead of through the run.
    #
    # Refused rather than silently corrected: an exported variable that would
    # have decided the experiment is exactly what the freeze exists to pin,
    # and a run started this way is one somebody meant to be about Sonnet.
    running = stop_rule.queue_model()
    if running != stop_rule.PRODUCT_MODEL:
        print("SECURITY_SCAN_MODEL is {!r} and a round is a measurement of "
              "{}. Its baselines come from the product's own verdicts, so a "
              "pass bought from another model would be compared against them "
              "and the difference reported as the product moving on its own. "
              "Unset the variable, or build a two-arm experiment with "
              "tools/experiment.py, which is what compares two models."
              .format(running, stop_rule.PRODUCT_MODEL))
        return 2
    path = manifest_path(number)
    if path.exists() and not dry_run:
        print("{} already exists. A frozen round is not rewritten — that is "
              "what freezing it was for. Use the next number."
              .format(path.relative_to(ROOT)))
        return 1

    body = build(number, scope)
    counts = body["counts"]
    if not counts["cases"]:
        # `sentinel.main` refuses an empty selection with exit 2 and this had
        # no equivalent: `read_cases` reads only lines beginning with `- `, so
        # a suite rewritten as a YAML flow list — legal, same meaning — selects
        # nothing, and `scope_cases("sentinel")` then finds no case missing
        # because it is comparing two empty sets. A round of nothing freezes,
        # runs, and compares without error over an empty denominator.
        print("scope {!r} selected no case. A round of nothing would freeze, "
              "run and compare without error, and report agreement over an "
              "empty denominator. Fix the scope — for `sentinel`, check that "
              "suites/sentinel.yml still lists its cases one per line."
              .format(scope))
        return 2
    print("round {} · scope {}".format(number, scope))
    print("  {} case(s), {} review(s)".format(counts["cases"], counts["reviews"]))
    print("  {} with a baseline — the stability denominator".format(
        counts["with_baseline"]))
    print("  {} without one; they answer recall only".format(
        counts["without_baseline"]))
    print("  order: shuffled, seed {}".format(number))
    if dry_run:
        print("\nNothing written.")
        return 0

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(body, indent=2, ensure_ascii=False) + "\n",
                    encoding="utf-8")
    print("\nWritten to {}. Run the queue with:".format(path.relative_to(ROOT)))
    print("  tools/run_queue.py --round {} --case ... (see the manifest order)"
          .format(number))
    return 0


def compare(number: int) -> int:
    """Read a finished round against the manifest that was frozen before it."""
    path = manifest_path(number)
    if not path.is_file():
        print("No manifest for round {}. It was never frozen, so there is no "
              "rule to compare against and none may be invented now."
              .format(number))
        return 2
    body = json.loads(path.read_text(encoding="utf-8"))
    if not body.get("cases"):
        # A manifest frozen before `freeze` learned to refuse one. Reading it
        # prints "0 agreed, 0 flipped" and a reader takes that for a round in
        # which nothing moved.
        print("Round {} was frozen with no cases. There is nothing to compare "
              "and nothing was bought; this is not a round in which nothing "
              "moved.".format(number))
        return 2

    directory = path.parent
    # Every row for a case, not the last file's. `results[case_id] = row` kept
    # whichever row came out of the last name in `sorted(glob("*.json"))`, so
    # renaming two files holding one case swapped this file's primary number
    # between "0 agreed, 1 flipped" and "1 agreed, 0 flipped" with nothing else
    # changed. `sentinel.recorded_outcomes` documents and refuses exactly that
    # trap and `check_accounted` refuses it too; this reader had not learned it.
    collected: Dict[str, list] = {}
    # From `body`, which is this manifest already parsed. The first version
    # opened the file a second time through a local named `manifest_path`,
    # which shadowed the module function of that name that `compare` had
    # called eleven lines earlier — an `UnboundLocalError` in the tool that
    # reads a paid round, caught by twelve tests within the minute.
    frozen_protocol = body.get("protocol") or {}
    if not isinstance(frozen_protocol, dict):
        frozen_protocol = {}
    # A round frozen before the model was written down names none, and then
    # the product is what it meant: every round so far was bought with it.
    # The manifest is not authoritative about which model, in this reader
    # either. Codex, 2026-09-09: `freeze` refuses to write one naming another
    # model, and a manifest already on disk — hand-edited, or from an earlier
    # revision — was still obeyed here, so the comparison could put Sonnet
    # rows against the Opus baselines and call the difference instability.
    # Absence still means the product: every round frozen before the field
    # existed was bought with it.
    # **One entry per case.** Codex, 2026-09-09: the reporting loop walks
    # `body["cases"]` and counts each entry, so a manifest naming a case twice
    # counted one observation twice — "2 agreed, 0 flipped" over a single
    # measurement, exit 0. Two entries with different baselines make the same
    # row an agreement *and* a flip. `run_queue` refuses such a manifest
    # before spending; this reader can be invoked on its own and did not,
    # which is the two ends of one rule disagreeing again.
    named = [entry.get("case_id") for entry in body["cases"]
             if isinstance(entry, dict) and entry.get("case_id")]
    if len(set(named)) != len(named):
        repeated = sorted({name for name in named if named.count(name) > 1})
        print("Round {} has a manifest naming the same case more than once: "
              "{}.\nEvery figure below would count one measurement as many, "
              "so nothing is reported. Re-freeze the round."
              .format(number, ", ".join(repeated)))
        return 2

    # **And the answer key.** Codex, 2026-09-09: `case_digest` covers the
    # members only, so editing a frozen case's `case.yml` left both this
    # reader and the queue accepting the row — and a flip caused by changing
    # what a pass means was reported as the product moving on its own. The
    # rows carry no key digest, so it is asked once, of the corpus as it
    # stands, against what the round froze.
    rekeyed = []
    for entry in body["cases"]:
        if not isinstance(entry, dict) or not entry.get("case_id"):
            continue
        frozen_key = entry.get("answer_key_digest")
        if not frozen_key:
            # A manifest from before the field existed. Not checked rather
            # than refused, which is the rule the digests above already use.
            continue
        if answer_key_digest(ROOT / "corpus-real" / entry["case_id"]) \
                != frozen_key:
            rekeyed.append(entry["case_id"])
    if rekeyed:
        print("Round {} froze an answer key that has changed since, for: {}.\n"
              "A pass does not mean the same thing on both sides of that "
              "edit, so the flips below would be the key moving rather than "
              "the product. Re-freeze the round."
              .format(number, ", ".join(sorted(rekeyed))))
        return 2

    named_model = frozen_protocol.get("model")
    if named_model is not None and named_model != stop_rule.PRODUCT_MODEL:
        print("Round {} has a manifest naming model {!r}. Its baselines are "
              "{}'s own verdicts, so rows from another model cannot be "
              "compared against them: that measures the models, not the "
              "product. Re-freeze the round, or use tools/experiment.py."
              .format(number, named_model, stop_rule.PRODUCT_MODEL))
        return 2
    wanted_model = named_model or stop_rule.PRODUCT_MODEL
    skipped_other_model = 0
    # **And about the case as it was frozen.** Codex, 2026-09-09: `freeze`
    # records `case_digest` and `legacy_case_digest` for every case and
    # `compare` read neither, so editing a member between the freeze and the
    # run made the new row answer a different question from the baseline it
    # was counted against — and when the two verdicts happened to agree, the
    # tool printed a stability measurement over two different inputs and
    # exited 0. This is the same check `check_accounted.about_this_version`
    # and `stage2` already apply to every other reader of the same rows; this
    # one had not learnt it.
    #
    # Both spellings are kept, because a row written before the digest changed
    # shape carries the legacy one and is still about the frozen case.
    frozen_digests = {
        case["case_id"]: {d for d in (case.get("case_digest"),
                                      case.get("legacy_case_digest")) if d}
        for case in body["cases"] if isinstance(case, dict)
        and case.get("case_id")}
    skipped_other_version = 0
    skipped_not_frozen = 0
    # `*/*.json` as well: under `--round N` the queue's directory *is* this
    # one, so `run_queue.result_path` writes a run of another model to
    # `round-N/<model>/<case>.json`. Reading only the top level would drop
    # those rows without a word — which is the right *outcome*, since the
    # model check below refuses them, reached the wrong way: silently, so the
    # line that names how many were set aside would never fire.
    for result in sorted(set(directory.glob("*.json"))
                         | set(directory.glob("by-model/*/*.json"))):
        if result.name == "manifest.json":
            continue
        try:
            stored = json.loads(result.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        # A batch file is a list of rows; an experiment writes one row per
        # file, as an object. Reading only lists opened the file, parsed it and
        # then iterated it as nothing.
        rows = stored if isinstance(stored, list) else [stored]
        for row in rows:
            if not (isinstance(row, dict) and row.get("case_id")
                    and not row.get("incomplete")):
                continue
            # **And produced by the model this round froze.** Codex,
            # 2026-09-09: `run_queue.result_path` writes a non-product run to
            # `<case>.<model>.json`, in this very directory, so a round could
            # hold rows from two models and this reader took the latest by
            # timestamp. The flips it then reported as the product moving on
            # its own were one model against another — and that number is what
            # every gate threshold sits above. A round frozen before the model
            # was written down names none, and then the product is what it
            # meant: every round so far was bought with it.
            if stop_rule.identified_model(row) != wanted_model:
                skipped_other_model += 1
                continue
            # **Three states, and the first version had two.** Codex,
            # 2026-09-09: `frozen_digests.get(...)` returned `None` both for a
            # case the manifest does not name and for a frozen case recorded
            # before digests existed, and the falsey test let the first
            # through — into `collected`, where the reporting loop, which
            # walks the manifest, never looks at it again. So a paid row for a
            # case outside the round vanished without a word, under a comment
            # claiming it was named. Absence read as agreement, in the line
            # written to stop absence being read as agreement.
            #
            #   not in the manifest        -> not this round's, and said so
            #   in it, with digests        -> must match one of them
            #   in it, none recorded       -> a manifest from before `freeze`
            #                                 stored them; refusing every row
            #                                 would make an old round measure
            #                                 nothing
            if row["case_id"] not in frozen_digests:
                skipped_not_frozen += 1
                continue
            wanted_digests = frozen_digests[row["case_id"]]
            if wanted_digests and row.get("case_digest") not in wanted_digests:
                skipped_other_version += 1
                continue
            collected.setdefault(row["case_id"], []).append(row)

    results: Dict[str, Any] = {}
    disagreed = set()
    for case_id, rows in collected.items():
        stamped = [(instant(row.get("ran_at")), row) for row in rows]
        dated = [(when, row) for when, row in stamped if when is not None]
        if dated:
            latest = max(when for when, _row in dated)
            pool = [(when, row) for when, row in dated if when == latest]
        else:
            pool = stamped
        if len({row.get("pair_success") for _when, row in pool}) > 1:
            # Two rows sharing the latest instant and disagreeing. Naming it is
            # the answer; picking one is what glob order used to do.
            disagreed.add(case_id)
            continue
        results[case_id] = pool[0][1]

    if skipped_not_frozen:
        print("{} row(s) in this round are for a case the manifest does not "
              "name. They were bought and are not part of the comparison; a "
              "round is what it froze.\n".format(skipped_not_frozen))

    if skipped_other_version:
        print("{} row(s) in this round are about a different version of their "
              "case than the one it froze, and are not part of the "
              "comparison.\n".format(skipped_other_version))

    if skipped_other_model:
        # Named, not dropped in silence. Those rows were bought, and a reader
        # that removes them without saying so reports a round as thinner than
        # it is — which is the same fault as counting them.
        print("{} row(s) in this round were produced by another model and are "
              "not part of the comparison; it froze {}.\n".format(
                  skipped_other_model, wanted_model))

    now = environment()
    drifted = [k for k, v in body["environment"].items() if now.get(k) != v]
    if drifted:
        # **Refused, not warned.** `environment()`'s own docstring calls these
        # "everything that would make two passes answer different questions",
        # and this printed exactly that and then printed the number anyway —
        # while an edit to the *other* half of the scoring rule, `case.yml`,
        # is exit 2 with nothing reported. One rule, two treatments, and the
        # softer one is on the half that includes `adjudications.yml`, where a
        # ruling added between the passes rescores a verdict without rerunning
        # anything.
        print("Changed since the round was frozen: {}. The two passes are not "
              "answering the same question, so no figure is reported: it "
              "would be that change and not the product. Re-freeze the round "
              "as a new experiment if the change is deliberate."
              .format(", ".join(sorted(drifted))))
        return 2

    agreed = flipped = missing = 0
    observed = set()
    moves: List[str] = []
    unresolved: List[str] = []
    for case in body["cases"]:
        # `.get`, so a hand-edited manifest reaches the guards below rather
        # than a `KeyError` here. The `isinstance` checks further down name
        # exactly these inputs and were unreachable, because this line and the
        # `case["baseline"]["pair_success"]` under it subscripted first: the
        # checks read as coverage and were not.
        if "stability" not in (case.get("contributes_to") or []):
            continue
        if case["case_id"] in disagreed:
            unresolved.append(
                "{}: two rows at the same instant disagree".format(
                    case["case_id"]))
            continue
        row = results.get(case["case_id"])
        if row is None:
            missing += 1
            continue
        # This case produced an observation, so a caveat about it has a figure
        # to attach to. The rest do not.
        observed.add(case["case_id"])
        baseline = case.get("baseline")
        before = baseline.get("pair_success") if isinstance(baseline, dict) \
            else None
        after = row.get("pair_success")
        # `is True` / `is False`, the spelling `experiment.verdicts` already
        # uses, and not `bool(row.get("pair_success"))`.
        #
        # `pair_corpus.run_case` writes `pair_success` only on the success
        # path; a pair that crashed carries `error` and neither that key nor
        # `incomplete`, so the filter above admits it. `bool(None)` is False,
        # and against a baseline of False that counted a review which never
        # produced an answer as evidence that nothing had moved — the one
        # thing this file exists to measure, satisfied by the absence of the
        # data rather than by the data. A stored `"false"` would have gone the
        # other way and read as a pass.
        if after is not True and after is not False:
            unresolved.append("{}: {}".format(
                case["case_id"],
                row.get("error") or "pair_success={!r}".format(after)))
            continue
        # The other half of the same comparison. A hand-edited manifest whose
        # baseline is null would make every case flip against it, and the
        # number would look like a finding.
        if before is not True and before is not False:
            unresolved.append("{}: the frozen baseline is {!r}, not a verdict"
                              .format(case["case_id"], before))
            continue
        if before == after:
            agreed += 1
        else:
            flipped += 1
            moves.append("{}: {} -> {}".format(case["case_id"], before, after))

    total = agreed + flipped
    print("stability, over the {} case(s) frozen with a baseline:".format(
        body["counts"]["with_baseline"]))
    print("  {} agreed, {} flipped, {} not yet run".format(agreed, flipped, missing))
    # **The qualification travels with the figure.** Codex, 2026-09-09: the
    # digests above catch an answer key edited *after* the freeze, and cannot
    # establish that the frozen baseline was itself scored under the frozen
    # key. No row written before 2026-09-09 records the key it was judged by —
    # `case_digest` covers the members only, on purpose — so for those cases a
    # flip may be the product moving or the key moving, and nothing here can
    # tell. `pair_corpus` records it from now on; until a case is re-measured,
    # this line is what stops the number being read as more than it is.
    # **Three states, and the first version had two.** It asked only whether
    # the baseline's key was *present*, so a baseline provably scored under a
    # different key printed nothing at all — the one case where the key is
    # demonstrably what moved was the one that said nothing, while "I cannot
    # tell" spoke. The control test asserted that as correct.
    #
    #   absent            -> cannot tell; the caveat below
    #   present, equal    -> the comparison means what it says
    #   present, differs  -> the key moved, and the flip is not the product's
    unproven, rekeyed_baseline = [], []
    for case in body["cases"]:
        if not isinstance(case, dict) or not case.get("case_id"):
            continue
        if "stability" not in (case.get("contributes_to") or []):
            continue
        if case["case_id"] not in observed:
            # No observation, so there is no flip for the doubt to attach to.
            # The first version counted every stability case in the manifest
            # and printed over "0 agreed, 0 flipped, 1 not yet run" — a caveat
            # about a figure that does not exist is noise on the one line
            # meant to be load-bearing.
            continue
        baseline = case.get("baseline")
        if not isinstance(baseline, dict):
            continue
        key = baseline.get("answer_key_digest")
        if not key:
            unproven.append(case["case_id"])
        elif case.get("answer_key_digest") and key != case["answer_key_digest"]:
            rekeyed_baseline.append(case["case_id"])
    if rekeyed_baseline:
        print("  the baseline for {} case(s) was scored under a different "
              "answer key from the one this round froze, so any flip there is "
              "the key moving and not the product: {}".format(
                  len(rekeyed_baseline), ", ".join(sorted(rekeyed_baseline))))
    unproven = sorted(unproven)
    if unproven:
        print("  {} of them rest on a baseline whose scoring key is not "
              "recorded, so a flip there may be the key moving rather than "
              "the product: {}".format(
                  len(unproven), ", ".join(unproven[:3])
                  + ("…" if len(unproven) > 3 else "")))
    for line in moves:
        print("    " + line)
    if unresolved:
        print("  {} ran without producing a verdict — neither agreement nor a "
              "flip, and no observation of this case:".format(len(unresolved)))
        for line in unresolved:
            print("    " + line)

    if total:
        print("  {:.0%} agreement — one pass against one pass, so this bounds "
              "instability and cannot establish stability.".format(agreed / total))
    if not total:
        # Exit 0 said "nothing wrong" about a comparison that compared nothing.
        # A round where every case is missing, or every row ran without
        # producing a verdict, printed the same green status as one where
        # everything agreed — and the reader who wanted the second cannot tell
        # them apart from the exit code alone.
        print("\n  No case produced both a baseline and a verdict, so this "
              "measured nothing. Not exit 0: an empty comparison and a "
              "comparison that found no movement are different answers.")
        return 2
    if unresolved:
        # A run that produced no verdict is an absence, and absences are what
        # this project refuses to read as agreement. Named above, and not
        # green here.
        return 2
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)

    it = sub.add_parser("freeze", help="write the manifest for a round")
    it.add_argument("number", type=int)
    it.add_argument("--scope", default="approved",
                    choices=("approved", "five", "all", "sentinel"))
    it.add_argument("--dry-run", action="store_true")

    done = sub.add_parser("compare", help="read a round against its manifest")
    done.add_argument("number", type=int)

    args = parser.parse_args(argv)
    if args.command == "freeze":
        return freeze(args.number, args.scope, args.dry_run)
    return compare(args.number)


if __name__ == "__main__":
    raise SystemExit(main())
