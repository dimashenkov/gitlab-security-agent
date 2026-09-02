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
from datetime import datetime
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

SYSTEM_IDENTITY = ("prompts", "model", "providers", "settings")
IDENTITY = SUITE_IDENTITY + SYSTEM_IDENTITY

# Fields added after baselines were already being frozen. Only these may be
# absent from a frozen identity and read as "not recorded" instead of
# "changed". The list is closed on purpose: while absence was forgiven in
# general, deleting a key from baseline.json switched off the check it stood
# for, `corpus` included.
LATE_FIELDS = ("providers",)

# How many times a case has to fail before a failure counts as a regression.
#
# It was one, implicitly, and that is now measured wrong. Thirteen cases run
# twice on 2026-09-01 with nothing changed between the passes — verified before
# and after every case, against digests of the prompts, the schema, the
# adjudications, the scorer and the reviewer's own source — moved twice:
#
#     go-m6jg-wr9m-cg2f   pass -> fail
#     rb-g65v-27r3-5p6m   fail -> pass
#
# Both directions, which is the part that matters. The suite does not decay
# under repetition, it moves; so a single `pass -> fail` is not evidence that
# anything broke, and a single `fail -> pass` is not evidence that anything was
# fixed. A gate that blocked on the first would block merges that broke nothing,
# and a gate that fires on noise is switched off after the third time.
#
# Two rather than three, and the number is here rather than in a flag on
# purpose. What the rate of flipping actually is remains unknown — two passes
# detect movement and cannot size it, and finding out costs about $26 a pair —
# but the rate is not needed to decide about *one case*: re-running a single
# suspicious case costs about a dollar, and asking twice turns an unknown
# frequency into a local check.
#
# Fixed in advance because the alternative is deciding it after seeing which
# cases flipped, which is choosing the rule to fit the answer. A case that fails
# once and then does not is recorded as unstable — not as passing, which would
# be re-running until the result is convenient.
CONFIRMATIONS_REQUIRED = 2


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
    # Both the requested and the served model. Reading only what was served
    # said "the model did not change" about two runs that asked for different
    # ones and were handed the same fallback — while the confirmation rule,
    # which reads both, split them into two systems. The comparison's own
    # explanation then contradicted its verdict.
    models = sorted({
        model
        for p in provenance
        for model in [*(p.get("models_served") or []),
                      p.get("model_requested", "")]
        if model
    })

    # Who ran the reviews. `_system_identity` counts it when deciding whether
    # two failing runs are the same experiment, and this did not — so a
    # baseline frozen on one provider could be compared against a run on the
    # other without the comparison saying the system under test had changed.
    # The two are not interchangeable: one bills per token and one does not.
    providers = sorted({p.get("provider", "") for p in provenance if p.get("provider")})

    return {
        "cases": sorted(cases),
        "providers": providers,
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


def _stamp(row):
    """When the row says it ran, as an instant, or None if it does not say.

    Compared as an instant and not as text, the same lesson `stage2._instant`
    already carries: `2026-09-01T14:00:00+03:00` is *earlier* than
    `2026-09-01T12:00:00+00:00`, and sorting the two strings puts them the
    other way round. A value that will not parse, or one carrying no timezone,
    is no time at all rather than a time that sorts somewhere — an unknown
    moment presented as the earliest possible one let an old failing row
    outrank a new passing row that simply carried no stamp.
    """
    try:
        when = datetime.fromisoformat(str((row or {}).get("ran_at", "")))
    except (TypeError, ValueError):
        return None
    return when if when.tzinfo else None


def outcomes_of(results: list) -> dict:
    """The per-case result, keyed by case. Unresolved cases are kept as such.

    The last row wins, and "last" is the latest run — not the last line read.
    `compare` concatenates the files in the order they were typed, so
    `compare new.json old.json` used to make the older run the current state of
    every case, quietly reversing every verdict below.

    Per case, and only when every row for that case says when it ran. One row
    without a usable stamp and the whole case keeps the order it was given:
    ordering the rest around it would put an unknown moment somewhere on the
    line, and wherever it goes is a claim nothing supports. It is `freeze` that
    makes this matter most — a baseline frozen from the wrong row is wrong for
    every comparison after it.
    """
    rows = [r for r in results if isinstance(r, dict)]
    by_case: dict = {}
    for row in rows:
        by_case.setdefault(row.get("case_id"), []).append(row)
    ordered = []
    for case_rows in by_case.values():
        dated = all(_stamp(row) is not None for row in case_rows)
        ordered.extend(sorted(case_rows, key=_stamp) if dated else case_rows)

    out = {}
    for row in ordered:
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


def _rows_for(case_id: str, results: list) -> list:
    """Every scorable row this result file holds for one case.

    More than one is the point. A case re-run to confirm a failure writes a
    second row beside the first, and the confirmation rule counts rows rather
    than trusting a single verdict. `outcomes_of` keeps only the last, which is
    right for "what is this case's state" and wrong for "how often has it done
    that".
    """
    rows = [row for row in results
            if isinstance(row, dict)
            and row.get("case_id") == case_id
            and isinstance(row.get("pair_success"), bool)]
    # One row per *execution*, not per line in a file: duplicating a row
    # fabricated a regression, and passing the same file twice produced "2 of 2
    # runs" out of one run.
    #
    # `run_id` is the identifier when the row carries one. `ran_at` is not: it
    # is stamped to the second and at the *start* of the case, so two runs
    # begun in the same second — a scripted pair, a retry, anything
    # concurrent — collapsed into one, which drops a confirming failure and
    # hides a regression. Older rows have no `run_id`, so they fall back to the
    # whole row, and that fallback has a known limit: two genuinely separate
    # legacy executions that produced identical rows count as one. The format
    # does not forbid it — normalised, hand-merged or trimmed artifacts can be
    # equal — so the claim is not that it cannot happen but that it errs the
    # safe way. Merging two real failures under-counts, and under-counting asks
    # for another run; splitting one row into two would invent a confirmation
    # nobody performed. Rows written from here on carry a `run_id` and do not
    # reach this branch.
    seen = {}
    for row in rows:
        seen.setdefault(row.get("run_id") or json.dumps(row, sort_keys=True), row)
    return list(seen.values())


def _system_identity(row: dict) -> str:
    """What produced this row: prompts, model, provider, settings.

    Two failing runs confirm each other only if they are the same experiment.
    Without this the confirmation counted any two failures in the files it was
    given — so a failure under one prompt and a failure under another was
    reported as a *confirmed* regression, which is the one thing a repetition
    rule exists to rule out. `identity_of` cannot answer it: it merges every
    row in every file into one identity and so cannot say which row came from
    which system.

    A row that does not record enough to say what produced it returns the empty
    string, which the caller reads as *unknown* rather than as a system of its
    own. Two rows that do not say what produced them are not thereby the same
    thing, and grouping them together let them confirm each other.

    "Enough" is every member naming a prompt and a model. Asking only whether
    *some* provenance existed was walked straight around by a partial one: a
    row carrying nothing but `reported_cost_usd`, or provenance on one member
    and none on the other, produced a perfectly ordinary identity whose prompt
    and model fields were all empty — and two of those confirmed each other.
    """
    parts = []
    members = row.get("members") or {}
    if not members or not all(
            (block or {}).get("provenance", {}).get("system_prompt_sha")
            and ((block or {}).get("provenance", {}).get("models_served")
                 or (block or {}).get("provenance", {}).get("model_requested"))
            for block in members.values()):
        return ""
    for member in sorted((row.get("members") or {}).keys()):
        block = (row.get("members") or {})[member] or {}
        prov = block.get("provenance") or {}
        parts.append("|".join([
            member,
            str(prov.get("system_prompt_sha", "")),
            str(prov.get("verifier_prompt_sha", "")),
            str(prov.get("schema_sha", "")),
            str(prov.get("agent_version", "")),
            str(prov.get("provider", "")),
            # What the run was *configured* to be, not what was observed
            # happening during it. `models_served` and `models_verified` are
            # observations: the verifier only runs when there is a finding to
            # verify, so a case with none records an empty list and a case with
            # one records a model. Folded into identity, two cases from the
            # same run became two systems — and a comparison of two passes
            # launched identically would have refused itself as "different
            # systems", on real files, for a difference that is not one.
            #
            # The settings digest carries the resolved `verify_model`, so the
            # verifier's configuration is here; what is absent is the accident
            # of whether it fired. A substitution is a fact about the run and
            # is checked as one, by name, rather than smuggled in here.
            str(prov.get("model_requested", "")),
            digest_json(block.get("settings") or {}),
        ]))
    return "\n".join(parts)


def _providers_named(case_ids: Sequence[str], results: list) -> str:
    """The provider to re-run with, read from the rows themselves.

    The printed instruction named none, and `--provider` is required — so
    following it exactly ended in an argparse error and no second measurement.
    Guessing a default here would be worse: one of the two choices bills.
    """
    named = {
        (block.get("provenance") or {}).get("provider")
        for case_id in case_ids
        for row in _rows_for(case_id, results)
        for block in (row.get("members") or {}).values()
    }
    named.discard(None)
    named.discard("")
    return named.pop() if len(named) == 1 else "<the provider that produced it>"


def _runs_recorded(case_id: str, results: list) -> int:
    return len(_rows_for(case_id, results))


def _failures_recorded(case_id: str, results: list) -> int:
    """How many failing runs of one case came from the *same* system.

    The largest group, not the total: two failures under two different prompts
    are two experiments, not a repetition, and counting them together confirms
    a regression that was never reproduced.
    """
    groups: dict = {}
    for row in _rows_for(case_id, results):
        if not row["pair_success"]:
            key = _system_identity(row)
            groups[key] = groups.get(key, 0) + 1
    return max(groups.values()) if groups else 0


def drifted(baseline: dict, current: dict, fields=IDENTITY) -> list:
    """Which of `fields` differ between the frozen identity and this one.

    The default is every field, so a caller that wants the old all-or-nothing
    reading still gets it. The two callers that matter pass one half each.

    A missing field is *unknown* rather than changed only for the fields in
    `LATE_FIELDS` — the ones added after the format existed. `providers` is
    one, and an older baseline would otherwise report the provider as having
    moved when nothing had; a drift warning that is false is one that gets
    ignored. It is not silently forgiven either: `unrecorded` names it, so
    "cannot be compared" stays distinguishable from "compared, and equal".

    Every other missing field counts as changed, and that is the whole reason
    for the list. Forgiving absence in general made deleting a key from
    baseline.json a way to switch off any check in it — `corpus` included, so
    an edited suite would have compared without a refusal, a warning or
    `--force`.
    """
    frozen = baseline.get("identity", {})
    return [field for field in fields
            if not (field in LATE_FIELDS and field not in frozen)
            and frozen.get(field) != current.get(field)]


def unrecorded(baseline: dict, fields=IDENTITY) -> list:
    """Late-added fields the frozen identity predates, so cannot be compared."""
    frozen = baseline.get("identity", {})
    return [field for field in fields
            if field in LATE_FIELDS and field not in frozen]


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


def compare(result_paths, corpus: Path, baseline_path: Path,
            force: bool) -> int:
    """Read one or more result files against a frozen baseline.

    More than one because a confirmation is a second *run*, and
    `pair_corpus --json` writes the whole file each time. Telling somebody to
    "run those cases again into the same file" produced a file with one row —
    so a failure could never be confirmed, and a re-run that passed erased the
    failure it was meant to confirm. That is the run-until-it-passes this rule
    exists to prevent, arrived at by following its own instructions.
    """
    baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
    if isinstance(result_paths, (str, Path)):
        result_paths = [result_paths]
    results = []
    for path in result_paths:
        body = json.loads(Path(path).read_text(encoding="utf-8"))
        results += body if isinstance(body, list) else [body]
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
    unknown = unrecorded(baseline, SYSTEM_IDENTITY)
    if unknown:
        # Said out loud, because the sentence below it — "nothing under test
        # changed" — would otherwise cover a field the baseline never wrote
        # down. Not compared is not the same as compared and equal, and this
        # tool exists to keep those two apart.
        print("Cannot be compared — the baseline predates {} and does not "
              "record it. Re-freeze to get an answer about it.\n".format(
                  ", ".join(unknown)))
    if not under_test:
        print("Nothing under test changed: same prompts, model and settings as "
              "the baseline. Any difference below is run-to-run variation, not "
              "an effect.\n")

    before, after = baseline.get("outcomes", {}), outcomes_of(results)
    regressed, fixed, unresolved, errored, missing = [], [], [], [], []
    reshaped, candidates, unstable, improved, across = [], [], [], [], []
    for case_id, was in sorted(before.items()):
        now = after.get(case_id)
        # Asked before the transition, because a case that failed and then
        # passed has no transition to read: `outcomes_of` keeps the last row,
        # so the two cancel and the case is reported as nothing at all. Mixed
        # rows are the third answer — not a regression, and not a pass either.
        # Calling it a pass would be re-running until the result is convenient.
        runs = _rows_for(case_id, results)
        # Grouped by what produced them, because "the same case disagreeing
        # with itself" is a statement about one experiment. Read across
        # systems, a failure under the prompt being tested and a pass under
        # another one cancelled each other and the case was printed as
        # unstable — a second false green, reached from the other side.
        groups: dict = {}
        for row in runs:
            groups.setdefault(_system_identity(row), []).append(row)
        mixed = any(len({row["pair_success"] for row in group}) > 1
                    for group in groups.values())
        # Asked before `mixed`, and this is a false green that was live. A case
        # with [fail, fail, pass] is mixed, and mixed was answered first, so a
        # regression reproduced twice was reported as "the suite moving on its
        # own" and exited 0. With the runs coming from two systems it was
        # worse: two failures under the prompt being tested, one pass under
        # another, and the pass cancelled them.
        #
        # Reproduced outranks moved. A later pass does not un-reproduce two
        # failures — it makes the case one that fails some of the time, which
        # is a failing case. Otherwise `CONFIRMATIONS_REQUIRED = 2` would mean
        # "two failures and no pass ever", which is not what it says.
        failing = _failures_recorded(case_id, results)
        # And never across systems. Counting inside each group is not enough on
        # its own: the tool has no notion of which group is the system under
        # test, so two failures from an older or foreign configuration, sitting
        # in a file somebody concatenated, were reported as a confirmed
        # regression of the current one. Rather than guess which group is
        # meant, this says the inputs cannot answer it — the runs are named,
        # the case is named, and what it asks for is two runs of one system.
        #
        # A group keyed on the empty string is the *unknown* system — a row
        # that does not record enough to say what produced it. Unknown is not a
        # system two rows can share: grouped together, two rows that do not say
        # what produced them confirmed each other.
        #
        # More than one of them, though. A single undated legacy row confirms
        # nothing on its own, and treating it as unanswerable made every older
        # result permanently uncomparable — including a run with one passing
        # row and no question in it. Runners before provenance existed wrote
        # exactly such files.
        spanning = len(groups) > 1 or len(groups.get("", ())) > 1
        confirmed = (was["outcome"] == "pass"
                     and failing >= CONFIRMATIONS_REQUIRED
                     and not spanning)
        if spanning:
            across.append(case_id)
        # The denominator has to come from the group that did the confirming.
        # "2 of 3 runs" counted a pass produced by a different system in the
        # same breath as two failures under this one, which is two experiments
        # reported as one history.
        within = max((len(group) for group in groups.values()
                      if sum(1 for r in group if not r["pair_success"])
                      == failing), default=len(runs))
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
        elif confirmed:
            regressed.append("{} ({} of {} runs)".format(
                case_id, failing, within))
        elif mixed:
            # Asked after the endings that mean "no result", and before the
            # transition. A file holding `[fail, pass, error]` has a last state
            # of `error`, and classifying it as unstable first returned 0 —
            # "the check did not finish" reported as a green gate, which is the
            # one thing this project exists to prevent.
            #
            # Before the transition because a case that failed and then passed
            # has no transition to read: `outcomes_of` keeps the last row, the
            # two cancel, and the case is reported as nothing at all. Mixed
            # runs are the third answer — not a regression, and not a pass
            # either, which would be re-running until the result is convenient.
            unstable.append("{} ({} of {} runs failed)".format(
                case_id, sum(1 for r in runs if not r["pair_success"]),
                len(runs)))
        elif was["outcome"] == "pass" and failing:
            # A candidate, not a verdict: the confirmed case was answered
            # above, so reaching here means one failing run and no second.
            # That second sighting is a re-run of this one case — about a
            # dollar — rather than another pass over the suite.
            #
            # Asked about the failing *runs* rather than about `now`, which is
            # the last row and can be a pass produced by another system. That
            # arrangement — fail under A, pass under B — matched nothing at
            # all and the case was printed as neither.
            candidates.append(case_id)
        elif was["outcome"] == "fail" and now["outcome"] == "pass":
            # The same bar as a failure, in the other direction. One passing
            # run is not evidence of a fix: the pair that measured the noise
            # turned a failure into a pass with nothing changed. Reporting
            # only — neither answer gates — but "it passes now" was the exact
            # sentence the measurement refuted.
            passing = max((sum(1 for r in group if r["pair_success"])
                           for group in groups.values()), default=0)
            # `not spanning` for the same reason as the confirmation above. The
            # rule said nothing is confirmed from runs of more than one system,
            # and it was applied to failures only — so a case could be called
            # fixed and listed as spanning in the same output.
            if passing >= CONFIRMATIONS_REQUIRED and not spanning:
                fixed.append(case_id)
            else:
                improved.append(case_id)
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
    for label, cases in (("regressed", regressed),
                         ("failed once, unconfirmed", candidates),
                         ("unstable: failed and passed in the same run", unstable),
                         ("fixed", fixed),
                         ("passed once, unconfirmed", improved),
                         ("runs came from more than one system", across),
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
    if candidates:
        # Named loudly, and not blocking. The suite is known to move on its own
        # in both directions, so one failure is a question rather than an
        # answer — and the answer costs about a dollar, because it is a re-run
        # of these cases and not of the suite.
        #
        # A *second file*, because `pair_corpus --json` writes the whole file
        # each time: "run them again into the same file" produced a file with
        # one row, so a failure could never be confirmed and a re-run that
        # passed erased the failure it was meant to confirm.
        print("\n{} case(s) failed once and have not been confirmed:\n  {}\n\n"
              "Run just those again into a NEW file and pass both:\n"
              "  tools/pair_corpus.py corpus-real --case {} "
              "--provider {} --json again.json\n"
              "  tools/baseline.py compare first.json again.json\n\n"
              "A single `pass -> fail` is not evidence that anything broke: "
              "thirteen cases run twice with nothing changed moved two, in both "
              "directions. {} failing runs make it a regression; one failing "
              "run and one passing makes it unstable, which is a third answer "
              "and a true one.".format(
                  len(candidates), "\n  ".join(candidates),
                  " --case ".join(candidates),
                  _providers_named(candidates, results),
                  CONFIRMATIONS_REQUIRED))
    if across:
        # The inputs, not the code, are what cannot answer here. Said in the
        # imperative, because the fix is a choice of files.
        print("\n{} case(s) have runs from more than one system in these "
              "files, so no repetition among them repeats the same "
              "experiment, and nothing is confirmed from them — in either "
              "direction. Compare files from one configuration, or run the "
              "case twice under the one you mean to test. The prompts, the "
              "settings and the provider are part of that, and so is the "
              "model that answered: a fallback served mid-run is a different "
              "system from the one that was asked for.".format(len(across)))
    if unstable:
        # Its own sentence. Folded in with the candidates it printed their
        # count and their list, so a run with only unstable cases announced
        # "0 case(s) failed once" above an empty list.
        print("\n{} case(s) failed and passed within the same comparison. That "
              "is the suite moving on its own, not a verdict about the code, "
              "and it is recorded rather than resolved: calling it a pass "
              "would be re-running until the result is convenient.".format(
                  len(unstable)))
    if regressed:
        return 1
    if unresolved or errored or missing:
        return 2
    if across:
        # The sentence above says these inputs cannot answer the question, and
        # the process exited 0 while saying it — one path even reached "No
        # regression against the frozen suite". A message that contradicts its
        # own exit code is read by the exit code.
        return 2
    if candidates:
        # 2, not 0. Not because one failure is a regression — it is measured
        # not to be — but because the comparison has no answer about this case
        # yet, and 0 is the code for "nothing blocking", which is read as
        # clean. The first version returned 0 here and left the confirming run
        # to whoever felt like paying for it; a question nobody is obliged to
        # answer is a question that stays unanswered.
        #
        # This is not the zero threshold returning, but it is close enough to
        # deserve the honest version: at the flip rate measured, most
        # comparisons will land here, and what ends the loop is a person
        # choosing to spend about a dollar re-running one case. Nothing
        # automates that — the CI job is manual and allow_failure, so exit 2
        # moves the decision to a human rather than forcing it. What 2 buys
        # over 0 is that the unanswered question is not printed in the colour
        # of an answer.
        return 2
    if unstable:
        # 0, and this one really is an answer: the case moves on its own. It is
        # printed, it is never counted as passing, and there is nothing further
        # to buy — a third run would only be re-running until the result is
        # convenient.
        return 0
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
    comparer.add_argument("result", nargs="+",
                          help="one file per run; a confirmation is a second "
                               "run, and `pair_corpus --json` overwrites, so "
                               "the second one is a second file")
    comparer.add_argument("--baseline", default="baseline.json")
    comparer.add_argument("--force", action="store_true",
                          help="compare anyway across a changed identity, and "
                               "own the fact that the delta is not attributable")

    args = parser.parse_args()
    corpus = Path(args.corpus)
    if not corpus.is_dir():
        print("no such corpus: {}".format(corpus), file=sys.stderr)
        return 2
    if args.command == "freeze":
        result = Path(args.result)
        if not result.is_file():
            print("no such result: {}".format(result), file=sys.stderr)
            return 2
        return freeze(result, corpus, Path(args.out))

    paths = [Path(name) for name in args.result]
    for path in paths:
        if not path.is_file():
            print("no such result: {}".format(path), file=sys.stderr)
            return 2
    baseline = Path(args.baseline)
    if not baseline.is_file():
        print("no baseline at {} — freeze one first".format(baseline), file=sys.stderr)
        return 2
    return compare(paths, corpus, baseline, args.force)


if __name__ == "__main__":
    sys.exit(main())
