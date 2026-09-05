"""Properties of the measuring tools, generated rather than remembered.

Every serious defect this repository has produced is one shape: a check
satisfied by the absence of the data it needs. `if expected and recorded`,
`bool(row.get(...))`, `is not False`, a glob that cannot see a subdirectory, a
timestamp compared as text. They are found by remembering to look for them.
A generator does not have to remember.

Scope is deliberate and narrow — the measurement machinery and the artifact
readers, never the product's review path. A property here asserts something a
tool says about itself in its own docstring; where the docstring says something
narrower than it seemed to, the narrower thing is what is asserted, and the
difference is written down beside it.

Regression tests live at the bottom, under `TestFoundByHypothesis`. Each one is
a shrunk counterexample with the wrong answer named. They are plain pytest
tests on purpose: once the input is known, generating it again buys nothing.
"""

from __future__ import annotations

import copy
import itertools
import json
import os
import sys
from datetime import timedelta, timezone
from pathlib import Path

import pytest
import yaml
from hypothesis import HealthCheck, assume, given, settings
from hypothesis import strategies as st

from security_agent import canonical
from strategies import (
    OFFSETS,
    artifacts,
    aware_moments,
    awkward_bools,
    dated_timestamps,
    result_rows,
    timestamps,
)

TOOLS = Path(__file__).resolve().parents[1] / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import check_accounted  # noqa: E402
import experiment  # noqa: E402
import sentinel_compare  # noqa: E402
import stage2  # noqa: E402
from artifact import case_digest, instant  # noqa: E402

# Modest on purpose. The suite is 2389 tests and runs on every change; a
# property that takes a second is a property that gets deleted. Raise it by
# hand — `--hypothesis-seed=... -p no:randomly` with a bigger profile — when
# hunting rather than guarding.
settings.register_profile(
    "measuring-tools",
    max_examples=40,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
# For hunting rather than guarding:
#
#     HYPOTHESIS_PROFILE=hunt PYTHONPATH=src python3 -m pytest \
#         tests/test_properties.py -q 2>&1 | tail -5
#
# Kept here so the wider search is something somebody can re-run, rather than a
# number edited into the file and then remembered back out again. An
# environment variable and not `--hypothesis-profile`, because that flag is read
# before this module is imported and the profile would not yet exist.
settings.register_profile(
    "hunt",
    max_examples=1500,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture,
                           HealthCheck.too_slow],
)
settings.load_profile(os.environ.get("HYPOTHESIS_PROFILE", "measuring-tools"))

_WORLDS = itertools.count()


# --------------------------------------------------------- canonical.split


TELEMETRY_HEADS = {p.split(".")[0].removesuffix("[]")
                   for p in canonical.TELEMETRY_PATHS}


@given(artifacts())
def test_split_does_not_modify_the_artifact_it_was_given(artifact):
    """`split` promises it in the first line of its docstring.

    It matters because the conformance suite splits the same artifact more than
    once — a `split` that consumed its input would make the second call see a
    stripped object and report agreement.
    """
    before = copy.deepcopy(artifact)
    canonical.split(artifact)
    assert artifact == before


@given(artifacts())
def test_no_declared_telemetry_path_survives_in_the_canonical_half(artifact):
    """The partition's whole job: what is declared provider-side is gone.

    Asserted through `lookup`, which is the module's own answer to "is this path
    real and did it actually leave", rather than by reconstructing the walk and
    testing the reconstruction.
    """
    result, _telemetry = canonical.split(artifact)
    for path in canonical.TELEMETRY_PATHS:
        assert canonical.lookup(result, path) is canonical.ABSENT, path


@given(artifacts())
def test_a_key_nobody_classified_stays_in_the_canonical_half(artifact):
    """"A field nobody classified is canonical." The module says so in bold.

    The direction is the point: an unclassified decision field left in the
    comparison makes a test fail and someone look; one dropped from it makes
    nothing happen at all.
    """
    result, _telemetry = canonical.split(artifact)
    for key, value in artifact.items():
        if key in TELEMETRY_HEADS:
            continue
        assert result[key] == value


def _reorder(value):
    """The same JSON, with every object's keys in the opposite order."""
    if isinstance(value, dict):
        return {k: _reorder(v) for k, v in reversed(list(value.items()))}
    if isinstance(value, list):
        return [_reorder(v) for v in value]
    return value


@given(artifacts())
def test_canonical_bytes_does_not_depend_on_key_order(artifact):
    """Sorted keys, "because dictionary order is an implementation detail of
    whichever code assembled the artifact"."""
    assert (canonical.canonical_bytes(artifact)
            == canonical.canonical_bytes(_reorder(artifact)))


@given(artifacts(), artifacts())
def test_differences_names_a_path_exactly_when_the_halves_are_not_identical(
        left, right):
    """The two readings of one comparison have to agree.

    `identical` decides and `differences` explains. A failing comparison that
    lists no differing path teaches a team to stop reading comparison failures,
    which is the failure mode `differences` was written against.

    Known hole, recorded rather than excluded from the domain:
    `TestFoundByHypothesis.test_negative_zero_differs_in_bytes_and_in_no_path`.
    Two independent draws practically never collide on it, so the property
    stands over the whole domain and the counterexample is named below.
    """
    assert (canonical.differences(left, right) == []) == canonical.identical(
        left, right)


# ------------------------------------------------------------ artifact.instant


@given(aware_moments(), OFFSETS, OFFSETS)
def test_one_moment_written_in_two_offsets_is_one_instant(moment, here, there):
    """The defect the function was extracted for.

    `2026-08-28T14:00:00+03:00` is *earlier* than `...T12:00:00+00:00` and sorts
    after it as text, so a lexicographic `max` let an earlier run supersede a
    later one whenever the offsets differed.
    """
    left = moment.astimezone(timezone(timedelta(hours=here))).isoformat()
    right = moment.astimezone(timezone(timedelta(hours=there))).isoformat()
    assert instant(left) == instant(right)


@given(st.lists(timestamps(), max_size=6))
def test_every_instant_is_ordered_against_every_other(values):
    """A total order, which means no naive moment gets in.

    Python refuses to compare an aware datetime with a naive one, so a single
    naive row would not sort last — it would raise, mid-ordering, in a tool that
    is deciding whether a case passed. "A value carrying no timezone is treated
    as no time at all" is what keeps the order total.
    """
    moments = [m for m in (instant(v) for v in values) if m is not None]
    assert all(m.tzinfo is not None for m in moments)
    assert len(sorted(moments)) == len(moments)


@given(timestamps())
def test_a_value_that_is_not_a_dated_string_is_no_time_at_all(value):
    """Only a parseable, offset-carrying string becomes a moment."""
    moment = instant(value)
    if moment is None:
        return
    assert isinstance(value, str)
    assert moment.tzinfo is not None


# --------------------------------------------- the latest instant, both readers


ROWS = st.lists(
    st.tuples(st.one_of(st.none(), aware_moments()), st.booleans()),
    max_size=6)


@given(seen=ROWS, data=st.data())
def test_what_stands_does_not_depend_on_the_order_rows_were_read_in(seen, data):
    """Glob order settled a case once — `rb-mx5j-mp4f-g8jg`, reported as failing
    because of the order the filesystem handed the files over."""
    shuffled = data.draw(st.permutations(seen))
    assert stage2._settle(list(shuffled)) == stage2._settle(list(seen))


@given(ROWS)
def test_an_undated_row_answers_only_when_nothing_dated_does(seen):
    """"Rows with no time do not sort anywhere." So dropping them all cannot
    change an answer that any dated row took part in."""
    dated = [(when, ok) for when, ok in seen if when is not None]
    assume(dated)
    assert stage2._settle(seen) == stage2._settle(dated)


@given(ROWS)
def test_a_tie_at_the_latest_instant_stays_unresolved(seen):
    """`pair_corpus` stamps whole seconds, so two rows can share an instant.
    Picking between two answers recorded at the same moment would be inventing
    an order, and `_settle` returns both."""
    result = stage2._settle(seen)
    if len(result) == 1:
        return
    assert result in ({True, False}, set())


# --------------------------------------------------------- check_accounted


CASE = "xx-prop-0000-0000"


def build_world(root: Path) -> str:
    """One case with two members, and the digest a row has to carry."""
    directory = root / "corpus-real" / CASE
    for member in ("safe", "unsafe"):
        body = directory / member / "app"
        body.mkdir(parents=True)
        (body / "handler.py").write_text("# {}\n".format(member), encoding="utf-8")
    (directory / "case.yml").write_text(yaml.safe_dump({
        "case_id": CASE,
        "language": "py",
        "construction": "regression",
        "expected_category": ["injection"],
        "expected_file": ["app/handler.py"],
    }), encoding="utf-8")
    (root / "corpus-real" / "adjudications.yml").write_text(
        "adjudications: []\n", encoding="utf-8")
    (root / "measurements").mkdir()
    return case_digest(directory)


def measured_row(*, digest, passes, ran_at=None) -> dict:
    finding = {"category": "injection", "file": "app/handler.py",
               "fingerprint": "f" * 16}
    out = {
        "case_id": CASE,
        "unsafe_findings": [finding] if passes else [],
        "safe_findings": [],
        "pair_success": passes,
        "case_digest": digest,
    }
    if ran_at is not None:
        out["ran_at"] = ran_at
    return out


@given(result_rows())
def test_a_row_is_only_finished_when_it_says_so_in_a_boolean(row):
    """`scorable` is one definition for both readers of the stream.

    It went wrong when there were two: `executed` demanded a boolean
    `pair_success` and `verdicts` asked only that the row was not `incomplete`,
    so a finished-looking row carrying `null` there was a canonical verdict in
    one reader and invisible to the other — and the verdict was the false one.
    """
    if not check_accounted.scorable(row):
        return
    assert isinstance(row.get("pair_success"), bool)
    assert row.get("case_id")
    assert not row.get("incomplete")


@given(st.lists(st.tuples(st.one_of(st.none(), dated_timestamps()),
                          st.booleans()),
                min_size=1, max_size=5),
       st.data())
def test_a_case_is_never_a_pass_on_disagreement_at_the_latest_instant(
        tmp_path, monkeypatch, rows, data):
    """"Disagreement at the latest instant is not a pass here."

    Two readers of one measurement stream could report opposite things about one
    case: `stage2` called a tie unresolved and this tool picked a winner by glob
    order.
    """
    world = tmp_path / "w{}".format(next(_WORLDS))
    world.mkdir()
    digest = build_world(world)
    monkeypatch.setattr(check_accounted, "ROOT", world)
    case = yaml.safe_load(
        (world / "corpus-real" / CASE / "case.yml").read_text(encoding="utf-8"))

    pairs = [(instant(when) if when else None,
              measured_row(digest=digest, passes=ok, ran_at=when))
             for when, ok in data.draw(st.permutations(rows))]
    if not check_accounted._standing(pairs, case):
        return

    dated = [(when, row) for when, row in pairs if when is not None]
    winners = ([row for when, row in dated if when == max(w for w, _ in dated)]
               if dated else [row for _when, row in pairs])
    assert all(check_accounted.passed(row, case) for row in winners)


@given(st.lists(st.tuples(st.one_of(st.none(), dated_timestamps()),
                          st.booleans()),
                min_size=1, max_size=4),
       st.data())
def test_a_verdict_does_not_depend_on_which_file_a_row_landed_in(
        tmp_path, monkeypatch, rows, data):
    """The same rows, dealt into files two different ways, settle the same case
    the same way. This is the `rb-mx5j` defect at the level it actually ran."""
    answers = []
    for split_at in (0, len(rows)):
        world = tmp_path / "w{}".format(next(_WORLDS))
        world.mkdir()
        digest = build_world(world)
        monkeypatch.setattr(check_accounted, "ROOT", world)
        ordered = list(data.draw(st.permutations(rows))) if split_at else list(rows)
        built = [measured_row(digest=digest, passes=ok, ran_at=when)
                 for when, ok in ordered]
        head, tail = built[:split_at], built[split_at:]
        if head:
            (world / "measurements" / "batch-z.json").write_text(
                json.dumps(head), encoding="utf-8")
        if tail:
            (world / "measurements" / "batch-a.json").write_text(
                json.dumps(tail), encoding="utf-8")
        answers.append(check_accounted.verdicts())
    assert answers[0] == answers[1]


@given(artifacts())
def test_splitting_a_canonical_half_again_changes_nothing(artifact):
    """The partition is a partition: applied twice it moves nothing further.

    Not a stated invariant, but the one that would break first if a declared
    path ever matched something the first pass left behind — which is exactly
    what a restructured artifact does.
    """
    once, _ = canonical.split(artifact)
    twice, telemetry = canonical.split(once)
    assert twice == once
    assert telemetry == {}


@given(result_rows(), st.data())
def test_reading_a_row_never_crashes_the_tally(tmp_path, monkeypatch, row,
                                               data):
    """"Could not check" and "clean" are different answers with different exit
    codes, and a traceback out of the middle of the tally is neither.

    `verdicts()` reaches `passed()` with whatever a measurement file holds. The
    file's own JSON parse is wrapped in `try`; the row's contents are not.

    Three answers, not two, and the third is why this property exists. `True`
    and `False` are verdicts about the agent; `None` is the row saying nothing
    — its findings are not a list, so nothing can be re-judged from it.
    `_standing` drops it and the case falls to `unaccounted`, which asks for a
    decision instead of making one. Asserting `isinstance(..., bool)` here
    would forbid exactly the answer the fix added.
    """
    world = tmp_path / "w{}".format(next(_WORLDS))
    world.mkdir()
    build_world(world)
    monkeypatch.setattr(check_accounted, "ROOT", world)
    case = yaml.safe_load(
        (world / "corpus-real" / CASE / "case.yml").read_text(encoding="utf-8"))
    if data.draw(st.booleans()):
        case = {}          # a manifest that failed to parse; `verdicts` feeds
        # `yaml.safe_load(...) or {}` straight in, so this is not hypothetical

    answer = check_accounted.passed(row, case)

    assert answer is None or isinstance(answer, bool)


# -------------------------------------------- the whole tally, as a partition


CASE_SPEC = st.fixed_dictionaries({
    "members": st.booleans(),
    "where": st.sampled_from(["nowhere", "stream", "queue", "experiment"]),
    "passes": st.booleans(),
    "digest_matches": st.booleans(),
    "limitation": st.booleans(),
    "malformed": st.booleans(),
    "known_failure": st.booleans(),
})


def build_corpus(root: Path, specs) -> list:
    """A whole small world: cases, rulings, LIMITATIONS.md, and rows."""
    (root / "measurements" / "queue").mkdir(parents=True)
    adjudications: list = []
    limitations: list = []
    ids = []
    for index, spec in enumerate(specs):
        case_id = "xx-p{}-0000-0000".format(index)
        ids.append(case_id)
        directory = root / "corpus-real" / case_id
        directory.mkdir(parents=True)
        if spec["members"]:
            for member in ("safe", "unsafe"):
                body = directory / member / "app"
                body.mkdir(parents=True)
                (body / "handler.py").write_text("# {}\n".format(member),
                                                 encoding="utf-8")
        (directory / "case.yml").write_text(yaml.safe_dump({
            "case_id": case_id, "language": "py", "construction": "regression",
            "expected_category": ["injection"],
            "expected_file": ["app/handler.py"],
        }), encoding="utf-8")
        if spec["malformed"]:
            adjudications.append({"case_id": case_id, "case_is_malformed": True,
                                  "why_malformed": "cannot discriminate"})
        if spec["known_failure"]:
            adjudications.append({"case_id": case_id, "known_failure": True})
        if spec["limitation"]:
            limitations.append("- {} is not fixed".format(case_id))
    (root / "corpus-real" / "adjudications.yml").write_text(
        yaml.safe_dump({"adjudications": adjudications}), encoding="utf-8")
    (root / "LIMITATIONS.md").write_text("\n".join(limitations) + "\n",
                                         encoding="utf-8")

    for case_id, spec in zip(ids, specs):
        if spec["where"] == "nowhere":
            continue
        digest = (case_digest(root / "corpus-real" / case_id)
                  if spec["digest_matches"] else "0" * 16)
        finding = {"category": "injection", "file": "app/handler.py",
                   "fingerprint": "f" * 16}
        row = {"case_id": case_id, "case_digest": digest,
               "pair_success": spec["passes"],
               "ran_at": "2026-08-28T12:00:00+00:00",
               "unsafe_findings": [finding] if spec["passes"] else [],
               "safe_findings": []}
        if spec["where"] == "stream":
            target = root / "measurements" / "{}.json".format(case_id)
            target.write_text(json.dumps([row]), encoding="utf-8")
        elif spec["where"] == "queue":
            target = root / "measurements" / "queue" / "{}.json".format(case_id)
            target.write_text(json.dumps(row), encoding="utf-8")
        else:
            outside = root / "measurements" / "experiment-x" / "pass-a"
            outside.mkdir(parents=True, exist_ok=True)
            (outside / "{}.json".format(case_id)).write_text(
                json.dumps(row), encoding="utf-8")
    return ids


@given(specs=st.lists(CASE_SPEC, min_size=1, max_size=4))
def test_every_case_lands_in_exactly_one_bucket(tmp_path, monkeypatch, specs):
    """"That is the whole test", and the report says the numbers sum.

    A case in two buckets double-counts the work left; a case in none is a
    failure sitting behind a fraction that looks finished — which is how point 9
    accumulated seventeen of them unnoticed.
    """
    world = tmp_path / "w{}".format(next(_WORLDS))
    world.mkdir()
    ids = build_corpus(world, specs)
    monkeypatch.setattr(check_accounted, "ROOT", world)

    buckets = check_accounted.account()
    placed = [case_id for names in buckets.values() for case_id in names]
    assert sorted(placed) == sorted(ids)
    assert len(placed) == len(set(placed))
    assert sum(len(v) for v in buckets.values()) == len(ids)


@given(specs=st.lists(CASE_SPEC, min_size=1, max_size=4))
def test_a_case_bought_outside_the_stream_is_never_reported_as_never_run(
        tmp_path, monkeypatch, specs):
    """It cost about a dollar, twice, before the two questions were separated.

    "What is this case's answer" comes from the production stream; "do we still
    owe a measurement for it" has to count every review that was bought,
    including the ones an experiment wrote under `experiment-*/pass-*/`.
    Reading it as `unrun` is a request to pay for the same case again.
    """
    world = tmp_path / "w{}".format(next(_WORLDS))
    world.mkdir()
    ids = build_corpus(world, specs)
    monkeypatch.setattr(check_accounted, "ROOT", world)

    buckets = check_accounted.account()
    for case_id, spec in zip(ids, specs):
        if (spec["where"] == "experiment" and spec["members"]
                and spec["digest_matches"] and not spec["malformed"]):
            assert case_id not in buckets["unrun"], case_id
            assert case_id in buckets["unadopted"], case_id


@given(specs=st.lists(CASE_SPEC, min_size=1, max_size=4))
def test_a_case_with_no_members_never_passes(tmp_path, monkeypatch, specs):
    """`case_digest` answers `no-members` rather than the empty-SHA constant,
    which was the same value for every such case — so one stored row would have
    answered `about_this_version` for all of them."""
    world = tmp_path / "w{}".format(next(_WORLDS))
    world.mkdir()
    ids = build_corpus(world, specs)
    monkeypatch.setattr(check_accounted, "ROOT", world)

    buckets = check_accounted.account()
    for case_id, spec in zip(ids, specs):
        if not spec["members"]:
            assert case_id not in buckets["pass"], case_id


@given(specs=st.lists(CASE_SPEC, min_size=1, max_size=4))
def test_a_row_inside_the_stream_is_never_counted_as_outside_it(
        tmp_path, monkeypatch, specs):
    """`stage2.measured_outside_the_stream` answers the other half of the same
    question, and the two readers have to agree about where a row lives."""
    world = tmp_path / "w{}".format(next(_WORLDS))
    world.mkdir()
    ids = build_corpus(world, specs)
    monkeypatch.setattr(stage2, "ROOT", world)

    current = {case_id: {case_digest(world / "corpus-real" / case_id)}
               for case_id in ids}
    outside = stage2.measured_outside_the_stream(current)
    for case_id, spec in zip(ids, specs):
        if spec["where"] != "experiment":
            assert case_id not in outside, case_id


# ----------------------------------------------------------- sentinel_compare


REF_MODEL = "claude-opus-5"
CHALLENGER = "claude-sonnet-5"
SC_DIGEST = "d" * 16


def sc_member() -> dict:
    return {
        "provenance": {"system_prompt_sha": "aaa", "verifier_prompt_sha": "bbb",
                       "schema_sha": "ccc", "agent_version": "0.1.0",
                       "model_requested": CHALLENGER,
                       "model_substituted": False,
                       "models_served": [CHALLENGER]},
        "settings": {"verify": True, "verify_model": REF_MODEL,
                     "effort": "high"},
    }


def sc_row(case_id: str, passed: bool, run_id: str, *,
           missed=None, false_alarm=False) -> dict:
    return {
        "case_id": case_id,
        "pair_success": passed,
        "case_digest": SC_DIGEST,
        "run_id": run_id,
        "unsafe_recall": (not missed) if missed is not None else passed,
        "safe_false_positive": false_alarm,
        "members": {"safe": sc_member(), "unsafe": sc_member()},
    }


def sc_reference(path: Path, comparable, failing=(), *, confirmations=2,
                 reject_at=2, failed_by="missed") -> Path:
    entries = {}
    for case_id in comparable:
        passed = case_id not in failing
        shape = {"missed": (not passed) and failed_by == "missed",
                 "false_alarm": (not passed) and failed_by == "false_alarm"}
        entries[case_id] = {
            "outcomes": {"pass-a": passed, "pass-b": passed},
            "shape": {"pass-a": dict(shape), "pass-b": dict(shape)},
            "case_digest": SC_DIGEST,
            # Written because the comparator requires the per-case flag and
            # the top-level list to agree — the same fact spelled twice, and
            # until 2026-09-05 only one spelling was checked.
            "unstable_under_reference": False,
        }
    path.write_text(json.dumps({
        "model": REF_MODEL,
        "verifier_model": REF_MODEL,
        "observed_models": {"safe": [REF_MODEL], "unsafe": [REF_MODEL]},
        "environment": {"system_prompt": "aaa", "verifier_prompt": "bbb",
                        "findings_schema": "ccc", "agent_version": "0.1.0"},
        "cases": entries,
        "comparable": sorted(comparable),
        "unstable_under_reference": [],
        "threshold": {"reject_at_net": reject_at,
                      "confirmations_required": confirmations,
                      "rule_version": sentinel_compare.RULE_VERSION,
                      "in_words": "two confirmed regressions reject"},
    }), encoding="utf-8")
    return path


def sc_write_run(path: Path, rows) -> Path:
    path.write_text(json.dumps(list(rows)), encoding="utf-8")
    return path


COMPARABLE = ("one", "two", "three")

# One outcome per case per run: whether the pair discriminated, and — because
# "worse is not one number" — which of the two kinds of failure it showed.
OUTCOME = st.fixed_dictionaries({"passed": st.booleans(),
                                 "missed": st.booleans(),
                                 "false_alarm": st.booleans()})
VERDICTS = st.lists(OUTCOME, min_size=len(COMPARABLE), max_size=len(COMPARABLE))

# At most one case may fail under the reference: `reject_at_net` is 2, and a
# reference with fewer than two steady passes cannot detect a `pass -> fail` at
# all — which the comparator refuses outright.
FAILING = st.sampled_from([(), ("one",), ("two",), ("three",)])


def _valid_runs(world: Path, verdicts_per_run):
    paths = []
    for index, outcomes in enumerate(verdicts_per_run):
        rows = [sc_row(case_id, out["passed"], "{}:{}".format(index, case_id),
                       missed=out["missed"], false_alarm=out["false_alarm"])
                for case_id, out in zip(COMPARABLE, outcomes)]
        paths.append(sc_write_run(world / "run-{}.json".format(index), rows))
    return paths


@given(runs=st.lists(VERDICTS, min_size=2, max_size=3),
       drop=st.sampled_from(COMPARABLE),
       from_run=st.integers(0, 2))
def test_a_case_missing_from_a_run_is_refused_rather_than_decided(
        tmp_path, runs, drop, from_run):
    """Every quiet zero here reads as "the cheaper model is fine"."""
    world = tmp_path / "w{}".format(next(_WORLDS))
    world.mkdir()
    reference = sc_reference(world / "reference.json", COMPARABLE)
    paths = _valid_runs(world, runs)
    target = paths[from_run % len(paths)]
    kept = [r for r in json.loads(target.read_text(encoding="utf-8"))
            if r["case_id"] != drop]
    sc_write_run(target, kept)

    with pytest.raises(sentinel_compare.ComparisonError):
        sentinel_compare.compare(reference, paths)


@given(runs=st.lists(VERDICTS, min_size=2, max_size=3),
       twice=st.sampled_from(COMPARABLE))
def test_a_case_recorded_twice_in_one_run_is_refused(tmp_path, runs, twice):
    """"One file is one run." A duplicate counts one measurement twice."""
    world = tmp_path / "w{}".format(next(_WORLDS))
    world.mkdir()
    reference = sc_reference(world / "reference.json", COMPARABLE)
    paths = _valid_runs(world, runs)
    rows = json.loads(paths[0].read_text(encoding="utf-8"))
    sc_write_run(paths[0], rows + [dict(r) for r in rows if r["case_id"] == twice])

    with pytest.raises(sentinel_compare.ComparisonError):
        sentinel_compare.compare(reference, paths)


@given(runs=st.lists(VERDICTS, min_size=2, max_size=3),
       case_id=st.sampled_from(COMPARABLE),
       value=awkward_bools().filter(lambda v: not isinstance(v, bool)))
def test_a_verdict_that_is_not_a_boolean_is_refused(tmp_path, runs, case_id,
                                                    value):
    """`bool(row.get(...))` reads a missing field as "no" and `"false"` as
    "yes". Either quietly moves a case between counted and not counted."""
    world = tmp_path / "w{}".format(next(_WORLDS))
    world.mkdir()
    reference = sc_reference(world / "reference.json", COMPARABLE)
    paths = _valid_runs(world, runs)
    rows = json.loads(paths[0].read_text(encoding="utf-8"))
    for row in rows:
        if row["case_id"] == case_id:
            row["pair_success"] = value
    sc_write_run(paths[0], rows)

    with pytest.raises(sentinel_compare.ComparisonError):
        sentinel_compare.compare(reference, paths)


@given(confirmations=st.integers(2, 4), runs=st.lists(VERDICTS, min_size=1,
                                                      max_size=3))
def test_net_is_never_computed_from_fewer_runs_than_the_threshold_requires(
        tmp_path, confirmations, runs):
    """One run cannot tell a worse model from the suite moving — the reference
    disagreed with itself on two of thirteen cases."""
    assume(len(runs) < confirmations)
    world = tmp_path / "w{}".format(next(_WORLDS))
    world.mkdir()
    reference = sc_reference(world / "reference.json", COMPARABLE,
                             confirmations=confirmations, reject_at=2)
    paths = _valid_runs(world, runs)

    with pytest.raises(sentinel_compare.ComparisonError):
        sentinel_compare.compare(reference, paths)


@given(runs=st.lists(VERDICTS, min_size=2, max_size=3), failing=FAILING,
       data=st.data())
def test_the_verdict_does_not_depend_on_the_order_the_runs_are_given_in(
        tmp_path, runs, failing, data):
    """A repetition is a set of runs, not a sequence. Order deciding anything
    here would be the glob-order defect again, one tool along."""
    world = tmp_path / "w{}".format(next(_WORLDS))
    world.mkdir()
    reference = sc_reference(world / "reference.json", COMPARABLE, failing)
    paths = _valid_runs(world, runs)
    shuffled = list(data.draw(st.permutations(paths)))

    first = sentinel_compare.compare(reference, paths)
    second = sentinel_compare.compare(reference, shuffled)
    assert first == second


@given(runs=st.lists(VERDICTS, min_size=2, max_size=3), failing=FAILING,
       data=st.data())
def test_the_verdict_does_not_depend_on_the_order_of_rows_in_a_file(
        tmp_path, runs, failing, data):
    """A pass directory is read with `glob`, so row order is the filesystem's
    choice and must not be a decision."""
    world = tmp_path / "w{}".format(next(_WORLDS))
    world.mkdir()
    reference = sc_reference(world / "reference.json", COMPARABLE, failing)
    paths = _valid_runs(world, runs)
    before = sentinel_compare.compare(reference, paths)
    for path in paths:
        rows = json.loads(path.read_text(encoding="utf-8"))
        sc_write_run(path, data.draw(st.permutations(rows)))

    assert sentinel_compare.compare(reference, paths) == before


@given(runs=st.lists(VERDICTS, min_size=2, max_size=3), failing=FAILING)
def test_a_pass_directory_and_one_file_of_the_same_rows_decide_the_same(
        tmp_path, runs, failing):
    """`experiment.py` writes one file per case under a pass directory, and the
    comparator first accepted only a single file holding the whole pass — so the
    paid results could not be handed to the thing built to read them."""
    world = tmp_path / "w{}".format(next(_WORLDS))
    world.mkdir()
    reference = sc_reference(world / "reference.json", COMPARABLE, failing)
    files = _valid_runs(world, runs)
    as_files = sentinel_compare.compare(reference, files)

    directories = []
    for index, path in enumerate(files):
        folder = world / "pass-{}".format(index)
        folder.mkdir()
        for row in json.loads(path.read_text(encoding="utf-8")):
            (folder / "{}.json".format(row["case_id"])).write_text(
                json.dumps(row), encoding="utf-8")
        directories.append(folder)

    assert sentinel_compare.compare(reference, directories) == as_files


@given(runs=st.lists(VERDICTS, min_size=2, max_size=4), failing=FAILING)
def test_a_rejection_names_enough_cases_that_actually_failed_enough_times(
        tmp_path, runs, failing):
    """The verdict has to be traceable back to the rows.

    "Two worse and two better was a net of zero and, the code decided, passes
    the gate" — the arithmetic is the thing that went wrong last time, so this
    checks the number against the data rather than against itself.
    """
    world = tmp_path / "w{}".format(next(_WORLDS))
    world.mkdir()
    reference = sc_reference(world / "reference.json", COMPARABLE, failing)
    paths = _valid_runs(world, runs)
    result = sentinel_compare.compare(reference, paths)
    needed = result["threshold"]["confirmations_required"]

    for case_id in result["regressed"]:
        index = COMPARABLE.index(case_id)
        if case_id in failing:
            continue          # a still-failing case regresses by shape, below
        assert sum(1 for outcomes in runs
                   if not outcomes[index]["passed"]) >= needed
    if result["verdict"] == "reject":
        assert len(result["regressed"]) >= result["threshold"]["reject_at_net"]


@given(runs=st.lists(VERDICTS, min_size=2, max_size=3), failing=FAILING,
       failed_by=st.sampled_from(["missed", "false_alarm"]))
def test_the_four_outcomes_partition_the_comparable_cases(
        tmp_path, runs, failing, failed_by):
    """Every comparable case lands in exactly one of regressed, improved,
    traded and steady, and `net` is the count of regressions and nothing else.
    A case falling out of all four would be a measurement quietly dropped."""
    world = tmp_path / "w{}".format(next(_WORLDS))
    world.mkdir()
    reference = sc_reference(world / "reference.json", COMPARABLE, failing,
                             failed_by=failed_by)
    paths = _valid_runs(world, runs)

    result = sentinel_compare.compare(reference, paths)
    buckets = [c for label in ("regressed", "improved", "traded", "steady")
               for c in result[label]]
    assert sorted(buckets) == sorted(COMPARABLE)
    assert len(buckets) == len(set(buckets))
    assert result["net"] == len(result["regressed"])
    assert result["net"] <= len(result["comparable"])


# --------------------------------------------------------- experiment.drift


ENV_KEYS = st.sampled_from(
    ["agent_version", "system_prompt", "verifier_prompt", "findings_schema",
     "adjudications", "scorer", "reviewer", "model_requested",
     "verifier_requested", "verify"])

ENV_VALUES = st.sampled_from(["0.1.0", "aa11bb22", "", "on", "off",
                              REF_MODEL, CHALLENGER])


@given(frozen=st.dictionaries(ENV_KEYS, ENV_VALUES, min_size=1, max_size=5),
       data=st.data())
def test_a_frozen_key_the_environment_no_longer_has_is_reported_as_moved(
        monkeypatch, frozen, data):
    """`verify`'s exit code is the permission to spend, so a key that stopped
    being recorded must read as a change and not as agreement.

    Everything `environment_now` produces today is a string, which is why the
    strategy holds strings: `None` there is a different question, and it is
    written up under `TestFoundByHypothesis`.
    """
    gone = set(data.draw(st.lists(st.sampled_from(sorted(frozen)),
                                  unique=True, max_size=len(frozen))))
    monkeypatch.setattr(experiment, "environment_now",
                        lambda: {k: v for k, v in frozen.items()
                                 if k not in gone})
    monkeypatch.setattr(experiment, "digest_file", lambda _path: "unchanged")

    moved = experiment.drift({"environment": frozen,
                              "suite": {"digest": "unchanged"},
                              "cases": []})
    for key in gone:
        assert any(line.startswith(key + ":") for line in moved), key


@given(frozen=st.dictionaries(ENV_KEYS, ENV_VALUES, min_size=1, max_size=5))
def test_an_unchanged_environment_reports_nothing_moved(monkeypatch, frozen):
    """The other direction, so the property above cannot be satisfied by a
    function that reports everything."""
    monkeypatch.setattr(experiment, "environment_now", lambda: dict(frozen))
    monkeypatch.setattr(experiment, "digest_file", lambda _path: "unchanged")

    assert experiment.drift({"environment": frozen,
                             "suite": {"digest": "unchanged"},
                             "cases": []}) == []


# --------------------------------------------------- what the properties found


class TestFoundByHypothesis:
    """Shrunk counterexamples, kept as plain tests. The generator's job was to
    find them; once the input is known, generating it again buys nothing.

    Each is `xfail(strict=True)` and asserts the **right** answer. It will turn
    red the day the defect is fixed and the marker is not removed, which is the
    signal wanted: nothing else in this repository would say so.
    """

    def test_a_findings_field_that_is_not_a_list_does_not_crash_the_tally(
            self, tmp_path, monkeypatch):
        """Shrunk from `test_reading_a_row_never_crashes_the_tally`.

        The input, minimised: a row that clears every guard in front of it —
        `scorable` says finished, `about_this_version` says it is about today's
        case — and whose `unsafe_findings` is an object rather than a list.

        The wrong answer: `check_accounted.verdicts()` raises
        `AttributeError: 'str' object has no attribute 'get'` out of
        `artifact.is_target`. `row.get("unsafe_findings") or []` keeps a truthy
        dict, iterating a dict yields its keys, and a key is a string. A list of
        strings does the same thing. `account()` goes down with it, so the
        command that answers "where are we in the cycle" prints a traceback and
        exits 1 — the same exit code it uses for "there is work left", so a
        crash is indistinguishable from an answer. `tools/stage2.py::_pair_passed`
        carries the identical two lines and fails the identical way.

        Fixed with `findings_list`, one definition read by both tools: a
        field that is not a list yields `None`, and `passed` returns `None`
        rather than `False`. Not `False`, because a row whose findings cannot
        be read has not said the agent missed the weakness — it has said
        nothing, and scoring it as a failure would put a wrong answer where an
        absent one belongs.
        """
        world = tmp_path / "no-list"
        world.mkdir()
        digest = build_world(world)
        monkeypatch.setattr(check_accounted, "ROOT", world)
        (world / "LIMITATIONS.md").write_text("\n", encoding="utf-8")
        (world / "measurements" / "batch.json").write_text(json.dumps([{
            "case_id": CASE,
            "case_digest": digest,
            "pair_success": True,
            "ran_at": "2026-08-28T12:00:00+00:00",
            "unsafe_findings": {"category": "injection",
                                "file": "app/handler.py"},
            "safe_findings": [],
        }]), encoding="utf-8")

        # Absent from the tally, not present as a failure: `verdicts` keeps
        # only rows that answered, so the case falls to `unaccounted` and
        # `account()` says its name instead of dying.
        assert check_accounted.verdicts() == {}

    def test_a_row_that_cannot_be_read_asks_for_a_decision(
            self, tmp_path, monkeypatch):
        """Where the case lands, not only whether the tally survives.

        `verdicts()` correctly skipped a case whose only row does not answer.
        `account()` then saw `executed()` still counting that row and filed the
        case under `unadopted` — which says "a measurement is waiting to be
        adopted" and sends somebody to adopt a row nothing can read.
        `unaccounted` is the bucket that asks for a decision rather than
        making one.

        And a *list* holding something that is not a finding was worse than
        the non-list case it was written beside: the first fix filtered the
        strays out and scored the row as a miss, which is a wrong answer where
        an absent one belongs. `["bad"]` is a findings field this cannot read,
        not a run that found nothing.
        """
        world = tmp_path / "unreadable"
        world.mkdir()
        digest = build_world(world)
        monkeypatch.setattr(check_accounted, "ROOT", world)
        (world / "LIMITATIONS.md").write_text("\n", encoding="utf-8")
        (world / "measurements" / "batch.json").write_text(json.dumps([{
            "case_id": CASE,
            "case_digest": digest,
            "pair_success": True,
            "ran_at": "2026-08-28T12:00:00+00:00",
            "unsafe_findings": ["not a finding"],
            "safe_findings": [],
        }]), encoding="utf-8")

        assert check_accounted.verdicts() == {}
        assert check_accounted.standings() == {CASE: None}

        buckets = check_accounted.account()
        assert CASE in buckets["unaccounted"]
        assert CASE not in buckets["unadopted"]
        assert CASE not in buckets["pass"]

    def test_a_silent_row_beside_a_readable_one_does_not_settle_the_case(
            self, tmp_path, monkeypatch):
        """"Does not say" must not become "ignore me".

        The first fix discarded `None` unconditionally, so `{True, None}`
        collapsed to `{True}` and one readable row settled a case whose other
        row at the same instant could not be read. The unreadable row may have
        been a disagreeing run whose answer cannot be recovered — it is a
        missing answer beside the readable one, not evidence for it.

        Alone, `None` means the case has no verdict. Beside a real answer it
        means the latest instant is unresolved, which is the rule this module
        already applies to two rows that disagree outright.
        """
        world = tmp_path / "mixed"
        world.mkdir()
        digest = build_world(world)
        monkeypatch.setattr(check_accounted, "ROOT", world)
        (world / "LIMITATIONS.md").write_text("\n", encoding="utf-8")
        same_moment = "2026-08-28T12:00:00+00:00"
        (world / "measurements" / "batch.json").write_text(json.dumps([
            {"case_id": CASE, "case_digest": digest, "pair_success": True,
             "ran_at": same_moment,
             "unsafe_findings": [{"category": "injection",
                                  "file": "app/handler.py"}],
             "safe_findings": []},
            {"case_id": CASE, "case_digest": digest, "pair_success": True,
             "ran_at": same_moment,
             "unsafe_findings": ["not a finding"], "safe_findings": []},
        ]), encoding="utf-8")

        # Not `{CASE: True}`: one of the two rows at that instant says nothing.
        assert check_accounted.verdicts() == {}
        assert check_accounted.account()["pass"] == []

    def test_an_unreadable_row_does_not_revoke_a_limitation(
            self, tmp_path, monkeypatch):
        """A malformed measurement is not an argument against a human ruling.

        The `unaccounted` branch was placed ahead of `known_failure` and
        `limitation`, so one broken row moved a case out of a decision somebody
        had made and recorded. Those classifications keep their precedence.
        """
        world = tmp_path / "ruled"
        world.mkdir()
        digest = build_world(world)
        monkeypatch.setattr(check_accounted, "ROOT", world)
        (world / "LIMITATIONS.md").write_text(
            "The agent does not handle {}.\n".format(CASE), encoding="utf-8")
        (world / "measurements" / "batch.json").write_text(json.dumps([{
            "case_id": CASE, "case_digest": digest, "pair_success": True,
            "ran_at": "2026-08-28T12:00:00+00:00",
            "unsafe_findings": ["not a finding"], "safe_findings": [],
        }]), encoding="utf-8")

        buckets = check_accounted.account()

        assert CASE in buckets["limitation"]
        assert CASE not in buckets["unaccounted"]

    def test_negative_zero_differs_in_bytes_and_in_no_path(self):
        """Shrunk from
        `test_differences_names_a_path_exactly_when_the_halves_are_not_identical`.

        The input: `{"cost": -0.0}` against `{"cost": 0.0}`.

        The wrong answer: `identical()` is `False` — `json.dumps` writes `-0.0`
        and `0.0` — while `differences()` returns `[]`, because `_diff` falls
        through to `left == right` and `-0.0 == 0.0`. A conformance failure that
        names no differing path is the failure `differences` exists to prevent:
        "a failing byte comparison says only that two long strings differ", and
        this is a comparison that fails and then says nothing at all.

        Latent rather than live: no producer here writes a negative zero, and
        `json.loads("-0.0")` is the only way one arrives.

        Fixed by comparing leaves as they will be *written* rather than as
        Python compares them, so the two answers agree by construction instead
        of by a list of special cases.
        """
        left, right = {"cost": -0.0}, {"cost": 0.0}
        assert (canonical.differences(left, right) == []) == canonical.identical(
            left, right)

    def test_a_frozen_null_that_left_the_environment_is_not_agreement(
            self, monkeypatch):
        """Shrunk from
        `test_a_frozen_key_the_environment_no_longer_has_is_reported_as_moved`.

        The input: a manifest freezing `{"scorer": None}`, checked against an
        environment that no longer records `scorer` at all.

        The wrong answer: `drift` returns `[]` — "nothing has moved since the
        freeze" — and `verify` exits 0, which *is the permission to spend*. The
        line is `if now.get(key) != was`, and `now.get` answers `None` for a key
        that is gone, so a frozen `None` and a vanished key compare equal. The
        repository's own recurring defect, in the one function whose exit code
        authorises money.

        Latent today: every producer of `environment_now` returns a string —
        `round.digest_of` answers `""` on a missing file, and `Config` resolves
        `verifier_model` to a string — so no manifest on disk holds a `None`.
        A frozen `""` was reported correctly; only `None` was invisible.

        Fixed: `drift` compares against a sentinel, so a key that has left the
        environment is movement whatever it was frozen as. The `xfail` marker
        turned red the moment it passed, which is the whole reason it was
        written as `strict`.
        """
        monkeypatch.setattr(experiment, "environment_now", dict)
        monkeypatch.setattr(experiment, "digest_file", lambda _path: "unchanged")

        moved = experiment.drift({"environment": {"scorer": None},
                                  "suite": {"digest": "unchanged"},
                                  "cases": []})
        assert moved != []
