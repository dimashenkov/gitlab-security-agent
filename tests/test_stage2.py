"""The tracker itself, because it drifted from the plan without saying so.

Point 8 stopped being "twenty reviews of this repository's own changes" on
2026-08-27 and became "both members of every advisory pair, decision
preserved". `STAGE-2.md` was rewritten that day; `stage2.py` went on counting
reviews against a journal for another day, printing `0/20 reviews filed` for
work nobody was doing and a heading about reviewing our own repository.

Nothing caught it because nothing tested it. A tracker with no test reports
whatever it used to report, and it is the thing the numbers are read from.
"""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import stage2
from artifact import case_digest
from stage2 import BROKEN, DONE, PARTIAL, TODO, probe_use


class Args:
    tests = False
    full = False


TARGET = {"category": "injection", "file": "app.py"}


def case(root: Path, case_id: str, construction: str = "regression") -> None:
    """A case with an answer key, because a case without one scores nothing.

    The manifest used to name only the id and the construction, and `is_target`
    answered True for every finding when a case named neither a category nor a
    file — so `unsafe_findings: [{}]`, a finding with no category and no file,
    counted as having found the weakness. That is the defect these fixtures sat
    on, not a shape any real case has: `check_corpus.py` calls both absences a
    problem.
    """
    directory = root / "corpus-real" / case_id
    directory.mkdir(parents=True)
    (directory / "case.yml").write_text(
        "case_id: {}\nconstruction: {}\nexpected_category: {}\n"
        "expected_file: {}\n".format(case_id, construction,
                                     TARGET["category"], TARGET["file"]),
        encoding="utf-8")


def batch(root: Path, name: str, rows, mtime: float = 0.0) -> None:
    """Rows are stamped with the digest of the case they name.

    A row without one is a result about a version of the case nobody recorded,
    which is a state the tracker reports rather than counts — so a fixture that
    left it out would be testing that path in every test by accident. Pass
    `case_digest` explicitly to test it on purpose.
    """
    if isinstance(rows, list):
        for row in rows:
            if isinstance(row, dict) and "case_digest" not in row:
                directory = root / "corpus-real" / str(row.get("case_id"))
                if directory.is_dir():
                    row["case_digest"] = case_digest(directory)
    measurements = root / "measurements"
    measurements.mkdir(exist_ok=True)
    path = measurements / name
    path.write_text(json.dumps(rows), encoding="utf-8")
    if mtime:
        os.utime(path, (mtime, mtime))


@pytest.fixture
def root(tmp_path, monkeypatch) -> Path:
    (tmp_path / "corpus-real").mkdir()
    (tmp_path / "measurements").mkdir()
    monkeypatch.setattr(stage2, "ROOT", tmp_path)
    return tmp_path


def test_a_corpus_nobody_has_run_is_todo_not_done(root):
    case(root, "one")
    result = probe_use(Args())
    assert result.state == TODO
    assert "0/1" in result.detail


def test_every_pair_run_and_preserved_is_done(root):
    case(root, "one")
    case(root, "two")
    batch(root, "b.json", [{"case_id": "one", "pair_success": True},
                           {"case_id": "two", "pair_success": True}])
    assert probe_use(Args()).state == DONE


def test_a_pair_that_ran_and_lost_the_decision_is_not_counted_as_run_and_done(root):
    """Running is not passing. The old probe counted reviews filed, which is a
    count of runs, and a run that reached the wrong answer is one of those."""
    case(root, "one")
    batch(root, "b.json", [{"case_id": "one", "pair_success": False}])
    result = probe_use(Args())
    assert result.state == PARTIAL
    assert "1/1 run, 0 preserved" in result.detail


def test_the_two_constructions_are_never_added_together(root):
    """In a regression pair every unsafe member deletes something, so direction
    alone predicts the answer. A number mixing the two hides that, and the plan
    says in as many words never to score them together."""
    case(root, "one")
    case(root, "one-snap", construction="snapshot")
    batch(root, "b.json", [{"case_id": "one", "pair_success": True}])

    result = probe_use(Args())
    assert result.state == DONE
    assert "1/1" in result.detail
    assert "+1 snapshot" in result.detail


def test_two_runs_that_agree_give_that_answer(root):
    case(root, "one")
    batch(root, "cli-batch-1.json", [{"case_id": "one", "pair_success": True}])
    batch(root, "cli-batch-2.json", [{"case_id": "one", "pair_success": True}])
    assert probe_use(Args()).state == DONE


def test_two_runs_that_disagree_leave_the_case_unresolved_and_named(root):
    """There is nothing here to take the later one by.

    Filename order is not run order — `first-cli-pair.json` is the oldest run
    in `measurements/` and sorts after both batches — and modification time is
    not a record of anything, since a clone or a `touch` rewrites it and the
    answer would change without the repository changing.

    So it does not pick. Being unable to tell is a third answer, and one that
    names the case is one somebody can go and settle.
    """
    case(root, "one")
    case(root, "two")
    batch(root, "a.json", [{"case_id": "one", "pair_success": False},
                           {"case_id": "two", "pair_success": True}])
    batch(root, "b.json", [{"case_id": "one", "pair_success": True},
                           {"case_id": "two", "pair_success": True}])

    result = probe_use(Args())
    assert result.state == PARTIAL
    assert "unresolved" in result.detail
    assert "one" in result.detail
    assert "2/2 run, 1 preserved" in result.detail


def test_a_later_run_settles_a_case_the_earlier_one_failed(root):
    """Without this a case could never be *fixed* by running it again.

    Two runs that disagree left it unresolved, and the failing row went on
    matching the digest and re-deriving as a failure — so a corrected re-run
    moved the case from "failing" to "unresolved" and the target became
    unreachable. A re-run that cannot improve anything is a re-run nobody does.

    The order comes from a time recorded *in the row*, so it is content rather
    than a fact about the filesystem: filename order is not run order, and a
    clone rewrites modification times.
    """
    case(root, "one")
    batch(root, "a.json", [{"case_id": "one", "pair_success": False,
                            "ran_at": "2026-08-28T10:00:00+00:00"}])
    assert probe_use(Args()).state == PARTIAL

    batch(root, "b.json", [{"case_id": "one", "pair_success": True,
                            "ran_at": "2026-08-28T14:00:00+00:00"}])
    assert probe_use(Args()).state == DONE


def test_an_earlier_run_does_not_overturn_a_later_one(root):
    """The other direction, so the rule is an ordering and not a preference for
    whichever answer is nicer.

    `PARTIAL` alone would not show that: the rule this replaced — collect every
    verdict into a set and call a disagreement unresolved — also answers
    `PARTIAL` here. So the detail is what is asserted. The later failure has to
    *stand as the answer*, which reads as one run and none preserved, and the
    case must not be named as one nobody can settle.
    """
    case(root, "one")
    batch(root, "a.json", [{"case_id": "one", "pair_success": True,
                            "ran_at": "2026-08-28T10:00:00+00:00"}])
    batch(root, "b.json", [{"case_id": "one", "pair_success": False,
                            "ran_at": "2026-08-28T14:00:00+00:00"}])

    result = probe_use(Args())
    assert result.state == PARTIAL
    assert "1/1 run, 0 preserved" in result.detail
    assert "unresolved" not in result.detail


def test_the_later_run_is_the_later_instant_and_not_the_later_text(root):
    """`+03:00` at 14:00 is *earlier* than `+00:00` at 12:00, and the strings
    sort the other way. Comparing them as text let an earlier run supersede a
    later one whenever two batches carried different offsets — and both of ours
    are written by whatever machine ran them."""
    case(root, "one")
    batch(root, "a.json", [{"case_id": "one", "pair_success": True,
                            "ran_at": "2026-08-28T14:00:00+03:00"}])
    batch(root, "b.json", [{"case_id": "one", "pair_success": False,
                            "ran_at": "2026-08-28T12:00:00+00:00"}])

    # `unresolved` is what separates this from the rule that predates ordering
    # altogether — that one also answers `PARTIAL` with nothing preserved, but
    # because it cannot tell, not because the failure is the later answer.
    result = probe_use(Args())
    assert result.state == PARTIAL
    assert "1/1 run, 0 preserved" in result.detail
    assert "unresolved" not in result.detail


def test_a_time_that_will_not_parse_cannot_win_an_ordering(root):
    """Anything truthy used to count as a date, so `"yesterday"` sorted after
    every real timestamp and settled the case. A value that is not a time is
    treated as no time — it answers only if nothing real does."""
    case(root, "one")
    batch(root, "a.json", [{"case_id": "one", "pair_success": True,
                            "ran_at": "2026-08-28T14:00:00+00:00"}])
    batch(root, "b.json", [{"case_id": "one", "pair_success": False,
                            "ran_at": "yesterday"}])

    assert probe_use(Args()).state == DONE


def test_a_time_with_no_zone_is_not_an_instant(root):
    """It says a wall clock, not a moment, and the two batches need not have
    run on the same one."""
    case(root, "one")
    batch(root, "a.json", [{"case_id": "one", "pair_success": True,
                            "ran_at": "2026-08-28T14:00:00+00:00"}])
    batch(root, "b.json", [{"case_id": "one", "pair_success": False,
                            "ran_at": "2026-08-29T09:00:00"}])

    assert probe_use(Args()).state == DONE


def test_two_answers_at_the_same_instant_stay_unresolved(root):
    """`pair_corpus` stamps whole seconds, so a tie is reachable rather than
    theoretical. Ordering `(time, passed)` tuples made Python break the tie on
    the boolean, and `True` sorts last — so a tie silently resolved in favour
    of the nicer answer. Nothing here can tell which ran second, and inventing
    an order is the thing this rule was written to stop.
    """
    case(root, "one")
    batch(root, "a.json", [{"case_id": "one", "pair_success": True,
                            "ran_at": "2026-08-28T14:00:00+00:00"}])
    batch(root, "b.json", [{"case_id": "one", "pair_success": False,
                            "ran_at": "2026-08-28T14:00:00+00:00"}])

    # Honest about what this is: the answer here matches the rule that predates
    # ordering, so it does not distinguish the two. It guards the obvious way
    # to write the ordering — `max` over `(time, passed)` tuples, which breaks
    # the tie on the boolean and always picks `True`.
    result = probe_use(Args())
    assert result.state == PARTIAL
    assert "unresolved" in result.detail


def test_a_dated_run_settles_a_case_an_undated_one_disagrees_with(root):
    """The older batches carry no time. They answer only when nothing dated
    does — otherwise the four rows written before the field existed would hold
    a case unresolved for ever."""
    case(root, "one")
    batch(root, "old.json", [{"case_id": "one", "pair_success": False}])
    batch(root, "new.json", [{"case_id": "one", "pair_success": True,
                              "ran_at": "2026-08-28T14:00:00+00:00"}])

    assert probe_use(Args()).state == DONE


def test_two_undated_runs_that_disagree_are_still_unresolved(root):
    """Nothing to order them by, so nothing is invented. Being unable to tell
    stays a third answer."""
    case(root, "one")
    batch(root, "a.json", [{"case_id": "one", "pair_success": False}])
    batch(root, "b.json", [{"case_id": "one", "pair_success": True}])

    result = probe_use(Args())
    assert result.state == PARTIAL
    assert "unresolved" in result.detail


def test_ordering_cannot_be_changed_by_touching_a_file(root):
    """The property the mtime rule did not have: the answer is in the files."""
    case(root, "one")
    batch(root, "a.json", [{"case_id": "one", "pair_success": True}], mtime=9_000)
    batch(root, "b.json", [{"case_id": "one", "pair_success": True}], mtime=1_000)
    before = probe_use(Args())

    os.utime(root / "measurements" / "b.json", (9_999, 9_999))
    assert probe_use(Args()) == before


def test_a_result_about_an_older_version_of_the_case_does_not_count(root):
    """`rb-mx5j-mp4f-g8jg` had its weakness deleted by a bug in the comment
    stripper and then repaired. Its recorded failure was a failure at reviewing
    code that no longer exists, and nothing in the batch said which version it
    had seen — so the number went on standing for a question nobody had asked
    of the case as it is.
    """
    case(root, "one")
    batch(root, "b.json", [{"case_id": "one", "pair_success": True,
                            "case_digest": "0000000000000000"}])

    result = probe_use(Args())
    assert result.state == TODO
    assert "0/1" in result.detail


def test_a_result_from_before_the_version_was_recorded_is_named_not_dropped(root):
    """It is not a verdict about the case as it stands, and it is also not
    nothing: somebody paid for it. Reported as what it is."""
    case(root, "one")
    case(root, "two")
    batch(root, "b.json", [{"case_id": "one", "pair_success": True,
                            "case_digest": None},
                           {"case_id": "two", "pair_success": True}])

    result = probe_use(Args())
    assert result.state == PARTIAL
    assert "1/2 run" in result.detail
    assert "1 from an unrecorded corpus version" in result.detail


def test_a_member_edited_after_its_run_stops_counting(root):
    """The digest is over the case's own members, so editing one case must not
    invalidate the results of the others — and editing the code the agent saw
    must invalidate its own."""
    case(root, "one")
    case(root, "two")
    (root / "corpus-real" / "one" / "safe").mkdir()
    (root / "corpus-real" / "one" / "safe" / "a.py").write_text("x = 1\n")
    batch(root, "b.json", [{"case_id": "one", "pair_success": True},
                           {"case_id": "two", "pair_success": True}])
    assert probe_use(Args()).state == DONE

    (root / "corpus-real" / "one" / "safe" / "a.py").write_text("x = 2\n")

    result = probe_use(Args())
    assert result.state == PARTIAL
    assert "1/2 run" in result.detail


def test_correcting_the_answer_key_does_not_discard_the_run(root):
    """Two questions were being asked with one hash: is this result about the
    code the agent saw, and was it scored against the key in force now.

    `case.yml` holds the key. Correcting a category changes how a finding is
    scored and not one byte of what the reviewer was shown — and two keys have
    been corrected since results were stored. Digesting the manifest as well
    made each correction throw away the run it was made for.
    """
    case(root, "one")
    (root / "corpus-real" / "one" / "safe").mkdir()
    (root / "corpus-real" / "one" / "safe" / "a.py").write_text("x = 1\n")
    batch(root, "b.json", [{"case_id": "one", "pair_success": True}])
    assert probe_use(Args()).state == DONE

    (root / "corpus-real" / "one" / "case.yml").write_text(
        "case_id: one\nconstruction: regression\n# the key, corrected\n",
        encoding="utf-8")

    assert probe_use(Args()).state == DONE, (
        "a corrected key discarded the run it was corrected for")


def test_a_digest_written_by_the_older_definition_is_still_accepted(root):
    """The definition narrowed to the members. Every digest already stored was
    computed over the whole case, so refusing them would have discarded five
    paid runs — a number quietly going to zero because a rule changed
    underneath it, which is the shape of loss this line of work exists to
    stop. The old value says the whole case is unchanged, which is stronger
    than what the new one asks."""
    from artifact import legacy_case_digest

    case(root, "one")
    (root / "corpus-real" / "one" / "safe").mkdir()
    (root / "corpus-real" / "one" / "safe" / "a.py").write_text("x = 1\n")
    batch(root, "b.json", [{
        "case_id": "one", "pair_success": True,
        "case_digest": legacy_case_digest(root / "corpus-real" / "one")}])

    assert probe_use(Args()).state == DONE


def test_a_run_that_did_not_finish_is_not_a_failed_pair(root):
    """`first-cli-pair.json` holds exactly this: a case with `incomplete` for
    both members and no `pair_success` at all. Reading that as "did not
    preserve the decision" is a check that never ran, reported as one that
    failed — and it would also make a later real result look like a
    disagreement with it.
    """
    case(root, "one")
    batch(root, "a.json", [{"case_id": "one", "incomplete": ["safe", "unsafe"]}])

    result = probe_use(Args())
    assert result.state == TODO
    assert "0/1" in result.detail

    batch(root, "b.json", [{"case_id": "one", "pair_success": True}])
    assert probe_use(Args()).state == DONE


def test_only_a_real_true_counts_as_a_pair_preserved(root):
    """`bool("false")` is true. A tracker that reads the string "false" as a
    pass can be told the work is done by a typo in a file nobody re-reads."""
    case(root, "one")
    batch(root, "b.json", [{"case_id": "one", "pair_success": "false"}])
    assert probe_use(Args()).state == PARTIAL


@pytest.mark.parametrize("body", [
    {"unrelated": True},          # a dict that is not a batch
    5,                            # a scalar
    "not a batch",                # a string
    {"results": "not a list"},    # the right key, the wrong shape
    [None, 7, {"case_id": None}],  # rows that are not rows
])
def test_a_measurement_file_that_is_not_a_batch_is_skipped_not_fatal(root, body):
    """`measurements/` holds more than batch results, and a tracker that dies
    on the first unexpected file reports nothing at all."""
    case(root, "one")
    batch(root, "a-odd.json", body, mtime=1_000)
    batch(root, "b.json", [{"case_id": "one", "pair_success": True}], mtime=2_000)
    assert probe_use(Args()).state == DONE


def test_the_heading_does_not_promise_reviews_of_our_own_code():
    """The wording the plan retired. It is what a reader sees first."""
    source = (Path(stage2.__file__)).read_text(encoding="utf-8")
    heading = [line for line in source.splitlines()
               if "print(\"Stage 2 —" in line]
    assert heading, "no heading found"
    assert "own repository" not in heading[0]


def adjudicate(root: Path, case_id: str, why: str = "cannot measure") -> None:
    (root / "corpus-real" / "adjudications.yml").write_text(
        "adjudications:\n"
        "  - case_id: {}\n    case_is_malformed: true\n"
        "    why_malformed: {}\n".format(case_id, why), encoding="utf-8")


def test_a_case_ruled_unable_to_measure_leaves_both_sides_of_the_fraction(root):
    """It passed, and then somebody read its safe member and found the weakness
    still in it. Two cases went that way in one afternoon.

    The result is not wrong; the question it answered was. So the case leaves
    the numerator and the denominator together, rather than staying as a pass
    against a total nobody can reach — the plan said 24 of 24 for a day after
    the total became 22, and the target could not have been met against its own
    document.
    """
    from stage2 import probe_spend  # noqa: F401  (same module, same ROOT)

    case(root, "one")
    case(root, "two")
    batch(root, "b.json", [{"case_id": "one", "pair_success": True},
                           {"case_id": "two", "pair_success": True}])
    assert probe_use(Args()).state == DONE
    assert "2/2" in probe_use(Args()).detail

    adjudicate(root, "one")
    after = probe_use(Args())

    assert after.state == DONE, after
    assert "1/1" in after.detail, after


# ------------------------------------------------------------ how it was billed


def review(root: Path, name: str, **provenance) -> None:
    """One filed result, where a run actually lands.

    `measurements/`, not `journal/`. That directory is written only by
    `tools/review.sh` — the review-your-own-branch flow point 8 retired — so a
    probe reading it answered "no runs filed" over five paid batches.
    """
    case(root, name)
    batch(root, name + ".json", [{
        "case_id": name, "pair_success": True,
        "members": {"unsafe": {"provenance": provenance}}}])


def test_a_run_is_judged_by_its_login_and_not_by_the_figure(root):
    """The CLI reports `total_cost_usd` on a subscription too — a two-token
    reply on a Max plan came back as $0.29 — so it is what the run *would* have
    cost. A probe reading it as a bill calls every subscription run billed,
    which is the opposite of what it was written to find.

    Both runs here carry a large figure. Only the login separates them.
    """
    from stage2 import probe_spend

    review(root, "on-a-plan", provider="claude-cli", auth_method="claude.ai",
           auth_subscription="max", reported_cost_usd=0.29)
    assert probe_spend(Args()).state == DONE

    review(root, "on-a-key", provider="claude-cli", auth_method="api-key",
           reported_cost_usd=0.29)
    result = probe_spend(Args())

    assert result.state == "broken"
    assert "on-a-key" in result.detail


def test_a_run_that_did_not_say_how_it_was_authenticated_is_named(root):
    """Not counted as billed and not counted as free. The version before this
    read a missing cost as a zero and called that proof of a free run — the
    project's own absent-versus-zero rule, broken inside the tool that checks
    it."""
    from stage2 import probe_spend

    review(root, "said-nothing", provider="claude-cli")
    result = probe_spend(Args())

    assert result.state == PARTIAL
    assert "no auth method" in result.detail


def test_a_figure_without_a_login_is_still_a_run_that_did_not_say(root):
    """The sentence said "neither a cost nor an auth method" and this artifact
    has a cost — so it described the one case it was reached by incorrectly."""
    from stage2 import probe_spend

    review(root, "priced-but-anonymous", provider="claude-cli",
           reported_cost_usd=0.29)
    result = probe_spend(Args())

    assert result.state == PARTIAL
    assert "no auth method" in result.detail


def test_a_billed_member_is_not_hidden_behind_a_subscription_member(root):
    """The two members are two separate runs of the CLI.

    `pair_corpus` invokes it once for the safe side and once for the unsafe
    side, and the login can differ between them — a token exported into the
    environment for one and not the other is enough. The probe took the first
    member that named a provider and reported the whole pair by it, so a member
    billed against an API key disappeared behind a member on a subscription.
    Naming the billed run is the entire purpose of this probe.
    """
    from stage2 import probe_spend

    case(root, "one")
    batch(root, "b.json", [{
        "case_id": "one", "pair_success": True,
        "members": {
            "unsafe": {"provenance": {"provider": "claude-cli",
                                      "auth_method": "claude.ai",
                                      "auth_subscription": "max"}},
            "safe": {"provenance": {"provider": "claude-cli",
                                    "auth_method": "api-key"}}}}])

    result = probe_spend(Args())
    assert result.state == BROKEN
    assert "safe" in result.detail
    assert "api-key" in result.detail


def test_a_member_that_did_not_say_is_named_even_beside_one_that_did(root):
    """Same collapse, the quieter half of it: a member with no login recorded
    is a run nobody can account for, and standing next to an accounted-for one
    does not account for it."""
    from stage2 import probe_spend

    case(root, "one")
    batch(root, "b.json", [{
        "case_id": "one", "pair_success": True,
        "members": {
            "unsafe": {"provenance": {"provider": "claude-cli",
                                      "auth_method": "claude.ai",
                                      "auth_subscription": "max"}},
            "safe": {"provenance": {"provider": "claude-cli"}}}}])

    result = probe_spend(Args())
    assert result.state == PARTIAL
    assert "safe" in result.detail


def test_an_api_run_is_not_a_local_run(root):
    """The probe is about the local runner. An artifact from the paid path is
    not evidence either way, and reading one would be reading the wrong
    question — which the version before this did to every artifact, by looking
    for a container no artifact has ever had."""
    from stage2 import probe_spend

    review(root, "from-ci", provider="anthropic-api")
    assert probe_spend(Args()).state == TODO


# --------------------------------------------- where a paid run actually lands


def experiment_row(root: Path, case_id: str, row: dict,
                   where: str = "experiment-noise-floor/pass-a") -> None:
    """One row where `experiment.py` writes it: a bare object, one per file.

    Two things have to be right for such a row to be read at all — the glob has
    to reach the directory, and the reader has to accept an object where a
    batch is a list. Get only the first and the file is opened, parsed, and
    then iterated as nothing, which looks exactly like the fix having worked.
    """
    directory = root / "measurements" / where
    directory.mkdir(parents=True, exist_ok=True)
    if "case_digest" not in row:
        case_dir = root / "corpus-real" / case_id
        if case_dir.is_dir():
            row["case_digest"] = case_digest(case_dir)
    (directory / (case_id + ".json")).write_text(
        json.dumps(dict(row, case_id=case_id)), encoding="utf-8")


def test_the_production_stream_is_batches_and_the_queue_only(root):
    """It is not "every file holding paid results", whatever the docstring used
    to say, and it must not become that.

    `check_accounted.py` records what it cost when the two were folded
    together: a stability experiment's pass B became the production answer and
    moved `rb-g65v-27r3-5p6m` out of `LIMITATIONS.md` on a row nobody had
    checked. An experiment reads its prompts from a frozen copy and keeps its
    own scorer, reviewer and answer key, none of which `case_digest` compares.
    """
    case(root, "one")
    batch(root, "b.json", [{"case_id": "one", "pair_success": True}])
    experiment_row(root, "one", {"pair_success": False})

    names = {path.name for path in stage2.result_files()}

    assert names == {"b.json"}


def test_an_experiment_cannot_overturn_a_recorded_verdict(root):
    """The property, at the level that matters. The experiment row here is the
    later one by `ran_at`, so a reader that widened the glob would hand it the
    verdict — quietly, and with the tracker turning green or red on it."""
    case(root, "one")
    batch(root, "b.json", [{"case_id": "one", "pair_success": True,
                            "ran_at": "2026-09-01T09:00:00+00:00"}])
    experiment_row(root, "one", {"pair_success": False,
                                 "ran_at": "2026-09-01T13:00:00+00:00"})

    assert probe_use(Args()).state == DONE


def test_a_case_measured_only_by_an_experiment_is_not_reported_unrun(root):
    """The money question, and the one the glob gap actually broke.

    A case bought through an experiment and nowhere else read as never run, so
    the tracker asked the owner to pay for it a second time. That happened
    twice before `check_accounted.py` split the two questions, at about a
    dollar each. It is not a pass either — nothing has adopted the row — so it
    is named, and the naming is the decision somebody still has to make.
    """
    case(root, "one")
    case(root, "two")
    batch(root, "b.json", [{"case_id": "one", "pair_success": True}])
    experiment_row(root, "two", {"pair_success": True})

    result = probe_use(Args())

    assert "measured outside the stream and not adopted: two" in result.detail
    assert result.state == PARTIAL


def test_an_experiment_run_is_read_by_the_billing_probe(root):
    """A billed run is a billed run wherever its file was written. 27 of them
    were outside what this probe could open, and it printed "each on an
    established subscription" over a set it had not read — the same clean sheet
    over an unread corpus it was rewritten once already to stop printing."""
    from stage2 import probe_spend

    case(root, "one")
    experiment_row(root, "one", {
        "pair_success": True,
        "members": {"unsafe": {"provenance": {"provider": "claude-cli",
                                              "auth_method": "api-key"}}}})

    result = probe_spend(Args())

    assert result.state == "broken", result
    assert "one" in result.detail


def test_a_round_directory_is_read_by_the_billing_probe(root):
    """`--round N` writes `measurements/round-N/<case>.json`, the fourth place
    results land and the one no reader had heard of."""
    from stage2 import probe_spend

    case(root, "one")
    experiment_row(root, "one", {
        "pair_success": True,
        "members": {"unsafe": {"provenance": {"provider": "claude-cli",
                                              "auth_method": "api-key"}}}},
        where="round-2")

    assert probe_spend(Args()).state == "broken"


def failing_row(root: Path, case_id: str) -> None:
    """A pair whose unsafe member found nothing, which is a failure."""
    batch(root, case_id + ".json", [{
        "case_id": case_id, "pair_success": False,
        "safe_findings": [], "unsafe_findings": []}])


def test_a_failing_pair_nobody_has_explained_is_named(root):
    """Point 9 says a failure gets a fix, a limitation or a reason, and that
    there is no third state. It read `journal/` — written only by
    `tools/review.sh`, the flow point 8 retired — so it answered "nothing to
    reconcile yet" while pairs sat failing in `measurements/`."""
    from stage2 import probe_fixes

    case(root, "one")
    failing_row(root, "one")
    (root / "LIMITATIONS.md").write_text("nothing about it\n", encoding="utf-8")

    result = probe_fixes(Args())
    assert result.state == PARTIAL
    assert "one" in result.detail


def test_a_ruling_that_did_not_resolve_the_failure_does_not_account_for_it(root):
    """Point 9 allows two outcomes and says there is no third.

    A ruling was briefly counted as one, and it cannot be: every ruling is
    already applied before the pair is judged, so a ruling that resolved
    anything has moved the pair to passing and it never reaches this list.
    What is left — `rb-g65v`'s says so itself — is a ruling that takes no
    effect, and a sentence about why one candidate excuse was rejected is not
    a sentence about why the failure is acceptable. Counting it let the
    tracker report point 9 done over a current, unexplained failure.
    """
    from stage2 import probe_fixes

    case(root, "one")
    failing_row(root, "one")
    (root / "LIMITATIONS.md").write_text("nothing\n", encoding="utf-8")
    # `rb-g65v`'s shape: a ruling that examined the finding and concluded it
    # changes nothing. Not `case_is_malformed`, which *does* take the case out
    # — that is the ruling being applied, not a third state.
    (root / "corpus-real" / "adjudications.yml").write_text(
        "adjudications:\n  - case_id: one\n    incidental: true\n"
        "    fingerprint: ''\n    takes_effect: after the case is run again\n",
        encoding="utf-8")

    result = probe_fixes(Args())
    assert result.state == PARTIAL
    assert "one" in result.detail


def test_a_case_ruled_unable_to_measure_is_not_owed_an_explanation(root):
    """The other kind of ruling, and the reason the two must not be conflated.

    `case_is_malformed` says in as many words "do not count it as a failure",
    and point 8 already drops the case from both sides of its fraction. Point 9
    asking for an explanation of a failure point 8 does not record is the
    tracker asking about something it has itself excluded — which it did, for
    `cs-q939` and `py-6x92`, on the same run that named them.
    """
    from stage2 import probe_fixes

    case(root, "one")
    failing_row(root, "one")
    (root / "LIMITATIONS.md").write_text("nothing\n", encoding="utf-8")
    adjudicate(root, "one", why="the safe member carries it too")

    assert probe_fixes(Args()).state == TODO


def test_a_recorded_limitation_accounts_for_a_failure(root):
    """The outcome point 9 does name: written down, in the file readers are
    pointed at, saying the model did not catch it."""
    from stage2 import probe_fixes

    case(root, "one")
    failing_row(root, "one")
    (root / "LIMITATIONS.md").write_text(
        "one: the model does not catch this class\n", encoding="utf-8")

    assert probe_fixes(Args()).state == DONE


def test_a_limitation_for_the_snapshot_twin_does_not_account_for_the_other(root):
    """Every snapshot case is its twin's id with `-snap` appended.

    So a plain substring test finds the shorter id inside the longer one, and
    a sentence written about one pair silently accounts for a different pair
    nobody has written about. Two of the four cases in the corpus that carry
    rulings have twins in exactly this shape.
    """
    from stage2 import probe_fixes

    case(root, "one")
    failing_row(root, "one")
    (root / "LIMITATIONS.md").write_text(
        "one-snap: the snapshot construction cannot show this\n",
        encoding="utf-8")

    result = probe_fixes(Args())
    assert result.state == PARTIAL
    assert "one" in result.detail


def test_a_legacy_row_is_read_the_same_way_by_both_probes(root):
    """Rows written before findings were stored carry only `pair_success`.

    The count reads them through the fallback and calls them failures; the
    reconciliation skipped any row without `safe_findings` and answered
    "nothing to reconcile yet" about the very case the line above had just
    named. Two probes reading one row two ways is the tracker disagreeing with
    itself, which is what this whole file was written after.
    """
    from stage2 import probe_fixes

    case(root, "one")
    batch(root, "b.json", [{"case_id": "one", "pair_success": False}])
    (root / "LIMITATIONS.md").write_text("nothing\n", encoding="utf-8")

    assert probe_use(Args()).state == PARTIAL
    result = probe_fixes(Args())
    assert result.state == PARTIAL
    assert "one" in result.detail


def test_a_failure_against_a_version_that_no_longer_exists_is_not_owed_a_reason(root):
    """Two runs of `rb-mx5j` failed against the version whose weakness a bug in
    the comment stripper had deleted. Asking for an explanation of a failure at
    reviewing code that no longer exists is asking about the wrong thing.

    A second case, current and failing, is present so that the answer
    distinguishes "the stale row was read and rejected" from "the probe is not
    reading `measurements/` at all" — which is the bug this file exists for,
    and which would also produce a clean answer here.
    """
    from stage2 import probe_fixes

    case(root, "one")
    case(root, "two")
    batch(root, "old.json", [{
        "case_id": "one", "pair_success": False, "case_digest": "0" * 16,
        "safe_findings": [], "unsafe_findings": []}])
    failing_row(root, "two")
    (root / "LIMITATIONS.md").write_text("nothing\n", encoding="utf-8")

    result = probe_fixes(Args())
    assert result.state == PARTIAL
    assert "two" in result.detail
    assert "one" not in result.detail.replace("nothing", "")


def test_a_case_that_was_re_run_and_passed_is_no_longer_owed_an_explanation(root):
    """The reason `ran_at` was added, asked of the other probe.

    `probe_fixes` appended a case on the first failure it met and never took it
    off, so a case fixed by a re-run went on being demanded a limitation or a
    ruling for ever — while `probe_use`, which does apply the rule, reported it
    passing. A tracker that contradicts itself is worse than one that is wrong
    in one direction, and the direction it contradicted itself in was to keep
    asking about work already done.
    """
    from stage2 import probe_fixes

    # A second case, failing and ruled on, keeps the probe in reconciliation
    # rather than in "nothing to reconcile yet" — so the answer is about `one`
    # dropping out of the list and not about the list being empty.
    case(root, "one")
    case(root, "two")
    failing_row(root, "two")
    (root / "LIMITATIONS.md").write_text("two: known gap\n", encoding="utf-8")

    batch(root, "a.json", [{"case_id": "one", "pair_success": False,
                            "ran_at": "2026-08-28T10:00:00+00:00",
                            "safe_findings": [], "unsafe_findings": []}])
    result = probe_fixes(Args())
    assert result.state == PARTIAL
    assert "one" in result.detail

    batch(root, "b.json", [{"case_id": "one", "pair_success": True,
                            "ran_at": "2026-08-28T14:00:00+00:00",
                            "safe_findings": [], "unsafe_findings": [TARGET]}])
    assert probe_fixes(Args()).state == DONE


def test_a_case_that_was_re_run_and_broke_is_owed_one_again(root):
    """The same rule the other way: a pair that used to pass and now fails is a
    failing pair.

    Only that. Nothing here ties a limitation to the result it was written
    about, so an entry already in the file would account for the new failure
    too — and claiming otherwise in a docstring is how a guarantee nothing
    enforces gets written, which is this repository's founding defect.
    """
    from stage2 import probe_fixes

    case(root, "one")
    batch(root, "a.json", [{"case_id": "one", "pair_success": True,
                            "ran_at": "2026-08-28T10:00:00+00:00",
                            "safe_findings": [], "unsafe_findings": [TARGET]}])
    batch(root, "b.json", [{"case_id": "one", "pair_success": False,
                            "ran_at": "2026-08-28T14:00:00+00:00",
                            "safe_findings": [], "unsafe_findings": []}])
    (root / "LIMITATIONS.md").write_text("nothing\n", encoding="utf-8")

    result = probe_fixes(Args())
    assert result.state == PARTIAL
    assert "one" in result.detail


def test_two_runs_that_disagree_at_one_instant_are_still_owed_an_explanation(root):
    """Unsettled is not passing. A case nobody can say the answer for is
    exactly a case somebody has to go and look at."""
    from stage2 import probe_fixes

    case(root, "one")
    batch(root, "a.json", [{"case_id": "one", "pair_success": True,
                            "ran_at": "2026-08-28T14:00:00+00:00",
                            "safe_findings": [], "unsafe_findings": [TARGET]}])
    batch(root, "b.json", [{"case_id": "one", "pair_success": False,
                            "ran_at": "2026-08-28T14:00:00+00:00",
                            "safe_findings": [], "unsafe_findings": []}])
    (root / "LIMITATIONS.md").write_text("nothing\n", encoding="utf-8")

    assert probe_fixes(Args()).state == PARTIAL


def test_the_billing_row_reads_where_the_work_lands(root):
    """It read `journal/` and answered "no runs filed" over five paid batches,
    because that directory is written by the retired flow."""
    from stage2 import probe_spend

    case(root, "one")
    batch(root, "b.json", [{
        "case_id": "one", "pair_success": True,
        "members": {"unsafe": {"provenance": {
            "provider": "claude-cli", "auth_method": "claude.ai",
            "auth_subscription": "max"}}}}])

    result = probe_spend(Args())
    assert result.state == DONE
    assert "subscription" in result.detail


# ------------------------------------------------- the tracker against the plan


PLAN = Path(__file__).resolve().parents[1] / "STAGE-2.md"


def plan_rows() -> dict:
    """The tracking table in STAGE-2.md, by point number.

    Read from the document rather than restated here. A copy of the plan
    written into a test is a second place for the plan to be wrong, and it
    drifts in silence exactly like the tool did.
    """
    rows = {}
    for line in PLAN.read_text(encoding="utf-8").splitlines():
        if not line.startswith("| "):
            continue
        cells = [c.strip() for c in line.strip("|").split("|")]
        if len(cells) == 4 and cells[0].isdigit():
            rows[cells[0]] = cells
    return rows


def test_the_plan_still_has_a_tracking_table_to_check_against():
    """If the table is renamed or reformatted, every test below turns into a
    test of nothing. This is the one that notices."""
    rows = plan_rows()
    assert len(rows) >= 9, "found {} numbered rows in STAGE-2.md".format(len(rows))


def test_every_numbered_point_in_the_plan_has_a_check_in_the_tracker():
    """A point with no probe is a point nobody is measuring, and the tracker
    prints a table that looks complete."""
    tracked = {check.number.rstrip("ab") for check in stage2.CHECKS}
    missing = sorted(set(plan_rows()) - tracked)
    assert not missing, "points in STAGE-2.md with no probe: {}".format(missing)


def test_the_tracker_measures_the_point_the_plan_now_states():
    """Point 8 stopped being about our own code and the tracker went on
    counting journal reviews for a day, printing `0/20 reviews filed`.

    Held by the words the two would have to share. The plan's row names the
    corpus and the tracker's target names it too; if either goes back to
    counting reviews of our own changes, one of these fails.
    """
    row = plan_rows()["8"]
    check = next(c for c in stage2.CHECKS if c.number == "8")

    assert "journal" not in " ".join(row), row
    assert "review" not in check.target.lower(), check.target

    # And neither states a count. The plan said 24 and two cases were then
    # adjudicated unable to measure anything, so the target could never be
    # reached against its own number — a denominator written into a document
    # goes stale the first time a case is ruled out, and nobody notices,
    # because the document is not what computes it.
    assert not re.search(r"\d", row[3]), row[3]
    assert not re.search(r"\d", check.target), check.target
