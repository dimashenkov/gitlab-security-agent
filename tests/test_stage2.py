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
from stage2 import DONE, PARTIAL, TODO, probe_use


class Args:
    tests = False
    full = False


def case(root: Path, case_id: str, construction: str = "regression") -> None:
    directory = root / "corpus-real" / case_id
    directory.mkdir(parents=True)
    (directory / "case.yml").write_text(
        "case_id: {}\nconstruction: {}\n".format(case_id, construction),
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


def test_a_case_edited_after_its_run_stops_counting(root):
    """The digest is over the case's own files, so editing one case must not
    invalidate the results of the others."""
    case(root, "one")
    case(root, "two")
    batch(root, "b.json", [{"case_id": "one", "pair_success": True},
                           {"case_id": "two", "pair_success": True}])
    assert probe_use(Args()).state == DONE

    (root / "corpus-real" / "one" / "case.yml").write_text(
        "case_id: one\nconstruction: regression\n# edited\n", encoding="utf-8")

    result = probe_use(Args())
    assert result.state == PARTIAL
    assert "1/2 run" in result.detail


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
    """One filed review, with the provenance an artifact actually carries."""
    directory = root / "journal" / name
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "findings.json").write_text(
        json.dumps({"provenance": provenance}), encoding="utf-8")


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


def test_an_api_run_is_not_a_local_run(root):
    """The probe is about the local runner. An artifact from the paid path is
    not evidence either way, and reading one would be reading the wrong
    question — which the version before this did to every artifact, by looking
    for a container no artifact has ever had."""
    from stage2 import probe_spend

    review(root, "from-ci", provider="anthropic-api")
    assert probe_spend(Args()).state == TODO


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
