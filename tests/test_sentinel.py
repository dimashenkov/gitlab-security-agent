"""The suite is chosen by a rule, and these tests are about the rule holding.

A sample chosen by the person whose work it will judge is not a control. So the
selection is code, it is deterministic, and the properties that make it a
control — no hand-picking, both constructions never mixed, a pass and a fail per
language — are asserted here rather than described in a comment.

The one property that cannot be asserted is blindness: step three uses outcomes
already seen. That is a deliberate choice and it is stated in the tool's own
docstring, because a limitation written down is one a reader can weigh and a
limitation implied is one they cannot.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from sentinel import (
    read_cases,
    recorded_outcomes,
    refusals,
    render,
    select,
)


def case(root: Path, case_id: str, language: str,
         construction: str = "regression") -> None:
    directory = root / case_id
    directory.mkdir(parents=True)
    (directory / "case.yml").write_text(
        "case_id: {}\nlanguage: {}\nfamily: injection\n"
        "construction: {}\nexpected_category: injection\n".format(
            case_id, language, construction),
        encoding="utf-8")


def measured(root: Path, rows: list, name: str = "batch-1.json") -> None:
    root.mkdir(parents=True, exist_ok=True)
    (root / name).write_text(json.dumps(rows), encoding="utf-8")


def row(case_id: str, passed) -> dict:
    return {"case_id": case_id, "pair_success": passed}


@pytest.fixture
def world(tmp_path):
    corpus, measurements = tmp_path / "corpus-real", tmp_path / "measurements"
    corpus.mkdir()
    return corpus, measurements


class TestTheRuleSelects:
    def test_a_pass_and_a_fail_from_each_language(self, world):
        """One of each, because a suite of only passing cases cannot show a
        decline and a suite of only failing ones cannot either — a failure that
        stays a failure is the same bit twice."""
        corpus, measurements = world
        case(corpus, "go-a", "go")
        case(corpus, "go-b", "go")
        measured(measurements, [row("go-a", True), row("go-b", False)])

        suite = select(corpus, measurements)

        assert suite["cases"] == ["go-a", "go-b"]

    def test_one_language_with_only_passes_contributes_one(self, world):
        corpus, measurements = world
        case(corpus, "rs-a", "rust")
        case(corpus, "rs-b", "rust")
        measured(measurements, [row("rs-a", True), row("rs-b", True)])

        assert select(corpus, measurements)["cases"] == ["rs-a"]

    def test_the_choice_within_an_arm_is_lexicographic(self, world):
        """A tie broken by preference is a tie broken by whoever is looking."""
        corpus, measurements = world
        for name in ("py-z", "py-a", "py-m"):
            case(corpus, name, "python")
        measured(measurements,
                 [row(n, True) for n in ("py-z", "py-a", "py-m")])

        assert select(corpus, measurements)["cases"] == ["py-a"]

    def test_it_is_deterministic(self, world):
        corpus, measurements = world
        for name in ("go-a", "go-b", "ts-a"):
            case(corpus, name, name.split("-")[0])
        measured(measurements, [row("go-a", True), row("go-b", False),
                                row("ts-a", True)])

        assert select(corpus, measurements) == select(corpus, measurements)


class TestWhatTheRuleRefuses:
    def test_a_snapshot_case_is_never_selected(self, world):
        """The two constructions measure different things and the project's own
        harvester says never to score them together. A suite holding both makes
        its single number a blend of two questions."""
        corpus, measurements = world
        case(corpus, "go-snap", "go", construction="snapshot")
        measured(measurements, [row("go-snap", True)])

        assert select(corpus, measurements)["cases"] == []

    def test_a_case_with_no_recorded_outcome_is_not_eligible(self, world):
        corpus, measurements = world
        case(corpus, "go-a", "go")
        measured(measurements, [])

        assert select(corpus, measurements)["cases"] == []

    def test_a_run_that_did_not_conclude_is_not_an_outcome(self, world):
        """`pair_success: null` is a review that did not finish, and reading it
        as a failure is the confusion that already cost this project a withdrawn
        result."""
        corpus, measurements = world
        case(corpus, "go-a", "go")
        measured(measurements, [row("go-a", None)])

        assert recorded_outcomes(measurements) == {}
        assert select(corpus, measurements)["cases"] == []

    def test_two_different_verdicts_make_a_case_unstable(self, world):
        """There is no "latest". The first version took the last verdict in file
        name order, and the names do not sort chronologically —
        `cli-batch-10-go-snap.json` sorts before `cli-batch-2.json`, and the
        oldest file in the corpus sorts last. So a case with two verdicts is not
        resolved by choosing one; the movement is the fact."""
        corpus, measurements = world
        case(corpus, "go-a", "go")
        measured(measurements, [row("go-a", False)], name="batch-1.json")
        measured(measurements, [row("go-a", True)], name="batch-2.json")

        assert recorded_outcomes(measurements)["go-a"] == "unstable"

    def test_file_order_cannot_change_the_answer(self, world):
        """The property the ordering assumption quietly removed. Same verdicts,
        names that sort the other way round, same result."""
        corpus, measurements = world
        case(corpus, "go-a", "go")
        measured(measurements, [row("go-a", True)], name="cli-batch-10.json")
        measured(measurements, [row("go-a", True)], name="cli-batch-2.json")

        assert recorded_outcomes(measurements)["go-a"] == "pass"

    def test_every_unstable_case_is_taken_not_the_first(self, world):
        """A case that moves on its own is what a noise floor is made of, and
        there are few enough that taking them all costs little."""
        corpus, measurements = world
        for name in ("go-a", "go-b"):
            case(corpus, name, "go")
        case(corpus, "go-c", "go")
        measured(measurements, [row("go-a", True), row("go-b", True),
                                row("go-c", False)], name="b1.json")
        measured(measurements, [row("go-a", False), row("go-b", False)],
                 name="b2.json")

        suite = select(corpus, measurements)

        assert suite["cases"] == ["go-a", "go-b", "go-c"]
        assert suite["outcomes"]["go-a"] == "unstable"
        assert suite["outcomes"]["go-b"] == "unstable"


class TestEveryPlaceAPaidRunWrites:
    """The suite was drawn from two of the four directories results land in.

    A run costs money once and is readable for ever after, so a reader that
    cannot see one of the places they land does not report less — it reports
    something false. Both of these were true against the real corpus: two cases
    the stability experiment had seen flip were recorded as settled failures,
    and the arm of the suite that exists to hold cases which move on their own
    was missing two of its five.
    """

    def test_an_experiment_pass_is_read(self, world):
        """`measurements/experiment-*/pass-*/` — 27 files, invisible.

        `go-m6jg-wr9m-cg2f` was True in pass A and False in pass B and the tool
        called it `fail`; `rb-g65v-27r3-5p6m` was False then True and it called
        that `fail` too.
        """
        corpus, measurements = world
        case(corpus, "go-a", "go")
        measured(measurements, [row("go-a", False)], name="batch-1.json")
        pass_a = measurements / "experiment-noise-floor" / "pass-a"
        pass_a.mkdir(parents=True)
        (pass_a / "go-a.json").write_text(
            json.dumps(row("go-a", True)), encoding="utf-8")

        assert recorded_outcomes(measurements)["go-a"] == "unstable"

    def test_an_experiment_file_is_an_object_not_a_list(self, world):
        """The shape, stated on its own. `experiment.py` writes one row per
        file as a bare object; a reader that iterates only lists opens the
        file, parses it, and then iterates it as nothing."""
        corpus, measurements = world
        case(corpus, "go-a", "go")
        directory = measurements / "experiment-x" / "pass-b"
        directory.mkdir(parents=True)
        (directory / "go-a.json").write_text(
            json.dumps(row("go-a", True)), encoding="utf-8")

        assert recorded_outcomes(measurements) == {"go-a": "pass"}

    def test_a_round_directory_is_read(self, world):
        """`--round N` writes `measurements/round-N/<case>.json`."""
        corpus, measurements = world
        case(corpus, "go-a", "go")
        directory = measurements / "round-2"
        directory.mkdir(parents=True)
        (directory / "go-a.json").write_text(
            json.dumps([row("go-a", True)]), encoding="utf-8")

        assert recorded_outcomes(measurements) == {"go-a": "pass"}

    def test_a_results_container_is_read(self, world):
        """`{"results": [...]}` is a shape `stage2` and `run_queue` both
        accept, so a reader here that did not would be the same defect a third
        time."""
        corpus, measurements = world
        case(corpus, "go-a", "go")
        measured(measurements, [row("go-a", True)])
        (measurements / "batch-2.json").write_text(
            json.dumps({"results": [row("go-a", False)]}), encoding="utf-8")

        assert recorded_outcomes(measurements)["go-a"] == "unstable"


class TestAVerdictIsReadNotCoerced:
    def test_the_string_false_is_not_a_pass(self, world):
        """`bool("false")` is true. A typo in one field could turn a recorded
        failure into a pass in the suite whose whole job is to notice a change
        in that direction, and nothing would have printed."""
        corpus, measurements = world
        case(corpus, "go-a", "go")
        measured(measurements, [{"case_id": "go-a", "pair_success": "false"}])

        assert recorded_outcomes(measurements) == {}

    def test_a_number_is_not_a_verdict(self, world):
        corpus, measurements = world
        case(corpus, "go-a", "go")
        measured(measurements, [{"case_id": "go-a", "pair_success": 1}])

        assert recorded_outcomes(measurements) == {}

    def test_an_incomplete_row_contributes_nothing(self, world):
        """A run that did not conclude is not a result. Left in, it makes a
        case that later passes look like a case that moves on its own — the
        noise floor measured on runs that were cut off."""
        corpus, measurements = world
        case(corpus, "go-a", "go")
        measured(measurements, [row("go-a", True)], name="batch-1.json")
        measured(measurements,
                 [{"case_id": "go-a", "pair_success": False, "incomplete": True}],
                 name="batch-2.json")

        assert recorded_outcomes(measurements)["go-a"] == "pass"


class TestTheManifest:
    def test_the_written_list_round_trips(self, world, tmp_path):
        corpus, measurements = world
        case(corpus, "go-a", "go")
        case(corpus, "go-b", "go")
        measured(measurements, [row("go-a", True), row("go-b", False)])
        suite = select(corpus, measurements)

        path = tmp_path / "sentinel.yml"
        path.write_text(render(suite), encoding="utf-8")

        assert read_cases(path) == suite["cases"]

    def test_the_manifest_records_what_it_chose_from(self, world):
        """The pool size and the per-language counts, so a later reader can see
        that nine languages over thirteen cases leaves cells with one
        observation — the suite is a tripwire, not a sample."""
        corpus, measurements = world
        case(corpus, "go-a", "go")
        case(corpus, "go-b", "go")
        measured(measurements, [row("go-a", True), row("go-b", False)])

        text = render(select(corpus, measurements))

        assert "pool: 2" in text
        assert "count: 2" in text
        assert "eligible: 1 pass, 1 fail, 0 unstable" in text


class TestASuiteThatCannotDoItsJobIsRefused:
    """A language with one arm still contributes — a passing case can decline.
    A *suite* with one arm cannot: with nothing failing nothing can be seen to
    recover, with nothing passing nothing can be seen to decline. The rule can
    produce either, correctly, from one more batch of measurements — which is
    how it would go unnoticed."""

    def test_a_suite_of_only_passes_is_refused(self, world):
        corpus, measurements = world
        for name, language in (("go-a", "go"), ("py-a", "python")):
            case(corpus, name, language)
        measured(measurements, [row("go-a", True), row("py-a", True)])

        problems = refusals(select(corpus, measurements))

        assert problems and "cannot be told from no change" in problems[0]

    def test_a_suite_of_only_failures_is_refused(self, world):
        corpus, measurements = world
        for name, language in (("go-a", "go"), ("py-a", "python")):
            case(corpus, name, language)
        measured(measurements, [row("go-a", False), row("py-a", False)])

        problems = refusals(select(corpus, measurements))

        assert problems and "nothing here can be seen to decline" in problems[0]

    def test_one_of_each_is_accepted(self, world):
        corpus, measurements = world
        for name, language in (("go-a", "go"), ("py-a", "python")):
            case(corpus, name, language)
        measured(measurements, [row("go-a", True), row("py-a", False)])

        assert refusals(select(corpus, measurements)) == []

    def test_an_unstable_case_counts_as_something_that_can_recover(self, world):
        """It is not passing, so a decline is visible; it is not simply failing
        either, and pretending otherwise would drop the one arm that measures
        movement."""
        corpus, measurements = world
        case(corpus, "go-a", "go")
        case(corpus, "py-a", "python")
        measured(measurements, [row("go-a", True), row("py-a", True)], name="b1.json")
        measured(measurements, [row("py-a", False)], name="b2.json")

        assert refusals(select(corpus, measurements)) == []


class TestTheRealSuite:
    """Against the repository's own corpus, not a fixture."""

    def test_every_case_in_the_manifest_is_still_eligible(self):
        """What the suite must keep being, rather than what the rule would pick
        today.

        Asserting equality with a fresh selection was the obvious test and the
        wrong one: the rule reads `measurements/`, so the first paid run after
        this would turn the suite red — a failing test at exactly the moment a
        result needs reading. Worse, the fix a red suite invites is
        `--write`, and a suite that follows the newest measurements is not a
        baseline at all.

        So this asserts the properties that make the manifest a control: every
        case exists, is a regression construction, and is not malformed. Whether
        the rule would choose differently today is a question for
        `tools/sentinel.py --check` and for a person.
        """
        root = Path(__file__).resolve().parents[1]
        manifest = root / "suites" / "sentinel.yml"
        assert manifest.is_file(), "the sentinel manifest is missing"

        from sentinel import malformed_cases, manifests

        corpus = root / "corpus-real"
        known, excluded = manifests(corpus), set(malformed_cases(corpus))
        outcomes = recorded_outcomes(root / "measurements")
        for case_id in read_cases(manifest):
            assert case_id in known, "{} is in the suite and not on disk".format(case_id)
            assert known[case_id].get("construction") == "regression", case_id
            assert case_id not in excluded, case_id
            # The fourth condition, and the one the first version of this test
            # left out while calling itself an eligibility check: a case whose
            # measurement was removed or invalidated is no longer eligible, and
            # the test stayed green.
            assert case_id in outcomes, "{} has no recorded outcome".format(case_id)

    def test_the_suite_is_not_one_language(self):
        """Stratification is the reason it is a suite rather than a case."""
        root = Path(__file__).resolve().parents[1]
        from sentinel import manifests

        known = manifests(root / "corpus-real")
        languages = {known[c].get("language")
                     for c in read_cases(root / "suites" / "sentinel.yml")}

        assert len(languages) >= 5

    def test_the_known_unstable_case_is_in_it(self):
        """`rb-mx5j-mp4f-g8jg` is the one case observed flipping with nothing
        changed — False, False, then True across three runs. A noise floor
        measured without it would be measured on the cases that never move."""
        root = Path(__file__).resolve().parents[1]

        assert "rb-mx5j-mp4f-g8jg" in read_cases(root / "suites" / "sentinel.yml")
        assert recorded_outcomes(root / "measurements")["rb-mx5j-mp4f-g8jg"] == "unstable"

    def test_the_two_cases_the_experiment_saw_flip_are_unstable(self):
        """Against the repository's own measurements, and the reason the glob
        was widened.

        Both are in `measurements/experiment-noise-floor-2/`, one verdict in
        pass A and the opposite in pass B, with nothing changed between. While
        those files were unread each was recorded as a settled `fail` — a case
        known to move, filed under an arm that says it does not.
        """
        root = Path(__file__).resolve().parents[1]
        outcomes = recorded_outcomes(root / "measurements")

        assert outcomes["go-m6jg-wr9m-cg2f"] == "unstable"
        assert outcomes["rb-g65v-27r3-5p6m"] == "unstable"
