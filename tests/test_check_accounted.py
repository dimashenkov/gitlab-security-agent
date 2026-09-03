"""The tool that enforces the stopping rule had no tests until now.

`tools/check_accounted.py` decides whether every case has a row — pass, fixed,
limitation, or invalid — and exits non-zero while anything is unaccounted. It is
the thing the project stops on, and nothing checked it.

Both tests below are about the same defect, found by asking why
`rb-mx5j-mp4f-g8jg` was reported as failing when its most recent run passed:

    cli-batch-1.json   pair_success=False   no case_digest, no ran_at
    cli-batch-2.json   pair_success=False   no case_digest, no ran_at
    cli-batch-3.json   pair_success=True    digest c7b07019e7f8bee2

The first two ran before the answer key was repaired, so they are results about
a version of the case that nobody recorded. `tools/stage2.py` has excluded such
rows for exactly that reason since a case had its weakness deleted by a bug and
then restored. `check_accounted.py` counted them, and worse, ordered them by
`ran_at` — which none of the three had, making the comparison `"" >= ""`, always
true, so the winner was whichever file the filesystem handed over last.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
import yaml

TOOLS = Path(__file__).resolve().parents[1] / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import check_accounted  # noqa: E402
from artifact import case_digest  # noqa: E402

CASE = "xx-test-0000-0000"


def build_corpus(root: Path) -> str:
    """One case with two members, and the digest a row would have to carry."""
    directory = root / "corpus-real" / CASE
    for member in ("safe", "unsafe"):
        body = directory / member / "app"
        body.mkdir(parents=True)
        (body / "handler.py").write_text("# {}\n".format(member), encoding="utf-8")
    (directory / "case.yml").write_text(yaml.safe_dump({
        "case_id": CASE,
        "language": "py",
        "family": "injection",
        "construction": "regression",
        "expected_category": ["injection"],
        "expected_file": ["app/handler.py"],
    }), encoding="utf-8")
    (root / "corpus-real" / "adjudications.yml").write_text(
        "adjudications: []\n", encoding="utf-8")
    (root / "measurements").mkdir()
    return case_digest(directory)


def write_rows(root: Path, name: str, *rows) -> None:
    (root / "measurements" / name).write_text(json.dumps(list(rows)), encoding="utf-8")


def row(*, digest, passes, ran_at=None):
    finding = {"category": "injection", "file": "app/handler.py",
               "fingerprint": "f" * 16}
    out = {
        "case_id": CASE,
        "unsafe_findings": [finding] if passes else [],
        "safe_findings": [],
        "pair_success": passes,
    }
    if digest is not None:
        out["case_digest"] = digest
    if ran_at is not None:
        out["ran_at"] = ran_at
    return out


@pytest.fixture()
def corpus(tmp_path, monkeypatch):
    digest = build_corpus(tmp_path)
    monkeypatch.setattr(check_accounted, "ROOT", tmp_path)
    return tmp_path, digest


class TestOnlyResultsAboutTodaysCase:
    def test_a_row_without_a_digest_is_not_a_verdict(self, corpus):
        """It ran, but nothing recorded which version of the case it saw.

        Counting it says "this case passes" on the strength of a result that
        might be about code the reviewer can no longer be shown.
        """
        root, _digest = corpus
        write_rows(root, "old.json", row(digest=None, passes=True))
        assert check_accounted.verdicts() == {}

    def test_a_row_from_another_version_is_not_a_verdict(self, corpus):
        root, _digest = corpus
        write_rows(root, "stale.json", row(digest="0" * 16, passes=True))
        assert check_accounted.verdicts() == {}

    def test_a_row_from_this_version_is(self, corpus):
        root, digest = corpus
        write_rows(root, "current.json", row(digest=digest, passes=True))
        assert check_accounted.verdicts() == {CASE: True}


class TestDisagreementIsNotSettledByFileOrder:
    def test_undated_rows_from_an_unrecorded_version_lose_to_the_current_one(
            self, corpus):
        """The `rb-mx5j` shape, and the reason this file exists.

        Two undated failures and one dated pass. Under the old rule every row
        was eligible and `"" >= ""` let the last file read win, so the answer
        depended on the order the filesystem returned. Here the two are not
        results about this version at all, and the case passes.
        """
        root, digest = corpus
        write_rows(root, "batch-1.json", row(digest=None, passes=False))
        write_rows(root, "batch-2.json", row(digest=None, passes=False))
        write_rows(root, "batch-3.json", row(digest=digest, passes=True))
        assert check_accounted.verdicts() == {CASE: True}

    def test_the_answer_does_not_depend_on_which_file_is_read_last(self, corpus):
        """Same rows, written under names that sort the other way.

        A test that only checked one ordering would have passed against the
        defect on a filesystem that happened to return the good file last.
        """
        root, digest = corpus
        write_rows(root, "zzz-old-1.json", row(digest=None, passes=False))
        write_rows(root, "zzz-old-2.json", row(digest=None, passes=False))
        write_rows(root, "aaa-current.json", row(digest=digest, passes=True))
        assert check_accounted.verdicts() == {CASE: True}


class TestRowsAreOrderedTheSameWayStage2OrdersThem:
    """`when >= latest[case_id][0]` over `row.get("ran_at") or ""`.

    Raw string comparison, which `stage2._instant` exists specifically to
    avoid, in the other reader of the same measurement stream. Three separate
    ways to pick the wrong row, and the two tools could report opposite things
    about one case — this one always produced a verdict, `stage2` reported the
    same input as unresolved.

    The comparison is now `artifact.instant`, one definition for both readers.
    """

    def test_a_later_run_in_another_offset_is_not_overturned_by_its_text(
            self, corpus):
        """`…T14:00:00+03:00` is 11:00 UTC — two hours *before*
        `…T12:00:00+00:00` — and the strings sort the other way round. Latent
        on today's disk, where all 78 dated rows are `+00:00`; one batch run on
        a machine with a local-time clock is all it takes."""
        root, digest = corpus
        write_rows(root, "a.json", row(digest=digest, passes=True,
                                       ran_at="2026-08-28T14:00:00+03:00"))
        write_rows(root, "b.json", row(digest=digest, passes=False,
                                       ran_at="2026-08-28T12:00:00+00:00"))

        # The `+00:00` row is the later one, and it failed.
        assert check_accounted.verdicts() == {CASE: False}

    def test_an_undated_row_does_not_answer_over_a_dated_one(self, corpus):
        """A control, said plainly: `"" >= "2026-…"` is false either way round,
        so the rule this replaced already answered here. It guards the *new*
        code — an undated row must answer only when nothing dated does, which
        is `stage2._settle`'s rule — and it does not discriminate against the
        defect."""
        root, digest = corpus
        write_rows(root, "aaa-undated.json", row(digest=digest, passes=True))
        write_rows(root, "zzz-dated.json",
                   row(digest=digest, passes=False,
                       ran_at="2026-08-28T12:00:00+00:00"))

        assert check_accounted.verdicts() == {CASE: False}

    @pytest.mark.parametrize("passing_name,failing_name",
                             [("aaa.json", "zzz.json"),
                              ("zzz.json", "aaa.json")])
    def test_two_undated_rows_that_disagree_are_not_a_pass(
            self, corpus, passing_name, failing_name):
        """Both compare `"" >= ""`, which is true, so the winner was whichever
        file the glob handed over last — an ordering nobody chose and nothing
        printed.

        Both arrangements, because `glob.glob` is not sorted and one of them
        passes against the defect on any given filesystem. Asserting one
        ordering is how a test of a non-deterministic answer proves nothing.
        """
        root, digest = corpus
        write_rows(root, passing_name, row(digest=digest, passes=True))
        write_rows(root, failing_name, row(digest=digest, passes=False))

        assert check_accounted.verdicts() == {CASE: False}
        assert CASE in check_accounted.account()["unaccounted"]

    @pytest.mark.parametrize("passing_name,failing_name",
                             [("aaa.json", "zzz.json"),
                              ("zzz.json", "aaa.json")])
    def test_two_rows_at_the_same_instant_that_disagree_are_not_a_pass(
            self, corpus, passing_name, failing_name):
        """`pair_corpus` stamps whole seconds, so a tie is reachable. `stage2`
        calls a tie unresolved and refuses to choose; this tool chose by glob
        order and announced a verdict — the two readers of one stream saying
        opposite things about one case.

        Nothing here can tell which ran second, and a case whose two runs
        disagree is what the `unaccounted` bucket is for. Both orderings, for
        the reason above.
        """
        root, digest = corpus
        when = "2026-08-28T14:00:00+00:00"
        write_rows(root, passing_name,
                   row(digest=digest, passes=True, ran_at=when))
        write_rows(root, failing_name,
                   row(digest=digest, passes=False, ran_at=when))

        assert check_accounted.verdicts() == {CASE: False}
        assert CASE in check_accounted.account()["unaccounted"]

    def test_a_ran_at_that_is_not_a_time_cannot_win_an_ordering(self, corpus):
        """As text, `"yesterday"` sorts after every ISO timestamp there will
        ever be. It is not a time, so it does not sort anywhere."""
        root, digest = corpus
        write_rows(root, "a.json", row(digest=digest, passes=False,
                                       ran_at="2026-08-28T14:00:00+00:00"))
        write_rows(root, "b.json", row(digest=digest, passes=True,
                                       ran_at="yesterday"))

        assert check_accounted.verdicts() == {CASE: False}


class TestAMemberLessCaseCannotBeCertified:
    def test_the_empty_sha_constant_is_not_a_digest(self, corpus):
        """`_files(members_only=True)` rglobs `safe/` and `unsafe/`; with
        neither present it returns `[]` and the digest was the empty-SHA
        constant `e3b0c44298fc1c14` — the same value for every such case, so
        one stored row would answer `about_this_version` for all of them.

        No case in `corpus-real/` reaches this today (82 checked, every one has
        members) and no stored row carries the constant. A guard, and the test
        says so: what it stops is a case being created without members later
        and silently inheriting somebody else's verdict.
        """
        root, _digest = corpus
        empty = root / "corpus-real" / "yy-empty-0000-0000"
        empty.mkdir()
        (empty / "case.yml").write_text("case_id: yy-empty-0000-0000\n",
                                        encoding="utf-8")

        assert case_digest(empty) != "e3b0c44298fc1c14"
        assert not check_accounted.about_this_version(
            "yy-empty-0000-0000", {"case_digest": "e3b0c44298fc1c14"})
        assert not check_accounted.about_this_version(
            "yy-empty-0000-0000", {"case_digest": case_digest(empty)})


class TestTheVerdictIsRederived:
    def test_a_stored_pass_does_not_survive_a_key_that_now_disagrees(self, corpus):
        """`pair_success` in the file is what was true under the old key.

        The row says it passed and carries no finding that matches the key, so
        re-deriving must contradict it. Reading the stored boolean is how
        `php-p2ch` was reported as a failure the day after it started passing.
        """
        root, digest = corpus
        stored = row(digest=digest, passes=True)
        stored["unsafe_findings"] = [
            {"category": "path-traversal", "file": "app/other.py"}]
        write_rows(root, "current.json", stored)
        assert check_accounted.verdicts() == {CASE: False}


class TestWhatWasBoughtVersusWhatWasDecided:
    """Two questions the tally had folded into one.

    "Do we still owe a measurement for this case" has to count every review
    that was actually paid for. "What is this case's answer" must not — an
    experiment freezes its own prompts, scorer and answer key, and
    `about_this_version` compares neither: it checks `case_digest` alone.
    """

    def experiment_row(self, root, digest, passes):
        directory = root / "measurements" / "experiment-noise" / "pass-a"
        directory.mkdir(parents=True)
        (directory / (CASE + ".json")).write_text(
            json.dumps(row(digest=digest, passes=passes,
                           ran_at="2026-09-01T11:00:00+00:00")),
            encoding="utf-8")

    def test_a_case_measured_only_by_an_experiment_is_not_bought_again(
            self, corpus):
        """It was called "not run" and would have been paid for twice.

        Two cases stood in that state on 2026-09-02, each already measured
        twice the day before, at about a dollar each.
        """
        root, digest = corpus
        self.experiment_row(root, digest, passes=True)

        buckets = check_accounted.account()
        assert CASE not in buckets["unrun"]
        assert CASE in buckets["unadopted"]

    def test_an_experiment_row_is_not_the_case_s_verdict(self, corpus):
        """The first fix folded them into `verdicts` and a limitation
        disappeared: `rb-g65v-27r3-5p6m` moved out of `LIMITATIONS.md` because
        an experiment's second pass was newer than the production row. What the
        limitation says had not been checked, and a pass produced under frozen
        prompts is not evidence that it no longer holds."""
        root, digest = corpus
        write_rows(root, "batch.json",
                   row(digest=digest, passes=False,
                       ran_at="2026-08-30T10:00:00+00:00"))
        self.experiment_row(root, digest, passes=True)

        assert check_accounted.verdicts() == {CASE: False}
        assert CASE in check_accounted.executed()

    def test_a_result_file_holding_one_row_as_an_object_is_read(self, corpus):
        """`experiment.py` writes an object per case, and the reader iterated
        `body if isinstance(body, list) else []` — so the file was opened,
        parsed, and then walked as nothing at all."""
        root, digest = corpus
        self.experiment_row(root, digest, passes=True)

        assert check_accounted.executed() == {CASE}

    def test_a_measured_but_unadopted_case_is_not_exit_zero(self, corpus,
                                                            capsys):
        """The most reachable harm in the first version of this bucket.

        The exit code asked only about `unaccounted` and `unrun`, so once the
        unmeasured cases are bought the tool would announce that everything is
        accounted for while two cases still have no verdict — the tally saying
        "done" over work nobody decided.
        """
        root, digest = corpus
        self.experiment_row(root, digest, passes=True)

        monkeypatch = pytest.MonkeyPatch()
        monkeypatch.setattr(sys, "argv", ["check_accounted.py"])
        try:
            assert check_accounted.main() == 1
        finally:
            monkeypatch.undo()
        assert "not the record" in capsys.readouterr().out

    def test_one_rule_decides_what_counts_as_a_measurement(self, corpus):
        """`executed` demanded a boolean `pair_success` and `verdicts` asked
        only that the row was not `incomplete`. A finished-looking row carrying
        `null` there became a canonical verdict in one and was invisible to the
        other — and the verdict was the false one, because `passed()` reads a
        row with no findings as a failure."""
        root, digest = corpus
        half = row(digest=digest, passes=True)
        half["pair_success"] = None
        write_rows(root, "batch.json", half)

        assert check_accounted.verdicts() == {}
        assert check_accounted.executed() == set()


class TestAFailureThatStaysInTheSet:
    """The fifth outcome, and why four were not enough.

    D-008 folded two independent questions into one: does this case have an
    explained outcome, and should it be measured again. For a case the agent
    genuinely failed — a false finding that survived the verifier and blocked a
    correct fix — the answers are yes and yes, and neither existing bucket can
    say that. `invalid` claims the case measures nothing; `limitation` removes
    it from measurement for good.
    """

    def rule(self, root, **keys):
        # A ruling that drops a case has to say why — `malformed_cases` and
        # `rulings` both require it, since a row that removes a measurement
        # without a reason is a deletion rather than a ruling. Supplied here so
        # the fixture is a ruling the tool would actually accept.
        if keys.get("case_is_malformed") and "why_malformed" not in keys:
            keys["why_malformed"] = "the safe member carries the weakness"
        body = {"adjudications": [dict({"case_id": CASE, "member": "safe"},
                                       **keys)]}
        (root / "corpus-real" / "adjudications.yml").write_text(
            yaml.safe_dump(body), encoding="utf-8")

    def test_a_known_failure_is_accounted_for_without_being_removed(
            self, corpus, capsys):
        root, digest = corpus
        write_rows(root, "r.json", row(digest=digest, passes=False))
        self.rule(root, known_failure=True)

        buckets = check_accounted.account()
        assert buckets["known_failure"] == [CASE]
        assert CASE not in buckets["limitation"]
        assert CASE not in buckets["invalid"]
        assert not buckets["unaccounted"]

    def test_it_wins_over_a_line_in_limitations(self, corpus):
        """Such a case is named in `LIMITATIONS.md` too — that line says what
        the failure is. Read the other way round it would be filed as removed,
        which is the one thing the ruling exists to prevent."""
        root, digest = corpus
        write_rows(root, "r.json", row(digest=digest, passes=False))
        self.rule(root, known_failure=True)
        (root / "LIMITATIONS.md").write_text(
            "The reviewer is wrong about {}.\n".format(CASE), encoding="utf-8")

        buckets = check_accounted.account()
        assert buckets["known_failure"] == [CASE]
        assert buckets["limitation"] == []

    def test_it_is_not_confused_with_a_case_that_measures_nothing(self, corpus):
        """`invalid` says the case cannot measure anything. A known failure
        measures something precise — whether a semantically wrong finding can
        survive the verifier and gate a merge."""
        root, digest = corpus
        write_rows(root, "r.json", row(digest=digest, passes=False))
        self.rule(root, case_is_malformed=True)

        buckets = check_accounted.account()
        assert buckets["invalid"] == [CASE]
        assert buckets["known_failure"] == []

