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

