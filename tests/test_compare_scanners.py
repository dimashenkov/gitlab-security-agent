"""The comparison harness, and the one direction it must never fail in.

Every number this file guards is a number about somebody else's tool, published
next to ours. A scanner that crashed, timed out, or skipped half its rules still
writes JSON for the part it managed, and reading that JSON without reading the
exit code turns "could not check" into "checked, found nothing" — a miss
credited to the other tool that it never had the chance to make. The bias runs
one way, toward this repository, which is the way a comparison is not allowed to
be wrong.

No scanner is executed here. `subprocess.run` is replaced with the shapes the
real ones produce: semgrep exiting non-zero with results on stdout, and codeql
leaving a SARIF behind after an analyze that failed.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import compare_scanners

SEMGREP_JSON = json.dumps({
    "results": [],
    "errors": [{"type": "Timeout", "path": "app/views.py"}],
    "paths": {"scanned": []},
})


def fake_run(returncode, stdout="", stderr=""):
    return lambda *args, **kwargs: SimpleNamespace(
        returncode=returncode, stdout=stdout, stderr=stderr)


class TestSemgrepExitCode:
    def test_only_a_completed_scan_gets_a_verdict(self, monkeypatch, tmp_path):
        """The whole defect, next to the case it must not break.

        Semgrep exits non-zero on rule or target failures and still prints the
        findings it did produce. Deciding on "was stdout non-empty" scored a run
        that skipped files as a completed run that found nothing in them. Both
        halves are asserted here so the fix cannot be "reject everything".
        """
        monkeypatch.setattr(compare_scanners.subprocess, "run",
                            fake_run(2, SEMGREP_JSON, "Timeout scanning app/views.py"))
        incomplete = compare_scanners.run_semgrep(tmp_path, ["app/views.py"])

        payload = json.dumps({"results": [
            {"path": "/work/unsafe/app/views.py", "check_id": "python.sqli"}]})
        monkeypatch.setattr(compare_scanners.subprocess, "run", fake_run(0, payload, ""))
        completed = compare_scanners.run_semgrep(tmp_path, ["app/views.py"])

        assert incomplete["ok"] is False
        assert "hit" not in incomplete, "an incomplete scan was given a verdict"
        assert completed["ok"] is True
        assert completed["hit"] is True
        assert completed["rules"] == ["python.sqli"]

    def test_the_error_names_the_exit_code(self, monkeypatch, tmp_path):
        # "could not check" is only useful if the reader can tell what stopped.
        monkeypatch.setattr(compare_scanners.subprocess, "run",
                            fake_run(7, SEMGREP_JSON, "all rules failed to parse"))

        out = compare_scanners.run_semgrep(tmp_path, ["app/views.py"])

        assert out["ok"] is False
        assert "7" in out["error"]


class TestCodeqlExitCode:
    """`database create` was checked; `database analyze` was not."""

    @pytest.fixture
    def repo(self, tmp_path):
        (tmp_path / "repo").mkdir()
        return tmp_path / "repo"

    def _codeql(self, monkeypatch, sarif, create=0, analyze=0):
        def run(cmd, *args, **kwargs):
            if "analyze" in cmd:
                # A real failed analyze can still have written the file — a
                # partial SARIF, or one from the query pack that did load.
                sarif.write_text(json.dumps({"runs": [{"results": []}]}))
                return SimpleNamespace(returncode=analyze, stdout="",
                                       stderr="A fatal error occurred: query pack")
            return SimpleNamespace(returncode=create, stdout="", stderr="")

        monkeypatch.setattr(compare_scanners.subprocess, "run", run)

    def test_the_sarif_is_only_read_when_analyze_succeeded(self, monkeypatch, repo):
        sarif = repo.parent / "results.sarif"

        self._codeql(monkeypatch, sarif, analyze=32)
        failed = compare_scanners.run_codeql(repo, ["app/views.py"], "python")

        self._codeql(monkeypatch, sarif, analyze=0)
        succeeded = compare_scanners.run_codeql(repo, ["app/views.py"], "python")

        assert failed["ok"] is False
        assert "hit" not in failed, \
            "queries that never ran were read as queries that found nothing"
        assert succeeded["ok"] is True
        assert succeeded["hit"] is False
        assert succeeded["total"] == 0


class TestTheHarnessNeverScoresAnIncompleteScan:
    """The chain, not the link: subprocess through `run_case` into `report`.

    `run_semgrep` returning the wrong shape is only a bug because of what
    happens downstream — the pair gets a row, the row gets a column, and the
    column says MISS or pass about a scan that did not finish.
    """

    @pytest.fixture
    def case(self, monkeypatch, tmp_path):
        def build_repo(case_dir, member, work):
            work.mkdir(parents=True, exist_ok=True)
            return work, "base", "head"

        monkeypatch.setattr(compare_scanners, "build_repo", build_repo)
        monkeypatch.setattr(compare_scanners, "target_paths",
                            lambda case: ["app/views.py"])
        return {"case_id": "cve-2024-0001", "language": "python",
                "family": "injection", "_dir": tmp_path}

    def test_an_incomplete_scan_produces_no_pair_verdict(self, monkeypatch, case):
        monkeypatch.setattr(compare_scanners.subprocess, "run",
                            fake_run(2, SEMGREP_JSON, "Timeout scanning app/views.py"))

        row = compare_scanners.run_case(case, "semgrep")

        assert "pair_success" not in row
        assert "unsafe_recall" not in row
        assert "error" in row

    def test_the_report_says_it_could_not_check_rather_than_printing_a_result(
            self, monkeypatch, case, capsys):
        monkeypatch.setattr(compare_scanners.subprocess, "run",
                            fake_run(2, SEMGREP_JSON, "Timeout scanning app/views.py"))

        row = compare_scanners.run_case(case, "semgrep")
        compare_scanners.report([row], "semgrep")
        printed = capsys.readouterr().out

        assert "errored" in printed
        assert "nothing scorable" in printed
        assert "MISS" not in printed
        assert "pairs discriminated" not in printed
