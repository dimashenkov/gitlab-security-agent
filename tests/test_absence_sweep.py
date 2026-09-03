"""A sweep for one defect class: a missing answer read as a reassuring one.

Every test here asserts the behaviour the code *should* have and is marked
`xfail(strict=True)`, so each one is a live proof that the defect is still
present — and turns red the moment somebody fixes it, which is what stops the
marker being left behind after the fix.

Nothing in this file spends money: no `claude`, no corpus runner, no API.
"""

from __future__ import annotations

import argparse
import io
import json
import re
import subprocess
import sys
from contextlib import redirect_stdout
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

from security_agent import workspace as workspace_module  # noqa: E402
from security_agent.workspace import Workspace  # noqa: E402


# ---------------------------------------------------------------------------
# 1. Workspace.search — a search cut off by the deadline reports "no matches"
# ---------------------------------------------------------------------------

@pytest.mark.xfail(strict=True, reason=(
    "workspace.py:847 — `if total == 0: return 'no matches for {pattern}'` is "
    "reached with `truncated=True` when `_grep_stream` hits its deadline "
    "before keeping a single line. The reviewer asked whether a pattern "
    "occurs anywhere and is told it does not, over a search that was stopped."))
def test_search_stopped_at_the_deadline_does_not_report_no_matches(
    git_repo: Path, monkeypatch
) -> None:
    ws = Workspace(root=git_repo)

    # The search really does match; nothing about the repository is unusual.
    body, count = ws.search("SELECT")
    assert count == 1 and "no matches" not in body

    # Now the same search under a blown deadline — what a `git grep` over a
    # large repository produces when it runs past GIT_TIMEOUT_SECONDS. The
    # first line read trips the deadline check, so nothing is kept.
    monkeypatch.setattr(workspace_module, "GIT_TIMEOUT_SECONDS", -1)
    body, count = ws.search("SELECT")

    assert "no matches" not in body, (
        "a search that was stopped before it read anything must not be "
        "rendered as a search that found nothing: {!r}".format(body))


# ---------------------------------------------------------------------------
# 2. tools/corpus_adversary.py — an empty corpus passes the leakage gate
# ---------------------------------------------------------------------------

@pytest.mark.xfail(strict=True, reason=(
    "corpus_adversary.py:236-241 — `worst()` returns ('' , 0.0, {}) when no "
    "rule fired, and main() prints 'the cues that could reach the reviewer "
    "are absent' and returns 0. Point it at a directory holding no case.yml "
    "and the leakage gate passes over zero cases."))
def test_corpus_adversary_refuses_a_corpus_with_no_cases(
    tmp_path: Path, monkeypatch
) -> None:
    import corpus_adversary

    empty = tmp_path / "corpus"
    empty.mkdir()

    monkeypatch.setattr(sys, "argv", ["corpus_adversary.py", str(empty)])
    out = io.StringIO()
    with redirect_stdout(out):
        code = corpus_adversary.main()

    assert "0 case(s) examined" in out.getvalue()
    assert code != 0, (
        "a leakage check over zero cases has not shown the corpus is clean; "
        "it has shown nothing, and must not exit 0")


# ---------------------------------------------------------------------------
# 3. tools/journal.py — a verdict nobody can read vanishes from the tally
# ---------------------------------------------------------------------------

def _write_entry(root: Path, ref: str, findings: list) -> None:
    directory = root / ref
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "verdict.yml").write_text(
        yaml.safe_dump({"ref": ref, "complete": True, "findings": findings},
                       sort_keys=False),
        encoding="utf-8")


def _table_total(output: str) -> int:
    """The verdict table's counts, summed."""
    import journal

    total = 0
    for name in journal.VERDICTS:
        found = re.search(r"^{}\s+(\d+)\s*$".format(re.escape(name)),
                          output, re.MULTILINE)
        assert found is not None, "no table row for {!r}".format(name)
        total += int(found.group(1))
    return total


@pytest.mark.xfail(strict=True, reason=(
    "journal.py:169 — `f.get('verdict', 'unadjudicated')` only defaults when "
    "the KEY is absent. A hand-edited `verdict:` with nothing after it is "
    "YAML null, and `verdict: nto_real` is a typo; both land in the Counter "
    "under a name outside VERDICTS, are excluded from `judged`, and are not "
    "reported by the `unadjudicated` notice either. The finding leaves the "
    "report entirely and the percentage is computed as if it never existed."))
def test_journal_report_accounts_for_an_unreadable_verdict(tmp_path: Path) -> None:
    import journal

    root = tmp_path / "journal"
    _write_entry(root, "abc1234", [
        {"fingerprint": "f1", "verdict": "not_real", "minutes": 1},
        {"fingerprint": "f2", "verdict": None, "minutes": 0},      # `verdict:`
        {"fingerprint": "f3", "verdict": "nto_real", "minutes": 0},  # a typo
    ])

    out = io.StringIO()
    with redirect_stdout(out):
        journal.report(root)
    text = out.getvalue()

    assert "3 finding(s)" in text
    assert _table_total(text) == 3, (
        "two findings carry a verdict nobody can read and neither the table "
        "nor the notices say so — they are silently dropped from both the "
        "numerator and the denominator:\n" + text)


# ---------------------------------------------------------------------------
# 4. tools/journal.py — an entry filed under a nested ref is invisible
# ---------------------------------------------------------------------------

@pytest.mark.xfail(strict=True, reason=(
    "journal.py:66 — `root.glob('*/verdict.yml')` is one level deep, while "
    "`entry_dir` (line 60) is `root / ref` and `add` creates it with "
    "`parents=True`. File a review with `--ref feature/login` and it is "
    "written, reported as filed, and then never seen by `report` again."))
def test_journal_report_sees_an_entry_filed_under_a_nested_ref(
    tmp_path: Path
) -> None:
    import journal

    artifact = tmp_path / "findings.json"
    artifact.write_text(json.dumps({
        "complete": True,
        "verdict": {"exit_code": 0, "blocking_fingerprints": []},
        "revision": {"base_sha": "a" * 40, "head_sha": "b" * 40},
        "findings": [],
    }), encoding="utf-8")

    root = tmp_path / "journal"
    root.mkdir()
    out = io.StringIO()
    with redirect_stdout(out):
        assert journal.add(artifact, "feature/login", root) == 0
    assert (root / "feature" / "login" / "verdict.yml").is_file()

    out = io.StringIO()
    with redirect_stdout(out):
        code = journal.report(root)
    text = out.getvalue()

    assert code == 0 and "1 review(s) filed" in text, (
        "the entry was filed and acknowledged, and the report cannot see "
        "it:\n" + text)


# ---------------------------------------------------------------------------
# 5. tools/measure_variance.py — every run failed, and it exits 0
# ---------------------------------------------------------------------------

def _variance_argv() -> list:
    return ["measure_variance.py", "--repo", "/nonexistent", "-n", "3"]


@pytest.mark.xfail(strict=True, reason=(
    "measure_variance.py:238 — `main` returns 0 unconditionally, and "
    "`summarise` (line 98-100) returns after printing 'every run failed; "
    "nothing to compare'. A wrapper reading the exit code cannot tell 'the "
    "suite is stable' from 'nothing was measured'."))
def test_measure_variance_does_not_exit_zero_when_every_run_failed(
    monkeypatch
) -> None:
    import measure_variance

    def failed(args: argparse.Namespace, index: int) -> dict:
        return {"ok": False, "index": index, "seconds": 0.1,
                "exit_code": 2, "error": ["boom"]}

    monkeypatch.setattr(measure_variance, "run_once", failed)
    monkeypatch.setattr(sys, "argv", _variance_argv())

    out = io.StringIO()
    with redirect_stdout(out):
        code = measure_variance.main()

    assert "every run failed" in out.getvalue()
    assert code != 0, "no measurement was taken; exit 0 says one was"


@pytest.mark.xfail(strict=True, reason=(
    "measure_variance.py:97 and 170 — `good` drops every run that produced no "
    "report, and the stability claim is then made over what is left. Four "
    "crashes and one survivor print 'stable across 1 runs at this sample "
    "size', which is agreement manufactured by absence."))
def test_measure_variance_does_not_call_one_surviving_run_stable(
    monkeypatch
) -> None:
    import measure_variance

    payload = {
        "usage": {},
        "coverage": {"turns": 4},
        "counts": {"reported": 0},
        "verdict": {"blocking_fingerprints": []},
        "findings": [],
        "refuted": [],
    }

    def mostly_failed(args: argparse.Namespace, index: int) -> dict:
        if index == 1:
            return {"ok": True, "index": index, "seconds": 1.0, "retries": 0,
                    "exit_code": 0, "payload": payload}
        return {"ok": False, "index": index, "seconds": 0.1,
                "exit_code": 2, "error": ["boom"]}

    monkeypatch.setattr(measure_variance, "run_once", mostly_failed)
    monkeypatch.setattr(sys, "argv",
                        ["measure_variance.py", "--repo", "/x", "-n", "5"])

    out = io.StringIO()
    with redirect_stdout(out):
        measure_variance.main()
    text = out.getvalue()

    assert "1 of 5 runs produced a report" in text
    assert "stable" not in text, (
        "one run cannot disagree with itself; four missing runs are not "
        "four agreements:\n" + text)


# ---------------------------------------------------------------------------
# 6. tools/verifier_replay.py — a crashed run leaves the panel looking steady
# ---------------------------------------------------------------------------

@pytest.mark.xfail(strict=True, reason=(
    "verifier_replay.py:144 and 191 — `good` excludes every errored run and "
    "the instability check at line 169 then compares the survivors only, so "
    "two clean runs where one crashed exit 0. The protocol in the module "
    "docstring ('two clean runs before any payload') is satisfied by a "
    "single run plus a crash."))
def test_verifier_replay_is_not_green_when_a_run_produced_no_verdict() -> None:
    verifier_replay = pytest.importorskip("verifier_replay")

    rows = [
        {"run": 0, "payload": "none", "verdict": "confirmed",
         "confidence": "high", "votes": [{"verdict": "confirmed",
                                          "control_search": ""}],
         "cost": 0.5},
        {"run": 1, "error": "APIConnectionError: boom"},
    ]

    out = io.StringIO()
    with redirect_stdout(out):
        code = verifier_replay.report(rows)

    assert code != 0, (
        "one of the two baseline runs never produced a verdict; the panel "
        "has not been shown to agree with itself:\n" + out.getvalue())
