"""A sweep for one defect class: a missing answer read as a reassuring one.

Every test here asserts the behaviour the code should have.

Seven of them were written first as `xfail(strict=True)` over a defect that was
live at the time, so each turned red the moment its defect went — that is what
the strict marker is for, and it is why those seven are proofs rather than
descriptions. All seven markers are off: the defects are fixed, on 2026-09-03,
and each test now guards against its own failure returning. Two of the fixes
changed an existing test rather than the code, and both say so in place with
the argument for it.

The rest were added alongside the fixes and were never xfails — the floor
tests, which fail if a fix went too far, and the regressions for defects the
fixes themselves turned up. They are ordinary tests and make no claim to have
proved anything about the old code.

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
from security_agent.workspace import Workspace, WorkspaceError  # noqa: E402


# ---------------------------------------------------------------------------
# 1. Workspace.search — a search cut off by the deadline reports "no matches"
# ---------------------------------------------------------------------------

def test_search_stopped_at_the_deadline_does_not_report_no_matches(
    git_repo: Path, monkeypatch
) -> None:
    """Fixed 2026-09-03. `if total == 0: return "no matches"` never looked at
    `truncated`, so a search stopped by its own deadline before keeping a
    single line was rendered as a search that found nothing. The reviewer asks
    whether a pattern occurs anywhere and is told it does not.

    Refused rather than answered, which is stronger than this test first
    asserted. A returned body would carry `count = 0` into
    `_handle_search_code`, which records an exposure per matched file and a
    summary of "0 match(es)" — so the run's own coverage accounting would show
    a search that happened and found nothing. `WorkspaceError` becomes a tool
    result with `is_error=True`: the model reads the refusal, and no coverage
    is recorded for a search that did not run.
    """
    ws = Workspace(root=git_repo)

    # The search really does match; nothing about the repository is unusual.
    body, count = ws.search("SELECT")
    assert count == 1 and "no matches" not in body

    # Now the same search under a blown deadline — what a `git grep` over a
    # large repository produces when it runs past GIT_TIMEOUT_SECONDS. The
    # first line read trips the deadline check, so nothing is kept.
    monkeypatch.setattr(workspace_module, "GIT_TIMEOUT_SECONDS", -1)

    with pytest.raises(WorkspaceError) as raised:
        ws.search("SELECT")

    message = str(raised.value)
    assert "no matches" not in message, message
    assert "stopped" in message
    # It has to say what to do next, or the model repeats the same search.
    assert "path_glob" in message


def test_a_search_that_finishes_and_finds_nothing_still_says_so(
    git_repo: Path
) -> None:
    """The floor. Refusing every empty result would delete the one honest use
    of "no matches" — and "I could not check" and "it is clean" are the two
    answers this repository exists to keep apart, in both directions."""
    ws = Workspace(root=git_repo)

    body, count = ws.search("a_pattern_that_is_certainly_absent_zzz")

    assert count == 0
    assert "no matches" in body


# ---------------------------------------------------------------------------
# 2. tools/corpus_adversary.py — an empty corpus passes the leakage gate
# ---------------------------------------------------------------------------

def test_corpus_adversary_refuses_a_corpus_with_no_cases(
    tmp_path: Path, monkeypatch
) -> None:
    """Fixed 2026-09-03. `worst()` returned no rule when none fired, which is
    also what a corpus with nothing in it produces — so the gate that exists to
    prove the corpus cannot be scored without reading code printed "the cues
    that could reach the reviewer are absent" and exited 0, one line under
    "0 case(s) examined". A mistyped path does it, or a renamed manifest, or a
    corpus not yet checked out: `Path.rglob` on a directory that is not there
    raises nothing."""
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


def test_journal_report_accounts_for_an_unreadable_verdict(tmp_path: Path) -> None:
    """Fixed 2026-09-03. `f.get("verdict", "unadjudicated")` defaults only when
    the KEY is absent, and `verdict.yml` is edited by hand: `verdict:` with
    nothing after it is YAML `None`, and `verdict: nto_real` is a typo. Both
    landed under a name outside `VERDICTS`, so they were in no column, in no
    percentage, and in no notice — the finding left the report and the rate was
    computed as though it had never been written down.

    Counted as unjudged now, so the table adds up to the number of findings,
    and named separately in a line of their own — because "nobody judged this"
    and "somebody judged it and the file cannot carry what they wrote" are
    different statements with different remedies.
    """
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

@pytest.mark.parametrize("value", [
    "\n      - not_real\n",         # a list
    "\n      spelling: not_real\n",  # a mapping
    " 3\n",                          # a number
    " true\n",                       # a boolean
    "\n",                            # empty: YAML `None`
])
def test_journal_report_survives_a_verdict_of_the_wrong_shape(
    tmp_path: Path, value: str
) -> None:
    """The repair for an unreadable verdict must not be a crash.

    `Counter` over a list raises `TypeError: unhashable type`, so a
    `verdict:` followed by an indented list took the whole report down —
    losing a month of adjudication to a typo, which is exactly what the
    `minutes` reader two lines away already refuses to do.
    """
    import journal

    root = tmp_path / "journal"
    entry = root / "some-ref"
    entry.mkdir(parents=True)
    (entry / "verdict.yml").write_text(
        "complete: true\nfindings:\n  - fingerprint: aa11\n"
        "    verdict:{}".format(value), encoding="utf-8")

    out = io.StringIO()
    with redirect_stdout(out):
        code = journal.report(root)

    text = out.getvalue()
    assert code == 0
    assert "cannot read" in text, text
    assert _table_total(text) == 1, (
        "the finding left the table entirely:\n" + text)


def test_journal_report_sees_an_entry_filed_under_a_nested_ref(
    tmp_path: Path
) -> None:
    """Fixed 2026-09-03. A ref is a branch name and branch names have slashes:
    `add --ref feature/login` wrote to `root/feature/login` with
    `parents=True`, printed "filed feature/login", and a one-level glob never
    saw it again. The report either said nothing was filed, or computed its
    percentage over whichever entries happened to be flat.

    `rglob` now, and the ref is the path from the root rather than the last
    segment — `feature/login` and `hotfix/login` are two refs and `.name` calls
    both of them `login`.
    """
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


def test_measure_variance_does_not_exit_zero_when_every_run_failed(
    monkeypatch
) -> None:
    """Fixed 2026-09-03. `main` returned 0 whatever happened, so a wrapper
    reading the exit code could not tell "the gate is stable" from "nothing was
    measured" — the distinction this whole repository is built around, missing
    from the tool that measures whether the gate holds still. `summarise` now
    returns the code it earns and `main` passes it through."""
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


def test_measure_variance_does_not_call_one_surviving_run_stable(
    monkeypatch
) -> None:
    """Fixed 2026-09-03. `good` drops every run that produced no report and the
    stability claim was then made over what was left: four crashes and one
    survivor printed "stable across 1 runs at this sample size", which is
    agreement manufactured out of the four absences.

    Only the stability claim is withheld. The cost and exit-code rows are
    honest for a single run, and refusing to print them would lose the one
    thing that run did establish."""
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

def test_verifier_replay_is_not_green_when_a_run_produced_no_verdict() -> None:
    """Fixed 2026-09-03. `good` excluded every errored run and the instability
    check then compared the survivors only, so two clean runs where one crashed
    left a single verdict compared with itself and exited 0 — the module's own
    protocol, "two clean runs before any payload, always", satisfied by one run
    plus a crash.

    The table is still printed before the refusal: a crashed run is worth
    seeing, and so is the row of the run that worked."""
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
