"""Reviews of real changes, and the rate they are allowed to produce.

The corpus is this project's own construction and can only support regression
claims. The journal is the other half: reviews of code nobody built to be
reviewed, each finding carrying a human verdict.

Its one dangerous property is the one tested hardest here. "Not yet judged" and
"judged not real" are different statements, and every measurement this project
has had to withdraw came from the second quietly absorbing the first — decoys
counted as precision, empty finding lists from runs that never completed
counted as misses, findings in the safe member counted as false positives by
construction.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from journal import _minutes, add, report

ARTIFACT = {
    "model": "claude-opus-5",
    "complete": True,
    "stop_reason": "completed",
    "revision": {"base_sha": "a" * 40, "head_sha": "b" * 40},
    "verdict": {"exit_code": 1, "blocking_fingerprints": ["ff01"]},
    "findings": [
        {"fingerprint": "ff01", "category": "injection", "severity": "high",
         "file": "app/views.py", "line": 14, "title": "SQL injection"},
        {"fingerprint": "ff02", "category": "xss", "severity": "low",
         "file": "app/render.py", "line": 3, "title": "Reflected value"},
    ],
}


def artifact(tmp_path, **overrides) -> Path:
    body = dict(ARTIFACT)
    body.update(overrides)
    path = tmp_path / "findings.json"
    path.write_text(json.dumps(body))
    return path


def verdicts_of(root: Path, ref: str) -> dict:
    return yaml.safe_load((root / ref / "verdict.yml").read_text())


def judge(root: Path, ref: str, *verdicts: str) -> None:
    data = verdicts_of(root, ref)
    for finding, verdict in zip(data["findings"], verdicts):
        finding["verdict"] = verdict
    (root / ref / "verdict.yml").write_text(yaml.safe_dump(data, sort_keys=False))


def test_filing_a_review_records_what_was_reviewed(tmp_path):
    """A finding is a claim about code at a moment; the verdict is a claim
    about the finding. Both need the moment."""
    root = tmp_path / "journal"
    assert add(artifact(tmp_path), "abc1234", root) == 0

    data = verdicts_of(root, "abc1234")
    assert data["reviewed_head"] == "b" * 40
    assert data["reviewed_base"] == "a" * 40
    assert (root / "abc1234" / "findings.json").is_file()


def test_every_finding_starts_unadjudicated(tmp_path):
    root = tmp_path / "journal"
    add(artifact(tmp_path), "abc1234", root)

    data = verdicts_of(root, "abc1234")
    assert [f["verdict"] for f in data["findings"]] == ["unadjudicated"] * 2
    assert data["findings"][0]["blocked_the_merge"] is True
    assert data["findings"][1]["blocked_the_merge"] is False


def test_refiling_does_not_overwrite_a_verdict_already_given(tmp_path):
    """The stub would silently replace a judgement someone spent time on."""
    root = tmp_path / "journal"
    add(artifact(tmp_path), "abc1234", root)
    judge(root, "abc1234", "real", "not_real")

    assert add(artifact(tmp_path), "abc1234", root) == 1
    assert [f["verdict"] for f in verdicts_of(root, "abc1234")["findings"]] == [
        "real", "not_real"]


def test_nothing_judged_means_nothing_to_decide_on(tmp_path, capsys):
    """The failure mode this file exists for: an unjudged finding is not a
    wrong one, and a tool that averages them says the reviewer is 0% correct."""
    root = tmp_path / "journal"
    add(artifact(tmp_path), "abc1234", root)

    report(root)
    out = capsys.readouterr().out
    assert "nothing to decide on" in out
    assert "%" not in out


def test_unjudged_findings_stay_out_of_the_rate(tmp_path, capsys):
    root = tmp_path / "journal"
    add(artifact(tmp_path), "abc1234", root)
    judge(root, "abc1234", "novel_actionable")   # the second stays unadjudicated

    report(root)
    out = capsys.readouterr().out
    assert "1 finding(s) a person has judged, 1 showed something" in out
    assert "not counted as wrong" in out


def test_unclear_is_a_real_answer_and_stays_out_of_the_count(tmp_path, capsys):
    root = tmp_path / "journal"
    add(artifact(tmp_path), "abc1234", root)
    judge(root, "abc1234", "novel_actionable", "unclear")

    report(root)
    out = capsys.readouterr().out
    assert "1 finding(s) a person has judged, 1 showed something" in out
    assert "left `unclear`" in out


def test_a_real_finding_the_author_already_knew_is_not_value(tmp_path, capsys):
    """The change that makes this vocabulary worth having.

    "Is it real" was the wrong question for deciding whether to keep the tool.
    A finding can be perfectly real and worth nothing, because the author had
    it in his pre-review note before the agent said anything.
    """
    root = tmp_path / "journal"
    add(artifact(tmp_path), "abc1234", root)
    judge(root, "abc1234", "already_known", "real_non_actionable")

    report(root)
    out = capsys.readouterr().out
    assert "2 finding(s) a person has judged, 0 showed something" in out
    assert "1 were already known" in out


def test_what_the_agent_missed_is_reported(tmp_path, capsys):
    """Without it the journal is a scoreboard of hits. A tool that never finds
    what you found yourself has told you nothing."""
    root = tmp_path / "journal"
    add(artifact(tmp_path), "abc1234", root)
    data = verdicts_of(root, "abc1234")
    data["missed_by_the_agent"] = "the token comparison in auth.py is not constant-time"
    (root / "abc1234" / "verdict.yml").write_text(yaml.safe_dump(data, sort_keys=False))

    report(root)
    assert "found a security issue the agent did not" in capsys.readouterr().out


def test_what_you_noticed_first_is_recorded_at_filing_time(tmp_path):
    """Read the report first and a useful finding can no longer be told apart
    from one you would have found anyway. The field exists so the ordering is
    visible afterwards."""
    root = tmp_path / "journal"
    add(artifact(tmp_path), "abc1234", root, "the region parameter is interpolated")

    assert verdicts_of(root, "abc1234")["noticed_before_running"] == (
        "the region parameter is interpolated")


def test_the_decision_is_spelled_out_not_left_to_the_table(tmp_path, capsys):
    """A reader looking for a reason to keep a tool will find one in any table."""
    root = tmp_path / "journal"
    add(artifact(tmp_path), "abc1234", root)
    judge(root, "abc1234", "not_real", "not_real")

    report(root)
    out = capsys.readouterr().out
    assert "Keep it if at least one of those 0" in out
    assert "Turn it off if none was" in out
    assert "1 of 10 eligible changes so far" in out


def test_an_incomplete_review_is_named_above_the_numbers(tmp_path, capsys):
    """Its finding count means nothing: it stopped, it did not conclude."""
    root = tmp_path / "journal"
    add(artifact(tmp_path, complete=False, stop_reason="context_exhausted",
                 findings=[]), "bad0001", root)

    report(root)
    out = capsys.readouterr().out
    assert "did not complete" in out
    assert out.index("did not complete") < out.index("verdict")


def test_a_block_that_was_wrong_is_reported_separately(tmp_path, capsys):
    """The costliest error this product can make, and the one an adopter asks
    about first."""
    root = tmp_path / "journal"
    add(artifact(tmp_path), "abc1234", root)
    judge(root, "abc1234", "not_real", "novel_actionable")

    report(root)
    out = capsys.readouterr().out
    assert "1 finding(s) actually blocked a merge; 1 of those were judged not real" in out


def test_the_report_says_it_is_not_independent_evidence(tmp_path, capsys):
    """The same person wrote the prompts, the code, and the verdicts. A number
    that does not carry that sentence will be quoted without it."""
    root = tmp_path / "journal"
    add(artifact(tmp_path), "abc1234", root)
    judge(root, "abc1234", "novel_actionable", "already_known")

    report(root)
    assert "not independent evidence" in capsys.readouterr().out


def test_an_empty_journal_is_not_a_clean_result(tmp_path, capsys):
    root = tmp_path / "journal"
    root.mkdir()
    assert report(root) == 2
    assert "nothing filed" in capsys.readouterr().out


def test_a_hand_typed_duration_never_loses_a_months_adjudication(tmp_path, capsys):
    """`verdict.yml` is edited by hand, so `minutes` arrives as `7.9`, `true`,
    or `"12m"`. A crash here would throw away a month of work over a typo."""
    assert _minutes(7) == 7
    assert _minutes(7.9) == 7
    assert _minutes("12") == 12
    assert _minutes("12m") == 0          # unreadable, dropped
    assert _minutes(True) == 0           # `true` is not a duration
    assert _minutes(None) == 0
    assert _minutes(-5) == 0
