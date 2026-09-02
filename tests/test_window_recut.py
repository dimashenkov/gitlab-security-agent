"""`tools/window_recut.py` could not be tested and dropped rows in silence.

Six defects now, all the same shape: paid work the tool could not see, and
values it coerced rather than read.

It was a bare script: `argparse` ran at module level, so importing it ran a full
analysis and no part of it could be reached by a test. The logic is in `main()`
now and the file is importable.

And `early_windows` added `row.get("window")` for any window row that did not end
in a refusal. A row missing that key contributed `None` — and every corpus review
carries no `window` key either, so `r.get("window") not in dropped` then dropped
**every review**. The report would have printed smaller numbers and said nothing.
That is the silent-truncation shape this project keeps finding: making the input
less parseable must never make the output quieter.
"""
from __future__ import annotations

import json
import sys
from datetime import timezone
from pathlib import Path

import pytest

TOOLS = Path(__file__).resolve().parents[1] / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import window_recut  # noqa: E402


def log_with(tmp_path, *rows):
    path = tmp_path / "log.jsonl"
    path.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
    return path


class TestEarlyWindows:
    def test_a_window_that_ran_to_refusal_is_kept(self, tmp_path, monkeypatch):
        monkeypatch.setattr(window_recut, "ROOT_LOG", log_with(
            tmp_path, {"kind": "window", "window": "w1",
                       "window_termination": "refused"}))
        assert window_recut.early_windows() == set()

    def test_a_window_stopped_early_is_dropped(self, tmp_path, monkeypatch):
        monkeypatch.setattr(window_recut, "ROOT_LOG", log_with(
            tmp_path, {"kind": "window", "window": "w1",
                       "window_termination": "work_exhausted"}))
        assert window_recut.early_windows() == {"w1"}

    def test_a_window_row_with_no_identifier_contributes_nothing(
            self, tmp_path, monkeypatch):
        """The defect. `None` in the drop set erases every review row.

        Reviews carry no `window` key, so `.get("window")` is `None` for all of
        them, and `None in dropped` was true for all of them at once.
        """
        monkeypatch.setattr(window_recut, "ROOT_LOG", log_with(
            tmp_path,
            {"kind": "window", "window_termination": "interrupted"},
            {"kind": "window", "window": "", "window_termination": "interrupted"}))
        dropped = window_recut.early_windows()
        assert None not in dropped
        assert "" not in dropped
        assert dropped == set()

    def test_a_review_row_survives_a_malformed_window_row(self, tmp_path, monkeypatch):
        """The property the fix is for, stated at the level that matters."""
        monkeypatch.setattr(window_recut, "ROOT_LOG", log_with(
            tmp_path, {"kind": "window", "window_termination": "interrupted"}))
        dropped = window_recut.early_windows()
        review = {"kind": "review", "who": "case/unsafe"}
        assert review.get("window") not in dropped

    def test_an_unparseable_line_is_skipped_not_fatal(self, tmp_path, monkeypatch):
        path = tmp_path / "log.jsonl"
        path.write_text('{"kind": "window", "window": "w1", '
                        '"window_termination": "interrupted"}\n'
                        'not json at all\n', encoding="utf-8")
        monkeypatch.setattr(window_recut, "ROOT_LOG", path)
        assert window_recut.early_windows() == {"w1"}

    def test_a_missing_log_drops_nothing(self, tmp_path, monkeypatch):
        monkeypatch.setattr(window_recut, "ROOT_LOG", tmp_path / "absent.jsonl")
        assert window_recut.early_windows() == set()


def measurement(root: Path, relative: str, body):
    """One result file, wherever a paid run puts it."""
    path = root / "measurements" / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(body), encoding="utf-8")
    return path


def pair(case_id="go-a", ran_at="2026-08-29T09:00:00+00:00", complete=True):
    # `complete` is written either way by a real run, and the helper has to
    # say it too: omitting it made "a complete report" a row that never
    # claimed to be one, and the test then asserted the forgiving reading.
    usage = {"input_tokens": 10, "output_tokens": 20,
             "cache_read_tokens": 30, "cache_write_tokens": 40,
             "complete": bool(complete)}
    if not complete:
        usage = dict(usage, unreported_stages=2)
    return {"case_id": case_id, "ran_at": ran_at,
            "members": {"safe": {"usage": usage}, "unsafe": {"usage": usage}}}


@pytest.fixture
def workspace(tmp_path, monkeypatch):
    """`window_recut` globs relative to the working directory."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / "measurements" / "queue").mkdir(parents=True)
    return tmp_path


class TestEveryPlaceAPaidRunWrites:
    """45 files read, 27 unread — and this is the tool the quota estimate
    rests on. A review that cost money and consumed a window counted as no
    review at all, in the direction that makes the limit look further away."""

    def test_an_experiment_pass_is_counted(self, workspace):
        """`measurements/experiment-*/pass-*/`, one bare object per file. Both
        the directory and the shape had to be wrong for the row to vanish, and
        both were."""
        measurement(workspace, "experiment-noise-floor/pass-a/go-a.json", pair())

        assert len(list(window_recut.reviews())) == 2

    def test_a_round_directory_is_counted(self, workspace):
        measurement(workspace, "round-2/go-a.json", [pair()])

        assert len(list(window_recut.reviews())) == 2

    def test_a_results_container_is_counted(self, workspace):
        measurement(workspace, "batch.json", {"results": [pair()]})

        assert len(list(window_recut.reviews())) == 2

    def test_a_file_read_twice_is_counted_once(self, workspace):
        """The globs overlap; a member run counted twice inflates the estimate
        of what a window holds, which is the same error the other way up."""
        measurement(workspace, "queue/go-a.json", [pair()])

        assert len(list(window_recut.reviews())) == 2


class TestAPartialUsageReportIsNotAZero:
    def test_a_member_with_unreported_stages_is_marked(self, workspace):
        """57 of 156 member runs in this corpus carry `usage.complete: false`.
        Their missing stages are summed in as zero and printed under a column
        called `tokens` — so the figure is a floor, and nothing said so."""
        measurement(workspace, "queue/go-a.json", [pair(complete=False)])

        assert [r["usage_complete"] for r in window_recut.reviews()] == [False, False]

    def test_a_complete_report_is_not_marked(self, workspace):
        measurement(workspace, "queue/go-a.json", [pair()])

        assert all(r["usage_complete"] for r in window_recut.reviews())

    def test_the_table_marks_a_floor_and_says_why(self, workspace, monkeypatch, capsys):
        monkeypatch.setattr(window_recut, "ledger", lambda since: ([], None))
        measurement(workspace, "queue/go-a.json", [pair(complete=False)])

        window_recut.main([])

        out = capsys.readouterr().out
        assert "≥" in out
        assert "is a floor and not a measurement" in out


class TestTheDropFilterCanActuallyDrop:
    """The banner said two windows were dropped. Nothing was dropped: no review
    row carries a `window`, so `r.get("window") not in dropped` was true for
    every one of them and the sentence above the table was the only evidence
    the filter existed."""

    def test_a_review_is_attributed_to_its_window(self, workspace):
        (workspace / "measurements" / "queue" / "log.jsonl").write_text(
            json.dumps({"kind": "review", "case_id": "go-a", "member": "safe",
                        "window": "w1"}) + "\n", encoding="utf-8")
        measurement(workspace, "queue/go-a.json", [pair()])

        windows = {r["who"]: r.get("window") for r in window_recut.reviews()}

        assert windows["go-a/safe"] == "w1"
        assert windows["go-a/unsafe"] is None

    def test_a_review_in_an_early_window_is_removed(self, workspace, monkeypatch,
                                                    capsys):
        monkeypatch.setattr(window_recut, "ledger", lambda since: ([], None))
        (workspace / "measurements" / "queue" / "log.jsonl").write_text("\n".join([
            json.dumps({"kind": "review", "case_id": "go-a", "member": "safe",
                        "window": "w1"}),
            json.dumps({"kind": "review", "case_id": "go-a", "member": "unsafe",
                        "window": "w1"}),
            json.dumps({"kind": "window", "window": "w1",
                        "window_termination": "work_exhausted"}),
        ]) + "\n", encoding="utf-8")
        measurement(workspace, "queue/go-a.json", [pair()])

        window_recut.main([])

        out = capsys.readouterr().out
        assert "removing 2 row(s)" in out
        # And gone from the table: 09:00 is inside the two hours before 10:00.
        assert "10:00                 2         0" in out

    def test_the_banner_cannot_claim_a_drop_that_did_not_happen(
            self, workspace, monkeypatch, capsys):
        """A window named in the log with no review attributable to it removes
        nothing, and the line has to say so rather than imply a number."""
        monkeypatch.setattr(window_recut, "ledger", lambda since: ([], None))
        (workspace / "measurements" / "queue" / "log.jsonl").write_text(
            json.dumps({"kind": "window", "window": "w1",
                        "window_termination": "work_exhausted"}) + "\n",
            encoding="utf-8")
        measurement(workspace, "queue/go-a.json", [pair()])

        window_recut.main([])

        assert "removing 0 row(s)" in capsys.readouterr().out


class TestTheTranscriptSourcesCannotGoMissingQuietly:
    def test_a_failing_ledger_is_reported_not_swallowed(self, workspace):
        """`.stdout` off a `check=False` run: if `session_ledger.py` raises,
        stdout is empty, stderr is thrown away, and the table prints zero
        subagent and zero session messages — which is what a quiet day looks
        like. Two of the three sources, gone without a word."""
        rows, problem = window_recut.ledger("2026-01-01")

        assert rows == []
        assert problem and "session_ledger.py" in problem

    def test_the_report_names_it_above_the_table(self, workspace, capsys):
        measurement(workspace, "queue/go-a.json", [pair()])

        window_recut.main([])

        out = capsys.readouterr().out
        assert "the transcript sources could not be read" in out
        assert out.index("could not be read") < out.index("window ends (UTC)")

    def test_a_working_ledger_reports_no_problem(self, workspace, monkeypatch):
        repo = Path(__file__).resolve().parents[1]
        monkeypatch.chdir(repo)

        rows, problem = window_recut.ledger("2026-08-28")

        assert problem is None
        assert rows and all("started_at" in r for r in rows)


class TestStamp:
    def test_a_zulu_timestamp_becomes_utc(self):
        got = window_recut.stamp({"started_at": "2026-08-30T12:00:00Z"})
        assert got.tzinfo is timezone.utc
        assert got.hour == 12

    def test_an_offset_timestamp_is_converted_not_relabelled(self):
        got = window_recut.stamp({"started_at": "2026-08-30T14:00:00+02:00"})
        assert got.hour == 12

    def test_a_naive_timestamp_raises_rather_than_being_assumed_utc(self):
        """Guessing a timezone here would move rows between windows silently."""
        with pytest.raises(ValueError):
            window_recut.stamp({"started_at": "not a time"})


def test_usage_that_says_nothing_is_not_counted_as_complete(tmp_path,
                                                            monkeypatch):
    """`is not False` read a row that never recorded completeness as complete.

    Thirty-eight rows on disk carry no such field, and their token sums were
    printed without the `≥` that says the number is a floor — the
    absence-is-agreement defect, one step inside the fix written against it.
    """
    import window_recut

    path = tmp_path / "r.json"
    path.write_text(json.dumps([{
        "case_id": "one", "ran_at": "2026-09-01T10:00:00+00:00",
        "members": {"safe": {"usage": {"input_tokens": 5}}},
    }]), encoding="utf-8")
    monkeypatch.setattr(window_recut, "result_files", lambda: [path])
    monkeypatch.setattr(window_recut, "review_windows", lambda *a, **k: {})

    rows = list(window_recut.reviews())

    assert rows and rows[0]["usage_complete"] is False


def test_a_case_measured_twice_belongs_to_two_windows(tmp_path, monkeypatch):
    """Keyed on `(case_id, member)` with `setdefault`, the first window seen was
    stamped on every measurement of that case.

    A case run again in a later window had all its history attributed to the
    first one — and with the drop filter now actually removing rows, that
    mis-attribution removes valid later measurements or keeps ones that should
    go.
    """
    import window_recut

    log = tmp_path / "log.jsonl"
    log.write_text("\n".join(json.dumps(row) for row in [
        {"kind": "review", "case_id": "one", "member": "safe",
         "started_at": "2026-09-01T10:00:00+00:00", "window": "first"},
        {"kind": "review", "case_id": "one", "member": "safe",
         "started_at": "2026-09-02T10:00:00+00:00", "window": "second"},
    ]), encoding="utf-8")
    windows = window_recut.review_windows(log)

    assert windows[("one", "safe", "2026-09-01T10:00:00+00:00")] == "first"
    assert windows[("one", "safe", "2026-09-02T10:00:00+00:00")] == "second"

