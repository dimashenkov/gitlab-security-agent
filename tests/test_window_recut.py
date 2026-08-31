"""`tools/window_recut.py` could not be tested and dropped rows in silence.

Two defects, both structural rather than arithmetic.

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
