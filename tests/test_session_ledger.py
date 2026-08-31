"""`tools/session_ledger.py` counts the half of the load the queue cannot see.

It exists because subagent messages are not under `~/.claude/projects/` at all —
on one day the projects tree held 2634 rows with no sidechain among them while
the harness's task transcripts held 4490 assistant messages and 375 million
tokens, and that load sat outside every count made of the day.

A miscount here is invisible by construction: the output is a number nobody can
check against anything else. So the properties that keep it honest are pinned —
an absent token count stays absent rather than becoming zero, nothing is summed,
and the two sources keep their own labels.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1] / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import session_ledger  # noqa: E402


def transcript(tmp_path, *messages, name="session-abcdef123456.jsonl"):
    project = tmp_path / "a-project"
    project.mkdir(exist_ok=True)
    path = project / name
    path.write_text("\n".join(json.dumps(m) for m in messages) + "\n",
                    encoding="utf-8")
    return str(tmp_path / "*" / "*.jsonl")


def message(stamp="2026-08-30T12:00:00.000Z", usage=None, sidechain=False):
    return {"timestamp": stamp, "isSidechain": sidechain,
            "message": {"usage": usage if usage is not None else {
                "input_tokens": 10, "output_tokens": 20,
                "cache_read_input_tokens": 300, "cache_creation_input_tokens": 40}}}


class TestAbsentIsNotZero:
    """The rule the whole project runs on, applied to the token counts.

    A run that reported nothing arriving as four zeros is how an unmeasured run
    prices at $0.00 and drags a median to the floor while looking cheap.
    """

    def test_a_missing_count_stays_none(self, tmp_path):
        pattern = transcript(tmp_path, message(usage={"input_tokens": 5}))
        row = next(iter(session_ledger.rows(pattern, "2026-01-01")))
        assert row["input_tokens"] == 5
        assert row["output_tokens"] is None
        assert row["cache_read_tokens"] is None
        assert row["cache_write_tokens"] is None

    def test_a_zero_is_kept_as_a_zero(self, tmp_path):
        pattern = transcript(tmp_path, message(usage={"output_tokens": 0}))
        row = next(iter(session_ledger.rows(pattern, "2026-01-01")))
        assert row["output_tokens"] == 0

    def test_nothing_is_summed(self, tmp_path):
        """Four counts out, no total. Any total is 99% cache reads."""
        pattern = transcript(tmp_path, message())
        row = next(iter(session_ledger.rows(pattern, "2026-01-01")))
        assert "total_tokens" not in row
        assert row["cache_read_tokens"] == 300


class TestTheTwoSourcesStaySeparate:
    def test_the_kind_is_whatever_the_caller_names(self, tmp_path):
        pattern = transcript(tmp_path, message())
        rows = list(session_ledger.rows(pattern, "2026-01-01", "subagent-message"))
        assert [r["kind"] for r in rows] == ["subagent-message"]

    def test_the_default_is_the_conversation(self, tmp_path):
        pattern = transcript(tmp_path, message())
        assert next(iter(session_ledger.rows(pattern, "2026-01-01")))["kind"] \
            == "session-message"

    def test_the_sidechain_flag_is_carried_not_inferred(self, tmp_path):
        pattern = transcript(tmp_path, message(sidechain=True))
        assert next(iter(session_ledger.rows(pattern, "2026-01-01")))["is_sidechain"]


class TestWhatIsSkipped:
    def test_a_line_with_no_usage_block(self, tmp_path):
        pattern = transcript(tmp_path, {"timestamp": "2026-08-30T12:00:00Z"})
        assert list(session_ledger.rows(pattern, "2026-01-01")) == []

    def test_a_line_that_is_not_json(self, tmp_path):
        project = tmp_path / "a-project"
        project.mkdir()
        (project / "s.jsonl").write_text(
            '{"usage": broken\n' + json.dumps(message()) + "\n", encoding="utf-8")
        rows = list(session_ledger.rows(str(tmp_path / "*" / "*.jsonl"), "2026-01-01"))
        assert len(rows) == 1

    def test_a_message_with_no_timestamp(self, tmp_path):
        pattern = transcript(tmp_path, {"message": {"usage": {"input_tokens": 1}}})
        assert list(session_ledger.rows(pattern, "2026-01-01")) == []

    def test_a_message_before_since(self, tmp_path):
        pattern = transcript(tmp_path, message(stamp="2026-08-01T12:00:00Z"))
        assert list(session_ledger.rows(pattern, "2026-08-28")) == []


class TestSinceIsAStringComparison:
    """Named rather than fixed, because the fix is a decision, not a tidy-up.

    `stamp < since` compares ISO text. That is correct while every transcript
    writes UTC with a `Z`, which is what Claude Code does today. It would be
    wrong the moment one wrote a local offset: `2026-08-30T01:00:00+03:00` is
    2026-08-29 in UTC and sorts as 2026-08-30, so a row would land in the wrong
    day and, in `window_recut`, in the wrong window.
    """

    def test_zulu_timestamps_compare_as_expected(self, tmp_path):
        pattern = transcript(tmp_path,
                             message(stamp="2026-08-27T23:59:59Z"),
                             message(stamp="2026-08-28T00:00:01Z"))
        rows = list(session_ledger.rows(pattern, "2026-08-28"))
        assert [r["started_at"] for r in rows] == ["2026-08-28T00:00:01Z"]

    def test_an_offset_timestamp_is_filed_by_its_text_not_its_instant(self, tmp_path):
        """Documented, not asserted as desirable. It is the known edge."""
        pattern = transcript(tmp_path, message(stamp="2026-08-28T01:00:00+03:00"))
        rows = list(session_ledger.rows(pattern, "2026-08-28"))
        assert len(rows) == 1, "text-ordered: kept, though the instant is 08-27 UTC"
