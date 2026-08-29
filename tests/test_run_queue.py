"""The queue that survives the subscription's session limit.

Three windows were exhausted in two days and each answer was a rule built on a
number measuring something else — batch size against the weekly limit, then
notional API cost against quota. Remaining session capacity is not observable
by anything here, so the queue does not predict it. It reads the refusal, which
is observable and carries the reset time, and waits.

The tests are of that reading. A refusal misread as a crash abandons the queue;
a crash misread as a refusal makes one broken case look like an exhausted
account and sits out a reset for nothing.
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from run_queue import classify, raw_rows, reset_at

LIMIT_MESSAGE = "You've hit your session limit · resets 7:20pm (Europe/Sofia)."


def member(**over):
    body = {"stop_reason": "completed", "stop_detail": "", "seconds": 12.0,
            "usage": {"input_tokens": 16, "output_tokens": 8183,
                      "cache_read_tokens": 105799, "cache_write_tokens": 15069},
            "provenance": {"reported_cost_usd": 0.409}}
    body.update(over)
    return body


def row(**members):
    return [{"case_id": "a-case", "members": members or {"unsafe": member(),
                                                         "safe": member()}}]


# ------------------------------------------------- telling the two apart


def test_the_limit_is_recognised_from_what_the_cli_actually_says():
    """The refusal arrives as an ordinary error — exit 1, message in the
    terminal object — so there is no status code to key on. This is the
    sentence, copied from a real refused run in `cli-batch-6-php.json`."""
    payload = row(unsafe=member(stop_reason="error", stop_detail=LIMIT_MESSAGE),
                  safe=member())
    assert classify(payload) == ("refused", LIMIT_MESSAGE)


def test_a_run_that_failed_some_other_way_is_not_a_refusal():
    """One broken case is a case to record and move past. Read as a refusal it
    would stop the queue and sit out a reset for nothing — and the reset it
    waited for would never come, because nothing was exhausted."""
    other = ("the CLI reported '(no subtype)' and exited 1. A process that "
             "failed and still printed a success object has not agreed with "
             "itself")
    payload = row(unsafe=member(stop_reason="error", stop_detail=other),
                  safe=member())
    assert classify(payload) == ("failed-known", other)


def test_a_finished_pair_is_not_a_refusal():
    assert classify(row()) == ("ok", None)


# ------------------------------------------------------ reading the clock


def test_the_reset_time_is_read_from_the_refusal():
    now = datetime(2026, 8, 29, 18, 5, tzinfo=timezone.utc)
    assert reset_at(LIMIT_MESSAGE, now) == datetime(2026, 8, 29, 19, 20, tzinfo=timezone.utc)


def test_a_reset_already_past_today_is_tomorrows():
    """`resets 7:20pm` carries no date. Refused at half past eight, the next
    such moment is tomorrow — and sleeping a negative interval would spin the
    queue against a limit that has not moved."""
    now = datetime(2026, 8, 29, 20, 30, tzinfo=timezone.utc)
    assert reset_at(LIMIT_MESSAGE, now) == datetime(2026, 8, 30, 19, 20, tzinfo=timezone.utc)


@pytest.mark.parametrize("text,hour", [
    ("resets 12:50pm (Europe/Sofia)", 12),
    ("resets 12:05am (Europe/Sofia)", 0),
    ("resets 9:30pm", 21),
    ("resets 11am", 11),
])
def test_midnight_and_noon_are_not_confused(text, hour):
    """`12pm` is noon and `12am` is midnight, and the ordinary modulo gets both
    wrong in the direction of waiting twelve hours too long."""
    now = datetime(2026, 8, 29, 0, 1, tzinfo=timezone.utc)
    when = reset_at(text, now)
    assert when is not None and when.hour == hour


def test_a_refusal_naming_no_readable_time_waits_blind_rather_than_guessing():
    """If the wording changes, the queue must not invent a moment. Returning
    None sends the caller to a fixed short wait, which is wrong by minutes
    rather than by hours."""
    assert reset_at("You've hit your session limit.", datetime.now(timezone.utc)) is None
    assert reset_at("", datetime.now(timezone.utc)) is None


# ------------------------------------------------------------- the log


def test_one_row_per_invocation_and_nothing_summed():
    """A row per member, not per pair, and no total anywhere in it.

    Today's analysis tripped over exactly one pre-summed figure: adding the
    four token counts gives a number that is 99% cache reads, so any total
    including them says "the conversation dominates" whatever else is true.
    The four are kept apart and the reader decides.
    """
    rows = raw_rows(row(), "2026-08-29T18:00:00+00:00",
                    "2026-08-29T18:04:00+00:00")

    assert len(rows) == 2
    assert {r["member"] for r in rows} == {"safe", "unsafe"}
    assert rows[0]["input_tokens"] == 16
    assert rows[0]["cache_read_tokens"] == 105799
    assert rows[0]["notional_api_cost"] == 0.409
    assert rows[0]["kind"] == "review"
    # No derived field of any kind. `tokens`, `reviews`, a cost total — each
    # was in an earlier version and each is a decision taken away from
    # whoever reads the log later.
    assert not {"tokens", "reviews", "total", "cost"} & set(rows[0])


def test_the_two_ends_of_the_invocation_are_both_recorded():
    """A row that carries only a duration cannot be placed inside a window
    somebody else chooses to cut. Moving one boundary today turned 25·34·26
    into 32·38·43, so both ends go on every line."""
    rows = raw_rows(row(), "2026-08-29T18:00:00+00:00",
                    "2026-08-29T18:04:00+00:00")
    assert rows[0]["started_at"] == "2026-08-29T18:00:00+00:00"
    assert rows[0]["finished_at"] == "2026-08-29T18:04:00+00:00"


def test_a_member_that_reported_no_usage_writes_null_and_not_zero():
    """The verifier is a second CLI invocation that returns no usage at all.
    A zero written in for it is a token count nobody measured, and it would
    average into any later analysis as a cheap run."""
    rows = raw_rows(row(unsafe=member(usage={}, provenance={}),
                        safe=member(usage={}, provenance={})),
                    "a", "b")

    assert rows[0]["input_tokens"] is None
    assert rows[0]["notional_api_cost"] is None
    assert rows[0]["usage_reported"] is False


def test_each_members_own_duration_survives():
    """Per invocation, so the two members of one pair are two observations.
    The earlier version kept only the slower of them and the other was lost."""
    rows = raw_rows(row(unsafe=member(seconds=300.0), safe=member(seconds=120.0)),
                    "a", "b")
    assert sorted(r["seconds"] for r in rows) == [120.0, 300.0]
