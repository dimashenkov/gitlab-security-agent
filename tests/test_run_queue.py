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
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from run_queue import classify, close_window, raw_rows, reset_at, sleep_until

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


# ------------------------------------------- waiting through a closed lid


def test_the_wait_is_against_the_clock_and_not_a_duration(monkeypatch):
    """The queue slept two and three quarter hours too long, correctly.

    It was refused at 09:47, the message said 12:50, and `reset_at` returned
    12:50 — every number right. At 15:32 it was still asleep, because
    `time.sleep` counts on a monotonic clock that does not advance while the
    machine is suspended, and the laptop had been shut for most of the
    interval. The machine's sleep was added to the queue's.

    So the wait is re-derived from the wall clock on every step, and a
    suspended machine costs one step of overshoot rather than however long the
    lid was closed. Simulated here by a clock that jumps: three hours pass
    between two consecutive reads, exactly as they do across a suspend.
    """
    import run_queue

    now = [datetime(2026, 8, 30, 9, 47, tzinfo=timezone.utc)]
    slept = []

    class Clock:
        @staticmethod
        def now(tz=None):
            return now[0]

    def fake_sleep(seconds):
        slept.append(seconds)
        # The suspend: the first step returns to a machine three hours older.
        now[0] += timedelta(hours=3) if len(slept) == 1 else timedelta(seconds=seconds)

    monkeypatch.setattr(run_queue, "time", type("t", (), {"sleep": staticmethod(fake_sleep)}))
    monkeypatch.setattr(run_queue, "datetime", type(
        "d", (), {"now": staticmethod(lambda tz=None: now[0])}))

    sleep_until(datetime(2026, 8, 30, 12, 51, tzinfo=timezone.utc))

    # No single wait is longer than a step, so the interval computed before
    # the suspend is never the thing being waited out.
    assert max(slept) <= 60.0
    # And it stops as soon as the clock says so. Three hours vanished during
    # the first step; what remained after it was four minutes, not the three
    # hours the original arithmetic had reserved.
    assert sum(slept) < 11040
    assert now[0] >= datetime(2026, 8, 30, 12, 51, tzinfo=timezone.utc)


def test_a_target_already_past_returns_at_once(monkeypatch):
    """Woken to find the moment gone — after a suspend, or because the message
    named a time that had already happened. Sleeping a negative interval, or
    any interval, would be waiting for something that has arrived."""
    import run_queue

    fixed = datetime(2026, 8, 30, 15, 32, tzinfo=timezone.utc)
    monkeypatch.setattr(run_queue, "datetime", type(
        "d", (), {"now": staticmethod(lambda tz=None: fixed)}))
    monkeypatch.setattr(run_queue, "time", type(
        "t", (), {"sleep": staticmethod(lambda s: pytest.fail("slept anyway"))}))

    sleep_until(datetime(2026, 8, 30, 12, 51, tzinfo=timezone.utc))


# --------------------------- telling the two kinds of window apart


def read_ledger(path):
    import json
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


@pytest.fixture
def ledger(tmp_path, monkeypatch):
    import run_queue
    monkeypatch.setattr(run_queue, "QUEUE", tmp_path)
    monkeypatch.setattr(run_queue, "LOG", tmp_path / "log.jsonl")
    return tmp_path / "log.jsonl"


def test_a_window_says_how_it_ended(ledger):
    """The whole point of the field.

    A window that ran to refusal measured where the limit fell, under that
    window's load. A window stopped after four pairs because somebody wanted
    room to work says only that the limit was above four. Averaging the two
    gives a number about neither, and the last cluster fell apart that way by
    accident — doing it on purpose would be worse.
    """
    close_window("w1", "refused", 6, 2, "unattended")
    close_window("w2", "stopped_early", 4, 8, "attended")

    rows = read_ledger(ledger)
    assert [r["window_termination"] for r in rows] == ["refused", "stopped_early"]
    assert [r["mode"] for r in rows] == ["unattended", "attended"]


def test_every_window_row_carries_enough_to_be_filtered_out(ledger):
    """A later analysis has to be able to drop the early stops without
    guessing which they were. The row names the window, so its per-invocation
    rows can be excluded with it."""
    close_window("w1", "stopped_early", 4, 8, "attended")

    row = read_ledger(ledger)[0]
    assert row["kind"] == "window"
    assert row["window"] == "w1"
    assert row["pairs_completed"] == 4 and row["pairs_left"] == 8
    assert "closed_at" in row


def test_a_drained_queue_is_not_a_refusal_either(ledger):
    """Running out of work is not running out of allowance. `work_exhausted`
    is its own value so it cannot be read as either of the other two."""
    close_window("w1", "work_exhausted", 11, 0, "unattended")

    row = read_ledger(ledger)[0]
    assert row["window_termination"] == "work_exhausted"
    assert row["pairs_left"] == 0


def test_nothing_in_the_window_row_is_derived(ledger):
    """No rate, no estimate, no threshold. The field exists so a filter can be
    written later; computing anything from it here is the mistake three rounds
    of this turned on."""
    close_window("w1", "refused", 6, 2, "unattended")

    row = read_ledger(ledger)[0]
    assert not {"limit", "estimate", "threshold", "cap", "budget"} & set(row)


# ------------------------- a file is not a measurement


def test_a_pair_that_did_not_finish_is_not_treated_as_recorded(tmp_path, monkeypatch):
    """The founding error of this project, found inside the queue built to
    avoid it.

    A review that stopped early leaves a result file saying so. The queue asked
    only whether the file existed, so `js-q4gh-4ffp-5cg8-snap` — one member
    incomplete, nothing measured — was skipped as done and would have stayed
    skipped for ever. "Did not check" reading as "checked" is the one confusion
    the whole tool exists to prevent.
    """
    import json

    import run_queue
    monkeypatch.setattr(run_queue, "QUEUE", tmp_path)
    monkeypatch.setattr(run_queue, "ROOT", tmp_path)

    unfinished = [{"case_id": "a-case", "incomplete": ["unsafe"],
                   "pair_success": None}]
    (tmp_path / "a-case.json").write_text(json.dumps(unfinished))
    assert run_queue.already_run("a-case") is False

    finished = [{"case_id": "a-case", "pair_success": True}]
    (tmp_path / "a-case.json").write_text(json.dumps(finished))
    assert run_queue.already_run("a-case") is True


def test_a_result_file_that_will_not_parse_is_not_a_measurement(tmp_path, monkeypatch):
    """Truncated by a kill, half-written by a crash. Either way nothing in it
    says the case was measured, and the safe reading is to run it again."""
    import run_queue
    monkeypatch.setattr(run_queue, "QUEUE", tmp_path)
    monkeypatch.setattr(run_queue, "ROOT", tmp_path)

    (tmp_path / "a-case.json").write_text('[{"case_id": "a-cas')
    assert run_queue.already_run("a-case") is False
