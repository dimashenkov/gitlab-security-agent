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

    # Which version of the case the row is about is a separate question, asked
    # by the test below; here it is held true so this one stays about the one
    # thing it was written for.
    monkeypatch.setattr(run_queue, "about_this_version",
                        lambda case_id, row: True)

    unfinished = [{"case_id": "a-case", "incomplete": ["unsafe"],
                   "pair_success": None}]
    (tmp_path / "a-case.json").write_text(json.dumps(unfinished))
    assert run_queue.already_run("a-case") is False

    finished = [{"case_id": "a-case", "pair_success": True}]
    (tmp_path / "a-case.json").write_text(json.dumps(finished))
    assert run_queue.already_run("a-case") is True


def test_a_row_from_another_model_does_not_skip_the_case(tmp_path, monkeypatch):
    """The Sonnet trial's rows, read as this product's completed runs.

    `already_run` asked whether any scorable row exists, never which model
    produced it. The trial wrote 52 such rows on 2026-09-08; the queue would
    have taken any of them for a finished run of the product and skipped the
    case for ever — the same "did not check reads as checked" confusion the
    test above is about, one field further along.
    """
    import json

    import run_queue
    monkeypatch.setattr(run_queue, "QUEUE", tmp_path)
    monkeypatch.setattr(run_queue, "ROOT", tmp_path)
    monkeypatch.setattr(run_queue, "about_this_version",
                        lambda case_id, row: True)

    def measured_by(name):
        block = {"provenance": {"model_requested": name,
                                "models_served": [name],
                                "models_verified": []}}
        return [{"case_id": "a-case", "pair_success": True,
                 "members": {"safe": block, "unsafe": dict(block)}}]

    (tmp_path / "a-case.json").write_text(json.dumps(measured_by("claude-sonnet-5")))
    assert run_queue.already_run("a-case") is False

    # The control. Without it the assertion above passes over a predicate that
    # rejects every row, which would make the queue buy the whole corpus again.
    (tmp_path / "a-case.json").write_text(json.dumps(measured_by("claude-opus-5")))
    assert run_queue.already_run("a-case") is True

    # And a row written before the field existed is still read: the history
    # carries no model name at all, and treating absence as another model
    # throws all of it away.
    (tmp_path / "a-case.json").write_text(
        json.dumps([{"case_id": "a-case", "pair_success": True}]))
    assert run_queue.already_run("a-case") is True

    # **The other path, and it is a different one.** `already_run` answers
    # from the queue's own file first and falls through to a walk of every
    # batch under `measurements/`. Both had to be repaired, and a test that
    # only reaches the first would leave the second open — the shape this
    # repository keeps finding.
    (tmp_path / "a-case.json").unlink()
    batches = tmp_path / "measurements"
    batches.mkdir()
    (batches / "batch.json").write_text(json.dumps(measured_by("claude-sonnet-5")))
    assert run_queue.already_run("a-case") is False
    (batches / "batch.json").write_text(json.dumps(measured_by("claude-opus-5")))
    assert run_queue.already_run("a-case") is True


def test_a_queue_buying_another_model_does_not_re_buy_its_own_row(
        tmp_path, monkeypatch):
    """Codex, 2026-09-09, against the first version of the filter above.

    That version asked for `claude-opus-5` by name. A queue started with
    `SECURITY_SCAN_MODEL=claude-sonnet-5` writes Sonnet rows into
    `QUEUE/<case>.json`; on restart with the same environment, case and corpus
    version, `already_run` answered `False` on its own finished row and the
    case was bought a second time for the same answer, overwriting the first.
    A real double payment, introduced by the line meant to prevent one.
    """
    import json

    import run_queue
    monkeypatch.setattr(run_queue, "QUEUE", tmp_path)
    monkeypatch.setattr(run_queue, "ROOT", tmp_path)
    monkeypatch.setattr(run_queue, "about_this_version",
                        lambda case_id, row: True)
    monkeypatch.setenv("SECURITY_SCAN_MODEL", "claude-sonnet-5")

    def measured_by(name):
        block = {"provenance": {"model_requested": name,
                                "models_served": [name],
                                "models_verified": []}}
        return [{"case_id": "a-case", "pair_success": True,
                 "members": {"safe": block, "unsafe": dict(block)}}]

    # Written where `run_one` would have written it, which for a model that is
    # not the product is a directory of its own.
    own = run_queue.result_path("a-case")
    own.parent.mkdir(parents=True, exist_ok=True)
    own.write_text(json.dumps(measured_by("claude-sonnet-5")))
    assert run_queue.already_run("a-case") is True

    # And the mirror: this queue is not buying Opus, so an Opus row does not
    # answer for it either. Without this the assertion above passes over a
    # predicate that accepts everything, which is the old defect returned.
    own.write_text(json.dumps(measured_by("claude-opus-5")))
    assert run_queue.already_run("a-case") is False

    # **A row written before `members` existed answers for the product and for
    # nothing else.** Codex, 2026-09-09: the legacy rule is a presumption that
    # such a row is Opus's — every one of them was — and that is a fact about
    # the product, not about whatever model the queue is buying. The version
    # that read it for any model let a legacy Opus row satisfy this Sonnet
    # queue, so the case was never measured with Sonnet and nothing would ever
    # ask again. The test above holds the other half: with no variable set the
    # queue is buying the product and the history is read.
    own.write_text(json.dumps([{"case_id": "a-case", "pair_success": True}]))
    assert run_queue.already_run("a-case") is False


def test_alternating_models_do_not_buy_each_other_again(tmp_path, monkeypatch):
    """Codex, 2026-09-09, against the first version of the model filter.

    `already_run` correctly refused a row from another model, but `run_one`
    wrote every result to the same `QUEUE/<case>.json`. So Sonnet, then Opus
    over the top of it, then Sonnet again — the Sonnet row no longer existed,
    and each switch bought its model a second time, indefinitely. The filter
    that stopped one duplicate purchase created another.

    Nothing is bought here: the two runs are simulated by writing to the path
    `run_one` would have written to.
    """
    import json

    import run_queue
    monkeypatch.setattr(run_queue, "QUEUE", tmp_path)
    monkeypatch.setattr(run_queue, "ROOT", tmp_path)
    monkeypatch.setattr(run_queue, "about_this_version",
                        lambda case_id, row: True)

    def measured_by(name):
        block = {"provenance": {"model_requested": name,
                                "models_served": [name],
                                "models_verified": []}}
        return [{"case_id": "a-case", "pair_success": True,
                 "members": {"safe": block, "unsafe": dict(block)}}]

    for name in ("claude-sonnet-5", "claude-opus-5"):
        monkeypatch.setenv("SECURITY_SCAN_MODEL", name)
        path = run_queue.result_path("a-case")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(measured_by(name)))

    # Back to the first model. Its result still exists, so nothing is bought.
    monkeypatch.setenv("SECURITY_SCAN_MODEL", "claude-sonnet-5")
    assert run_queue.already_run("a-case") is True
    monkeypatch.setenv("SECURITY_SCAN_MODEL", "claude-opus-5")
    assert run_queue.already_run("a-case") is True

    # And the product keeps the bare name, because every file already on disk
    # carries it and every reader globs `queue/*.json`. Renaming them would
    # rewrite the record to fix a path.
    assert run_queue.result_path("a-case").name == "a-case.json"
    assert run_queue.result_path("a-case").parent == tmp_path
    monkeypatch.setenv("SECURITY_SCAN_MODEL", "claude-sonnet-5")
    # A directory, not a suffix: `<case>.<model>.json` cannot tell a product
    # run of a case called `a-case.claude-sonnet-5` from a Sonnet run of
    # `a-case`, and one would overwrite the other.
    assert run_queue.result_path("a-case").name == "a-case.json"
    assert run_queue.result_path("a-case").parent.name == "claude-sonnet-5"

    # A third model has never been measured, so it is still bought.
    monkeypatch.setenv("SECURITY_SCAN_MODEL", "claude-haiku-4-5")
    assert run_queue.already_run("a-case") is False


def test_a_case_whose_name_looks_like_a_model_suffix_does_not_collide(
        tmp_path, monkeypatch):
    """Codex, 2026-09-09, against the first version of the qualified naming.

    `<case>.<model>.json` does not uniquely encode the pair. A product run of
    a case literally called `a-case.claude-sonnet-5` and a Sonnet run of
    `a-case` both landed on `a-case.claude-sonnet-5.json`, so one overwrote
    the other; on restart `already_run` read the file, rejected the `case_id`
    inside it, and bought the case again — the defect the qualified name was
    introduced to prevent, back through an ambiguity in the name. Case ids are
    directory names and nothing forbids a dot in one.
    """
    import json

    import run_queue
    monkeypatch.setattr(run_queue, "QUEUE", tmp_path)
    monkeypatch.setattr(run_queue, "ROOT", tmp_path)
    monkeypatch.setattr(run_queue, "about_this_version",
                        lambda case_id, row: True)

    def measured_by(name, case_id):
        block = {"provenance": {"model_requested": name,
                                "models_served": [name],
                                "models_verified": []}}
        return [{"case_id": case_id, "pair_success": True,
                 "members": {"safe": block, "unsafe": dict(block)}}]

    # The product measuring a case whose id ends in a model name.
    monkeypatch.delenv("SECURITY_SCAN_MODEL", raising=False)
    awkward = "a-case.claude-sonnet-5"
    product = run_queue.result_path(awkward)
    product.parent.mkdir(parents=True, exist_ok=True)
    product.write_text(json.dumps(measured_by("claude-opus-5", awkward)))

    # Sonnet measuring the ordinary case. Two different files.
    monkeypatch.setenv("SECURITY_SCAN_MODEL", "claude-sonnet-5")
    other = run_queue.result_path("a-case")
    other.parent.mkdir(parents=True, exist_ok=True)
    other.write_text(json.dumps(measured_by("claude-sonnet-5", "a-case")))

    assert product != other
    assert run_queue.already_run("a-case") is True
    monkeypatch.delenv("SECURITY_SCAN_MODEL")
    assert run_queue.already_run(awkward) is True


def test_a_model_name_that_is_a_path_is_refused(tmp_path, monkeypatch):
    """The name goes into a file name, so a separator in it would write
    outside the queue. Refused rather than sanitised: a sanitised name is a
    different name, and it would then look like a different model."""
    import pytest as _pytest

    import run_queue
    monkeypatch.setattr(run_queue, "QUEUE", tmp_path)

    for bad in ("../escape", "a/b", ".hidden", "..", "."):
        monkeypatch.setenv("SECURITY_SCAN_MODEL", bad)
        with _pytest.raises(SystemExit):
            run_queue.result_path("a-case")

    # **And a name that collides with the queue's own files does not need
    # refusing, because it cannot reach them.** Codex, 2026-09-09: with the
    # model directory placed straight in the queue, `SECURITY_SCAN_MODEL`
    # values like `log.jsonl` or `manifest.json` — or the name of an existing
    # result — made `mkdir` run beneath a file and the run died before it
    # started. The reserved `by-model` segment puts every model somewhere
    # nothing else is ever written.
    for awkward in ("log.jsonl", "manifest.json", "a-case.json"):
        monkeypatch.setenv("SECURITY_SCAN_MODEL", awkward)
        path = run_queue.result_path("a-case")
        assert path.parent.parent.name == "by-model"
        # It can be created: no file of the queue's stands in the way.
        path.parent.mkdir(parents=True, exist_ok=True)


def test_the_variable_is_read_the_way_the_product_reads_it(monkeypatch):
    """Two spellings of one rule drift, and this is the second spelling.

    `Config` resolves the reviewing model from `SECURITY_SCAN_MODEL` with
    `claude-opus-5` as the default; `stop_rule.queue_model` has to give the
    same answer, or the queue skips a case the run would have measured with a
    different model. Asserted against `Config` itself rather than against a
    copy of its rule.
    """
    import sys
    from pathlib import Path

    src = Path(__file__).resolve().parents[1] / "src"
    if str(src) not in sys.path:
        sys.path.insert(0, str(src))
    from security_agent.config import Config

    import stop_rule

    # The empty and whitespace values are the ones that caught a real
    # disagreement: `_env` reads them as absent and buys Opus, while the first
    # version of `queue_model` returned the empty string and would have made
    # the queue re-buy every case it had already measured.
    for value in (None, "", "   ", " claude-sonnet-5 ", "claude-sonnet-5",
                  "claude-opus-5"):
        if value is None:
            monkeypatch.delenv("SECURITY_SCAN_MODEL", raising=False)
        else:
            monkeypatch.setenv("SECURITY_SCAN_MODEL", value)
        assert stop_rule.queue_model() == Config.from_env().model, value


def test_a_frozen_round_refuses_a_different_model_before_spending(
        tmp_path, monkeypatch, capsys):
    """Codex, 2026-09-09. The model was the one frozen condition that was
    neither written down nor enforced.

    A round frozen for the product ran happily under
    `SECURITY_SCAN_MODEL=claude-sonnet-5`, wrote its rows into the round's own
    directory, and `round.compare` then reported Sonnet against Opus as the
    product moving on its own — the number every gate threshold sits above.

    The refusal has to come *before* anything is bought, which is what this
    test is really about: `run_one` is replaced by something that fails the
    test if it is ever reached.
    """
    import json
    import sys as _sys

    import pytest as _pytest

    import run_queue
    monkeypatch.setattr(run_queue, "ROOT", tmp_path)
    monkeypatch.setattr(run_queue, "run_one", _never_spend)
    home = tmp_path / "measurements" / "round-9"
    home.mkdir(parents=True)
    (home / "manifest.json").write_text(json.dumps({
        "protocol": {"order": ["a-case"], "provider": "claude-cli",
                     "profile": "normal", "model": "claude-opus-5"},
    }), encoding="utf-8")

    monkeypatch.setenv("SECURITY_SCAN_MODEL", "claude-sonnet-5")
    monkeypatch.setattr(_sys, "argv", ["run_queue.py", "--round", "9"])
    with _pytest.raises(SystemExit) as raised:
        run_queue.main()

    assert "froze model" in str(raised.value)
    assert "claude-sonnet-5" in str(raised.value)


def test_a_queue_file_written_before_the_naming_changed_is_still_found(
        tmp_path, monkeypatch):
    """Codex, 2026-09-09. The migration the naming repair created.

    `result_path` gives a non-product run a model-qualified name. A Sonnet
    result written by an earlier version sits under the old universal
    `<case>.json`, and the reader that looked only at the path *this*
    invocation would write missed it — buying the case again over a valid,
    current-digest row sitting right there.

    Which model a row belongs to is decided by reading it. A file name is a
    place to look, not an answer, so the search is by content.
    """
    import json

    import run_queue
    monkeypatch.setattr(run_queue, "QUEUE", tmp_path)
    monkeypatch.setattr(run_queue, "ROOT", tmp_path)
    monkeypatch.setattr(run_queue, "about_this_version",
                        lambda case_id, row: True)
    monkeypatch.setenv("SECURITY_SCAN_MODEL", "claude-sonnet-5")

    block = {"provenance": {"model_requested": "claude-sonnet-5",
                            "models_served": ["claude-sonnet-5"],
                            "models_verified": []}}
    (tmp_path / "a-case.json").write_text(json.dumps(
        [{"case_id": "a-case", "pair_success": True,
          "members": {"safe": block, "unsafe": dict(block)}}]))

    assert run_queue.result_path("a-case") == (
        tmp_path / "by-model" / "claude-sonnet-5" / "a-case.json")
    assert run_queue.already_run("a-case") is True

    # **And the layout that existed in between.** Codex, 2026-09-09: the
    # search was still keyed on the file name while the comment beside it
    # claimed it read the row. Any layout the queue has ever written is found,
    # because `case_id` is in the row and the name is only a place to look.
    (tmp_path / "a-case.json").unlink()
    (tmp_path / "a-case.claude-sonnet-5.json").write_text(json.dumps(
        [{"case_id": "a-case", "pair_success": True,
          "members": {"safe": block, "unsafe": dict(block)}}]))
    assert run_queue.already_run("a-case") is True

    # And a file whose *name* says one case while its row says another is
    # read by the row. The name has no vote.
    (tmp_path / "a-case.claude-sonnet-5.json").unlink()
    (tmp_path / "somebody-else.json").write_text(json.dumps(
        [{"case_id": "a-case", "pair_success": True,
          "members": {"safe": block, "unsafe": dict(block)}}]))
    assert run_queue.already_run("a-case") is True

    # And the control that keeps it honest: an Opus row still does not answer
    # for a Sonnet queue. Finding the file is a different question from whose
    # measurement it holds — which is the whole reason the name has no vote.
    (tmp_path / "somebody-else.json").unlink()
    opus = {"provenance": {"model_requested": "claude-opus-5",
                           "models_served": ["claude-opus-5"],
                           "models_verified": []}}
    (tmp_path / "a-case.json").write_text(json.dumps(
        [{"case_id": "a-case", "pair_success": True,
          "members": {"safe": opus, "unsafe": dict(opus)}}]))
    assert run_queue.already_run("a-case") is False

    # **And a queue file that answers for nobody must not stop the search.**
    # Codex, 2026-09-09: the first version returned `False` as soon as a file
    # for the case existed, so this Opus queue row hid a valid current Sonnet
    # row in a batch and Sonnet was bought a second time. The question is
    # whether this model's measurement exists *anywhere*, and a queue file
    # that answers for another model says nothing about it.
    batches = tmp_path / "measurements"
    batches.mkdir()
    (batches / "batch.json").write_text(json.dumps(
        [{"case_id": "a-case", "pair_success": True,
          "members": {"safe": block, "unsafe": dict(block)}}]))
    assert run_queue.already_run("a-case") is True


def test_a_manifest_whose_two_lists_disagree_is_refused(tmp_path, monkeypatch):
    """Codex, 2026-09-09. `protocol.order` decides what is bought; `cases`
    carries the digests and is what `compare` reads.

    Nothing checked that they name the same set, so a case in `order` and not
    in `cases` was bought with no digest check and then ignored by the
    comparison — money spent on a row nothing looks at, while the case the
    comparison does look at is reported as never run. A repeated id in `order`
    bought the same case twice, because `queued` is computed once.
    """
    import json
    import sys as _sys

    import pytest as _pytest

    import run_queue
    monkeypatch.setattr(run_queue, "ROOT", tmp_path)
    monkeypatch.setattr(run_queue, "run_one", _never_spend)
    home = tmp_path / "measurements" / "round-9"
    home.mkdir(parents=True)

    def freeze(order, cases):
        (home / "manifest.json").write_text(json.dumps({
            "protocol": {"order": order, "provider": "claude-cli",
                         "profile": "normal", "model": "claude-opus-5"},
            "cases": [{"case_id": c} for c in cases],
        }), encoding="utf-8")

    monkeypatch.setattr(_sys, "argv", ["run_queue.py", "--round", "9"])

    freeze(["case-b"], ["case-a"])
    with _pytest.raises(SystemExit) as raised:
        run_queue.main()
    assert "order and case list disagree" in str(raised.value)

    # The same id twice: `queued` is computed once, so the case is bought
    # twice in one pass.
    freeze(["case-a", "case-a"], ["case-a"])
    with _pytest.raises(SystemExit) as raised:
        run_queue.main()
    assert "order and case list disagree" in str(raised.value)

    # **And the duplicate with the case list agreeing**, which is the only
    # input the second clause of the guard decides. Both assertions above are
    # settled by the first clause — the sets differ — so deleting
    # `len(set(order)) != len(order)` would leave them green, and that clause
    # is the one guarding the real path: `round.build` derives `order` and
    # `cases` from one list, so a manifest `freeze` writes can only ever fail
    # the duplicate test. A suite file naming a case twice produces exactly
    # this shape, and without the clause the case is bought twice.
    freeze(["case-a", "case-a"], ["case-a", "case-a"])
    with _pytest.raises(SystemExit) as raised:
        run_queue.main()
    assert "order and case list disagree" in str(raised.value)

    # The control. A manifest whose two lists are one list gets past the
    # refusal and stops at the first thing that would spend — which is what
    # `freeze` writes, since it builds both from one list.
    (tmp_path / "corpus-real" / "case-a").mkdir(parents=True)
    freeze(["case-a"], ["case-a"])
    with _pytest.raises(AssertionError) as raised:
        run_queue.main()
    assert "the refusal must come before any purchase" in str(raised.value)


def _frozen_round(tmp_path, monkeypatch, case_digest_now, frozen_digest):
    """A frozen round of one case, with the case on disk under our control.

    `case_digest` is replaced rather than a real corpus built: the refusal
    under test is about the two values differing, and building two genuine
    member trees would test `artifact.case_digest` instead.
    """
    import json
    import sys as _sys

    import run_queue
    monkeypatch.setattr(run_queue, "ROOT", tmp_path)
    monkeypatch.setattr(run_queue, "run_one", _never_spend)
    monkeypatch.setattr(run_queue, "case_digest", lambda d: case_digest_now)
    monkeypatch.setattr(run_queue, "legacy_case_digest", lambda d: "legacy")
    (tmp_path / "corpus-real" / "a-case").mkdir(parents=True)
    home = tmp_path / "measurements" / "round-9"
    home.mkdir(parents=True)
    body = {
        "protocol": {"order": ["a-case"], "provider": "claude-cli",
                     "profile": "normal", "model": "claude-opus-5"},
        "cases": [{"case_id": "a-case"}],
    }
    if frozen_digest is not None:
        body["cases"][0]["case_digest"] = frozen_digest
    (home / "manifest.json").write_text(json.dumps(body), encoding="utf-8")
    monkeypatch.setattr(_sys, "argv", ["run_queue.py", "--round", "9"])
    return run_queue


def test_a_frozen_round_refuses_an_edited_case_before_spending(
        tmp_path, monkeypatch):
    """Codex, 2026-09-09, and it follows directly from the repair before it.

    `round.compare` now refuses a row about a different version of its case —
    correctly — but nothing stopped the queue buying it first. The case was
    purchased, its row recorded the new digest, and `compare` then reported it
    as "not yet run" and could exit 2 having measured nothing. The money was
    spent on a row thrown away at the other end.
    """
    import pytest as _pytest

    run_queue = _frozen_round(tmp_path, monkeypatch,
                              case_digest_now="e" * 16, frozen_digest="d" * 16)

    with _pytest.raises(SystemExit) as raised:
        run_queue.main()

    assert "cases that have changed since" in str(raised.value)
    assert "a-case" in str(raised.value)


def test_a_frozen_round_refuses_an_edited_answer_key_before_spending(
        tmp_path, monkeypatch):
    """The other end of the same defect. Codex, 2026-09-09.

    The members are untouched, so `case_digest` matches and the case was
    bought — then scored against the new key, and the flip read as
    instability. The money is spent before anything can notice.
    """
    import json
    import sys as _sys

    import pytest as _pytest

    import run_queue
    monkeypatch.setattr(run_queue, "ROOT", tmp_path)
    monkeypatch.setattr(run_queue, "run_one", _never_spend)
    monkeypatch.setattr(run_queue, "case_digest", lambda d: "d" * 16)
    monkeypatch.setattr(run_queue, "legacy_case_digest", lambda d: "legacy")
    (tmp_path / "corpus-real" / "a-case").mkdir(parents=True)
    home = tmp_path / "measurements" / "round-9"
    home.mkdir(parents=True)
    (home / "manifest.json").write_text(json.dumps({
        "protocol": {"order": ["a-case"], "provider": "claude-cli",
                     "profile": "normal", "model": "claude-opus-5"},
        # **No `case_digest`**, which is what the first version returned
        # early on — so the key was never checked, `compare` refused the round
        # afterwards, and the pairs had already been bought.
        "cases": [{"case_id": "a-case",
                   "answer_key_digest": "frozen-under-the-old-key"}],
    }), encoding="utf-8")
    monkeypatch.setattr(_sys, "argv", ["run_queue.py", "--round", "9"])

    with _pytest.raises(SystemExit) as raised:
        run_queue.main()

    assert "answer key changed since the freeze" in str(raised.value)


def test_a_frozen_round_whose_cases_are_unchanged_is_not_refused(
        tmp_path, monkeypatch):
    """The control. Without it the test above passes over a check that refuses
    every round, which would stop the queue buying anything at all.

    `run_one` still fails the test if reached — the run gets past the refusal
    and stops at the first thing that would spend.
    """
    import pytest as _pytest

    run_queue = _frozen_round(tmp_path, monkeypatch,
                              case_digest_now="d" * 16, frozen_digest="d" * 16)

    with _pytest.raises(AssertionError) as raised:
        run_queue.main()

    assert "the refusal must come before any purchase" in str(raised.value)


def test_a_round_frozen_without_digests_is_not_refused(tmp_path, monkeypatch):
    """A manifest from before `freeze` stored them records none. Refusing it
    would make every old round unbuyable, and `round.compare` applies the same
    rule at the other end so the two agree about which rounds are checkable."""
    import pytest as _pytest

    run_queue = _frozen_round(tmp_path, monkeypatch,
                              case_digest_now="e" * 16, frozen_digest=None)

    with _pytest.raises(AssertionError) as raised:
        run_queue.main()

    assert "the refusal must come before any purchase" in str(raised.value)


def test_a_frozen_round_naming_another_model_is_refused(tmp_path, monkeypatch):
    """The same in the queue, and here it is money. A manifest naming Sonnet
    matched a Sonnet environment and the round was bought — against baselines
    that are the product's own verdicts."""
    import json
    import sys as _sys

    import pytest as _pytest

    import run_queue
    monkeypatch.setattr(run_queue, "ROOT", tmp_path)
    monkeypatch.setattr(run_queue, "run_one", _never_spend)
    home = tmp_path / "measurements" / "round-9"
    home.mkdir(parents=True)
    (home / "manifest.json").write_text(json.dumps({
        "protocol": {"order": ["a-case"], "provider": "claude-cli",
                     "profile": "normal", "model": "claude-sonnet-5"},
        "cases": [{"case_id": "a-case"}],
    }), encoding="utf-8")

    # The environment agrees with the manifest, which is exactly what made the
    # old check pass it through.
    monkeypatch.setenv("SECURITY_SCAN_MODEL", "claude-sonnet-5")
    monkeypatch.setattr(_sys, "argv", ["run_queue.py", "--round", "9"])
    with _pytest.raises(SystemExit) as raised:
        run_queue.main()

    assert "naming model 'claude-sonnet-5'" in str(raised.value)


def test_a_stale_artifact_is_not_read_as_this_run_s_result(tmp_path,
                                                          monkeypatch):
    """Codex, 2026-09-09, and it predates the model work entirely.

    `already_run` reschedules a case whose code changed after its last queue
    result, and the old artifact stays on disk. If `pair_corpus` then dies
    before writing, `target.is_file()` is still true — so the previous run's
    row was read, classified, and the failed attempt counted as a completed
    measurement. "Did not check" read as "checked", the founding error of this
    project, inside the queue built to avoid it.

    Nothing is bought: `subprocess.run` is replaced by a call that writes
    nothing, which is exactly what a crashed `pair_corpus` leaves behind.
    """
    import json
    import subprocess as _subprocess

    import run_queue
    monkeypatch.setattr(run_queue, "QUEUE", tmp_path)
    monkeypatch.setattr(run_queue, "ROOT", tmp_path)
    monkeypatch.delenv("SECURITY_SCAN_MODEL", raising=False)

    stale = run_queue.result_path("a-case")
    stale.parent.mkdir(parents=True, exist_ok=True)
    stale.write_text(json.dumps(
        [{"case_id": "a-case", "pair_success": True,
          "members": {"safe": {"stop_reason": "completed"},
                      "unsafe": {"stop_reason": "completed"}}}]))

    monkeypatch.setattr(
        run_queue.subprocess, "run",
        lambda *a, **k: _subprocess.CompletedProcess(a[0] if a else [], 1))

    class Args:
        provider = "claude-cli"
        profile = "normal"

    payload, kind, detail = run_queue.run_one("a-case", Args())

    assert kind == "no-artifact", (kind, detail)
    assert payload is None
    # And the paid row is still there. Proving a later run is fresh must not
    # throw away the measurement that answered a different question.
    assert stale.is_file()


def test_two_queues_on_one_case_do_not_share_an_attempt_file(tmp_path,
                                                             monkeypatch):
    """Codex, 2026-09-09. A deterministic `<case>.json.attempt` is shared.

    One queue completes a valid result there; the other replaces it with a
    refusal before the first reads it. The first reads the refusal and deletes
    it, the second finds nothing, and a paid measurement is gone with the case
    still queued. The reverse order promotes one invocation's result and tells
    the other that it succeeded.

    Nothing is bought: the two runs are simulated by capturing the path each
    is given.
    """
    import subprocess as _subprocess

    import run_queue
    monkeypatch.setattr(run_queue, "QUEUE", tmp_path)
    monkeypatch.setattr(run_queue, "ROOT", tmp_path)
    monkeypatch.delenv("SECURITY_SCAN_MODEL", raising=False)

    given = []

    def capture(*a, **k):
        command = a[0]
        given.append(command[command.index("--json") + 1])
        _write(command, [{"case_id": "a-case", "pair_success": True,
                          "members": {"safe": {"stop_reason": "completed"},
                                      "unsafe": {"stop_reason": "completed"}}}])
        return _subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(run_queue.subprocess, "run", capture)

    class Args:
        provider = "claude-cli"
        profile = "normal"

    run_queue.run_one("a-case", Args())
    run_queue.run_one("a-case", Args())

    assert len(given) == 2
    assert given[0] != given[1], "two runs were handed one path"
    # And neither is the target, which is what the promotion writes over.
    assert str(run_queue.result_path("a-case")) not in given


def test_the_promoted_artifact_is_readable(tmp_path, monkeypatch):
    """Codex, 2026-09-09. Two repairs, each right alone, composing wrongly.

    `mkstemp` creates the attempt at `0600`; `pair_corpus.write_results`
    preserves the mode of the file it replaces — which is that attempt, not
    the target — and the promotion then carried `0600` onto the result. A
    later job running as another account cannot read it, `already_run` reads
    the `OSError` as "no measurement", and the case is bought again.

    The two halves were each covered and their composition was not, which is
    why this drives `run_one` and looks at the file it leaves behind.
    """
    import os
    import stat as _stat
    import subprocess as _subprocess

    import pair_corpus
    import run_queue
    monkeypatch.setattr(run_queue, "QUEUE", tmp_path)
    monkeypatch.setattr(run_queue, "ROOT", tmp_path)
    monkeypatch.delenv("SECURITY_SCAN_MODEL", raising=False)

    rows = [{"case_id": "a-case", "pair_success": True,
             "members": {"safe": {"stop_reason": "completed"},
                         "unsafe": {"stop_reason": "completed"}}}]

    def child(*a, **k):
        # What `pair_corpus` really does with `--json`, including the mode
        # rule, so the composition under test is the production one.
        command = a[0]
        pair_corpus.write_results(
            Path(command[command.index("--json") + 1]), rows)
        return _subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(run_queue.subprocess, "run", child)

    class Args:
        provider = "claude-cli"
        profile = "normal"

    run_queue.run_one("a-case", Args())

    target = run_queue.result_path("a-case")
    current = os.umask(0)
    os.umask(current)
    assert _stat.S_IMODE(target.stat().st_mode) == 0o666 & ~current

    # And a mode set on the target by hand survives the next run, rather than
    # the attempt's mode overwriting it.
    os.chmod(target, 0o640)
    run_queue.run_one("a-case", Args())
    assert _stat.S_IMODE(target.stat().st_mode) == 0o640


def test_a_second_queue_does_not_buy_a_case_the_first_holds(tmp_path,
                                                           monkeypatch):
    """Codex, 2026-09-09. Unique attempt paths stopped two queues corrupting
    each other's files and did nothing about the purchase.

    Both evaluate `already_run`, both see no result, both buy the same pair,
    and the later promotion silently discards the earlier paid one: four
    reviews bought for two, and one of them thrown away.
    """
    import subprocess as _subprocess

    import run_queue
    monkeypatch.setattr(run_queue, "QUEUE", tmp_path)
    monkeypatch.setattr(run_queue, "ROOT", tmp_path)
    monkeypatch.setattr(run_queue, "about_this_version",
                        lambda case_id, row: True)
    monkeypatch.delenv("SECURITY_SCAN_MODEL", raising=False)

    # With provenance, because `already_run` asks which model produced the
    # row — a member without one is refused, and the fixture would then be
    # testing a shape production never writes.
    block = {"stop_reason": "completed",
             "provenance": {"model_requested": "claude-opus-5",
                            "models_served": ["claude-opus-5"],
                            "models_verified": []}}
    rows = [{"case_id": "a-case", "pair_success": True,
             "members": {"safe": block, "unsafe": dict(block)}}]
    bought = []

    def child(*a, **k):
        command = a[0]
        bought.append(command)
        _write(command, rows)
        return _subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(run_queue.subprocess, "run", child)

    class Args:
        provider = "claude-cli"
        profile = "normal"

    # The first queue takes the claim and does not release it — which is what
    # a run still in flight looks like from outside.
    target = run_queue.result_path("a-case")
    target.parent.mkdir(parents=True, exist_ok=True)
    held = run_queue._take_claim(target)
    assert held is not None

    _payload, kind, detail = run_queue.run_one("a-case", Args())

    assert kind == "held", (kind, detail)
    assert bought == [], "the second queue bought a case the first holds"

    # And once the first finishes, the second finds the result rather than
    # buying beside it — the claim serialises them and the re-check under it
    # is what stops the second purchase.
    _write(["--json", str(target)], rows)
    run_queue._release_claim(held)
    _payload, kind, _detail = run_queue.run_one("a-case", Args())
    assert kind == "already", kind
    assert bought == []

    # The control: with no claim and no result, it does buy.
    target.unlink()
    _payload, kind, _detail = run_queue.run_one("a-case", Args())
    assert kind == "ok", kind
    assert len(bought) == 1


def test_a_held_case_is_deferred_and_the_run_says_so(tmp_path, monkeypatch,
                                                    capsys):
    """Two rounds of Codex, on the same branch, in opposite directions.

    First: `continue` without popping retried the same case for ever — a tight
    loop against a live claim, and then a tight loop on "already".

    Then: popping it dropped the case, so this queue reported completion over
    work nobody measured. Neither. A held case goes to the back, and a whole
    lap of held cases ends the run with an exit code and the names.

    The loop is bounded here by a `run_one` that counts its calls and fails
    the test rather than by a timeout, so a regression is a message and not a
    hung suite.
    """
    import sys as _sys

    import run_queue
    monkeypatch.setattr(run_queue, "ROOT", tmp_path)
    queue = tmp_path / "measurements" / "queue"
    monkeypatch.setattr(run_queue, "QUEUE", queue)
    # A module constant pointing into the real tree, which the summary at the
    # end of the run reports relative to `ROOT`.
    monkeypatch.setattr(run_queue, "LOG", queue / "log.jsonl")
    monkeypatch.setattr(run_queue, "malformed", set)
    monkeypatch.setattr(run_queue, "already_run", lambda *a, **k: False)
    monkeypatch.setattr(run_queue, "note", lambda *a, **k: None)
    monkeypatch.setattr(run_queue, "close_window", lambda *a, **k: None)
    monkeypatch.delenv("SECURITY_SCAN_MODEL", raising=False)

    calls = []

    def held(case_id, args):
        calls.append(case_id)
        assert len(calls) <= 6, "the queue is spinning on {}".format(case_id)
        return None, "held", "another queue holds it"

    monkeypatch.setattr(run_queue, "run_one", held)
    monkeypatch.setattr(_sys, "argv",
                        ["run_queue.py", "--case", "a-case", "--case", "b-case"])

    code = run_queue.main()

    # **Deferred, not dropped, and the exit says so.** Codex, 2026-09-09: the
    # first version of this test asserted the cases were popped, which is the
    # queue reporting completion over work nobody measured — the lock owner
    # may crash, be refused, or write nothing. "Did not check" reported as
    # "checked", encoded in a test.
    #
    # Each case is tried, moved to the back, and once a whole lap comes back
    # held the run stops and names them.
    assert calls[:2] == ["a-case", "b-case"]
    assert code == 5, code
    assert "held by another queue" in capsys.readouterr().out


def test_a_round_rechecks_with_its_own_semantics(tmp_path, monkeypatch):
    """Codex, 2026-09-09. The guard added to protect the round disabled it.

    A frozen round queues a case *because* `repeat=True` ignores the
    production baseline. The re-check under the claim asked with `False`, so
    it found that baseline and answered "already" — and the round could not
    re-measure precisely the cases its stability denominator is made of.
    """
    import run_queue
    monkeypatch.setattr(run_queue, "QUEUE", tmp_path)
    monkeypatch.setattr(run_queue, "ROOT", tmp_path)
    monkeypatch.delenv("SECURITY_SCAN_MODEL", raising=False)

    asked = []
    monkeypatch.setattr(run_queue, "already_run",
                        lambda case_id, repeat=False: asked.append(repeat) or False)
    monkeypatch.setattr(run_queue, "subprocess", run_queue.subprocess)

    def child(*a, **k):
        import subprocess as _subprocess
        _write(a[0], [{"case_id": "a-case", "pair_success": True,
                       "members": {"safe": {"stop_reason": "completed"},
                                   "unsafe": {"stop_reason": "completed"}}}])
        return _subprocess.CompletedProcess(a[0], 0)

    monkeypatch.setattr(run_queue.subprocess, "run", child)

    class Round:
        provider = "claude-cli"
        profile = "normal"
        round = 2

    run_queue.run_one("a-case", Round())
    assert asked == [True], asked

    # And an ordinary run still asks the ordinary question.
    asked.clear()

    class Plain:
        provider = "claude-cli"
        profile = "normal"

    run_queue.run_one("a-case", Plain())
    assert asked == [False], asked


def test_a_dead_queue_does_not_hold_a_case(tmp_path, monkeypatch):
    """The claim is a lock on an open descriptor, not a file whose presence
    means something.

    The first version was a file with an age at which it could be taken over,
    and that age is a guess about a live process: a queue past the ceiling had
    its claim removed by a second, then finished and unlinked the second's
    claim on its way out, and a third took the case while the second was still
    running — the double purchase the claim exists to prevent, put back by the
    takeover. Codex, 2026-09-09.

    The kernel releases the lock when the process ends, so a claim left by a
    machine that lost power holds nothing.
    """
    import os

    import run_queue
    monkeypatch.setattr(run_queue, "QUEUE", tmp_path)
    monkeypatch.setattr(run_queue, "ROOT", tmp_path)

    target = tmp_path / "a-case.json"

    # Held: a second attempt from this process is refused, because the lock is
    # exclusive per descriptor.
    first = run_queue._take_claim(target)
    assert first is not None
    assert run_queue._take_claim(target) is None

    # Released: available again, and the file itself is still there — it is a
    # lock, not a record, and unlinking it is what created the defect above.
    run_queue._release_claim(first)
    assert run_queue._claim_path(target).is_file()
    second = run_queue._take_claim(target)
    assert second is not None
    run_queue._release_claim(second)

    # A stale file from a process that is gone holds nothing at all.
    run_queue._claim_path(target).write_text('{"pid": 1, "at": "old"}')
    third = run_queue._take_claim(target)
    assert third is not None
    run_queue._release_claim(third)
    del os


def test_a_refused_retry_does_not_destroy_the_earlier_measurement(
        tmp_path, monkeypatch):
    """Codex, 2026-09-09, against the version that wrote straight to the
    target.

    A refused pair has measured nothing, so its file is deleted — otherwise
    `already_run` would skip the case for ever. But once the child wrote to
    the target, the file that branch deleted was no longer this run's: a case
    whose code changed is rescheduled, the retry is refused, and the *earlier
    paid* measurement is what gets unlinked.
    """
    import json
    import subprocess as _subprocess

    import run_queue
    monkeypatch.setattr(run_queue, "QUEUE", tmp_path)
    monkeypatch.setattr(run_queue, "ROOT", tmp_path)
    monkeypatch.delenv("SECURITY_SCAN_MODEL", raising=False)

    target = run_queue.result_path("a-case")
    target.parent.mkdir(parents=True, exist_ok=True)
    paid = [{"case_id": "a-case", "pair_success": True,
             "members": {"safe": {"stop_reason": "completed"},
                         "unsafe": {"stop_reason": "completed"}}}]
    target.write_text(json.dumps(paid))

    refusal = [{"case_id": "a-case",
                "members": {"safe": {"stop_reason": "completed"},
                            "unsafe": {"stop_reason": "error",
                                       "stop_detail": LIMIT_MESSAGE}}}]

    def refused(*a, **k):
        # The attempt path is unique per invocation, so it is read from the
        # command rather than guessed — which is also the only way a fixture
        # can be sure it is writing where the run is looking.
        command = a[0]
        _write(command, refusal)
        return _subprocess.CompletedProcess(command, 1)

    monkeypatch.setattr(run_queue.subprocess, "run", refused)

    class Args:
        provider = "claude-cli"
        profile = "normal"

    _payload, kind, _detail = run_queue.run_one("a-case", Args())

    assert kind == "refused"
    # The earlier measurement is untouched, and no attempt file is left for
    # the next run to read as its own.
    assert json.loads(target.read_text(encoding="utf-8")) == paid
    assert not list(target.parent.glob(target.name + ".*.attempt"))


def test_an_artifact_this_run_wrote_is_read(tmp_path, monkeypatch):
    """The control. Without it the test above passes over a `run_one` that
    calls every run artefactless, and the queue would never record
    anything."""
    import json
    import subprocess as _subprocess

    import run_queue
    monkeypatch.setattr(run_queue, "QUEUE", tmp_path)
    monkeypatch.setattr(run_queue, "ROOT", tmp_path)
    monkeypatch.delenv("SECURITY_SCAN_MODEL", raising=False)

    target = run_queue.result_path("a-case")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("[]")

    fresh = [{"case_id": "a-case", "pair_success": True,
              "members": {"safe": {"stop_reason": "completed"},
                          "unsafe": {"stop_reason": "completed"}}}]

    def writes(*a, **k):
        # Where `pair_corpus` is pointed: a unique path beside the target,
        # never the target itself.
        command = a[0]
        _write(command, fresh)
        return _subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(run_queue.subprocess, "run", writes)

    class Args:
        provider = "claude-cli"
        profile = "normal"

    payload, kind, _detail = run_queue.run_one("a-case", Args())

    assert kind == "ok", kind
    assert payload == fresh


def test_the_same_case_named_twice_is_bought_once(tmp_path, monkeypatch,
                                                 capsys):
    """Codex, 2026-09-09. `--case` is `action="append"`.

    Naming one case twice put it in the eligible list twice, and `queued` is
    computed once, before anything runs. The first run wrote a valid result
    and the second entry was still in the list, so `already_run` was never
    asked again: the identical pair was bought a second time and the first
    artifact overwritten. The frozen-round manifest gained a duplicate check
    two rounds earlier; this path, the ordinary one, did not.
    """
    import sys as _sys

    import run_queue
    monkeypatch.setattr(run_queue, "ROOT", tmp_path)
    queue = tmp_path / "measurements" / "queue"
    monkeypatch.setattr(run_queue, "QUEUE", queue)
    # A module constant pointing into the real tree, which the closing summary
    # reports relative to `ROOT`. The first version never reached that line.
    monkeypatch.setattr(run_queue, "LOG", queue / "log.jsonl")
    monkeypatch.setattr(run_queue, "malformed", set)
    monkeypatch.delenv("SECURITY_SCAN_MODEL", raising=False)

    bought = []

    def once(case_id, args):
        bought.append(case_id)
        return [{"case_id": case_id, "pair_success": True}], "ok", None

    monkeypatch.setattr(run_queue, "run_one", once)
    monkeypatch.setattr(run_queue, "note", lambda *a, **k: None)
    monkeypatch.setattr(run_queue, "close_window", lambda *a, **k: None)
    # **Not `--dry-run`.** The first version passed it, so `main` returned
    # before any purchase and the `once` stub was dead code — the test pinned
    # the printed counting line and nothing about buying, under a name that
    # claims the opposite. `run_one` is stubbed instead, so the run goes all
    # the way through and what it bought is observable.
    monkeypatch.setattr(_sys, "argv",
                        ["run_queue.py", "--case", "a-case", "--case", "a-case"])

    run_queue.main()
    out = capsys.readouterr().out

    # One purchase, not two. This is the assertion the test's name makes.
    assert bought == ["a-case"], bought

    # The whole line, not the first number. The count of "already recorded"
    # was taken from the list *before* deduplication, so the removed
    # duplicate was reported as a case that already had a measurement — a
    # claim about a run that never happened, from the tool whose whole
    # purpose is not to make one. Codex, 2026-09-09.
    assert ("1 case(s) queued, 0 already recorded, 0 ruled unable to measure "
            "anything and not swept") in out, out


def _write(command, rows):
    """Write `rows` where the run pointed `pair_corpus`, as the child would.

    The attempt path is unique per invocation — two queues on one case would
    otherwise share it and unlink each other's work — so a fixture cannot name
    it in advance and takes it from `--json`.
    """
    import json as _json

    target = command[command.index("--json") + 1]
    with open(target, "w", encoding="utf-8") as handle:
        _json.dump(rows, handle)


def test_the_probe_buys_from_the_run_s_own_list(tmp_path, monkeypatch, capsys):
    """`--wait-for-reset` buys a real pair to find out whether the window is
    already spent, and the first version bought it from the whole corpus.

    Three wrongs in one command: `--language go` bought a C# pair, because the
    probe cleared every filter and took the alphabetically first case;
    `--pairs 1` bought two, because the probe's pair was counted nowhere; and
    under `--round N` it bought a case the manifest does not name, after every
    frozen condition had been enforced.

    The probe is a paid pair. It has to be one the run was going to buy
    anyway, or it is an extra purchase wearing the name of a check.
    """
    import sys as _sys

    import run_queue
    queue = tmp_path / "measurements" / "queue"
    monkeypatch.setattr(run_queue, "ROOT", tmp_path)
    monkeypatch.setattr(run_queue, "QUEUE", queue)
    monkeypatch.setattr(run_queue, "LOG", queue / "log.jsonl")
    monkeypatch.setattr(run_queue, "malformed", set)
    monkeypatch.setattr(run_queue, "already_run", lambda *a, **k: False)
    monkeypatch.setattr(run_queue, "note", lambda *a, **k: None)
    monkeypatch.setattr(run_queue, "close_window", lambda *a, **k: None)
    monkeypatch.setattr(run_queue, "sleep_until", lambda when: None)
    monkeypatch.delenv("SECURITY_SCAN_MODEL", raising=False)

    for case_id, language in (("aa-cs-0000-0000", "csharp"),
                              ("go-0000-0000-0000", "go")):
        directory = tmp_path / "corpus-real" / case_id
        directory.mkdir(parents=True)
        (directory / "case.yml").write_text(
            "language: {}\nconstruction: regression\n".format(language),
            encoding="utf-8")

    bought = []

    def buy(case_id, args):
        bought.append(case_id)
        return [{"case_id": case_id, "pair_success": True}], "ok", None

    monkeypatch.setattr(run_queue, "run_one", buy)
    monkeypatch.setattr(_sys, "argv",
                        ["run_queue.py", "--language", "go", "--pairs", "1",
                         "--wait-for-reset"])

    run_queue.main()

    # One pair, and it is the Go one. Not the alphabetically first case of the
    # corpus, and not two.
    assert bought == ["go-0000-0000-0000"], bought
    assert "1 case(s) run" in capsys.readouterr().out


def test_a_ruling_is_read_the_way_the_other_two_readers_read_it(tmp_path,
                                                                monkeypatch):
    """`check_accounted.rulings`'s docstring names this defect, because it was
    repaired there and in `artifact` and not here.

    `case_is_malformed: "false"` is truthy, and a `true` with no reason is a
    ruling nobody wrote down. Either one dropped the case from every sweep for
    ever, while `check_accounted` kept reporting it as not run — a case the
    queue will never schedule and the accounting will never stop asking for.
    """
    import run_queue
    monkeypatch.setattr(run_queue, "ROOT", tmp_path)
    corpus = tmp_path / "corpus-real"
    corpus.mkdir()

    def ruling(text):
        (corpus / "adjudications.yml").write_text(text, encoding="utf-8")
        return run_queue.malformed()

    # The string "false" is truthy in Python and is not a ruling.
    assert ruling('adjudications:\n'
                  '  - case_id: a-case\n'
                  '    case_is_malformed: "false"\n'
                  '    why_malformed: because\n') == set()

    # `true` with no reason is a ruling nobody wrote down.
    assert ruling('adjudications:\n'
                  '  - case_id: a-case\n'
                  '    case_is_malformed: true\n') == set()

    # Nor one whose reason is blank.
    assert ruling('adjudications:\n'
                  '  - case_id: a-case\n'
                  '    case_is_malformed: true\n'
                  '    why_malformed: "   "\n') == set()

    # A ruling with no case id put `None` in the set and inflated the printed
    # "ruled out" count by one.
    assert ruling('adjudications:\n'
                  '  - case_is_malformed: true\n'
                  '    why_malformed: because\n') == set()

    # The control: a real ruling still drops the case, or nothing here is
    # doing anything at all.
    assert ruling('adjudications:\n'
                  '  - case_id: a-case\n'
                  '    case_is_malformed: true\n'
                  '    why_malformed: the members are identical\n') == {"a-case"}


def test_a_claim_that_cannot_be_taken_is_not_reported_as_held(tmp_path,
                                                              monkeypatch):
    """"I could not lock" is not "somebody else has it".

    A read-only queue directory, a `.claim` path occupied by a directory, a
    filesystem with no `flock` — each answered with the sentence about another
    queue, and the window ledger then recorded `held_elsewhere` as a fact
    about a window where no other queue existed. The one confusion this
    project exists to refuse, in the newest code in the file.
    """
    import pytest as _pytest

    import run_queue
    monkeypatch.setattr(run_queue, "QUEUE", tmp_path)
    monkeypatch.setattr(run_queue, "ROOT", tmp_path)
    monkeypatch.delenv("SECURITY_SCAN_MODEL", raising=False)

    target = run_queue.result_path("a-case")
    # A directory where the claim file goes: the open fails, and it is not a
    # lock somebody holds.
    run_queue._claim_path(target).mkdir(parents=True)

    with _pytest.raises(run_queue.ClaimUnavailable):
        run_queue._take_claim(target)

    class Args:
        provider = "claude-cli"
        profile = "normal"

    _payload, kind, detail = run_queue.run_one("a-case", Args())

    assert kind == "unknown", (kind, detail)
    assert "cannot be opened" in str(detail)

    # The control: a claim another descriptor really holds is still `held`,
    # or this repair has turned every busy case into a stop.
    run_queue._claim_path(target).rmdir()
    held = run_queue._take_claim(target)
    assert held is not None
    _payload, kind, _detail = run_queue.run_one("a-case", Args())
    assert kind == "held", kind
    run_queue._release_claim(held)


def test_a_ruled_out_case_named_by_hand_does_not_stop_the_queue(tmp_path,
                                                                monkeypatch):
    """The ruling is applied on a sweep, and `--case` and a frozen round's
    list both go round it.

    `pair_corpus` drops such a case and exits "no such case" before writing
    anything, so the queue saw an empty attempt, called it `no-artifact`,
    printed "no session document was written", and stopped the whole
    unattended run — with a message asserting a provider failure that did not
    happen, and a window recorded as `interrupted`.
    """
    import run_queue
    monkeypatch.setattr(run_queue, "QUEUE", tmp_path)
    monkeypatch.setattr(run_queue, "ROOT", tmp_path)
    monkeypatch.setattr(run_queue, "run_one", run_queue.run_one)
    monkeypatch.setattr(run_queue, "malformed", lambda: {"a-case"})
    monkeypatch.setattr(run_queue, "subprocess", run_queue.subprocess)
    monkeypatch.delenv("SECURITY_SCAN_MODEL", raising=False)

    def never(*a, **k):
        raise AssertionError("a ruled-out case reached pair_corpus")

    monkeypatch.setattr(run_queue.subprocess, "run", never)

    class Args:
        provider = "claude-cli"
        profile = "normal"

    payload, kind, detail = run_queue.run_one("a-case", Args())

    assert kind == "ruled-out", (kind, detail)
    assert payload is None
    assert "cannot measure anything" in str(detail)

    # The control: a case no ruling names still runs, or this has turned the
    # queue off entirely.
    monkeypatch.setattr(run_queue, "malformed", set)
    with __import__("pytest").raises(AssertionError, match="reached pair_corpus"):
        run_queue.run_one("a-case", Args())


def test_a_failed_promotion_does_not_delete_the_paid_payload(tmp_path,
                                                            monkeypatch):
    """`promoted = True` was a separate statement *after* `os.replace`.

    Everything between the child returning and that assignment is a window in
    which the `finally` deletes the pair this run has just paid for. Narrow —
    same-directory rename, so `EXDEV` is impossible; it needs a sticky-bit
    directory, an ACL, or the target occupied by a directory — but the class
    is the one that costs money, so the flag is set before the rename rather
    than after it.
    """
    import json
    import os
    import subprocess as _subprocess

    import pytest as _pytest

    import run_queue
    monkeypatch.setattr(run_queue, "QUEUE", tmp_path)
    monkeypatch.setattr(run_queue, "ROOT", tmp_path)
    monkeypatch.delenv("SECURITY_SCAN_MODEL", raising=False)

    rows = [{"case_id": "a-case", "pair_success": True,
             "members": {"safe": {"stop_reason": "completed"},
                         "unsafe": {"stop_reason": "completed"}}}]

    def child(*a, **k):
        command = a[0]
        _write(command, rows)
        return _subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(run_queue.subprocess, "run", child)

    real_replace = os.replace

    def refuses(src, dst):
        raise PermissionError("the target is not writable")

    monkeypatch.setattr(run_queue.os, "replace", refuses)

    class Args:
        provider = "claude-cli"
        profile = "normal"

    with _pytest.raises(PermissionError):
        run_queue.run_one("a-case", Args())

    # The payload is still on disk under its attempt name, for a person to
    # find. The first version deleted it on the way out.
    left = sorted(p.name for p in tmp_path.glob("a-case.json.*.attempt"))
    assert len(left) == 1, left
    assert json.loads((tmp_path / left[0]).read_text(encoding="utf-8")) == rows

    # The control: when the rename works, nothing is left behind.
    monkeypatch.setattr(run_queue.os, "replace", real_replace)
    (tmp_path / left[0]).unlink()
    run_queue.run_one("a-case", Args())
    assert not list(tmp_path.glob("a-case.json.*.attempt"))
    assert run_queue.result_path("a-case").is_file()


def test_an_unknown_ending_is_billed_and_the_advice_is_true(tmp_path,
                                                            monkeypatch,
                                                            capsys):
    """Two defects in one branch.

    An `unknown` is a **paid** pair — one member completes, the other errors
    out — and its payload is promoted. The refused and success branches both
    write `kind: "review"` rows; this one did not, so `spend.py --source
    queue`, which filters on exactly that field, could not see the purchase.

    And the sentence it printed — "the result file, if any, is left in place
    for a person to look at" — was false for `no-artifact`, where the `finally`
    has just removed the attempt and nothing was ever written.
    """
    import json
    import sys as _sys

    import run_queue
    queue = tmp_path / "measurements" / "queue"
    monkeypatch.setattr(run_queue, "ROOT", tmp_path)
    monkeypatch.setattr(run_queue, "QUEUE", queue)
    monkeypatch.setattr(run_queue, "LOG", queue / "log.jsonl")
    monkeypatch.setattr(run_queue, "malformed", set)
    monkeypatch.setattr(run_queue, "already_run", lambda *a, **k: False)
    monkeypatch.setattr(run_queue, "close_window", lambda *a, **k: None)
    monkeypatch.delenv("SECURITY_SCAN_MODEL", raising=False)

    written = []
    monkeypatch.setattr(run_queue, "note", lambda row: written.append(row))

    paid = [{"case_id": "a-case", "members": {
        "safe": {"stop_reason": "completed", "seconds": 10.0,
                 "usage": {"input_tokens": 5, "output_tokens": 7},
                 "provenance": {"reported_cost_usd": 0.4}},
        "unsafe": {"stop_reason": "error", "stop_detail": "something new",
                   "seconds": 3.0, "usage": {}, "provenance": {}}}}]

    monkeypatch.setattr(run_queue, "run_one",
                        lambda case_id, args: (paid, "unknown", "new wording"))
    monkeypatch.setattr(_sys, "argv", ["run_queue.py", "--case", "a-case"])

    assert run_queue.main() == 3
    out = capsys.readouterr().out

    # The pair is on the bill: one row per member, the field `spend.py` reads.
    reviews = [row for row in written if row.get("kind") == "review"]
    assert len(reviews) == 2, written
    assert {row["member"] for row in reviews} == {"safe", "unsafe"}

    # And the advice names the file that exists.
    assert "left for a person to look at" in out
    assert "a-case.json" in out
    del json


def test_a_missing_artifact_does_not_promise_a_file(tmp_path, monkeypatch,
                                                    capsys):
    """The other half. `no-artifact` means nothing was written and the
    attempt is gone, so telling the operator to look at a file is telling
    them to look at nothing."""
    import sys as _sys

    import run_queue
    queue = tmp_path / "measurements" / "queue"
    monkeypatch.setattr(run_queue, "ROOT", tmp_path)
    monkeypatch.setattr(run_queue, "QUEUE", queue)
    monkeypatch.setattr(run_queue, "LOG", queue / "log.jsonl")
    monkeypatch.setattr(run_queue, "malformed", set)
    monkeypatch.setattr(run_queue, "already_run", lambda *a, **k: False)
    monkeypatch.setattr(run_queue, "note", lambda *a, **k: None)
    monkeypatch.setattr(run_queue, "close_window", lambda *a, **k: None)
    monkeypatch.setattr(run_queue, "run_one",
                        lambda case_id, args: (None, "no-artifact", "died"))
    monkeypatch.setattr(_sys, "argv", ["run_queue.py", "--case", "a-case"])
    monkeypatch.delenv("SECURITY_SCAN_MODEL", raising=False)

    assert run_queue.main() == 3
    out = capsys.readouterr().out

    assert "no file to look at" in out
    assert "left for a person to look at" not in out


def test_a_refused_probe_leaves_the_case_queued(tmp_path, monkeypatch, capsys):
    """Codex, 2026-09-09. A refusal costs twelve seconds and no tokens.

    Recording it as spent removed the case from the queue and ate the whole of
    `--pairs 1`, so the command slept out the reset and then exited
    successfully without ever measuring the one case it was asked for. The
    probe exists to find a spent window; finding one must not consume the
    allowance it was checking for.
    """
    import sys as _sys

    import run_queue
    queue = tmp_path / "measurements" / "queue"
    monkeypatch.setattr(run_queue, "ROOT", tmp_path)
    monkeypatch.setattr(run_queue, "QUEUE", queue)
    monkeypatch.setattr(run_queue, "LOG", queue / "log.jsonl")
    monkeypatch.setattr(run_queue, "malformed", set)
    monkeypatch.setattr(run_queue, "already_run", lambda *a, **k: False)
    monkeypatch.setattr(run_queue, "note", lambda *a, **k: None)
    monkeypatch.setattr(run_queue, "close_window", lambda *a, **k: None)
    monkeypatch.setattr(run_queue, "sleep_until", lambda when: None)
    monkeypatch.delenv("SECURITY_SCAN_MODEL", raising=False)

    directory = tmp_path / "corpus-real" / "go-0000-0000-0000"
    directory.mkdir(parents=True)
    (directory / "case.yml").write_text(
        "language: go\nconstruction: regression\n", encoding="utf-8")

    seen = []

    def refuse_then_run(case_id, args):
        seen.append(case_id)
        if len(seen) == 1:
            return None, "refused", LIMIT_MESSAGE
        return [{"case_id": case_id, "pair_success": True}], "ok", None

    monkeypatch.setattr(run_queue, "run_one", refuse_then_run)
    monkeypatch.setattr(_sys, "argv",
                        ["run_queue.py", "--pairs", "1", "--wait-for-reset"])

    run_queue.main()

    # The probe was refused, the queue slept, and the case was then measured.
    # It is not removed by a refusal and does not spend the allowance.
    assert seen == ["go-0000-0000-0000", "go-0000-0000-0000"], seen
    assert "1 case(s) run" in capsys.readouterr().out


def _never_spend(case_id, args):
    raise AssertionError(
        "a run was started for {!r}; the refusal must come before any "
        "purchase".format(case_id))


def test_a_result_file_that_will_not_parse_is_not_a_measurement(tmp_path, monkeypatch):
    """Truncated by a kill, half-written by a crash. Either way nothing in it
    says the case was measured, and the safe reading is to run it again.

    **The version check is pinned and there is a control.** Without them this
    passed for a reason it did not name: `about_this_version` is imported from
    `check_accounted` and resolves the corpus against *that* module's `ROOT`,
    which the test does not patch — so `already_run` answered `False` because
    `corpus-real/a-case` does not exist, whatever the file contained. A
    parseable file would have answered `False` too, and the assertion would
    still have held.
    """
    import json

    import run_queue
    monkeypatch.setattr(run_queue, "QUEUE", tmp_path)
    monkeypatch.setattr(run_queue, "ROOT", tmp_path)
    monkeypatch.setattr(run_queue, "about_this_version",
                        lambda case_id, row: True)
    monkeypatch.delenv("SECURITY_SCAN_MODEL", raising=False)

    (tmp_path / "a-case.json").write_text('[{"case_id": "a-cas')
    assert run_queue.already_run("a-case") is False

    # The control: the same file, whole, does say the case was measured.
    (tmp_path / "a-case.json").write_text(json.dumps(
        [{"case_id": "a-case", "pair_success": True}]))
    assert run_queue.already_run("a-case") is True


def test_a_window_records_which_compaction_it_ran_under(ledger, monkeypatch):
    """Windows compacted at different thresholds are not comparable.

    `CLAUDE_AUTOCOMPACT_PCT_OVERRIDE` lowers when auto-compaction fires, and it
    is a documented variable with reports of being set and silently ignored. So
    the value is read from the environment at the moment the window closes,
    not declared once — a variable that is present and inert then shows up in
    the ledger as what it actually was.

    Recording it is the point. Mixing windows with different compaction
    behaviour would break the next re-cut the same way the uncounted subagents
    broke the last one, except deliberately.
    """
    import run_queue

    monkeypatch.delenv("CLAUDE_AUTOCOMPACT_PCT_OVERRIDE", raising=False)
    run_queue.close_window("w1", "refused", 3, 1, "unattended")

    monkeypatch.setenv("CLAUDE_AUTOCOMPACT_PCT_OVERRIDE", "50")
    run_queue.close_window("w2", "refused", 3, 1, "unattended")

    rows = read_ledger(ledger)
    # "default", not "" or None: absent must be a value somebody can filter on,
    # not an empty cell that reads as unknown.
    assert [r["autocompact_pct"] for r in rows] == ["default", "50"]


def test_a_batch_row_about_an_older_case_does_not_skip_the_case(
        tmp_path, monkeypatch):
    """The queue and the accounting disagreed, and the queue was wrong.

    `cli-batch-1` and `cli-batch-2` predate `case_digest` and carry none, so
    `check_accounted` refuses them as verdicts — "it ran, but nothing recorded
    which version of the case it saw". This counted them anyway and skipped the
    case. On 2026-09-02 three cases sat in exactly that state: the tally said
    "not run", the queue said "already recorded", and a run of the twelve would
    have bought nine while reporting twelve.

    A queue that skips a case is how "not measured" becomes invisible, which is
    the same failure as a green gate over unread code — with money on it in the
    other direction too, since the missing rows are bought later or never.
    """
    import json

    import run_queue

    measurements = tmp_path / "measurements"
    measurements.mkdir()
    monkeypatch.setattr(run_queue, "QUEUE", tmp_path / "queue")
    monkeypatch.setattr(run_queue, "ROOT", tmp_path)
    (tmp_path / "queue").mkdir()

    (measurements / "cli-batch-1.json").write_text(json.dumps(
        [{"case_id": "a-case", "pair_success": True}]))

    monkeypatch.setattr(run_queue, "about_this_version",
                        lambda case_id, row: False)
    assert run_queue.already_run("a-case") is False, (
        "a row that is not about today's case counted as a measurement")

    monkeypatch.setattr(run_queue, "about_this_version",
                        lambda case_id, row: True)
    assert run_queue.already_run("a-case") is True

