"""The third-vendor answer key, and the ways it could quietly not be one.

Every test here is written against a way the adjudication could look done and
be worthless: a case silently dropped, a failure counted as a verdict, a retry
that re-rolls a case until it agrees, a prompt that leaks the label the sampling
rules already applied.

`grok` itself is never invoked. The subprocess boundary is replaced, so these
run offline, spend nothing, and pin the tool's behaviour rather than the
vendor's.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import grok_adjudicate as ga
import spend_gate


@pytest.fixture(autouse=True)
def order_permits(monkeypatch):
    """Every test here is about the adjudicator, not about the order.

    `ask` asks `spend_gate` immediately before the billable call, and against
    the real `DECISIONS.md` that answer is currently a refusal — correctly, the
    freeze is stale. Replaced explicitly rather than bypassed with a flag, so
    it is visible in this file that these tests do not exercise the gate. The
    gate is exercised in `tests/test_spend_gate.py`, including that a refusal
    stops the call rather than being reported after it.
    """
    monkeypatch.setattr(spend_gate, "_ask_the_order",
                        lambda step, **kwargs: (0, []))


def pool_record(repo: str, commit: str, diff: str = "diff --git a/x b/x\n+ok\n"):
    return {"repo": repo, "commit": commit, "diff_text": diff,
            "diff_truncated": False}


def seal_of(rows, candidates_digest):
    """The digest is not optional here, because it is not optional in a seal.

    A default would let every test hand in a seal that names no pool, and the
    check that a seal must name one would then be pinned by nothing.
    """
    return {"selected": [{"case_id": c, "repo": r, "commit": s}
                         for c, r, s in rows],
            "candidates": {"digest": candidates_digest}}


def fake_run(monkeypatch, answers):
    """Replace the CLI. `answers` is consulted per call, in order."""
    calls = []

    def run(command, **kwargs):
        calls.append(command)
        if command[:2] == ["grok", "--version"]:
            return subprocess.CompletedProcess(command, 0, "grok 9.9.9", "")
        reply = answers[len(calls) - 2] if len(calls) > 1 else answers[0]
        if isinstance(reply, Exception):
            raise reply
        return reply

    monkeypatch.setattr(ga.subprocess, "run", run)
    return calls


_SESSIONS = iter(["s-{}".format(n) for n in range(1, 500)])


def ok(verdict="ordinary", session=None, rationale="because"):
    session = session or next(_SESSIONS)
    body = {"sessionId": session, "requestId": "r-" + session,
            "num_turns": 1,
            "stopReason": "end_turn", "modelUsage": {"grok-4.6-build": {}},
            "total_cost_usd": 0.004,
            "structuredOutput": {"verdict": verdict, "rationale": rationale}}
    return subprocess.CompletedProcess([], 0, json.dumps(body), "")


def write_pool(tmp_path, records):
    pool = tmp_path / "pool.json"
    pool.write_text(json.dumps(records), encoding="utf-8")
    return pool


def write_pair(tmp_path, rows, records):
    """Pool first, then a seal naming its digest — the order a real seal has."""
    pool = write_pool(tmp_path, records)
    seal = tmp_path / "seal.json"
    seal.write_text(json.dumps(seal_of(rows, ga.oc.digest_file(pool))),
                    encoding="utf-8")
    return seal, pool


def run_tool(tmp_path, monkeypatch, rows, answers, pool_records=None,
             seal_digest=None, **extra):
    # A distinct diff per case. They shared one at first, so the prompts were
    # byte-identical and the test that two cases carry two prompt digests was
    # asserting the fixture rather than the tool.
    pool = write_pool(tmp_path, pool_records if pool_records is not None else [
        pool_record(r, s, "diff --git a/{0} b/{0}\n+line for {0}\n".format(
            s[:8])) for _, r, s in rows])
    # The seal is written after the pool, because it has to name its digest.
    seal = tmp_path / "seal.json"
    seal.write_text(json.dumps(seal_of(
        rows, seal_digest if seal_digest is not None
        else ga.oc.digest_file(pool))), encoding="utf-8")
    calls = fake_run(monkeypatch, answers)
    argv = ["--seal", str(seal), "--candidates", str(pool),
            "--out", str(tmp_path / "out"), "--seed", "7"]
    for key, value in extra.items():
        argv += ["--" + key.replace("_", "-"), str(value)]
    code = ga.main(argv)
    written = tmp_path / "out" / "grok-adjudication.json"
    body = json.loads(written.read_text(encoding="utf-8")) if written.exists() \
        else None
    return code, body, calls


# Real-shaped case ids, because the leak test looks for `ord-` and a
# fixture of `c0`/`c1` made that assertion pass over nothing.
ROWS = [("ord-rs-05751605", "github.com/o/a", "a" * 40),
        ("ord-js-0331ea21", "github.com/o/b", "b" * 40)]


def test_a_case_whose_diff_is_missing_stops_everything(tmp_path, monkeypatch):
    """A subset silently adjudicated is a rate over a denominator nobody chose."""
    seal, pool = write_pair(tmp_path, ROWS,
                            [pool_record("github.com/o/a", "a" * 40)])
    fake_run(monkeypatch, [ok()])
    with pytest.raises(SystemExit) as exit_:
        ga.main(["--seal", str(seal), "--candidates", str(pool),
                 "--out", str(tmp_path / "out")])
    assert "ord-js-0331ea21" in str(exit_.value)


def test_a_candidates_file_that_is_not_the_sealed_one_is_refused(
        tmp_path, monkeypatch):
    """The seal recorded the digest and nothing compared it.

    An edited pool could be adjudicated while the artifact carried the genuine
    seal digest beside the answers — the seal asserting a provenance the run
    had not honoured. Codex, 2026-09-05.
    """
    calls = fake_run(monkeypatch, [ok(), ok()])
    with pytest.raises(SystemExit) as exit_:
        run_tool(tmp_path, monkeypatch, ROWS, [ok(), ok()],
                 seal_digest="0000000000000000")
    assert "does not match the seal" in str(exit_.value)
    assert calls == [], "it spent a call before checking the provenance"


def test_a_seal_naming_no_candidates_digest_is_refused(tmp_path, monkeypatch):
    """A missing digest is not a waiver of the check."""
    pool = write_pool(tmp_path, [pool_record(r, s) for _, r, s in ROWS])
    seal = tmp_path / "seal.json"
    seal.write_text(json.dumps({"selected": [
        {"case_id": c, "repo": r, "commit": s} for c, r, s in ROWS]}),
        encoding="utf-8")
    fake_run(monkeypatch, [ok(), ok()])
    with pytest.raises(SystemExit) as exit_:
        ga.main(["--seal", str(seal), "--candidates", str(pool),
                 "--out", str(tmp_path / "out")])
    assert "names no digest" in str(exit_.value)


def test_a_cut_off_diff_is_refused_before_anything_is_spent(
        tmp_path, monkeypatch):
    """`diff_truncated` was recorded on every case and read by nothing.

    The model would answer over the half it was shown and the verdict would
    count as a verdict over the whole change. Knowable before the first call,
    so it is refused there. Codex, 2026-09-05.
    """
    records = [pool_record(r, s) for _, r, s in ROWS]
    records[1]["diff_truncated"] = True
    calls = fake_run(monkeypatch, [ok(), ok()])
    with pytest.raises(SystemExit) as exit_:
        run_tool(tmp_path, monkeypatch, ROWS, [ok(), ok()],
                 pool_records=records)
    said = str(exit_.value)
    assert "captured whole" in said and "ord-js-0331ea21" in said
    assert calls == [], "it paid for a question it could not ask"


@pytest.mark.parametrize("value, why", [
    (None, "the field is absent"),
    ("false", "the string that looks like the answer"),
    (0, "a number that is falsey"),
    ("", "an empty string"),
])
def test_a_record_that_does_not_say_the_diff_is_whole_is_refused(
        value, why, tmp_path, monkeypatch):
    """`bool(record.get("diff_truncated"))` read absence as "not truncated".

    The repository's recurring defect, live inside the line written one round
    earlier to fix truncation. What is required is a record that says the diff
    is whole, not one that fails to say it is cut. Codex, 2026-09-05.
    """
    records = [pool_record(r, s) for _, r, s in ROWS]
    if value is None:
        records[1].pop("diff_truncated")
    else:
        records[1]["diff_truncated"] = value
    calls = fake_run(monkeypatch, [ok(), ok()])
    with pytest.raises(SystemExit) as exit_:
        run_tool(tmp_path, monkeypatch, ROWS, [ok(), ok()],
                 pool_records=records)
    said = str(exit_.value)
    assert "captured whole" in said, why
    assert "ord-js-0331ea21" in said
    assert calls == [], "it paid for a question it could not ask"


@pytest.mark.parametrize("block", ["unknown", 7, [], True])
def test_a_seal_whose_candidates_block_is_not_an_object_is_refused(
        block, tmp_path, monkeypatch):
    """`(x or {}).get(...)` looked like a safe default and crashed on a
    truthy non-object — a crash where a refusal was promised."""
    pool = write_pool(tmp_path, [pool_record(r, s) for _, r, s in ROWS])
    seal = tmp_path / "seal.json"
    seal.write_text(json.dumps(
        {"selected": [{"case_id": c, "repo": r, "commit": s}
                      for c, r, s in ROWS],
         "candidates": block}), encoding="utf-8")
    fake_run(monkeypatch, [ok(), ok()])
    with pytest.raises(SystemExit) as exit_:
        ga.main(["--seal", str(seal), "--candidates", str(pool),
                 "--out", str(tmp_path / "out")])
    assert "names no digest" in str(exit_.value)


def test_a_limit_of_zero_asks_nothing_rather_than_everything(
        tmp_path, monkeypatch):
    """`if args.limit:` made `--limit 0` mean "no limit".

    The flag whose only purpose is to spend less became the full paid run.
    Codex, 2026-09-05.
    """
    calls = fake_run(monkeypatch, [ok(), ok()])
    code, body, _ = run_tool(tmp_path, monkeypatch, ROWS, [ok(), ok()],
                             limit=0)
    assert [c for c in calls if c[:2] != ["grok", "--version"]] == []
    assert body["order"] == []
    assert body["cases"] == {}
    assert code == 0


@pytest.mark.parametrize("limit", [-1, -30])
def test_a_negative_limit_is_refused_before_any_call(
        limit, tmp_path, monkeypatch):
    """`order[:-1]` paid for all but the tail."""
    calls = fake_run(monkeypatch, [ok(), ok()])
    with pytest.raises(SystemExit) as exit_:
        run_tool(tmp_path, monkeypatch, ROWS, [ok(), ok()], limit=limit)
    assert "negative number of cases" in str(exit_.value)
    assert calls == [], "it spent a call before refusing"


def test_whole_diffs_are_not_refused(tmp_path, monkeypatch):
    """The committed thirty carried `diff_truncated: false` throughout, so
    this check tightens the tool without touching that result."""
    code, body, _ = run_tool(tmp_path, monkeypatch, ROWS, [ok(), ok()])
    assert code == 0
    assert body["counts"]["no_verdict"] == 0


def test_the_repository_case_fold_is_honoured(tmp_path, monkeypatch):
    """The manifest lowercases a repository path and the pool does not.

    Measured on the live sample: a raw join on `(repo, commit)` lost exactly
    two of thirty, both `AutoMapper/AutoMapper` against
    `automapper/automapper`. The join goes through `ordinary_corpus.identity`,
    which is the one normalisation every other call site uses.
    """
    seal, pool = write_pair(
        tmp_path, [("c0", "github.com/automapper/automapper", "a" * 40)],
        [pool_record("github.com/AutoMapper/AutoMapper", "A" * 40)])
    fake_run(monkeypatch, [ok()])
    assert ga.main(["--seal", str(seal), "--candidates", str(pool),
                    "--out", str(tmp_path / "out")]) == 0


def test_a_failed_call_is_not_a_verdict_and_exits_two(tmp_path, monkeypatch):
    """`no_verdict` is the third answer, and a partial key is not a key."""
    failed = subprocess.CompletedProcess([], 1, "", "the model is unavailable")
    code, body, _ = run_tool(tmp_path, monkeypatch, ROWS, [ok(), failed])
    assert code == 2
    verdicts = [c.get("verdict") for c in body["cases"].values()]
    assert None in verdicts
    assert body["counts"]["no_verdict"] == 1
    assert any("unavailable" in (c.get("failed") or "")
               for c in body["cases"].values())


def test_a_timeout_is_recorded_and_never_retried(tmp_path, monkeypatch):
    """A second ask is a second sample of the same coin.

    The protocol forbids re-rolling a case until it agrees, so a timeout must
    leave one attempt with no verdict — not two attempts and a verdict.
    """
    timeout = subprocess.TimeoutExpired(cmd="grok", timeout=1)
    code, body, calls = run_tool(tmp_path, monkeypatch, ROWS, [ok(), timeout])
    assert code == 2
    # One version call plus one per case, and no more.
    assert len(calls) == 1 + len(ROWS)
    assert any("timed out" in (c.get("failed") or "")
               for c in body["cases"].values())


def test_a_verdict_outside_the_three_is_refused(tmp_path, monkeypatch):
    code, body, _ = run_tool(tmp_path, monkeypatch, ROWS,
                             [ok(), ok(verdict="probably fine")])
    assert code == 2
    assert any("not one of the three" in (c.get("failed") or "")
               for c in body["cases"].values())


def test_the_prompt_carries_the_change_and_nothing_that_labels_it(
        tmp_path, monkeypatch):
    """The stratum would be a direct hint: it *is* the rules' own label.

    So would the case id, which encodes the language, and anything about why
    the change was sampled.
    """
    code, _body, calls = run_tool(tmp_path, monkeypatch, ROWS, [ok(), ok()])
    assert code == 0
    prompts = [c[c.index("-p") + 1] for c in calls if "-p" in c]
    assert prompts and all("diff --git" in p for p in prompts)
    for prompt in prompts:
        for leak in ("stratum", "sensitive", "quiet", "ord-", "case_id",
                     "reviewer", "finding"):
            assert leak not in prompt, leak


def test_no_session_flag_is_ever_passed(tmp_path, monkeypatch):
    """Fresh context is the protocol's core claim about this tool."""
    run_tool(tmp_path, monkeypatch, ROWS, [ok(), ok()])
    _code, _body, calls = run_tool(tmp_path, monkeypatch, ROWS, [ok(), ok()])
    for command in calls:
        assert "--resume" not in command
        assert "--continue" not in command
        assert "--session-id" not in command
        assert "-c" not in command


def test_the_record_carries_what_a_later_reader_needs(tmp_path, monkeypatch):
    code, body, _ = run_tool(tmp_path, monkeypatch, ROWS, [ok(), ok("unclear")])
    assert code == 0
    assert body["adjudicated_by"] == "model"
    assert body["vendor"] == "xai"
    assert body["model_requested"] == ga.MODEL
    assert body["cli_version"] == "grok 9.9.9"
    assert body["order_seed"] == 7
    assert body["rubric_digest"] and body["schema_digest"]
    assert body["counts"] == {"ordinary": 1, "not_ordinary": 0, "unclear": 1,
                              "no_verdict": 0}
    # The served model, not the requested one. They differ in practice:
    # `grok-4.6` is asked for and `grok-4.6-build` answers.
    assert body["cases"]["ord-rs-05751605"]["model_served"] == ["grok-4.6-build"]
    assert "not human ground truth" in body["what_this_is_not"]


def test_repeated_sessions_are_refused_rather_than_assumed(
        tmp_path, monkeypatch):
    """Reported was not enough; it exits 2 now.

    The first version asserted `code == 0` beside `sessions_distinct: False` —
    a run where two cases shared one context still succeeded. Codex,
    2026-09-05: distinct identifiers are what separate one call from another.
    """
    code, body, _ = run_tool(tmp_path, monkeypatch, ROWS,
                             [ok(session="same"), ok(session="same")])
    assert code == 2
    assert body["sessions_distinct"] is False


def test_a_refused_call_still_counts_against_distinctness(
        tmp_path, monkeypatch):
    """One accepted answer beside a refused one sharing its session.

    The refused call went to the vendor and carries its identifiers; reuse
    there is the same contamination. Computed over accepted answers only, the
    artifact said one call compared, sessions distinct, no reuse — over two
    calls that shared a context. Codex, 2026-09-05.
    """
    code, body, _ = run_tool(
        tmp_path, monkeypatch, ROWS,
        [ok(session="same"), reply(sessionId="same", stopReason="max_turns")])
    assert body["calls_made"] == 2
    assert body["sessions_compared"] == 2
    assert body["sessions_distinct"] is False
    assert body["identifier_reuse"] is True
    assert code == 2


def test_a_call_with_no_id_is_not_counted_as_compared(tmp_path, monkeypatch):
    """Distinctness over the rest is not a statement about every call."""
    code, body, _ = run_tool(tmp_path, monkeypatch, ROWS,
                             [ok(session="s-a"),
                              reply(sessionId=None, requestId="r-x")])
    assert body["calls_made"] == 2
    assert body["sessions_compared"] == 1
    assert body["responses_compared"] == 2
    assert body["every_call_compared"] is False
    assert body["sessions_distinct"] is True, "of the one that carried an id"
    assert body["identifier_reuse"] is False
    assert code == 2, "the reply with no id produced no verdict"


def test_a_missing_response_id_is_not_covered_by_a_present_session_id(
        tmp_path, monkeypatch):
    """One count stood for two comparisons.

    An attempt carrying a session id and no response id was reported as
    compared, and the run could claim every call was compared while response
    distinctness covered one attempt of two. Codex, 2026-09-05.
    """
    code, body, _ = run_tool(tmp_path, monkeypatch, ROWS,
                             [ok(session="s-a"),
                              reply(sessionId="s-b", requestId=None)])
    assert body["calls_made"] == 2
    assert body["sessions_compared"] == 2
    assert body["responses_compared"] == 1
    assert body["every_call_compared"] is False
    assert code == 2


def test_a_whole_run_reports_that_every_call_was_compared(
        tmp_path, monkeypatch):
    code, body, _ = run_tool(tmp_path, monkeypatch, ROWS,
                             [ok(session="s-a"), ok(session="s-b")])
    assert code == 0
    assert body["calls_made"] == 2
    assert body["sessions_compared"] == body["responses_compared"] == 2
    assert body["every_call_compared"] is True


def test_the_order_is_shuffled_and_the_seed_recorded(tmp_path, monkeypatch):
    rows = [("c{}".format(i), "github.com/o/r{}".format(i),
             "{:040x}".format(i)) for i in range(12)]
    _code, body, _ = run_tool(tmp_path, monkeypatch, rows, [ok()] * 12)
    assert body["order"] != [c for c, _, _ in rows], "the order was not shuffled"
    assert sorted(body["order"]) == sorted(c for c, _, _ in rows)
    assert body["order_seed"] == 7


# --------------------------------------------------------------------------
# The evidence is checked, not merely written down
#
# Codex, 2026-09-04: "protocol evidence is recorded but never validated". The
# first version put the session id, the turn count and the served model into
# the artifact and read none of them, so a reply that was not a single-turn
# call still produced a verdict and exit 0. Recording evidence and not reading
# it is a claim nothing enforces.
# --------------------------------------------------------------------------

def reply(**over):
    """A well-formed reply with one field spoiled."""
    body = {"sessionId": "s-1", "requestId": "r-1", "num_turns": 1,
            "stopReason": "end_turn", "modelUsage": {"grok-4.6-build": {}},
            "total_cost_usd": 0.004,
            "structuredOutput": {"verdict": "ordinary", "rationale": "because"}}
    body.update(over)
    return subprocess.CompletedProcess([], 0, json.dumps(body), "")


@pytest.mark.parametrize("spoiled, expect", [
    # `num_turns` is no longer a freshness test - see the ceiling tests
    # below. What is still refused is a reply with no usable count at all,
    # since a missing field must never read as agreement.
    ({"num_turns": None}, "no usable turn count"),
    # `True == 1` in Python, so an `== 1` check accepted a JSON boolean where
    # a count belongs. Codex found it by probing the checker, not reading it.
    ({"num_turns": True}, "no usable turn count"),
    ({"num_turns": "1"}, "no usable turn count"),
    ({"num_turns": 0}, "no usable turn count"),
    # `not [""]` is False, so a list holding an empty name passed as evidence
    # that a model was named.
    ({"modelUsage": {"": {}}}, "names no model"),
    ({"modelUsage": {"   ": {}}}, "names no model"),
    ({"sessionId": None}, "session id"),
    ({"sessionId": "  "}, "session id"),
    ({"requestId": None}, "provider response id"),
    ({"modelUsage": {}}, "names no model"),
    ({"structuredOutput": {"verdict": "ordinary"}}, "no rationale"),
    ({"structuredOutput": {"verdict": "ordinary", "rationale": " "}},
     "no rationale"),
])
def test_a_reply_that_cannot_show_the_protocol_gets_no_verdict(
        tmp_path, monkeypatch, spoiled, expect):
    code, body, _ = run_tool(tmp_path, monkeypatch, ROWS,
                             [ok(), reply(**spoiled)])
    assert code == 2
    failures = [c.get("failed") or "" for c in body["cases"].values()]
    assert any(expect in f for f in failures), failures
    assert body["counts"]["no_verdict"] == 1


def test_every_reply_missing_a_session_id_is_not_freshness(
        tmp_path, monkeypatch):
    """`sessions_distinct` was True when *every* id was missing.

    The empty set has no duplicates, and the ids were filtered out before the
    comparison — so the absence certified the property it was meant to
    demonstrate. Now a reply with no id gets no verdict at all, and the
    distinctness is read over the cases that produced one.

    With none of them producing one, the answer is `null` and not `False`:
    nothing was compared, which is a different statement from "the calls were
    not separate". The assertion is that it is never `True`, which is the
    thing this test exists to prevent, and that the count says why.
    """
    code, body, _ = run_tool(
        tmp_path, monkeypatch, ROWS,
        # Distinct response ids, or the run would be refused for sharing one
        # and this test would pass for the wrong reason.
        [reply(sessionId=None, requestId="r-1"),
         reply(sessionId=None, requestId="r-2")])
    assert code == 2
    assert body["counts"]["no_verdict"] == 2
    assert body["sessions_distinct"] is not True
    assert body["sessions_compared"] == 0
    assert body["identifier_reuse"] is False, \
        "nothing was reused; nothing was asked"


def test_two_replies_sharing_a_session_are_refused_not_merely_reported(
        tmp_path, monkeypatch):
    """Reuse across cases is the contamination this actually looks for.

    It was recorded as a boolean nobody acted on, so a run where two cases
    shared one context still exited 0. Distinct identifiers are what separate
    one call from another; two cases sharing one is the same context answering
    twice. Codex, 2026-09-05.
    """
    code, body, _ = run_tool(tmp_path, monkeypatch, ROWS,
                             [ok(session="same"), ok(session="same")])
    assert code == 2
    assert body["sessions_distinct"] is False
    assert body["identifier_reuse"] is True


def test_a_run_whose_calls_are_all_separate_exits_zero(tmp_path, monkeypatch):
    code, body, _ = run_tool(tmp_path, monkeypatch, ROWS,
                             [ok(session="s-1"), ok(session="s-2")])
    assert code == 0
    assert body["identifier_reuse"] is False


def test_many_turns_are_recorded_and_not_refused(tmp_path, monkeypatch):
    """No ceiling, and the reason is a rule this project already has.

    A ceiling of 12 was written — one above the eleven observed once — and
    Codex struck it out: a threshold from a single observation, when the
    timeout already bounds the resource prospectively, and refusing a finished
    thirteen-turn answer discards evidence without saving anything. The count
    is recorded and the verdict stands.
    """
    code, body, _ = run_tool(tmp_path, monkeypatch, ROWS,
                             [ok(), reply(num_turns=99, sessionId="s-99",
                                          requestId="r-99")])
    assert code == 0
    assert body["counts"]["no_verdict"] == 0
    assert 99 in [c.get("turns") for c in body["cases"].values()]
    failures = [c.get("failed") or "" for c in body["cases"].values()]
    assert not any("fresh" in f for f in failures)


def test_a_working_call_with_a_few_turns_is_accepted(tmp_path, monkeypatch):
    """Measured on 2026-09-05: a real reply came back with eleven turns.

    Refusing it as contamination would discard an adjudication for having
    thought harder.
    """
    code, body, _ = run_tool(tmp_path, monkeypatch, ROWS,
                             [ok(), reply(num_turns=11, sessionId="s-2",
                                          requestId="r-2")])
    assert code == 0
    assert body["counts"]["no_verdict"] == 0


@pytest.mark.parametrize("stop", [None, "", "max_turns", "error", "cancelled"])
def test_a_call_that_did_not_finish_its_answer_is_not_a_verdict(
        stop, tmp_path, monkeypatch):
    """`stopReason` was recorded and never read.

    A call that stopped on a limit or an error left off mid-answer, and its
    structured output is whatever had been assembled by then — accepted as an
    adjudication until this check. Required, not forbidden: enumerating the
    bad endings would miss the next one the CLI invents. Codex, 2026-09-05.
    """
    code, body, _ = run_tool(tmp_path, monkeypatch, ROWS,
                             [ok(), reply(stopReason=stop, sessionId="s-2",
                                          requestId="r-2")])
    assert code == 2
    assert body["counts"]["no_verdict"] == 1
    failures = [c.get("failed") or "" for c in body["cases"].values()]
    assert any("rather than finishing its answer" in f for f in failures)


# --------------------------------------------------------------------------
# A case cannot be adjudicated twice
# --------------------------------------------------------------------------

def test_a_repeated_case_id_is_refused_before_any_call(tmp_path, monkeypatch):
    """The second answer would overwrite the first, hiding a paid call."""
    rows = [("ord-rs-1", "github.com/o/a", "a" * 40),
            ("ord-rs-1", "github.com/o/b", "b" * 40)]
    seal, pool = write_pair(tmp_path, rows,
                            [pool_record(r, s) for _, r, s in rows])
    calls = fake_run(monkeypatch, [ok(), ok()])
    with pytest.raises(SystemExit) as exit_:
        ga.main(["--seal", str(seal), "--candidates", str(pool),
                 "--out", str(tmp_path / "out")])
    assert "ord-rs-1" in str(exit_.value)
    assert calls == [], "it spent a call before refusing"


def test_one_change_under_two_names_is_refused(tmp_path, monkeypatch):
    """Same commit, same repository spelled differently, two case ids.

    Counted twice in the rate, and asked about twice at the vendor.
    """
    rows = [("ord-cs-1", "github.com/AutoMapper/AutoMapper", "A" * 40),
            ("ord-cs-2", "github.com/automapper/automapper", "a" * 40)]
    seal, pool = write_pair(tmp_path, rows,
                            [pool_record(r, s) for _, r, s in rows])
    calls = fake_run(monkeypatch, [ok(), ok()])
    with pytest.raises(SystemExit) as exit_:
        ga.main(["--seal", str(seal), "--candidates", str(pool),
                 "--out", str(tmp_path / "out")])
    assert "automapper" in str(exit_.value).lower()
    assert calls == []


def test_the_command_and_the_prompt_digest_are_recorded(tmp_path, monkeypatch):
    """The protocol asks for the command shape and the prompt digest.

    The prompt itself is not stored — a 26 KB diff inlined into every record
    would make the artifact unreadable and the digest already fixes it.
    """
    _code, body, _ = run_tool(tmp_path, monkeypatch, ROWS, [ok(), ok()])
    for case in body["cases"].values():
        assert case["command"][0] == "grok"
        assert "<prompt>" in case["command"]
        assert not any("diff --git" in part for part in case["command"])
        assert len(case["prompt_digest"]) == 16
    digests = {c["prompt_digest"] for c in body["cases"].values()}
    assert len(digests) == len(ROWS), "two cases shared a prompt digest"


@pytest.mark.parametrize("payload, expect", [
    ("[]", "not an object"),
    ('"ok"', "not an object"),
    ("42", "not an object"),
    ('{"modelUsage": "x", "sessionId": "s", "requestId": "r", '
     '"num_turns": 1, "structuredOutput": {"verdict": "ordinary", '
     '"rationale": "r"}}', "names no model"),
    ('{"modelUsage": ["x"], "sessionId": "s", "requestId": "r", '
     '"num_turns": 1, "structuredOutput": {"verdict": "ordinary", '
     '"rationale": "r"}}', "names no model"),
])
def test_valid_json_of_the_wrong_shape_is_a_refusal_not_a_crash(
        tmp_path, monkeypatch, payload, expect):
    """Decoded is not the same as shaped.

    `[]` parses fine and then raised on the first `.get`, and
    `{"modelUsage": "x"}` raised on `.keys()` - killing the whole run without
    recording the attempt, writing the artifact, or exiting 2. A crash where a
    refusal belongs is the one thing this repository never allows: it borrows
    another answer's exit code. Codex, 2026-09-04.
    """
    shaped = subprocess.CompletedProcess([], 0, payload, "")
    code, body, _ = run_tool(tmp_path, monkeypatch, ROWS, [ok(), shaped])
    assert code == 2
    assert body is not None, "the artifact was not written"
    assert any(expect in (c.get("failed") or "")
               for c in body["cases"].values())
