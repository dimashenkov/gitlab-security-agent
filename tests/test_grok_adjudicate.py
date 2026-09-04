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


def pool_record(repo: str, commit: str, diff: str = "diff --git a/x b/x\n+ok\n"):
    return {"repo": repo, "commit": commit, "diff_text": diff,
            "diff_truncated": False}


def seal_of(rows):
    return {"selected": [{"case_id": c, "repo": r, "commit": s}
                         for c, r, s in rows]}


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


def ok(verdict="ordinary", session="s-1", rationale="because"):
    body = {"sessionId": session, "requestId": "r-1", "num_turns": 1,
            "stopReason": "end_turn", "modelUsage": {"grok-4.6-build": {}},
            "total_cost_usd": 0.004,
            "structuredOutput": {"verdict": verdict, "rationale": rationale}}
    return subprocess.CompletedProcess([], 0, json.dumps(body), "")


def run_tool(tmp_path, monkeypatch, rows, answers, **extra):
    seal = tmp_path / "seal.json"
    seal.write_text(json.dumps(seal_of(rows)), encoding="utf-8")
    pool = tmp_path / "pool.json"
    # A distinct diff per case. They shared one at first, so the prompts were
    # byte-identical and the test that two cases carry two prompt digests was
    # asserting the fixture rather than the tool.
    pool.write_text(json.dumps([
        pool_record(r, s, "diff --git a/{0} b/{0}\n+line for {0}\n".format(
            s[:8])) for _, r, s in rows]), encoding="utf-8")
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
    seal = tmp_path / "seal.json"
    seal.write_text(json.dumps(seal_of(ROWS)), encoding="utf-8")
    pool = tmp_path / "pool.json"
    pool.write_text(json.dumps([pool_record("github.com/o/a", "a" * 40)]),
                    encoding="utf-8")
    fake_run(monkeypatch, [ok()])
    with pytest.raises(SystemExit) as exit_:
        ga.main(["--seal", str(seal), "--candidates", str(pool),
                 "--out", str(tmp_path / "out")])
    assert "ord-js-0331ea21" in str(exit_.value)


def test_the_repository_case_fold_is_honoured(tmp_path, monkeypatch):
    """The manifest lowercases a repository path and the pool does not.

    Measured on the live sample: a raw join on `(repo, commit)` lost exactly
    two of thirty, both `AutoMapper/AutoMapper` against
    `automapper/automapper`. The join goes through `ordinary_corpus.identity`,
    which is the one normalisation every other call site uses.
    """
    seal = tmp_path / "seal.json"
    seal.write_text(json.dumps(seal_of(
        [("c0", "github.com/automapper/automapper", "a" * 40)])),
        encoding="utf-8")
    pool = tmp_path / "pool.json"
    pool.write_text(json.dumps(
        [pool_record("github.com/AutoMapper/AutoMapper", "A" * 40)]),
        encoding="utf-8")
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


def test_repeated_sessions_are_reported_rather_than_assumed(
        tmp_path, monkeypatch):
    """If two calls came back with one session id, that is the claim failing.

    The tool must report it instead of asserting freshness it did not observe.
    """
    code, body, _ = run_tool(tmp_path, monkeypatch, ROWS,
                             [ok(session="same"), ok(session="same")])
    assert code == 0
    assert body["sessions_distinct"] is False


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
    ({"num_turns": 2}, "exactly one"),
    ({"num_turns": None}, "exactly one"),
    # `True == 1` in Python, so `turns == 1` accepted a JSON boolean where a
    # count belongs. Codex found it by probing the checker, not by reading it.
    ({"num_turns": True}, "exactly one"),
    ({"num_turns": "1"}, "exactly one"),
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
    """
    code, body, _ = run_tool(tmp_path, monkeypatch, ROWS,
                             [reply(sessionId=None), reply(sessionId=None)])
    assert code == 2
    assert body["counts"]["no_verdict"] == 2
    assert body["sessions_distinct"] is False


def test_two_replies_sharing_a_session_are_reported_not_hidden(
        tmp_path, monkeypatch):
    code, body, _ = run_tool(tmp_path, monkeypatch, ROWS,
                             [ok(session="same"), ok(session="same")])
    assert code == 0
    assert body["sessions_distinct"] is False
    assert body["responses_distinct"] is False


# --------------------------------------------------------------------------
# A case cannot be adjudicated twice
# --------------------------------------------------------------------------

def test_a_repeated_case_id_is_refused_before_any_call(tmp_path, monkeypatch):
    """The second answer would overwrite the first, hiding a paid call."""
    rows = [("ord-rs-1", "github.com/o/a", "a" * 40),
            ("ord-rs-1", "github.com/o/b", "b" * 40)]
    seal = tmp_path / "seal.json"
    seal.write_text(json.dumps(seal_of(rows)), encoding="utf-8")
    pool = tmp_path / "pool.json"
    pool.write_text(json.dumps([pool_record(r, s) for _, r, s in rows]),
                    encoding="utf-8")
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
    seal = tmp_path / "seal.json"
    seal.write_text(json.dumps(seal_of(rows)), encoding="utf-8")
    pool = tmp_path / "pool.json"
    pool.write_text(json.dumps([pool_record(r, s) for _, r, s in rows]),
                    encoding="utf-8")
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
