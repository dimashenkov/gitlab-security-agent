"""Coding the twenty causes, and the ways a coding could mean nothing.

Every test is written against a way this could look done and not be: a coding
that contradicts itself across fields, an `unclear` with nothing named as
missing, a superseded ruling shown to the classifier, a prompt carrying the
answer.

`grok` is never invoked — the subprocess boundary is replaced, so these run
offline and spend nothing.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import classify_alarms as ca  # noqa: E402
import spend_gate  # noqa: E402


@pytest.fixture(autouse=True)
def order_permits(monkeypatch):
    """These tests are about the codebook, not about the order.

    `ask` asks `spend_gate` immediately before the billable call. Replaced
    explicitly rather than bypassed with a flag, so it is visible here that
    these tests do not exercise the gate — `tests/test_spend_gate.py` does.
    """
    monkeypatch.setattr(spend_gate, "_ask_the_order",
                        lambda step, **kwargs: (0, []))

_SESSIONS = iter(["s-{}".format(n) for n in range(1, 500)])


def coding(**over):
    body = {"alarm_source": "reviewer", "reviewer_error": "wrong_semantics",
            "confidence": "medium", "evidence_refs": ["a.py:12"],
            "evidence_assessment": "the caller validates first",
            "missing_context": []}
    body.update(over)
    return body


def reply(session=None, **over):
    session = session or next(_SESSIONS)
    body = {"sessionId": session, "requestId": "r-" + session, "num_turns": 1,
            "stopReason": "end_turn", "modelUsage": {"grok-4.6-build": {}},
            "total_cost_usd": 0.005, "structuredOutput": coding()}
    body.update(over)
    return subprocess.CompletedProcess([], 0, json.dumps(body), "")


def fake_run(monkeypatch, answers):
    calls = []

    def run(command, **kwargs):
        calls.append(command)
        if command[:2] == ["grok", "--version"]:
            return subprocess.CompletedProcess(command, 0, "grok 9.9.9", "")
        return answers[min(len(calls) - 2, len(answers) - 1)]

    monkeypatch.setattr(ca.subprocess, "run", run)
    return calls


# --------------------------------------------------------------------------
# The vocabulary, which `--json-schema` promises and does not enforce here
# --------------------------------------------------------------------------

@pytest.mark.parametrize("field, invented", [
    ("alarm_source", "banana"),
    ("reviewer_error", "gravy"),
    ("confidence", "yes"),
])
def test_a_value_outside_the_codebook_is_refused(field, invented):
    """Demonstrated live before it was fixed.

    All three invented values passed every cross-field rule, the coding was
    counted in the denominator, and it appeared in no bucket.
    """
    problems = ca._coding_problems(coding(**{field: invented}))
    assert any(field in p and "not one of" in p for p in problems)


@pytest.mark.parametrize("field", ["alarm_source", "reviewer_error",
                                   "confidence"])
def test_a_field_missing_altogether_is_refused(field):
    """It reached the aggregation and raised `KeyError` — a crash where a
    refusal belongs."""
    body = coding()
    body.pop(field)
    problems = ca._coding_problems(body)
    assert any(field in p and "not one of" in p for p in problems)


def test_a_field_the_codebook_does_not_define_is_refused():
    problems = ca._coding_problems(coding(severity="high"))
    assert any("severity" in p and "does not define" in p for p in problems)


def test_the_schema_and_the_checker_name_the_same_fields():
    """Neither side may gain a field alone.

    The checker's field list is written out rather than derived, so that a
    field added to the schema is not accepted by a checker that has never read
    it. This is what keeps the two level.
    """
    assert set(ca.CODEBOOK_SCHEMA["properties"]) == ca._CODING_FIELDS
    assert set(ca.CODEBOOK_SCHEMA["required"]) == ca._CODING_FIELDS


# --------------------------------------------------------------------------
# The cross-field rules, which the schema cannot express
# --------------------------------------------------------------------------

def test_metric_with_a_named_reviewer_error_contradicts_itself():
    """`metric` says the reviewer did nothing wrong."""
    problems = ca._coding_problems(coding(alarm_source="metric",
                                          reviewer_error="wrong_location"))
    assert any("did nothing wrong" in p for p in problems)


def test_metric_with_not_applicable_is_accepted():
    assert ca._coding_problems(coding(alarm_source="metric",
                                      reviewer_error="not_applicable")) == []


@pytest.mark.parametrize("source", ["reviewer", "both"])
def test_a_reviewer_error_of_not_applicable_states_no_mechanism(source):
    problems = ca._coding_problems(coding(alarm_source=source,
                                          reviewer_error="not_applicable"))
    assert any("names no mechanism" in p for p in problems)


@pytest.mark.parametrize("source", ["other", "unclear"])
def test_other_and_unclear_may_leave_the_mechanism_unstated(source):
    """Codex was explicit: forcing a mechanism here would invent one."""
    assert ca._coding_problems(
        coding(alarm_source=source, reviewer_error="not_applicable",
               missing_context=["the caller is outside the corpus"])) == []


@pytest.mark.parametrize("field", ["alarm_source", "reviewer_error"])
def test_unclear_must_name_what_was_missing(field):
    """Otherwise it is a shrug with a field name on it."""
    problems = ca._coding_problems(coding(**{field: "unclear"}))
    assert any("nothing is named as missing" in p for p in problems)


def test_a_coding_with_no_references_is_refused():
    """A required paragraph validates eloquence; references name artifacts."""
    problems = ca._coding_problems(coding(evidence_refs=[]))
    assert any("no evidence references" in p for p in problems)


def test_a_coding_with_blank_references_is_refused():
    problems = ca._coding_problems(coding(evidence_refs=["   ", ""]))
    assert any("is blank or is not text" in p for p in problems)


def test_one_unreadable_reference_is_not_saved_by_a_readable_one():
    """`any` asked whether the list held one usable entry and said yes."""
    problems = ca._coding_problems(coding(evidence_refs=["a.py:1", 7]))
    assert any("is blank or is not text" in p for p in problems)


@pytest.mark.parametrize("named", [[""], ["   "], [3], [None], ["ok", ""]])
def test_something_named_as_missing_must_be_readable(named):
    problems = ca._coding_problems(coding(missing_context=named))
    assert any("is blank or is not text" in p for p in problems)


def test_unclear_with_one_empty_string_is_not_a_naming():
    """`not [""]` is False, so a list of one empty string read as agreement.

    This is the repository's recurring defect, live inside a checker written
    against it. Codex, 2026-09-05.
    """
    problems = ca._coding_problems(coding(alarm_source="unclear",
                                          missing_context=[""]))
    assert problems, "an empty string named nothing and passed as a naming"


def test_a_coding_with_no_assessment_is_refused():
    problems = ca._coding_problems(coding(evidence_assessment="  "))
    assert any("no assessment" in p for p in problems)


def test_a_reply_that_is_not_an_object_is_refused():
    assert ca._coding_problems("ordinary") == ["no structured coding in the "
                                               "response"]


# --------------------------------------------------------------------------
# What the classifier is shown
# --------------------------------------------------------------------------

def identities_and_rulings():
    identities = {
        "schema": "alarm-finding-identity/1",
        "findings": [
            {"finding_id": "one-finding", "case_id": "case-x", "member": "safe",
             "file": "x.py", "fingerprint": "ffff9999",
             "same_finding_as": "revision",
             "decided_by": "assistant", "decided_on": "2026-09-04",
             "rationale": "one finding stated twice",
             "evidence_refs": ["corpus-real/adjudications.yml"],
             "rulings": [{"adjudicated_on": "2026-08-24", "fingerprint": None},
                         {"adjudicated_on": "2026-09-02",
                          "fingerprint": "ffff9999"}]},
        ],
    }
    rulings = [
        {"case_id": "case-x", "member": "safe", "adjudicated_on": "2026-08-24",
         "fingerprint": None, "file": "x.py", "claim": "the older wording"},
        {"case_id": "case-x", "member": "safe", "adjudicated_on": "2026-09-02",
         "fingerprint": "ffff9999", "file": "x.py",
         "claim": "the revised wording", "verdict": "real"},
    ]
    return identities, rulings


def test_a_superseded_ruling_is_not_shown_to_the_classifier():
    """The identities file already decided which row a finding is.

    Handing over both would ask the classifier to re-decide something frozen
    before it ran.
    """
    identities, rulings = identities_and_rulings()
    items = ca.material(identities, rulings, {"case-x": "one-finding"})
    assert len(items) == 1
    assert "the revised wording" in items[0]["ruling"]
    assert "the older wording" not in items[0]["ruling"]


def test_the_prompt_carries_the_ruling_and_nothing_that_labels_it(
        tmp_path, monkeypatch):
    identities, rulings = identities_and_rulings()
    items = ca.material(identities, rulings, {"case-x": "one-finding"})
    prompt = ca.RUBRIC.format(ruling=items[0]["ruling"])
    for leak in ("case-x", "one-finding", "stratum", "sensitive", "quiet",
                 "safe_false_positive"):
        assert leak not in prompt, leak


def test_two_rulings_after_supersession_stop_the_run():
    """Guessing which would undo a decision the identities file froze."""
    identities, rulings = identities_and_rulings()
    identities["findings"][0].pop("same_finding_as")
    with pytest.raises(SystemExit) as exit_:
        ca.material(identities, rulings, {"case-x": "one-finding"})
    assert "2 ruling(s)" in str(exit_.value)


# --------------------------------------------------------------------------
# The protocol evidence, copied from step 2 rather than inherited
# --------------------------------------------------------------------------

@pytest.mark.parametrize("spoiled, expect", [
    ({"sessionId": None}, "session id"),
    ({"requestId": "  "}, "provider response id"),
    ({"num_turns": None}, "no usable turn count"),
    ({"num_turns": True}, "no usable turn count"),
    ({"modelUsage": {}}, "names no model"),
    ({"modelUsage": "x"}, "names no model"),
])
def test_a_reply_that_cannot_show_the_protocol_is_refused(spoiled, expect):
    attempt = {"session_id": "s", "request_id": "r", "turns": 1,
               "stop_reason": "end_turn", "model_served": ["grok-4.6-build"]}
    field = {"sessionId": "session_id", "requestId": "request_id",
             "num_turns": "turns", "modelUsage": "model_served"}
    for key, value in spoiled.items():
        attempt[field[key]] = (sorted(value.keys())
                               if key == "modelUsage" and isinstance(value, dict)
                               else value)
    assert any(expect in p for p in ca._evidence_problems(attempt))


def test_many_turns_are_recorded_and_not_refused():
    """No ceiling: one above a single observation is not a budget."""
    attempt = {"session_id": "s", "request_id": "r", "turns": 99,
               "stop_reason": "end_turn", "model_served": ["grok-4.6-build"]}
    assert ca._evidence_problems(attempt) == []


@pytest.mark.parametrize("stop", [None, "", "max_turns", "error", "cancelled"])
def test_only_a_call_that_finished_its_answer_is_accepted(stop):
    """Required, not forbidden: listing the bad endings would miss the next
    one the CLI invents."""
    attempt = {"session_id": "s", "request_id": "r", "turns": 1,
               "stop_reason": stop, "model_served": ["grok-4.6-build"]}
    assert any("rather than finishing its answer" in p
               for p in ca._evidence_problems(attempt))


# --------------------------------------------------------------------------
# End to end, with the CLI replaced
# --------------------------------------------------------------------------

def run_tool(tmp_path, monkeypatch, answers, identities=None, rulings=None):
    identities = identities or identities_and_rulings()[0]
    rulings = rulings if rulings is not None else identities_and_rulings()[1]
    path = tmp_path / "identities.yml"
    path.write_text(yaml.safe_dump(identities), encoding="utf-8")
    monkeypatch.setattr(ca.ai, "load_identities", lambda _p: identities)
    monkeypatch.setattr(ca.ai, "alarms_and_rulings",
                        lambda _c: ({"case-x"}, rulings))
    calls = fake_run(monkeypatch, answers)
    code = ca.main(["--identities", str(path), "--out", str(tmp_path / "out"),
                    "--seed", "3"])
    written = tmp_path / "out" / "codebook.json"
    body = json.loads(written.read_text(encoding="utf-8")) \
        if written.exists() else None
    return code, body, calls


def test_a_run_records_the_provenance_and_the_denominator(
        tmp_path, monkeypatch):
    code, body, _ = run_tool(tmp_path, monkeypatch, [reply()])
    assert code == 0
    assert body["coded_by"] == "model" and body["vendor"] == "xai"
    assert body["cli_version"] == "grok 9.9.9"
    assert body["order_seed"] == 3
    assert body["rubric_digest"] and body["schema_digest"]
    assert body["identities"]["digest"]
    assert body["denominator"] == 1
    assert "do not authorise step 5" in body["what_this_is_not"]


def test_a_failed_coding_exits_two_and_the_artifact_is_still_written(
        tmp_path, monkeypatch):
    bad = subprocess.CompletedProcess([], 1, "", "the model is unavailable")
    code, body, _ = run_tool(tmp_path, monkeypatch, [bad])
    assert code == 2
    assert body is not None
    assert body["counts"]["no_coding"] == 1


def test_no_session_flag_is_ever_passed(tmp_path, monkeypatch):
    _code, _body, calls = run_tool(tmp_path, monkeypatch, [reply()])
    for command in calls:
        for flag in ("--resume", "--continue", "-c", "--session-id"):
            assert flag not in command


def two_findings():
    """Reuse cannot happen with one call, so the fixture has two."""
    identities = {
        "schema": "alarm-finding-identity/1",
        "findings": [
            {"finding_id": "first", "case_id": "case-a", "member": "safe",
             "file": "a.py", "fingerprint": "aaaa1111",
             "decided_by": "assistant", "decided_on": "2026-09-04",
             "rationale": "one ruling, one finding",
             "evidence_refs": ["corpus-real/adjudications.yml"],
             "rulings": [{"adjudicated_on": "2026-09-02",
                          "fingerprint": "aaaa1111"}]},
            {"finding_id": "second", "case_id": "case-b", "member": "safe",
             "file": "b.py", "fingerprint": "bbbb2222",
             "decided_by": "assistant", "decided_on": "2026-09-04",
             "rationale": "one ruling, one finding",
             "evidence_refs": ["corpus-real/adjudications.yml"],
             "rulings": [{"adjudicated_on": "2026-09-02",
                          "fingerprint": "bbbb2222"}]},
        ],
    }
    rulings = [
        {"case_id": "case-a", "member": "safe", "adjudicated_on": "2026-09-02",
         "fingerprint": "aaaa1111", "file": "a.py", "claim": "the first"},
        {"case_id": "case-b", "member": "safe", "adjudicated_on": "2026-09-02",
         "fingerprint": "bbbb2222", "file": "b.py", "claim": "the second"},
    ]
    return identities, rulings


def run_two(tmp_path, monkeypatch, answers):
    identities, rulings = two_findings()
    path = tmp_path / "identities.yml"
    path.write_text(yaml.safe_dump(identities), encoding="utf-8")
    monkeypatch.setattr(ca.ai, "load_identities", lambda _p: identities)
    monkeypatch.setattr(ca.ai, "alarms_and_rulings",
                        lambda _c: ({"case-a", "case-b"}, rulings))
    fake_run(monkeypatch, answers)
    code = ca.main(["--identities", str(path), "--out", str(tmp_path / "out"),
                    "--seed", "3"])
    body = json.loads((tmp_path / "out" / "codebook.json")
                      .read_text(encoding="utf-8"))
    return code, body


def test_two_codings_that_are_separate_exit_zero(tmp_path, monkeypatch):
    code, body = run_two(tmp_path, monkeypatch,
                         [reply(session="s-a"), reply(session="s-b")])
    assert code == 0
    assert body["identifier_reuse"] is False
    assert body["counts"]["no_coding"] == 0


def test_a_repeated_session_id_is_refused(tmp_path, monkeypatch, capsys):
    """Two findings answered inside one context are not two observations."""
    code, body = run_two(tmp_path, monkeypatch,
                         [reply(session="same"), reply(session="same")])
    assert code == 2
    assert body["sessions_distinct"] is False
    assert body["identifier_reuse"] is True
    assert "share a session id" in capsys.readouterr().err


def test_a_repeated_response_id_is_refused_and_named_differently(
        tmp_path, monkeypatch, capsys):
    """A repeated response id is one answer counted twice — a different
    failure from a shared context, and the message must say which."""
    code, body = run_two(tmp_path, monkeypatch,
                         [reply(session="s-a", requestId="r-shared"),
                          reply(session="s-b", requestId="r-shared")])
    assert code == 2
    assert body["sessions_distinct"] is True
    assert body["responses_distinct"] is False
    assert body["identifier_reuse"] is True
    said = capsys.readouterr().err
    assert "share a response id" in said
    assert "counted twice" in said


def test_a_limited_run_reports_the_denominator_it_asked(tmp_path, monkeypatch):
    """`--limit 1` coded one finding and reported a denominator of twenty.

    Counts over one, presented as a rate over twenty. The full population is
    still recorded, under a name that cannot be mistaken for the denominator.
    Codex, 2026-09-05.
    """
    identities, rulings = two_findings()
    path = tmp_path / "identities.yml"
    path.write_text(yaml.safe_dump(identities), encoding="utf-8")
    monkeypatch.setattr(ca.ai, "load_identities", lambda _p: identities)
    monkeypatch.setattr(ca.ai, "alarms_and_rulings",
                        lambda _c: ({"case-a", "case-b"}, rulings))
    fake_run(monkeypatch, [reply(session="s-a")])
    code = ca.main(["--identities", str(path), "--out", str(tmp_path / "out"),
                    "--seed", "3", "--limit", "1"])
    body = json.loads((tmp_path / "out" / "codebook.json")
                      .read_text(encoding="utf-8"))
    assert code == 0
    assert body["denominator"] == 1
    assert body["population_denominator"] == 2
    assert body["limit"] == 1
    assert len(body["order"]) == 1
    assert len(body["findings"]) == 1
    for dimension in ("alarm_source", "reviewer_error", "confidence"):
        assert sum(body["counts"][dimension].values()) == 1
    assert body["counts"]["no_coding"] == 0


def run_limited(tmp_path, monkeypatch, answers, limit):
    identities, rulings = two_findings()
    path = tmp_path / "identities.yml"
    path.write_text(yaml.safe_dump(identities), encoding="utf-8")
    monkeypatch.setattr(ca.ai, "load_identities", lambda _p: identities)
    monkeypatch.setattr(ca.ai, "alarms_and_rulings",
                        lambda _c: ({"case-a", "case-b"}, rulings))
    calls = fake_run(monkeypatch, answers)
    code = ca.main(["--identities", str(path), "--out", str(tmp_path / "out"),
                    "--seed", "3", "--limit", str(limit)])
    written = tmp_path / "out" / "codebook.json"
    body = json.loads(written.read_text(encoding="utf-8")) \
        if written.exists() else None
    return code, body, calls


def test_a_limit_of_zero_asks_nothing_rather_than_everything(
        tmp_path, monkeypatch):
    """`if args.limit:` made `--limit 0` mean "no limit" — the flag whose only
    purpose is to spend less became the full paid run. Codex, 2026-09-05."""
    code, body, calls = run_limited(tmp_path, monkeypatch,
                                    [reply(session="s-a")], 0)
    assert [c for c in calls if c[:2] != ["grok", "--version"]] == []
    assert body["order"] == []
    assert body["findings"] == {}
    assert body["denominator"] == 0
    assert body["population_denominator"] == 2
    assert code == 0


@pytest.mark.parametrize("limit", [-1, -20])
def test_a_negative_limit_is_refused_before_any_call(
        limit, tmp_path, monkeypatch):
    with pytest.raises(SystemExit) as exit_:
        run_limited(tmp_path, monkeypatch, [reply(session="s-a")], limit)
    assert "negative number of findings" in str(exit_.value)


def test_an_unlimited_run_has_one_denominator_for_both(tmp_path, monkeypatch):
    code, body = run_two(tmp_path, monkeypatch,
                         [reply(session="s-a"), reply(session="s-b")])
    assert code == 0
    assert body["denominator"] == body["population_denominator"] == 2
    assert body["limit"] is None


def test_a_refused_call_still_counts_against_distinctness(
        tmp_path, monkeypatch):
    """The refused call went to the vendor and carries its identifiers.

    Computed over accepted codings only, the artifact said one call compared,
    sessions distinct, no reuse — over two calls that shared a context.
    Codex, 2026-09-05.
    """
    code, body = run_two(tmp_path, monkeypatch,
                         [reply(session="same"),
                          reply(session="same", stopReason="max_turns")])
    assert body["calls_made"] == 2
    assert body["sessions_compared"] == 2
    assert body["sessions_distinct"] is False
    assert body["identifier_reuse"] is True
    assert code == 2


def test_a_call_with_no_id_is_not_counted_as_compared(tmp_path, monkeypatch):
    code, body = run_two(tmp_path, monkeypatch,
                         [reply(session="s-a"),
                          reply(sessionId=None, requestId="r-x")])
    assert body["calls_made"] == 2
    assert body["sessions_compared"] == 1
    assert body["responses_compared"] == 2
    assert body["every_call_compared"] is False
    assert body["identifier_reuse"] is False
    assert code == 2


def test_a_missing_response_id_is_not_covered_by_a_present_session_id(
        tmp_path, monkeypatch):
    """One count stood for two comparisons. Codex, 2026-09-05."""
    code, body = run_two(tmp_path, monkeypatch,
                         [reply(session="s-a"),
                          reply(sessionId="s-b", requestId=None)])
    assert body["calls_made"] == 2
    assert body["sessions_compared"] == 2
    assert body["responses_compared"] == 1
    assert body["every_call_compared"] is False
    assert code == 2


def test_a_call_that_did_not_finish_is_not_counted(tmp_path, monkeypatch):
    """`stopReason` was recorded and never read."""
    code, body = run_two(tmp_path, monkeypatch,
                         [reply(session="s-a"),
                          reply(session="s-b", stopReason="max_turns")])
    assert code == 2
    assert body["counts"]["no_coding"] == 1
    failures = [f.get("failed") or "" for f in body["findings"].values()]
    assert any("rather than finishing its answer" in f for f in failures)


def test_the_command_and_the_prompt_digest_are_recorded(tmp_path, monkeypatch):
    _code, body, _ = run_tool(tmp_path, monkeypatch, [reply()])
    for finding in body["findings"].values():
        assert finding["command"][0] == "grok"
        assert "<prompt>" in finding["command"]
        assert len(finding["prompt_digest"]) == 16
        assert len(finding["ruling_digest"]) == 16
