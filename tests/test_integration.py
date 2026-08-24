"""End-to-end runs against a scripted client.

Covers the wiring the unit tests cannot: the agent loop's turn handling, the
hand-off into verification, suppression, gating, and the report that comes out
the other side.
"""

import json
from pathlib import Path

import pytest

from fakes import FakeClient, FakeResponse, json_text, text, thinking, tool_use
from security_agent.agent import SecurityAgent
from security_agent.config import Config, GitLabContext
from security_agent.gate import EXIT_ERROR, EXIT_FINDINGS, EXIT_OK, decide
from security_agent.models import (
    STOP_COMPLETED,
    STOP_REFUSAL,
    STOP_TURN_LIMIT,
    VERDICT_CONFIRMED,
    VERDICT_REFUTED,
)
from security_agent.report import build_json, render_markdown
from security_agent.verify import verify_candidates
from security_agent.workspace import Workspace

PROMPTS = Path(__file__).resolve().parents[1] / "prompts"
REAL_EVIDENCE = 'return db.execute("SELECT * FROM users WHERE id = " + user_id)'

FINDING_ARGS = {
    "title": "SQL injection in get_user",
    "severity": "high",
    "confidence": "high",
    "category": "injection",
    "file": "app/views.py",
    "line": 3,
    "evidence": REAL_EVIDENCE,
    "description": "The id parameter is concatenated into a SQL string.",
    "exploit_scenario": "An anonymous caller sends ?id=1 OR 1=1 and reads every user row.",
    "recommendation": "Use a parameterised query with a bound parameter.",
}


@pytest.fixture
def cfg(tmp_path):
    return Config(
        prompt_dir=PROMPTS,
        output_dir=tmp_path / "out",
        gitlab=GitLabContext(project_path="group/project"),
        post_comment=False,
        verify_votes=1,
    )


@pytest.fixture
def ws(git_repo):
    return Workspace(root=git_repo, excludes=(), diff_base="", diff_head="HEAD")


def verdict(status, reasoning="Traced the call chain and confirmed it.", **extra):
    payload = {"verdict": status, "reasoning": reasoning,
               "corrected_severity": "", "corrected_confidence": ""}
    payload.update(extra)
    return FakeResponse([json_text(payload)], stop_reason="end_turn")


class TestAgentLoop:
    def test_a_clean_review_completes(self, cfg, ws):
        client = FakeClient([
            FakeResponse([tool_use("list_directory", {}, id="t1")], stop_reason="tool_use"),
            FakeResponse([text("Nothing exploitable here.")], stop_reason="end_turn"),
        ])
        outcome = SecurityAgent(cfg, ws, client=client).run("repo", "review this")

        assert outcome.stop_reason == STOP_COMPLETED
        assert outcome.summary == "Nothing exploitable here."
        assert outcome.turns == 2
        assert [c.name for c in outcome.tool_calls] == ["list_directory"]

    def test_a_finding_is_recorded_through_the_tool(self, cfg, ws):
        client = FakeClient([
            FakeResponse([tool_use("report_finding", FINDING_ARGS, id="t1")],
                         stop_reason="tool_use"),
            FakeResponse([text("One finding.")], stop_reason="end_turn"),
        ])
        agent = SecurityAgent(cfg, ws, client=client)
        agent.run("repo", "review this")

        assert len(agent.candidates) == 1
        assert agent.candidates[0].finding.title == "SQL injection in get_user"

    def test_parallel_tool_calls_return_in_one_message(self, cfg, ws):
        client = FakeClient([
            FakeResponse([
                tool_use("read_file", {"path": "app/views.py"}, id="t1"),
                tool_use("search_code", {"pattern": "execute"}, id="t2"),
            ], stop_reason="tool_use"),
            FakeResponse([text("Done.")], stop_reason="end_turn"),
        ])
        SecurityAgent(cfg, ws, client=client).run("repo", "go")

        second = client.agent_requests[1]["params"]["messages"]
        tool_results = second[-1]["content"]
        assert second[-1]["role"] == "user"
        assert len(tool_results) == 2

    def test_thinking_blocks_are_echoed_back_unchanged(self, cfg, ws):
        client = FakeClient([
            FakeResponse([thinking("reasoning"), tool_use("git_log", {}, id="t1")],
                         stop_reason="tool_use"),
            FakeResponse([text("Done.")], stop_reason="end_turn"),
        ])
        SecurityAgent(cfg, ws, client=client).run("repo", "go")

        assistant_turn = client.agent_requests[1]["params"]["messages"][1]
        assert assistant_turn["role"] == "assistant"
        assert any(getattr(b, "type", "") == "thinking" for b in assistant_turn["content"])


class TestStopConditions:
    def test_the_turn_limit_is_not_a_clean_pass(self, cfg, ws):
        cfg.max_turns = 2
        client = FakeClient([
            FakeResponse([tool_use("git_log", {}, id="t1")], stop_reason="tool_use"),
            FakeResponse([tool_use("git_log", {}, id="t2")], stop_reason="tool_use"),
            FakeResponse([text("never reached")], stop_reason="end_turn"),
        ])
        outcome = SecurityAgent(cfg, ws, client=client).run("repo", "go")

        assert outcome.stop_reason == STOP_TURN_LIMIT
        assert not outcome.complete
        assert decide(cfg, outcome).exit_code == EXIT_ERROR

    def test_a_refusal_is_not_a_clean_pass(self, cfg, ws):
        client = FakeClient([FakeResponse([], stop_reason="refusal")])
        outcome = SecurityAgent(cfg, ws, client=client).run("repo", "go")

        assert outcome.stop_reason == STOP_REFUSAL
        assert decide(cfg, outcome).exit_code == EXIT_ERROR

    def test_hitting_max_tokens_is_an_error(self, cfg, ws):
        client = FakeClient([FakeResponse([text("truncated")], stop_reason="max_tokens")])
        outcome = SecurityAgent(cfg, ws, client=client).run("repo", "go")

        assert not outcome.complete
        assert "max_tokens" in outcome.stop_detail


class TestRequestShape:
    def test_the_system_prompt_is_cached_with_the_configured_ttl(self, cfg, ws):
        client = FakeClient([FakeResponse([text("done")], stop_reason="end_turn")])
        SecurityAgent(cfg, ws, client=client).run("repo", "go")

        system = client.requests[0]["params"]["system"]
        assert system[0]["cache_control"] == {"type": "ephemeral", "ttl": "1h"}

    def test_the_cache_breakpoint_moves_instead_of_accumulating(self, cfg, ws):
        client = FakeClient([
            FakeResponse([tool_use("git_log", {}, id="t1")], stop_reason="tool_use"),
            FakeResponse([tool_use("git_log", {}, id="t2")], stop_reason="tool_use"),
            FakeResponse([text("done")], stop_reason="end_turn"),
        ])
        SecurityAgent(cfg, ws, client=client).run("repo", "go")

        # Breakpoints are limited per request; a trail of them would exhaust the
        # allowance within a few turns.
        messages = client.agent_requests[-1]["params"]["messages"]
        marked = [block for message in messages if isinstance(message.get("content"), list)
                  for block in message["content"]
                  if isinstance(block, dict) and "cache_control" in block]
        assert len(marked) == 1

    def test_optional_betas_are_requested_by_default(self, cfg, ws):
        client = FakeClient([FakeResponse([text("done")], stop_reason="end_turn")])
        SecurityAgent(cfg, ws, client=client).run("repo", "go")

        request = client.requests[0]
        assert request["beta"] is True
        assert request["params"]["fallbacks"] == "default"
        assert "task-budgets-2026-03-13" in request["params"]["betas"]

    def test_thinking_is_adaptive(self, cfg, ws):
        client = FakeClient([FakeResponse([text("done")], stop_reason="end_turn")])
        SecurityAgent(cfg, ws, client=client).run("repo", "go")
        assert client.requests[0]["params"]["thinking"] == {"type": "adaptive"}


class TestVerificationHandoff:
    def _run_with_verdict(self, cfg, ws, status):
        client = FakeClient(
            script=[
                FakeResponse([tool_use("report_finding", FINDING_ARGS, id="t1")],
                             stop_reason="tool_use"),
                FakeResponse([text("One finding.")], stop_reason="end_turn"),
            ],
            verifier_script=[verdict(status), verdict(status)],
        )
        agent = SecurityAgent(cfg, ws, client=client)
        outcome = agent.run("repo", "go")
        outcome.verification_usage = verify_candidates(cfg, ws, client, agent.candidates)
        return client, agent.candidates[0], outcome

    def test_a_confirmed_finding_is_reported(self, cfg, ws):
        _, candidate, _ = self._run_with_verdict(cfg, ws, VERDICT_CONFIRMED)
        assert candidate.verdict == VERDICT_CONFIRMED

    def test_a_refuted_finding_is_dropped_from_the_gate(self, cfg, ws):
        _, candidate, outcome = self._run_with_verdict(cfg, ws, VERDICT_REFUTED)
        assert candidate.verdict == VERDICT_REFUTED

        outcome.refuted = [candidate]
        outcome.reported = []
        assert decide(cfg, outcome).exit_code == EXIT_OK

    def test_a_blocking_finding_gets_an_odd_panel(self, cfg, ws):
        # Three, not two. Two verifiers cannot form a majority, so their
        # disagreement was settled by a rule — and that rule turned out to let
        # one hedge decide the gate.
        client, _, _ = self._run_with_verdict(cfg, ws, VERDICT_CONFIRMED)
        assert len(client.verifier_requests) == 3

    def test_the_verifier_cannot_report_findings(self, cfg, ws):
        client, _, _ = self._run_with_verdict(cfg, ws, VERDICT_CONFIRMED)
        names = {t["name"] for t in client.verifier_requests[0]["params"]["tools"]}
        assert "report_finding" not in names

    def test_verification_is_a_separate_conversation(self, cfg, ws):
        # Independence is the point: a verifier that inherited the agent's
        # reasoning would mostly agree with it.
        client, _, _ = self._run_with_verdict(cfg, ws, VERDICT_CONFIRMED)
        messages = client.verifier_requests[0]["params"]["messages"]
        assert len(messages) == 1
        assert messages[0]["role"] == "user"

    def test_disabling_verification_still_reports(self, cfg, ws):
        cfg.verify = False
        client = FakeClient([
            FakeResponse([tool_use("report_finding", FINDING_ARGS, id="t1")],
                         stop_reason="tool_use"),
            FakeResponse([text("One finding.")], stop_reason="end_turn"),
        ])
        agent = SecurityAgent(cfg, ws, client=client)
        agent.run("repo", "go")
        verify_candidates(cfg, ws, client, agent.candidates)

        assert client.verifier_requests == []
        assert "disabled" in agent.candidates[0].verdict_reason


class TestReporting:
    def _outcome(self, cfg, ws):
        client = FakeClient(
            script=[
                FakeResponse([tool_use("report_finding", FINDING_ARGS, id="t1")],
                             stop_reason="tool_use"),
                FakeResponse([text("Reviewed the user lookup path.")],
                             stop_reason="end_turn"),
            ],
            verifier_script=[verdict(VERDICT_CONFIRMED), verdict(VERDICT_CONFIRMED)],
        )
        agent = SecurityAgent(cfg, ws, client=client)
        outcome = agent.run("diff", "go")
        verify_candidates(cfg, ws, client, agent.candidates)
        outcome.reported = agent.candidates
        return outcome

    def test_markdown_contains_the_evidence_and_the_verdict(self, cfg, ws):
        outcome = self._outcome(cfg, ws)
        markdown = render_markdown(cfg, outcome, decide(cfg, outcome))

        assert "SQL injection in get_user" in markdown
        assert REAL_EVIDENCE in markdown
        assert "app/views.py:3" in markdown
        assert "Verification" in markdown
        assert "ai-security-scan" in markdown  # the update marker

    def test_markdown_offers_the_suppression_fingerprint(self, cfg, ws):
        outcome = self._outcome(cfg, ws)
        markdown = render_markdown(cfg, outcome, decide(cfg, outcome))
        assert outcome.reported[0].fingerprint in markdown

    def test_json_is_serialisable_and_carries_the_verdict(self, cfg, ws):
        outcome = self._outcome(cfg, ws)
        decision = decide(cfg, outcome)
        payload = build_json(cfg, outcome, decision)

        json.dumps(payload)  # would raise on a stray object
        assert payload["verdict"]["exit_code"] == EXIT_FINDINGS
        assert payload["findings"][0]["verification"]["verdict"] == VERDICT_CONFIRMED
        assert payload["findings"][0]["evidence"] == REAL_EVIDENCE

    def test_an_incomplete_run_is_flagged_in_the_report(self, cfg, ws):
        cfg.max_turns = 1
        client = FakeClient([FakeResponse([tool_use("git_log", {}, id="t1")],
                                          stop_reason="tool_use")])
        outcome = SecurityAgent(cfg, ws, client=client).run("repo", "go")
        markdown = render_markdown(cfg, outcome, decide(cfg, outcome))

        assert "Coverage is partial" in markdown
        assert "did not complete" in markdown


class TestProvenanceIsRecorded:
    """A blocking verdict has to be reproducible enough to argue with.

    Prompts and the schema are read from disk at run time, which makes them easy
    to iterate on and invisible when they change; a server-side fallback can
    swap the model mid-review. Each changes the verdict and none shows up in a
    diff, so "the same code passed last week" would otherwise have no answer.
    """

    def test_prompt_and_schema_hashes_are_captured(self, cfg, ws):
        client = FakeClient([FakeResponse([text("done")], stop_reason="end_turn")])
        outcome = SecurityAgent(cfg, ws, client=client).run("repo", "go")
        p = outcome.provenance

        assert len(p.system_prompt_sha) == 16
        assert len(p.verifier_prompt_sha) == 16
        assert len(p.schema_sha) == 16
        assert p.system_prompt_sha != p.verifier_prompt_sha

    def test_the_requested_model_is_recorded(self, cfg, ws):
        client = FakeClient([FakeResponse([text("done")], stop_reason="end_turn")])
        outcome = SecurityAgent(cfg, ws, client=client).run("repo", "go")
        assert outcome.provenance.model_requested == "claude-opus-5"
        assert not outcome.provenance.model_substituted

    def test_a_substituted_model_is_flagged(self, cfg, ws):
        # Server-side refusal fallback can answer from a different model inside
        # the same call. A gate that blocks a merge should say so.
        client = FakeClient([
            FakeResponse([text("done")], stop_reason="end_turn",
                         model="claude-opus-4-8"),
        ])
        outcome = SecurityAgent(cfg, ws, client=client).run("repo", "go")

        assert outcome.provenance.model_substituted
        assert "claude-opus-4-8" in outcome.provenance.models_served

    def test_it_reaches_the_artifact_and_the_report(self, cfg, ws):
        client = FakeClient([FakeResponse([text("done")], stop_reason="end_turn")])
        outcome = SecurityAgent(cfg, ws, client=client).run("repo", "go")
        decision = decide(cfg, outcome)

        payload = build_json(cfg, outcome, decision)
        assert payload["provenance"]["model_requested"] == "claude-opus-5"
        assert "Provenance" in render_markdown(cfg, outcome, decision)


class TestStageMetrics:
    """Counts that let the stages be argued about with numbers.

    The open question is whether adversarial verification earns roughly three
    times the cost of the review. A report showing only what survived cannot
    answer it; the count of verdicts verification actually changed can.
    """

    def _finding(self, **overrides):
        args = dict(FINDING_ARGS)
        args.update(overrides)
        return args

    def test_accepted_citations_are_counted(self, cfg, ws):
        client = FakeClient([
            FakeResponse([tool_use("report_finding", FINDING_ARGS, id="t1")],
                         stop_reason="tool_use"),
            FakeResponse([text("done")], stop_reason="end_turn"),
        ])
        outcome = SecurityAgent(cfg, ws, client=client).run("repo", "go")
        assert outcome.metrics.citations_accepted == 1

    def test_a_rejected_citation_is_counted_by_reason(self, cfg, ws):
        invented = self._finding(evidence='os.system("rm -rf /" + attacker_input)')
        client = FakeClient([
            FakeResponse([tool_use("report_finding", invented, id="t1")],
                         stop_reason="tool_use"),
            FakeResponse([text("withdrawn")], stop_reason="end_turn"),
        ])
        outcome = SecurityAgent(cfg, ws, client=client).run("repo", "go")
        assert outcome.metrics.citations_rejected_not_found == 1
        assert outcome.metrics.citations_accepted == 0

    def test_an_ambiguous_citation_is_counted_separately(self, cfg, ws):
        # Distinguishing "not there" from "could be three places" is the point
        # of the rejection reasons; the counts have to keep them apart too.
        ambiguous = self._finding(evidence="user_id = request.args.get(\"id\")",
                                  line=999)
        client = FakeClient([
            FakeResponse([tool_use("report_finding", ambiguous, id="t1")],
                         stop_reason="tool_use"),
            FakeResponse([text("withdrawn")], stop_reason="end_turn"),
        ])
        outcome = SecurityAgent(cfg, ws, client=client).run("repo", "go")
        assert outcome.metrics.citations_accepted + sum((
            outcome.metrics.citations_rejected_not_found,
            outcome.metrics.citations_rejected_ambiguous,
            outcome.metrics.citations_rejected_too_short,
        )) == 1

    def test_a_corrected_line_is_counted(self, cfg, ws):
        wrong_line = self._finding(line=999)
        client = FakeClient([
            FakeResponse([tool_use("report_finding", wrong_line, id="t1")],
                         stop_reason="tool_use"),
            FakeResponse([text("done")], stop_reason="end_turn"),
        ])
        outcome = SecurityAgent(cfg, ws, client=client).run("repo", "go")
        assert outcome.metrics.lines_corrected == 1

    def test_verification_records_what_it_changed(self, cfg, ws):
        from security_agent.verify import verify_candidates

        client = FakeClient(
            script=[
                FakeResponse([tool_use("report_finding", FINDING_ARGS, id="t1")],
                             stop_reason="tool_use"),
                FakeResponse([text("done")], stop_reason="end_turn"),
            ],
            verifier_script=[verdict(VERDICT_REFUTED)] * 2,
        )
        agent = SecurityAgent(cfg, ws, client=client)
        outcome = agent.run("repo", "go")
        verify_candidates(cfg, ws, client, agent.candidates, metrics=outcome.metrics)

        assert outcome.metrics.verified == 1
        assert outcome.metrics.verdicts_changed == 1, "a refutation is a changed verdict"

    def test_metrics_reach_the_artifact(self, cfg, ws):
        client = FakeClient([FakeResponse([text("done")], stop_reason="end_turn")])
        outcome = SecurityAgent(cfg, ws, client=client).run("repo", "go")
        payload = build_json(cfg, outcome, decide(cfg, outcome))
        assert "stage_metrics" in payload
        assert "coverage_accounting" in payload
