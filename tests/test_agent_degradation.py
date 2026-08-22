"""What happens when the account cannot use the optional betas.

Task budgets and server-side refusal fallbacks are both requested by default
because they genuinely help this workload. Neither is essential to producing a
review, so an account without them must degrade to a plain request rather than
fail — a scanner that hard-errors on someone else's entitlement is a scanner
that gets deleted from the pipeline.

The other half of the rule matters just as much: a real request error must still
surface. Retrying every 400 with fewer features would turn a genuine bug into a
silent behaviour change.
"""

from pathlib import Path

import anthropic
import pytest

from fakes import FakeClient, FakeResponse, text, tool_use
from security_agent.agent import SecurityAgent, _is_capability_error
from security_agent.config import Config, GitLabContext
from security_agent.models import STOP_COMPLETED, STOP_ERROR
from security_agent.workspace import Workspace

PROMPTS = Path(__file__).resolve().parents[1] / "prompts"


class _Response:
    """The little the SDK reads off a response when building an error.

    Deliberately not an `httpx.Response`: which HTTP library the SDK sits on has
    already changed once (`anthropic` 1.x moved to `httpx2`), and a test that
    imports the wrong one fails for a reason that has nothing to do with the
    behaviour under test.
    """

    status_code = 400
    request = None

    @property
    def headers(self):
        return {}


def bad_request(message):
    return anthropic.BadRequestError(message, response=_Response(), body=None)


@pytest.fixture
def cfg(tmp_path):
    return Config(prompt_dir=PROMPTS, output_dir=tmp_path / "out",
                  gitlab=GitLabContext(), post_comment=False)


@pytest.fixture
def ws(git_repo):
    return Workspace(root=git_repo, excludes=(), diff_base="", diff_head="HEAD")


class TestDegradation:
    def test_falls_back_to_a_plain_request(self, cfg, ws):
        client = FakeClient(
            [FakeResponse([text("Reviewed, nothing found.")], stop_reason="end_turn")],
            beta_error=bad_request("beta task-budgets-2026-03-13 is not available"),
        )
        outcome = SecurityAgent(cfg, ws, client=client).run("repo", "go")

        assert outcome.stop_reason == STOP_COMPLETED
        assert outcome.summary == "Reviewed, nothing found."
        assert [r["beta"] for r in client.requests] == [True, False]

    def test_the_retry_drops_the_task_budget(self, cfg, ws):
        client = FakeClient(
            [FakeResponse([text("done")], stop_reason="end_turn")],
            beta_error=bad_request("task_budget is not supported"),
        )
        SecurityAgent(cfg, ws, client=client).run("repo", "go")

        retry = client.requests[1]["params"]
        assert "task_budget" not in retry["output_config"]
        assert "betas" not in retry
        assert "fallbacks" not in retry

    def test_later_turns_do_not_retry_the_betas(self, cfg, ws):
        # Degradation is sticky for the run: re-probing every turn would double
        # the request count on an account that will never have the entitlement.
        client = FakeClient(
            [FakeResponse([tool_use("git_log", {}, id="t1")], stop_reason="tool_use"),
             FakeResponse([text("done")], stop_reason="end_turn")],
            beta_error=bad_request("beta not enabled for this organization"),
        )
        SecurityAgent(cfg, ws, client=client).run("repo", "go")

        assert [r["beta"] for r in client.requests] == [True, False, False]

    def test_the_review_still_produces_findings_after_degrading(self, cfg, ws):
        finding = {
            "title": "SQL injection in get_user", "severity": "high",
            "confidence": "high", "category": "injection", "file": "app/views.py",
            "line": 3,
            "evidence": 'return db.execute("SELECT * FROM users WHERE id = " + user_id)',
            "description": "Concatenated query.",
            "exploit_scenario": "An anonymous caller sends ?id=1 OR 1=1.",
            "recommendation": "Parameterise it.",
        }
        client = FakeClient(
            [FakeResponse([tool_use("report_finding", finding, id="t1")],
                          stop_reason="tool_use"),
             FakeResponse([text("One finding.")], stop_reason="end_turn")],
            beta_error=bad_request("beta not available"),
        )
        agent = SecurityAgent(cfg, ws, client=client)
        agent.run("repo", "go")

        assert len(agent.candidates) == 1


class TestRealErrorsStillSurface:
    def test_a_genuine_bad_request_is_not_retried_away(self, cfg, ws):
        client = FakeClient(
            [FakeResponse([text("never reached")], stop_reason="end_turn")],
            beta_error=bad_request("messages.0.content.0: field required"),
        )
        outcome = SecurityAgent(cfg, ws, client=client).run("repo", "go")

        assert outcome.stop_reason == STOP_ERROR
        assert "field required" in outcome.stop_detail
        assert len(client.requests) == 1  # no retry

    def test_an_incomplete_run_from_an_api_error_is_not_a_pass(self, cfg, ws):
        client = FakeClient(
            [FakeResponse([text("x")], stop_reason="end_turn")],
            beta_error=bad_request("messages: invalid"),
        )
        outcome = SecurityAgent(cfg, ws, client=client).run("repo", "go")
        assert not outcome.complete


class TestCapabilityErrorDetection:
    @pytest.mark.parametrize("message", [
        "beta task-budgets-2026-03-13 is not available",
        "The beta header server-side-fallback-2026-07-01 is not enabled",
        "task_budget: unsupported parameter",
        "fallbacks: unexpected value",
        "unrecognized beta flag",
    ])
    def test_capability_complaints_are_recognised(self, message):
        assert _is_capability_error(bad_request(message))

    @pytest.mark.parametrize("message", [
        "messages.0.content.0: field required",
        "max_tokens must be greater than thinking budget",
        "model: claude-nonexistent-9 not found",
    ])
    def test_request_errors_are_not(self, message):
        assert not _is_capability_error(bad_request(message))


class TestDisablingBetasUpFront:
    def test_no_beta_endpoint_is_used_when_both_are_off(self, cfg, ws):
        cfg.use_task_budget = False
        cfg.use_refusal_fallback = False
        client = FakeClient([FakeResponse([text("done")], stop_reason="end_turn")])
        SecurityAgent(cfg, ws, client=client).run("repo", "go")

        assert client.requests[0]["beta"] is False

    def test_the_fallback_alone_still_uses_the_beta_endpoint(self, cfg, ws):
        cfg.use_task_budget = False
        client = FakeClient([FakeResponse([text("done")], stop_reason="end_turn")])
        SecurityAgent(cfg, ws, client=client).run("repo", "go")

        params = client.requests[0]["params"]
        assert client.requests[0]["beta"] is True
        assert params["fallbacks"] == "default"
        assert "task_budget" not in params["output_config"]


class TestTransientFailures:
    """A dropped stream must not destroy the run.

    The SDK retries a connection that fails while a request is *starting*. It
    does not help once bytes are flowing: a stream that dies mid-read surfaces
    as a raw `httpx.ReadError`, which is not an `anthropic` exception at all.
    Before this was handled, one reset packet threw away every turn taken and
    every token paid for.
    """

    def test_a_mid_stream_read_error_is_retried(self, cfg, ws, monkeypatch):
        import security_agent.transport as transport

        monkeypatch.setattr(transport.time, "sleep", lambda _: None)
        calls = {"n": 0}
        real = FakeClient([FakeResponse([text("recovered")], stop_reason="end_turn")])

        class Flaky:
            def __init__(self):
                self.beta = real.beta
                self.messages = self

            def stream(self, **params):
                calls["n"] += 1
                if calls["n"] == 1:
                    raise ConnectionResetError(54, "Connection reset by peer")
                return real.messages.stream(**params)

        cfg.use_task_budget = False
        cfg.use_refusal_fallback = False
        outcome = SecurityAgent(cfg, ws, client=Flaky()).run("repo", "go")

        assert calls["n"] == 2
        assert outcome.stop_reason == STOP_COMPLETED
        assert outcome.summary == "recovered"

    def test_persistent_failure_becomes_a_recognised_api_error(self, cfg, ws, monkeypatch):
        import security_agent.transport as transport

        monkeypatch.setattr(transport.time, "sleep", lambda _: None)

        class Dead:
            def __init__(self):
                self.messages = self

            def stream(self, **params):
                raise ConnectionError("no route to host")

        cfg.use_task_budget = False
        cfg.use_refusal_fallback = False
        outcome = SecurityAgent(cfg, ws, client=Dead()).run("repo", "go")

        # Classified, not crashed: the loop already knows how to report this.
        assert outcome.stop_reason == STOP_ERROR
        assert "could not reach the Claude API" in outcome.stop_detail
        assert not outcome.complete

    def test_a_bad_request_is_not_retried(self, cfg, ws, monkeypatch):
        import security_agent.transport as transport

        monkeypatch.setattr(transport.time, "sleep", lambda _: None)
        calls = {"n": 0}

        class Rejecting:
            def __init__(self):
                self.messages = self

            def stream(self, **params):
                calls["n"] += 1
                raise bad_request("messages.0: field required")

        cfg.use_task_budget = False
        cfg.use_refusal_fallback = False
        SecurityAgent(cfg, ws, client=Rejecting()).run("repo", "go")
        assert calls["n"] == 1  # spending money to get the same 400 helps nobody
