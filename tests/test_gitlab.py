"""Tests for posting the review back to the merge request.

Two behaviours carry weight here. The note must be *edited* rather than
re-posted, or a branch with ten pushes buries the discussion under ten copies of
the same report. And a failure to comment must never change the pipeline
verdict — a scan that passes because the API was unreachable is a hole.
"""

import pytest
import requests

from security_agent.config import GitLabContext
from security_agent.gitlab import MAX_NOTE_CHARS, GitLabClient, GitLabError, publish
from security_agent.report import COMMENT_MARKER


class FakeResponse:
    def __init__(self, status_code=200, payload=None, text=""):
        self.status_code = status_code
        self._payload = payload if payload is not None else {}
        self.text = text
        self.content = b"x" if payload is not None else b""

    def json(self):
        return self._payload


class FakeSession:
    """Records requests and replays scripted responses."""

    def __init__(self, responses=None, raise_on=None):
        self.headers = {}
        self.calls = []
        self.responses = list(responses or [])
        self.raise_on = raise_on

    def request(self, method, url, timeout=None, **kwargs):
        self.calls.append({"method": method, "url": url, **kwargs})
        if self.raise_on and self.raise_on in method:
            raise requests.RequestException("connection reset")
        if self.responses:
            return self.responses.pop(0)
        return FakeResponse(200, {"id": 99})


def context(**overrides):
    values = {
        "api_url": "https://gitlab.example.com/api/v4",
        "project_id": "7",
        "token": "glpat-test",
        "mr_iid": "42",
    }
    values.update(overrides)
    return GitLabContext(**values)


class TestCreatingAndUpdating:
    def test_creates_a_note_when_none_exists(self):
        session = FakeSession([
            FakeResponse(200, []),            # notes listing: empty
            FakeResponse(200, {"id": 500}),   # POST
        ])
        result = GitLabClient(context(), session=session).post_or_update_note("body")

        assert "created" in result
        assert session.calls[-1]["method"] == "POST"

    def test_updates_its_own_previous_note(self):
        session = FakeSession([
            FakeResponse(200, [
                {"id": 1, "body": "unrelated review comment"},
                {"id": 2, "body": COMMENT_MARKER + "\n## previous report"},
            ]),
            FakeResponse(200, {"id": 2}),
        ])
        result = GitLabClient(context(), session=session).post_or_update_note("new body")

        assert "updated note 2" in result
        assert session.calls[-1]["method"] == "PUT"
        assert session.calls[-1]["url"].endswith("/notes/2")

    def test_never_touches_a_note_it_did_not_write(self):
        session = FakeSession([
            FakeResponse(200, [{"id": 1, "body": "Looks good to me"}]),
            FakeResponse(200, {"id": 500}),
        ])
        GitLabClient(context(), session=session).post_or_update_note("body")
        assert session.calls[-1]["method"] == "POST"

    def test_ignores_system_notes(self):
        # GitLab's own "added 3 commits" notes must never be mistaken for ours.
        session = FakeSession([
            FakeResponse(200, [{"id": 1, "body": COMMENT_MARKER, "system": True}]),
            FakeResponse(200, {"id": 500}),
        ])
        GitLabClient(context(), session=session).post_or_update_note("body")
        assert session.calls[-1]["method"] == "POST"

    def test_sends_the_token_as_a_private_header(self):
        session = FakeSession([FakeResponse(200, []), FakeResponse(200, {"id": 1})])
        GitLabClient(context(), session=session)
        assert session.headers["PRIVATE-TOKEN"] == "glpat-test"


class TestErrorMapping:
    @pytest.mark.parametrize("status,expected", [
        (401, "CI_JOB_TOKEN cannot create"),
        (403, "`api` scope"),
        (404, "not found"),
    ])
    def test_http_errors_become_actionable_messages(self, status, expected):
        # The person reading a red job log needs to know which token to fix.
        session = FakeSession([FakeResponse(status, None, "denied")])
        with pytest.raises(GitLabError, match=expected):
            GitLabClient(context(), session=session).post_or_update_note("body")

    def test_a_network_failure_is_wrapped(self):
        session = FakeSession(raise_on="GET")
        with pytest.raises(GitLabError, match="connection reset"):
            GitLabClient(context(), session=session).post_or_update_note("body")

    def test_an_unexpected_status_is_reported_with_its_body(self):
        session = FakeSession([FakeResponse(500, None, "upstream exploded")])
        with pytest.raises(GitLabError, match="upstream exploded"):
            GitLabClient(context(), session=session).post_or_update_note("body")


class TestClipping:
    def test_a_long_report_is_trimmed_with_a_pointer_to_the_artifact(self):
        session = FakeSession([FakeResponse(200, []), FakeResponse(200, {"id": 1})])
        body = "line\n" * (MAX_NOTE_CHARS // 2)
        GitLabClient(context(), session=session).post_or_update_note(body)

        sent = session.calls[-1]["json"]["body"]
        assert len(sent) <= MAX_NOTE_CHARS + 200
        assert "job artifacts" in sent


class TestPublishGuards:
    def test_skips_outside_a_merge_request(self, caplog):
        assert publish(context(mr_iid=""), "body") is None

    def test_skips_without_a_token(self):
        assert publish(context(token=""), "body") is None

    def test_skips_with_an_incomplete_context(self):
        assert publish(context(api_url=""), "body") is None

    def test_an_api_failure_does_not_raise(self, monkeypatch):
        # The caller's exit code belongs to the findings, not to whether GitLab
        # happened to be reachable.
        def boom(self, body):
            raise GitLabError("gitlab is down")

        monkeypatch.setattr(GitLabClient, "post_or_update_note", boom)
        assert publish(context(), "body") is None
