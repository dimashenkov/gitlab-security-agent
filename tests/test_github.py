"""Posting the review to a pull request, and detecting which forge this is.

The GitLab path has been exercised by a real pipeline for days. This one has
not, so the tests carry the weight — and the properties that matter are the
ones shared with GitLab rather than anything GitHub-specific: one comment
edited in place, never a second; a failure to post never touches the exit code;
and a comment the agent did not write is never edited.
"""

from __future__ import annotations

import json

import pytest

from security_agent.config import ForgeContext
from security_agent.forge import publish as dispatch
from security_agent.github import GitHubClient, GitHubError, _clip, publish
from security_agent.report import COMMENT_MARKER


class FakeResponse:
    def __init__(self, status=200, payload=None, text=""):
        self.status_code = status
        self._payload = payload if payload is not None else {}
        self.text = text
        self.content = b"x" if payload is not None or text else b""

    def json(self):
        return self._payload


class FakeSession:
    """Records every request and replays a scripted set of responses."""

    def __init__(self, script=None):
        self.headers = {}
        self.calls = []
        self.script = list(script or [])

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        if self.script:
            return self.script.pop(0)
        return FakeResponse(payload={"id": 99})


def ctx(**overrides) -> ForgeContext:
    body = dict(kind="github", api_url="https://api.github.com",
                project_id="o/r", project_path="o/r", token="t", mr_iid="7")
    body.update(overrides)
    return ForgeContext(**body)


# ------------------------------------------------------------------ posting


def test_a_first_run_creates_one_comment():
    session = FakeSession([FakeResponse(payload=[]),
                           FakeResponse(payload={"id": 42})])
    result = GitHubClient(ctx(), session).post_or_update_note("body")

    assert result == "created comment 42"
    methods = [call[0] for call in session.calls]
    assert methods == ["GET", "POST"]


def test_a_second_run_edits_the_first_comment_rather_than_adding_one():
    """A pipeline that appends on every push buries the discussion under its
    own output, and reviewers stop reading any of it."""
    session = FakeSession([
        FakeResponse(payload=[{"id": 5, "body": "unrelated"},
                              {"id": 6, "body": COMMENT_MARKER + "\nold"}]),
        FakeResponse(payload={"id": 6}),
    ])
    result = GitHubClient(ctx(), session).post_or_update_note("new")

    assert result == "updated comment 6"
    method, url, kwargs = session.calls[1]
    assert method == "PATCH"
    assert url.endswith("/issues/comments/6")
    assert kwargs["json"]["body"] == "new"


def test_a_comment_the_agent_did_not_write_is_never_touched():
    """Matched on the marker, not the author: the token can change between
    runs, and nothing else in the thread may be edited."""
    session = FakeSession([FakeResponse(payload=[{"id": 5, "body": "a human wrote this"}]),
                           FakeResponse(payload={"id": 9})])
    GitHubClient(ctx(), session).post_or_update_note("body")

    assert [call[0] for call in session.calls] == ["GET", "POST"]


def test_it_posts_to_the_issues_endpoint_not_the_pull_one():
    """Pull comments are review comments, anchored to a diff line. This is a
    summary and belongs on the issue thread."""
    session = FakeSession([FakeResponse(payload=[]), FakeResponse(payload={"id": 1})])
    GitHubClient(ctx(), session).post_or_update_note("body")

    assert "/issues/7/comments" in session.calls[1][1]
    assert "/pulls/" not in session.calls[1][1]


# ------------------------------------------------------------------- errors


@pytest.mark.parametrize("status,expected", [
    (401, "SECURITY_SCAN_GITHUB_TOKEN"),
    (403, "pull-requests: write"),
    (404, "not found"),
])
def test_each_refusal_says_what_to_fix(status, expected):
    session = FakeSession([FakeResponse(status=status, text="no")])
    with pytest.raises(GitHubError) as caught:
        GitHubClient(ctx(), session).post_or_update_note("body")
    assert expected in str(caught.value)


def test_a_failure_to_post_is_swallowed_not_raised(monkeypatch):
    """The exit code belongs to the findings. A review that found something and
    could not say so is still a review that found something."""
    def explode(self, body):
        raise GitHubError("GitHub is down")

    monkeypatch.setattr(GitHubClient, "post_or_update_note", explode)
    assert publish(ctx(), "body") is None      # and no exception escapes


def test_the_client_itself_does_raise_so_the_publisher_can_decide():
    """Swallowing belongs in one place. A client that hid its own errors would
    leave nothing able to tell a missing comment from a posted one."""
    session = FakeSession([FakeResponse(status=500, text="down")])
    with pytest.raises(GitHubError):
        GitHubClient(ctx(), session).post_or_update_note("body")


@pytest.mark.parametrize("missing", ["token", "mr_iid", "project_path"])
def test_an_incomplete_context_skips_rather_than_fails(missing):
    assert publish(ctx(**{missing: ""}), "body") is None


def test_a_long_report_is_trimmed_with_a_pointer_to_the_artifact():
    trimmed = _clip("line\n" * 40_000)
    assert len(trimmed) < 61_000
    assert "complete report is in the run artifacts" in trimmed


# ---------------------------------------------------------------- detection


def test_a_github_actions_environment_is_detected(monkeypatch, tmp_path):
    event = tmp_path / "event.json"
    event.write_text(json.dumps({
        "pull_request": {"number": 12, "title": "Add a handler",
                         "body": "why", "labels": [{"name": "security"}],
                         "base": {"sha": "b" * 40}, "head": {"sha": "h" * 40}},
        "repository": {"default_branch": "trunk"},
    }))
    for name, value in (("GITHUB_ACTIONS", "true"), ("GITHUB_REPOSITORY", "o/r"),
                        ("GITHUB_EVENT_PATH", str(event)),
                        ("GITHUB_HEAD_REF", "feature"), ("GITHUB_BASE_REF", "trunk"),
                        ("GITHUB_SERVER_URL", "https://github.com"),
                        ("GITHUB_RUN_ID", "555"), ("GITHUB_SHA", "h" * 40)):
        monkeypatch.setenv(name, value)

    forge = ForgeContext.from_env()
    assert forge.kind == "github"
    assert forge.mr_iid == "12" and forge.is_merge_request
    assert forge.mr_title == "Add a handler"
    assert forge.mr_labels == ["security"]
    assert forge.diff_base_sha == "b" * 40
    assert forge.default_branch == "trunk"
    assert forge.job_url == "https://github.com/o/r/actions/runs/555"


def test_the_pull_number_falls_back_to_the_ref(monkeypatch):
    """`GITHUB_EVENT_PATH` is not always readable, and `refs/pull/N/merge` is."""
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_REPOSITORY", "o/r")
    monkeypatch.setenv("GITHUB_REF", "refs/pull/34/merge")
    monkeypatch.delenv("GITHUB_EVENT_PATH", raising=False)

    assert ForgeContext.from_env().mr_iid == "34"


def test_an_unreadable_event_payload_does_not_fail_the_review(monkeypatch):
    """A crash here would turn a missing file into a failed security check,
    which is the inversion this project exists to avoid."""
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_REPOSITORY", "o/r")
    monkeypatch.setenv("GITHUB_EVENT_PATH", "/nowhere/event.json")

    forge = ForgeContext.from_env()
    assert forge.kind == "github"
    assert forge.mr_title == ""


def test_github_is_detected_before_gitlab(monkeypatch):
    """A GitHub runner sets generic CI variables too, and a GitLab-shaped read
    of those gives a half-populated context that fails at posting rather than
    at detection."""
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_REPOSITORY", "o/r")
    monkeypatch.setenv("CI_API_V4_URL", "https://gitlab.example/api/v4")

    assert ForgeContext.from_env().kind == "github"


def test_no_forge_at_all_is_not_an_error(monkeypatch, caplog):
    for name in ("GITHUB_ACTIONS", "GITHUB_REPOSITORY", "CI_API_V4_URL",
                 "CI_MERGE_REQUEST_IID", "CI_PROJECT_ID"):
        monkeypatch.delenv(name, raising=False)

    forge = ForgeContext.from_env()
    assert not forge.is_merge_request
    assert dispatch(ForgeContext(kind="none"), "body") is None


def test_the_dispatcher_sends_each_kind_to_its_own_adapter(monkeypatch):
    """The messages differ because what a person must fix differs — `api` scope
    on one, workflow permissions on the other."""
    seen = {}
    monkeypatch.setattr("security_agent.github.publish",
                        lambda c, b: seen.setdefault("github", True))
    monkeypatch.setattr("security_agent.gitlab.publish",
                        lambda c, b: seen.setdefault("gitlab", True))

    dispatch(ForgeContext(kind="github"), "body")
    dispatch(ForgeContext(kind="gitlab"), "body")
    assert seen == {"github": True, "gitlab": True}
