"""Posting the review to a pull request, and detecting which forge this is.

The GitLab path has been exercised by a real pipeline for days. This one has
not, so the tests carry the weight — and the properties that matter are the
ones shared with GitLab rather than anything GitHub-specific: one comment
edited in place, never a second; a failure to post never touches the exit code;
and a comment the agent did not write is never edited — including one that
carries the agent's own marker, which anyone reading this repository can copy.
"""

from __future__ import annotations

import json

import pytest

from security_agent.config import ForgeContext
from security_agent.forge import publish as dispatch
from security_agent.github import (
    IDENTITY_ENV,
    GitHubClient,
    GitHubError,
    _clip,
    publish,
)
from security_agent.report import COMMENT_MARKER


class FakeResponse:
    def __init__(self, status=200, payload=None, text="", headers=None,
                 body_is_json=True):
        self.status_code = status
        self._payload = payload if payload is not None else {}
        self.text = text
        self.headers = headers or {}
        self.content = b"x" if payload is not None or text else b""
        # A 200 whose body is not JSON is a real thing a proxy or an error page
        # produces, and `json()` raising is how it arrives.
        self._body_is_json = body_is_json

    def json(self):
        if not self._body_is_json:
            raise ValueError("no JSON object could be decoded")
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


# Who the token posts as, and who else is in the thread. The impostor is the
# pull request's own author: they can always comment on their own pull request,
# and the marker is a fixed string in a public repository.
WHOAMI = {"login": "scan-bot", "id": 1234}
IMPOSTOR = {"login": "pr-author", "id": 77}


def own(comment_id, body=COMMENT_MARKER + "\nold"):
    return {"id": comment_id, "body": body, "user": dict(WHOAMI)}


def impostor(comment_id, body=COMMENT_MARKER + "\n## No findings"):
    return {"id": comment_id, "body": body, "user": dict(IMPOSTOR)}


@pytest.fixture(autouse=True)
def _no_configured_login(monkeypatch):
    # A developer machine that happens to export it must not decide the result.
    monkeypatch.delenv(IDENTITY_ENV, raising=False)


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
        FakeResponse(payload=[{"id": 5, "body": "unrelated"}, own(6)]),
        FakeResponse(payload=WHOAMI),
        FakeResponse(payload={"id": 6}),
    ])
    result = GitHubClient(ctx(), session).post_or_update_note("new")

    assert result == "updated comment 6"
    method, url, kwargs = session.calls[-1]
    assert method == "PATCH"
    assert url.endswith("/issues/comments/6")
    assert kwargs["json"]["body"] == "new"


def test_a_comment_the_agent_did_not_write_is_never_touched():
    """An unrelated comment is not a candidate at all — no author lookup is
    needed and none is made."""
    session = FakeSession([FakeResponse(payload=[{"id": 5, "body": "a human wrote this"}]),
                           FakeResponse(payload={"id": 9})])
    GitHubClient(ctx(), session).post_or_update_note("body")

    assert [call[0] for call in session.calls] == ["GET", "POST"]


# --------------------------------------------------------------- impersonation


def test_a_marker_written_by_somebody_else_is_never_edited():
    """The defect this exists to catch: ownership decided by the marker alone.

    The marker is a fixed string in an open-source repository and an HTML
    comment, so it renders invisibly, and the pull request's author can post it
    on their own pull request. Editing it either hands the report to an account
    that rewrites it once the pipeline ends, or is refused — and a refusal is
    swallowed, so the report is never posted at all, on this run or any later
    one.
    """
    session = FakeSession([
        FakeResponse(payload=[impostor(5)]),
        FakeResponse(payload=WHOAMI),
        FakeResponse(payload={"id": 9}),
    ])
    result = GitHubClient(ctx(), session).post_or_update_note("body")

    assert result == "created comment 9"
    assert [call[0] for call in session.calls] == ["GET", "GET", "POST"]
    assert "PATCH" not in [call[0] for call in session.calls]


def test_the_agents_own_comment_behind_an_impostor_is_still_found():
    """An impostor posting first must not cost the agent its own comment, or a
    single forged comment turns every later run into a fresh duplicate."""
    session = FakeSession([
        FakeResponse(payload=[impostor(5), own(6)]),
        FakeResponse(payload=WHOAMI),
        FakeResponse(payload={"id": 6}),
    ])

    assert GitHubClient(ctx(), session).post_or_update_note("new") == (
        "updated comment 6")
    assert [call[0] for call in session.calls] == ["GET", "GET", "PATCH"]
    assert session.calls[-1][1].endswith("/issues/comments/6")


def test_an_identity_that_cannot_be_read_posts_a_new_comment():
    """Unable to establish ownership must fail toward a duplicate comment, not
    toward editing one. `/user` is refused for an installation token, which is
    exactly what GitHub Actions hands the job."""
    session = FakeSession([
        FakeResponse(payload=[impostor(5, COMMENT_MARKER + "\nold")]),
        FakeResponse(status=403, text="Resource not accessible by integration"),
        FakeResponse(payload={"id": 9}),
    ])

    assert GitHubClient(ctx(), session).post_or_update_note("body") == (
        "created comment 9")
    assert [call[0] for call in session.calls] == ["GET", "GET", "POST"]


def test_a_configured_login_stands_in_for_an_unreadable_user_endpoint(monkeypatch):
    """The workflow controls the environment; the pull request's author does
    not. Without this, an installation token could never edit its own comment
    and would leave a new one on every push."""
    monkeypatch.setenv(IDENTITY_ENV, "github-actions[bot]")
    bot = {"id": 6, "body": COMMENT_MARKER + "\nold",
           "user": {"login": "github-actions[bot]"}}
    session = FakeSession([FakeResponse(payload=[impostor(5), bot]),
                           FakeResponse(payload={"id": 6})])

    assert GitHubClient(ctx(), session).post_or_update_note("new") == (
        "updated comment 6")
    assert [call[0] for call in session.calls] == ["GET", "PATCH"]


def test_the_identity_is_read_once_however_many_markers_are_in_the_thread():
    """A thread stuffed with forged markers must not become one API call per
    comment."""
    session = FakeSession([
        FakeResponse(payload=[impostor(n) for n in range(5)] + [own(6)]),
        FakeResponse(payload=WHOAMI),
        FakeResponse(payload={"id": 6}),
    ])
    GitHubClient(ctx(), session).post_or_update_note("new")

    assert [url for _, url, _ in session.calls].count(
        "https://api.github.com/user") == 1


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


@pytest.mark.parametrize("headers,text", [
    ({"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": "1787600000"}, ""),
    ({"Retry-After": "60"}, ""),
    ({}, "You have exceeded a secondary rate limit"),
])
def test_a_403_that_is_a_quota_problem_does_not_ask_for_permissions(headers, text):
    """GitHub answers 403 for two unrelated things.

    This test previously locked in the wrong advice: it asserted the
    permissions message for every 403, so a rate-limited run told the operator
    to widen a token's scope — sending them to fix the wrong problem, and to
    grant something they did not need.
    """
    session = FakeSession([FakeResponse(status=403, headers=headers, text=text)])
    with pytest.raises(GitHubError) as caught:
        GitHubClient(ctx(), session).post_or_update_note("body")

    message = str(caught.value)
    assert "rate limiting" in message
    assert "permissions" not in message
    assert "Nothing needs to be granted" in message


def test_a_403_with_no_quota_signal_is_still_a_permission_problem():
    session = FakeSession([FakeResponse(status=403, text="Resource not accessible")])
    with pytest.raises(GitHubError) as caught:
        GitHubClient(ctx(), session).post_or_update_note("body")
    assert "pull-requests: write" in str(caught.value)


def test_a_marker_on_the_second_page_is_still_found():
    """The pagination loop was written and never exercised. A second comment
    per run is exactly what this client exists to prevent."""
    first = [{"id": n, "body": "chatter"} for n in range(100)]
    second = [own(500)]
    session = FakeSession([FakeResponse(payload=first),
                           FakeResponse(payload=second),
                           FakeResponse(payload=WHOAMI),
                           FakeResponse(payload={"id": 500})])

    assert GitHubClient(ctx(), session).post_or_update_note("new") == (
        "updated comment 500")
    assert [call[0] for call in session.calls] == ["GET", "GET", "GET", "PATCH"]


def test_a_short_page_ends_the_search_rather_than_paging_forever():
    session = FakeSession([FakeResponse(payload=[{"id": 1, "body": "x"}]),
                           FakeResponse(payload={"id": 9})])
    GitHubClient(ctx(), session).post_or_update_note("body")

    assert [call[0] for call in session.calls] == ["GET", "POST"]


def test_a_body_that_is_not_json_is_an_error_not_a_crash():
    """A proxy or an error page returns 200 with HTML. `json()` raising is how
    that arrives, and it must become a diagnosed failure to post — never an
    exception escaping into the exit code."""
    session = FakeSession([FakeResponse(payload=[], text="<html>", body_is_json=False)])
    with pytest.raises(GitHubError) as caught:
        GitHubClient(ctx(), session).post_or_update_note("body")
    assert "non-JSON" in str(caught.value)


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
