"""Posting the review back to a pull request.

The same contract as `gitlab.py`, because the promise is about the reader and
not the forge: one comment per pull request, edited in place on every re-run,
and nothing in here can change the exit code. A pipeline that appends a fresh
comment on every push buries the discussion under its own output; a scan that
passes because an API was unreachable is a hole.

GitHub differs from GitLab in two ways that matter here. Pull request comments
live on the *issues* endpoint, and updating one addresses it by comment id
without the pull request in the path. And the body limit is an order of
magnitude larger, so a report that GitLab truncates usually fits whole.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

import requests

from .config import ForgeContext
from .report import COMMENT_MARKER

log = logging.getLogger(__name__)

TIMEOUT = 30
# GitHub's documented maximum is 65,536 characters for an issue comment.
MAX_COMMENT_CHARS = 60_000


class GitHubError(Exception):
    """The comment could not be posted. Never fatal to a review."""


class GitHubClient:
    def __init__(self, ctx: ForgeContext, session: Optional[Any] = None) -> None:
        self.ctx = ctx
        self.session = session or requests.Session()
        self.session.headers.update({
            "Authorization": "Bearer {}".format(ctx.token),
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "gitlab-security-agent",
        })

    @property
    def _issue_url(self) -> str:
        # Pull request comments are issue comments. The pull endpoint holds
        # review comments, which are anchored to a diff line and are a
        # different thing from the summary this posts.
        return "{}/repos/{}/issues/{}".format(
            self.ctx.api_url.rstrip("/"), self.ctx.project_path, self.ctx.mr_iid)

    @property
    def _comments_url(self) -> str:
        return "{}/repos/{}/issues/comments".format(
            self.ctx.api_url.rstrip("/"), self.ctx.project_path)

    def post_or_update_note(self, body: str) -> str:
        """Create the agent's comment, or edit the one it left last time."""
        body = _clip(body)
        existing = self._find_own_comment()
        if existing is not None:
            self._request("PATCH", "{}/{}".format(self._comments_url, existing),
                          json={"body": body})
            return "updated comment {}".format(existing)
        created = self._request("POST", "{}/comments".format(self._issue_url),
                                json={"body": body})
        return "created comment {}".format(created.get("id", "?"))

    def _find_own_comment(self) -> Optional[int]:
        """Find a previous comment from this agent by its marker.

        Matched on the marker rather than the author, so the comment is still
        found when the token changes between runs — and so it can never touch a
        comment the agent did not write.
        """
        page = 1
        while page <= 10:            # 1000 comments is more than any real thread
            comments: List[Dict[str, Any]] = self._request(
                "GET", "{}/comments".format(self._issue_url),
                params={"per_page": 100, "page": page},
            )
            if not isinstance(comments, list) or not comments:
                return None
            for comment in comments:
                if COMMENT_MARKER in (comment.get("body") or ""):
                    return comment.get("id")
            if len(comments) < 100:
                return None
            page += 1
        return None

    def _request(self, method: str, url: str, **kwargs: Any) -> Any:
        try:
            response = self.session.request(method, url, timeout=TIMEOUT, **kwargs)
        except requests.RequestException as exc:
            raise GitHubError("{} {} failed: {}".format(method, url, exc)) from exc

        if response.status_code == 401:
            raise GitHubError(
                "GitHub rejected the token (401). Set SECURITY_SCAN_GITHUB_TOKEN, "
                "or pass GITHUB_TOKEN through explicitly — it is not in the "
                "environment unless the workflow puts it there."
            )
        if response.status_code == 403:
            raise GitHubError(
                "GitHub denied the request (403). The workflow needs "
                "`permissions: pull-requests: write`, and the automatic token "
                "cannot comment on a pull request from a fork."
            )
        if response.status_code == 404:
            raise GitHubError(
                "Pull request #{} not found in {} (404). A private repository "
                "also answers 404 to a token that cannot see it.".format(
                    self.ctx.mr_iid, self.ctx.project_path)
            )
        if response.status_code >= 400:
            raise GitHubError("{} {} returned {}: {}".format(
                method, url, response.status_code, response.text[:400]))

        if not response.content:
            return {}
        try:
            return response.json()
        except ValueError as exc:
            raise GitHubError(
                "{} {} returned a non-JSON body".format(method, url)) from exc


def publish(ctx: ForgeContext, body: str) -> Optional[str]:
    """Post the report if the workflow is configured for it.

    Returns a log-friendly description, or None when commenting was skipped.
    Never raises: the caller's exit code belongs to the findings.
    """
    if not ctx.is_merge_request:
        log.info("not a pull request run — skipping the comment")
        return None
    if not ctx.token:
        log.warning(
            "no token available — skipping the pull request comment. GITHUB_TOKEN "
            "is not in the environment unless the workflow passes it. The report "
            "is still written to the run artifacts."
        )
        return None
    if not ctx.can_comment:
        log.warning(
            "incomplete GitHub context (api_url=%s repo=%s pr=%s) — skipping the "
            "comment", bool(ctx.api_url), bool(ctx.project_path), bool(ctx.mr_iid),
        )
        return None

    try:
        result = GitHubClient(ctx).post_or_update_note(body)
        log.info("pull request comment: %s", result)
        return result
    except GitHubError as exc:
        log.error("could not post the pull request comment: %s", exc)
        return None


def _clip(body: str) -> str:
    if len(body) <= MAX_COMMENT_CHARS:
        return body
    head = body[:MAX_COMMENT_CHARS].rsplit("\n", 1)[0]
    return head + (
        "\n\n---\n\n_Report trimmed for GitHub. The complete report is in the "
        "run artifacts._\n"
    )
