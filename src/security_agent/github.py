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

Which comment is the agent's own is a security question, not a bookkeeping one:
see `_find_own_comment`. The token that answers it is an installation token in
GitHub Actions, and such a token is refused at `/user`; `SECURITY_SCAN_COMMENT_AUTHOR`
exists for that case, and without it such a run posts a fresh comment each time
rather than editing one it cannot prove is its own.
"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, List, Optional

import requests

from .config import ForgeContext
from .report import COMMENT_MARKER

log = logging.getLogger(__name__)

TIMEOUT = 30
# GitHub's documented maximum is 65,536 characters for an issue comment.
MAX_COMMENT_CHARS = 60_000
# The login this token comments as, for tokens that cannot read `/user`. It is
# read from the environment, which the workflow controls — never from anything
# on the pull request, which its author controls.
IDENTITY_ENV = "SECURITY_SCAN_COMMENT_AUTHOR"


class GitHubError(Exception):
    """The comment could not be posted. Never fatal to a review."""


class GitHubClient:
    def __init__(self, ctx: ForgeContext, session: Optional[Any] = None) -> None:
        self.ctx = ctx
        self._identity: Optional[Dict[str, Any]] = None
        self._identity_resolved = False
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
        """Find this agent's previous comment: the marker *and* the author.

        The marker cannot establish ownership on its own. It is a fixed string
        in an open-source repository and an HTML comment, so it renders
        invisibly, and the author of a pull request can always comment on their
        own pull request. Trusting it alone produces one of two failures, both
        silent: with a token that may edit other people's comments, the report
        is written into a comment the attacker owns and can rewrite the moment
        the pipeline ends; with a token that may not, the edit is refused,
        `publish` swallows the error, and the report is never posted — not on
        this run and not on any later one, because the impostor keeps matching.

        So a marker only nominates a candidate; the author decides. Scanning
        continues past an impostor, because the genuine comment may be further
        down the thread.
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
                if COMMENT_MARKER not in (comment.get("body") or ""):
                    continue
                identity = self._own_identity()
                if identity is None:
                    # Not knowing who this token is must cost a duplicate
                    # comment, never an edit to somebody else's.
                    return None
                if _authored_by(comment, identity):
                    return comment.get("id")
                log.warning(
                    "comment %s carries this agent's marker but was written by "
                    "%s — leaving it alone and posting a new comment",
                    comment.get("id"), _author_name(comment) or "another account")
            if len(comments) < 100:
                return None
            page += 1
        return None

    def _own_identity(self) -> Optional[Dict[str, Any]]:
        """Who this token comments as, or None when that cannot be established.

        Resolved at most once per client, and only once a marker candidate has
        actually been seen — a first run then still costs one listing and one
        create, as it did before ownership was checked.
        """
        if self._identity_resolved:
            return self._identity
        self._identity_resolved = True

        configured = os.environ.get(IDENTITY_ENV, "").strip()
        if configured:
            self._identity = {"login": configured, "id": None}
            return self._identity

        try:
            user = self._request(
                "GET", "{}/user".format(self.ctx.api_url.rstrip("/")))
        except GitHubError as exc:
            user = None
            log.warning("could not read the authenticated user: %s", exc)
        if isinstance(user, dict) and (user.get("login") or user.get("id") is not None):
            self._identity = {"login": user.get("login") or "", "id": user.get("id")}
            return self._identity

        log.warning(
            "this token's own identity is unknown, so no existing comment can "
            "be shown to belong to this agent — posting a new comment instead "
            "of editing one. An installation token (GitHub Actions' own) is "
            "refused at /user; set %s to the login it comments as to keep one "
            "comment per pull request.", IDENTITY_ENV)
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
        if response.status_code in (403, 429):
            # GitHub answers 403 for two unrelated things, and telling someone
            # to widen a token's permissions when they are simply out of quota
            # sends them to fix the wrong problem — and to grant a scope they
            # did not need.
            raise GitHubError(_denied(response))
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


def _author_name(comment: Dict[str, Any]) -> str:
    """The author to name in the log, or "" — used only for a message."""
    user = comment.get("user")
    return str(user.get("login") or "") if isinstance(user, dict) else ""


def _authored_by(comment: Dict[str, Any], identity: Dict[str, Any]) -> bool:
    """Whether this comment was written by the account the agent posts as.

    The numeric id wins when both sides have one: a login can be released and
    taken over by somebody else, an account id cannot. Compared as text because
    a JSON id may arrive as either a number or a string, and `1 != "1"` would
    read as "not ours" — which fails toward a duplicate comment, but silently.
    """
    user = comment.get("user")
    author = user if isinstance(user, dict) else {}
    own_id, author_id = identity.get("id"), author.get("id")
    if own_id is not None and author_id is not None:
        return str(own_id) == str(author_id)
    own_login = str(identity.get("login") or "").lower()
    return bool(own_login) and own_login == str(author.get("login") or "").lower()


def _denied(response: Any) -> str:
    """Tell a 403 that is a quota problem from a 403 that is a permission one.

    Read from the headers rather than the body: `X-RateLimit-Remaining: 0` is
    the documented signal, `Retry-After` covers the secondary limits, and both
    survive a message GitHub may reword. The body is only consulted as a
    fallback, and only for phrases GitHub uses for this and nothing else.
    """
    headers = getattr(response, "headers", None) or {}

    def header(name: str) -> str:
        try:
            return str(headers.get(name, "") or "")
        except AttributeError:                       # a plain dict-like fake
            return ""

    remaining = header("X-RateLimit-Remaining")
    retry_after = header("Retry-After")
    body = (getattr(response, "text", "") or "").lower()
    throttled = (
        remaining == "0"
        or bool(retry_after)
        or "rate limit" in body
        or "secondary rate limit" in body
        or "abuse detection" in body
    )

    if throttled:
        reset = header("X-RateLimit-Reset")
        when = " Retry after {}s.".format(retry_after) if retry_after else (
            " The limit resets at {} (unix time).".format(reset) if reset else "")
        return (
            "GitHub is rate limiting this token ({}), not refusing it.{} "
            "Nothing needs to be granted — the comment was not posted and the "
            "review is unaffected.".format(response.status_code, when)
        )
    return (
        "GitHub denied the request ({}). The workflow needs "
        "`permissions: pull-requests: write`, and the automatic token cannot "
        "comment on a pull request from a fork.".format(response.status_code)
    )


def _clip(body: str) -> str:
    if len(body) <= MAX_COMMENT_CHARS:
        return body
    head = body[:MAX_COMMENT_CHARS].rsplit("\n", 1)[0]
    return head + (
        "\n\n---\n\n_Report trimmed for GitHub. The complete report is in the "
        "run artifacts._\n"
    )
