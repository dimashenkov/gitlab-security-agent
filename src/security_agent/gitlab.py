"""Posting the review back to the merge request.

One note per merge request, edited in place on every re-run. A pipeline that
appends a fresh comment each time a branch is pushed buries the discussion under
its own output, and reviewers stop reading any of it.

Nothing in here can change the pipeline verdict: if commenting fails, that is
logged and the exit code still comes from the findings. A missing comment is an
inconvenience; a scan that passes because the API was unreachable is a hole.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

import requests

from .config import GitLabContext
from .report import COMMENT_MARKER

log = logging.getLogger(__name__)

TIMEOUT = 30
# GitLab accepts about 1 MB per note; well before that a comment stops being
# readable. Long reports are trimmed with a pointer to the job artifact.
MAX_NOTE_CHARS = 60_000


class GitLabError(Exception):
    """The GitLab API could not be used as configured."""


class GitLabClient:
    def __init__(self, ctx: GitLabContext, session: Optional[Any] = None) -> None:
        self.ctx = ctx
        self._identity: Optional[Dict[str, Any]] = None
        self._identity_resolved = False
        self.session = session or requests.Session()
        self.session.headers.update({
            "PRIVATE-TOKEN": ctx.token,
            "User-Agent": "gitlab-security-agent",
        })

    @property
    def _mr_url(self) -> str:
        return "{}/projects/{}/merge_requests/{}".format(
            self.ctx.api_url.rstrip("/"), self.ctx.project_id, self.ctx.mr_iid
        )

    def post_or_update_note(self, body: str) -> str:
        """Create the agent's note, or edit the one it left last time.

        Returns a short description of what happened, for the job log.
        """
        body = _clip(body)
        existing = self._find_own_note()
        if existing is not None:
            self._request("PUT", "{}/notes/{}".format(self._mr_url, existing),
                          json={"body": body})
            return "updated note {}".format(existing)
        created = self._request("POST", "{}/notes".format(self._mr_url),
                                json={"body": body})
        return "created note {}".format(created.get("id", "?"))

    def _find_own_note(self) -> Optional[int]:
        """Find this agent's previous note: the marker *and* the author.

        The marker cannot establish ownership on its own. It is a fixed string
        in an open-source repository and an HTML comment, so it renders
        invisibly, and the author of a merge request can always comment on their
        own merge request. Trusting it alone produces one of two failures, both
        silent: a token with Maintainer rights writes the report into a note the
        attacker owns and can rewrite the moment the pipeline ends, and a token
        without them is refused with a 403, `publish` swallows it, and the
        report is never posted — not on this run and not on any later one,
        because the impostor keeps matching.

        So a marker only nominates a candidate; the author decides. Scanning
        continues past an impostor, because the genuine note may be further
        down the discussion.
        """
        page = 1
        while page <= 10:  # 1000 notes is far more than any real discussion
            notes: List[Dict[str, Any]] = self._request(
                "GET", "{}/notes".format(self._mr_url),
                params={"per_page": 100, "page": page, "sort": "asc"},
            )
            if not notes:
                return None
            for note in notes:
                if note.get("system"):
                    continue
                if COMMENT_MARKER not in (note.get("body") or ""):
                    continue
                identity = self._own_identity()
                if identity is None:
                    # Not knowing who this token is must cost a duplicate note,
                    # never an edit to somebody else's.
                    return None
                if _authored_by(note, identity):
                    return note.get("id")
                log.warning(
                    "note %s carries this agent's marker but was written by %s "
                    "— leaving it alone and posting a new note",
                    note.get("id"), _author_name(note) or "another account")
            if len(notes) < 100:
                return None
            page += 1
        return None

    def _own_identity(self) -> Optional[Dict[str, Any]]:
        """Who this token comments as, or None when that cannot be established.

        `/user` answers for any token that can create a note — a project or
        group access token resolves to its own bot user. Resolved at most once
        per client, and only once a marker candidate has actually been seen, so
        a first run still costs one listing and one create.
        """
        if self._identity_resolved:
            return self._identity
        self._identity_resolved = True

        try:
            user = self._request(
                "GET", "{}/user".format(self.ctx.api_url.rstrip("/")))
        except GitLabError as exc:
            user = None
            log.warning("could not read the authenticated user: %s", exc)
        if isinstance(user, dict) and (
                user.get("username") or user.get("id") is not None):
            self._identity = {"username": user.get("username") or "",
                              "id": user.get("id")}
            return self._identity

        log.warning(
            "this token's own identity is unknown, so no existing note can be "
            "shown to belong to this agent — posting a new note instead of "
            "editing one.")
        return None

    def _request(self, method: str, url: str, **kwargs: Any) -> Any:
        try:
            response = self.session.request(method, url, timeout=TIMEOUT, **kwargs)
        except requests.RequestException as exc:
            raise GitLabError("{} {} failed: {}".format(method, url, exc)) from exc

        if response.status_code == 401:
            raise GitLabError(
                "GitLab rejected the token (401). SECURITY_SCAN_GITLAB_TOKEN must "
                "be a project or group access token with `api` scope — CI_JOB_TOKEN "
                "cannot create merge request notes."
            )
        if response.status_code == 403:
            raise GitLabError(
                "GitLab denied the request (403). The token needs `api` scope and "
                "at least Reporter access to this project."
            )
        if response.status_code == 404:
            raise GitLabError(
                "Merge request !{} not found in project {} (404).".format(
                    self.ctx.mr_iid, self.ctx.project_id)
            )
        if response.status_code >= 400:
            raise GitLabError("{} {} returned {}: {}".format(
                method, url, response.status_code, response.text[:400]))

        if not response.content:
            return {}
        try:
            return response.json()
        except ValueError as exc:
            raise GitLabError(
                "{} {} returned a non-JSON body".format(method, url)) from exc


def publish(ctx: GitLabContext, body: str) -> Optional[str]:
    """Post the report if the pipeline is configured for it.

    Returns a log-friendly description, or None when commenting was skipped.
    Never raises: the caller's exit code belongs to the findings.
    """
    if not ctx.is_merge_request:
        log.info("not a merge request pipeline — skipping the comment")
        return None
    if not ctx.token:
        log.warning(
            "no SECURITY_SCAN_GITLAB_TOKEN set — skipping the merge request "
            "comment. The report is still written to the job artifacts."
        )
        return None
    if not ctx.can_comment:
        log.warning(
            "incomplete GitLab context (api_url=%s project=%s mr=%s) — skipping "
            "the comment", bool(ctx.api_url), bool(ctx.project_id), bool(ctx.mr_iid),
        )
        return None

    try:
        result = GitLabClient(ctx).post_or_update_note(body)
        log.info("merge request comment: %s", result)
        return result
    except GitLabError as exc:
        log.error("could not post the merge request comment: %s", exc)
        return None


def _author_name(note: Dict[str, Any]) -> str:
    """The author to name in the log, or "" — used only for a message."""
    author = note.get("author")
    return str(author.get("username") or "") if isinstance(author, dict) else ""


def _authored_by(note: Dict[str, Any], identity: Dict[str, Any]) -> bool:
    """Whether this note was written by the account the agent posts as.

    The numeric id wins when both sides have one: a username can be released
    and taken over by somebody else, a user id cannot. Compared as text because
    a JSON id may arrive as either a number or a string, and `1 != "1"` would
    read as "not ours" — which fails toward a duplicate note, but silently.
    """
    author = note.get("author")
    author = author if isinstance(author, dict) else {}
    own_id, author_id = identity.get("id"), author.get("id")
    if own_id is not None and author_id is not None:
        return str(own_id) == str(author_id)
    own_name = str(identity.get("username") or "").lower()
    return bool(own_name) and own_name == str(author.get("username") or "").lower()


def _clip(body: str) -> str:
    if len(body) <= MAX_NOTE_CHARS:
        return body
    head = body[:MAX_NOTE_CHARS].rsplit("\n", 1)[0]
    return head + (
        "\n\n---\n\n_Report trimmed for GitLab. The complete report is in the "
        "job artifacts (`.security-scan/report.md`)._\n"
    )
