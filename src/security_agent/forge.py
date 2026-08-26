"""Which forge gets the comment.

A dispatch, and deliberately nothing else. The two adapters keep their own
error messages because the thing a person needs to fix differs — a GitLab token
needs `api` scope, a GitHub workflow needs `permissions: pull-requests: write`
— and collapsing them into one message would replace both with something that
helps nobody.

The `none` case is not an error. A local run has no forge, writes its artifact,
and says so once.
"""

from __future__ import annotations

import logging
from typing import Optional

from .config import ForgeContext

log = logging.getLogger(__name__)


def publish(ctx: ForgeContext, body: str) -> Optional[str]:
    """Post the report where this run's forge takes comments.

    Never raises. The exit code belongs to the findings, and it has done since
    the first version: a review that found something and could not say so is
    still a review that found something.
    """
    if ctx.kind == "github":
        from .github import publish as post
    elif ctx.kind == "gitlab":
        from .gitlab import publish as post
    else:
        log.info("no forge detected — the report is in the output directory only")
        return None
    return post(ctx, body)
