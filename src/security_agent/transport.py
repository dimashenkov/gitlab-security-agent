"""Streaming requests that survive a dropped connection.

The SDK retries connection failures when a request is *started*. It does not
help once bytes are flowing: a stream that dies mid-read surfaces as a raw
`httpx.ReadError`, which is neither an `anthropic.APIConnectionError` nor
anything the loop above would recognise. One reset packet then destroys an
entire review — every turn taken, every finding recorded, every token paid for —
and the job reports an error for a reason that had nothing to do with the code
under review.

Retrying is unusually cheap here. The conversation prefix is already in the
prompt cache, so a repeated turn re-reads it at a tenth of the price rather than
paying for it again.
"""

from __future__ import annotations

import logging
import time
from typing import Any, Dict, Optional, Tuple

import anthropic
import httpx

log = logging.getLogger(__name__)

# Failures worth repeating: the connection dropped, stalled, or the server had a
# moment. A 400 or a refusal is not in here — repeating those just spends money
# to get the same answer.
TRANSIENT = (
    httpx.TransportError,      # ReadError, ConnectError, ReadTimeout, …
    httpx.RemoteProtocolError,
    anthropic.APIConnectionError,
    anthropic.APITimeoutError,
    anthropic.InternalServerError,
)

DEFAULT_ATTEMPTS = 3
BACKOFF_SECONDS = (2.0, 8.0)


def stream_message(
    client: Any,
    params: Dict[str, Any],
    betas: Optional[list] = None,
    fallbacks: Optional[str] = None,
    attempts: int = DEFAULT_ATTEMPTS,
    label: str = "request",
) -> Any:
    """Run one streamed Messages request, retrying transient failures.

    Streaming is not optional: `max_tokens` is large enough here that a
    non-streaming call risks an HTTP timeout on a long turn.
    """
    last: Optional[BaseException] = None

    for attempt in range(1, attempts + 1):
        try:
            if betas:
                kwargs = dict(params, betas=betas)
                if fallbacks:
                    kwargs["fallbacks"] = fallbacks
                with client.beta.messages.stream(**kwargs) as stream:
                    return stream.get_final_message()
            with client.messages.stream(**params) as stream:
                return stream.get_final_message()
        except TRANSIENT as exc:
            last = exc
            if attempt == attempts:
                break
            delay = BACKOFF_SECONDS[min(attempt - 1, len(BACKOFF_SECONDS) - 1)]
            log.warning(
                "%s failed (%s: %s); retrying in %.0fs [attempt %d/%d]",
                label, type(exc).__name__, exc, delay, attempt + 1, attempts,
            )
            time.sleep(delay)

    # Re-raise as something the callers already know how to classify, so a
    # dropped stream and an unreachable API are handled identically upstream.
    raise anthropic.APIConnectionError(
        message="{} failed after {} attempts: {}: {}".format(
            label, attempts, type(last).__name__, last),
        request=_request_of(last),
    ) from last


def _request_of(exc: Optional[BaseException]) -> httpx.Request:
    """`APIConnectionError` needs a request object; synthesise one if absent.

    `httpx` exposes `.request` as a property that *raises* when the exception
    was constructed without one, so `getattr(exc, "request", None)` is not the
    safe read it looks like.
    """
    try:
        candidate = exc.request  # type: ignore[union-attr]
        if isinstance(candidate, httpx.Request):
            return candidate
    except (AttributeError, RuntimeError):
        pass
    return httpx.Request("POST", "https://api.anthropic.com/v1/messages")


def split_capability_error(exc: Exception) -> Tuple[bool, str]:
    """Is this 400 about an unavailable beta rather than a malformed request?

    Only a capability complaint justifies retrying with the optional betas off;
    a genuine request error would fail again and the retry would mask the real
    cause.
    """
    message = (getattr(exc, "message", "") or str(exc)).lower()
    markers = (
        "beta", "task_budget", "task budget", "fallback",
        "not available", "not enabled", "unsupported",
        "unexpected value", "unrecognized", "unrecognised",
    )
    return any(marker in message for marker in markers), message
