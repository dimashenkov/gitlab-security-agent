"""Streaming requests that survive a dropped connection.

The SDK retries a connection that fails while a request is *starting*. It does
not help once bytes are flowing: a stream that dies mid-read surfaces as the
underlying HTTP library's own exception, which is not an `anthropic` error and
which no caller here would recognise. One reset packet then destroys an entire
review — every turn taken, every finding recorded, every token paid for — and
the job reports a failure that had nothing to do with the code under review.

Retrying is unusually cheap. The conversation prefix is already in the prompt
cache, so a repeated turn re-reads it at a tenth of the price.

Nothing here imports the HTTP library. Which one the SDK sits on is an
implementation detail that has already changed once — `anthropic` 1.x moved from
`httpx` to `httpx2` — and a scanner that crashes on `ModuleNotFoundError`
because it guessed wrong is worse than one that classifies by behaviour.
"""

from __future__ import annotations

import logging
import time
from typing import Any, Dict, Optional, Tuple

import anthropic

log = logging.getLogger(__name__)

DEFAULT_ATTEMPTS = 3
BACKOFF_SECONDS = (2.0, 8.0)

# Modules whose exceptions mean "the connection had a problem". Matched by name
# so a future SDK can swap its transport again without breaking this.
_TRANSPORT_MODULES = ("httpx", "httpx2", "httpcore", "httpcore2", "h11", "h2")

# Exception names from those modules that are *not* transport failures: an HTTP
# error carrying a real status code is the server answering, not the connection
# breaking, and repeating it buys the same answer twice.
_NOT_TRANSIENT = ("HTTPStatusError", "TooManyRedirects", "UnsupportedProtocol",
                  "InvalidURL", "ProtocolError")


class TransportFailure(Exception):
    """A request could not be completed after retrying.

    Its own type rather than a re-used SDK exception, so callers catch it
    explicitly and it cannot be confused with an error the API actually
    returned.
    """


def is_transient(exc: BaseException) -> bool:
    """Is this worth trying again?

    Connection dropped, stalled, or the server had a moment. A 400, a refusal,
    or an authentication failure is not — repeating those spends money to reach
    the same conclusion.
    """
    if isinstance(exc, (anthropic.APIConnectionError, anthropic.APITimeoutError,
                        anthropic.InternalServerError)):
        return True
    if isinstance(exc, anthropic.APIStatusError):
        return exc.status_code in (408, 409, 429) or exc.status_code >= 500

    name = type(exc).__name__
    module = type(exc).__module__.split(".")[0]
    if module in _TRANSPORT_MODULES:
        return name not in _NOT_TRANSIENT

    # Sockets and DNS, for the case where nothing wraps them at all.
    return isinstance(exc, (ConnectionError, TimeoutError)) or (
        isinstance(exc, OSError) and not isinstance(exc, (FileNotFoundError, PermissionError))
    )


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
        except Exception as exc:
            if not is_transient(exc):
                raise
            last = exc
            if attempt == attempts:
                break
            delay = BACKOFF_SECONDS[min(attempt - 1, len(BACKOFF_SECONDS) - 1)]
            log.warning(
                "%s failed (%s: %s); retrying in %.0fs [attempt %d/%d]",
                label, type(exc).__name__, exc, delay, attempt + 1, attempts,
            )
            time.sleep(delay)

    raise TransportFailure(
        "{} failed after {} attempts: {}: {}".format(
            label, attempts, type(last).__name__, last)
    ) from last


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
