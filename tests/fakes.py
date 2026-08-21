"""A scripted stand-in for the Anthropic client.

Enough of the response shape to drive the agent loop end to end without a
network call: content blocks, stop reasons, and usage. Requests are recorded so
tests can assert on what was actually sent — the prompt-cache markers and the
tool list are part of the contract too.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional


class Block:
    def __init__(self, type: str, **kwargs: Any) -> None:
        self.type = type
        for key, value in kwargs.items():
            setattr(self, key, value)


def text(body: str) -> Block:
    return Block("text", text=body)


def thinking(body: str = "") -> Block:
    return Block("thinking", thinking=body)


def tool_use(name: str, input: Dict[str, Any], id: str = "toolu_1") -> Block:
    return Block("tool_use", name=name, input=input, id=id)


def json_text(payload: Dict[str, Any]) -> Block:
    return Block("text", text=json.dumps(payload))


class FakeUsage:
    def __init__(self, input_tokens=1000, output_tokens=200,
                 cache_read_input_tokens=0, cache_creation_input_tokens=0):
        self.input_tokens = input_tokens
        self.output_tokens = output_tokens
        self.cache_read_input_tokens = cache_read_input_tokens
        self.cache_creation_input_tokens = cache_creation_input_tokens


class FakeResponse:
    def __init__(self, content: List[Block], stop_reason: str = "end_turn",
                 model: str = "claude-opus-5", usage: Optional[FakeUsage] = None,
                 stop_details: Any = None):
        self.content = content
        self.stop_reason = stop_reason
        self.model = model
        self.usage = usage or FakeUsage()
        self.stop_details = stop_details


class _Stream:
    def __init__(self, response: FakeResponse) -> None:
        self._response = response

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def get_final_message(self) -> FakeResponse:
        return self._response


class _Messages:
    def __init__(self, client: "FakeClient", beta: bool) -> None:
        self._client = client
        self._beta = beta

    def stream(self, **params: Any) -> _Stream:
        # The agent appends to the same `messages` list every turn, so a
        # recorded reference would show the conversation's final state for every
        # request. Snapshot the list to keep per-request assertions meaningful.
        snapshot = dict(params)
        if "messages" in snapshot:
            snapshot["messages"] = list(snapshot["messages"])
        self._client.requests.append({"beta": self._beta, "params": snapshot})
        if self._beta and self._client.beta_error is not None:
            raise self._client.beta_error
        return _Stream(self._client._next(params))


class _Beta:
    def __init__(self, client: "FakeClient") -> None:
        self.messages = _Messages(client, beta=True)


class FakeClient:
    """Replays a script of responses.

    ``script`` is a list of FakeResponse. ``verifier_script`` is used instead for
    requests that carry an `output_config.format`, which is how a verification
    call is distinguished from an agent turn.
    """

    def __init__(self, script: List[FakeResponse],
                 verifier_script: Optional[List[FakeResponse]] = None,
                 beta_error: Optional[Exception] = None) -> None:
        self.script = list(script)
        self.verifier_script = list(verifier_script or [])
        self.requests: List[Dict[str, Any]] = []
        # When set, every call through the beta endpoint raises it — the shape of
        # an account that cannot use the optional betas.
        self.beta_error = beta_error
        self.messages = _Messages(self, beta=False)
        self.beta = _Beta(self)

    def _next(self, params: Dict[str, Any]) -> FakeResponse:
        is_verifier = "format" in (params.get("output_config") or {})
        queue = self.verifier_script if is_verifier else self.script
        if not queue:
            # Ending the loop cleanly beats an IndexError deep inside the agent.
            return FakeResponse([text("Done.")], stop_reason="end_turn")
        return queue.pop(0)

    # --- assertions helpers -------------------------------------------------

    @property
    def agent_requests(self) -> List[Dict[str, Any]]:
        return [r for r in self.requests
                if "format" not in (r["params"].get("output_config") or {})]

    @property
    def verifier_requests(self) -> List[Dict[str, Any]]:
        return [r for r in self.requests
                if "format" in (r["params"].get("output_config") or {})]
