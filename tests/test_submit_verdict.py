"""The verifier's answer as an act, not as whatever it said last.

`finish_review` and `submit_verdict` are the same idea at two scales. A review
that stops is not a review that finished; a verifier that stops is not a
verifier that voted. With the Messages API the second is nearly safe — a
schema-constrained final message is a guarantee — but a provider that runs its
own loop offers no such guarantee, and "the process exited" would otherwise be
read as "the panel voted".

Both channels stay open, because removing the constrained-message route would
weaken the path that currently works. The vote records which one carried it:
an argument the verifier submitted and a reply the transport happened to
validate are not the same event, and the artifact should not flatten them.

Everything here drives `_one_vote` against a scripted client, so what is under
test is the verification loop rather than the handler's assignment statement.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from conftest import make_candidate
from fakes import FakeClient, FakeResponse, json_text, text, tool_use
from security_agent.config import Config, GitLabContext
from security_agent.models import (
    VERDICT_CONFIRMED,
    VERDICT_REFUTED,
    VERDICT_UNCERTAIN,
)
from security_agent.tools import SUBMIT_VERDICT, verifier_tool_definitions
from security_agent.verify import VERDICT_SCHEMA, _one_vote, _system_blocks
from security_agent.workspace import Workspace

PROMPTS = Path(__file__).resolve().parents[1] / "prompts"

SEARCH = ("Looked for a validating caller in app/ and found none; the sink is "
          "reached directly.")


def _payload(**overrides):
    data = {
        "verdict": VERDICT_CONFIRMED,
        "reasoning": "Traced the call chain from the handler and confirmed it.",
        "corrected_impact": "",
        "corrected_reachable_without_authentication": "",
        "corrected_requires_user_interaction": "",
        "corrected_confidence": "",
        "control_search": SEARCH,
        "entry_point": "app/views.py:14 via the public handler",
    }
    data.update(overrides)
    return data


@pytest.fixture
def cfg(tmp_path):
    return Config(
        prompt_dir=PROMPTS,
        output_dir=tmp_path / "out",
        gitlab=GitLabContext(project_path="group/project"),
        post_comment=False,
    )


@pytest.fixture
def ws(git_repo):
    return Workspace(root=git_repo, excludes=(), diff_base="", diff_head="HEAD")


def _vote(cfg, ws, *responses):
    client = FakeClient(verifier_script=list(responses), script=[])
    tools = verifier_tool_definitions(VERDICT_SCHEMA, diff_available=False)
    vote, _usage = _one_vote(cfg, ws, client, _system_blocks(cfg), tools,
                             make_candidate(), vote_index=0)
    return vote


def submit(**args):
    return FakeResponse([tool_use(SUBMIT_VERDICT, args, id="v1")],
                        stop_reason="tool_use")


# ------------------------------------------------------- the tool channel


def test_a_submitted_verdict_is_the_vote(cfg, ws):
    vote = _vote(cfg, ws, submit(**_payload()))

    assert vote.verdict == VERDICT_CONFIRMED
    assert vote.control_search == SEARCH
    assert not vote.error


def test_the_channel_is_recorded(cfg, ws):
    """An argument the verifier submitted and a reply the transport happened to
    validate are different events. The artifact should not flatten them."""
    submitted = _vote(cfg, ws, submit(**_payload()))
    replied = _vote(cfg, ws, FakeResponse([json_text(_payload())],
                                          stop_reason="end_turn"))

    assert submitted.channel == "submit_verdict"
    assert replied.channel == "final_message"


def test_submitting_ends_the_verifier(cfg, ws):
    """It is both the answer and the statement of being done. Counted in
    requests: an exhausted script answers "Done." rather than raising, so a
    loop that kept going would still return a vote."""
    client = FakeClient(verifier_script=[submit(**_payload())], script=[])
    tools = verifier_tool_definitions(VERDICT_SCHEMA, diff_available=False)
    _one_vote(cfg, ws, client, _system_blocks(cfg), tools, make_candidate(), 0)

    assert len(client.verifier_requests) == 1


def test_a_refutation_survives_the_tool_channel(cfg, ws):
    """The direction that matters most: a refutation ungates a finding, so a
    channel that quietly lost one would be a channel that blocks merges."""
    vote = _vote(cfg, ws, submit(**_payload(
        verdict=VERDICT_REFUTED,
        reasoning="The caller validates the id against the session first.",
        control_search="Read both callers in app/views.py; both validate.")))

    assert vote.verdict == VERDICT_REFUTED


# ------------------------------------------------ the same rules still apply


def test_a_confirmation_without_a_search_is_still_downgraded(cfg, ws):
    """The rule that turned a false positive into a refutation. Routing the
    verdict through a tool must not route it around the evidence check."""
    vote = _vote(cfg, ws, submit(**_payload(control_search="")))

    assert vote.verdict == VERDICT_UNCERTAIN


def test_an_unknown_verdict_word_is_not_accepted(cfg, ws):
    vote = _vote(cfg, ws, submit(**_payload(verdict="probably")))

    assert vote.verdict == VERDICT_UNCERTAIN
    assert vote.error


def test_two_submissions_in_one_response_keep_the_first(cfg, ws):
    """The only way a second vote can actually arrive: parallel tool blocks in
    a single turn. The loop returns after the turn, so a sequential retry never
    reaches the handler — testing this any other way would test nothing.

    The first stands because a later answer is not a better one, and letting it
    through would let a truncated retry replace a real verdict."""
    vote = _vote(cfg, ws, FakeResponse(
        [tool_use(SUBMIT_VERDICT, _payload(verdict=VERDICT_REFUTED), id="v1"),
         tool_use(SUBMIT_VERDICT, _payload(verdict=VERDICT_CONFIRMED), id="v2")],
        stop_reason="tool_use"))

    assert vote.verdict == VERDICT_REFUTED


def test_a_verifier_that_stops_without_voting_does_not_count_as_a_vote(cfg, ws):
    vote = _vote(cfg, ws, FakeResponse([text("I had a look and it seems fine.")],
                                       stop_reason="end_turn"))

    assert vote.verdict == VERDICT_UNCERTAIN
    assert vote.error


# ----------------------------------------------------------- what is offered


def test_the_verifier_is_offered_exactly_one_way_to_answer():
    names = [t["name"] for t in verifier_tool_definitions(VERDICT_SCHEMA,
                                                          diff_available=True)]

    assert names.count(SUBMIT_VERDICT) == 1
    assert "report_finding" not in names
    assert "finish_review" not in names


def test_the_verdict_schema_has_one_definition():
    """Passed in rather than restated in the tool layer. Two definitions of a
    verdict is the drift this project has already been bitten by twice."""
    tool = next(t for t in verifier_tool_definitions(VERDICT_SCHEMA, False)
                if t["name"] == SUBMIT_VERDICT)

    assert tool["input_schema"] is VERDICT_SCHEMA


def test_the_verifier_is_told_to_call_it():
    prompt = (PROMPTS / "verifier.md").read_text(encoding="utf-8")

    assert SUBMIT_VERDICT in prompt
    # And the fallback is still described, because the constrained-message
    # route is what the API path actually uses today.
    assert "not available to you" in prompt
