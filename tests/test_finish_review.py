"""Saying the review is over, rather than being observed to stop.

With the Messages API the difference is small: `end_turn` is the model choosing
to stop, and reading that as "finished" is nearly right. With a provider that
owns its own loop it is not small at all — the process exits zero whether the
review finished or the harness gave up, and this project's one unbreakable rule
is that those two must never render the same.

So completion becomes a statement the reviewer makes, through the same channel
as everything else it states. Both runners then read one statement instead of
each inferring completion from its own provider's exit.

Every test here drives the real agent loop against a scripted client. A test
that called the handler directly would prove the handler sets a flag, which is
the half that was never in doubt — and this repository has already shipped a
fix whose tests called the helper and never the chain.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from fakes import FakeClient, FakeResponse, text, tool_use
from security_agent.agent import SecurityAgent
from security_agent.config import Config, GitLabContext
from security_agent.gate import decide
from security_agent.models import STOP_COMPLETED
from security_agent.report import build_json, render_markdown
from security_agent.tools import (
    FINISH_REVIEW,
    MIN_SUMMARY_CHARS,
    REPORT_FINDING,
    read_only_tool_definitions,
)
from security_agent.workspace import Workspace

PROMPTS = Path(__file__).resolve().parents[1] / "prompts"
GOOD_SUMMARY = ("Read the changed handler and both of its callers; the id is "
                "bound as a parameter and nothing else touches the query.")


@pytest.fixture
def cfg(tmp_path):
    return Config(
        prompt_dir=PROMPTS,
        output_dir=tmp_path / "out",
        gitlab=GitLabContext(project_path="group/project"),
        post_comment=False,
        verify_votes=1,
    )


@pytest.fixture
def ws(git_repo):
    return Workspace(root=git_repo, excludes=(), diff_base="", diff_head="HEAD")


def _run(cfg, ws, *responses):
    agent = SecurityAgent(cfg, ws, client=FakeClient(list(responses)))
    return agent.run("diff", "go")


def finish(**args):
    return FakeResponse([tool_use(FINISH_REVIEW, args, id="f1")],
                        stop_reason="tool_use")


# ------------------------------------------------- the reviewer signs off


def test_calling_finish_review_ends_the_run_and_supplies_the_summary(cfg, ws):
    """The loop must stop on the sign-off, not merely record it.

    Counted in requests rather than inferred from the summary: an exhausted
    script does not raise here, it answers "Done." with `end_turn`, so a loop
    that kept going would still finish and only the count would show it."""
    client = FakeClient([finish(summary=GOOD_SUMMARY)])
    outcome = SecurityAgent(cfg, ws, client=client).run("diff", "go")

    assert len(client.agent_requests) == 1
    assert outcome.finished_explicitly is True
    assert outcome.stop_reason == STOP_COMPLETED
    assert outcome.summary == GOOD_SUMMARY


def test_the_summary_comes_from_the_argument_not_the_last_text(cfg, ws):
    """The point of routing it through a tool. Trailing prose is presentation;
    the argument is what the reviewer submitted, and it is what gets stored."""
    outcome = _run(
        cfg, ws,
        FakeResponse([text("Let me wrap up."),
                      tool_use(FINISH_REVIEW, {"summary": GOOD_SUMMARY}, id="f1")],
                     stop_reason="tool_use"),
    )

    assert outcome.summary == GOOD_SUMMARY
    assert "wrap up" not in outcome.summary


def test_unresolved_questions_survive_into_the_outcome(cfg, ws):
    outcome = _run(cfg, ws, finish(
        summary=GOOD_SUMMARY,
        unresolved=["Could not find the router that mounts /admin.",
                    "auth.py is excluded, so the decorator was not read."]))

    assert len(outcome.unresolved) == 2
    assert "router" in outcome.unresolved[0]


def test_one_string_where_a_list_was_asked_for_is_kept(cfg, ws):
    """A real answer arriving in the wrong shape. Discarding it on a shape
    complaint loses the gap and leaves a review that looks complete."""
    outcome = _run(cfg, ws, finish(summary=GOOD_SUMMARY,
                                   unresolved="Could not read vendor/."))

    assert outcome.unresolved == ["Could not read vendor/."]


def test_empty_entries_do_not_become_empty_bullets(cfg, ws):
    outcome = _run(cfg, ws, finish(summary=GOOD_SUMMARY,
                                   unresolved=["", "   ", "One real gap."]))

    assert outcome.unresolved == ["One real gap."]


# ------------------------------------------------------ and when it does not


def test_a_review_that_just_stops_is_recorded_as_not_signed_off(cfg, ws):
    """Still complete — `end_turn` is the model choosing to stop, and failing
    these runs today would fail runs that are fine. Recorded so the rate can be
    read off real reviews instead of guessed at."""
    outcome = _run(cfg, ws, FakeResponse([text("Nothing exploitable here.")],
                                         stop_reason="end_turn"))

    assert outcome.stop_reason == STOP_COMPLETED
    assert outcome.finished_explicitly is False
    assert outcome.summary == "Nothing exploitable here."


def test_the_report_says_when_nobody_signed_off(cfg, ws):
    outcome = _run(cfg, ws, FakeResponse([text("Nothing exploitable here.")],
                                         stop_reason="end_turn"))
    markdown = render_markdown(cfg, outcome, decide(cfg, outcome))

    assert "stopped without signing off" in markdown


def test_the_report_stays_quiet_when_the_reviewer_did_sign_off(cfg, ws):
    """A note that appears on every clean review is a note nobody reads."""
    outcome = _run(cfg, ws, finish(summary=GOOD_SUMMARY))
    markdown = render_markdown(cfg, outcome, decide(cfg, outcome))

    assert "stopped without signing off" not in markdown


def test_a_run_that_hit_the_turn_limit_does_not_get_the_sign_off_note(cfg, ws):
    """It already carries the coverage warning, which says more. Two warnings
    about the same truncation train a reader to skip both."""
    cfg.max_turns = 1
    outcome = _run(cfg, ws,
                   FakeResponse([tool_use("list_directory", {}, id="t1")],
                                stop_reason="tool_use"))
    markdown = render_markdown(cfg, outcome, decide(cfg, outcome))

    assert not outcome.complete
    assert "stopped without signing off" not in markdown


# ------------------------------------------------------------ bad sign-offs


def test_a_two_word_sign_off_is_refused_and_the_review_continues(cfg, ws):
    """Refused as a tool result, not as an exception: the reviewer is told what
    was wrong and gets to answer properly. The review must not be left running
    with no way to end it."""
    outcome = _run(
        cfg, ws,
        finish(summary="Looks fine."),
        finish(summary=GOOD_SUMMARY),
    )

    assert outcome.finished_explicitly is True
    assert outcome.summary == GOOD_SUMMARY


def test_a_refused_sign_off_alone_does_not_finish_the_review(cfg, ws):
    outcome = _run(
        cfg, ws,
        finish(summary="ok"),
        FakeResponse([text("I will stop here.")], stop_reason="end_turn"),
    )

    assert outcome.finished_explicitly is False
    assert outcome.summary == "I will stop here."


def test_the_minimum_is_low_enough_for_one_honest_sentence():
    """A bound that rejects real answers is a bound that gets removed."""
    honest = "I read the two changed files and found nothing exploitable."
    assert len(honest) >= MIN_SUMMARY_CHARS


# --------------------------------------------------------- the artifact half


def test_the_artifact_separates_finishing_from_completing(cfg, ws):
    """Two different questions. `complete` is whether the loop reached its end;
    `finished_explicitly` is whether the reviewer said so."""
    outcome = _run(cfg, ws, FakeResponse([text("Nothing exploitable here.")],
                                         stop_reason="end_turn"))
    payload = build_json(cfg, outcome, decide(cfg, outcome))

    assert payload["complete"] is True
    assert payload["finished_explicitly"] is False


def test_an_artifact_that_predates_the_field_is_unknown_and_not_a_no(cfg, ws):
    """The rate this field exists to produce must not be poisoned by artifacts
    that predate the question.

    The last blocking finding of the repository audit — the Messages API path
    accepting `end_turn` as a completed review — was held back for a number:
    how often a real review ends without calling `finish_review`. The field was
    added to answer it, and the batch summary read it with `bool(...)`, so an
    artifact written before it existed counted as a review that did not sign
    off. All 36 member runs already stored are such artifacts. A denominator
    built from them would have looked like an answer and been one of the worst
    kinds of wrong: confident, and about the wrong population.
    """
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
    from artifact import signature

    case = {"expected_category": [], "expected_file": []}
    base = {"complete": True, "stop_reason": "completed", "findings": [],
            "verdict": {"exit_code": 0, "blocked": False,
                        "blocking_fingerprints": []},
            "usage": {}, "provenance": {}, "settings": {}, "model": "x"}

    assert signature(dict(base), case)["finished_explicitly"] is None
    assert signature(dict(base, finished_explicitly=False),
                     case)["finished_explicitly"] is False
    assert signature(dict(base, finished_explicitly=True),
                     case)["finished_explicitly"] is True


def test_unresolved_reaches_the_artifact_and_the_report(cfg, ws):
    outcome = _run(cfg, ws, finish(summary=GOOD_SUMMARY,
                                   unresolved=["Could not locate the router."]))
    payload = build_json(cfg, outcome, decide(cfg, outcome))
    markdown = render_markdown(cfg, outcome, decide(cfg, outcome))

    assert payload["unresolved"] == ["Could not locate the router."]
    assert "Could not locate the router." in markdown


def test_an_unresolved_entry_cannot_drive_the_report(cfg, ws):
    """Model-written prose about attacker-authored code. Five of six report
    sections once let it through as Markdown."""
    outcome = _run(cfg, ws, finish(
        summary=GOOD_SUMMARY,
        unresolved=["</details><script>alert(1)</script> [x](javascript:0)"]))
    markdown = render_markdown(cfg, outcome, decide(cfg, outcome))

    assert "<script>" not in markdown
    assert "</details><script>" not in markdown


# ---------------------------------------------------------- who may call it


def test_the_verifier_can_neither_report_nor_finish():
    """It answers one claim with one verdict. A vote on a single finding has no
    business closing the review that produced the finding."""
    names = {tool["name"] for tool in read_only_tool_definitions(diff_available=True)}

    assert FINISH_REVIEW not in names
    assert REPORT_FINDING not in names


def test_the_reviewer_is_told_to_call_it():
    """Severity was once derived from an `impact` value the prompt never
    mentioned. A tool the model is not told to use is a tool it will not use."""
    prompt = (PROMPTS / "system.md").read_text(encoding="utf-8")

    assert FINISH_REVIEW in prompt
    assert "unresolved" in prompt
