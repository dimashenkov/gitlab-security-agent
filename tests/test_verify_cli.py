"""Verification driven by the CLI, and the one lie it must never tell.

The chain under test is the whole one: this process reserves a seat, writes an
MCP config, launches a process, that process talks JSON-RPC to our own server,
the server runs `dispatch`, records the verdict in a `Session`, writes a session
document, and this process reads it back and hands it to the panel. Nothing here
constructs a `Vote` and calls `_decide` — that would prove the panel works,
which is already tested, and nothing about whether a vote can get from a child
process to a candidate.

Nothing here runs `claude` either. In its place is a script this file writes: it
reads the `--mcp-config` it was given, speaks enough MCP to call
`submit_verdict`, and prints the terminal JSON the CLI would print. It contains
no model, costs nothing, and — unlike the real CLI — can be asked to die halfway
through, which is where every failure that matters lives.

The failure the whole file is written against: **a verifier that did not vote
must never render as one that agreed.** A killed session, a missing document, a
session that stopped without voting, and a seat the budget refused all end as a
vote carrying `error`, and a candidate whose votes all errored is reported
unverified rather than confirmed by a panel that never spoke.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from conftest import make_candidate
from security_agent import verify as verify_api
from security_agent import verify_cli
from security_agent.budget import PROFILES, Profile, RunBudget
from security_agent.config import Config, GitLabContext
from security_agent.models import (
    VERDICT_CONFIRMED,
    VERDICT_REFUTED,
    VERDICT_UNCERTAIN,
    StageMetrics,
)
from security_agent.runner_claude_code import RunnerError
from security_agent.verify_cli import verify_candidates_with_cli
from security_agent.workspace import Workspace

PROMPTS = Path(__file__).resolve().parents[1] / "prompts"

# A verdict that satisfies the evidence rule: it names what would have refuted
# the finding and where that was looked for.
CONFIRMED = {
    "verdict": "confirmed",
    "reasoning": "The identifier reaches db.execute unquoted on every path.",
    "corrected_impact": "",
    "corrected_reachable_without_authentication": "",
    "corrected_requires_user_interaction": "",
    "corrected_confidence": "",
    "control_search": (
        "searched app/views.py and every caller of get_user for a validation "
        "of `id`; no such check exists"
    ),
    "entry_point": "app/views.py:1, get_user, reached from the public URL map",
}

REFUTED = {
    "verdict": "refuted",
    "reasoning": "Every caller coerces `id` to an integer before this line.",
    "corrected_impact": "",
    "corrected_reachable_without_authentication": "no",
    "corrected_requires_user_interaction": "",
    "corrected_confidence": "",
    "control_search": "searched the two callers in app/; both coerce to int first",
    "entry_point": "",
}


# ------------------------------------------------------------ the fake `claude`

FAKE_CLI = '''#!@PYTHON@
"""Stands in for `claude -p`: speaks MCP to our own server, and holds no model.

Everything below the `--mcp-config` flag is real — the server is our own module
in its own process, the tool call goes through `dispatch`, and the session
document is written by the code that writes it in production. What this script
replaces is only the part that would cost money.
"""
import json
import os
import subprocess
import sys
import time

PLAN = json.load(open("@PLAN@"))


def send(child, message):
    child.stdin.write(json.dumps(message) + "\\n")
    child.stdin.flush()


def ask(child, request_id, method, params):
    send(child, {"jsonrpc": "2.0", "id": request_id, "method": method,
                 "params": params})
    line = child.stdout.readline()
    if not line:
        raise SystemExit("the MCP server closed the connection")
    return json.loads(line)


def main():
    argv = sys.argv[1:]
    brief = sys.stdin.read()
    # What the process was actually started with, so a test can assert on the
    # world the session ran in rather than on the functions that build it.
    with open("@ENV_DUMP@", "w") as handle:
        json.dump({"environ": dict(os.environ), "cwd": os.getcwd(),
                   "argv": argv}, handle)

    if PLAN.get("sleep"):
        # Before the server is started, so a deadline test leaves no orphan.
        time.sleep(PLAN["sleep"])

    config = json.load(open(argv[argv.index("--mcp-config") + 1]))
    server = config["mcpServers"]["security_agent"]
    child = subprocess.Popen(
        [server["command"]] + server["args"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, env=server["env"],
        text=True)

    ask(child, 1, "initialize", {
        "protocolVersion": "2025-06-18", "capabilities": {},
        "clientInfo": {"name": "fake-claude", "version": "0"}})
    send(child, {"jsonrpc": "2.0", "method": "notifications/initialized"})

    request_id = 2
    for call in PLAN.get("calls") or []:
        ask(child, request_id, "tools/call",
            {"name": call["name"], "arguments": call.get("arguments") or {}})
        request_id += 1

    if PLAN.get("verdict") is not None:
        ask(child, request_id, "tools/call",
            {"name": "submit_verdict", "arguments": PLAN["verdict"]})

    if PLAN.get("kill_server"):
        # A child that dies after voting: the verdict was recorded in its
        # session and the session document is never written.
        child.kill()
    else:
        child.stdin.close()
    child.wait(timeout=30)

    print(json.dumps({
        "type": "result",
        "subtype": PLAN.get("subtype", "success"),
        "is_error": PLAN.get("is_error", False),
        "result": "read a brief of {} characters".format(len(brief)),
    }))
    return PLAN.get("exit_code", 0)


sys.exit(main())
'''


@pytest.fixture
def fake_cli(tmp_path):
    """Writes the stand-in and returns (path, environment-dump reader)."""
    directory = tmp_path / "fake-cli"
    directory.mkdir()
    plan_path = directory / "plan.json"
    env_dump = directory / "env.json"
    script = directory / "claude"

    def build(**plan):
        plan_path.write_text(json.dumps(plan), encoding="utf-8")
        script.write_text(
            FAKE_CLI.replace("@PYTHON@", sys.executable)
                    .replace("@PLAN@", str(plan_path))
                    .replace("@ENV_DUMP@", str(env_dump)),
            encoding="utf-8")
        script.chmod(0o755)
        return str(script)

    build.env_dump = env_dump  # type: ignore[attr-defined]
    return build


@pytest.fixture
def cfg(tmp_path):
    """One vote per finding, so a test asserts about one session.

    `fail_on="none"` is what buys that: `_votes_for` escalates anything that
    could block to a panel of three, which is right in production and is three
    processes per assertion here.
    """
    return Config(prompt_dir=PROMPTS, output_dir=tmp_path / "out",
                  gitlab=GitLabContext(), post_comment=False,
                  fail_on="none", verify_votes=1)


@pytest.fixture
def budget():
    return RunBudget(profile=PROFILES["normal"], turns_enforced=False)


@pytest.fixture
def ws(git_repo):
    return Workspace(root=git_repo, diff_base="", diff_head="HEAD")


def _dump(fake_cli):
    """What the stand-in recorded about the process it was started as."""
    return json.loads(fake_cli.env_dump.read_text(encoding="utf-8"))


def run(cfg, ws, candidates, budget, executable, **kwargs):
    verify_candidates_with_cli(
        cfg, ws, candidates, budget, executable=executable,
        config_digest="digest-123", **kwargs)


# --------------------------------------------------------- a vote that arrived


class TestAVoteReachesTheCandidate:
    def test_a_confirmation_travels_from_the_child_process_to_the_panel(
            self, cfg, ws, budget, fake_cli):
        """The whole chain in one assertion: seat, process, MCP, dispatch,
        session document, `_vote_from_payload`, panel. Every link in it has been
        broken at least once by a change that left its own tests green."""
        candidate = make_candidate()

        run(cfg, ws, [candidate], budget, fake_cli(
            verdict=CONFIRMED,
            calls=[{"name": "read_file", "arguments": {"path": "app/views.py"}}]))

        assert len(candidate.votes) == 1
        vote = candidate.votes[0]
        assert vote.error == ""
        assert vote.verdict == VERDICT_CONFIRMED
        assert candidate.verdict == VERDICT_CONFIRMED
        # Not "the panel agreed" in the abstract — the reasoning the verifier
        # gave, and what it searched for, are what a person overruling the gate
        # reads.
        assert "db.execute" in candidate.verdict_reason
        assert "Searched:" in candidate.verdict_reason

    def test_the_vote_records_which_channel_carried_it(
            self, cfg, ws, budget, fake_cli):
        """A verdict submitted as a tool argument and one scraped out of a final
        message are not equally trustworthy. On this transport only the first
        exists, and the artifact should say so rather than leave it blank."""
        candidate = make_candidate()

        run(cfg, ws, [candidate], budget, fake_cli(verdict=CONFIRMED))

        assert candidate.votes[0].channel == "submit_verdict"

    def test_what_the_verifier_opened_travels_with_its_vote(
            self, cfg, ws, budget, fake_cli):
        """A payload in a file that was never read did not fail — it was never
        tried. That question is only answerable if the files the session opened
        cross the process boundary with the vote."""
        candidate = make_candidate()

        run(cfg, ws, [candidate], budget, fake_cli(
            verdict=CONFIRMED,
            calls=[{"name": "read_file", "arguments": {"path": "app/views.py"}}]))

        assert "app/views.py" in candidate.votes[0].files_read

    def test_a_refutation_travels_the_same_way(self, cfg, ws, budget, fake_cli):
        """The direction that costs money to get wrong in the other sense: a
        refuted finding stops blocking, so it must not be reachable by any path
        looser than the one a confirmation takes."""
        candidate = make_candidate()

        run(cfg, ws, [candidate], budget, fake_cli(verdict=REFUTED))

        assert candidate.votes[0].verdict == VERDICT_REFUTED
        assert candidate.verdict == VERDICT_REFUTED

    def test_the_child_spends_from_the_seat_this_process_reserved(
            self, cfg, ws, budget, fake_cli):
        """The allowance is spent in another process. Unfolded, the run's usage
        report shows a ceiling that was allocated and never touched, which reads
        as capacity nobody needed."""
        run(cfg, ws, [make_candidate()], budget, fake_cli(
            verdict=CONFIRMED,
            calls=[{"name": "read_file", "arguments": {"path": "app/views.py"}}]))

        assert budget.verifier_sessions == 1
        # `read_file` and `submit_verdict`.
        assert budget.verifier_allowances[0].spent == 2


class TestTheEvidenceRuleStillApplies:
    def test_a_confirmation_that_cannot_say_what_it_searched_is_downgraded(
            self, cfg, ws, budget, fake_cli):
        """`_require_evidence` lives behind `_vote_from_payload`, and this path
        must go through it rather than around it. A verifier that confirms a
        finding without opening the caller is the exact defect it was written
        for, and on this transport the verdict arrives by a different route."""
        candidate = make_candidate()
        payload = dict(CONFIRMED, control_search="")

        run(cfg, ws, [candidate], budget, fake_cli(verdict=payload))

        vote = candidate.votes[0]
        assert vote.verdict == VERDICT_UNCERTAIN
        assert "downgraded from confirmed" in vote.reasoning
        assert candidate.verdict != VERDICT_CONFIRMED


# ------------------------------------------------- a vote that never arrived


class TestAVerifierThatDidNotVote:
    def test_a_session_that_ends_without_submitting_is_an_error_not_a_verdict(
            self, cfg, ws, budget, fake_cli):
        """The CLI exits zero whether the verifier voted or wandered off. Its
        own word is never enough: the vote is what the session document says,
        and a document with no verdict in it is a verifier that did not vote."""
        candidate = make_candidate()

        run(cfg, ws, [candidate], budget, fake_cli(
            verdict=None,
            calls=[{"name": "read_file", "arguments": {"path": "app/views.py"}}]))

        vote = candidate.votes[0]
        assert vote.error
        assert "without submitting a verdict" in vote.error
        assert vote.verdict != VERDICT_CONFIRMED

    def test_a_vote_submitted_before_the_child_died_still_counts(
            self, cfg, ws, budget, fake_cli):
        """This asserted the opposite yesterday, and yesterday was right.

        The child used to hand its session over once, at exit, so a verdict
        recorded and then killed reached nobody — the vote had to be an error.
        It hands over after every state change now, because that exit does not
        arrive: the CLI takes its MCP servers down with it.

        So the document written at the moment of the vote *is* the session at
        the moment of the vote, not one a deadline cut off later. And a verifier
        is not a reviewer: `submit_verdict` is its whole answer, and there was
        nothing further it was going to do. Counting it is right.
        """
        candidate = make_candidate()

        run(cfg, ws, [candidate], budget, fake_cli(
            verdict=CONFIRMED, kill_server=True))

        vote = candidate.votes[0]
        assert not vote.error
        assert vote.verdict == VERDICT_CONFIRMED
        assert vote.channel == "submit_verdict"

    def test_a_document_from_another_run_is_refused_rather_than_read(
            self, cfg, ws, budget, fake_cli, monkeypatch):
        """A document that exists and cannot be trusted is worse than none: it
        has the shape of an answer. Simulated by moving the run id after the
        child was launched with the old one, which is what a stale document from
        a previous run looks like from here."""
        candidate = make_candidate()
        original = verify_cli.read_session

        def different_run(path, *, run_id, revision, config_digest):
            return original(path, run_id="somebody-elses", revision=revision,
                            config_digest=config_digest)

        monkeypatch.setattr(verify_cli, "read_session", different_run)

        run(cfg, ws, [candidate], budget, fake_cli(verdict=CONFIRMED))

        assert "cannot accept" in candidate.votes[0].error
        assert candidate.votes[0].verdict != VERDICT_CONFIRMED

    def test_a_session_killed_at_the_deadline_is_an_error(
            self, cfg, ws, fake_cli):
        """A verifier stopped by the clock searched for as long as it had, not
        for as long as it needed. Its own child writes a session document when
        its pipes close — which killing it does — so a verdict may land on disk
        during the kill; reading it would be reading a session that was still
        going."""
        profile = Profile("test-deadline", review_turns=None,
                          review_tool_calls=10, verifier_sessions=3,
                          verifier_tool_calls=5, runtime_seconds=1)
        budget = RunBudget(profile=profile, turns_enforced=False)
        candidate = make_candidate()

        run(cfg, ws, [candidate], budget, fake_cli(verdict=CONFIRMED, sleep=30))

        vote = candidate.votes[0]
        assert vote.error
        assert "time limit" in vote.error
        assert vote.verdict != VERDICT_CONFIRMED


class TestWhenNoVerifierVoted:
    def test_the_finding_is_reported_unverified_not_confirmed_by_the_panel(
            self, cfg, ws, budget, fake_cli):
        """The whole file's rule, at the point where it decides the gate.

        Three sessions, none of which voted. `_decide` has one behaviour for
        that — the finding keeps the rating it arrived with and is labelled
        unverified — and what must never happen is a `confirmed` that reads as
        three verifiers agreeing.
        """
        cfg.fail_on = "high"  # the panel of three a blocking finding gets
        candidate = make_candidate()
        metrics = StageMetrics()

        run(cfg, ws, [candidate], budget, fake_cli(verdict=None), metrics=metrics)

        assert len(candidate.votes) == 3
        assert all(vote.error for vote in candidate.votes)
        assert not any(vote.verdict == VERDICT_CONFIRMED for vote in candidate.votes)
        # `_decide`'s answer with nothing usable: the finding stands, and the
        # reason says plainly that nobody checked it.
        assert candidate.verdict == VERDICT_CONFIRMED
        assert candidate.verdict_reason.startswith("reported unverified")
        assert "verification could not run" in candidate.verdict_reason
        assert metrics.verification_failed == 1


# ------------------------------------------------------------------- the seat


class TestTheBudgetDecidesHowManySessionsRun:
    def test_a_fourth_seat_is_refused_and_the_claim_says_it_was_not_checked(
            self, cfg, ws, budget, fake_cli):
        """`reserve_verifier` hands out the seat and the tool-call allowance in
        one step, and the profile allows three. The fourth finding must not be
        quietly dropped, and must not borrow a verdict from the three that ran:
        it gets a vote that says no session was available."""
        candidates = [make_candidate(title="finding {}".format(n)) for n in range(4)]

        run(cfg, ws, candidates, budget, fake_cli(verdict=CONFIRMED))

        assert budget.verifier_sessions == PROFILES["normal"].verifier_sessions == 3
        for candidate in candidates[:3]:
            assert candidate.votes[0].error == ""
            assert candidate.verdict == VERDICT_CONFIRMED
        refused = candidates[3].votes[0]
        assert "no verifier session was available" in refused.error
        assert candidates[3].verdict_reason.startswith("reported unverified")

    def test_no_seat_means_no_process(self, cfg, ws, fake_cli):
        """A profile with no verifiers must not launch anything at all — the
        seat is reserved before the session starts, which is the only ordering
        in which a refusal can prevent the cost."""
        budget = RunBudget(profile=PROFILES["probe"], turns_enforced=False)
        candidate = make_candidate()
        executable = fake_cli(verdict=CONFIRMED)

        run(cfg, ws, [candidate], budget, executable)

        assert budget.verifier_sessions == 0
        assert candidate.votes[0].error
        # The stand-in writes this the moment it starts; its absence is proof
        # no process ran.
        assert not fake_cli.env_dump.exists()


# ----------------------------------------------------------- the child's world


class TestWhatTheSessionIsRunWith:
    def test_the_api_key_is_not_in_the_environment_of_the_session(
            self, cfg, ws, budget, fake_cli, monkeypatch):
        """A verifier that could not authenticate as the subscription must not
        quietly bill an account instead. Enforced by taking away the means, and
        asserted from inside the process that was actually launched rather than
        from the function that builds its environment."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
        monkeypatch.setenv("ANTHROPIC_AUTH_TOKEN", "token")

        run(cfg, ws, [make_candidate()], budget, fake_cli(verdict=CONFIRMED))

        environment = _dump(fake_cli)["environ"]
        assert "ANTHROPIC_API_KEY" not in environment
        assert "ANTHROPIC_AUTH_TOKEN" not in environment
        # Not an empty environment: the CLI still needs its own configuration to
        # run as the developer at all.
        assert "PATH" in environment

    def test_the_session_runs_outside_the_repository_it_is_reading(
            self, cfg, ws, budget, fake_cli):
        """The reviewed tree carries `CLAUDE.md`, hooks, settings and plugins
        that the author of the change under review can edit — a second
        instruction channel underneath our prompt contract. The verifier reads
        that repository through our server, in another process, and is never
        started inside it. Not a setting: the absence of a path."""
        run(cfg, ws, [make_candidate()], budget, fake_cli(verdict=CONFIRMED))

        dump = _dump(fake_cli)
        assert not Path(dump["cwd"]).is_relative_to(ws.root)
        # And no path into the tree is in what the session itself was run with;
        # the one place the repository appears is our server's own arguments,
        # in another process.
        assert str(ws.root) not in dump["argv"]

    def test_a_missing_cli_is_refused_rather_than_worked_around(
            self, cfg, ws, budget):
        """There is no route from here to the paid API. Raised rather than
        turned into an errored vote per finding: "every verifier failed"
        describes a panel that ran and could not answer, and nothing ran."""
        with pytest.raises(RunnerError) as raised:
            run(cfg, ws, [make_candidate()], budget,
                "a-command-that-does-not-exist")

        assert "will not fall back" in str(raised.value)


# ------------------------------------------------- the findings never verified


class TestFindingsThatAreNotSentToAPanel:
    def test_verification_can_be_switched_off_without_launching_anything(
            self, cfg, ws, budget):
        """Decided before the executable is looked for, so a run with nothing to
        verify does no work at all — including not failing over a CLI it was
        never going to use."""
        cfg.verify = False
        candidate = make_candidate()

        run(cfg, ws, [candidate], budget, "a-command-that-does-not-exist")

        assert candidate.verdict == VERDICT_CONFIRMED
        assert candidate.verdict_reason == (
            "verification disabled (SECURITY_SCAN_VERIFY=false)")
        assert candidate.votes == []

    def test_a_finding_that_cannot_block_is_labelled_exactly_as_the_api_path_does(
            self, cfg, ws, budget):
        """Two runners that skip the same finding for different stated reasons
        are two products. The scope rules are called rather than restated — this
        is what proves it, by putting the same candidate through both paths and
        comparing the sentence a reader gets.

        Neither path spends anything here: both decide the finding is
        informational before any client is touched, which is why the API path
        can be driven with no client at all.
        """
        cfg.fail_on = "high"
        cli_side = make_candidate(severity="low", in_changed_lines=False)
        api_side = make_candidate(severity="low", in_changed_lines=False)

        run(cfg, ws, [cli_side], budget, "a-command-that-does-not-exist")
        verify_api.verify_candidates(cfg, ws, None, [api_side])

        assert cli_side.verdict_reason.startswith("not verified —")
        assert cli_side.verdict_reason == api_side.verdict_reason
        assert cli_side.verdict == api_side.verdict == VERDICT_CONFIRMED

    def test_beyond_the_maximum_is_named_rather_than_dropped(
            self, cfg, ws, budget, fake_cli):
        """A finding past `SECURITY_SCAN_VERIFY_MAX` is still reported, and the
        report says why nobody checked it."""
        cfg.verify_max_findings = 1
        candidates = [make_candidate(title="finding {}".format(n)) for n in range(2)]

        run(cfg, ws, candidates, budget, fake_cli(verdict=CONFIRMED))

        assert candidates[0].votes and candidates[0].votes[0].error == ""
        assert candidates[1].votes == []
        assert "SECURITY_SCAN_VERIFY_MAX" in candidates[1].verdict_reason

    def test_a_finding_past_the_maximum_is_not_counted_as_verified(
            self, cfg, ws, budget, fake_cli):
        """The count and the sentence have to agree. They did not: `verified`
        included the findings whose own reason says nobody checked them, so the
        artifact contradicted itself on every run over the limit."""
        cfg.verify_max_findings = 1
        metrics = StageMetrics()
        candidates = [make_candidate(title="finding {}".format(n)) for n in range(3)]

        run(cfg, ws, candidates, budget, fake_cli(verdict=CONFIRMED), metrics=metrics)

        assert metrics.verified == 1
        assert metrics.verified == sum(1 for c in candidates if c.votes)
