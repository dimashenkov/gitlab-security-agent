"""A review that was refused what it asked for used to exit 0.

`context_budget.py` says of itself that every refusal "counts toward the run
being incomplete, and can never turn into a clean pass". Nothing outside the
module read `refused_results`. `gate._partial` looked at the stop reason and at
`diff_truncated` and at nothing else, so a reviewer told "that result was too
large" could call `finish_review`, end `completed`, and be reported as clean.

Twenty-four tests covered the budget itself and all of them passed. They tested
the helper. This file tests the chain — refused result, finish_review, verdict —
which is the boundary where the promise either holds or does not.

There was a second half to the same defect, and it was worse. The read handlers
recorded `note_exposure` *before* the budget was consulted, so a refused read
was filed as bytes that had reached the model. `gate._reviewed_nothing` reads
exposures to tell a review that stopped early from one that never started: a run
refused every single result would have claimed to have seen the change.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from security_agent.context_budget import BYTES_PER_TOKEN, ContextBudget
from security_agent.gate import EXIT_ERROR, EXIT_OK, decide
from security_agent.models import ScanOutcome
from security_agent.runner_claude_code import _apply_session
from security_agent.tools import Session, ToolResult, _budgeted, dispatch
from security_agent.workspace import Workspace

PROMPTS = Path(__file__).resolve().parents[1] / "prompts"


def big(tokens: int) -> str:
    return "x" * (tokens * BYTES_PER_TOKEN)


@pytest.fixture
def repo(tmp_path):
    """A real repository with one changed file, so the read is a real read."""
    import subprocess

    root = tmp_path / "repo"
    root.mkdir()

    def git(*args):
        subprocess.run(["git", "-C", str(root), *args], check=True,
                       capture_output=True)

    subprocess.run(["git", "init", "-q", str(root)], check=True,
                   capture_output=True)
    git("config", "user.email", "t@example.com")
    git("config", "user.name", "T")
    (root / "app.py").write_text("VALUE = 0\n", encoding="utf-8")
    git("add", "-A")
    git("commit", "-qm", "base")
    base = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"],
                          capture_output=True, text=True, check=True).stdout.strip()
    (root / "app.py").write_text(
        "".join("LINE_{} = {}\n".format(n, n) for n in range(3000)),
        encoding="utf-8")
    git("add", "-A")
    git("commit", "-qm", "change")
    return Workspace(root=root, diff_base=base, diff_head="HEAD")


class TestARefusedReadIsNotAnExposure:
    """The half of the defect that defeated the last line of defence."""

    def test_a_refused_read_file_records_nothing(self, repo):
        session = Session()
        session.context = ContextBudget(soft=10, hard=20)

        result = dispatch(repo, session, "read_file", {"path": "app.py"})

        assert result.is_error
        assert session.exposures == []
        assert session.files_examined == []

    def test_an_admitted_read_file_records_it(self, repo):
        """The control. Deferring the accounting must not lose it."""
        session = Session()
        session.context = ContextBudget(soft=100_000, hard=200_000)

        dispatch(repo, session, "read_file", {"path": "app.py"})

        assert session.exposures == [("app.py", "read_file")]
        assert session.files_examined == ["app.py"]

    def test_a_refused_diff_records_no_exposure(self, repo):
        session = Session()
        session.context = ContextBudget(soft=10, hard=20)

        dispatch(repo, session, "get_diff", {})

        assert session.exposures == []

    def test_recording_it_anyway_is_what_would_have_passed_the_gate(
            self, config, repo):
        """Spelled out, because the counter-example is the whole point.

        A run that was refused everything has no exposures, so even before the
        refusal count reaches the gate, `_reviewed_nothing` catches it — and
        catches it in the way no setting can forgive.
        """
        session = Session()
        session.context = ContextBudget(soft=10, hard=20)
        dispatch(repo, session, "read_file", {"path": "app.py"})
        dispatch(repo, session, "get_diff", {})
        session.finished = True

        outcome = ScanOutcome(mode="diff")
        outcome.coverage.changed = ["app.py"]
        _apply_session(outcome, session)

        decision = decide(config, outcome)

        assert decision.exit_code == EXIT_ERROR
        assert "no part of the change" in decision.reason


class TestARefusalReachesTheVerdict:
    """The run that read *most* of the change and was refused one result."""

    def _outcome(self, repo, config):
        session = Session()
        session.context = ContextBudget(soft=100_000, hard=200_000)
        # A real read, admitted: this run saw the change.
        dispatch(repo, session, "get_diff", {})
        # Then one request the budget would not hand over.
        session.context.hard = session.context.estimated_result_tokens + 5
        refused = _budgeted(session, "read_file", ToolResult(big(5000), "big"))
        assert refused.is_error
        session.finished = True

        outcome = ScanOutcome(mode="diff")
        outcome.coverage.changed = ["app.py"]
        _apply_session(outcome, session)
        return outcome

    def test_the_run_looks_healthy_which_is_the_problem(self, repo, config):
        outcome = self._outcome(repo, config)

        assert outcome.complete is True
        assert outcome.exposures
        assert outcome.reported == []

    def test_the_refusal_travels_to_the_coverage_accounting(self, repo, config):
        outcome = self._outcome(repo, config)

        assert outcome.coverage.context_refusals == 1

    def test_the_gate_refuses_to_call_it_checked(self, repo, config):
        outcome = self._outcome(repo, config)

        decision = decide(config, outcome)

        assert decision.exit_code == EXIT_ERROR
        assert "never saw" in decision.reason

    def test_the_reason_names_both_remedies(self, repo, config):
        """A warning whose only remedy is "configure it differently" gets
        configured away. The broad request can also simply be narrowed."""
        outcome = self._outcome(repo, config)

        reason = decide(config, outcome).reason
        assert "Narrow those reads" in reason
        assert "raise the context limit" in reason

    def test_the_operator_can_still_forgive_it(self, repo, config):
        """Like a truncated diff and unlike an inconclusive profile. A refusal
        is a property of one run against one limit, and the operator has real
        moves; a gate a large change can never satisfy gets deleted."""
        config.fail_on_incomplete = False
        outcome = self._outcome(repo, config)

        assert decide(config, outcome).exit_code == EXIT_OK

    def test_a_run_refused_nothing_is_unaffected(self, repo, config):
        """The control: this cannot be satisfied by failing everything."""
        session = Session()
        dispatch(repo, session, "get_diff", {})
        session.finished = True
        outcome = ScanOutcome(mode="diff")
        outcome.coverage.changed = ["app.py"]
        _apply_session(outcome, session)

        assert outcome.coverage.context_refusals == 0
        assert decide(config, outcome).exit_code == EXIT_OK
