"""A review shown half a change used to exit 0 and say "no security findings".

`Workspace._bounded` stops reading git's output at a ceiling and records that it
did. Everything past the cut was never put in front of the model. The run then
ended `completed`, coverage accounting listed every changed file, and the gate
returned 0 — the one sentence this product exists to prevent, printed over a
change nobody read the end of.

The only thing standing in front of that was a warning in the report, which is
a document a person may or may not open, under a green tick.

Truncation is deliberately *not* in `NEVER_FORGIVEN`. A profile that cannot
conclude is a property of the configuration, and no run of it means anything; a
diff over the ceiling is a property of one change, and the operator has real
moves — split it, narrow the review with `--path`, raise the ceiling. A gate
that a large legitimate change can never satisfy is a gate that gets deleted, so
this fails loudly by default and is forgiven by the same documented flag as
every other partial review.
"""

from __future__ import annotations

import subprocess

import pytest

from conftest import make_candidate
from security_agent.gate import EXIT_ERROR, EXIT_FINDINGS, EXIT_OK, decide
from security_agent.models import STOP_INCONCLUSIVE, ScanOutcome
from security_agent.workspace import Workspace


@pytest.fixture
def big_change(tmp_path, monkeypatch):
    """A real repository whose change is larger than the ceiling."""
    root = tmp_path / "repo"
    root.mkdir()

    def git(*args):
        subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True)

    subprocess.run(["git", "init", "-q", str(root)], check=True, capture_output=True)
    git("config", "user.email", "t@example.com")
    git("config", "user.name", "T")
    (root / "app.py").write_text("VALUE = 0\n", encoding="utf-8")
    git("add", "-A")
    git("commit", "-qm", "base")
    base = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"],
                          capture_output=True, text=True, check=True).stdout.strip()
    (root / "app.py").write_text(
        "".join("LINE_{} = {}\n".format(n, n) for n in range(4000)), encoding="utf-8")
    git("add", "-A")
    git("commit", "-qm", "change")

    monkeypatch.setattr(Workspace, "MAX_DIFF_BYTES", 4096)
    return Workspace(root=root, diff_base=base, diff_head="HEAD")


def outcome_for(ws: Workspace) -> ScanOutcome:
    """What the run records after showing the model the diff.

    The one assignment `agent.py` makes, made here: reading the diff is what
    sets the flag, and a test that set the field by hand would prove nothing
    about whether reading a real oversized change sets it.
    """
    outcome = ScanOutcome(mode="diff")
    ws.diff()
    outcome.coverage.diff_truncated = ws.diff_truncated
    return outcome


class TestATruncatedDiffIsNotAPass:
    def test_reading_an_oversized_change_records_the_cut(self, big_change):
        outcome = outcome_for(big_change)

        assert outcome.coverage.diff_truncated is True
        # And the run itself looks perfectly healthy, which is the problem.
        assert outcome.complete is True

    def test_the_gate_refuses_to_call_it_checked(self, config, big_change):
        decision = decide(config, outcome_for(big_change))

        assert decision.exit_code == EXIT_ERROR
        assert "first part of the diff" in decision.reason

    def test_the_reason_says_what_to_do_about_it(self, config, big_change):
        """A warning nobody can act on is a warning that gets ignored. Turn
        limits and truncation are both "partial", and only one of them is fixed
        by splitting the merge request."""
        decision = decide(config, outcome_for(big_change))

        assert "--path" in decision.reason or "Split the change" in decision.reason

    def test_a_change_inside_the_ceiling_is_unaffected(self, config, tmp_path):
        """The control: an ordinary change still passes with the ordinary
        sentence, so this cannot be satisfied by failing everything."""
        outcome = ScanOutcome(mode="diff")

        decision = decide(config, outcome)

        assert decision.exit_code == EXIT_OK
        assert decision.reason == "No security findings."


class TestWhoMayForgiveIt:
    def test_the_documented_flag_still_lets_it_through(self, config, big_change):
        config.fail_on_incomplete = False

        decision = decide(config, outcome_for(big_change))

        assert decision.exit_code == EXIT_OK
        assert "Coverage is partial" in decision.reason
        assert "No security findings" not in decision.reason

    def test_a_profile_that_cannot_conclude_is_still_never_forgiven(self, config):
        """The distinction the two cases turn on, asserted so that a later
        change cannot quietly merge them."""
        config.fail_on_incomplete = False
        outcome = ScanOutcome(mode="diff", stop_reason=STOP_INCONCLUSIVE)

        assert decide(config, outcome).exit_code == EXIT_ERROR

    def test_findings_still_block_when_the_diff_was_cut(self, config, big_change):
        """Forgiving the coverage does not forgive what was found in the part
        that *was* read."""
        config.fail_on_incomplete = False
        outcome = outcome_for(big_change)
        outcome.reported = [make_candidate(severity="high")]

        assert decide(config, outcome).exit_code == EXIT_FINDINGS
