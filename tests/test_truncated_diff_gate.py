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
moves — split it, narrow the review with `--path`, read the oversized file in
windows, or raise the ceiling. A gate that a large legitimate change can never
satisfy is a gate that gets deleted, so this fails loudly by default and is
forgiven by the same documented flag as every other partial review.

The windows are third in that list and were once absent from it, which mattered
once any cut in any scope began to count: for a *single file* bigger than the
ceiling, splitting the change and narrowing with `--path` are both advice that
cannot be followed, and raising a global ceiling to read one file is the wrong
lever. A reader told to do something they cannot do stops reading.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from conftest import make_candidate
from fakes import FakeClient, FakeResponse, text, tool_use
from security_agent.agent import SecurityAgent
from security_agent.config import Config, GitLabContext
from security_agent.gate import EXIT_ERROR, EXIT_FINDINGS, EXIT_OK, decide
from security_agent.models import STOP_COMPLETED, STOP_INCONCLUSIVE, ScanOutcome
from security_agent.runner_claude_code import _apply_session
from security_agent.tools import Session, dispatch
from security_agent.workspace import Workspace

PROMPTS = Path(__file__).resolve().parents[1] / "prompts"


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
    # A truncated review is one that read the first part of a large change, so
    # part of that change reached the model. Recorded here because the gate now
    # separates a review that stopped early from one nothing reached, and a
    # fixture with no exposures describes the second while meaning the first.
    #
    # As an exposure rather than as `examined`: `get_diff` is what happened
    # here, and it carries a file's bytes without opening it by name.
    outcome.coverage.changed = ["big/one.py", "big/two.py"]
    outcome.exposures = [("big/one.py", "get_diff")]
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

    def test_the_reason_names_the_remedy_for_one_oversized_file(
            self, config, big_change):
        """Splitting the change and narrowing with `--path` are both impossible
        when the file itself is over the ceiling — and since any cut in any
        scope now counts, that is a case a reader will actually meet. Naming
        only the two moves they cannot make sends them to raise a global
        ceiling to read one file."""
        decision = decide(config, outcome_for(big_change))

        assert "windows" in decision.reason

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


class TestTheCutHasToReachTheOutcome:
    """The one assignment `outcome_for` above makes by hand, made by the code.

    Everything in this file so far starts from `outcome.coverage.diff_truncated`
    already being set. That is the field `gate._partial` reads, and it is the
    *end* of the chain; the hops that fill it were held by nothing, which is
    exactly the shape that produced this defect the first time — the workspace
    recorded the cut correctly for weeks while the runner reported an
    untruncated diff, because nobody carried the flag across the gap.

    There are two carriers, one per runner, and each had one untested hop:

    * `tools._handle_get_diff` copies the workspace's flag onto the *session*.
      That is the CLI runner's route, and it needs one, because `get_diff` runs
      in a child process against a different `Workspace` — the parent's own
      flag is always False there. `_apply_session` reading the session is
      tested in `test_runner_claude_code.py`; the session getting the flag in
      the first place was not, and every test that exercised the far half set
      `session.diff_truncated = True` by hand.
    * `agent.py` reads its own workspace, because on the API path there is only
      one. Nothing asserted that line either.

    Delete either one and `python3 -m pytest tests/ -q` stays green while the
    gate is handed False for a review that saw the first 4 KB of a change.
    """

    def _fresh(self, ws: Workspace) -> Workspace:
        """A second workspace over the same repository.

        `diff_truncated` is sticky once set, so a test about *not* setting it
        cannot reuse a workspace another call has already diffed.
        """
        return Workspace(root=ws.root, diff_base=ws.diff_base, diff_head="HEAD")

    def test_asking_for_the_whole_change_marks_the_session(self, big_change):
        session = Session()
        dispatch(big_change, session, "get_diff", {})

        # The precondition, said out loud: if the fixture ever stopped
        # overflowing the ceiling the assertion below would be about nothing.
        assert big_change.diff_truncated is True
        assert session.diff_truncated is True

    def test_a_single_file_diff_marks_the_session_too(self, big_change):
        """`app.py` is over the ceiling on its own, and the session says so.

        This assertion used to be `is False`, on the argument that the flag was
        a statement about the unqualified diff and that failing every review of
        a large file makes a gate nothing can satisfy — and a gate nothing can
        satisfy gets switched off. That argument is real and it lost, for two
        reasons found later.

        The first is that it was never true of both runners. `agent.py` reads
        its own workspace, where the flag is set by any cut in any scope, so the
        Messages API path already exited 2 on this case while the CLI path
        exited 0 — the same review, two verdicts, decided by which runner
        happened to be configured.

        The second is Codex's ruling, translated: *"a particular file cut short
        is exactly 'the whole relevant change was not seen'. Exit 0 would breach
        the fundamental invariant."* A file handed over in part is part of the
        change unseen, and the notice in the tool output is read by the model,
        not by the person merging.

        The right model is a third thing and is not built: separate *truncation
        was observed* from *a relevant part is still unread*, and gate only on
        the second, so that reading the rest afterwards clears it. Until that
        distinction exists, strict is the only correct choice — and the remedy
        for one oversized file is to read it in windows, not to raise a global
        ceiling.
        """
        ws = self._fresh(big_change)
        session = Session()
        dispatch(ws, session, "get_diff", {"path": "app.py"})

        assert ws.diff_truncated is True
        assert session.diff_truncated is True

    def test_the_cli_runners_chain_ends_at_the_gate(self, config, big_change):
        """Workspace to session to outcome to exit code, nothing set by hand.

        The whole point of the flag is the last step, so the test that holds
        the missing hop has to go all the way there. `_apply_session` is the
        same call the CLI runner makes on the parent side.
        """
        session = Session()
        dispatch(big_change, session, "get_diff", {})
        outcome = ScanOutcome(mode="diff")
        _apply_session(outcome, session)

        # The run looks entirely healthy, which is what made this dangerous:
        # it completed, and reading the diff put the file in front of the
        # model, so neither of the gate's other two partial-review branches
        # fires here.
        assert outcome.complete is True
        assert outcome.exposures, "nothing reached the model, so a later "\
                                  "assertion could pass down the wrong branch"

        decision = decide(config, outcome)

        assert decision.exit_code == EXIT_ERROR
        assert "first part of the diff" in decision.reason

    def test_the_api_runner_records_the_cut_it_made(self, tmp_path, big_change):
        """The same journey on the other runner, driven by a real agent loop.

        Here the model asks for the diff, the workspace cuts it, and the run
        ends cleanly on `end_turn` — a completed review of a change it was
        shown 4 KB of. The line under test is the one in `agent.py` that reads
        the workspace after the loop; without it this exits 0 saying "No
        security findings."
        """
        cfg = Config(prompt_dir=PROMPTS, output_dir=tmp_path / "out",
                     gitlab=GitLabContext(), post_comment=False)
        client = FakeClient([
            FakeResponse([tool_use("get_diff", {}, id="t1")], stop_reason="tool_use"),
            FakeResponse([text("Reviewed the change; nothing found.")],
                         stop_reason="end_turn"),
        ])

        outcome = SecurityAgent(cfg, big_change, client=client).run(
            "diff", "Review the change.")

        assert outcome.stop_reason == STOP_COMPLETED
        assert outcome.coverage.diff_truncated is True

        decision = decide(cfg, outcome)

        assert decision.exit_code == EXIT_ERROR
        assert "first part of the diff" in decision.reason
