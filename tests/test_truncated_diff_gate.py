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
diff over the ceiling is a property of one change, and the operator has a real
move. A gate that a large legitimate change can never satisfy is a gate that
gets deleted, so this fails loudly by default and is forgiven by the same
documented flag as every other partial review.

**Which move, though, took eight gate rounds to state truthfully**, and every
wrong version was the same shape: a sentence naming a remedy that nothing
checked.

`--path` is a remedy for the files whose own diff fits the limit, and for no
others. A file bigger than it comes back cut in exactly the same way when asked
for alone — whether it is the file the cut landed inside or a later one dropped
entirely — and only splitting the change to it helps. Splitting it by which
*cut* happened, as this file did for a round, gets that wrong for a dropped
oversized file.

Three candidates were tried for a general third move and all three refused.

"Read the oversized file in windows" is worse than useless: `read_file` returns
the reviewed revision, so it cannot show a removed line and cannot tell an
added one from a line that was always there. It looks like a recovery and is
not, and a reader who believes it has recovered the change stops looking.

Raising `SECURITY_SCAN_DIFF_CEILING_BYTES` does not fill it either, and that
was measured rather than argued: it moves `Workspace.diff_ceiling`, the ceiling
on *bytes read*, while `tools.MAX_DIFF_CHARS` independently trims what the
model is shown and is a module constant. With the byte ceiling raised fifty
times above it, `last_diff_truncated` is False and the result is still trimmed.

Saying flatly that it does not help was then wrong in the other direction. Two
ceilings can cut a diff and `_why_partial` sees one flag for both, because
`_handle_get_diff` collapses `trimmed` and `ws.last_diff_truncated` into one
`diff_truncated` before the gate looks. So the sentence is conditional — the
setting helps when the byte ceiling is what cut — which is what the code can
support.

The same missing distinction runs through the `--path` half: `DiffCut` knows
whether the cut was mid-file and does not pass it on either, so both messages
describe both cases rather than choosing. Carrying the cause through
`Coverage` would let them say the true thing for the run in hand. It is not
built, and `LIMITATIONS.md` records that.

Splitting covers the single-file case after all: the change *to that file* can
be split. What no move does is recover the current run; `LIMITATIONS.md`
carries the residue.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from conftest import make_candidate
from fakes import FakeClient, FakeResponse, text, tool_use
from security_agent.agent import SecurityAgent
from security_agent.config import Config, GitLabContext
from security_agent.gate import (
    EXIT_ERROR,
    EXIT_FINDINGS,
    EXIT_OK,
    decide,
    truncation_remedy,
)
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
        assert "some changed lines were never delivered" in decision.reason

    def test_the_reason_says_what_to_do_about_it(self, config, big_change):
        """A warning nobody can act on is a warning that gets ignored. Turn
        limits and truncation are both "partial", and only one of them is fixed
        by splitting the merge request."""
        decision = decide(config, outcome_for(big_change))

        assert "--path" in decision.reason or "Split the change" in decision.reason

    def test_the_reason_names_the_remedy_for_one_oversized_file(
            self, config, big_change):
        """A single file whose own diff is over the shown-limit has exactly one
        move — splitting the change to that file — and the sentence has to say
        which one, because the other two do nothing there. `--path` on that
        file reaches the identical limit, and the ceiling setting lifts the
        byte limit and not this one.

        Two candidates were tried in this slot and refused a round apart:
        "read the oversized file in windows" (`read_file` returns the reviewed
        revision, so it cannot show a removed line) and the ceiling setting
        (measured — the workspace read it whole and the result was still
        trimmed).
        """
        decision = decide(config, outcome_for(big_change))

        assert "has to have the change to it split" in decision.reason
        assert "asking for that file alone is cut in the same place" \
            in decision.reason
        assert "windows" not in decision.reason

    def test_the_report_and_the_gate_do_not_disagree_about_the_remedy(
            self, config, big_change):
        """One run, two documents a person reads, and for one round they said
        different things: the gate had been repaired and `report.py` still
        recommended raising the ceiling "for a complete reading". Codex found
        it on the fourth gate round, together with the same stale claim in
        `README.md` and in this file's own narrative.

        Asserted as a pair, because each was self-consistent while they
        disagreed — which is the state that let it survive.

        The first version of this test *blessed* the difference: it asserted
        "does not help" in one and "helps only when" in the other, which is a
        test written to accept exactly the contradiction it was added to
        forbid. Codex found that on the fifth round, along with the fact that
        the gate's flat claim was unsupportable — two ceilings can cut a diff
        and `_why_partial` cannot tell which one did, because
        `_handle_get_diff` collapses both into one flag before it looks.
        """
        from security_agent.report import _truncated_diff_note

        decision = decide(config, outcome_for(big_change))
        note = " ".join(_truncated_diff_note(outcome_for(big_change)))

        # **Equality, not a list of substrings.** Two earlier versions of this
        # test asserted selected phrases in each — which is a test that cannot
        # enforce the property it is named for, because each copy was
        # self-consistent while the pair contradicted itself. Codex said so on
        # the seventh round, and the repair is structural: one function builds
        # the sentence and each channel only chooses how identifiers are
        # wrapped.
        #
        # Normalised for the three differences that are presentation:
        # backticks (markdown against a job log), leading case and the full
        # stop (a clause inside a verdict line against a sentence of its own).
        def normalised(text):
            return " ".join(text.replace("`", "").split()).strip(".").casefold()

        shared = normalised(truncation_remedy())
        assert shared in normalised(decision.reason), decision.reason
        assert shared in normalised(note), note

        # And the sentence itself still carries the qualification that took six
        # rounds: `--path` is a remedy for the files whose own diff fits, and
        # the ceiling setting only for the byte cut.
        assert "--path helps only for the files whose own diff fits" in shared
        assert "security_scan_diff_ceiling_bytes helps only when" in shared

    def test_the_sentence_does_not_say_which_limit_cut_the_diff(self):
        """It cannot know. `diff_truncated` is one flag over two limits, and
        with `SECURITY_SCAN_DIFF_CEILING_BYTES` set below `MAX_DIFF_CHARS` a
        diff can fit what the reviewer is shown and still be cut while the
        workspace reads it — the same for a `--path` call on a file that fits
        the display limit.

        It opened with "larger than the reviewer can be shown" for one round,
        which names one of the two. Codex, eighth gate round, 2026-09-08.
        """
        said = truncation_remedy()

        assert said.startswith(
            "at least one diff was cut before all of it reached"), said
        assert "larger than the reviewer can be shown" not in said, said
        assert "too large" not in said, said

    def test_the_ceiling_setting_is_named_as_the_lever_that_does_not_work(
            self, config, big_change):
        """It filled the third slot for one round as an unqualified move, and
        for one more round as an unqualified refusal. Both were wrong, in
        opposite directions, and the second is the interesting one: two
        ceilings can cut a diff, `_why_partial` sees one flag for both, and
        "this lever does not help" is a claim about which ceiling cut it.

        Named rather than omitted because it is the obvious lever, and a reader
        who reaches for it unwarned and gets the same result stops trusting the
        message. Conditional, because that is what the code can support.
        """
        decision = decide(config, outcome_for(big_change))

        assert "SECURITY_SCAN_DIFF_CEILING_BYTES helps only when" \
            in decision.reason
        assert "the smaller of the two by default" in decision.reason

    def test_raising_the_ceiling_really_does_not_complete_the_reading(
            self, tmp_path):
        """The measurement behind the sentence, and the thing the earlier
        version of this test was missing: it asserted the setting's name and
        never followed the advice.

        Its own repository rather than the `big_change` fixture, whose diff is
        under `MAX_DIFF_CHARS` and is only oversized because that fixture
        patches the *byte* ceiling down to 4 KiB. Asking this question there
        would answer about the patched limit and not about the real pair.

        One file, one diff over 120,000 characters, and the workspace ceiling
        raised fifty times above it: the workspace reads the whole thing —
        `last_diff_truncated` is False, so the byte ceiling is provably not
        what binds — and the model is still shown a trimmed diff.
        """
        from security_agent.tools import MAX_DIFF_CHARS, Session, dispatch
        from security_agent.workspace import Workspace

        root = tmp_path / "one-big-file"
        root.mkdir()

        def git(*args):
            subprocess.run(["git", "-C", str(root), *args], check=True,
                           capture_output=True)

        subprocess.run(["git", "init", "-q", str(root)], check=True,
                       capture_output=True)
        git("config", "user.email", "t@example.com")
        git("config", "user.name", "T")
        (root / "one.py").write_text("VALUE = 0\n", encoding="utf-8")
        git("add", "-A")
        git("commit", "-qm", "base")
        base = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"],
                              capture_output=True, text=True,
                              check=True).stdout.strip()
        (root / "one.py").write_text(
            "".join("LINE_{} = {}\n".format(n, "z" * 40)
                    for n in range(MAX_DIFF_CHARS // 40)), encoding="utf-8")
        git("add", "-A")
        git("commit", "-qm", "change")

        raised = Workspace(root=root, excludes=(), diff_base=base,
                           diff_head="HEAD",
                           diff_ceiling=MAX_DIFF_CHARS * 50)
        result = dispatch(raised, Session(), "get_diff", {})

        assert raised.diff_ceiling == MAX_DIFF_CHARS * 50
        assert raised.last_diff_truncated is False, \
            "the workspace read it whole, so the byte ceiling is not what binds"
        assert "Diff trimmed at" in result.content, result.content[-300:]

    def test_the_reason_does_not_promise_the_change_can_be_recovered(
            self, config, big_change):
        """Every move it names is about the *next* run. A reader who believes
        the missing hunks can still be fetched stops here, and this run's
        blindness becomes permanent and unnoticed."""
        decision = decide(config, outcome_for(big_change))

        assert "cannot be recovered" in decision.reason

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
        distinction exists, strict is the only correct choice.

        This paragraph used to end "and the remedy for one oversized file is to
        read it in windows". It is not: `read_file` returns the reviewed
        revision, so a removed line is not in it. There is no remedy for that
        case except splitting the change to that file, and `LIMITATIONS.md`
        records why. Codex, ninth gate round, 2026-09-08.
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
        assert "some changed lines were never delivered" in decision.reason

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
        assert "some changed lines were never delivered" in decision.reason
