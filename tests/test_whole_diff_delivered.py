"""Was the change ever put in front of the reviewer as a whole?

The completeness question has been answered wrongly twice, both times by a
per-file boolean. `coverage.complete` counts files *opened by name*, and a
whole-change diff opens none of them, so it answers "nothing was covered" for
the most complete reading there is. Exposures count files whose bytes arrived,
and one `search_code` hit marks a whole file seen — while a binary blob, a
rename and a mode-only change never appear in a diff body at all.

Line-level accounting was the third attempt and Codex refused it, on a ground
that survives the arithmetic: an overview the model selects from is cheaper
*because* something goes unread, so it cannot be both cheaper and no more
permissive. What is left is one fact — the entire text of the change reached the
model once, uncut — and this file is about that fact being recorded honestly.

Honestly means: false when part of the change was cut off at either ceiling,
false when only one file was asked for, and false when the result was produced
and then never delivered. That last one is the shape that has bitten this
repository before: a handler recording what it *would* have shown.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from security_agent.context_budget import ContextBudget
from security_agent.models import Coverage, ScanOutcome
from security_agent.runner_claude_code import _apply_session
from security_agent.session_document import _decode_session, _encoded_session
from security_agent.tools import MAX_DIFF_CHARS, Session, dispatch
from security_agent.workspace import Workspace

PROMPTS = Path(__file__).resolve().parents[1] / "prompts"


def _git(root, *args):
    subprocess.run(["git", "-C", str(root), *args], check=True,
                   capture_output=True)


def _repo(tmp_path, name="repo"):
    root = tmp_path / name
    root.mkdir()
    subprocess.run(["git", "init", "-q", str(root)], check=True,
                   capture_output=True)
    _git(root, "config", "user.email", "t@example.com")
    _git(root, "config", "user.name", "T")
    return root


def _base(root):
    return subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"],
                          capture_output=True, text=True,
                          check=True).stdout.strip()


@pytest.fixture
def small(tmp_path):
    """A change small enough that nothing cuts it."""
    root = _repo(tmp_path)
    (root / "app.py").write_text("VALUE = 0\n", encoding="utf-8")
    _git(root, "add", "-A")
    _git(root, "commit", "-qm", "base")
    base = _base(root)
    (root / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
    (root / "other.py").write_text("SECOND = 2\n", encoding="utf-8")
    _git(root, "add", "-A")
    _git(root, "commit", "-qm", "change")
    return Workspace(root=root, diff_base=base, diff_head="HEAD")


@pytest.fixture
def huge(tmp_path):
    """A change larger than the per-result ceiling, in two files.

    Two, so `_trim_diff` has a file boundary to cut at. One file bigger than the
    whole ceiling falls back to a line boundary, which is a different branch and
    a different test.
    """
    root = _repo(tmp_path)
    (root / "a.py").write_text("A = 0\n", encoding="utf-8")
    (root / "b.py").write_text("B = 0\n", encoding="utf-8")
    _git(root, "add", "-A")
    _git(root, "commit", "-qm", "base")
    base = _base(root)
    filler = "".join("LINE_{} = {}\n".format(n, n)
                     for n in range(MAX_DIFF_CHARS // 12))
    (root / "a.py").write_text(filler, encoding="utf-8")
    (root / "b.py").write_text(filler, encoding="utf-8")
    _git(root, "add", "-A")
    _git(root, "commit", "-qm", "change")
    return Workspace(root=root, diff_base=base, diff_head="HEAD")


@pytest.fixture
def deep(tmp_path):
    """One small hunk in the middle of a long file.

    So that the same change has two very different sizes depending on how much
    context is asked for — which is what makes a single-file diff able to cross
    a ceiling the whole-change diff stays under.
    """
    root = _repo(tmp_path)
    body = ["LINE_{} = {}\n".format(n, n) for n in range(400)]
    (root / "big.py").write_text("".join(body), encoding="utf-8")
    _git(root, "add", "-A")
    _git(root, "commit", "-qm", "base")
    base = _base(root)
    body[200] = "LINE_200 = 'changed'\n"
    (root / "big.py").write_text("".join(body), encoding="utf-8")
    _git(root, "add", "-A")
    _git(root, "commit", "-qm", "change")
    return Workspace(root=root, diff_base=base, diff_head="HEAD")


@pytest.fixture
def binary_only(tmp_path):
    """A change with no reviewable text in it at all.

    Its whole-change diff body is empty. That is not a change being hidden from
    the reviewer — there is nothing to show — and reading it as "never seen"
    would report every binary-only merge request as unread.
    """
    root = _repo(tmp_path)
    (root / "logo.png").write_bytes(bytes(range(256)) * 8)
    _git(root, "add", "-A")
    _git(root, "commit", "-qm", "base")
    base = _base(root)
    (root / "logo.png").write_bytes(bytes(range(255, -1, -1)) * 8)
    _git(root, "add", "-A")
    _git(root, "commit", "-qm", "change")
    return Workspace(root=root, diff_base=base, diff_head="HEAD")


class TestWhatCounts:
    def test_the_whole_diff_counts(self, small):
        session = Session()

        dispatch(small, session, "get_diff", {})

        assert session.whole_diff_delivered

    def test_one_file_does_not(self, small):
        """It is a complete reading of one file and a partial reading of the
        change, and the flag is about the change."""
        session = Session()

        dispatch(small, session, "get_diff", {"path": "app.py"})

        assert not session.whole_diff_delivered

    def test_reading_every_file_one_at_a_time_still_does_not(self, small):
        """Deliberate. The flag is not a coverage sum — it is "was the whole
        thing shown at once", which is the only version of the question that a
        model's own selection cannot satisfy by choosing well."""
        session = Session()

        dispatch(small, session, "get_diff", {"path": "app.py"})
        dispatch(small, session, "get_diff", {"path": "other.py"})

        assert not session.whole_diff_delivered

    def test_a_search_does_not(self, small):
        session = Session()

        dispatch(small, session, "search_code", {"pattern": "VALUE"})

        assert not session.whole_diff_delivered

    def test_a_file_listing_does_not(self, small):
        session = Session()

        dispatch(small, session, "list_changed_files", {})

        assert not session.whole_diff_delivered

    def test_a_change_with_no_readable_line_counts(self, binary_only):
        """git says "Binary files ... differ" and no source line follows. The
        reviewer has been shown everything there is, and the inventory names the
        file and why it cannot be read."""
        session = Session()

        result = dispatch(binary_only, session, "get_diff", {})

        assert "Binary files" in result.content
        assert session.whole_diff_delivered

    def test_an_empty_whole_diff_counts(self, small):
        """A body with nothing in it is not a body being withheld. Reading it as
        "never seen" would mark a change with no reviewable text as unread for
        ever, and the branch that returns it is a separate one from the branch
        that returns a diff."""
        empty = Workspace(root=small.root, diff_base="HEAD", diff_head="HEAD")
        session = Session()

        result = dispatch(empty, session, "get_diff", {})

        assert "Empty diff" in result.content
        assert session.whole_diff_delivered


class TestACutDiffDoesNotCount:
    def test_the_per_result_ceiling(self, huge):
        session = Session()

        result = dispatch(huge, session, "get_diff", {})

        assert "trimmed" in result.summary
        assert not session.whole_diff_delivered

    def test_the_workspace_ceiling(self, small):
        """A different cut, made before this module sees the text: the
        workspace stops reading at its own ceiling. Both mean part of the change
        is missing from the body, and one flag has to catch both."""
        bounded = Workspace(root=small.root, diff_base=small.diff_base,
                            diff_head="HEAD", diff_ceiling=200)
        session = Session()

        dispatch(bounded, session, "get_diff", {})

        assert bounded.diff_truncated
        assert not session.whole_diff_delivered

    def test_the_truncation_flag_still_travels(self, small):
        """The control: catching one gap must not lose the other."""
        bounded = Workspace(root=small.root, diff_base=small.diff_base,
                            diff_head="HEAD", diff_ceiling=200)
        session = Session()

        dispatch(bounded, session, "get_diff", {})

        assert session.diff_truncated

    def test_an_earlier_cut_does_not_condemn_a_later_whole_diff(self, deep):
        """`ws.diff_truncated` is the run's flag and stays set once anything has
        been cut. Read here it would let a single-file diff that hit the ceiling
        decide that a later, genuinely complete whole-change diff was never
        delivered — a fact about one call answered from a fact about the run.

        Found by Codex on review; the first version of these tests never called
        `get_diff` twice, so nothing could have caught it. The second version
        called it twice on two *different* workspaces, which would have passed
        against the unfixed code — the same objection a second time, and the
        reason this one uses one workspace throughout.

        The sequence is a real one: a hundred lines of context around a small
        hunk is larger than the same hunk with twelve, so a single file asked
        for in detail can cross a ceiling the whole change does not.
        """
        ws = Workspace(root=deep.root, diff_base=deep.diff_base,
                       diff_head="HEAD", diff_ceiling=1500)
        session = Session()

        dispatch(ws, session, "get_diff", {"path": "big.py",
                                           "context_lines": 100})
        assert ws.diff_truncated, "the wide single-file diff should be cut"

        dispatch(ws, session, "get_diff", {})

        assert session.whole_diff_delivered

    def test_the_run_still_remembers_the_earlier_cut(self, deep):
        """The other half of the same distinction, on the same sequence. Per-call
        precision must not turn into forgetting that something was cut."""
        ws = Workspace(root=deep.root, diff_base=deep.diff_base,
                       diff_head="HEAD", diff_ceiling=1500)
        session = Session()

        dispatch(ws, session, "get_diff", {"path": "big.py",
                                           "context_lines": 100})
        dispatch(ws, session, "get_diff", {})

        # Both records it. A single-file diff handed over in part is the same
        # fact in a smaller frame as a whole-change diff handed over in part,
        # and the rule that only the second counted is what let the two runners
        # reach different verdicts on identical reviews.
        assert ws.diff_truncated
        assert session.diff_truncated

    def test_a_diff_that_ends_exactly_on_the_ceiling_is_whole(self, small):
        """Reaching the limit is not being cut by it. The read stopped at
        `size >= ceiling` and called that truncation, so a body whose last byte
        lands on the boundary was reported as partial — the reviewer told it had
        seen part of a change it had seen all of."""
        whole = small.diff()
        exact = Workspace(root=small.root, diff_base=small.diff_base,
                          diff_head="HEAD",
                          diff_ceiling=len(whole.encode("utf-8")))
        session = Session()

        dispatch(exact, session, "get_diff", {})

        assert not exact.diff_truncated
        assert session.whole_diff_delivered

    def test_the_last_call_flag_is_cleared_before_the_work(self, small):
        """It names the last call, and a call that raised is still the last one.
        Left over from the call before, it would answer for a diff that never
        happened."""
        from security_agent.workspace import WorkspaceError

        ws = Workspace(root=small.root, diff_base=small.diff_base,
                       diff_head="HEAD", diff_ceiling=50)
        ws.diff()
        assert ws.last_diff_truncated

        ws.diff_base = "no-such-ref"
        with pytest.raises(WorkspaceError):
            ws.diff()

        assert not ws.last_diff_truncated


class TestTheGapBetweenTheTwoCeilings:
    """A change cut in half, and a run that called itself complete.

    Two ceilings sit in series and only the outer one was recorded.
    `Workspace.MAX_DIFF_BYTES` is 512 KiB and sets `diff_truncated`;
    `tools.MAX_DIFF_CHARS` is 120,000 and trims the body before the model sees
    it. A diff between them — the `huge` fixture is about 247,000 characters —
    was cut by the inner ceiling while the outer flag stayed False, so the
    reviewer read the first half of a change and the accounting said it had read
    all of it. Exit 0, "checked and clean", over code nobody looked at.

    It was found by measuring rather than by reading: the flag for "was the
    whole change shown" disagreed with the flag for "was the change cut", and
    only one of them could be right. Nothing in 2008 tests covered the band.
    """

    def test_a_trimmed_whole_diff_makes_the_run_partial(self, huge):
        session = Session()

        result = dispatch(huge, session, "get_diff", {})

        assert "trimmed" in result.summary
        assert not huge.diff_truncated, (
            "the outer ceiling is not reached — that is the whole point")
        assert session.diff_truncated

    def test_the_gate_now_refuses_to_call_it_checked(self, huge):
        from security_agent.config import Config, GitLabContext
        from security_agent.gate import EXIT_ERROR, decide

        session = Session()
        dispatch(huge, session, "get_diff", {})
        outcome = ScanOutcome(mode="diff")
        outcome.finished_explicitly = True
        _apply_session(outcome, session)

        decision = decide(Config(gitlab=GitLabContext()), outcome)

        assert decision.exit_code == EXIT_ERROR


class TestAFailedGitIsNotAnEmptyDiff:
    """An empty body counts as a whole delivery — a change with no reviewable
    text has nothing to withhold. That reading is only safe if "empty" cannot
    also mean "the command failed". stderr goes to /dev/null here and the exit
    status went unread, so a bad revision came back as an empty diff and would
    have been recorded as complete coverage of the change.
    """

    def test_a_bad_revision_raises_rather_than_returning_nothing(self, small):
        from security_agent.workspace import WorkspaceError

        broken = Workspace(root=small.root, diff_base="no-such-ref",
                           diff_head="HEAD")

        with pytest.raises(WorkspaceError, match="exited"):
            broken.diff()

    def test_it_never_reaches_the_session_as_a_delivery(self, small):
        broken = Workspace(root=small.root, diff_base="no-such-ref",
                           diff_head="HEAD")
        session = Session()

        result = dispatch(broken, session, "get_diff", {})

        assert result.is_error
        assert not session.whole_diff_delivered

    def test_a_genuinely_empty_diff_still_counts(self, small):
        """The control, so the fix does not close the case it was written for."""
        empty = Workspace(root=small.root, diff_base="HEAD", diff_head="HEAD")
        session = Session()

        dispatch(empty, session, "get_diff", {})

        assert session.whole_diff_delivered


class TestARefusedDiffDoesNotCount:
    """The shape this repository has been caught by before: a handler that
    records what delivering its result *would* have meant, on a result that was
    never delivered."""

    def test_a_refused_whole_diff_records_nothing(self, small):
        session = Session()
        session.context = ContextBudget(soft=1, hard=2, enforcing=True)

        result = dispatch(small, session, "get_diff", {})

        assert result.is_error
        assert not session.whole_diff_delivered

    def test_the_same_diff_under_a_budget_that_admits_it(self, small):
        """The control. Deferring the record must not lose it."""
        session = Session()
        session.context = ContextBudget(soft=10_000, hard=20_000, enforcing=True)

        dispatch(small, session, "get_diff", {})

        assert session.whole_diff_delivered

    def test_observing_admits_and_records(self, small):
        """Observing mode returns everything. A flag that went false there
        would make the measurement change the thing measured."""
        session = Session()
        session.context = ContextBudget(soft=1, hard=2, enforcing=False)

        dispatch(small, session, "get_diff", {})

        assert session.whole_diff_delivered
        assert session.context.would_refuse_results == 1


class TestItReachesTheReport:
    def test_it_crosses_the_process_boundary(self, small):
        """On the CLI path `get_diff` runs in a child, against a different
        workspace. A fact the session does not carry is a fact the parent never
        learns."""
        session = Session()
        dispatch(small, session, "get_diff", {})

        restored = _decode_session(_encoded_session(session), where="test")

        assert restored.whole_diff_delivered

    def test_it_lands_in_the_coverage_accounting(self, small):
        session = Session()
        dispatch(small, session, "get_diff", {})
        outcome = ScanOutcome(mode="diff")

        _apply_session(outcome, session)

        assert outcome.coverage.whole_diff_delivered

    def test_an_untouched_session_lands_false(self, small):
        outcome = ScanOutcome(mode="diff")

        _apply_session(outcome, Session())

        assert not outcome.coverage.whole_diff_delivered

    def test_it_is_in_the_artifact(self):
        assert Coverage().to_dict()["whole_diff_delivered"] is False
        assert Coverage(whole_diff_delivered=True).to_dict()[
            "whole_diff_delivered"] is True


class TestBothRunnersCarryIt:
    """`_apply_session` is the CLI runner's half. The Messages API runner fills
    the same field from its own session in `agent.py`, and that assignment was
    held by nothing — the same untested-hop shape that let the truncation flag
    be recorded correctly for weeks and never reach the gate.
    """

    def test_the_messages_api_path_fills_it(self, small, tmp_path):
        from fakes import FakeClient, FakeResponse, text, tool_use
        from security_agent.agent import SecurityAgent
        from security_agent.config import Config, GitLabContext

        cfg = Config(prompt_dir=PROMPTS, output_dir=tmp_path / "out",
                     gitlab=GitLabContext(), post_comment=False)
        client = FakeClient([
            FakeResponse([tool_use("get_diff", {}, id="t1")],
                         stop_reason="tool_use"),
            FakeResponse([text("Reviewed the change; nothing found.")],
                         stop_reason="end_turn"),
        ])

        outcome = SecurityAgent(cfg, small, client=client).run(
            "diff", "Review the change.")

        assert outcome.coverage.whole_diff_delivered is True

    def test_the_messages_api_path_reports_a_review_that_never_asked(
            self, small, tmp_path):
        """The control, and the case the note exists for: a review that read
        one file and signed off."""
        from fakes import FakeClient, FakeResponse, text, tool_use
        from security_agent.agent import SecurityAgent
        from security_agent.config import Config, GitLabContext

        cfg = Config(prompt_dir=PROMPTS, output_dir=tmp_path / "out",
                     gitlab=GitLabContext(), post_comment=False)
        client = FakeClient([
            FakeResponse([tool_use("get_diff", {"path": "app.py"}, id="t1")],
                         stop_reason="tool_use"),
            FakeResponse([text("Reviewed the change; nothing found.")],
                         stop_reason="end_turn"),
        ])

        outcome = SecurityAgent(cfg, small, client=client).run(
            "diff", "Review the change.")

        assert outcome.coverage.whole_diff_delivered is False


class TestTheReportSaysIt:
    def _render(self, coverage: Coverage) -> str:
        from security_agent.config import Config, GitLabContext
        from security_agent.gate import decide
        from security_agent.report import render_markdown

        outcome = ScanOutcome(mode="diff")
        outcome.coverage = coverage
        outcome.coverage.changed = []
        outcome.finished_explicitly = True
        cfg = Config(gitlab=GitLabContext())
        return render_markdown(cfg, outcome, decide(cfg, outcome))

    def test_a_whole_reading_says_nothing(self):
        body = self._render(Coverage(whole_diff_delivered=True))

        assert "never shown to the reviewer as a whole" not in body

    def test_a_partial_reading_is_named(self):
        body = self._render(Coverage(whole_diff_delivered=False))

        assert "never shown to the reviewer as a whole" in body

    def test_it_is_a_note_and_not_a_warning(self):
        """It is recorded, not gated. Whether a healthy review asks for the
        whole diff has never been measured — the paid artifacts do not record
        which tools were called — and a warning would be a verdict about a
        habit nobody has counted."""
        body = self._render(Coverage(whole_diff_delivered=False))

        assert "> [!NOTE]" in body

    def test_a_truncated_diff_says_it_once(self):
        """The truncation warning already explains the gap and names its own
        remedy. Two sentences in two voices about one fact turn the second into
        furniture."""
        body = self._render(Coverage(whole_diff_delivered=False,
                                     diff_truncated=True))

        assert "too large to show in full" in body
        assert "never shown to the reviewer as a whole" not in body

    def test_an_unrelated_refusal_does_not_silence_it(self):
        """The refusal counter does not say *which* tool was refused, so
        silencing on it let one rejected `read_file` hide the observation about
        the diff — and the observation is the reason this fact is recorded
        rather than gated on. Codex's objection; the first version silenced on
        any refusal at all."""
        body = self._render(Coverage(whole_diff_delivered=False,
                                     context_refusals=1))

        assert "never shown to the reviewer as a whole" in body
        assert "not returned" in body


class TestItDoesNotDecideTheExitCode:
    """Deliberately, and this test exists so that changing it is a decision.

    Observation before enforcement, the same order the context limit was given.
    Gating on it now would be gating on an unmeasured habit, which is exactly
    how the two earlier proposals would have failed reviews that were fine.
    """

    def test_a_run_that_never_saw_the_whole_change_still_exits_zero(self):
        from security_agent.config import Config, GitLabContext
        from security_agent.gate import EXIT_OK, decide

        outcome = ScanOutcome(mode="diff")
        outcome.finished_explicitly = True
        outcome.exposures = [("app.py", "read_file")]
        outcome.coverage = Coverage(whole_diff_delivered=False)

        decision = decide(Config(gitlab=GitLabContext()), outcome)

        assert decision.exit_code == EXIT_OK
