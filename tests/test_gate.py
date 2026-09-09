"""Tests for the pipeline verdict.

The rule that matters most here is the one about incomplete runs: an agent that
stopped early must never produce a green pipeline, because a green pipeline is
indistinguishable from "we checked and it's fine".
"""

from dataclasses import replace

import pytest

from conftest import make_candidate
from security_agent.config import Config, GitLabContext
from security_agent.gate import EXIT_ERROR, EXIT_FINDINGS, EXIT_OK, blocking_findings, decide
from security_agent.models import (
    STOP_BUDGET,
    STOP_COMPLETED,
    STOP_ERROR,
    STOP_REFUSAL,
    STOP_TIME_LIMIT,
    STOP_TRANSPORT,
    STOP_TURN_LIMIT,
    Coverage,
    ScanOutcome,
    ToolCallRecord,
)


def outcome_with(*candidates, **kwargs):
    """A run that saw some of the change, unless a test says otherwise.

    The default matters. Every test here about an incomplete review means a
    review that did some work and then stopped, and the fixture used to build
    one where nothing had reached the model — a different thing, and now
    decided differently: `fail_on_incomplete` weighs partial coverage, and a
    run that saw nothing has none to weigh. Pass `exposures=[]` for that case,
    as the tests below that mean it do.
    """
    outcome = ScanOutcome(mode="diff", stop_reason=kwargs.pop("stop_reason", STOP_COMPLETED))
    outcome.stop_detail = kwargs.pop("stop_detail", "")
    outcome.reported = list(candidates)
    outcome.coverage = kwargs.pop(
        "coverage", Coverage(changed=["app/views.py"], examined=["app/views.py"]))
    outcome.exposures = kwargs.pop(
        "exposures", [("app/views.py", "get_diff")])
    for key, value in kwargs.items():
        setattr(outcome, key, value)
    return outcome


class TestIncompleteRuns:
    def test_turn_limit_is_an_error_not_a_pass(self, config):
        decision = decide(config, outcome_with(stop_reason=STOP_TURN_LIMIT))
        assert decision.exit_code == EXIT_ERROR
        assert "incomplete" in decision.reason.lower()

    def test_refusal_is_an_error_not_a_pass(self, config):
        decision = decide(config, outcome_with(stop_reason=STOP_REFUSAL))
        assert decision.exit_code == EXIT_ERROR

    def test_incomplete_can_be_allowed_through_explicitly(self, config):
        config.fail_on_incomplete = False
        decision = decide(config, outcome_with(stop_reason=STOP_TURN_LIMIT))
        assert decision.exit_code == EXIT_OK
        assert "did not complete" in decision.reason

    def test_incomplete_still_blocks_when_it_found_something(self, config):
        config.fail_on_incomplete = False
        decision = decide(config, outcome_with(make_candidate(), stop_reason=STOP_TURN_LIMIT))
        assert decision.exit_code == EXIT_FINDINGS

    def test_fail_on_none_does_not_forgive_an_incomplete_run(self, config):
        """The two switches are not the same switch, and a comment said they were.

        `templates/github-actions.yml` told a reader that `SECURITY_SCAN_FAIL_ON=none`
        "turns a run that could not conclude into a pass". It does not: the
        incomplete check runs before the severity threshold is ever consulted,
        so dropping the threshold cannot reach it. Only
        `fail_on_incomplete=False` forgives partial coverage.

        Written because that sentence was repeated into a distributed SKILL.md,
        where an agent would have acted on it unattended — silencing a gate by
        setting the one variable that cannot silence it, and getting exit 2 in a
        pipeline it believed it had made advisory.
        """
        config.fail_on = "none"
        decision = decide(config, outcome_with(stop_reason=STOP_TURN_LIMIT))
        assert decision.exit_code == EXIT_ERROR
        assert "incomplete" in decision.reason.lower()

        config.fail_on_incomplete = False
        forgiven = decide(config, outcome_with(stop_reason=STOP_TURN_LIMIT))
        assert forgiven.exit_code == EXIT_OK


class TestThresholds:
    def test_high_blocks_at_the_default_threshold(self, config):
        decision = decide(config, outcome_with(make_candidate(severity="high")))
        assert decision.exit_code == EXIT_FINDINGS
        assert len(decision.blocking) == 1

    def test_medium_does_not_block_at_the_default_threshold(self, config):
        decision = decide(config, outcome_with(make_candidate(severity="medium")))
        assert decision.exit_code == EXIT_OK
        assert "below the high severity threshold" in " ".join(decision.non_blocking_reasons)

    def test_low_confidence_does_not_block(self, config):
        decision = decide(config, outcome_with(make_candidate(severity="critical", confidence="low")))
        assert decision.exit_code == EXIT_OK

    def test_fail_on_none_blocks_nothing(self, config):
        config.fail_on = "none"
        decision = decide(config, outcome_with(make_candidate(severity="critical")))
        assert decision.exit_code == EXIT_OK
        assert decision.blocking == []

    def test_clean_run_passes(self, config):
        decision = decide(config, outcome_with())
        assert decision.exit_code == EXIT_OK
        assert decision.reason == "No security findings."


class TestPreExisting:
    def test_pre_existing_does_not_block_by_default(self, config):
        candidate = make_candidate(severity="critical", in_changed_lines=False)
        decision = decide(config, outcome_with(candidate))
        assert decision.exit_code == EXIT_OK
        assert any("pre-existing" in note for note in decision.non_blocking_reasons)

    def test_pre_existing_blocks_when_opted_in(self, config):
        config.gate_pre_existing = True
        candidate = make_candidate(severity="critical", in_changed_lines=False)
        assert decide(config, outcome_with(candidate)).exit_code == EXIT_FINDINGS

    def test_introduced_findings_always_count(self, config):
        candidate = make_candidate(severity="high", in_changed_lines=True)
        assert decide(config, outcome_with(candidate)).exit_code == EXIT_FINDINGS


class TestBlockingSelection:
    def test_only_qualifying_findings_are_returned(self, config):
        candidates = [
            make_candidate(severity="critical", title="a"),
            make_candidate(severity="low", title="b"),
            make_candidate(severity="high", confidence="low", title="c"),
        ]
        blocking = blocking_findings(config, outcome_with(*candidates))
        assert [c.finding.title for c in blocking] == ["a"]

    def test_reasons_explain_everything_withheld(self, config):
        candidates = [
            make_candidate(severity="low", title="a"),
            make_candidate(severity="high", confidence="low", title="b"),
        ]
        decision = decide(config, outcome_with(*candidates))
        joined = " ".join(decision.non_blocking_reasons)
        assert "below the high severity threshold" in joined
        assert "below medium confidence" in joined


class TestRemovedControlsBlock:
    """Deleting a security control blocks on that alone.

    Every part of this rule existed — the question to the verifier, the
    aggregation, the config flag, the verification scope — except the line in
    the gate that acts on it. 282 tests passed because none of them followed
    the rule all the way to the verdict. Five runs over a merge request
    reverting the fix for CVE-2023-41040 confirmed it five times and blocked it
    zero times.
    """

    def test_a_removed_control_blocks_below_the_severity_threshold(self, config):
        candidate = make_candidate(severity="low", confidence="high",
                                   removes_control=True)
        decision = decide(config, outcome_with(candidate))
        assert decision.exit_code == EXIT_FINDINGS
        assert decision.blocking == [candidate]

    def test_it_blocks_below_the_confidence_threshold_too(self, config):
        candidate = make_candidate(severity="low", confidence="low",
                                   removes_control=True)
        assert decide(config, outcome_with(candidate)).exit_code == EXIT_FINDINGS

    def test_it_can_be_switched_off(self, config):
        config.gate_removed_controls = False
        candidate = make_candidate(severity="low", removes_control=True)
        assert decide(config, outcome_with(candidate)).exit_code == EXIT_OK

    def test_it_does_not_override_pre_existing(self, config):
        # Code the change did not touch is not this author's to answer for,
        # whatever the verifiers concluded about it.
        candidate = make_candidate(severity="low", removes_control=True,
                                   in_changed_lines=False)
        assert decide(config, outcome_with(candidate)).exit_code == EXIT_OK

    def test_fail_on_none_still_means_none(self, config):
        config.fail_on = "none"
        candidate = make_candidate(severity="critical", removes_control=True)
        assert decide(config, outcome_with(candidate)).exit_code == EXIT_OK

    def test_an_ordinary_finding_is_unaffected(self, config):
        candidate = make_candidate(severity="low", removes_control=False)
        assert decide(config, outcome_with(candidate)).exit_code == EXIT_OK


class TestTheVerdictNamesTheRuleThatApplied:
    """Two different rules block, and the message has to say which one did.

    A finding stopped for deleting a guard is usually below the severity
    threshold. Telling its author it was "at or above the high threshold" sends
    them to argue with a number that had nothing to do with the decision —
    which is what the first real pipeline run reported.
    """

    def test_a_removed_control_is_described_as_one(self, config):
        candidate = make_candidate(severity="medium", removes_control=True)
        reason = decide(config, outcome_with(candidate)).reason
        assert "removes an existing security control" in reason
        assert "threshold" not in reason

    def test_an_ordinary_finding_still_cites_the_threshold(self, config):
        candidate = make_candidate(severity="critical", confidence="high")
        reason = decide(config, outcome_with(candidate)).reason
        assert "at or above the high threshold" in reason
        assert "removes an existing" not in reason

    def test_both_rules_at_once_are_both_named(self, config):
        candidates = [
            make_candidate(severity="low", removes_control=True, title="a"),
            make_candidate(severity="critical", confidence="high", title="b"),
        ]
        reason = decide(config, outcome_with(*candidates)).reason
        assert "removes an existing security control" in reason
        assert "at or above the high threshold" in reason


class TestAnUnknownRatingCannotUnGateAFinding:
    """One capital letter used to carry a critical finding past the gate.

    `severity_rank` and `confidence_rank` return -1 for a word nobody
    recognises. That is right for sorting — an unknown value goes to one end
    and stays there — and it was read as a threshold: `-1 < minimum` meant an
    unrecognised rating was quietly treated as *less* severe than `low`, so it
    never blocked. The report still rendered it as CRITICAL and the pipeline
    still exited 0.

    Neither field is derived or validated on that path. `Finding.from_dict`
    takes `str(data["confidence"])`, and the schema's enum is enforced by the
    API — except on the hand-rolled fallback in `_parse_verdict`, which exists
    precisely for when it was not.
    """

    def _blocks(self, cfg, **overrides) -> bool:
        from security_agent.gate import blocking_findings

        candidate = make_candidate(**overrides)
        outcome = ScanOutcome(mode="diff", model="m")
        outcome.reported = [candidate]
        return bool(blocking_findings(cfg, outcome))

    def test_a_capital_letter_is_the_same_word(self, config):
        """`High` and `high` are one rating written two ways."""
        assert self._blocks(config, severity="critical", confidence="High")
        assert self._blocks(config, severity="Critical", confidence="high")

    def test_surrounding_whitespace_is_the_same_word(self, config):
        assert self._blocks(config, severity="critical", confidence=" high ")

    def test_a_rating_nobody_recognises_does_not_silently_pass(self, config):
        """It fails toward blocking. An unparseable rating is a statement that
        the rating could not be read — never that it was low."""
        assert self._blocks(config, severity="critical", confidence="pretty sure")
        assert self._blocks(config, severity="devastating", confidence="high")

    def test_a_recognised_rating_below_the_bar_still_does_not_block(self, config):
        """The fix must not turn the threshold off."""
        assert not self._blocks(config, severity="low", confidence="high")
        assert not self._blocks(config, severity="critical", confidence="low")


class TestSomeEndingsAreNotTheOperatorsToForgive:
    """`fail_on_incomplete=false` is a policy about partial reviews. It is not
    permission for a profile to conclude when it says it cannot.

    `probe` is six turns and no verifiers, sized to run on every save, and
    `Profile.conclusive` has said `False` about it since the day it was written
    — to nobody. The flag was read nowhere outside `budget.py`, so a probe that
    signed off ended `completed` and exited 0. Making it a stop reason was half
    the fix; the other half is that a setting meaning "accept partial reviews"
    must not turn it back into a pass.

    Found by the author reading the file, after nine review rounds had passed
    over it.
    """

    def test_a_profile_that_cannot_conclude_never_exits_zero(self):
        from security_agent.models import STOP_INCONCLUSIVE

        outcome = outcome_with(stop_reason=STOP_INCONCLUSIVE)

        for forgiving in (True, False):
            cfg = Config(gitlab=GitLabContext(), fail_on_incomplete=forgiving)
            decision = decide(cfg, outcome)

            assert decision.exit_code == EXIT_ERROR, (
                "fail_on_incomplete={} let a non-conclusive profile "
                "pass".format(forgiving))
            assert "property of the profile" in decision.reason

    def test_an_ordinary_truncation_is_still_the_operators_call(self):
        """The flag keeps working for what it is for. A rule that swallowed
        every incomplete ending would take away a real choice about a team's own
        risk, and would be removed for it."""
        from security_agent.models import STOP_TURN_LIMIT

        cfg = Config(gitlab=GitLabContext(), fail_on_incomplete=False)

        assert decide(cfg, outcome_with(
            stop_reason=STOP_TURN_LIMIT)).exit_code != EXIT_ERROR

    @pytest.mark.parametrize("stop_reason", [
        STOP_TRANSPORT,     # the CLI would not start
        STOP_ERROR,         # it started and broke
        STOP_TIME_LIMIT,    # it was killed
        STOP_BUDGET,        # it ran out before opening anything
        STOP_TURN_LIMIT,    # it spent its turns without opening anything
    ])
    def test_a_review_nothing_reached_is_never_a_pass(self, stop_reason):
        """The hole the flag was standing in front of.

        `fail_on_incomplete` weighs *partial* coverage: six files of ten, the
        operator knows which six. There is nothing to weigh when no part of the
        change reached the model — the CLI failing to start, the MCP server
        never coming up, a terminal object that will not parse. Six of the
        eight ways the local runner can fail reached exit 0 through that flag,
        and the reason printed was "No blocking findings, but the review did
        not complete."

        Every stop reason, because the rule is about the absence of evidence
        rather than about the endings somebody thought to name.
        """
        outcome = outcome_with(stop_reason=stop_reason, exposures=[],
                               coverage=Coverage(changed=["app/views.py"]))

        for forgiving in (True, False):
            cfg = Config(gitlab=GitLabContext(), fail_on_incomplete=forgiving)
            decision = decide(cfg, outcome)

            assert decision.exit_code == EXIT_ERROR, (
                "fail_on_incomplete={} passed a review nothing reached".format(
                    forgiving))
        assert "reached the reviewer" in decision.reason

    def test_a_whole_diff_read_without_opening_a_file_is_work(self):
        """Opening a file by name is not how most of a change is seen. A
        whole-change `get_diff` puts every changed file in front of the model
        and opens none of them, so judging on `files_examined` would call the
        commonest shape of review absent — and a rule that fires on real work
        is a rule that gets switched off."""
        cfg = Config(gitlab=GitLabContext(), fail_on_incomplete=False)
        outcome = outcome_with(
            stop_reason=STOP_TURN_LIMIT,
            coverage=Coverage(changed=["app/views.py"]),
            exposures=[("app/views.py", "get_diff")])

        assert decide(cfg, outcome).exit_code != EXIT_ERROR

    def test_calling_tools_without_seeing_code_is_not_work(self):
        """`list_changed_files` then `finish_review` is two tool calls and no
        code seen, and the record keeps failures too — a refused read and a
        search that matched nothing are both in it. Counting attempts would let
        a session that reached the repository and got nothing out of it pass."""
        cfg = Config(gitlab=GitLabContext(), fail_on_incomplete=False)
        outcome = outcome_with(
            stop_reason=STOP_TURN_LIMIT, exposures=[],
            coverage=Coverage(changed=["app/views.py"]),
            tool_calls=[ToolCallRecord(name="list_changed_files", arguments={},
                                       turn=1, summary="listed the change")])

        assert decide(cfg, outcome).exit_code == EXIT_ERROR

    def test_a_finding_alone_does_not_legitimise_the_run(self):
        """A finding proves its citation exists — `report_finding` validates
        the quoted lines against the file — which is a fact about the quote and
        not about whether the change was investigated. Nothing in
        `report_finding` records an exposure. So a finding is shown, and it is
        not what decides that a review happened."""
        cfg = Config(gitlab=GitLabContext(), fail_on_incomplete=False)
        outcome = outcome_with(
            make_candidate(severity="low"),
            stop_reason=STOP_TURN_LIMIT, exposures=[],
            coverage=Coverage(changed=["app/views.py"]))

        assert decide(cfg, outcome).exit_code == EXIT_ERROR

    def test_the_set_is_not_empty(self):
        """A refactor that emptied it would leave every test above passing."""
        from security_agent.gate import NEVER_FORGIVEN

        assert NEVER_FORGIVEN


def test_a_finished_review_that_opened_nothing_is_not_a_pass(config):
    """The hole this file exists to hold shut, found on 2026-09-02.

    `_reviewed_nothing` was asked only of a run that had already admitted to
    stopping early — `_partial(outcome) and _reviewed_nothing(outcome)` — so a
    review that ended cleanly on its first turn, having opened nothing at all,
    walked past every branch and came out `exit 0`, "No security findings.",
    over a changed file nothing had read.

    Every existing test that passes `exposures=[]` also passes a stop reason
    that makes the run partial, so the combination that matters — finished, and
    nothing opened — was never asked about. That is how a check written against
    exactly this failure stayed green over it.
    """
    outcome = ScanOutcome(mode="diff", summary="Nothing looked suspicious.",
                          stop_reason=STOP_COMPLETED, finished_explicitly=True)
    outcome.reported = []
    outcome.exposures = []
    outcome.coverage = Coverage(changed=["src/app.py"], examined=[],
                                whole_diff_delivered=True)

    decision = decide(config, outcome)

    assert decision.exit_code == EXIT_ERROR
    assert "without opening any part of the change" in decision.reason
    # And it says the true thing rather than guessing at a limit never hit.
    # The truncation sentence no longer names a limit at all — two can cut a
    # diff and the gate is not told which — so the marker is the clause it
    # opens with. Codex, eighth gate round, 2026-09-08.
    assert "cut before all of it reached the reviewer" not in decision.reason


def test_a_deletion_only_change_that_nobody_read_is_not_a_pass(config):
    """The same hole, one filter away, found 2026-09-09.

    `coverage.changed` comes from a `--diff-filter=ACMRT` call, so a pure
    deletion is not in it — `workspace.py` says exactly that on the line that
    builds the list. A merge request whose only change was `git rm` of a guard,
    reviewed by a run that called `finish_review` on its first turn, therefore
    reached `_reviewed_nothing` true and `_readable_change` false, and came out
    `exit 0`, "No security findings."

    The same file modified instead of deleted exits 2. A removed security
    control is one of the things this product exists to catch, and it was the
    one case the predicate dropped.
    """
    outcome = ScanOutcome(mode="diff", summary="Nothing looked suspicious.",
                          stop_reason=STOP_COMPLETED, finished_explicitly=True)
    outcome.reported = []
    outcome.exposures = []
    outcome.coverage = Coverage(changed=[], examined=[],
                                deleted=["auth/guard.py"],
                                whole_diff_delivered=True)

    decision = decide(config, outcome)

    assert decision.exit_code == EXIT_ERROR
    assert "without opening any part of the change" in decision.reason


def test_a_review_that_opened_nothing_because_nothing_changed_still_passes(
        config):
    """The control. An empty change has nothing to open, and refusing it would
    make every no-op merge request fail — a gate that fires on nothing is
    switched off within a week."""
    outcome = ScanOutcome(mode="diff", summary="No changes to review.",
                          stop_reason=STOP_COMPLETED, finished_explicitly=True)
    outcome.reported = []
    outcome.exposures = []
    outcome.coverage = Coverage(changed=[], examined=[],
                                whole_diff_delivered=True)

    assert decide(config, outcome).exit_code == EXIT_OK


def test_a_change_made_only_of_binary_files_is_not_refused(config):
    """A binary diff carries no text to open, and that is not a pass.

    `git diff` emits `Binary files a/x and b/x differ` with no `+++` line, so
    `_paths_in_diff` records no exposure and none could be recorded. This test
    asserted `EXIT_OK` for exactly that reason — a run which opened nothing
    because there was nothing openable did everything available to it.

    **The reasoning was about the reviewer's conduct and the exit code is
    about the change.** Nothing inspectable is not evidence of no findings, and
    the run was exiting 0 with "No security findings." over material nobody
    could look at. Reached on 2026-09-07 from an attack rather than from an
    asset commit: one line of `.gitattributes` saying `* -diff` made every file
    read as binary, and this unconditional green was the second of the two ways
    that line disarmed the gate. Codex adjudicated it stricter than the
    proposal put to it.

    So the verdict is now exit 2 — but *forgivable*, unlike the branch that
    refuses a review which opened nothing it could have opened. A repository
    whose merge requests are genuinely assets has a real move, and a gate that
    cannot be satisfied gets deleted rather than obeyed.
    """
    outcome = ScanOutcome(mode="diff", summary="Only assets changed.",
                          stop_reason=STOP_COMPLETED, finished_explicitly=True)
    outcome.reported = []
    outcome.exposures = []
    outcome.coverage = Coverage(
        changed=["assets/logo.png"], examined=[],
        unreadable=[("assets/logo.png", "binary")],
        whole_diff_delivered=True)

    decision = decide(config, outcome)
    assert decision.exit_code == EXIT_ERROR
    assert "binary or otherwise unreadable" in decision.reason

    # And forgivable, which is what separates it from a review that opened
    # nothing it could have opened.
    forgiving = replace(config, fail_on_incomplete=False)
    assert decide(forgiving, outcome).exit_code == EXIT_OK


def test_a_readable_file_beside_a_binary_one_is_still_refused(config):
    """The exemption is for a change with nothing to read, not for a change
    that happens to contain something unreadable."""
    outcome = ScanOutcome(mode="diff", summary="Assets and code.",
                          stop_reason=STOP_COMPLETED, finished_explicitly=True)
    outcome.reported = []
    outcome.exposures = []
    outcome.coverage = Coverage(
        changed=["assets/logo.png", "src/app.py"], examined=[],
        unreadable=[("assets/logo.png", "binary")],
        whole_diff_delivered=True)

    assert decide(config, outcome).exit_code == EXIT_ERROR



class TestTheBannerFollowsTheGate:
    """The banner asked `outcome.complete`, which is only the stop reason,
    while `gate._partial` counts three things. So a truncated diff and a
    context refusal each got "## ✅ AI security review — no findings reported"
    over a review that had not seen the change — and the function's own comment
    says the warning further down does not undo a green tick at the top.

    Found by a hostile hunt whose mandate was one class: claims the code makes
    about what it did that nothing verifies. Codex ruled the renderer must not
    recompute `_partial`, so the decision carries the flag.
    """

    def banner(self, config, coverage):
        from security_agent.report import render_markdown
        outcome = ScanOutcome(mode="diff", coverage=coverage,
                              finished_explicitly=True)
        outcome.exposures = [("a.py", "get_diff")]
        decision = decide(config, outcome)
        head = [line for line in render_markdown(config, outcome, decision)
                .splitlines() if line.startswith("## ")]
        return decision, head[0] if head else ""

    def forgiving(self, config):
        return replace(config, fail_on_incomplete=False)

    def test_a_truncated_diff_is_not_green(self, config):
        decision, head = self.banner(
            self.forgiving(config),
            Coverage(changed=["a.py"], examined=["a.py"], diff_truncated=True))
        assert decision.exit_code == EXIT_OK
        assert decision.partial is True
        assert "did not complete" in head, head

    def test_context_refusals_are_not_green(self, config):
        decision, head = self.banner(
            self.forgiving(config),
            Coverage(changed=["a.py"], examined=["a.py"], context_refusals=3))
        assert decision.exit_code == EXIT_OK
        assert "did not complete" in head, head

    def test_a_complete_review_is_still_green(self, config):
        """The control. A banner that warns about everything warns about
        nothing."""
        decision, head = self.banner(
            self.forgiving(config),
            Coverage(changed=["a.py"], examined=["a.py"]))
        assert decision.partial is False
        assert "no findings reported" in head, head

    def test_the_flag_is_adjudicated_once(self, config):
        """Carried on the decision rather than recomputed by the renderer: two
        places deciding what partial means is two places to drift."""
        outcome = ScanOutcome(mode="diff", finished_explicitly=True,
                              coverage=Coverage(changed=["a.py"],
                                                examined=["a.py"],
                                                diff_truncated=True))
        outcome.exposures = [("a.py", "get_diff")]
        assert decide(self.forgiving(config), outcome).partial is True


class TestTheVerdictDoesNotBlameSeverity:
    """"N finding(s) reported, none at or above the X threshold" was returned
    whenever nothing blocked, whatever the reason — and it was printed about a
    withheld `critical` whose finding had been filed as pre-existing by one
    line of `.gitattributes`.

    Which rule applied is in `non_blocking_reasons`, one reason per finding.
    """

    def withheld(self, config):
        """A critical finding held back for attribution, not for severity —
        which is the case the old sentence described wrongly."""
        return decide(config, outcome_with(
            make_candidate(severity="critical", in_changed_lines=False)))

    def test_the_sentence_does_not_name_the_threshold(self, config):
        decision = self.withheld(config)
        assert "at or above" not in decision.reason, decision.reason
        assert "none blocking" in decision.reason, decision.reason

    def test_the_real_reason_is_still_carried(self, config):
        """The sentence says less; the structure has to say the same. A
        shorter headline that also loses the detail is not honesty."""
        decision = self.withheld(config)
        assert decision.non_blocking_reasons, decision
        assert any("pre-existing" in line
                   for line in decision.non_blocking_reasons), \
            decision.non_blocking_reasons

    def test_a_finding_below_the_threshold_still_reads_sensibly(self, config):
        """The control: when severity *is* the reason, the sentence must not
        have become vague to be honest."""
        decision = decide(config, outcome_with(make_candidate(severity="low")))
        assert "none blocking" in decision.reason, decision.reason
        assert any("threshold" in line or "below" in line
                   for line in decision.non_blocking_reasons), \
            decision.non_blocking_reasons
