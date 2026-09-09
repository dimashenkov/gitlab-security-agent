"""The job log view.

This is the only output most people ever read, so the tests are about what a
reader can and cannot be misled by: a truncated quote that looks whole, a
verdict that disagrees with the exit code, colour bleeding into a log that
cannot render it.
"""

from __future__ import annotations

import pytest

from security_agent import terminal
from security_agent.gate import Decision
from security_agent.models import (
    VERDICT_UNCERTAIN,
    Candidate,
    Finding,
    RejectedClaim,
    ScanOutcome,
    Vote,
)


def make_finding(**overrides) -> Finding:
    defaults = dict(
        title="Region parameter interpolated into SQL",
        category="injection", severity="high", confidence="high",
        file="store/lookup.go", line=14,
        description="Comes from the query string.",
        exploit_scenario="A quote in region closes the literal.",
        recommendation="Use a placeholder.",
        evidence='db.Query(fmt.Sprintf("... region = \'%s\'", region))',
        impact="code_execution",
        reachable_without_authentication="yes",
        requires_user_interaction="no",
    )
    defaults.update(overrides)
    return Finding(**defaults)


def make_outcome(candidates=(), **overrides) -> ScanOutcome:
    outcome = ScanOutcome(mode="diff", model="claude-opus-5")
    outcome.reported = list(candidates)
    # A run that looked at something, because that is what every case here is
    # about. `exposures=[]` is a run that read nothing, and it has its own
    # verdict on screen now — pass it explicitly to test that.
    outcome.exposures = [("app/views.py", "get_diff")]
    for key, value in overrides.items():
        setattr(outcome, key, value)
    return outcome


@pytest.fixture(autouse=True)
def _no_colour(monkeypatch):
    """Assert on text, not on escape codes. Colour has its own tests."""
    monkeypatch.setenv("NO_COLOR", "1")
    monkeypatch.delenv("FORCE_COLOR", raising=False)
    monkeypatch.delenv("GITLAB_CI", raising=False)


# ------------------------------------------------------------------- verdict


def test_banner_states_the_verdict_that_matches_the_exit_code():
    candidate = Candidate(finding=make_finding())
    text = terminal.render(
        make_outcome([candidate]),
        Decision(exit_code=1, reason="one high finding", blocking=[candidate]))
    assert "MERGE BLOCKED" in text
    assert "exit 1 — blocking findings" in text


def test_findings_that_do_not_block_do_not_say_blocked():
    candidate = Candidate(finding=make_finding(severity="low"))
    text = terminal.render(
        make_outcome([candidate]), Decision(exit_code=0, reason="nothing blocking"))
    assert "PASSED WITH FINDINGS" in text
    assert "MERGE BLOCKED" not in text
    assert "advisory" in text


def test_clean_run_says_so_without_a_findings_block():
    text = terminal.render(make_outcome(), Decision(exit_code=0, reason="no findings"))
    assert "PASSED" in text
    # "reported", not a claim about the code. The agent read what it read.
    assert "No findings reported." in text


def test_a_run_that_read_nothing_does_not_say_passed(mocked=None):
    """Nothing reached the reviewer, so there is nothing to have passed.

    The skip label, an all-excluded change, an empty range and a `--path` that
    matched no file all end the same way — complete, nothing reported, exit 0 —
    and the biggest word on the screen was a green PASSED over code no one had
    opened. The exit code is right: the tool did what it was told. The word was
    not, and the word is what a person glancing at a pipeline log reads.
    """
    text = terminal.render(
        make_outcome(exposures=[]),
        Decision(exit_code=0, reason="every file in this change is excluded"))
    assert "NOT REVIEWED" in text
    assert "PASSED" not in text


def test_an_empty_finding_list_from_an_incomplete_run_is_not_green():
    """The list is empty because the review stopped, not because it looked.

    Same two words on screen, opposite meanings, and the colour was the only
    thing distinguishing them — it said green for both.
    """
    outcome = make_outcome()
    outcome.stop_reason = "context_exhausted"
    text = terminal.render(outcome, Decision(exit_code=2, reason="did not complete"))
    assert "did not complete" in text
    assert "No findings reported." not in text


def test_incomplete_review_is_not_reported_as_a_pass():
    """Exit 2 must never read like a clean bill of health."""
    text = terminal.render(
        make_outcome(stop_reason="turn_limit"),
        Decision(exit_code=2, reason="the agent ran out of turns"))
    assert "REVIEW INCOMPLETE" in text
    assert "exit 2" in text
    assert "PASSED" not in text


def test_blocking_finding_is_marked_and_advisory_one_is_not():
    blocking = Candidate(finding=make_finding())
    advisory = Candidate(finding=make_finding(
        title="Body logged", category="logging", severity="low",
        impact="metadata_disclosure", reachable_without_authentication="no",
        evidence='log.Printf("payload=%s", body)'))
    text = terminal.render(
        make_outcome([blocking, advisory]),
        Decision(exit_code=1, reason="one blocking", blocking=[blocking]))
    assert text.count("BLOCKS THE MERGE") == 1
    assert "advisory" in text


# ------------------------------------------------------------------ evidence


def test_a_truncated_quote_is_visibly_truncated():
    """A quote cut off silently reads as the whole line, which is a lie."""
    long_line = "x = " + "a" * 400
    candidate = Candidate(finding=make_finding(evidence=long_line))
    text = terminal.render(make_outcome([candidate]),
                           Decision(exit_code=0, reason="ok"))
    assert "…" in text
    assert max(len(line) for line in text.splitlines()) <= terminal.WIDTH


def test_tabs_are_expanded_so_the_gutter_stays_aligned():
    candidate = Candidate(finding=make_finding(evidence="func f() {\n\treturn g()\n}"))
    text = terminal.render(make_outcome([candidate]),
                           Decision(exit_code=0, reason="ok"))
    assert "\t" not in text


def test_evidence_keeps_relative_indentation_but_drops_the_common_margin():
    candidate = Candidate(finding=make_finding(
        evidence="        if user.admin:\n            grant(user)"))
    text = terminal.render(make_outcome([candidate]),
                           Decision(exit_code=0, reason="ok"))
    assert "│ if user.admin:" in text
    assert "│     grant(user)" in text


def test_a_very_long_quote_says_how_much_was_left_out():
    candidate = Candidate(finding=make_finding(
        evidence="\n".join("line {}".format(i) for i in range(30))))
    text = terminal.render(make_outcome([candidate]),
                           Decision(exit_code=0, reason="ok"))
    assert "more line(s)" in text


# --------------------------------------------------------------- disposition


def test_verification_result_is_shown_for_each_finding():
    candidate = Candidate(
        finding=make_finding(),
        votes=[Vote(verdict="confirmed", reasoning=""),
               Vote(verdict="confirmed", reasoning="")])
    text = terminal.render(make_outcome([candidate]),
                           Decision(exit_code=0, reason="ok"))
    assert "confirmed by 2 of 2 independent verifiers" in " ".join(text.split())


def test_an_unverified_finding_says_it_was_not_verified():
    candidate = Candidate(finding=make_finding())
    text = terminal.render(make_outcome([candidate]),
                           Decision(exit_code=0, reason="ok"))
    assert "not verified" in text


def test_a_removed_control_is_called_out():
    candidate = Candidate(finding=make_finding(), removes_control=True,
                          attributed_by="deleted")
    text = terminal.render(make_outcome([candidate]),
                           Decision(exit_code=1, reason="control removed",
                                    blocking=[candidate]))
    flat = " ".join(text.split())
    assert "removes an existing control" in flat
    assert "introduced by a deletion in this change" in flat


def test_what_was_thrown_away_is_reported_not_hidden():
    """Silence about rejected claims makes the tool look better than it is."""
    refuted = Candidate(finding=make_finding(), verdict="refuted")
    outcome = make_outcome(
        refuted=[refuted], duplicates_dropped=2,
        rejected_claims=[RejectedClaim(
            title="phantom", file="a.py", reason="evidence-not-found", detail="")])
    text = terminal.render(outcome, Decision(exit_code=0, reason="ok"))
    assert "1 refuted by verification" in text
    assert "quoted code not in the file" in " ".join(text.split())
    assert "2 duplicate" in text


def test_incomplete_coverage_is_surfaced_in_the_footer():
    outcome = make_outcome()
    outcome.coverage.changed = ["a.py", "b.py"]
    outcome.coverage.examined = ["a.py"]
    text = terminal.render(outcome, Decision(exit_code=0, reason="ok"))
    assert "incomplete" in text


def test_a_substituted_model_is_named_in_the_footer():
    """A blocking verdict from a model nobody asked for has to say so."""
    outcome = make_outcome()
    outcome.provenance.model_requested = "claude-opus-5"
    outcome.provenance.models_served = ["claude-sonnet-5"]
    text = terminal.render(outcome, Decision(exit_code=0, reason="ok"))
    assert "SUBSTITUTED" in text


def test_the_fingerprint_needed_to_suppress_is_shown():
    candidate = Candidate(finding=make_finding())
    text = terminal.render(make_outcome([candidate]),
                           Decision(exit_code=0, reason="ok"))
    assert candidate.fingerprint in text


# ------------------------------------------------------------------- colour


def test_no_colour_when_the_reader_asked_for_none(monkeypatch):
    monkeypatch.setenv("NO_COLOR", "1")
    monkeypatch.setenv("GITLAB_CI", "true")
    assert terminal.colour_enabled() is False


def test_colour_in_gitlab_even_though_a_job_has_no_terminal(monkeypatch):
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setenv("GITLAB_CI", "true")
    assert terminal.colour_enabled() is True


def test_no_colour_when_piped_to_a_file(monkeypatch):
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.delenv("GITLAB_CI", raising=False)
    monkeypatch.delenv("FORCE_COLOR", raising=False)

    class NotATerminal:
        def isatty(self):
            return False

    assert terminal.colour_enabled(NotATerminal()) is False


def test_rendered_width_is_bounded_even_with_colour(monkeypatch):
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setenv("FORCE_COLOR", "1")
    candidate = Candidate(finding=make_finding())
    text = terminal.render(make_outcome([candidate]),
                           Decision(exit_code=1, reason="x", blocking=[candidate]))
    widest = max(len(terminal._visible(line)) for line in text.splitlines())
    assert widest <= terminal.WIDTH


# ------------------------------------------------------------------ sections


def test_section_markers_carry_the_name_on_both_ends():
    """GitLab pairs the start and end by name; a mismatch leaves it open."""
    start = terminal.section("review", "Reviewing the change", True, 1000)
    end = terminal.section("review", "", False, 1090)
    assert "section_start:1000:review" in start
    assert "section_end:1090:review" in end
    assert "[collapsed=true]" in start
    assert "Reviewing the change" in start


class TestHostileTextCannotDriveTheTerminal:
    """The job log is the other place attacker-authored text is rendered.

    THE FIRST VERSION OF THIS CLASS TESTED THE WRONG THING. Every test called
    `_visible` directly, and `_visible` was reachable only from the width
    calculation — the rendered lines used the raw strings. Three green tests
    named for a property the product did not have, which is the project's own
    rule about testing the chain rather than the link, broken in the test
    written to enforce it. The tests below go through `render()`.

    The Markdown report has escaped hostile content since the fence bug. The
    terminal renderer had not: a finding's title and its quoted code are
    written by whoever opened the merge request, and a raw escape sequence in
    one of them is acted on by the terminal reading the CI log.
    """

    def test_an_osc_hyperlink_is_stripped(self):
        from security_agent.terminal import _visible

        hostile = "\033]8;;http://evil.example\007click\033]8;;\007"
        assert _visible(hostile) == "click"

    def test_a_carriage_return_cannot_rewrite_a_printed_line(self):
        """It is how a title overwrites the verdict that was already drawn."""
        from security_agent.terminal import _visible

        assert _visible("finding\rPASSED") == "findingPASSED"

    def test_ordinary_colour_codes_are_still_stripped(self):
        from security_agent.terminal import _visible

        assert _visible("\033[1;31mblocked\033[0m") == "blocked"


class TestWidthIsCellsNotCodePoints:
    """`len()` counted code points, so a CJK title or an emoji reported one
    cell where the terminal drew two and every border after it landed short."""

    def test_a_wide_character_counts_as_two(self):
        from security_agent.terminal import _width

        assert _width("ab") == 2
        assert _width("日本") == 4
        assert _width("🔴") == 2

    def test_escapes_do_not_count(self):
        from security_agent.terminal import _width

        assert _width("\033[31mred\033[0m") == 3

    def test_combining_marks_occupy_nothing(self):
        from security_agent.terminal import _width

        assert _width("e\u0301") == 1

    def test_a_wide_title_does_not_push_the_box_open(self):
        """The property the pad computation exists for, asserted end to end."""
        from security_agent.gate import Decision
        from security_agent.terminal import WIDTH, _visible

        outcome = make_outcome()
        text = terminal.render(outcome, Decision(exit_code=0, reason="nothing"))
        for line in _visible(text).splitlines():
            assert len(line) <= WIDTH + 2, repr(line)


class TestHostileTextThroughRender:
    """Through the whole renderer, because the last version was not."""

    def _rendered(self, **overrides) -> str:
        from security_agent.gate import Decision
        from security_agent.models import Candidate, Finding

        fields = dict(
            title="SQL injection", category="injection", severity="high",
            confidence="high", file="app/views.py", line=14,
            impact="broad_data_access", reachable_without_authentication="yes",
            requires_user_interaction="no", evidence="db.execute(q)",
            description="User input reaches the query.",
            exploit_scenario="Anyone reads every row.",
            recommendation="Parameterise it.")
        fields.update(overrides)
        outcome = make_outcome()
        outcome.reported = [Candidate(finding=Finding.from_dict(fields))]
        return terminal.render(outcome, Decision(exit_code=1, reason="blocked"))

    def test_a_title_cannot_clear_the_screen(self):
        """`\033[2J\033[H` erases the banner above it and leaves whatever the
        attacker wrote where the verdict was."""
        assert "\033[2J" not in self._rendered(title="\033[2J\033[HALL CLEAR")
        assert "ALL CLEAR" in self._rendered(title="\033[2J\033[HALL CLEAR")

    def test_a_title_cannot_become_a_hyperlink(self):
        hostile = "\033]8;;http://evil.example\007Approve\033]8;;\007"
        rendered = self._rendered(title=hostile)
        assert "\033]8" not in rendered
        assert "evil.example" not in rendered

    def test_quoted_code_cannot_drive_the_terminal(self):
        """It is copied verbatim from a file the contributor wrote."""
        rendered = self._rendered(evidence="x = 1\n\033[2J\033[Hall clear")
        assert "\033[2J" not in rendered

    def test_a_category_cannot_either(self):
        """Never validated on this path — `vocabulary.is_category` is applied
        to operator configuration and not to a finding."""
        assert "\033[2J" not in self._rendered(category="\033[2Jinjection")

    def test_a_recommendation_cannot_either(self):
        assert "\033[2J" not in self._rendered(
            recommendation="\033[2J\033[HPIPELINE PASSED")

    def test_a_path_cannot_either(self):
        assert "\033[2J" not in self._rendered(file="\033[2Japp/views.py")

    def test_the_ordinary_text_still_arrives(self):
        """A renderer that dropped the content would pass every test above."""
        rendered = self._rendered()
        assert "SQL injection" in rendered
        assert "app/views.py" in rendered
        assert "db.execute(q)" in rendered


class TestAnOpenQuestionIsVisibleBesideTheVerdict:
    """`decide` never reads `unresolved`, so a run that recorded "cannot
    establish authentication for /admin/run" exits 0 exactly like one that
    settled everything — measured with a control on 2026-09-06.

    Making it *block* was adjudicated and refused: it would merge "the
    machinery denied the reviewer evidence" with "the reviewer examined the
    evidence and cannot justify a conclusion", and teach a model that admitting
    uncertainty fails the job. Codex, 2026-09-07. So the answer is visibility —
    an operator reads "exit 0, with N unresolved questions" rather than a
    settled clean result.
    """

    def rendered(self, unresolved):
        from security_agent.gate import EXIT_OK, Decision
        from security_agent.models import ScanOutcome
        from security_agent.terminal import render

        outcome = ScanOutcome(mode="advisory", model="claude-opus-5")
        outcome.unresolved = list(unresolved)
        return render(outcome, Decision(exit_code=EXIT_OK, reason=""))

    def test_the_count_travels_with_the_exit_code(self):
        text = self.rendered(["cannot establish authentication for /admin/run"])
        assert "exit 0 — nothing blocking, with 1 unresolved question" in text

    def test_it_is_plural_when_it_should_be(self):
        text = self.rendered(["one", "two"])
        assert "with 2 unresolved questions" in text

    def test_a_settled_review_says_nothing_extra(self):
        """The control. A line that always mentioned questions would carry no
        information."""
        text = self.rendered([])
        assert "exit 0 — nothing blocking" in text
        assert "unresolved" not in text


class TestTheVerificationRowCannotOnlySayNOfN:
    """The footer's `Verified` row, on runs where nothing was verified.

    The denominator was `verified + verification_skipped` and the numerator was
    `verified`, so the ratio was built out of its own numerator and could not
    print anything but "N of N". Two populations sat outside both counters, and
    they are exactly the ones a reader needs: findings dropped past
    SECURITY_SCAN_VERIFY_MAX, and panels where every verifier call failed.

    Measured on 2026-09-07 through `verify.verify_candidates`, with a client
    that raises if a paid call is attempted: three unverified criticals
    rendered `Verified  0 of 0 findings`, and four dead panels rendered
    `Verified  4 of 4 findings` while `report.py` said "4 could not run" about
    the same run. The terminal is the one people read in the CI log.
    """

    def row(self, **counters):
        outcome = make_outcome()
        for name, value in counters.items():
            setattr(outcome.metrics, name, value)
        text = terminal.render(outcome, Decision(exit_code=0, reason="ok"))
        return next(line for line in text.splitlines() if "Verified" in line)

    def test_findings_past_the_limit_are_in_the_denominator(self):
        # The run that printed "0 of 0": nothing was panelled, so `verified` is
        # zero, and three criticals were stamped unverified and counted nowhere.
        row = self.row(verification_over_limit=3)
        assert "0 of 3 findings completed" in row
        assert "3 over the limit" in row

    def test_a_panel_where_every_call_failed_is_not_completed(self):
        row = self.row(verified=4, verification_unavailable=4,
                       verification_failed=4)
        assert "0 of 4 findings completed" in row
        assert "4 unavailable" in row
        assert "4 of 4" not in row

    def test_a_partial_panel_completes_and_says_it_was_short(self):
        """A verdict two verifiers out of three reached is a real verdict.

        Counting it as unavailable would understate the review as badly as
        counting a dead panel as completed overstates it.
        """
        row = self.row(verified=1, verification_completed=1,
                       verification_degraded=1, verification_failed=1)
        assert "1 of 1 finding completed" in row
        assert "1 short a vote" in row

    def test_every_disposition_is_in_the_denominator(self):
        row = self.row(verified=3, verification_completed=2,
                       verification_unavailable=1, verification_skipped=1,
                       verification_over_limit=1)
        assert "2 of 5 findings completed" in row
        assert "1 non-blocking skip" in row
        assert "1 over the limit" in row
        assert "1 unavailable" in row

    def test_a_clean_run_does_not_list_empty_baskets(self):
        """The control. A row naming four dispositions on every clean run
        teaches the eye to skip the whole line."""
        row = self.row(verified=2, verification_completed=2)
        assert "2 of 2 findings completed" in row
        for word in ("over the limit", "unavailable", "short a vote",
                     "non-blocking"):
            assert word not in row


class TestBothRenderersReadTheSameNumbers:
    """The terminal row and the Markdown report's line, on one run, together.

    They disagreed by construction: the report has always appended "· N could
    not run" from `verification_failed`, while the terminal's ratio counted
    those same findings as verified. One metric, two renderers, opposite
    claims — and it survived because nothing ever asserted the pair together.

    In this file rather than beside the report's own tests because the pair is
    the assertion; splitting it leaves each renderer checked against itself,
    which is the state the defect lived in.
    """

    def _both(self, **counters):
        from security_agent.config import Config, GitLabContext
        from security_agent.report import _coverage_section

        outcome = make_outcome()
        outcome.metrics.citations_accepted = 1
        for name, value in counters.items():
            setattr(outcome.metrics, name, value)
        decision = Decision(exit_code=0, reason="ok")
        row = next(line for line in
                   terminal.render(outcome, decision).splitlines()
                   if "Verified" in line)
        markdown = " ".join(_coverage_section(
            Config(gitlab=GitLabContext()), outcome, decision))
        return row, markdown

    def test_neither_calls_a_dead_panel_verified(self):
        row, markdown = self._both(verified=4, verification_unavailable=4,
                                   verification_failed=4)
        assert "0 of 4 findings completed" in row
        assert "0 of 4 findings completed" in markdown
        assert "4 unavailable" in row
        assert "4 unavailable" in markdown

    def test_neither_loses_the_findings_past_the_limit(self):
        row, markdown = self._both(verification_over_limit=3)
        assert "0 of 3 findings completed" in row
        assert "0 of 3 findings completed" in markdown
        assert "3 over the limit" in row
        assert "3 past SECURITY_SCAN_VERIFY_MAX" in markdown

    def test_neither_loses_the_findings_when_verification_is_off(self):
        """`SECURITY_SCAN_VERIFY=false` returns before any disposition is
        recorded, so both renderers said "0 of 0" — a denominator of zero
        reading as "nothing was owed" over findings nobody checked. Codex found
        it on the gate for the four counters that fixed the other cases."""
        row, markdown = self._both(verification_disabled=3)
        assert "0 of 3 findings completed" in row
        assert "0 of 3 findings completed" in markdown
        assert "3 with verification off" in row
        assert "3 with SECURITY_SCAN_VERIFY=false" in markdown


class TestARunThatReviewedNothingGetsNoGreenSentence:
    """The third time this renderer has been left behind by a repair.

    `report._header` was given the two non-performed dispositions on
    2026-09-09; the terminal was not, so a skipped run and a real clean review
    printed the same green "No findings reported.", colour code and all. Only
    the banner word differed, and a banner word is what a reader skims.

    `review_status` is asked rather than inferred: `decision.partial` is false
    for both non-performed states by design, because a label waiver that
    blocked the merge would be an escape hatch nobody can use.
    """

    def rendered(self, status):
        outcome = make_outcome([])
        outcome.review_status = status
        return terminal.render(
            outcome, Decision(exit_code=0, reason="ok", partial=False))

    @pytest.mark.parametrize("status", ["skipped", "nothing_reviewable"])
    def test_a_run_that_did_not_review_says_so(self, status):
        text = self.rendered(status)

        assert "No review was performed" in text
        assert "not a statement about the code" in text
        assert "No findings reported." not in text

    def test_a_real_clean_review_still_gets_it(self):
        """The control. A sentence withheld from every run is a sentence
        nobody believes when it appears."""
        assert "No findings reported." in self.rendered("performed")


class TestADeadVerifierSeatIsNotOneThatAgreed:
    """Every failed verification call records `verdict=uncertain` with an
    `error` — `verify.py` does it in two places — so when the panel landed on
    `uncertain` a seat that never answered entered the numerator. A three-seat
    panel with one connection failure printed "left uncertain by 2 of 3
    independent verifiers", which is what it also printed when all three really
    answered. Found 2026-09-09.

    The failures are named rather than dropped, and the denominator stays at
    the seats the panel reserved: a panel that lost a seat is a weaker panel,
    and printing `2/2` would make three verifiers of which one died read as a
    two-seat panel that worked.
    """

    def rendered(self, votes):
        candidate = Candidate(finding=make_finding())
        candidate.verdict = VERDICT_UNCERTAIN
        candidate.votes = votes
        text = terminal.render(
            make_outcome([candidate]),
            Decision(exit_code=0, reason="ok", partial=False))
        # Whitespace-collapsed: the `Checked` field is wrapped to the terminal
        # width, so a sentence near the end of it is split across lines and a
        # substring test would be asserting about the wrapping.
        return " ".join(text.split())

    def test_a_failed_call_is_not_counted_as_a_verifier(self):
        text = self.rendered([
            Vote(verdict=VERDICT_UNCERTAIN, reasoning="cannot tell"),
            Vote(verdict=VERDICT_UNCERTAIN, reasoning="cannot tell"),
            Vote(verdict=VERDICT_UNCERTAIN, reasoning="",
                 error="verification call failed: connection"),
        ])

        # `2 of 3`, not `2 of 2`. Codex refused the first version of this on
        # 2026-09-09: publishing only the seats that answered says a complete
        # two-person panel agreed, where the truth is two of three reserved
        # seats with the quorum degraded. `panel.py` defines the panel as the
        # reserved seats, and a renderer that redefines it is a second
        # definition of one thing.
        assert "2 of 3 independent verifiers" in text
        assert "1 verifier call failed" in text

    def test_a_panel_that_all_answered_reads_as_before(self):
        """The control, and it is the reason the denominator is the seats that
        answered rather than the seats reserved."""
        text = self.rendered([
            Vote(verdict=VERDICT_UNCERTAIN, reasoning="cannot tell"),
            Vote(verdict=VERDICT_UNCERTAIN, reasoning="cannot tell"),
            Vote(verdict=VERDICT_UNCERTAIN, reasoning="cannot tell"),
        ])

        assert "3 of 3 independent verifiers" in text
        assert "call failed" not in text


class TestTheBannerFollowsTheGateNotTheStopReason:
    """A forgiven partial review printed a green `PASSED`.

    `SECURITY_SCAN_FAIL_ON_INCOMPLETE=false` leaves `outcome.complete` true
    while `decision.partial` is true — the gate counts a truncated diff and
    refused context as well as the stop reason. The Markdown renderer was
    repaired for exactly this and the terminal was left behind, so the loudest
    line in the CI log said PASSED over a change the reviewer saw part of, and
    the line under it said "No findings reported." in green.

    Found by Codex on the gate for that repair, 2026-09-08.
    """

    def rendered(self, partial, candidates=()):
        outcome = make_outcome(candidates)
        return terminal.render(
            outcome, Decision(exit_code=0, reason="ok", partial=partial))

    def test_a_forgiven_partial_review_is_not_called_passed(self):
        text = self.rendered(True)
        assert "INCOMPLETE, FORGIVEN" in text
        assert "PASSED" not in text

    def test_the_no_findings_line_is_not_green_over_a_partial_review(self):
        assert "the review did not complete" in self.rendered(True)

    def test_a_partial_review_with_findings_is_not_called_passed_either(self):
        """The findings branch made the same claim over the same half-read
        change, one line higher up, so repairing only the empty case would have
        left the defect for every run that reported something."""
        text = self.rendered(True, [Candidate(finding=make_finding())])
        assert "INCOMPLETE, FORGIVEN" in text
        assert "PASSED WITH FINDINGS" not in text

    def test_a_complete_review_is_still_passed_and_still_green(self):
        """The control. A banner that warns about every run warns about
        none."""
        text = self.rendered(False)
        assert "PASSED" in text
        assert "No findings reported." in text
        assert "INCOMPLETE" not in text
