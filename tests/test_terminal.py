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
