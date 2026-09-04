"""Properties of the review path, generated rather than remembered.

`test_properties.py` covers the measuring tools — what reads an artifact after
the money has been spent. This file covers the half that decides: the diff
parser that says which lines a change answers for, the quote matcher, the
accepted-risk file, the gate, the budget, and the two tools that freeze a round
and a suite.

Same hunt, because it is the same defect: a check satisfied by the absence of
the data it needs. A hunk header that declares a count its body does not
honour. A path carrying a byte that is not UTF-8. A severity nobody recognises.
A verifier's usage block that says `NaN`. An ignore entry that constrains
nothing. Each of those decides whether a merge blocks, and none of them is a
value a hand-written fixture supplies.

Every property asserts something a module says about itself, in its own words,
and where the docstring turned out to claim something narrower than it seemed
to, the narrower thing is what is asserted. Where the module claims something
it does not do, the property is marked `xfail(strict=True)` and asserts the
*right* answer, so it turns red the day the code is fixed.

Regression tests are at the bottom under `TestFoundByHypothesis`: shrunk inputs,
plain pytest, each one naming the wrong answer it produced.


Every `xfail` in this file has been removed: each defect it named was
fixed on 2026-09-03, and each marker turned red the moment it passed —
which is the whole reason they were written `strict=True`.
"""

from __future__ import annotations

import itertools
import json
import os
import sys
from pathlib import Path

import pytest
import yaml
from hypothesis import HealthCheck, assume, example, given, settings
from hypothesis import strategies as st

from security_agent import budget as budget_mod
from security_agent import evidence, gate, suppress
from security_agent.config import Config
from security_agent.models import (
    STOP_COMPLETED,
    STOP_INCONCLUSIVE,
    Coverage,
    Finding,
    ScanOutcome,
    Usage,
    severity_rank,
)
from strategies_more import (
    CATEGORY_NAMES,
    IGNORE_ENTRIES,
    LONE_SURROGATE,
    PATH_NAMES,
    candidates,
    diff_plans,
    findings_objects,
    miscounted_diffs,
    quote_git_style,
)

TOOLS = Path(__file__).resolve().parents[1] / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import round as round_tools  # noqa: E402
import sentinel  # noqa: E402

# Same reasoning as next door: this runs on every change, so a property that
# takes a second is a property somebody deletes. `HYPOTHESIS_PROFILE=hunt` for
# the wider search.
settings.register_profile(
    "review-path",
    max_examples=40,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
settings.register_profile(
    "hunt",
    max_examples=1500,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture,
                           HealthCheck.too_slow],
)
settings.load_profile(os.environ.get("HYPOTHESIS_PROFILE", "review-path"))

# `tmp_path` is one directory for every example a property draws, so anything
# written under it survives into the next one. A counter, not the drawn values:
# two examples that draw the same values are still two runs.
_WORLDS = itertools.count()


# ================================================== evidence.changed_lines


@given(diff_plans())
def test_a_well_formed_diff_is_read_as_the_change_it_describes(plan):
    """`changed_lines` splits a unified diff into the lines a change answers for.

    The expectation is computed from the format's own definition — a line's
    new-file number is its hunk's start plus the number of lines before it that
    exist on the new side — rather than from the parser. Additions and deletions
    are checked separately because they reach differently, which is the reason
    `ChangedLines` keeps them apart.
    """
    got = evidence.changed_lines(plan["text"])
    assert got.added == plan["added"]
    assert got.removed_at == plan["removed"]


@given(diff_plans())
def test_no_line_is_attributed_to_a_file_no_header_named(plan):
    """Only a `+++` header names a file, and `/dev/null` names none.

    "reading that as a file header hands every addition below it to a file that
    does not exist" — the decoy rule, from the other side: nothing may appear in
    the map that was not named by a header outside a hunk body.
    """
    got = evidence.changed_lines(plan["text"])
    named = {entry["path"] for entry in plan["files"] if not entry["deleted"]}
    assert got.files() <= named
    assert "/dev/null" not in got.files()


@given(diff_plans())
def test_every_added_line_falls_inside_a_hunk_the_parser_read(plan):
    """An added line is only ever numbered from a hunk header it parsed.

    Stated as: every number in `added` lies within some hunk's declared new-side
    span. A number outside every span would mean the counter kept running past
    the end of a hunk, which is how a decoy header takes the additions after it.
    """
    got = evidence.changed_lines(plan["text"])
    spans = {}
    for entry in plan["files"]:
        for hunk in entry["hunks"]:
            new_count = sum(1 for marker, _ in hunk["ops"] if marker != "-")
            spans.setdefault(entry["path"], []).append(
                (hunk["new_start"], hunk["new_start"] + max(new_count, 1) - 1))
    for path, lines in got.added.items():
        for line in lines:
            assert any(low <= line <= high for low, high in spans.get(path, [])), (
                path, line, spans.get(path))


@given(miscounted_diffs(with_git_lines=True))
# Both file sections carry the separator, because that is the shape this test
# is about. They did not before, and the `assume` below silently discarded the
# example every run — a pinned counterexample that never executed. Found on
# 2026-09-04 while chasing the health-check failure that made the same filter
# throw seven diffs in eight away.
@example({"text": ("diff --git a/a.py b/a.py\n--- a/a.py\n+++ b/a.py\n"
                   "@@ -0,0 +1,2 @@\n+one\n"
                   "diff --git a/b.py b/b.py\n--- a/b.py\n+++ b/b.py\n"
                   "@@ -0,0 +1,1 @@\n+two\n"),
          "where": (0, 0), "last": False, "side": "new", "amount": 1})
def test_a_diff_whose_counts_do_not_add_up_is_refused(broken):
    """`DiffFormatError`: "a diff whose own structure does not add up".

    Refused rather than worked around, and the docstring says why: "a partial
    map is indistinguishable from a complete one to every caller, and a finding
    the map does not cover is reported as pre-existing, which does not block."
    A header that declares one line too many is exactly that — content the
    producer meant to send and did not.

    **Narrowed to diffs carrying `diff --git` separators, and the exclusion is
    the finding.** Without them there is a shape nothing can decide: an
    under-delivering hunk followed by the next file's `--- a/x` header eats
    that header as an ordinary deletion, because a line beginning `-` inside a
    hunk body *is* a deletion — `-- ` opens a comment in SQL, Lua, Haskell and
    Ada, which is why the parser reads column zero as the diff's own structure
    and never as a header while a hunk is open.

    Detecting it would mean treating `--- `/`+++ ` as headers inside a hunk
    body, and that is precisely the forgery this parser was rewritten to stop:
    an author writes `++ b/decoy.py`, git emits `+++ b/decoy.py`, and every
    addition after it is filed against a file that does not exist. Trading a
    live vulnerability for an unreachable one is not a trade.

    Unreachable is measured, not assumed: `workspace.changed_line_map` is the
    only caller and it shells out to `git diff`, which writes a `diff --git`
    line per file section. Recorded in `LIMITATIONS.md`.
    """
    assume(broken is not None)
    # *Every* file section, not merely one somewhere. A diff that carries the
    # separator for its first file and not its second has the undecidable shape
    # again, at the boundary between them — which is how the first attempt at
    # this assumption was too weak, and the generator found that too.
    #
    # Generated rather than assumed, since 2026-09-04. As a filter it threw
    # away seven diffs in eight, Hypothesis raised `FailedHealthCheck` at seed
    # 34 — eight generated against fifty discarded — and the health check said
    # the thing that matters: that much filtering distorts what the test
    # actually covers. It also silently discarded the pinned `@example` on
    # every run. The assertion stays, as a check on the generator.
    text = broken["text"]
    assert text.count("diff --git ") == text.count("\n+++ ") \
        + text.startswith("+++ ")
    with pytest.raises(evidence.DiffFormatError):
        evidence.changed_lines(text)


@given(miscounted_diffs(amounts=(-1,)))
def test_an_over_delivering_hunk_is_always_refused(broken):
    """The half of the promise that does hold, kept separate so it stays green.

    A body longer than its header declares is caught wherever it sits: the
    surplus would be read as structure, and "`+++ b/decoy.py` sitting in it
    would name the next hunk's additions after a file the author chose".
    """
    assume(broken is not None)
    with pytest.raises(evidence.DiffFormatError):
        evidence.changed_lines(broken["text"])


@given(st.text(max_size=200))
def test_reading_any_text_as_a_diff_either_answers_or_refuses(text):
    """Two outcomes and no third: a map, or `DiffFormatError`.

    `changed_lines` is documented as parsing a unified diff, and its caller
    treats anything it returns as the whole change. Any other exception escaping
    it aborts the changed-line map, and a change with no map has every finding
    recorded as pre-existing — which does not block.
    """
    try:
        got = evidence.changed_lines(text)
    except evidence.DiffFormatError:
        return
    assert set(got.added) == set(got.removed_at)


# ================================================== evidence.unquote_path


@given(PATH_NAMES, st.booleans())
def test_a_path_git_would_quote_survives_being_unquoted(path, escape_high):
    """"decode the path rather than trusting a configuration knob".

    Both quoting styles round-trip: `core.quotePath=false`, which still escapes
    the quote, the backslash and the control characters, and the default, which
    also escapes every byte above 0x7f as octal.
    """
    assert evidence.unquote_path(quote_git_style(path, escape_high)) == path


@given(st.text(max_size=20))
def test_an_unquoted_path_is_returned_untouched(path):
    """"if it is quoted at all" — anything not in quotes is not a quoted path."""
    assume(not (len(path) >= 2 and path.startswith('"') and path.endswith('"')))
    assert evidence.unquote_path(path) == path


@given(st.text(alphabet='ab\\"01234567' + LONE_SURROGATE, max_size=12))
@example('"' + LONE_SURROGATE + '"')
def test_unquote_path_never_raises(body):
    """"an exception escaping here aborts the whole changed-line map, so the
    change's own additions stop being attributed at all".

    The function's stated answer to anything it cannot decode is to return the
    string as it arrived. Raising is not one of the two directions it weighed.
    """
    evidence.unquote_path(body)
    evidence.unquote_path('"' + body + '"')


# ==================================================== evidence.attribution


@given(diff_plans(), st.integers(0, 60), st.integers(1, 4))
def test_attribution_is_one_of_three_answers_and_agrees_with_touches(
        plan, line, span):
    """`attribution` returns "added", "deleted", or "" — and nothing else.

    `touches_change` is documented as `bool(attribution(...))`, so the two can
    never disagree about whether the change is answerable for the cited code.
    """
    changed = evidence.changed_lines(plan["text"])
    path = next(iter(changed.files()), "nothing/here.py")
    answer = evidence.attribution(path, line, span, changed)
    assert answer in ("", evidence.ATTRIBUTED_ADDED, evidence.ATTRIBUTED_DELETED)
    assert evidence.touches_change(path, line, span, changed) is bool(answer)


@given(diff_plans())
def test_a_finding_sitting_on_an_added_line_is_attributed_to_the_change(plan):
    """"An added line is suspect where it sits."

    Every line the change added, cited on its own line, must come back as this
    change's responsibility. A gap here is the failure the module names: the
    finding is recorded as pre-existing, "which does not block".
    """
    changed = evidence.changed_lines(plan["text"])
    for path, lines in changed.added.items():
        for line in lines:
            assert evidence.attribution(path, line, 1, changed) == \
                evidence.ATTRIBUTED_ADDED


@given(diff_plans(), st.integers(1, 60))
def test_a_file_the_change_never_touched_is_never_this_change_s_fault(
        plan, line):
    """A path absent from the map is absent from the change."""
    changed = evidence.changed_lines(plan["text"])
    assert evidence.attribution("no/such/file.py", line, 1, changed) == ""


# ================================================== evidence.locate_evidence


@given(st.text(max_size=300), st.text(max_size=120), st.integers(0, 50))
def test_a_located_line_is_always_a_line_of_the_file(text, quote, claimed):
    """`locate_evidence` "Returns a 1-based line number" — of this file.

    Or raises `EvidenceProblem`, which is the documented third answer:
    "Ambiguity is now an answer, not something resolved by position."
    """
    try:
        line = evidence.locate_evidence(text, quote, claimed)
    except evidence.EvidenceProblem:
        return
    assert 1 <= line <= len(text.splitlines())


@given(st.text(max_size=60))
def test_the_span_of_a_quote_is_never_less_than_one(quote):
    assert evidence.evidence_span(quote) >= 1


# ========================================================= suppress.apply


def _rule(**kwargs):
    return suppress.Rule(reason="accepted", **kwargs)


@given(st.lists(candidates(), max_size=4),
       st.lists(st.one_of(
           st.builds(lambda c: _rule(category=c), CATEGORY_NAMES),
           st.builds(lambda p: _rule(path=p), PATH_NAMES),
           st.builds(lambda f: _rule(fingerprint=f),
                     st.sampled_from(["f" * 16, ""]))), max_size=3),
       st.booleans())
def test_kept_and_suppressed_partition_the_candidates(found, rules, self_added):
    """"Split candidates into (kept, suppressed)" — a split, not a filter.

    Nothing is lost and nothing is counted twice: `apply` decides where a
    finding is shown, never whether it exists. "Suppressed findings still appear
    in the report, in their own section. They are removed from the gate, never
    from view."
    """
    kept, hidden = suppress.apply(found, rules, self_added=self_added)
    assert len(kept) + len(hidden) == len(found)
    assert [id(c) for c in kept + hidden].count(id(kept[0])) == 1 if kept else True
    by_identity = {id(c) for c in kept} | {id(c) for c in hidden}
    assert by_identity == {id(c) for c in found}
    assert not ({id(c) for c in kept} & {id(c) for c in hidden})


@given(st.lists(candidates(), max_size=4),
       st.lists(st.builds(lambda c: _rule(category=c), CATEGORY_NAMES),
                max_size=3))
def test_a_change_that_edits_the_ignore_file_cannot_suppress_itself(
        found, rules):
    """"Suppressions then do not apply to this change — they take effect from
    the next one."

    Without it "a merge request can introduce a weakness and the entry excusing
    it in the same breath, and the gate approves itself."
    """
    kept, hidden = suppress.apply(found, rules, self_added=True)
    assert hidden == []
    assert len(kept) == len(found)


@given(st.lists(candidates(), max_size=4),
       st.lists(st.builds(lambda c: _rule(category=c), CATEGORY_NAMES),
                max_size=3))
def test_every_suppressed_finding_records_which_entry_silenced_it(found, rules):
    """"an accepted risk is a decision with a date on it rather than a permanent
    silence" — so the report has to be able to say which entry, and why.
    """
    _, hidden = suppress.apply(found, rules, self_added=False)
    for candidate in hidden:
        assert candidate.suppressed_by
        assert "accepted" in candidate.suppressed_by


# ========================================================== suppress.load


@given(st.lists(IGNORE_ENTRIES, max_size=3))
def test_a_rule_that_survives_loading_always_constrains_something(
        tmp_path, entries):
    """"entry N must set at least one of `fingerprint`, `path`, or `category`".

    A rule constraining nothing "would silence the entire report", and
    `Rule.matches` relies on `load` having refused it: its path/category branch
    returns True when both are empty.
    """
    path = tmp_path / ".security-agent-ignore.yml"
    path.write_text(yaml.safe_dump({"ignore": entries}), encoding="utf-8")
    try:
        rules, warnings = suppress.load(path)
    except suppress.SuppressionError:
        return
    for rule in rules:
        assert rule.fingerprint or rule.path or rule.category
        assert rule.reason
    assert len(rules) + len(warnings) <= len(entries)


@given(st.lists(IGNORE_ENTRIES, max_size=3))
def test_an_expired_entry_is_never_returned_as_an_active_rule(
        tmp_path, entries):
    """"expired on {} and is no longer applied" — a warning, not a rule."""
    path = tmp_path / ".security-agent-ignore.yml"
    path.write_text(yaml.safe_dump({"ignore": entries}), encoding="utf-8")
    import datetime as dt
    today = dt.date(2026, 9, 3)
    try:
        rules, _ = suppress.load(path, today=today)
    except suppress.SuppressionError:
        return
    for rule in rules:
        assert not rule.expired(today)


# =================================================== gate.blocking_findings


def _config(**kwargs):
    cfg = Config()
    for name, value in kwargs.items():
        setattr(cfg, name, value)
    return cfg


def _outcome(**kwargs):
    coverage = kwargs.pop("coverage", None) or Coverage()
    return ScanOutcome(mode="diff", coverage=coverage, **kwargs)


GATE_CONFIGS = st.builds(
    _config,
    fail_on=st.sampled_from(["critical", "high", "medium", "low", "none"]),
    min_confidence=st.sampled_from(["low", "medium", "high"]),
    gate_pre_existing=st.booleans(),
    gate_removed_controls=st.booleans(),
    fail_on_incomplete=st.booleans(),
    ungated_categories=st.lists(CATEGORY_NAMES, max_size=2).map(tuple),
)


@given(GATE_CONFIGS, st.lists(candidates(), max_size=5))
def test_nothing_blocks_that_was_not_reported(cfg, found):
    """"Which reported findings actually stop the merge" — reported ones."""
    outcome = _outcome(reported=found)
    blocking = gate.blocking_findings(cfg, outcome)
    assert {id(c) for c in blocking} <= {id(c) for c in found}


@given(GATE_CONFIGS, st.lists(candidates(), max_size=5))
def test_an_ungated_category_never_stops_a_merge(cfg, found):
    """"A category the project has decided not to gate on takes precedence over
    every rule below, including the removed-control one."
    """
    outcome = _outcome(reported=found)
    ungated = {c.lower() for c in cfg.ungated_categories}
    for candidate in gate.blocking_findings(cfg, outcome):
        assert candidate.finding.category.lower() not in ungated


@given(GATE_CONFIGS, st.lists(candidates(), max_size=5))
def test_a_finding_excluded_by_policy_is_never_also_a_blocking_one(cfg, found):
    """The report marks these individually; a finding cannot be both."""
    outcome = _outcome(reported=found)
    blocking = {id(c) for c in gate.blocking_findings(cfg, outcome)}
    excluded = {id(c) for c in gate.policy_excluded(cfg, outcome)}
    assert not (blocking & excluded)


@given(GATE_CONFIGS, st.lists(candidates(), max_size=5))
def test_removing_a_control_blocks_whatever_the_severity_says(cfg, found):
    """"A change that deletes a security control blocks on that alone."

    Measured, and the reason the rule exists: "a merge request reverting the fix
    for CVE-2023-41040 was found and confirmed on five runs out of five and
    blocked on none of them, because three independent reads agreed it rated
    below the threshold."
    """
    assume(cfg.gate_removed_controls and cfg.fail_threshold is not None)
    outcome = _outcome(reported=found)
    blocking = {id(c) for c in gate.blocking_findings(cfg, outcome)}
    ungated = {c.lower() for c in cfg.ungated_categories}
    for candidate in found:
        reachable = candidate.in_changed_lines or cfg.gate_pre_existing
        if (candidate.removes_control and reachable
                and candidate.finding.category.lower() not in ungated):
            assert id(candidate) in blocking


@given(GATE_CONFIGS, st.lists(candidates(), max_size=5))
def test_a_pre_existing_finding_blocks_only_when_the_setting_says_so(cfg, found):
    assume(not cfg.gate_pre_existing)
    outcome = _outcome(reported=found)
    for candidate in gate.blocking_findings(cfg, outcome):
        assert candidate.in_changed_lines


@given(st.lists(candidates(), max_size=5))
def test_fail_on_none_blocks_nothing_at_all(found):
    """"SECURITY_SCAN_FAIL_ON=none, so nothing blocks the merge"."""
    cfg = _config(fail_on="none")
    assert gate.blocking_findings(cfg, _outcome(reported=found)) == []


@given(st.builds(_config,
                 fail_on=st.sampled_from(["critical", "high", "medium", "low"]),
                 min_confidence=st.sampled_from(["low", "medium", "high"]),
                 gate_pre_existing=st.booleans(),
                 gate_removed_controls=st.booleans()),
       candidates(),
       st.sampled_from(["Sev-9", "HIGH", "critical"]))
def test_a_rating_nobody_recognises_fails_towards_blocking(cfg, candidate,
                                                           word):
    """"A value nobody recognises is not a value below the threshold."

    `severity_rank` returns -1 for an unknown word and `-1 < minimum` "was
    letting a `confidence` of 'High' — one capital letter — carry a `critical`
    finding past the gate: rendered as CRITICAL in the report, absent from
    `blocking_fingerprints`, exit 0."
    """
    candidate.severity = word
    candidate.confidence = word
    candidate.in_changed_lines = True
    outcome = _outcome(reported=[candidate])
    blocking = gate.blocking_findings(cfg, outcome)
    if severity_rank(word) < 0:
        assert blocking, "an unrecognised rating must not be read as 'below'"


# ============================================================== gate.decide


OUTCOMES = st.builds(
    _outcome,
    stop_reason=st.sampled_from(
        [STOP_COMPLETED, "turn_limit", "context_exhausted", STOP_INCONCLUSIVE,
         "a_reason_nobody_added"]),
    stop_detail=st.sampled_from(["", "the CLI exited 1"]),
    reported=st.lists(candidates(), max_size=4),
    exposures=st.lists(st.tuples(PATH_NAMES, st.just("diff")), max_size=2),
    coverage=st.builds(
        Coverage,
        changed=st.lists(PATH_NAMES, max_size=3),
        examined=st.lists(PATH_NAMES, max_size=2),
        diff_truncated=st.booleans(),
        context_refusals=st.integers(0, 2),
        unreadable=st.lists(st.tuples(PATH_NAMES, st.just("binary")),
                            max_size=2)),
)


@given(GATE_CONFIGS, OUTCOMES)
def test_the_verdict_is_always_one_of_the_three_exit_codes(cfg, outcome):
    """0 "nothing blocking", 1 "the code has a problem", 2 "the check itself did
    not run properly" — "a distinction worth keeping, because the first is the
    author's to fix and the second is the pipeline owner's."
    """
    decision = gate.decide(cfg, outcome)
    assert decision.exit_code in (gate.EXIT_OK, gate.EXIT_FINDINGS,
                                  gate.EXIT_ERROR)
    assert decision.reason
    assert decision.blocked is (decision.exit_code != gate.EXIT_OK)


@given(GATE_CONFIGS, OUTCOMES)
def test_exit_one_is_exactly_the_verdict_with_blocking_findings(cfg, outcome):
    """The reason names which rule applied, so the two cannot come apart."""
    decision = gate.decide(cfg, outcome)
    assert bool(decision.blocking) is (decision.exit_code == gate.EXIT_FINDINGS)


@given(GATE_CONFIGS, OUTCOMES)
def test_an_incomplete_review_is_never_a_pass_unless_it_was_forgiven(
        cfg, outcome):
    """"An incomplete review has no opinion worth acting on."

    Exit 0 over a partial run means exactly one thing: the operator set
    `SECURITY_SCAN_FAIL_ON_INCOMPLETE=false`. Three ways to be partial — the
    reviewer stopped early, the diff was cut at its ceiling, or the context
    budget refused a result — and all three go through the same flag.
    """
    decision = gate.decide(cfg, outcome)
    partial = (not outcome.complete or outcome.coverage.diff_truncated
               or outcome.coverage.context_refusals > 0)
    if partial and decision.exit_code == gate.EXIT_OK:
        assert cfg.fail_on_incomplete is False


@given(GATE_CONFIGS, OUTCOMES)
def test_a_review_that_opened_nothing_is_never_a_pass(cfg, outcome):
    """"A verdict over code nothing read is not a verdict, and no setting makes
    it a pass."

    The combination that shipped: finished cleanly, opened nothing. "Every test
    that passed `exposures=[]` also passed a stop reason that made the run
    partial, so the combination that matters — finished, and nothing opened —
    was never asked about."
    """
    outcome.exposures = []
    outcome.coverage.unreadable = []
    outcome.coverage.changed = outcome.coverage.changed or ["app/handler.py"]
    assert gate.decide(cfg, outcome).exit_code == gate.EXIT_ERROR


@given(GATE_CONFIGS, OUTCOMES)
def test_a_profile_that_cannot_conclude_is_never_forgiven(cfg, outcome):
    """"No setting makes this a pass: it is a property of the profile, not a
    policy about partial reviews."

    The stop reason is set rather than drawn: `probe` ending this way is the
    whole case, and filtering for it would spend the examples on drawing it.
    """
    outcome.stop_reason = STOP_INCONCLUSIVE
    assert gate.decide(cfg, outcome).exit_code == gate.EXIT_ERROR


@given(GATE_CONFIGS, OUTCOMES)
def test_deciding_twice_gives_the_same_verdict(cfg, outcome):
    """`decide` reads a run; it does not change one."""
    first = gate.decide(cfg, outcome)
    second = gate.decide(cfg, outcome)
    assert first.exit_code == second.exit_code
    assert first.reason == second.reason
    assert len(first.blocking) == len(second.blocking)


# ================================================================= budget


@given(st.integers(0, 8), st.integers(0, 12))
def test_an_allowance_never_spends_past_its_ceiling(ceiling, calls):
    """"A fixed number of tool calls, held by exactly one session."

    "The call that reaches the ceiling is served; the next one is refused."
    """
    allowance = budget_mod.Allowance("review", ceiling)
    served = sum(1 for _ in range(calls) if allowance.note_tool_call())
    assert served == min(calls, ceiling)
    assert allowance.spent == min(calls, ceiling)
    assert allowance.remaining == max(0, ceiling - allowance.spent)
    assert allowance.exhausted is (allowance.spent >= ceiling)


PROFILES = st.sampled_from(sorted(budget_mod.PROFILES))


@given(PROFILES, st.integers(0, 6))
def test_a_run_never_seats_more_verifiers_than_the_profile_pays_for(
        name, wanted):
    """"a run-wide ceiling on verifier sessions — the money limit, and the
    largest single cost in the tool."
    """
    profile = budget_mod.profile_named(name)
    run = budget_mod.RunBudget(profile)
    seats = [run.reserve_verifier() for _ in range(wanted)]
    granted = [seat for seat in seats if seat is not None]
    assert len(granted) <= profile.verifier_sessions
    assert run.verifier_sessions == len(granted)
    assert run.allocated_tool_calls == (
        run.review.ceiling + sum(a.ceiling for a in granted))


@given(st.integers(1, 3), st.integers(1, 3),
       st.lists(st.sampled_from(["call", "turn"]), max_size=10))
@example(turns=1, calls=1, actions=["call", "turn"])
def test_the_ceiling_a_run_reports_is_the_first_one_it_hit(turns, calls,
                                                           actions):
    """"a report naming the wrong ceiling sends the reader to raise the wrong
    limit" — `check()` says so, and it is why tool calls are tested before the
    clock. Which ceiling stopped a run cannot depend on what happened after it.

    The ceilings are small on purpose: the shipped profiles allow forty tool
    calls against six turns, so a property that used them would never reach a
    ceiling at all and would pass without asking anything.
    """
    run = budget_mod.RunBudget(budget_mod.Profile(
        "t", review_turns=turns, review_tool_calls=calls, verifier_sessions=0,
        verifier_tool_calls=0, runtime_seconds=600))
    first = ""
    for action in actions:
        if action == "call":
            run.note_tool_call()
        else:
            run.note_review_turn()
        run.check()
        if run.stopped_by and not first:
            first = run.stopped_by
        assert run.stopped_by in ("", first)


@given(st.lists(st.one_of(st.none(), st.integers(0, 100)), max_size=4),
       st.lists(st.one_of(st.none(), st.floats(0, 5, allow_nan=False,
                                               allow_infinity=False)),
                max_size=4))
def test_usage_nobody_reported_stays_unreported(tokens, costs):
    """"Record what a runner could tell us. Absent stays absent."

    `None` is "the backend did not say", "which is reported as 'unavailable',
    never as zero". A zero it did say is a different answer and must survive.
    """
    run = budget_mod.RunBudget(budget_mod.profile_named("normal"))
    for value in tokens:
        run.note_usage(input_tokens=value)
    for value in costs:
        run.note_usage(cost_usd=value)
    said = [v for v in tokens if v is not None]
    assert run.input_tokens == (sum(said) if said else None)
    assert run.output_tokens is None
    paid = [v for v in costs if v is not None]
    assert (run.cost_usd is None) is (not paid)


@given(PROFILES)
def test_a_run_that_stopped_says_so_in_a_sentence(name):
    """A sentence for the report, or the empty string if nothing stopped it."""
    run = budget_mod.RunBudget(budget_mod.profile_named(name))
    assert run.why_stopped() == ""
    while not run.check():
        run.note_tool_call()
    assert run.why_stopped()
    assert run.summary()


# ================================================================= models


USAGES = st.builds(
    Usage,
    input_tokens=st.integers(0, 10 ** 6),
    output_tokens=st.integers(0, 10 ** 6),
    cache_read_tokens=st.integers(0, 10 ** 6),
    cache_write_tokens=st.integers(0, 10 ** 6),
    requests=st.integers(0, 5),
    unreported_stages=st.integers(0, 3),
)


@given(USAGES)
def test_a_stored_usage_block_reads_back_as_itself(usage):
    """"One reader, so no tool re-derives 'was this reported' from the keys
    itself and gets it slightly different."

    `reported` and `complete` are conclusions and are re-derived; every figure
    the record carries has to survive the round trip, including the count of
    stages that reported nothing.
    """
    again = Usage.from_dict(usage.to_dict())
    assert again == usage
    assert again.reported == usage.reported
    assert again.complete == usage.complete


@given(USAGES)
def test_a_usage_block_never_prices_a_total_it_cannot_see(usage):
    """"`None` rather than `0.0` for a run nobody reported... `None` for an
    incomplete total too, and for the same reason."
    """
    total = usage.cost_usd(3.0, 15.0)
    if not usage.reported or not usage.complete:
        assert total is None
    else:
        assert total is not None and total >= 0


@given(st.dictionaries(
    st.sampled_from([*Usage.CLI_FIELDS, "other"]),
    st.one_of(st.integers(-5, 10 ** 6), st.floats(allow_nan=True,
                                                  allow_infinity=True),
              st.none(), st.booleans(), st.text(max_size=3)),
    max_size=5))
@example({"input_tokens": float("nan"), "output_tokens": 1,
          "cache_creation_input_tokens": 1, "cache_read_input_tokens": 1})
def test_a_provider_block_is_read_whole_or_not_at_all(block):
    """"an unexpected shape — a spelling nobody anticipated, a truncated
    document, a future field set — produces 'this runner reported nothing',
    which is true, rather than a number that is not."

    All four names or none, and never an exception: this is the one place a
    review's cost is read off what the CLI printed.
    """
    usage = Usage.from_provider(block)
    complete = all(
        isinstance(block.get(name), (int, float))
        and not isinstance(block.get(name), bool)
        for name in Usage.CLI_FIELDS)
    if not complete:
        assert not usage.reported and usage.unreported_stages == 1


@given(findings_objects())
def test_a_finding_always_has_at_least_one_identity(finding):
    """"Never empty — the report prints `fingerprints[0]` under 'accept this
    risk by adding', and `suppress.Rule.matches` asks whether the value in the
    ignore file is *in this list*."
    """
    values = finding.fingerprints
    assert values
    assert finding.fingerprint == values[0]
    assert finding.fingerprint in values
    assert all(len(v) == 16 for v in values)
    assert len(set(values)) == len(values)


@given(findings_objects())
def test_an_identity_does_not_move_between_reads(finding):
    """"Identity is never tied to prose": the same finding, read twice, is the
    same finding. Five runs over an identical diff once produced five
    fingerprints, and "that silently broke the only escape hatch a blocking gate
    has".
    """
    assert finding.fingerprints == Finding.from_dict(
        {**finding.__dict__, "line": finding.line}).fingerprints


@given(st.data())
def test_two_quotes_sharing_a_line_are_the_same_finding(data):
    """"Two findings are the same when any anchor is shared, which survives a
    run quoting one line more, one line fewer, or starting anywhere inside the
    same block."
    """
    category = data.draw(CATEGORY_NAMES)
    path = data.draw(PATH_NAMES)
    shared = "rows, err := s.db.QueryContext(r.Context(), query)"
    base = data.draw(findings_objects(
        category=st.just(category), file_=st.just(path)))
    one = Finding(**{**base.__dict__, "evidence": shared})
    two = Finding(**{**base.__dict__,
                     "evidence": "if err != nil {\n" + shared + "\nreturn"})
    assert set(one.fingerprints) & set(two.fingerprints)


@given(st.lists(candidates(), max_size=3), st.lists(candidates(), max_size=3))
def test_a_stage_that_reported_nothing_keeps_the_total_incomplete(found, more):
    """"a review whose verifier reported nothing came out with `requests > 0`
    and presented the review stage's cost as the whole review's cost."
    """
    outcome = _outcome(reported=found, refuted=more, turns=1)
    outcome.metrics.verified = 1
    outcome.usage = Usage(input_tokens=10, requests=1)
    total = outcome.total_usage()
    assert not total.complete
    assert total.unreported_stages >= 1
    assert total.cost_usd(3.0, 15.0) is None


# ============================================================ tools/round.py


def _freeze_round(tmp_path, monkeypatch, baselines):
    root = tmp_path / "world-{}".format(next(_WORLDS))
    monkeypatch.setattr(round_tools, "ROOT", root)
    monkeypatch.setattr(round_tools, "environment",
                        lambda: {"agent_version": "0.1.0"})
    directory = root / "measurements" / "round-1"
    directory.mkdir(parents=True)
    body = {
        "round": 1,
        "environment": {"agent_version": "0.1.0"},
        "counts": {"with_baseline": len(baselines)},
        "cases": [{"case_id": case_id,
                   "baseline": {"pair_success": verdict},
                   "contributes_to": ["stability", "recall"]}
                  for case_id, verdict in baselines],
    }
    (directory / "manifest.json").write_text(json.dumps(body), encoding="utf-8")
    return directory


@given(st.lists(st.tuples(st.sampled_from(["go-1", "py-2", "rb-3"]),
                          st.booleans()),
                max_size=3, unique_by=lambda pair: pair[0]),
       st.lists(st.sampled_from([True, False, None, "false", "true"]),
                max_size=3))
def test_a_round_that_compared_nothing_is_not_reported_as_agreement(
        tmp_path, monkeypatch, capsys, baselines, verdicts):
    """"an empty comparison and a comparison that found no movement are
    different answers."

    Exit 2 covers both "not measured" endings: nothing comparable, and a row
    that ran without producing a verdict. Exit 0 has to mean at least one case
    produced a baseline and a boolean beside it.
    """
    directory = _freeze_round(tmp_path, monkeypatch, baselines)
    rows = [{"case_id": case_id, "pair_success": verdict}
            for (case_id, _), verdict in zip(baselines, verdicts)]
    (directory / "batch.json").write_text(json.dumps(rows), encoding="utf-8")

    code = round_tools.compare(1)
    printed = capsys.readouterr().out
    assert code in (0, 2)
    settled = [row for row in rows if row["pair_success"] in (True, False)]
    if not settled:
        assert code == 2
    if code == 0:
        assert settled and "agreed" in printed


@given(st.booleans(), st.booleans())
def test_a_case_recorded_twice_is_not_settled_by_a_file_name(
        tmp_path, monkeypatch, capsys, baseline, first):
    """"it is decided **in advance** which pass-2 row each pass-1 row is
    comparable to, and under what rule they count as agreeing. Deciding either
    afterwards — once the disagreements are visible — produces a number chosen
    to fit them."

    Two rows for one case disagree. Whichever rule settles that, it must be the
    same rule when the two rows swap files: `a.json`/`b.json` is not a
    chronology, and `sentinel.py` documents the same trap — "`cli-batch-10-go-
    snap.json` sorts before `cli-batch-2.json`".
    """
    answers = []
    for order in ((first, not first), (not first, first)):
        directory = _freeze_round(tmp_path, monkeypatch, [("go-1", baseline)])
        for name, verdict in zip(("a.json", "b.json"), order):
            (directory / name).write_text(
                json.dumps([{"case_id": "go-1", "pair_success": verdict}]),
                encoding="utf-8")
        code = round_tools.compare(1)
        answers.append((code, capsys.readouterr().out))
    assert answers[0] == answers[1]


# ========================================================= tools/sentinel.py


@given(st.lists(st.sampled_from(["go-a", "go-b", "py-a", "rb-c"]),
                min_size=1, max_size=4, unique=True),
       st.sampled_from(["pass", "fail", "unstable"]))
def test_a_written_suite_reads_back_as_the_cases_it_named(
        tmp_path, cases, verdict):
    """`--write` then `--check`: "exit 1 if the manifest no longer matches the
    rule". The check is only meaningful if reading a suite returns exactly what
    writing one put there — otherwise a drift is reported that never happened.
    """
    suite = {
        "cases": sorted(cases),
        "outcomes": {case_id: verdict for case_id in cases},
        "pool": len(cases),
        "strata": [{"language": case_id.split("-")[0], "eligible_pass": 1,
                    "eligible_fail": 0, "eligible_unstable": 0,
                    "chosen": [case_id]} for case_id in sorted(cases)],
    }
    path = tmp_path / "sentinel.yml"
    path.write_text(sentinel.render(suite), encoding="utf-8")
    assert sentinel.read_cases(path) == sorted(cases)


WRITE_PLACES = st.sampled_from(
    ["batch.json", "queue/one.json", "experiment-1/pass-a/one.json",
     "round-1/one.json"])

ROW_SHAPES = st.sampled_from(["list", "results", "bare"])


@given(WRITE_PLACES, ROW_SHAPES,
       st.lists(st.sampled_from([True, False, "false", "true", None, 1, 0]),
                min_size=1, max_size=3),
       st.booleans())
def test_only_a_boolean_verdict_becomes_a_recorded_outcome(
        tmp_path, place, shape, verdicts, incomplete):
    """"A row whose `pair_success` is absent, null, or not a boolean is not an
    outcome... Not truthiness: `"false"` is a true string, so a row carrying the
    *text* 'false' was recorded as a pass."

    And every place a paid run writes, not the two most readers know about.
    """
    rows = [{"case_id": "go-1", "pair_success": verdict,
             **({"incomplete": True} if incomplete else {})}
            for verdict in verdicts]
    body = rows if shape == "list" else (
        {"results": rows} if shape == "results" else rows[0])
    root = tmp_path / "world-{}".format(next(_WORLDS))
    path = root / place
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(body), encoding="utf-8")

    found = sentinel.recorded_outcomes(root)
    seen = [v for v in (verdicts if shape != "bare" else verdicts[:1])
            if isinstance(v, bool)]
    if incomplete or not seen:
        assert found == {}
    else:
        expected = {"pass" if v else "fail" for v in seen}
        assert found == {"go-1": (expected.pop() if len(expected) == 1
                                  else "unstable")}


@given(st.dictionaries(
    st.sampled_from(["go-1", "go-2", "py-1"]),
    st.sampled_from(["pass", "fail", "unstable"]), max_size=3))
def test_a_suite_that_cannot_show_a_regression_is_refused(outcomes):
    """"A suite the rule produced correctly and that cannot do its job is the
    worst of the three outcomes: it looks like a control and is not one."
    """
    suite = {"cases": sorted(outcomes), "outcomes": outcomes}
    problems = sentinel.refusals(suite)
    kinds = set(outcomes.values())
    assert bool(problems) is not (bool(kinds & {"pass"})
                                 and bool(kinds & {"fail", "unstable"}))


@given(st.lists(st.sampled_from([
    ["a"], {"results": [{"case_id": "go-1", "pair_success": True}]},
    {"case_id": "go-1", "pair_success": True}, {"results": "not a list"},
    "text", 3, None]), max_size=3))
def test_a_result_file_is_never_iterated_as_nothing_by_accident(bodies):
    """"Reading an object as `[]` is the quiet version: the file is opened,
    parsed, and then iterated as nothing."
    """
    for body in bodies:
        rows = sentinel.rows_in(body)
        assert isinstance(rows, list)
        assert all(isinstance(row, dict) for row in rows)
        if isinstance(body, dict) and not isinstance(body.get("results"), list):
            assert rows == [body]


# ================================================== TestFoundByHypothesis


class TestFoundByHypothesis:
    """Shrunk counterexamples. Each one names the wrong answer it produced.

    Plain pytest on purpose: once the input is known, generating it again buys
    nothing. Each asserts the *right* answer. They were marked
    `xfail(strict=True)` while the defects were open,
    so it turns red the day the defect is fixed.
    """

    def test_a_path_carrying_a_non_utf8_byte_is_decoded_not_refused(self):
        """`unquote_path('"b/x\\udcff.py"')` raised `UnicodeEncodeError`.

        Wrong answer: an exception out of a path decoder. `workspace` decodes
        git's output with `errors="surrogateescape"` — deliberately, so that a
        byte which is not UTF-8 survives — and a path is quoted whenever it
        contains a double quote, "regardless of the setting". A name holding
        both arrives here as `"b/a\\"b\\udcff.py"`, and `char.encode("utf-8")`
        refuses a lone surrogate.

        Right answer: the byte comes back out, as `surrogateescape` promises on
        the way in. The exception escapes `changed_lines`, so the whole
        changed-line map is lost and every finding in the change is recorded as
        pre-existing — which does not block.
        """
        assert evidence.unquote_path('"b/x' + LONE_SURROGATE + '.py"') == \
            "b/x" + LONE_SURROGATE + ".py"

    def test_a_diff_naming_such_a_path_still_produces_a_map(self):
        """`changed_lines` raised `UnicodeEncodeError` rather than a map.

        The same defect one level up, and this is where it costs something: not
        a `DiffFormatError` the caller handles, but an exception out of the
        parser, so the run has no map at all.
        """
        text = ('+++ "b/src/x' + LONE_SURROGATE + '.py"\n'
                "@@ -1,0 +1,1 @@\n"
                "+password = 'hunter2'\n")
        assert evidence.changed_lines(text).added

    def test_a_hunk_that_under_delivers_is_refused_wherever_it_sits(self):
        """A header declaring two added lines over a body with one, followed by
        another file, returned a map instead of raising.

        Wrong answer: `{'a.py': {1}, 'b.py': {1}}` — the missing line simply is
        not there, and the caller cannot tell this map from a complete one. The
        `@@` and `diff ` lines are matched before the in-hunk check, so the next
        header closes an unfinished hunk without a word.

        Right answer: `DiffFormatError`. The module's own reason — "a partial
        map is indistinguishable from a complete one to every caller, and a
        finding the map does not cover is reported as pre-existing, which does
        not block" — does not depend on where in the diff the bad header sits.
        """
        text = ("--- a/a.py\n+++ b/a.py\n@@ -0,0 +1,2 @@\n+one\n"
                "diff --git a/b.py b/b.py\n--- a/b.py\n+++ b/b.py\n"
                "@@ -0,0 +1,1 @@\n+two\n")
        with pytest.raises(evidence.DiffFormatError):
            evidence.changed_lines(text)

    def test_a_usage_block_saying_nan_reads_as_unreported(self):
        """`Usage.from_provider({... "input_tokens": NaN ...})` raised
        `ValueError: cannot convert float NaN to integer`.

        Wrong answer: an exception, where the documented answer to any shape it
        does not recognise is "this runner reported nothing". `json.loads`
        parses the bare literals `NaN`, `Infinity` and `-Infinity` by default,
        and the CLI's stdout is read with `json.loads`, so the guard —
        `isinstance(v, (int, float))` — lets them straight through to `int()`.
        `Infinity` raises `OverflowError` on the same line.
        """
        block = {"input_tokens": float("nan"), "output_tokens": 1,
                 "cache_creation_input_tokens": 1,
                 "cache_read_input_tokens": 1}
        assert Usage.from_provider(block).unreported_stages == 1

    def test_a_stored_usage_block_saying_nan_reads_as_zero(self):
        """`Usage.from_dict({"input_tokens": NaN})` raised the same `ValueError`.

        Wrong answer: the reader that exists so "no tool re-derives 'was this
        reported' from the keys itself" cannot read the file at all. `count()`
        accepts any `int` or `float` and hands it to `int()`.
        """
        assert Usage.from_dict({"input_tokens": float("nan")}).input_tokens == 0

    def test_a_run_stopped_by_its_tool_calls_does_not_become_a_turn_limit(self):
        """A budget that had already stopped on `tool_calls` reported `turns`
        after one more turn was noted.

        Wrong answer: `why_stopped()` said "the run reached its turn limit" for
        a run that stopped because its allowance ran out. `note_review_turn`
        assigns `stopped_by` with no guard, while `check()` has one — so which
        ceiling a run reports depends on what happened after it was already
        stopped, and `check()`'s own reasoning is that "a report naming the
        wrong ceiling sends the reader to raise the wrong limit".
        """
        profile = budget_mod.Profile(
            "t", review_turns=2, review_tool_calls=1, verifier_sessions=0,
            verifier_tool_calls=0, runtime_seconds=100)
        run = budget_mod.RunBudget(profile)
        run.note_tool_call()
        assert run.check() == budget_mod.STOPPED_TOOL_CALLS
        run.note_review_turn()
        run.note_review_turn()
        assert run.stopped_by == budget_mod.STOPPED_TOOL_CALLS

    def test_two_disagreeing_rows_for_one_case_are_not_settled_silently(
            self, tmp_path, monkeypatch, capsys):
        """One case, two rows, two files: `compare` counted whichever row was in
        the file whose name sorted last.

        Wrong answer: with a baseline of `True`, `a.json` saying `True` and
        `b.json` saying `False` counted as one flip; swapping the file names
        counted as one agreement. Nothing changed but the file names.

        Right answer: the same one `sentinel.recorded_outcomes` gives — a case
        seen to answer two ways is not resolved by picking one — or the refusal
        `check_accounted` gives. Either way the number this file exists to
        produce must not depend on a glob's ordering.
        """
        answers = []
        for order in ((True, False), (False, True)):
            directory = _freeze_round(tmp_path, monkeypatch,
                                      [("go-1", True)])
            for name, verdict in zip(("a.json", "b.json"), order):
                (directory / name).write_text(
                    json.dumps([{"case_id": "go-1", "pair_success": verdict}]),
                    encoding="utf-8")
            answers.append((round_tools.compare(1),
                            capsys.readouterr().out))
        assert answers[0] == answers[1], (
            "same two rows, different file names, different count")
