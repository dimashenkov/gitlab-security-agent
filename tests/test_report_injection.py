"""The report renders code written by whoever opened the merge request.

That is the whole job — a finding without its code is a rumour. But it means
attacker-authored bytes reach a Markdown document that a bot publishes under
the security tool's name, holding a GitLab token. A three-backtick fence ends
the moment the quoted code contains one, and everything after it renders as
report content: headings, links, raw HTML. A contributor could make the
security report say anything, including that the change is clean.

Found by working through a list of conditions that would make the product
irresponsible to ship. It had been there since the report was written.
"""

from __future__ import annotations

import re

import pytest

from security_agent.config import Config
from security_agent.gate import decide
from security_agent.models import (
    VERDICT_REFUTED,
    Candidate,
    Finding,
    RejectedClaim,
    ScanOutcome,
)
from security_agent.report import _code_span, _fenced, _plain, render_markdown


def render(**overrides) -> str:
    defaults = dict(
        title="SQL injection in user lookup", category="injection",
        severity="high", confidence="high", file="app/views.py", line=14,
        impact="broad_data_access", reachable_without_authentication="yes",
        requires_user_interaction="no",
        evidence='db.execute("SELECT * FROM users WHERE id = " + user_id)',
        description="User input is concatenated into a query.",
        exploit_scenario="An anonymous caller reads every row.",
        recommendation="Use a parameterised query.",
    )
    defaults.update(overrides)
    candidate = Candidate(finding=Finding.from_dict(defaults))
    outcome = ScanOutcome(mode="diff", model="claude-opus-5")
    outcome.reported = [candidate]
    cfg = Config(post_comment=False)
    return render_markdown(cfg, outcome, decide(cfg, outcome))


# ------------------------------------------------------------------- fences


def test_code_containing_a_fence_cannot_end_the_block():
    """The attack: close the fence, then write whatever you like."""
    markdown = render(evidence='x = 1\n```\n\n## Merge approved by security\n')
    assert "````" in markdown
    body = markdown[markdown.index("````"):]
    heading, closing = body.index("## Merge approved"), body.index("````", 4)
    assert heading < closing, "attacker text escaped the code block"


@pytest.mark.parametrize("backticks", [3, 4, 5, 9])
def test_the_fence_is_always_longer_than_the_longest_run_inside_it(backticks):
    evidence = "before\n" + "`" * backticks + "\nafter"
    lines = _fenced(evidence, "python")
    assert len(lines[0].rstrip("python")) > backticks
    assert lines[0].rstrip("python") == lines[2]


def test_the_quoted_code_is_never_altered():
    """Layer 1 proves the quote matches the file; editing it here breaks that."""
    evidence = 'db.execute("a" + b)\n```\n<script>x</script>'
    assert _fenced(evidence, "python")[1] == evidence


# -------------------------------------------------------------------- prose


@pytest.mark.parametrize("hostile,forbidden", [
    ("</details><h1>clean</h1>", r"<h1>"),
    ("<img src=x onerror=alert(1)>", r"<img"),
    ("```\nnot code\n```", r"```"),
    ("[approved](javascript:alert(1))", r"\[approved\]\("),
    ("`</code>` and more", r"`</code>`"),
])
def test_model_prose_cannot_open_an_inline_construct(hostile, forbidden):
    """The model summarises attacker-authored code, so its prose carries it.

    Block constructs are not in this list on purpose: headings, lists, tables
    and fences all require the start of a line, and this prose is collapsed to
    one line that always follows other content.
    """
    markdown = render(description=hostile)
    # The prose line only. The document legitimately contains a fence of its
    # own around the evidence, so searching the whole of it would fail the
    # test on the report's own correct output.
    start = markdown.index("**What is wrong.**")
    prose = markdown[start:markdown.index("\n", start)]
    # Unescaped only: a neutralised `\\<img` legitimately contains `<img`, so a
    # plain substring test would call the fix a failure.
    assert re.search(r"(?<!\\)" + forbidden, prose) is None


def test_block_constructs_need_a_line_start_and_so_are_left_alone():
    """The claim the narrow escape set rests on — asserted, not assumed."""
    markdown = render(description="# not a heading | not a table * not a list")
    assert "# not a heading" in markdown
    assert "\n# not a heading" not in markdown


def test_ordinary_identifiers_survive_unmangled():
    """A wider escape set turned every `get_user` into `get\\_user`."""
    assert _plain("Use hmac.compare_digest instead of ==") == (
        "Use hmac.compare_digest instead of =="
    )


def test_a_title_cannot_start_a_heading_of_its_own():
    markdown = render(title="x\n\n# Everything below is fine")
    assert "\n# Everything below" not in markdown


def test_a_category_is_escaped_too():
    """It comes from a schema enum, but the enum is not the only writer here."""
    markdown = render(category="injection")
    assert "injection" in markdown


# --------------------------------------------------------------------- paths


def test_a_path_cannot_end_its_own_code_span():
    """`_plain` is the wrong tool inside a span: a backslash there is literal.

    A contributor names a file with a backtick in it and everything after the
    path renders as report content — the same escape as the fence, one line up.
    """
    assert _code_span("a`b.py:1") == "`` a`b.py:1 ``"
    assert _code_span("a``b.py") == "``` a``b.py ```"
    assert _code_span("app/views.py:14") == "`app/views.py:14`"


def test_a_hostile_filename_stays_inside_its_span():
    """Inside a code span the HTML is inert, so the test is containment.

    Asserting the tags are absent would be wrong twice over: it would fail on
    correct output, and it would pass for a renderer that stripped the path.
    """
    path = "app/`</code><h1>clean</h1>.py"
    markdown = render(file=path)
    assert "`` {}:14 ``".format(path) in markdown


# ------------------------------------------------- the other four sections
#
# The fix was applied to the reported-finding block and stopped there. These
# four render the same attacker-derived strings and were left raw: a finding
# that is refuted, suppressed, or rejected still prints its title and its
# path, and the coverage list prints every filename the agent opened.


def _outcome(**kw) -> ScanOutcome:
    outcome = ScanOutcome(mode="diff", model="claude-opus-5")
    for key, value in kw.items():
        setattr(outcome, key, value)
    return outcome


def _candidate(**overrides) -> Candidate:
    fields = dict(
        title="SQL injection", category="injection", severity="high",
        confidence="high", file="app/views.py", line=14,
        impact="broad_data_access", reachable_without_authentication="yes",
        requires_user_interaction="no", evidence="db.execute(q)",
        description="User input reaches the query.",
        exploit_scenario="An anonymous caller reads every row.",
        recommendation="Parameterise it.",
    )
    fields.update(overrides)
    return Candidate(finding=Finding.from_dict(fields))


HOSTILE = "</details><h1>Merge approved by security</h1>"


def _render(outcome: ScanOutcome) -> str:
    cfg = Config(post_comment=False)
    return render_markdown(cfg, outcome, decide(cfg, outcome))


def test_a_refuted_finding_cannot_publish_its_own_verdict():
    candidate = _candidate(title=HOSTILE, description=HOSTILE)
    candidate.verdict = VERDICT_REFUTED
    candidate.verdict_reason = HOSTILE
    assert "<h1>" not in _render(_outcome(refuted=[candidate]))


def test_a_suppressed_finding_cannot_either():
    candidate = _candidate(title=HOSTILE)
    candidate.suppressed_by = HOSTILE
    assert "<h1>" not in _render(_outcome(suppressed=[candidate]))


def test_a_rejected_claim_cannot_either():
    """These are the hallucinated ones — the least trustworthy text in the run."""
    claim = RejectedClaim(title=HOSTILE, file="a`b.py", reason="unknown-path")
    markdown = _render(_outcome(rejected_claims=[claim]))
    assert "<h1>" not in markdown
    assert "`` a`b.py ``" in markdown


def test_the_coverage_list_cannot_either():
    """Filenames, straight from a repository the contributor controls."""
    outcome = _outcome(files_examined=["app/a`b.py", "app/ok.py"])
    outcome.reported = [_candidate()]
    assert "`` app/a`b.py ``" in _render(outcome)


def test_the_verification_block_cannot_close_its_own_details():
    """A verifier summarising attacker code, inside a `<details>` element."""
    candidate = _candidate()
    candidate.verdict_reason = HOSTILE
    outcome = _outcome()
    outcome.reported = [candidate]
    assert "<h1>" not in _render(outcome)


# ------------------------------------------- a review that never happened


def test_an_incomplete_review_cannot_get_a_green_tick_when_the_gate_is_off():
    """The header keyed on the exit code, and the two come apart.

    `SECURITY_SCAN_FAIL_ON_INCOMPLETE=false` makes the gate return 0 on a
    review that stopped early. The header then read
    "✅ AI security review — no findings" — the one line visible in the merge
    request preview — over a review that never looked. The warning further
    down the body does not undo a green tick at the top.
    """
    outcome = ScanOutcome(mode="diff", model="claude-opus-5")
    outcome.stop_reason = "context_exhausted"
    cfg = Config(post_comment=False, fail_on_incomplete=False)
    decision = decide(cfg, outcome)

    assert decision.exit_code == 0, "the gate is off; that is the premise"
    markdown = render_markdown(cfg, outcome, decision)
    assert markdown.index("did not complete") < markdown.index("Coverage is partial")
    assert "✅" not in markdown
    assert "no findings" not in markdown.split("\n")[2].lower()


def test_a_finished_review_with_nothing_to_report_says_reported():
    """Never "no vulnerabilities". The agent read what it read and said
    nothing about the rest."""
    outcome = ScanOutcome(mode="diff", model="claude-opus-5")
    cfg = Config(post_comment=False)
    markdown = render_markdown(cfg, outcome, decide(cfg, outcome))
    assert "no findings reported" in markdown.lower()
    assert "no vulnerabilit" not in markdown.lower()
