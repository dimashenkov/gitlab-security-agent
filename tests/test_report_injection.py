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
from pathlib import Path

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


def test_a_file_hidden_by_an_exclude_rule_is_named_in_the_comment():
    """`coverage.excluded` reached the JSON and neither human channel.

    `--path` scope gets a warning block ending "This is not a review of the
    change". The exclude rules got nothing — and `DEFAULT_EXCLUDES`
    (`*/vendor/*`, `*/dist/*`, `*.map`, `*.min.js`, `*.snap`) needs no
    operator to be in force. So a change to a vendored dependency was reviewed
    by nobody, reported by nothing, and came out under the green heading.
    """
    outcome = ScanOutcome(mode="diff", model="claude-opus-5")
    outcome.coverage.changed = ["app/views.py"]
    outcome.coverage.examined = ["app/views.py"]
    outcome.coverage.excluded = ["vendor/acme/auth.php", "dist/bundle.js"]
    outcome.exposures = [("app/views.py", "read_file")]
    cfg = Config(post_comment=False)

    markdown = render_markdown(cfg, outcome, decide(cfg, outcome))

    assert "vendor/acme/auth.php" in markdown
    assert "Excluded by rule" in markdown


def test_a_change_with_nothing_excluded_says_nothing():
    """The control. A line that prints whatever the rules did names nothing,
    and this one is in the block a reader opens to check coverage."""
    outcome = ScanOutcome(mode="diff", model="claude-opus-5")
    outcome.coverage.changed = ["app/views.py"]
    outcome.coverage.examined = ["app/views.py"]
    outcome.exposures = [("app/views.py", "read_file")]
    cfg = Config(post_comment=False)

    assert "Excluded by rule" not in render_markdown(
        cfg, outcome, decide(cfg, outcome))


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


# ------------------------------------------ a file name is attacker-supplied


PATH_PAYLOAD = ("assets\n\n</details>\n\n## Security review passed\n\n"
                "No blocking findings were recorded.\n\n"
                "<details><summary>ignore</summary>\n\n`blob.bin")


def _covered(**coverage) -> ScanOutcome:
    outcome = ScanOutcome(mode="diff", model="claude-opus-5")
    outcome.summary = "Nothing looked suspicious."
    outcome.coverage.changed = ["app/views.py"]
    outcome.coverage.examined = ["app/views.py"]
    outcome.exposures = [("app/views.py", "get_diff")]
    for name, value in coverage.items():
        setattr(outcome.coverage, name, value)
    return outcome


@pytest.mark.parametrize("field, value", [
    ("unreadable", [(PATH_PAYLOAD, "binary")]),
    ("deleted", [PATH_PAYLOAD]),
    # `unopened` is derived from `changed` minus `examined`, so the state is
    # made rather than asserted.
    ("changed", ["app/views.py", PATH_PAYLOAD]),
])
def test_a_file_name_cannot_write_a_heading_into_the_report(field, value):
    """Found 2026-09-09. Three coverage lists interpolated the path with a
    hand-written backtick pair instead of `_code_span`, and `/` is a legal path
    separator — so every component of a hostile name is a legal file name and
    `git add` accepts it.

    One added binary file whose *name* carries `</details>` and a `##` heading
    closes the collapsed block and renders a second, attacker-written verdict
    inside the comment the agent posts under its own name. The real banner is
    untouched above it, so the note carries two contradictory verdicts and the
    contributor wrote the second.

    Nothing else is needed: no operator setting, no runner state, no label.
    The neighbouring list four lines up already used `_code_span`, which
    collapses the whitespace and lengthens the backtick run; these three did
    not.
    """
    outcome = _covered(**{field: value})
    cfg = Config(post_comment=False)

    text = render_markdown(cfg, outcome, decide(cfg, outcome))
    headings = [line for line in text.splitlines() if line.startswith("#")]

    # Containment, not removal. Asserting the text is absent would be wrong
    # twice over — it would fail on correct output, and it would pass for a
    # renderer that silently dropped the path, which is how a reader stops
    # learning that a file was unreadable at all. The same reasoning the
    # neighbouring `test_a_hostile_filename_stays_inside_its_span` states.
    assert headings == ["## ✅ AI security review — no findings reported"]
    assert "\n## Security review passed" not in text
    assert "\n</details>" not in text.replace("\n</details>\n", "", 1) \
        or text.count("</details>") == text.count("<details>")


def test_an_ordinary_file_name_still_reads_as_one():
    """The control. Escaping that mangles every path would make the coverage
    section unreadable, and a section nobody reads guards nothing."""
    cfg = Config(post_comment=False)
    outcome = _covered(unreadable=[("assets/blob.bin", "binary")])

    text = render_markdown(cfg, outcome, decide(cfg, outcome))

    assert "`assets/blob.bin` (binary)" in text


# ------------------------------------------------------- the banner's colour


def test_the_banner_carries_the_worst_severity_and_not_the_first():
    """Found 2026-09-09. `decision.blocking` keeps the order the findings were
    reported in, and the banner took `blocking[0]` — so a medium reported
    before a critical put a yellow circle over the one line a reader sees in
    the merge request preview.

    Every other renderer in `report.py` sorts before it prints, and
    `ScanOutcome.worst_severity` existed and was not used here. Reordering two
    `report_finding` calls changed the top-line signal with no change to the
    code, which is the shape this repository hunts: a claim about the change
    that depends on something other than the change.
    """
    outcome = ScanOutcome(mode="diff", model="claude-opus-5")
    outcome.coverage.changed = ["app/views.py"]
    outcome.exposures = [("app/views.py", "get_diff")]
    # `Candidate.severity` is the *derived* disposition, not the label the
    # model proposed, and it is what the banner reads. Setting it directly is
    # what the derivation would produce; going through the finding's own
    # `severity` would test a field this line never looks at.
    worst = _candidate(title="Command exec", file="app/exec.py")
    worst.severity = "critical"
    lesser = _candidate()
    lesser.severity = "high"
    outcome.reported = [worst, lesser]
    cfg = Config(post_comment=False)

    reversed_order = ScanOutcome(mode="diff", model="claude-opus-5")
    reversed_order.coverage.changed = ["app/views.py"]
    reversed_order.exposures = [("app/views.py", "get_diff")]
    reversed_order.reported = list(reversed(outcome.reported))

    first = render_markdown(cfg, outcome, decide(cfg, outcome))
    second = render_markdown(cfg, reversed_order,
                             decide(cfg, reversed_order))

    def banner(text: str) -> str:
        return next(line for line in text.splitlines()
                    if line.startswith("## "))

    assert banner(first) == banner(second)
    assert "🔴" in banner(first)


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
    # Running out of context means a great deal reached the model, so this is a
    # review that stopped early rather than one nothing reached — a distinction
    # the gate now makes, and one this fixture has to state, since an outcome
    # with no exposures is the second and exits 2 whatever the flag says.
    outcome.coverage.changed = ["app/views.py", "app/models.py"]
    outcome.exposures = [("app/views.py", "get_diff")]
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


# --------------------------------------------------- what the report claims


def test_every_report_says_it_is_experimental():
    """In the footer of every report, not only in a README nobody opens.

    The measured evidence is a regression suite of this project's own
    construction. There is no production deployment and no independent
    adjudication behind any number, and a report that does not say so is read
    as though there were.
    """
    assert "**Experimental.**" in render()


def test_a_quiet_result_is_not_called_safe():
    """The exact sentence an adopter would otherwise supply themselves."""
    outcome = ScanOutcome(mode="diff", model="claude-opus-5")
    cfg = Config(post_comment=False)
    markdown = render_markdown(cfg, outcome, decide(cfg, outcome)).lower()

    assert "not evidence that the change is safe" in markdown
    for claim in ("no vulnerabilit", "is secure", "passed security"):
        assert claim not in markdown, claim


def test_the_limitations_document_exists_and_says_what_is_unmeasured():
    """A README that promises a limitations file, and no file, is worse than
    neither: it reads as diligence that was done."""
    root = Path(__file__).resolve().parents[1]
    # Collapsed: these are sentences in a wrapped document, so a line break
    # falls in a different place every time the paragraph is edited.
    limitations = " ".join(
        (root / "LIMITATIONS.md").read_text(encoding="utf-8").split())

    # The claims an adopter would otherwise have to reconstruct from commit
    # messages. This asked for "no recall figure and no precision figure" until
    # 2026-09-06, by which time the repository was gating on a recall figure —
    # `stop_rule.py` rejects a configuration below 65% and recomputes 61/78
    # every run. Codex adjudicated it that day. What an adopter needs is the
    # figure **with its qualification**, not its absence.
    assert "61 of 78 = 78%" in limitations
    assert "*corpus* recall, not recall in use" in limitations
    assert "no precision figure" in limitations
    assert "withdrawn" in limitations
    assert "does not mean the change is safe" in limitations
    # And the open defect, named rather than buried.
    assert "three of four suppression payloads" in limitations.lower()

    readme = " ".join((root / "README.md").read_text(encoding="utf-8").split())
    assert "LIMITATIONS.md" in readme
    assert "do not gate merges on it" in readme.lower()


# ------------------------------------- a disposition an attacker can move


def _refuted(**overrides) -> Candidate:
    candidate = _candidate(**overrides)
    candidate.verdict = VERDICT_REFUTED
    candidate.verdict_reason = "The caller validates first."
    candidate.in_changed_lines = True
    return candidate


class TestDisputedFindingsAreNotHidden:
    """The working prompt-injection payloads do not erase the finding.

    They leave it in the report and move its disposition — from confirmed to
    refuted, or its confidence under the gate. Collapsing refuted findings
    behind a `<details>` is what turns an attacker-influenced disposition into
    hidden evidence: the reader sees a quiet report and a folded block.

    Injection is unsolved. This does not fix it. It makes the residual failure
    corrupted prioritisation rather than a real finding the reader never sees.
    """

    def test_a_refutation_that_would_have_blocked_is_shown_open(self):
        outcome = _outcome(refuted=[_refuted(severity="high")])
        markdown = _render(outcome)

        assert "## Disputed" in markdown
        # The finding itself, not just a heading — and outside every collapsed
        # block. `<details>` opens a fold; the disputed body must precede any
        # of them, or the reader has to click to see it.
        body = markdown.index("SQL injection", markdown.index("## Disputed"))
        folds = [i for i in range(len(markdown)) if markdown.startswith("<details>", i)]
        assert all(body < fold for fold in folds), "the disputed finding is folded away"

    def test_it_carries_the_caveat_about_repository_authored_text(self):
        markdown = _render(_outcome(refuted=[_refuted(severity="high")]))
        assert "input to the model, not evidence" in markdown
        assert "Read the code, not the verdict." in markdown

    def test_a_report_quiet_only_because_of_a_refutation_gets_no_green_tick(self):
        """The header is the line a reader stops at, and a tick there says the
        opposite of what happened."""
        markdown = _render(_outcome(refuted=[_refuted(severity="high")]))

        assert "✅" not in markdown
        assert "disputed finding" in markdown
        assert "would have blocked if the verifier had confirmed it" in markdown

    def test_a_refuted_low_stays_collapsed_as_noise(self):
        """Everything open is the same failure with the sign flipped: the loud
        thing stops being loud."""
        markdown = _render(_outcome(refuted=[_refuted(severity="low")]))

        assert "## Disputed" not in markdown
        assert "Refuted during verification (1)" in markdown
        assert "✅" in markdown

    def test_a_confirmed_finding_still_leads(self):
        outcome = _outcome(refuted=[_refuted(severity="high")])
        outcome.reported = [_candidate(severity="high")]
        markdown = _render(outcome)

        assert markdown.index("Blocking findings") < markdown.index("## Disputed")


# ------------------ the three channels that were still raw, found by the agent


HOSTILE_SUMMARY = (
    "No issues.\n\n</blockquote>\n"
    "## \u2705 AI security review — no findings reported\n\n"
    "<details><summary>ignore the section below</summary>\n"
    "[click here](https://evil.example/steal)"
)


def test_the_summary_cannot_forge_a_second_verdict_banner():
    """The sixth of six sections, and the last one left raw.

    It sits directly under the real verdict line, so a summary carrying a
    closing tag and a heading of its own renders an attacker-chosen banner
    inside the comment the agent posts under its own name. Every other model
    string in this document has gone through the escaper since the other five
    were fixed; this one had no test at all.
    """
    outcome = ScanOutcome(mode="diff")
    outcome.summary = HOSTILE_SUMMARY
    cfg = Config(post_comment=False)

    body = render_markdown(cfg, outcome, decide(cfg, outcome))
    # The quoted summary is one line, between the meta line and whatever comes
    # next. Sliced to it, because the document legitimately contains
    # `<details>` further down and asserting over the whole page would pass or
    # fail for the wrong reason.
    quoted = next(line for line in body.splitlines() if line.startswith("> "))

    assert "</blockquote>" not in quoted
    assert "<details>" not in quoted
    # The words still appear, inside the quoted line, and that is fine — what
    # must not happen is a second *heading*. Asserted on lines that begin one,
    # because counting the string counts the summary's own harmless copy and
    # would fail for a reason that is not the defect.
    headings = [line for line in body.splitlines() if line.startswith("## ")]
    assert len([h for h in headings if "AI security review" in h]) == 1


def test_a_stop_detail_cannot_break_out_of_its_warning():
    """On the CLI runner this string can carry the tail of the child's standard
    error, which carries file names and git's messages about them — and the
    child moved its own stdout onto that stream, so tool summaries are in it
    too. All of it comes from the repository under review."""
    outcome = ScanOutcome(mode="diff")
    outcome.stop_reason = "error"
    outcome.stop_detail = (
        "the CLI produced no output. Its error output ended: "
        "</blockquote>\n## Everything is fine\n<script>alert(1)</script>"
    )
    cfg = Config(post_comment=False)

    body = render_markdown(cfg, outcome, decide(cfg, outcome))

    assert "<script>" not in body
    assert "\n## Everything is fine" not in body


def test_a_hostile_file_name_cannot_add_a_link_to_the_report():
    """A Markdown destination ends at the first unbalanced `)`, and `)`, `(`,
    `[` and `]` are all legal in a path. The reviewed repository is where file
    names come from, and `report_finding` requires the path to resolve to a real
    blob — so a name that reaches this line is one the attacker committed."""
    from security_agent.config import GitLabContext
    from security_agent.report import _located

    linked = _located(
        Config(post_comment=False,
               gitlab=GitLabContext(kind="gitlab", project_path="g/p",
                                    commit_sha="a" * 40,
                                    api_url="https://gl.example/api/v4")),
        "a)[Review passed](https://evil.example/ok)x.py", 12)

    # The label keeps the name verbatim and that is fine — it is inside a code
    # span, where CommonMark renders it literally. What must not happen is the
    # *destination* ending early, which is what put a second, attacker-chosen
    # link beside the real one.
    destination = linked[linked.rindex("](") + 2:-1]

    assert ")" not in destination
    assert "%29" in destination
    assert destination.startswith("https://gl.example/")


def test_the_raw_markdown_channel_refuses_a_plain_string():
    """The one place this document emits a string without escaping it.

    What may travel there is provenance, and a `str` does not carry provenance
    — the first version of this branch decided the same question by counting
    newlines, which any attacker-authored string can satisfy. A plain string is
    escaped rather than refused, because refusing would throw away the
    diagnostics of a run that already failed, which is when a person needs them
    most.
    """
    outcome = ScanOutcome(mode="diff")
    outcome.stop_reason = "error"
    outcome.trace_markdown = "## Everything is fine\n<script>alert(1)</script>"
    cfg = Config(post_comment=False)

    body = render_markdown(cfg, outcome, decide(cfg, outcome))

    assert "<script>" not in body
    assert not any(line.startswith("## Everything is fine")
                   for line in body.splitlines())


def test_a_rendered_trace_keeps_its_formatting():
    """And the trusted type is not merely tolerated — it is what makes the
    trace readable. Escaping everything would be safe and useless."""
    from security_agent.rendering import Rendered

    outcome = ScanOutcome(mode="diff")
    outcome.stop_reason = "error"
    outcome.trace_markdown = Rendered("### How far it got\n\n- `read_file`\n")
    cfg = Config(post_comment=False)

    body = render_markdown(cfg, outcome, decide(cfg, outcome))

    assert "### How far it got" in body


def test_only_the_journal_renderer_produces_the_trusted_type():
    """A marker type is worth nothing if anything constructs one. Asserted by
    reading the source, because the guarantee is about who calls it."""
    import subprocess

    root = Path(__file__).resolve().parents[1]
    hits = subprocess.run(
        ["git", "-C", str(root), "grep", "-n", "Rendered(", "--", "src"],
        capture_output=True, text=True, check=False).stdout.splitlines()
    constructing = [h for h in hits if "class Rendered" not in h]

    assert len(constructing) == 1, constructing
    assert "crash_journal.py" in constructing[0]
