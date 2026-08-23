"""The job log view.

Nobody renders Markdown in a CI log, and nobody reads a wall of it either. The
person looking at this has one question — *did it block, and why* — and the
answer has to survive being skimmed in a browser tab at 200 lines of scrollback.

So: a verdict banner first, then one block per finding with the code it is
about, then the accounting folded away where it is not in the way. The full
report is still written to disk and posted to the merge request; this is the
version you read while waiting for the pipeline.
"""

from __future__ import annotations

import os
import sys
import textwrap
from typing import List

from .gate import EXIT_ERROR, EXIT_OK, Decision
from .models import (
    VERDICT_CONFIRMED,
    VERDICT_REFUTED,
    VERDICT_UNCERTAIN,
    Candidate,
    ScanOutcome,
)

WIDTH = 78
INDENT = "   "

# Bright red for critical rather than plain red, so the two most severe levels
# are distinguishable in a job log where everything is on the same background.
_SEVERITY_COLOUR = {
    "critical": "1;91", "high": "1;31", "medium": "33", "low": "36",
}
_LABEL_WIDTH = 10


class Style:
    """Colour, when the thing reading this can show it."""

    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled

    def __call__(self, text: str, code: str) -> str:
        if not self.enabled or not code:
            return text
        return "\033[{}m{}\033[0m".format(code, text)


def colour_enabled(stream=None) -> bool:
    """GitLab renders ANSI in job logs, but a job has no TTY.

    Keying on `isatty` alone would leave the CI log — the one place this output
    exists for — permanently monochrome.
    """
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR") or os.environ.get("GITLAB_CI"):
        return True
    stream = stream or sys.stdout
    return bool(getattr(stream, "isatty", lambda: False)())


def render(outcome: ScanOutcome, decision: Decision, report_path: str = "") -> str:
    s = Style(colour_enabled())
    blocking = {id(c) for c in decision.blocking}

    lines = ["", *_banner(s, outcome, decision)]

    excluded = {id(c) for c in decision.policy_excluded}

    ordered = sorted(outcome.reported, key=lambda c: c.sort_key)
    for candidate in ordered:
        lines += _finding(s, candidate, id(candidate) in blocking,
                          id(candidate) in excluded)

    if not ordered:
        lines += ["", INDENT + s("No findings.", "32")]

    lines += _dropped(s, outcome)
    if decision.non_blocking_reasons:
        lines += ["", INDENT + s("Not gated  ", "1;2")
                  + s("; ".join(decision.non_blocking_reasons), "2")]
    lines += _footer(s, outcome, decision, report_path)
    return "\n".join(lines)


# -------------------------------------------------------------------- pieces


def _banner(s: Style, outcome: ScanOutcome, decision: Decision) -> List[str]:
    if decision.exit_code == EXIT_ERROR:
        verdict, colour = "REVIEW INCOMPLETE", "1;35"
    elif decision.blocked:
        verdict, colour = "MERGE BLOCKED", "1;31"
    elif outcome.reported:
        verdict, colour = "PASSED WITH FINDINGS", "1;33"
    else:
        verdict, colour = "PASSED", "1;32"

    counts = outcome.counts_by_severity()
    tally = " ".join(
        "{} {}".format(counts[level], level)
        for level in ("critical", "high", "medium", "low")
        if counts.get(level)
    )

    rule = "━" * WIDTH
    headline = "  {}".format(verdict)
    if tally:
        headline += "   " + tally
    return [
        s(rule, colour),
        s(headline, colour),
        s(rule, colour),
        "",
        INDENT + _wrap(decision.reason, len(INDENT)).lstrip(),
    ]


def _finding(
    s: Style, candidate: Candidate, blocks: bool, excluded_by_policy: bool = False
) -> List[str]:
    finding = candidate.finding
    colour = _SEVERITY_COLOUR.get(candidate.severity, "37")

    marker = "▲" if blocks else "•"
    heading = "{} {}  {}".format(marker, candidate.severity.upper(), finding.category)
    if blocks:
        flag = s("BLOCKS THE MERGE", "1;31")
    elif excluded_by_policy:
        # Said here, beside the finding, and not only in the footer: a `high`
        # under a green pipeline is the moment a reader decides the tool is
        # broken, and the answer has to be in front of them at that moment.
        flag = s("not gated — category excluded", "35")
    else:
        flag = s("advisory", "2")
    pad = max(1, WIDTH - len(heading) - len(_visible(flag)) - 1)

    lines = [
        "",
        " " + s(heading, colour) + " " * pad + flag,
        INDENT + s("{}:{}".format(finding.file, candidate.line), "1"),
        "",
        _wrap(finding.title, len(INDENT)),
        "",
    ]

    lines += _evidence(s, finding.evidence, colour)

    lines += _field(s, "Exploit", finding.exploit_scenario)
    lines += _field(s, "Fix", finding.recommendation)
    lines += _field(s, "Why", candidate.severity_derivation)
    lines += _field(s, "Checked", _checked(candidate))
    lines += _field(s, "Accept", "add fingerprint {} to the ignore file".format(
        candidate.fingerprint))
    return lines


MAX_EVIDENCE_LINES = 8


def _evidence(s: Style, evidence: str, colour: str) -> List[str]:
    """The quoted code, in a gutter, as close to how it sits in the file as fits.

    Tabs are expanded rather than passed through: Go and Makefiles indent with
    them, and a raw tab in a log line lands on the terminal's tab stops, not on
    the gutter, so the block stops looking like code. Long lines are cut with an
    ellipsis instead of silently — a truncation you cannot see is a quote that
    reads as complete and is not.
    """
    # Trim blank lines, not leading whitespace: `.strip()` would take the first
    # line's indentation and leave every other line's, so the common margin
    # computed below would be zero and the block would render as a staircase.
    body = [ln.rstrip() for ln in evidence.expandtabs(4).splitlines()]
    while body and not body[0].strip():
        body.pop(0)
    while body and not body[-1].strip():
        body.pop()
    if not body:
        return []

    # Re-indent relative to the shallowest line, so a method body pulled out of
    # a deeply nested file does not arrive already half-way across the screen.
    margin = min((len(ln) - len(ln.lstrip()) for ln in body if ln.strip()), default=0)
    room = WIDTH - len(INDENT) - 3

    lines = []
    for line in body[:MAX_EVIDENCE_LINES]:
        text = line[margin:] if line.strip() else ""
        if len(text) > room:
            text = text[:room - 1] + "…"
        lines.append(INDENT + " " + s("│ ", "2") + s(text, colour))
    if len(body) > MAX_EVIDENCE_LINES:
        lines.append(INDENT + " " + s("│ ", "2")
                     + s("… {} more line(s)".format(len(body) - MAX_EVIDENCE_LINES), "2"))
    return [*lines, ""]


def _checked(candidate: Candidate) -> str:
    """One line summarising everything that was done to disbelieve this."""
    bits = []
    if candidate.votes:
        agreeing = sum(1 for v in candidate.votes if v.verdict == candidate.verdict)
        word = {
            VERDICT_CONFIRMED: "confirmed", VERDICT_UNCERTAIN: "left uncertain",
            VERDICT_REFUTED: "refuted",
        }.get(candidate.verdict, candidate.verdict)
        bits.append("{} by {} of {} independent verifier{}".format(
            word, agreeing, len(candidate.votes),
            "" if len(candidate.votes) == 1 else "s"))
    else:
        bits.append("cited code found in the file; not verified")
    if candidate.removes_control:
        bits.append("removes an existing control")
    if candidate.attributed_by == "deleted":
        bits.append("introduced by a deletion in this change")
    elif not candidate.in_changed_lines:
        bits.append("pre-existing, not introduced here")
    bits.append("confidence {}".format(candidate.confidence))
    return " · ".join(bits)


def _field(s: Style, label: str, text: str) -> List[str]:
    text = (text or "").strip()
    if not text:
        return []
    body = _wrap(text, len(INDENT) + _LABEL_WIDTH)
    return [INDENT + s(label.ljust(_LABEL_WIDTH), "1;2")
            + body[len(INDENT) + _LABEL_WIDTH:]]


def _dropped(s: Style, outcome: ScanOutcome) -> List[str]:
    """What was thrown away, in one line each — the part that builds trust."""
    bits = []
    if outcome.refuted:
        bits.append("{} refuted by verification".format(len(outcome.refuted)))
    if outcome.suppressed:
        bits.append("{} suppressed".format(len(outcome.suppressed)))
    if outcome.rejected_claims:
        bits.append("{} rejected — quoted code not in the file".format(
            len(outcome.rejected_claims)))
    if outcome.duplicates_dropped:
        bits.append("{} duplicate".format(outcome.duplicates_dropped))
    if not bits:
        return []
    return ["", INDENT + s("Dropped   ", "1;2") + s(" · ".join(bits), "2")]


def _footer(
    s: Style, outcome: ScanOutcome, decision: Decision, report_path: str
) -> List[str]:
    m = outcome.metrics
    rejected = (m.citations_rejected_not_found + m.citations_rejected_ambiguous
                + m.citations_rejected_too_short + m.citations_rejected_unknown_path)
    lines = ["", s("─" * WIDTH, "2")]

    rows = [
        ("Reviewed", "{} file{} · {} tool call{} · {} turn{}".format(
            len(outcome.files_examined),
            "" if len(outcome.files_examined) == 1 else "s",
            len(outcome.tool_calls), "" if len(outcome.tool_calls) == 1 else "s",
            outcome.turns, "" if outcome.turns == 1 else "s")),
        ("Citations", "{} accepted, {} rejected".format(m.citations_accepted, rejected)),
        ("Verified", "{} of {} finding{}, {} verdict{} changed".format(
            m.verified, m.verified + m.verification_skipped,
            "" if m.verified + m.verification_skipped == 1 else "s",
            m.verdicts_changed, "" if m.verdicts_changed == 1 else "s")),
        ("Model", outcome.model + (
            s("  — SUBSTITUTED SERVER-SIDE", "1;35")
            if outcome.provenance.model_substituted else "")),
    ]
    if not outcome.coverage.complete and outcome.coverage.changed:
        rows.insert(1, ("Coverage", s("incomplete — {} changed file(s) never opened".format(
            len(outcome.coverage.unopened)), "33")))
    if report_path:
        rows.append(("Report", report_path))

    for label, value in rows:
        lines.append(" " + s(label.ljust(_LABEL_WIDTH), "2") + value)
    lines.append(s("─" * WIDTH, "2"))

    code = decision.exit_code
    word = {EXIT_OK: "exit 0 — nothing blocking",
            EXIT_ERROR: "exit 2 — the review did not complete"}.get(
                code, "exit 1 — blocking findings")
    lines += [" " + s(word, "1" if code == EXIT_OK else "1;31"), ""]
    return lines


# ------------------------------------------------------------------- helpers


def _wrap(text: str, indent: int) -> str:
    pad = " " * indent
    return textwrap.fill(
        " ".join((text or "").split()),
        width=WIDTH, initial_indent=pad, subsequent_indent=pad) or pad


def _visible(text: str) -> str:
    """Length of a styled string as it appears, ignoring escape sequences."""
    out, i = [], 0
    while i < len(text):
        if text[i] == "\033":
            i = text.find("m", i) + 1 or len(text)
            continue
        out.append(text[i])
        i += 1
    return "".join(out)


def section(name: str, title: str, start: bool, when: int) -> str:
    """A GitLab collapsible section marker, so the trace folds away by default.

    GitLab reads these out of the log stream itself; anywhere else they are
    invisible control characters on their own line, which is why they are safe
    to emit unconditionally.
    """
    verb = "section_start" if start else "section_end"
    collapse = "[collapsed=true]" if start else ""
    return "\033[0K{}:{}:{}{}\r\033[0K{}".format(
        verb, when, name, collapse, title if start else "")
