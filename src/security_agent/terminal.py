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

from . import PROJECT_NAME, PROJECT_URL, __version__
from .gate import EXIT_ERROR, EXIT_OK, Decision
from .models import (
    REVIEW_PERFORMED,
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
        # Green only when the review actually finished. An incomplete run has
        # an empty finding list because it stopped, not because it looked and
        # found nothing, and colouring that green says the opposite.
        #
        # **`decision.partial`, not `outcome.complete`.** The second is only
        # the stop reason; the gate counts three things, and the other two — a
        # truncated diff and refused context — leave `complete` true. With
        # `SECURITY_SCAN_FAIL_ON_INCOMPLETE=false` such a run therefore printed
        # green "No findings reported." over a change the reviewer was shown
        # half of. The markdown renderer was repaired for exactly this and the
        # terminal was left behind; Codex found it on the gate for that repair.
        #
        # `exit_code` is in the condition as well, and not as belt and braces:
        # `partial` is one adjudicated fact and every decision that reaches
        # here in production carries it, but a decision that did not get to an
        # answer at all must never print this line, whatever else it holds.
        # Exit 2 means "I could not check", and that is the one thing this
        # renderer may not render as "nothing to report".
        # **And a review that was never performed does not get the green
        # sentence either.** `report._header` was repaired for exactly this on
        # 2026-09-09 and this renderer was left behind — which the comment
        # above records happening to it once before. A skipped run and a real
        # clean review printed the same green line, colour code and all; only
        # the banner word differed, which is a difference a reader skims past.
        #
        # `review_status` is asked rather than inferred: `partial` is false for
        # both non-performed dispositions by design, because a label waiver
        # that blocked the merge would be an escape hatch nobody can use.
        if outcome.review_status != REVIEW_PERFORMED:
            lines += ["", INDENT + s(
                "No review was performed — this is not a statement about the "
                "code.", "33")]
        elif not decision.partial and decision.exit_code != EXIT_ERROR:
            lines += ["", INDENT + s("No findings reported.", "32")]
        else:
            lines += ["", INDENT + s("No findings — the review did not complete.", "33")]

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
    elif decision.partial:
        # A partial review the operator chose to forgive. The exit code is 0
        # and that is correct — `SECURITY_SCAN_FAIL_ON_INCOMPLETE=false` is a
        # documented decision — but the loudest line on the screen said green
        # PASSED over a change the reviewer was shown part of. Amber, and the
        # word says what happened rather than what was permitted.
        #
        # Above the findings branch, not below it: "PASSED WITH FINDINGS" makes
        # the same claim over the same half-read change, and the tally is
        # printed beside the verdict either way, so nothing is lost by saying
        # the truer thing first.
        verdict, colour = "INCOMPLETE, FORGIVEN", "1;33"
    elif outcome.reported:
        verdict, colour = "PASSED WITH FINDINGS", "1;33"
    elif not outcome.exposures:
        # Nothing reached the reviewer, so there is nothing to have passed.
        # The skip label, an all-excluded change, an empty range and a scope
        # that matched no file all end here: complete, nothing reported, exit
        # 0 — and the loudest line on the screen used to be a green PASSED
        # over code no one had read. The exit code is right, because the tool
        # did what it was told; the word was not. Grey, because this is
        # neither good news nor bad, and the reason is one line below.
        verdict, colour = "NOT REVIEWED", "1;37"
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
    # `category` and `severity` are model strings and are not validated
    # anywhere on this path, so they reach the log exactly as written.
    heading = "{} {}  {}".format(
        marker, _visible(candidate.severity).upper(), _visible(finding.category))
    if blocks:
        flag = s("BLOCKS THE MERGE", "1;31")
    elif excluded_by_policy:
        # Said here, beside the finding, and not only in the footer: a `high`
        # under a green pipeline is the moment a reader decides the tool is
        # broken, and the answer has to be in front of them at that moment.
        flag = s("not gated — category excluded", "35")
    else:
        flag = s("advisory", "2")
    # Cells, not code points. A CJK title or an emoji in a finding counts one
    # per character with `len()` and draws two, so every border after it landed
    # a cell short — and the title is attacker-authored.
    pad = max(1, WIDTH - _width(heading) - _width(flag) - 1)

    lines = [
        "",
        " " + s(heading, colour) + " " * pad + flag,
        INDENT + s("{}:{}".format(_visible(finding.file), candidate.line), "1"),
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
    # Escapes out first, and per line so a stripped sequence cannot merge two.
    # The quoted code is copied from a file the contributor wrote; `\033[2J`
    # in it clears the screen of anyone tailing the job log, taking the verdict
    # banner with it.
    body = [_visible(ln).rstrip()
            for ln in evidence.expandtabs(4).splitlines()]
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
        # **A seat that never answered is not a seat that agreed.** Every
        # failed verification call records `verdict=uncertain` with an `error`
        # — `verify.py` does it in two places — so when the panel lands on
        # `uncertain` a dead seat entered the numerator and the line read
        # "left uncertain by 2 of 3 independent verifiers", which is what it
        # also reads when all three really answered. Found 2026-09-09.
        #
        # The failures are named rather than dropped: a panel that lost a seat
        # is a weaker panel, and subtracting it silently would make three
        # verifiers of which one died read as a two-seat panel that worked.
        failed = [v for v in candidate.votes if getattr(v, "error", "")]
        answering = [v for v in candidate.votes if not getattr(v, "error", "")]
        agreeing = sum(1 for v in answering if v.verdict == candidate.verdict)
        word = {
            VERDICT_CONFIRMED: "confirmed", VERDICT_UNCERTAIN: "left uncertain",
            VERDICT_REFUTED: "refuted",
        }.get(candidate.verdict, candidate.verdict)
        # **The denominator is the seats the panel reserved.** Publishing only
        # the seats that answered was the first repair and Codex refused it the
        # same day: `2/2` says a complete two-person panel agreed, where the
        # truth is two of three seats with the quorum degraded. `panel.py`
        # defines the panel as the reserved seats, and a renderer that quietly
        # redefines it is the second definition this repository keeps finding.
        bits.append("{} by {} of {} independent verifier{}".format(
            word, agreeing, len(candidate.votes),
            "" if len(candidate.votes) == 1 else "s"))
        if failed:
            bits.append("{} verifier call{} failed".format(
                len(failed), "" if len(failed) == 1 else "s"))
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


def _verification(m) -> str:
    """What the verification stage did, without folding it into one ratio.

    The row used to read `verified of verified + skipped`, which is a
    denominator built from the numerator: it could not print anything but "N of
    N". Both populations it could not see were the ones a reader needs — three
    criticals dropped past SECURITY_SCAN_VERIFY_MAX printed "0 of 0", and four
    panels whose every call failed printed "4 of 4" while the report beside it
    said "4 could not run". Adjudicated 2026-09-07.

    So each disposition gets its own word, and the ones that are zero are left
    out: this line is read by someone skimming a job log, and "0 over the
    limit" on every clean run trains the eye to skip the whole row.
    """
    presented = m.verification_presented
    bits = ["{} of {} finding{} completed".format(
        m.verification_completed, presented, "" if presented == 1 else "s")]
    if m.verification_skipped:
        bits.append("{} non-blocking skip{}".format(
            m.verification_skipped, "" if m.verification_skipped == 1 else "s"))
    if m.verification_over_limit:
        bits.append("{} over the limit".format(m.verification_over_limit))
    if m.verification_disabled:
        # Named as the setting it is. "Skipped" would put it beside the
        # per-finding judgement above and read as the same kind of thing.
        bits.append("{} with verification off".format(m.verification_disabled))
    if m.verification_unavailable:
        # Named "unavailable" and not "failed": the finding is still in the
        # report and still gates, and what is missing is the verdict about it.
        bits.append("{} unavailable".format(m.verification_unavailable))
    if m.verification_degraded:
        bits.append("{} short a vote".format(m.verification_degraded))
    bits.append("{} verdict{} changed".format(
        m.verdicts_changed, "" if m.verdicts_changed == 1 else "s"))
    return " · ".join(bits)


def _footer(
    s: Style, outcome: ScanOutcome, decision: Decision, report_path: str
) -> List[str]:
    m = outcome.metrics
    # Every rejection reason, and the sum is the place that goes wrong: a
    # reason added to the metrics and left out of this line is a claim the
    # report says nothing about, which is what the counter existed to stop.
    rejected = (m.citations_rejected_not_found + m.citations_rejected_ambiguous
                + m.citations_rejected_too_short + m.citations_rejected_unknown_path
                + m.citations_rejected_too_large)
    lines = ["", s("─" * WIDTH, "2")]

    rows = [
        ("Reviewed", "{} file{} · {} tool call{} · {} turn{}".format(
            len(outcome.files_examined),
            "" if len(outcome.files_examined) == 1 else "s",
            len(outcome.tool_calls), "" if len(outcome.tool_calls) == 1 else "s",
            outcome.turns, "" if outcome.turns == 1 else "s")),
        ("Citations", "{} accepted, {} rejected".format(m.citations_accepted, rejected)),
        ("Verified", _verification(m)),
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
    # **Beside the verdict, because it does not change it.** An open question
    # the reviewer recorded exits 0 exactly like a settled review, and that was
    # adjudicated as the right decision — but a reader who sees only "nothing
    # blocking" mistakes an honest "I could not tell about the authentication"
    # for a clean result. The count travels with the code, on the one line
    # everybody reads. Codex, 2026-09-07.
    open_questions = len(outcome.unresolved)
    if open_questions:
        word += ", with {} unresolved question{}".format(
            open_questions, "" if open_questions == 1 else "s")
    lines += [
        " " + s(word, "1" if code == EXIT_OK else "1;31"),
        "",
        " " + s("{} v{} — by Dimitar Shenkov, MIT licensed".format(
            PROJECT_NAME, __version__), "2"),
        " " + s(PROJECT_URL, "2"),
        "",
    ]
    return lines


# ------------------------------------------------------------------- helpers


def _wrap(text: str, indent: int) -> str:
    pad = " " * indent
    return textwrap.fill(
        " ".join(_visible(text or "").split()),
        width=WIDTH, initial_indent=pad, subsequent_indent=pad) or pad


def _visible(text: str) -> str:
    """A styled string with its escape sequences removed.

    Also strips escapes the agent never emits but a *finding* might: titles and
    quoted code are attacker-authored, and a raw `\\033]8;;http://…\\007` in one
    of them would be written straight to a CI log where the terminal acts on
    it. The Markdown report has been escaping hostile content since the fence
    bug; the terminal renderer had not.
    """
    out, i = [], 0
    while i < len(text):
        if text[i] == "\033":
            # CSI (`\033[…m`) and OSC (`\033]…` up to BEL or ST) both start
            # here. Consume to the terminator, or to the end if there is none.
            nxt = text[i + 1] if i + 1 < len(text) else ""
            if nxt == "]":
                # OSC runs to BEL or to ST (`ESC \`). Both terminators are
                # optional in hostile input, so an absent one ends the string.
                # `find` returning -1 must not be arithmetic'd into a small
                # positive index: that walks `i` backwards and loops forever,
                # which is how this first behaved.
                bell = text.find("\007", i)
                st = text.find("\033\\", i)
                ends = [bell + 1 for _ in (1,) if bell != -1]
                ends += [st + 2 for _ in (1,) if st != -1]
                end = min(ends) if ends else len(text)
            elif nxt == "[":
                # CSI: `ESC [`, parameter bytes 0x30-0x3F, intermediate bytes
                # 0x20-0x2F, then any final byte 0x40-0x7E. Looking only for
                # `m` was enough for the colours this file emits and wrong for
                # everything else: `ESC [ 2 J` clears the screen and ends in
                # `J`, so the search ran off the end and swallowed the text
                # after it. Stripping the payload as well as the escape hides
                # the attack instead of defusing it.
                end = i + 2
                while end < len(text) and 0x30 <= ord(text[end]) <= 0x3F:
                    end += 1
                while end < len(text) and 0x20 <= ord(text[end]) <= 0x2F:
                    end += 1
                if end < len(text) and 0x40 <= ord(text[end]) <= 0x7E:
                    end += 1
            else:
                # A two-character escape: `ESC c` resets the terminal, `ESC 7`
                # saves the cursor. Drop both bytes and no more.
                end = i + 2
            # Never stand still, whatever the input claims.
            i = max(end, i + 1)
            continue
        if text[i] in "\r\b\007":
            # A carriage return can rewrite a line that has already been
            # printed, which is how a finding's title overwrites the verdict.
            i += 1
            continue
        out.append(text[i])
        i += 1
    return "".join(out)


# Ranges that occupy two terminal cells. Not a full Unicode width table — the
# East Asian blocks and the emoji planes are what actually appear in a title or
# a line of quoted code, and counting code points made every one of them push
# the box border a cell to the right.
_WIDE = (
    (0x1100, 0x115F), (0x2E80, 0x303E), (0x3041, 0x33FF),
    (0x3400, 0x4DBF), (0x4E00, 0x9FFF), (0xA000, 0xA4CF),
    (0xAC00, 0xD7A3), (0xF900, 0xFAFF), (0xFE30, 0xFE6F),
    (0xFF00, 0xFF60), (0xFFE0, 0xFFE6),
    (0x1F300, 0x1F64F), (0x1F900, 0x1F9FF), (0x20000, 0x3FFFD),
)


def _width(text: str) -> int:
    """How many cells a string occupies once its escapes are gone.

    `len()` counts code points, so a CJK title or an emoji severity marker
    reported one cell where the terminal drew two, and every box border after
    it landed short.
    """
    total = 0
    for char in _visible(text):
        point = ord(char)
        if 0x0300 <= point <= 0x036F:        # combining marks occupy nothing
            continue
        total += 2 if any(lo <= point <= hi for lo, hi in _WIDE) else 1
    return total


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
