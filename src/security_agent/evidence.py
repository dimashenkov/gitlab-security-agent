"""Layer 1 of the hallucination check: does the cited code actually exist?

Every finding must quote the vulnerable code verbatim. Before a finding is
accepted, that quote is matched against the real file on disk. This is a cheap,
deterministic assertion about reality, and it catches the failure mode a
language model is most prone to in a review: describing code that is plausible
for the file but is not in it.

Matching is tolerant of whitespace and of diff markers copied along with the
quote, and nothing else. Tolerating more — fuzzy or partial matching across
lines — would let a paraphrase through, which is exactly what this is here to
stop.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Set, Tuple

HUNK_HEADER = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")


def normalize(line: str) -> str:
    """Collapse all whitespace so indentation and tab/space choices don't matter."""
    return " ".join(line.split())


def _evidence_lines(evidence: str) -> List[str]:
    return [normalize(line) for line in evidence.splitlines() if normalize(line)]


def _strip_diff_markers(lines: Sequence[str]) -> List[str]:
    """Drop a single leading +/- that came from copying out of a diff.

    Only applied as a second pass: a leading '-' is meaningful in YAML lists and
    a leading '+' is valid in plenty of languages, so stripping unconditionally
    would make the match looser than intended.
    """
    stripped = []
    for line in lines:
        if line[:1] in ("+", "-"):
            stripped.append(normalize(line[1:]))
        else:
            stripped.append(line)
    return [line for line in stripped if line]


# A quote has to carry enough information to identify one place in a file.
# `return value` occurs in most files several times; matching it proves nothing
# and silently attaches the finding to the first occurrence, taking the location
# and the change attribution with it.
MIN_EVIDENCE_CHARS = 24
# And a maximum, because there was not one. Far more than a quotation
# needs — the report renders eight lines — and small enough that the
# window walk below stays bounded whatever the model sends.
MAX_EVIDENCE_LINES = 200
MAX_EVIDENCE_CHARS = 16_000


class EvidenceProblem(Exception):
    """The quote cannot be tied to one place in the file.

    Carries a message written for the agent, because the agent is what has to
    act on it — by quoting more, or by dropping the finding.
    """


def locate_evidence(file_text: str, evidence: str, claimed_line: int = 0) -> int:
    """Find where the quoted code sits in the file, or refuse to guess.

    Returns a 1-based line number. Raises `EvidenceProblem` when the quote is
    absent, too thin to identify anything, or matches several places without the
    claimed line settling which.

    Taking the first match used to be the behaviour, and it made this layer
    weaker than its own docstring claimed: it proved similar text occurred
    *somewhere*, not that the quoted operation was at the cited site. Ambiguity
    is now an answer, not something resolved by position.
    """
    wanted = _evidence_lines(evidence)
    if not wanted:
        raise EvidenceProblem(
            "the evidence is empty — quote the vulnerable code verbatim")

    if sum(len(line) for line in wanted) < MIN_EVIDENCE_CHARS:
        raise EvidenceProblem(
            "the quoted code is too short to identify one place in the file "
            "({} characters). Quote the whole statement, or a couple of lines "
            "around it.".format(sum(len(line) for line in wanted)))

    # There was a minimum and no maximum. The matcher below walks every window
    # of the file for every candidate, so a quote of a few thousand lines
    # against a large file takes tens of seconds *per call* — and the run's
    # deadline is only checked between turns, so a turn issuing twenty of them
    # runs a quarter of an hour past the limit before anything notices.
    #
    # Rejected here rather than optimised: a bounded quadratic is easier to
    # reason about than an unbounded clever matcher, and the report shows eight
    # lines of evidence anyway. Anything approaching this size is a claim about
    # a file, not a quote of a statement.
    if len(wanted) > MAX_EVIDENCE_LINES or sum(
            len(line) for line in wanted) > MAX_EVIDENCE_CHARS:
        raise EvidenceProblem(
            "the quoted code is too long ({} lines, {} characters). Quote the "
            "statement the weakness is in and a couple of lines around it — "
            "at most {} lines. A quote this size cannot identify one place in "
            "the file, which is what the quote is for.".format(
                len(wanted), sum(len(line) for line in wanted),
                MAX_EVIDENCE_LINES))

    haystack = [normalize(line) for line in file_text.splitlines()]
    if not haystack:
        raise EvidenceProblem("the file is empty")

    for candidate in (wanted, _strip_diff_markers(wanted)):
        if not candidate:
            continue
        for exact in (True, False):
            hits = _match_all(haystack, candidate, exact=exact)
            if not hits:
                continue
            if len(hits) == 1:
                return hits[0]
            chosen = _closest(hits, claimed_line)
            if chosen is not None:
                return chosen
            raise EvidenceProblem(
                "that code appears {} times in the file (lines {}), so it does "
                "not identify one place. Quote more of the surrounding code, or "
                "give the line you mean.".format(
                    len(hits), ", ".join(str(h) for h in hits[:6])))

    raise EvidenceProblem("the quoted code does not appear in the file")


def _closest(hits: List[int], claimed_line: int) -> Optional[int]:
    """Pick the occurrence the finding meant, when its own line says clearly.

    Two conditions, and both are needed. The nearest occurrence must be within
    reach of the claim — a claim tens of lines away is not pointing at it — and
    it must be *strictly* nearer than every other. A claim equidistant from two
    occurrences has disambiguated nothing, and guessing there is the behaviour
    this replaced.
    """
    if not claimed_line:
        return None
    ranked = sorted(hits, key=lambda h: (abs(h - claimed_line), h))
    nearest = ranked[0]
    if abs(nearest - claimed_line) > NEAR_CLAIMED_LINE:
        return None
    runner_up = ranked[1]
    if abs(nearest - claimed_line) == abs(runner_up - claimed_line):
        return None
    return nearest


# How close a claimed line has to be to count as pointing at an occurrence. The
# agent's own line numbers are routinely a few off, since it counts hunk offsets
# by hand — but not tens off.
NEAR_CLAIMED_LINE = 10


def _match_all(haystack: List[str], needle: List[str], exact: bool) -> List[int]:
    """Every place the quote matches, as 1-based line numbers.

    ``exact=False`` allows each quoted line to be a substring of the file line,
    which covers a quote that clipped a long line mid-way. Every line of the
    quote must still match, in order, with no gaps.
    """
    span = len(needle)
    if span > len(haystack):
        return []
    hits = []
    for start in range(len(haystack) - span + 1):
        window = haystack[start : start + span]
        if exact:
            ok = all(w == n for w, n in zip(window, needle))
        else:
            ok = all(n in w for w, n in zip(window, needle))
        if ok:
            hits.append(start + 1)
    return hits


@dataclass(frozen=True)
class ChangedLines:
    """What a change did to one file, in new-file line numbers.

    Additions and deletions are kept apart because they reach differently. An
    added line is suspect where it sits. A deleted line has no position at all —
    what it leaves behind is an absence, and the effect of an absence is on the
    code that used to be protected by it, which is always *below*.
    """

    added: Dict[str, Set[int]] = field(default_factory=dict)
    removed_at: Dict[str, Set[int]] = field(default_factory=dict)

    def files(self) -> Set[str]:
        return set(self.added) | set(self.removed_at)

    def __bool__(self) -> bool:
        return any(self.added.values()) or any(self.removed_at.values())


# The escapes git uses inside a quoted path. Anything else after a backslash is
# an octal byte.
_C_ESCAPES = {
    "a": 0x07, "b": 0x08, "f": 0x0C, "n": 0x0A, "r": 0x0D, "t": 0x09,
    "v": 0x0B, "\\": 0x5C, '"': 0x22,
}


def unquote_path(path: str) -> str:
    """Undo git's C-style quoting of a path, if it is quoted at all.

    `core.quotePath=false` is pinned in the git environment and it is not
    enough on its own: it stops git quoting bytes above 0x7f, and git's own
    documentation says double-quote, backslash and control characters are
    escaped *regardless of the setting*. So `src/report\\v2.py` — a legal name
    on Linux — still arrives as `"b/src/report\\\\v2.py"`, and a path nothing
    can look up is a finding the gate treats as pre-existing.

    Found by this agent reviewing its own fix for the byte-above-0x7f case, on
    the first real run of the CLI runner. The fix it proposed is this one:
    decode the path rather than trusting a configuration knob to make it
    unnecessary.

    A malformed quoted string is returned as it arrived. Guessing at a repair
    would invent a path, and a path that fails to match is the safe direction
    here only because the caller treats an unmatched file as unattributed —
    which is why the decoding has to be right rather than best-effort.
    """
    if len(path) < 2 or not path.startswith('"') or not path.endswith('"'):
        return path

    body = path[1:-1]
    out = bytearray()
    index = 0
    while index < len(body):
        char = body[index]
        if char != "\\":
            out += char.encode("utf-8")
            index += 1
            continue
        index += 1
        if index >= len(body):
            return path                      # trailing backslash: malformed
        marker = body[index]
        if marker in _C_ESCAPES:
            out.append(_C_ESCAPES[marker])
            index += 1
            continue
        octal = body[index:index + 3]
        if len(octal) != 3 or any(digit not in "01234567" for digit in octal):
            return path                      # not an escape git would emit
        out.append(int(octal, 8))
        index += 3

    # `surrogateescape` rather than `replace`: a byte sequence that is not
    # UTF-8 is still a real path, and mangling it into `?` would produce a key
    # that matches nothing — the failure this whole function exists to end.
    return out.decode("utf-8", errors="surrogateescape")


def _header_path(line: str) -> str:
    """The file named by a `+++ b/...` header, decoded exactly.

    Two details, both of which decide whether a finding is attributed to the
    change or recorded as pre-existing — and pre-existing does not block.

    Git terminates the path with a single TAB when it contains a space, so that
    the space cannot be mistaken for the end of the name. That one tab is what
    gets removed here, and nothing else. `.strip()` was removing it *and* any
    real trailing whitespace, so `src/handler ` — a legal name on Linux, which
    git does not quote because a space is not a control character — became the
    key `src/handler`, which nothing ever looks up. The file then appeared in
    neither the additions nor the deletions, which is how a weakness that was
    *already there* is recorded.

    The `b/` prefix goes last, after unquoting, because git puts the prefix
    inside the quotes: `"b/src/caf\\303\\251.py"`.
    """
    body = line[4:]
    if body.endswith("\t"):
        body = body[:-1]
    path = unquote_path(body)
    return path[2:] if path.startswith("b/") else path


def changed_lines(diff_text: str) -> ChangedLines:
    """Split a unified diff into the lines a change is answerable for.

    Counting only additions is the obvious implementation and it is wrong. A
    change that only deletes has no added lines at all, so nothing could ever be
    attributed to it — and "only deletes" is the exact shape of removing a
    security control, which is among the most important regressions there is. A
    real merge request reverting GitPython's CVE-2023-41040 guard was found and
    confirmed by the agent, then waved through as "pre-existing" for precisely
    this reason.

    The diff is parsed as a structure, not scanned for lines that look like
    headers, because half of a diff is text an author wrote. A file that adds

        ++ b/src/decoy.py

    produces the diff line `+++ b/src/decoy.py`, and reading that as a file
    header hands every addition below it to a file that does not exist — the
    file actually being changed loses them, and a finding on the vulnerable
    line the author added right after it comes out "pre-existing", which does
    not block. The same trick with `-- ` suppressed deletions, and it did not
    even need an attacker: `--` opens a comment in SQL, Lua, Haskell and Ada,
    so deleting one such line from a migration was already invisible to the
    removed-control rule.
    """
    added: Dict[str, Set[int]] = {}
    removed: Dict[str, Set[int]] = {}
    current: Optional[str] = None
    lineno = 0
    # Whether we are reading the body of a hunk, which is the only part of a
    # diff whose text an author chose. See `_header_path` for what that means.
    in_hunk = False

    for line in diff_text.splitlines():
        # Column zero belongs to the diff's own structure. Every line of a hunk
        # body carries a marker column — `+`, `-`, or a space — so a line
        # beginning `diff ` or `@@ ` cannot have come out of a file, whatever
        # an author wrote in it. These two are therefore trusted anywhere;
        # `+++ ` and `--- ` are not, and are read only outside a hunk body.
        if line.startswith("diff "):
            in_hunk = False
            current = None
            continue
        match = HUNK_HEADER.match(line)
        if match:
            lineno = int(match.group(1))
            in_hunk = True
            continue
        if not in_hunk:
            if line.startswith("+++ "):
                path = _header_path(line)
                current = None if path == "/dev/null" else path
                if current is not None:
                    added.setdefault(current, set())
                    removed.setdefault(current, set())
            # `--- `, `index`, mode and similarity lines say nothing this map
            # needs; the new-side header alone names the file.
            continue
        if current is None:
            continue
        if line.startswith("+"):
            added[current].add(lineno)
            lineno += 1
        elif line.startswith("-"):
            # A deleted line occupies no position in the new file, so anchor it
            # where the removal happened. max(1, ...) keeps a deletion at the
            # very top of a file from anchoring to line 0.
            removed[current].add(max(1, lineno))
        elif line.startswith("\\"):
            continue
        else:
            # Context line (leading space), or a blank line git emitted without one.
            lineno += 1

    return ChangedLines(added=added, removed_at=removed)


# How far each kind of change reaches, in lines.
#
# Additions get a small symmetric window: an added line is suspect roughly where
# it sits. Deletions reach much further, and only downwards, because a removed
# guard protects what follows it — the sink is always after the check, never
# before. Fifteen lines covers a typical function body without swallowing the
# file; the real GitPython case had the sink four lines below the deleted guard,
# and a symmetric window of three missed it by one.
ADDITION_SLACK = 3
DELETION_REACH = 15


def touches_change(
    path: str,
    line: int,
    span: int,
    changed: "ChangedLines",
    slack: int = ADDITION_SLACK,
    deletion_reach: int = DELETION_REACH,
) -> bool:
    """Is the cited code this change's responsibility?"""
    return bool(attribution(path, line, span, changed, slack, deletion_reach))


ATTRIBUTED_ADDED = "added"
ATTRIBUTED_DELETED = "deleted"


def attribution(
    path: str,
    line: int,
    span: int,
    changed: "ChangedLines",
    slack: int = ADDITION_SLACK,
    deletion_reach: int = DELETION_REACH,
) -> str:
    """How this change is responsible for the cited code — or "" if it is not.

    The distinction matters to the gate, not just to the report. Code the change
    *added* is judged on its severity like anything else. Code the change
    *removed* is a different question: something that was there is gone, and if
    a weakness sits where it used to be, the honest reading is that this change
    took a guard away.
    """
    last = line + max(span, 1) - 1

    added = changed.added.get(path) or set()
    if any(line - slack <= n <= last + slack for n in added):
        return ATTRIBUTED_ADDED

    removed = changed.removed_at.get(path) or set()
    if any(n - slack <= last and line <= n + deletion_reach for n in removed):
        return ATTRIBUTED_DELETED
    return ""


def evidence_span(evidence: str) -> int:
    return max(1, len(_evidence_lines(evidence)))


def excerpt(file_text: str, line: int, radius: int = 25) -> Tuple[str, int, int]:
    """A line-numbered window around a line, for showing a verifier the context."""
    lines = file_text.splitlines()
    if not lines:
        return "", 0, 0
    center = max(1, min(line or 1, len(lines)))
    start = max(1, center - radius)
    stop = min(len(lines), center + radius)
    body = "\n".join(
        "{:>6} | {}".format(n, lines[n - 1]) for n in range(start, stop + 1)
    )
    return body, start, stop
