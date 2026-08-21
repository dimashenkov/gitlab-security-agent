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


def locate_evidence(file_text: str, evidence: str) -> Optional[int]:
    """Find where the quoted code sits in the file.

    Returns the 1-based line number of the first quoted line, or None when the
    quote does not appear. A returned line number is authoritative: it is used
    to correct the finding's own claim, which is often off by a few lines when
    the agent counted hunk offsets by hand.
    """
    wanted = _evidence_lines(evidence)
    if not wanted:
        return None

    haystack = [normalize(line) for line in file_text.splitlines()]
    if not haystack:
        return None

    for candidate in (wanted, _strip_diff_markers(wanted)):
        if not candidate:
            continue
        hit = _match(haystack, candidate, exact=True)
        if hit is not None:
            return hit
        hit = _match(haystack, candidate, exact=False)
        if hit is not None:
            return hit
    return None


def _match(haystack: List[str], needle: List[str], exact: bool) -> Optional[int]:
    """Sliding-window match of consecutive lines. Returns a 1-based line number.

    ``exact=False`` allows each quoted line to be a substring of the file line,
    which covers a quote that clipped a long line mid-way. Every line of the
    quote must still match, in order, with no gaps.
    """
    span = len(needle)
    if span > len(haystack):
        return None
    for start in range(len(haystack) - span + 1):
        window = haystack[start : start + span]
        if exact:
            ok = all(w == n for w, n in zip(window, needle))
        else:
            ok = all(n in w for w, n in zip(window, needle))
        if ok:
            return start + 1
    return None


def added_lines(diff_text: str) -> Dict[str, Set[int]]:
    """Map each file in a unified diff to the line numbers it adds.

    Used to tell a weakness this change introduced from one it merely sits next
    to. Both are worth reporting, but only the first is the author's to fix in
    this merge request, and a gate that blocks on pre-existing findings blocks
    every merge request until someone cleans up the whole repository.
    """
    result: Dict[str, Set[int]] = {}
    current: Optional[str] = None
    lineno = 0

    for line in diff_text.splitlines():
        if line.startswith("+++ "):
            path = line[4:].strip()
            if path.startswith("b/"):
                path = path[2:]
            current = None if path == "/dev/null" else path
            if current is not None:
                result.setdefault(current, set())
            continue
        if line.startswith("--- ") or line.startswith("diff --git"):
            continue
        match = HUNK_HEADER.match(line)
        if match:
            lineno = int(match.group(1))
            continue
        if current is None:
            continue
        if line.startswith("+"):
            result[current].add(lineno)
            lineno += 1
        elif line.startswith("-") or line.startswith("\\"):
            continue
        else:
            # Context line (leading space), or a blank line git emitted without one.
            lineno += 1

    return result


def touches_change(
    path: str, line: int, span: int, changed: Dict[str, Set[int]], slack: int = 3
) -> bool:
    """Did this change introduce the cited code?

    A small slack window is allowed because a weakness is often introduced by an
    added line that removes a guard a line or two above the sink itself.
    """
    lines = changed.get(path)
    if lines is None:
        return False
    if not lines:
        return False
    low = line - slack
    high = line + max(span, 1) - 1 + slack
    return any(low <= n <= high for n in lines)


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
