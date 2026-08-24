#!/usr/bin/env python3
"""Try to score the corpus without reading the code.

A pair is supposed to measure whether a reviewer can tell a dangerous data flow
from a safe one. It measures that only if there is no other way to tell the two
members apart — and there usually is, because the two members are written by
someone who knows which is which.

This is the check that catches it. Each rule below looks at surface properties
only: how many comment lines, how many bytes, how many imports. None of them
can read code. If any of them can pick the safe member reliably, the corpus is
answering a different question than the one it claims to.

It was written after an audit found that

    the member with more comment lines is the safe one,
    tiebreak on more bytes

scored **48 out of 48** on the harvested corpus. Real fix commits carry the
maintainer's explanation of the fix, and harvesting put that prose on the safe
side only. Nothing in the review pipeline would ever have shown this; the agent
would simply have scored well for the wrong reason.

    tools/corpus_adversary.py corpus/ corpus-real/
    tools/corpus_adversary.py corpus-real/ --threshold 0.65
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Line comment markers by extension. Block comments are not chased — a rule
# that undercounts is fine here, because the point is to detect an asymmetry,
# and an undercount that is applied identically to both members still shows one.
LINE_COMMENT = {
    ".py": ("#",), ".rb": ("#",), ".sh": ("#",), ".yml": ("#",), ".yaml": ("#",),
    ".go": ("//",), ".java": ("//",), ".rs": ("//",), ".cs": ("//",),
    ".ts": ("//",), ".tsx": ("//",), ".js": ("//",), ".jsx": ("//",),
    ".php": ("//", "#"), ".c": ("//",), ".cpp": ("//",), ".h": ("//",),
}

IMPORT_PREFIX = ("import ", "from ", "use ", "require", "using ", "#include")


def change_files(member: Path) -> list:
    change = member / "change"
    if not change.is_dir():
        return []
    return sorted(p for p in change.rglob("*") if p.is_file())


def read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        return ""


def comment_lines(member: Path) -> int:
    total = 0
    for path in change_files(member):
        markers = LINE_COMMENT.get(path.suffix.lower())
        if not markers:
            continue
        for line in read(path).splitlines():
            stripped = line.strip()
            if stripped.startswith("#!"):          # shebang, not prose
                continue
            if any(stripped.startswith(m) for m in markers):
                total += 1
    return total


def byte_count(member: Path) -> int:
    return sum(len(read(p).encode("utf-8")) for p in change_files(member))


def line_count(member: Path) -> int:
    return sum(len(read(p).splitlines()) for p in change_files(member))


def import_lines(member: Path) -> int:
    return sum(
        1
        for path in change_files(member)
        for line in read(path).splitlines()
        if line.strip().startswith(IMPORT_PREFIX)
    )


# Each rule returns the member it believes is safe, or "" to abstain. Abstaining
# matters: a rule that fires twice and is right twice has found nothing, and
# reporting it as 100% would bury the rule that fires forty times.
RULES = {
    "more comment lines": comment_lines,
    "more bytes": byte_count,
    "more lines": line_count,
    "more imports": import_lines,
}


def judge(case: Path, measure) -> str:
    safe, unsafe = measure(case / "safe"), measure(case / "unsafe")
    if safe == unsafe:
        return ""
    return "safe" if safe > unsafe else "unsafe"


def evaluate(roots: list) -> dict:
    cases = sorted(
        manifest.parent
        for root in roots
        for manifest in Path(root).rglob("case.yml")
    )
    scores = {}
    for name, measure in RULES.items():
        fired = correct = 0
        examples = []
        for case in cases:
            guess = judge(case, measure)
            if not guess:
                continue
            fired += 1
            if guess == "safe":
                correct += 1
                if len(examples) < 4:
                    examples.append(case.name)
        scores[name] = {"fired": fired, "correct": correct,
                        "cases": len(cases), "examples": examples}

    # The composite the audit actually used: the cheapest thing a person would
    # try, and the one that scored 48/48.
    fired = correct = 0
    for case in cases:
        guess = judge(case, comment_lines) or judge(case, byte_count)
        if not guess:
            continue
        fired += 1
        correct += guess == "safe"
    scores["comments, then bytes"] = {
        "fired": fired, "correct": correct, "cases": len(cases), "examples": []}
    return scores


def worst(scores: dict, min_fires: int = 6) -> tuple:
    """The strongest rule that fired often enough to mean anything."""
    ranked = [
        (name, row["correct"] / row["fired"], row)
        for name, row in scores.items()
        if row["fired"] >= min_fires
    ]
    if not ranked:
        return ("", 0.0, {})
    # Distance from chance, not raw accuracy: a rule that reliably picks the
    # *unsafe* member leaks exactly as much as one that picks the safe member.
    return max(ranked, key=lambda item: abs(item[1] - 0.5))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("roots", nargs="+")
    parser.add_argument("--threshold", type=float, default=0.65,
                        help="accuracy a code-blind rule may not exceed (0.65)")
    parser.add_argument("--min-fires", type=int, default=6)
    args = parser.parse_args()

    scores = evaluate(args.roots)
    print("{:<24}{:>8}{:>10}{:>12}   {}".format(
        "code-blind rule", "fires", "correct", "accuracy", "examples"))
    print("-" * 78)
    for name, row in scores.items():
        accuracy = row["correct"] / row["fired"] if row["fired"] else 0.0
        print("{:<24}{:>8}{:>10}{:>11.0f}%   {}".format(
            name, row["fired"], row["correct"], 100 * accuracy,
            ", ".join(row["examples"][:3])))

    name, accuracy, row = worst(scores, args.min_fires)
    total = next(iter(scores.values()))["cases"]
    print("\n{} case(s) examined.".format(total))
    if not name:
        print("No rule fired often enough to judge.")
        return 0

    print("Strongest code-blind rule: {!r} at {:.0f}% over {} case(s).".format(
        name, 100 * accuracy, row["fired"]))
    if abs(accuracy - 0.5) > args.threshold - 0.5:
        print("\nFAIL — a rule that reads no code should be near 50%. At {:.0f}% "
              "the corpus is measuring that rule, not the reviewer.".format(
                  100 * accuracy))
        return 1
    print("Within {:.0f}% of chance. No surface cue found — which is not the "
          "same as none existing.".format(100 * (args.threshold - 0.5)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
