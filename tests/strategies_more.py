"""Generators for the *review* path: diffs, findings, candidates, ignore rules.

`strategies.py` builds artifact-shaped values for the measuring tools — rows,
usage blocks, whole artifacts. Nothing there reaches the product's own decision
path, and that is where the gate lives: a diff is parsed into the lines a change
answers for, a quote is tied to a place in a file, an accepted risk removes a
finding from the gate, and an exit code comes out the far end.

The bias is the same one as next door, because the defect is the same one: a
check satisfied by the absence of the data it needs. So a hunk header here can
declare a count the body does not honour, a path can arrive quoted, with a
trailing space, or carrying a byte that is not UTF-8, an ignore entry can name
nothing, and a severity can be a word nobody recognises. Those are the inputs a
hand-written fixture never supplies, and every one of them has a branch in the
code that decides whether a merge blocks.

Diffs are built from a *plan* — files, hunks, and the ops inside them — so the
expected answer is computed from the unified-diff format's own definition (a
line's new-file number is its hunk's start plus the number of lines before it
that exist on the new side) rather than from the parser being tested.
"""

from __future__ import annotations

from typing import Any, Dict, List, Set, Tuple

from hypothesis import strategies as st

from security_agent.models import Candidate, Finding

# --------------------------------------------------------------------- paths

# Every one of these is a legal file name on Linux, and each one has already
# broken something: the trailing space was being `.strip()`ped away, the space
# in the middle makes git terminate the header with a TAB, the double quote and
# the backslash make git quote the whole path whatever `core.quotePath` says,
# and the non-ASCII name is what `core.quotePath=false` was set for.
PATH_NAMES = st.sampled_from([
    "app/handler.py",
    "src/report.go",
    "src/report v2.py",
    "src/handler ",
    'src/a"b.py',
    "src/back\\slash.py",
    "src/café.py",
    "deep/nested/path/to/mod.rb",
])

# A byte that is not valid UTF-8, as `workspace` hands it over: git's output is
# decoded with `errors="surrogateescape"`, so an undecodable byte arrives as a
# lone surrogate and stays reversible. Nothing else in a Python string behaves
# like one — in particular `.encode("utf-8")` refuses it.
LONE_SURROGATE = "\udcff"


def quote_git_style(body: str, escape_high: bool = False) -> str:
    """Quote a path the way git writes one in a `+++` header.

    `escape_high=False` is `core.quotePath=false`, which the agent pins: the
    quote, the backslash and the control characters are escaped and everything
    else is written as itself. `escape_high=True` is the default setting, which
    also writes every byte above 0x7f as an octal escape. Both are shapes
    `unquote_path` promises to undo.
    """
    out = ['"']
    for char in body:
        if char == '"':
            out.append('\\"')
        elif char == "\\":
            out.append("\\\\")
        elif ord(char) < 0x20 or ord(char) == 0x7F:
            out.append("\\{:03o}".format(ord(char)))
        elif ord(char) > 0x7F and escape_high:
            out.extend("\\{:03o}".format(byte) for byte in char.encode("utf-8"))
        else:
            out.append(char)
    out.append('"')
    return "".join(out)


def _needs_quoting(body: str) -> bool:
    return any(char in '"\\' or ord(char) < 0x20 for char in body)


def header_for(path: str) -> str:
    """The `+++` line git would write for this path, quoted only if it must be."""
    body = "b/" + path
    if _needs_quoting(body):
        return "+++ " + quote_git_style(body)
    # A path containing a space is terminated with a single TAB, so the space
    # cannot be read as the end of the name.
    return "+++ " + body + ("\t" if " " in body else "")


# ---------------------------------------------------------------------- diffs

# Deliberately free of anything that could be mistaken for diff structure: the
# point of a *well-formed* plan is that its expected answer is unambiguous, and
# a generated line reading `+++ b/x` would be testing the decoy rule instead.
LINE_TEXT = st.text(
    alphabet="abcdefgxyz0123_()'\"=.", min_size=0, max_size=12)

MARKERS = st.sampled_from(["+", "-", " ", " "])


@st.composite
def hunk_plans(draw):
    ops = draw(st.lists(st.tuples(MARKERS, LINE_TEXT), min_size=1, max_size=5))
    return {
        "old_start": draw(st.integers(1, 40)),
        "new_start": draw(st.integers(1, 40)),
        "ops": ops,
        # git omits a count of 1; the format says an omitted count *is* 1.
        "omit_unit_counts": draw(st.booleans()),
        "heading": draw(st.sampled_from(["", " func handler()"])),
    }


@st.composite
def file_plans(draw, min_hunks: int = 0):
    return {
        "path": draw(PATH_NAMES),
        "hunks": draw(st.lists(hunk_plans(), min_size=min_hunks, max_size=2)),
        "with_git_line": draw(st.booleans()),
        # `+++ /dev/null` — the file was deleted, and nothing is attributed to
        # it, but its hunk body still has to be walked past.
        "deleted": draw(st.booleans()),
        "quote_high_bytes": draw(st.booleans()),
    }


def _counts(ops) -> Tuple[int, int]:
    old = sum(1 for marker, _ in ops if marker in ("-", " "))
    new = sum(1 for marker, _ in ops if marker in ("+", " "))
    return old, new


def render_hunk(hunk: Dict[str, Any], explicit_counts: bool = False,
                delta: Tuple[str, int] = ("", 0)) -> List[str]:
    old_count, new_count = _counts(hunk["ops"])
    side, amount = delta
    if side == "old":
        old_count += amount
    elif side == "new":
        new_count += amount
    omit = hunk["omit_unit_counts"] and not explicit_counts

    def side_text(sign: str, start: int, count: int) -> str:
        if omit and count == 1:
            return "{}{}".format(sign, start)
        return "{}{},{}".format(sign, start, count)

    lines = ["@@ {} {} @@{}".format(
        side_text("-", hunk["old_start"], old_count),
        side_text("+", hunk["new_start"], new_count),
        hunk["heading"])]
    for marker, text in hunk["ops"]:
        # A context line git emitted without its leading space is a real shape
        # the parser names, and an empty one is the only way to write it.
        lines.append("" if (marker == " " and not text) else marker + text)
    return lines


def render_plan(files: List[Dict[str, Any]]) -> str:
    lines: List[str] = []
    for entry in files:
        path = entry["path"]
        if entry["with_git_line"]:
            lines.append("diff --git a/{} b/{}".format(path, path))
        lines.append("--- a/{}".format(path))
        if entry["deleted"]:
            lines.append("+++ /dev/null")
        elif entry["quote_high_bytes"] and any(ord(c) > 0x7F for c in path):
            lines.append("+++ " + quote_git_style("b/" + path, escape_high=True))
        else:
            lines.append(header_for(path))
        for hunk in entry["hunks"]:
            lines += render_hunk(hunk)
    return "\n".join(lines) + ("\n" if lines else "")


def expected_map(files: List[Dict[str, Any]]):
    """What a reader of the unified-diff format says this plan changed.

    Positional, not incremental: the new-file number of an op is its hunk's
    `new_start` plus however many of the ops before it exist on the new side.
    A deleted line has no number of its own, so it is anchored at the number of
    the line that now stands where it was.
    """
    added: Dict[str, Set[int]] = {}
    removed: Dict[str, Set[int]] = {}
    for entry in files:
        if entry["deleted"]:
            continue
        path = entry["path"]
        added.setdefault(path, set())
        removed.setdefault(path, set())
        for hunk in entry["hunks"]:
            ops = hunk["ops"]
            for index, (marker, _) in enumerate(ops):
                here = hunk["new_start"] + sum(
                    1 for before, _ in ops[:index] if before != "-")
                if marker == "+":
                    added[path].add(here)
                elif marker == "-":
                    removed[path].add(max(1, here))
    return added, removed


@st.composite
def diff_plans(draw):
    """A well-formed unified diff, and the map it means."""
    files = draw(st.lists(file_plans(), min_size=1, max_size=3,
                          unique_by=lambda f: f["path"]))
    added, removed = expected_map(files)
    return {"text": render_plan(files), "added": added, "removed": removed,
            "files": files}


@st.composite
def miscounted_diffs(draw, amounts=(-1, 1)):
    """A diff whose hunk header does not agree with its own body.

    One hunk declares one line too many or too few on one side. Nothing else
    about it is unusual — this is the shape `DiffFormatError` exists for, and
    the only thing worth generating is *where* in the diff it sits.

    `amounts` narrows it to one direction: `-1` is a body longer than its
    header, `+1` a header promising more than the body delivers. The two are
    caught by different branches and only one of them always fires.
    """
    files = draw(st.lists(file_plans(min_hunks=1), min_size=1, max_size=3,
                          unique_by=lambda f: f["path"]))
    positions = [(f, h) for f, entry in enumerate(files)
                 for h in range(len(entry["hunks"]))]
    target = draw(st.sampled_from(positions))
    amount = draw(st.sampled_from(list(amounts)))
    old_count, new_count = _counts(files[target[0]]["hunks"][target[1]]["ops"])
    # A count cannot go below zero, so the side is drawn from the ones where
    # this mutation is expressible rather than filtered out afterwards.
    sides = [name for name, count in (("old", old_count), ("new", new_count))
             if count + amount >= 0]
    if not sides:
        return None
    side = draw(st.sampled_from(sides))

    lines: List[str] = []
    for index, entry in enumerate(files):
        path = entry["path"]
        if entry["with_git_line"]:
            lines.append("diff --git a/{} b/{}".format(path, path))
        lines.append("--- a/{}".format(path))
        lines.append("+++ /dev/null" if entry["deleted"] else header_for(path))
        for position, hunk in enumerate(entry["hunks"]):
            delta = (side, amount) if (index, position) == target else ("", 0)
            lines += render_hunk(hunk, explicit_counts=True, delta=delta)
    return {"text": "\n".join(lines) + "\n", "where": target,
            "last": target == positions[-1], "side": side, "amount": amount}


# ------------------------------------------------------------------ findings

CATEGORY_NAMES = st.sampled_from(
    ["injection", "authn-authz", "crypto", "dos", "xss", "other"])

# Recognised words, the same words with a capital, and words nobody knows. The
# gate reads all three and the middle one is what carried a critical finding
# past it: `severity_rank` returned -1 for `"High"` and -1 is below every
# threshold.
SEVERITY_WORDS = st.sampled_from(
    ["low", "medium", "high", "critical", "High", "CRITICAL", "sev-2", ""])
CONFIDENCE_WORDS = st.sampled_from(
    ["low", "medium", "high", "High", "probable", ""])

EVIDENCE_TEXT = st.sampled_from([
    "rows, err := s.db.QueryContext(r.Context(), query)",
    "+ rows, err := s.db.QueryContext(r.Context(), query)\n+ if err != nil {",
    "if err != nil {\n}",
    "}",
    "  cmd = subprocess.run(user_input, shell=True)  ",
    "x",
    "",
])


@st.composite
def findings_objects(draw, category=None, file_=None):
    return Finding(
        title=draw(st.sampled_from(["Reverted guard", "SQL injection"])),
        severity=draw(SEVERITY_WORDS),
        confidence=draw(CONFIDENCE_WORDS),
        category=draw(CATEGORY_NAMES if category is None else category),
        file=draw(PATH_NAMES if file_ is None else file_),
        line=draw(st.integers(0, 200)),
        impact=draw(st.sampled_from(
            ["rce", "data_loss", "info_leak", "unclear", ""])),
        reachable_without_authentication=draw(
            st.sampled_from(["yes", "no", "unclear", ""])),
        requires_user_interaction=draw(st.sampled_from(["yes", "no", "unclear"])),
        evidence=draw(EVIDENCE_TEXT),
        description=draw(st.text(max_size=8)),
        exploit_scenario=draw(st.text(max_size=8)),
        recommendation=draw(st.text(max_size=8)),
    )


@st.composite
def candidates(draw, category=None, file_=None):
    """A finding plus everything the gate reads off it."""
    return Candidate(
        finding=draw(findings_objects(category=category, file_=file_)),
        in_changed_lines=draw(st.booleans()),
        attributed_by=draw(st.sampled_from(["added", "deleted", ""])),
        removes_control=draw(st.booleans()),
        severity=draw(SEVERITY_WORDS),
        confidence=draw(CONFIDENCE_WORDS),
    )


# ----------------------------------------------------------- ignore file rules

# `reason` missing, empty, or not a string; `expires` in every spelling YAML can
# carry it; a rule that constrains nothing. Each of these decides whether a
# finding is silently removed from the gate.
IGNORE_ENTRIES = st.fixed_dictionaries({}, optional={
    "fingerprint": st.one_of(st.sampled_from(["f" * 16, ""]), st.none(),
                             st.integers()),
    "path": st.one_of(PATH_NAMES, st.sampled_from(["src/", "*.py", "/src/x.py",
                                                   ""]), st.none()),
    "category": st.one_of(CATEGORY_NAMES, st.sampled_from(["", "Injection"]),
                          st.none()),
    "reason": st.one_of(st.sampled_from(["accepted 2026-01-01", "", "   "]),
                        st.none(), st.integers()),
    "expires": st.one_of(st.sampled_from(["2020-01-01", "2099-01-01", "",
                                          "yesterday", "2026-13-45"]),
                         st.none(), st.booleans()),
    "note": st.text(max_size=4),
})
