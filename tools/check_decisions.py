#!/usr/bin/env python3
"""Is `DECISIONS.md` still true about itself?

The file records why choices were made, so that the reasoning survives a
conversation ending. Codex refused to admit it without this checker, and the
argument was the whole point of the file: *without enforced states it becomes
worse than missing memory — it becomes confidently stale memory.* A ledger that
looks strictly structured and is machine-false is exactly the failure it exists
to prevent.

This does not check whether a decision is *right*. It checks that the document
is honest about its own shape: that every field a reader relies on is there,
that every symbol and test it names still exists, that a superseded entry has a
successor and the successor points back, and that a proposal is not sitting
among the decisions.

    tools/check_decisions.py            # exit 1 on any problem
    tools/check_decisions.py --tests    # also resolve the pytest node ids

Renaming a test is the ordinary way this file goes stale, and nothing else in
the repository would notice.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
import unicodedata
from pathlib import Path
from typing import Dict, List

ROOT = Path(__file__).resolve().parents[1]
DOC = ROOT / "DECISIONS.md"

# The four states, and nothing else. "active, with a known hole" was a state in
# the first draft: a value carrying an explanation, which no parser can read and
# which lets a decision look active and qualified at once. The qualification
# belongs in its own field.
DECISION_STATES = {"active", "superseded", "withdrawn"}
PROPOSAL_STATES = {"proposed", "withdrawn"}

DECISION_FIELDS = ("State", "Scope", "Checked against")
PROPOSAL_FIELDS = ("State", "Scope")

# A decision claims something is true of the code. These say what makes it true
# and how a reader checks it; a proposal has neither by construction, which is
# what makes it a proposal.
DECISION_SECTIONS = ("Decided", "Rejected", "Reason", "Enforced by",
                     "Evidence", "Objection", "Revisited when")
PROPOSAL_SECTIONS = ("Proposed", "Objection", "Becomes a decision when")

# ` {0,3}` because Markdown renders a heading with up to three leading spaces.
# Anchored at column zero, an indented `## D-013 …` was a heading to every
# reader and to no parser here — the same silence the em dash produced, by a
# character nobody can see.
ENTRY = re.compile(r"^ {0,3}##\s+(D-\d{3}|P-\d{3})\s+·\s+(.+)$", re.M)
# Anything that announces itself as an entry. `ENTRY` above requires the middle
# dot, and a heading that missed it was not a malformed entry to this checker —
# it was no entry at all, and its body was swallowed into the entry above.
# D-013 was written with an em dash on 2026-09-02 and went unchecked for a day:
# no state, no scope, no `Checked against`, its sections counted as D-012's and
# its file references resolved as D-012's. The rule that authorises abandoning
# the project, invisible to the tool that exists to keep this file honest.
#
# Requiring the separator is right; reading its absence as "nothing here" is
# the defect. This repository's own shape, in the checker for the file that
# records the decisions about it.
ENTRY_LOOSE = re.compile(r"^ {0,3}##\s+(D-\d{3}|P-\d{3})\b(.*)$", re.M)

# A fenced block is an example, not structure. Without this, a document that
# shows what a malformed heading looks like fails its own check — and a
# correctly formatted example becomes a fourteenth decision.
#
# Scanned line by line rather than matched with one regex. `^ {0,3}(```|~~~)
# .*?^ {0,3}\1` was the first version and got four things wrong, each of which
# leaves real fenced text visible to the parser: a fence never closed runs to
# the end of the document in Markdown and it blanked nothing; a four-backtick
# fence was read as a three-backtick one, so a ``` line inside it closed the
# match early; a line of backticks with text after it was accepted as a close,
# which Markdown does not allow; and the same for longer tilde runs.
FENCE_OPEN = re.compile(r"^ {0,3}(`{3,}|~{3,})(.*)$")
FIELD = re.compile(r"^\|\s*\*\*(.+?)\*\*\s*\|\s*(.+?)\s*\|$", re.M)
# The whole bold run, then trailing punctuation stripped. Matching up to the
# first space instead read `**Enforced by.**` as the section "Enforced", so
# every entry was missing a section it plainly had — a checker wrong in the
# direction that fails loudly, which is the safe one, but wrong.
BOLD_SECTION = re.compile(r"\*\*(.+?)\*\*", re.S)

# `path.py:symbol` or `path.py::node_id` inside backticks.
SYMBOL = re.compile(r"`([\w/]+\.py)[:.]{1,2}([\w.]+)`")
PATH = re.compile(r"`((?:src|tools|tests)/[\w/]+\.py)`")
NODE_ID = re.compile(r"`?(tests/[\w/]+\.py)((?:::[\w\[\]-]+)+)`?")
COMMIT = re.compile(r"^[0-9a-f]{7,40}$")


class Entry:
    def __init__(self, ident: str, title: str, body: str) -> None:
        self.id = ident
        self.title = title
        self.body = body
        self.fields: Dict[str, str] = {}
        for name, value in FIELD.findall(body):
            self.fields[name.strip()] = value.strip().strip("`")
        self.sections = {m.strip().rstrip(".,:") for m in BOLD_SECTION.findall(body)}

    @property
    def is_proposal(self) -> bool:
        return self.id.startswith("P-")


def unparsed_headings(text: str) -> List[str]:
    """Headings that name an entry and that `ENTRY` will not match.

    Returned rather than skipped. A heading this checker cannot read is not an
    absent entry; it is an entry it cannot see, and the two produce opposite
    reports from the same file.
    """
    text = blank_fences(text)
    seen = {m.start() for m in ENTRY.finditer(text)}
    return ["{}{}".format(m.group(1), m.group(2))
            for m in ENTRY_LOOSE.finditer(text) if m.start() not in seen]


def blank_fences(text: str) -> str:
    """Fenced blocks emptied line by line, so the **line count** holds.

    Emptied rather than removed so a line number in this text still names the
    same line in the document — which is what a person reading a message goes
    looking for. Character offsets do not survive and nothing needs them to:
    `parse` finds headings and slices bodies in this same transformed text.

    Markdown's rules, and each one was got wrong by the regex this replaced:
    an opening fence is three or more backticks or tildes; it is closed by at
    least as many of the *same* character with nothing but spaces or tabs
    after them;
    and a fence that is never closed runs to the end of the document.

    **What it does not do: containers.** A fence opened inside a list item or a
    blockquote is indented past three spaces relative to the document, so this
    scanner does not see it, and a `## D-999 · …` line inside such a block
    would be read as a real entry. Not implemented, because tracking containers
    is a Markdown parser and this checks one file whose entries are all at the
    top level. The failure direction is the safe one — an extra entry, which
    then fails for every missing field, loudly — and this paragraph is here so
    the next person meets a stated limit rather than a surprise.
    """
    out, fence = [], None
    for line in text.split("\n"):
        if fence is None:
            opened = FENCE_OPEN.match(line)
            # A backtick fence's info string may not contain a backtick —
            # ```` ```python`oops ```` is not a fence at all, and treating it as
            # one blanked the rest of the document. A tilde fence's info string
            # may, so the rule depends on which character opened it.
            if opened and not (opened.group(1)[0] == "`"
                               and "`" in opened.group(2)):
                fence = opened.group(1)
                out.append("")
                continue
            out.append(line)
            continue
        # Inside a fence. A close is the same character, at least as long, and
        # nothing after it but spaces — so a ``` line inside a ```` block is
        # content, and a ```` line with text after it does not close anything.
        #
        # Indented at most three **from column zero**, not from the opener:
        # measuring it against the opener accepted a close six spaces in, which
        # Markdown reads as content, so everything after it was exposed. Spaces
        # only, because `strip()` removes a tab while a space count does not
        # see it — and a tab-indented line that looked like a close was closing
        # the fence at indentation zero.
        body = line.lstrip(" ")
        # Spaces **or tabs** after a closing fence — CommonMark allows both.
        # `body == stripped` was the first version and refused any trailing
        # whitespace; `rstrip(" ")` was the second and still refused a tab.
        # Both fail in the silent direction: the parser stays inside a fence
        # that Markdown has closed, and every real entry after that block goes
        # unchecked while the report says every field is present.
        #
        # Leading tabs stay refused. Indentation before a fence is spaces, up
        # to three; a tab is four columns, which makes the line indented code.
            # `\r` too. Not reachable through the CLI, which reads with
        # `Path.read_text` and its universal newlines — but this function is
        # called directly from tests and from `unparsed_headings`, and a stray
        # carriage return refusing a close fails in the silent direction.
        run = body.rstrip(" \t\r")
        closes = (len(line) - len(body) <= 3
                  and run
                  and set(run) == {fence[0]}
                  and len(run) >= len(fence))
        out.append("")
        if closes:
            fence = None
    return "\n".join(out)


def parse(text: str) -> List[Entry]:
    # Headings **and** bodies from the blanked text. Finding headings in one
    # view and slicing bodies from the other was the first version of this, and
    # it left every fenced example supplying fields and sections to the entry
    # it sat in: a decision whose only `**State**` row and only `**Decided.**`
    # were inside a code block passed with no problem reported. The checker
    # then said "example, not structure" in a comment while reading the example
    # as structure.
    text = blank_fences(text)
    marks = list(ENTRY.finditer(text))
    out = []
    for i, mark in enumerate(marks):
        end = marks[i + 1].start() if i + 1 < len(marks) else len(text)
        out.append(Entry(mark.group(1), mark.group(2), text[mark.end():end]))
    return out


def _section_present(entry: Entry, name: str) -> bool:
    """Is this section here, and not merely something that starts like it?

    The heading is written as `**Decided.**`, `**Decided 2026-09-03.**` or
    `**Evidence,** and namely ...`, so a bare prefix match is what the document
    actually contains; matching the whole run would pass for no entry at all.

    But a bare prefix match also accepts the **field** `**Decided by**` as the
    **section** `Decided` — so an entry carrying that field satisfied the
    requirement for a section it did not have. Three entries carry it. Latent,
    because all three also have a real `**Decided.**`, and latent is how it
    would have stayed until the first entry that did not.

    So the prefix has to end the word: what follows `name` may be nothing, or
    punctuation, or whitespace and then something that is not a letter — a
    date, a bracket. Whitespace and a letter is a longer name, not this one.

    Written by stripping the whitespace and asking what the next character
    *is*. Two earlier versions asked narrower questions and both had a door
    left open: looking at the first two characters let `Decided  by` through
    with two spaces, and `not ....isalpha()` let `Decided<zero-width-space>by`
    through, because a zero-width joiner is not a letter and `lstrip` does not
    remove it. `unicodedata.category` answers the question directly — L is a
    letter, M a combining mark, C a control or format character, and none of
    the three is a boundary.
    """
    for section in entry.sections:
        if section == name:
            return True
        if not section.startswith(name):
            continue
        rest = section[len(name):].lstrip()
        if not rest:
            return True
        if unicodedata.category(rest[0])[0] not in "LMC":
            return True
    return False


def check(text: str, run_tests: bool) -> List[str]:
    entries = parse(text)
    problems: List[str] = []

    if not entries:
        return ["no entries found — the heading format changed and this "
                "checker is now reading nothing, which passes vacuously"]

    for heading in unparsed_headings(text):
        problems.append(
            "`## {}` names an entry this checker cannot read: the separator "
            "between the id and the title must be ` · `. Its body is being "
            "counted as part of the entry above it, so every field and file "
            "reference in it is going unchecked".format(heading.strip()))

    seen: Dict[str, Entry] = {}
    for entry in entries:
        if entry.id in seen:
            problems.append("{}: id used twice".format(entry.id))
        seen[entry.id] = entry

    for entry in entries:
        want_fields = PROPOSAL_FIELDS if entry.is_proposal else DECISION_FIELDS
        want_sections = PROPOSAL_SECTIONS if entry.is_proposal else DECISION_SECTIONS
        states = PROPOSAL_STATES if entry.is_proposal else DECISION_STATES

        for name in want_fields:
            if name not in entry.fields:
                problems.append("{}: no `{}` field".format(entry.id, name))

        state = entry.fields.get("State", "")
        if state and state not in states:
            problems.append(
                "{}: state {!r} is not one of {} — a state carrying its own "
                "explanation cannot be read by anything".format(
                    entry.id, state, ", ".join(sorted(states))))

        for name in want_sections:
            if not _section_present(entry, name):
                problems.append("{}: no **{}** section".format(entry.id, name))

        commit = entry.fields.get("Checked against", "")
        if commit and not COMMIT.match(commit):
            problems.append("{}: {!r} is not a commit".format(entry.id, commit))
        elif commit:
            proc = subprocess.run(("git", "cat-file", "-e", commit + "^{commit}"),
                                  cwd=ROOT, capture_output=True, check=False)
            if proc.returncode != 0:
                # "Not fetched" is not "not in this repository", and this tool
                # said the second about the first. CI clones at depth 20; every
                # commit older than that is absent from the checkout and
                # present in the repository, so nine entries were reported as
                # naming commits that do not exist. A confident false verdict
                # from the tool that exists to keep the record honest.
                problems.append(
                    "{}: commit {} is {}".format(
                        entry.id, commit,
                        "not in this checkout — it is shallow, so this cannot "
                        "be checked here" if _shallow()
                        else "not in this repository"))

        problems += _check_supersession(entry, seen)
        problems += _check_references(entry, run_tests)

    return problems


def _shallow() -> bool:
    """Is this a truncated clone, where absence proves nothing?"""
    proc = subprocess.run(("git", "rev-parse", "--is-shallow-repository"),
                          cwd=ROOT, capture_output=True, text=True, check=False)
    return proc.stdout.strip() == "true"


def _check_supersession(entry: Entry, seen: Dict[str, Entry]) -> List[str]:
    """Both directions, or the first replacement leaves two live decisions.

    Untested until something is actually superseded, which is why the rules are
    written down now rather than the first time one is: the entry that replaces
    another will be written months from now by someone with none of this in
    mind.
    """
    problems = []
    state = entry.fields.get("State", "")
    replaces = entry.fields.get("Replaces", "")
    replaced_by = entry.fields.get("Replaced by", "")

    if state == "superseded" and not replaced_by:
        problems.append(
            "{}: superseded and does not name its successor — a reader has "
            "nowhere to go and no way to know the decision moved".format(
                entry.id))
    if replaced_by:
        successor = seen.get(replaced_by)
        if successor is None:
            problems.append("{}: names {} as its successor, which does not "
                            "exist".format(entry.id, replaced_by))
        elif successor.id == entry.id:
            problems.append("{}: names itself as its successor".format(entry.id))
        elif successor.fields.get("Replaces") != entry.id:
            problems.append(
                "{}: says {} replaces it, and {} does not say so back".format(
                    entry.id, replaced_by, replaced_by))
        if state != "superseded":
            problems.append(
                "{}: names a successor while still {!r}".format(
                    entry.id, state or "stateless"))
    if replaces and replaces not in seen:
        problems.append("{}: replaces {}, which does not exist".format(
            entry.id, replaces))
    if replaces == entry.id:
        problems.append("{}: replaces itself".format(entry.id))

    # A proposal never becomes a decision by being renamed: the proposal stays
    # where it is and the decision is new, so the history of the argument
    # survives instead of being overwritten by its outcome.
    if not entry.is_proposal and entry.fields.get("Comes from", "").startswith("P-"):
        origin = entry.fields["Comes from"]
        if origin not in seen:
            problems.append("{}: comes from {}, which does not exist".format(
                entry.id, origin))
    return problems


def _check_references(entry: Entry, run_tests: bool) -> List[str]:
    """Renaming a test is how this file goes stale, and nothing else notices."""
    problems = []

    for path in set(PATH.findall(entry.body)):
        if not (ROOT / path).is_file():
            problems.append("{}: names {}, which does not exist".format(
                entry.id, path))

    for path, symbol in set(SYMBOL.findall(entry.body)):
        target = ROOT / path
        if not target.is_file():
            problems.append("{}: names {}, which does not exist".format(
                entry.id, path))
            continue
        leaf = symbol.split(".")[-1]
        body = target.read_text(encoding="utf-8")
        if not re.search(r"\b(def|class)\s+{}\b".format(re.escape(leaf)), body):
            problems.append(
                "{}: names {}:{}, and {} defines no such symbol".format(
                    entry.id, path, symbol, path))

    if run_tests:
        for path, nodes in set(NODE_ID.findall(entry.body)):
            for node in [n for n in nodes.split("::") if n]:
                proc = subprocess.run(
                    (sys.executable, "-m", "pytest", "--collect-only", "-q",
                     "{}::{}".format(path, node)),
                    cwd=ROOT, capture_output=True, text=True, check=False)
                if proc.returncode != 0:
                    problems.append(
                        "{}: {}::{} does not collect — the test was renamed "
                        "and the entry now cites nothing".format(
                            entry.id, path, node))
    return problems


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tests", action="store_true",
                        help="also resolve every pytest node id (slower)")
    args = parser.parse_args()

    if not DOC.is_file():
        print("DECISIONS.md does not exist")
        return 1

    problems = check(DOC.read_text(encoding="utf-8"), args.tests)
    if problems:
        print("{} problem(s) in DECISIONS.md:".format(len(problems)))
        for problem in problems:
            print("  " + problem)
        return 1

    entries = parse(DOC.read_text(encoding="utf-8"))
    decisions = [e for e in entries if not e.is_proposal]
    print("{} decision(s) and {} proposal(s); every field present, every "
          "symbol and commit resolves{}.".format(
              len(decisions), len(entries) - len(decisions),
              ", every test collects" if args.tests else ""))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
