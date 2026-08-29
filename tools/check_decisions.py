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
from pathlib import Path
from typing import Dict, List

ROOT = Path(__file__).resolve().parents[1]
DOC = ROOT / "DECISIONS.md"

# The four states, and nothing else. "действащо, с известна дупка" was a state
# in the first draft: a value carrying an explanation, which no parser can read
# and which lets a decision look active and qualified at once. The qualification
# belongs in its own field.
DECISION_STATES = {"действащо", "заменено", "оттеглено"}
PROPOSAL_STATES = {"предложено", "оттеглено"}

DECISION_FIELDS = ("Състояние", "Обхват", "Проверено срещу")
PROPOSAL_FIELDS = ("Състояние", "Обхват")

# A decision claims something is true of the code. These say what makes it true
# and how a reader checks it; a proposal has neither by construction, which is
# what makes it a proposal.
DECISION_SECTIONS = ("Решено", "Отхвърлено", "Причина", "Наложено от",
                     "Доказателство", "Възражение", "Преразглежда се когато")
PROPOSAL_SECTIONS = ("Предложено", "Възражение", "Става решение когато")

ENTRY = re.compile(r"^##\s+(D-\d{3}|P-\d{3})\s+·\s+(.+)$", re.M)
FIELD = re.compile(r"^\|\s*\*\*(.+?)\*\*\s*\|\s*(.+?)\s*\|$", re.M)
# The whole bold run, then trailing punctuation stripped. Matching up to the
# first space instead read `**Наложено от.**` as the section "Наложено", so
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


def parse(text: str) -> List[Entry]:
    marks = list(ENTRY.finditer(text))
    out = []
    for i, mark in enumerate(marks):
        end = marks[i + 1].start() if i + 1 < len(marks) else len(text)
        out.append(Entry(mark.group(1), mark.group(2), text[mark.end():end]))
    return out


def _section_present(entry: Entry, name: str) -> bool:
    # The heading is written as `**Решено.**` or `**Доказателство,** и то ...`,
    # so a prefix match is what the document actually contains. Matching the
    # whole line would pass for any entry and check nothing.
    return any(s == name or s.startswith(name) for s in entry.sections)


def check(text: str, run_tests: bool) -> List[str]:
    entries = parse(text)
    problems: List[str] = []

    if not entries:
        return ["no entries found — the heading format changed and this "
                "checker is now reading nothing, which passes vacuously"]

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

        state = entry.fields.get("Състояние", "")
        if state and state not in states:
            problems.append(
                "{}: state {!r} is not one of {} — a state carrying its own "
                "explanation cannot be read by anything".format(
                    entry.id, state, ", ".join(sorted(states))))

        for name in want_sections:
            if not _section_present(entry, name):
                problems.append("{}: no **{}** section".format(entry.id, name))

        commit = entry.fields.get("Проверено срещу", "")
        if commit and not COMMIT.match(commit):
            problems.append("{}: {!r} is not a commit".format(entry.id, commit))
        elif commit:
            proc = subprocess.run(("git", "cat-file", "-e", commit + "^{commit}"),
                                  cwd=ROOT, capture_output=True, check=False)
            if proc.returncode != 0:
                problems.append(
                    "{}: commit {} is not in this repository".format(
                        entry.id, commit))

        problems += _check_supersession(entry, seen)
        problems += _check_references(entry, run_tests)

    return problems


def _check_supersession(entry: Entry, seen: Dict[str, Entry]) -> List[str]:
    """Both directions, or the first replacement leaves two live decisions.

    Untested until something is actually superseded, which is why the rules are
    written down now rather than the first time one is: the entry that replaces
    another will be written months from now by someone with none of this in
    mind.
    """
    problems = []
    state = entry.fields.get("Състояние", "")
    replaces = entry.fields.get("Заменя", "")
    replaced_by = entry.fields.get("Заменено от", "")

    if state == "заменено" and not replaced_by:
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
        elif successor.fields.get("Заменя") != entry.id:
            problems.append(
                "{}: says {} replaces it, and {} does not say so back".format(
                    entry.id, replaced_by, replaced_by))
        if state != "заменено":
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
    if not entry.is_proposal and entry.fields.get("Произлиза от", "").startswith("P-"):
        origin = entry.fields["Произлиза от"]
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
