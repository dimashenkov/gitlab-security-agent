#!/usr/bin/env python3
"""Names this codebase defines, documents, and never reads anywhere else.

`Profile.conclusive` was written on the first day of stage 2 with a docstring
saying a profile carrying it must never be able to conclude a review. Nothing
outside `budget.py` ever read it. So `--profile probe` — six turns, no
verifiers, sized to stop early and documented as never conclusive — could call
`finish_review`, end `completed`, and exit 0. A flag that states a guarantee and
is read by nobody is worse than one that never claimed anything, because the
comment above it does the reassuring that the code is not doing.

It was found by a person opening the file, after nine review rounds had passed
over it. Those rounds could not have found it: they were given prose about what
the code did — *"`verifiers` is votes per candidate and is odd on purpose"* —
and reasoned from the sentence rather than from the file. A reviewer told what a
flag means will believe it. `grep` will not.

So this is that grep, kept.

    tools/unenforced.py                 # every suspicious name
    tools/unenforced.py --strict        # exit 1 if any are unexplained

**Dataclass fields only.** The first version also listed module constants and
returned a hundred and twenty-seven names, nearly all of them right: a threshold
applied ten lines below where it is declared *is* enforced, and "read only in its
own module" says nothing about it. A check whose output is mostly noise is a
check nobody runs twice, and this one is meant to be run before every audit.

A field is different. A field on a shared dataclass exists to be honoured by
other code — that is what putting it on the object is for — so one that nothing
outside its module reads is a policy the system was told about and does not
apply. That is exactly `conclusive`.

A name read only inside its own module is not automatically wrong. Plenty are
internal by design. What is wrong is a name whose *docstring makes a promise
about the system* and whose only reader is the file it lives in — and telling
those apart needs a person, which is why the unexplained ones are listed rather
than failed by default.

**A reader is any file that contains the word**, comments and docstrings
included, and that is coarser than it sounds. Two consequences, both real:

This file is one of the files searched, and its own docstring says
`conclusive` — the name it exists to find. So it counted itself as a reader and
was blind to its own example. Had the field not since acquired genuine readers
in `gate.py`, `models.py` and `runner_claude_code.py`, running this tool would
have reported that everything was fine. It excludes itself now; the general
version of the problem — prose about a name counting as use of it — stands, and
is the reason the output is a list for a person rather than a verdict.

`EXPLAINED` accepts a qualified key (`Profile.review_turns`) and a bare one
(`PROVIDER`). The bare form exempts every class's field of that name at once,
which was tolerable at nine entries and stopped being so at thirty-one, so
everything added since is qualified. The nine module-constant entries keep the
bare form because that is the shape they have.
"""

from __future__ import annotations

import argparse
import ast
import re
from pathlib import Path
from typing import Dict, List, Set, Tuple

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src" / "security_agent"

# Names that are read only in their own module and are meant to be. Each entry
# is a claim that somebody looked, so an unexplained name is a name nobody has.
EXPLAINED: Dict[str, str] = {
    "PROVIDER": "the runner's own identity string, written into the artifact",
    "SERVER_NAME": "the MCP server's name, sent in the handshake",
    "PROTOCOL_VERSION": "answered on `initialize`, compared against nothing",
    "DEFAULT_PROFILE": "the name a caller passes when it has no preference",
    "MAX_ARGS": "bounds one journal record, read where it is applied",
    "MAX_ARG_CHARS": "the same",
    "MAX_EXCERPT_CHARS": "the same",
    "MAX_TEXT_CHARS": "the same",
    "ABSENT": "re-exported sentinel; the tests are its readers",

    # Triaged 2026-08-31, all twenty-two read inside the module that declares
    # them and in no other. Each line is a claim that somebody opened the file,
    # which is the only thing that separates "internal by design" from "a
    # promise nobody keeps".

    # budget.py *is* the enforcement. A ceiling read where it is applied is
    # enforced; that is what these are. The field that started this tool,
    # `Profile.conclusive`, was different — it named a guarantee about the rest
    # of the system and only budget.py ever looked at it.
    "Profile.review_turns": "turn ceiling, applied in RunBudget.turn",
    "Profile.review_tool_calls": "the reviewer's allowance, applied on construction",
    "Profile.verifier_tool_calls": "one verifier's allowance, applied when it opens",
    "RunBudget.verifier_allowances": "the open verifier ledgers; summed for the total",
    "RunBudget.review_turns": "turns taken so far, compared against the profile",

    # A rendering structure. It is filled by the reader that parses a crashed
    # run's journal and consumed by the summary printed beside it, both here.
    "TracedCall.seq": "ordering within one crashed run's journal",
    "TracedResult.seq": "the same",
    "TracedFinding.seq": "the same",
    "TracedRejection.seq": "the same",
    "PartialTrace.foreign_runs": "counted while parsing, printed in the summary",
    "PartialTrace.disordered_sequence_numbers": "the same",
    "PartialTrace.last_record_at": "the same",
    "PartialTrace.records_read": "the same",
    "PartialTrace.unmatched_results": "the same",
    "PartialTrace.findings_claimed": "the same",
    "PartialTrace.claims_rejected": "the same",
    "PartialTrace.review_summary": "the same",
    "PartialTrace.verdict_reasoning": "the same",
    "PartialTrace.missing_sequence_numbers": "the same",

    # `ContextEvent` is built and consumed inside `context_budget.py`: `admit`
    # and `refuse` append one, `largest_result` reads them back to name the
    # heaviest single tool result. Nothing outside needs an event, and the
    # session document deliberately carries the counts without them — a run
    # that hit the ceiling repeatedly would otherwise send hundreds of lines
    # across a boundary whose purpose is to be small.
    "ContextEvent.estimated_tokens": "read by ContextBudget.largest_result",
    # `ChangedObject` answers about itself. `submodule`, `symlink`,
    # `mode_changed`, `has_reviewable_text` and `why_unreadable` all read these
    # in workspace.py, and what leaves the module is the rendered sentence —
    # "mode 100644 → 100755" — rather than the raw mode strings. The first
    # version of this check was right to flag them: they were declared while
    # the code that consumes them did not exist yet, and only stopped being a
    # promise nobody kept when `unreadable_objects` gave them a caller.
    # The running total of the *imagined* enforcing run, which exists so the
    # observing mode can report what enforcement would have refused rather than
    # what this run's own total happens to be past. Only `ContextBudget.shadow`
    # advances or reads it; what leaves the module is `would_refuse_results`.
    # It deliberately does not cross the session document: it is the state of a
    # simulation, not a fact about the review.
    "ContextBudget.shadow_tokens": "read by ContextBudget.shadow",
    "ChangedObject.old_path": "read by ChangedObject.why_unreadable",
    "ChangedObject.old_mode": "read by ChangedObject.mode_changed and .submodule",
    "ChangedObject.new_mode": "the same",
    "Capabilities.refusal_fallback": "read in agent.py where the call is built",
    "ChangedLines.removed_at": "read by ChangedLines' own helpers and by evidence.py",
    "Disposition.interaction": "carried through panel.py's own correction path",
}


def _defined(path: Path) -> List[Tuple[str, int, str]]:
    """(name, line, kind) for every dataclass field and module constant."""
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except (OSError, SyntaxError):
        return []

    found: List[Tuple[str, int, str]] = []
    for node in tree.body:
        if isinstance(node, ast.ClassDef):
            for item in node.body:
                if isinstance(item, ast.AnnAssign) and isinstance(item.target, ast.Name):
                    name = item.target.id
                    if not name.startswith("_"):
                        found.append(("{}.{}".format(node.name, name),
                                      item.lineno, "field"))
    return found


def _readers(name: str, home: Path, files: List[Path]) -> Set[str]:
    """Which other files mention this name at all."""
    bare = name.split(".")[-1]
    pattern = re.compile(r"\b{}\b".format(re.escape(bare)))
    seen = set()
    for path in files:
        if path == home:
            continue
        try:
            if pattern.search(path.read_text(encoding="utf-8")):
                seen.add(str(path.relative_to(ROOT)))
        except OSError:
            continue
    return seen


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--strict", action="store_true",
                        help="Exit 1 when an unexplained name is found.")
    parser.add_argument("--include-tests", action="store_true",
                        help="Count a mention in the tests as a reader. Off by "
                             "default: a field only the tests read is a field "
                             "the product does not act on, which is exactly "
                             "the shape being looked for.")
    args = parser.parse_args()

    sources = sorted(SRC.glob("*.py"))
    elsewhere = list(sources)
    if args.include_tests:
        elsewhere += sorted((ROOT / "tests").glob("*.py"))
    # Every tool except this one. A tool that reads a product field is a real
    # reader — `artifact.py` imports the product's evidence rule on purpose —
    # but this file's own docstring names `conclusive`, the field it was
    # written to catch, so counting itself made it blind to its own example.
    elsewhere += [p for p in sorted((ROOT / "tools").glob("*.py"))
                  if p.resolve() != Path(__file__).resolve()]

    rows = []
    for path in sources:
        for name, line, kind in _defined(path):
            # Qualified first, bare second. The bare form exempts every
            # class's field of that name at once, which was fine at nine
            # entries and is not at thirty-one; new entries are qualified and
            # the old module-constant ones keep working.
            if name in EXPLAINED or name.split(".")[-1] in EXPLAINED:
                continue
            if not _readers(name, path, elsewhere):
                rows.append((str(path.relative_to(ROOT)), line, name, kind))

    if not rows:
        print("Every declared name is read somewhere outside the file that "
              "declares it.")
        return 0

    print("Declared here and read nowhere else:\n")
    width = max(len(r[2]) for r in rows)
    for where, line, name, kind in rows:
        print("  {:<{w}}  {:<9}  {}:{}".format(name, kind, where, line, w=width))
    print("\n{} name(s). Each is either internal by design — add it to "
          "EXPLAINED with the reason — or a promise the code is not "
          "keeping.".format(len(rows)))
    return 1 if args.strict else 0


if __name__ == "__main__":
    raise SystemExit(main())
