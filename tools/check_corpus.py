#!/usr/bin/env python3
"""Is the corpus able to measure what it claims to?

Free, deterministic, and belongs in CI, because every defect it checks for was
found by hand after a paid run had already been scored against it.

    tools/check_corpus.py corpus/ corpus-real/

Each check exists because it did not exist.

**The category must be one the agent can emit.** The schema holds one list of
category names and there was a second list in my head. They did not match, so
`authorization`, `path_traversal` and `open_redirect` were scored against for
seven cases the agent could never have passed. The test that should have caught
it asserted against a set typed from the same wrong assumption.

**The target must name every file the fix touched.** The harvester recorded the
first changed path and called it the target. Winter's CSRF fix normalises a
name in `BackendController.php` and rejects the bad ones in `Controller.php`,
and the manifest named the file without the check in it — so a review that
found the actual check was scored as finding it in the wrong place. Twenty of
forty-eight manifests were wrong this way, and nothing said so.

**The target must exist.** A path that matches nothing scores every run as a
miss, silently and forever.

**The members must differ.** Two identical members measure nothing, and a
harvest that dropped the decisive file produces exactly that.

**The advisory must not be named in the code.** A case that carries `GHSA-…` or
`CVE-…` in a comment is answerable without reading anything.

Exit 0 means checked and clean, 1 means a case is broken, 2 means the check
could not run — the same three states the product uses, for the same reason.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from artifact import target_categories, target_paths
from strip_comments import STRIPPED, UNCHANGED, strip_comments_report

from security_agent.vocabulary import VocabularyError, categories

MEMBERS = ("safe", "unsafe")

# An advisory identifier anywhere in the reviewed code is the answer key.
LEAK = re.compile(r"CVE-\d{4}-\d{4,7}|GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}",
                  re.IGNORECASE)


def changed_files(case_dir: Path, member: str) -> set:
    change = case_dir / member / "change"
    if not change.is_dir():
        return set()
    return {str(p.relative_to(change)) for p in change.rglob("*") if p.is_file()}


def member_bytes(case_dir: Path, member: str) -> dict:
    change = case_dir / member / "change"
    if not change.is_dir():
        return {}
    return {str(p.relative_to(change)): p.read_bytes()
            for p in change.rglob("*") if p.is_file()}


def check_case(case_dir: Path, vocabulary: set) -> list:
    """Every complaint about one case. Empty means it can measure something."""
    problems = []
    manifest = case_dir / "case.yml"
    try:
        spec = yaml.safe_load(manifest.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:
        return ["case.yml does not parse: {}".format(exc)]

    for member in MEMBERS:
        if not (case_dir / member).is_dir():
            problems.append("no {}/ directory".format(member))
    if problems:
        return problems

    # The category the case is scored against has to be one the agent can
    # produce. Otherwise the case is a guaranteed miss and reads as a failure
    # of the reviewer.
    wanted_categories = target_categories(spec)
    if not wanted_categories:
        problems.append(
            "no expected_category — every finding in the target file counts as "
            "the weakness, which is a looser case than the table implies")
    for category in wanted_categories:
        if category not in vocabulary:
            problems.append(
                "expected_category {!r} is not in the schema: the agent cannot "
                "emit it, so this case can only ever be a miss. Known: {}".format(
                    category, ", ".join(sorted(vocabulary))))

    changed = {m: changed_files(case_dir, m) for m in MEMBERS}
    every_changed = changed["safe"] | changed["unsafe"]
    wanted = set(target_paths(spec))

    if not wanted:
        problems.append("no expected_file — every finding counts as the target")
    else:
        missing = sorted(p for p in wanted if p not in every_changed)
        if missing:
            problems.append(
                "expected_file names {} which no member changes; a path that "
                "matches nothing scores every run as a miss".format(
                    ", ".join(missing)))
        # A file byte-identical in both members cannot be the decisive control
        # — it is the same code on both sides — so it cannot be the target and
        # does not need listing. `go-sql-decoy-01` adds a `routes.go` that is
        # identical in safe and unsafe: it puts the middleware genuinely on the
        # call path, which both members need, and it is not what either member
        # is about. Requiring it in `expected_file` would widen the target to a
        # file where a finding would be neither expected nor wrong.
        safe_bytes = member_bytes(case_dir, "safe")
        unsafe_bytes = member_bytes(case_dir, "unsafe")
        identical = {p for p in every_changed
                     if safe_bytes.get(p) is not None
                     and safe_bytes.get(p) == unsafe_bytes.get(p)}
        unlisted = sorted(p for p in every_changed
                          if p not in wanted and p not in identical)
        if unlisted:
            problems.append(
                "the fix also touches {} which expected_file does not list; a "
                "finding there would be scored as the wrong place".format(
                    ", ".join(unlisted)))

    if not every_changed:
        problems.append("neither member has a change/ directory — nothing to review")
    elif member_bytes(case_dir, "safe") == member_bytes(case_dir, "unsafe"):
        problems.append(
            "the two members are byte-identical: there is no difference to "
            "discriminate, and every run scores the same on both")

    # A file the stripper could not read still carries the maintainer's prose,
    # and inside `change/` that prose is on the reviewed side of a fix — which
    # is the answer key this corpus exists to remove. It is refused rather than
    # patched, deliberately (`strip_comments.py`), and refusing loudly is only
    # safe if something downstream then refuses to ship it. Nothing did.
    #
    # Harvested cases only, and the line is `source_advisory`. A hand-written
    # case has no maintainer: its author wrote both members and can make the
    # prose identical between them, which `corpus/ts-xss-01` does — the same
    # two comment lines on each side, saying nothing about the fix, so there is
    # no side to read off them. It is a `.tsx` file the stripper declines for
    # its own safety, and failing it here would be failing a case for a
    # property it does not have.
    #
    # Two cases reached the corpus this way. `js-w93q-cq9w-58p7` held a file
    # with JSX in it, the stripper declined, and the safe member arrived with
    # 14 comment lines against the unsafe member's 13 — caught, but only
    # because the leak happened to be in comment syntax. `py-mv8m-v9v6-5f94`
    # held a `.rst` whose note says the fix "disables ssh host key checking …
    # does not apply it in local environments, starting with kas 5.4", and
    # nothing saw it: `corpus_adversary.py` counts comment lines, and reStructured
    # Text has no comment marker it counts. The cue was invisible by
    # construction, which is the worst kind to rely on a symptom for.
    for member in ("safe", "unsafe") if spec.get("source_advisory") else ():
        change = case_dir / member / "change"
        for path in sorted(change.rglob("*")) if change.is_dir() else ():
            if not path.is_file():
                continue
            try:
                body = path.read_text(encoding="utf-8")
            except (UnicodeDecodeError, OSError):
                problems.append("{} cannot be read as text, so nothing has "
                                "stripped it".format(path.relative_to(case_dir)))
                continue
            _text, status = strip_comments_report(body, path.suffix)
            if status not in (STRIPPED, UNCHANGED):
                problems.append(
                    "{} was not stripped ({}) and is in the reviewed change, "
                    "so the maintainer's prose about the fix is on the safe "
                    "side".format(path.relative_to(case_dir), status))

    for path in sorted(case_dir.rglob("*")):
        if not path.is_file() or path.name == "case.yml":
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        found = LEAK.findall(text)
        if found:
            problems.append("{} names the advisory ({}) — the answer is in the "
                            "code".format(path.relative_to(case_dir), found[0]))
            break

    return problems


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("roots", nargs="+")
    args = parser.parse_args()

    try:
        vocabulary = set(categories())
    except VocabularyError as exc:
        print("cannot read the category schema: {}".format(exc), file=sys.stderr)
        return 2

    manifests = []
    for root in args.roots:
        path = Path(root)
        if not path.is_dir():
            print("no such directory: {}".format(root), file=sys.stderr)
            return 2
        manifests += sorted(path.rglob("case.yml"))
    if not manifests:
        print("no case.yml under {}".format(", ".join(args.roots)), file=sys.stderr)
        return 2

    broken = 0
    for manifest in manifests:
        problems = check_case(manifest.parent, vocabulary)
        if problems:
            broken += 1
            print("\n{}".format(manifest.parent.name))
            for problem in problems:
                print("  - {}".format(problem))

    print("\n{} case(s) checked, {} with problems.".format(len(manifests), broken))
    if broken:
        print("A case that cannot measure anything still produces a number, and "
              "the number is read as a statement about the reviewer.")
        return 1
    print("Every case names a category the agent can emit, targets the files "
          "its fix touches, and differs between members.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
