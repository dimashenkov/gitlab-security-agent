"""Every setting the documentation offers has to be one the code implements.

`SECURITY_SCAN_CONTEXT_LINES` was documented in the README, read from the
environment, stored on `Config`, and consulted by nothing. An operator could set
it, get no warning, and believe the review had changed. It was found by running
`tools/unenforced.py` by hand on 2026-08-31; nothing would have found the next
one.

Two directions, because they fail differently. A variable the docs promise and
the code ignores is a control that does not exist. A variable the code reads and
the docs never mention is a control nobody can find — less harmful, and still
a thing that gets rediscovered by grep years later.

This does not check that a setting *works*, only that both halves know about it.
The stronger question — is it read, or merely recorded — is
`tools/unenforced.py`, which lists any `Config` field nothing outside
`config.py` reads.
"""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src" / "security_agent"

DOCS = (
    "README.md",
    "LIMITATIONS.md",
    "templates/security-scan.yml",
    "templates/github-actions.yml",
    "skills/security-review-in-ci/SKILL.md",
    ".gitlab-ci.yml",
)

# Variables the CI system evaluates itself, so no Python ever reads them. Each
# entry names where the evaluation happens, because "the pipeline handles it" is
# the sentence a dead setting would also come wrapped in.
EVALUATED_BY_CI = {
    "SECURITY_SCAN_FULL":
        "templates/security-scan.yml — a GitLab `rules:` expression, "
        "`$CI_PIPELINE_SOURCE == \"schedule\" && $SECURITY_SCAN_FULL`",
}

PATTERN = re.compile(r"\bSECURITY_SCAN_[A-Z0-9_]+")


def _named_in(paths) -> dict:
    found: dict = {}
    for rel in paths:
        path = ROOT / rel
        if not path.is_file():
            continue
        for name in PATTERN.findall(path.read_text(encoding="utf-8")):
            found.setdefault(name, set()).add(rel)
    return found


def documented() -> dict:
    return _named_in(DOCS)


def in_code() -> set:
    names: set = set()
    for path in SRC.glob("*.py"):
        names |= set(PATTERN.findall(path.read_text(encoding="utf-8")))
    return names


class TestDocumentedSettingsExist:
    def test_every_documented_variable_is_read_somewhere(self):
        """The `diff_context_lines` shape: promised, and not implemented."""
        missing = {name: sorted(where) for name, where in documented().items()
                   if name not in in_code() and name not in EVALUATED_BY_CI}
        assert not missing, (
            "documented and read by no source file — either wire it or remove "
            "the documentation; if a CI system evaluates it, add it to "
            "EVALUATED_BY_CI with the file and the expression: {}".format(missing))

    def test_every_ci_evaluated_variable_is_still_documented(self):
        """An exemption for a variable nobody mentions is an exemption for
        nothing, and would quietly outlive whatever it excused."""
        docs = documented()
        stale = sorted(name for name in EVALUATED_BY_CI if name not in docs)
        assert not stale, (
            "exempted as CI-evaluated and named in no document: {}".format(stale))

    def test_every_ci_evaluated_variable_is_absent_from_the_code(self):
        """If the code starts reading one, the exemption is hiding a real
        reader and the next dead setting could take shelter behind it."""
        overlapping = sorted(set(EVALUATED_BY_CI) & in_code())
        assert not overlapping, (
            "exempted as CI-evaluated and read by the code after all; remove "
            "the exemption: {}".format(overlapping))


class TestCodeSettingsAreDocumented:
    def test_every_variable_the_code_reads_is_written_down(self):
        undocumented = sorted(in_code() - set(documented()))
        assert not undocumented, (
            "read by the code and documented nowhere: {}".format(undocumented))


class TestTheCheckItself:
    """A check that finds nothing because it looks nowhere passes forever."""

    def test_it_is_actually_reading_the_documents(self):
        assert len(documented()) > 20

    def test_it_is_actually_reading_the_source(self):
        assert len(in_code()) > 20

    def test_the_two_sets_overlap(self):
        assert len(set(documented()) & in_code()) > 20
