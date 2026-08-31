"""`tools/unenforced.py` was blind to the field it was written to find.

It lists dataclass fields that nothing outside their own module reads, because
`Profile.conclusive` carried a docstring promising a profile with it could never
conclude a review, and nothing ever read it — so `--profile probe` could sign off
and exit 0.

A reader, to this tool, is any file containing the word. `tools/` is among the
files searched, this file is in `tools/`, and its own docstring says
`conclusive`. So it counted itself and would have reported that all was well.
The field has genuine readers today, in `gate.py`, `models.py` and
`runner_claude_code.py`, which is the only reason the defect was invisible rather
than active.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

TOOLS = Path(__file__).resolve().parents[1] / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import unenforced  # noqa: E402


def write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


@pytest.fixture(autouse=True)
def rooted(tmp_path, monkeypatch):
    """`_readers` names its hits relative to ROOT and would raise otherwise.

    It catches `OSError` only, so a path outside the project raises ValueError
    out of `relative_to`. That cannot happen in the product — every file it is
    handed comes from globbing ROOT — so this points the root at the fixture
    rather than inventing a requirement the tool does not have.
    """
    monkeypatch.setattr(unenforced, "ROOT", tmp_path)


class TestItDoesNotCountItselfAsAReader:
    def test_a_tool_that_only_names_a_field_in_prose_is_still_a_reader(self, tmp_path):
        """The general case, stated so the narrower fix is not mistaken for it.

        Any file whose *comment* mentions the word counts. That is coarse and
        deliberate — the output is a list for a person, not a verdict — and it
        is why the self-exclusion below is a fix and not the whole answer.
        """
        home = write(tmp_path / "budget.py", "class Profile:\n    conclusive: bool\n")
        other = write(tmp_path / "notes.py", "# conclusive is mentioned here only\n")
        assert unenforced._readers("Profile.conclusive", home, [home, other])

    def test_the_checkers_own_text_does_not_count(self, tmp_path, monkeypatch):
        """The defect: this file's docstring names `conclusive`.

        Built as a corpus where the *only* other mention of the field is inside
        the checker itself. Before the fix that came back as "read somewhere
        else" and the field was never listed.
        """
        src = tmp_path / "src" / "security_agent"
        write(src / "budget.py",
              "from dataclasses import dataclass\n\n\n"
              "@dataclass\nclass Profile:\n"
              "    conclusive: bool = False\n")
        tools = tmp_path / "tools"
        write(tools / "unenforced.py",
              '"""A docstring that happens to say conclusive."""\n')

        monkeypatch.setattr(unenforced, "ROOT", tmp_path)
        monkeypatch.setattr(unenforced, "SRC", src)
        monkeypatch.setattr(unenforced, "__file__", str(tools / "unenforced.py"))
        monkeypatch.setattr(sys, "argv", ["unenforced.py", "--strict"])

        assert unenforced.main() == 1


class TestWhatCountsAsDeclared:
    def test_a_dataclass_field_is_declared(self, tmp_path):
        home = write(tmp_path / "m.py", "class C:\n    field: int = 1\n")
        assert ("C.field", 2, "field") in unenforced._defined(home)

    def test_a_private_field_is_not(self, tmp_path):
        home = write(tmp_path / "m.py", "class C:\n    _field: int = 1\n")
        assert unenforced._defined(home) == []

    def test_a_plain_assignment_without_an_annotation_is_not(self, tmp_path):
        home = write(tmp_path / "m.py", "class C:\n    field = 1\n")
        assert unenforced._defined(home) == []

    def test_a_file_that_does_not_parse_yields_nothing_rather_than_raising(self, tmp_path):
        home = write(tmp_path / "m.py", "class C:\n  def (\n")
        assert unenforced._defined(home) == []


class TestReaders:
    def test_the_declaring_file_is_never_its_own_reader(self, tmp_path):
        home = write(tmp_path / "m.py",
                     "class C:\n    field: int = 1\n\n\nprint(C.field)\n")
        assert unenforced._readers("C.field", home, [home]) == set()

    def test_a_substring_is_not_a_match(self, tmp_path):
        """`\\b` on purpose: `fields` must not make `field` look read."""
        home = write(tmp_path / "m.py", "class C:\n    field: int = 1\n")
        other = write(tmp_path / "o.py", "fields = []\nmyfield = 2\n")
        assert unenforced._readers("C.field", home, [home, other]) == set()

    def test_an_unreadable_file_is_skipped_not_fatal(self, tmp_path):
        home = write(tmp_path / "m.py", "class C:\n    field: int = 1\n")
        assert unenforced._readers("C.field", home, [home, tmp_path / "gone.py"]) == set()
