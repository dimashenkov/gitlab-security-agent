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

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
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


class TestTheRealTreeStaysClean:
    """The check itself, against this repository, on every test run.

    `Config.diff_context_lines` was found on 2026-08-31 by someone running this
    tool by hand — a documented setting read from the environment, stored, and
    consulted by nothing. Nothing would have found the next one.

    Note what this catches that `test_documented_settings.py` cannot: that file
    asks whether a documented variable is *named* in the source, and
    `SECURITY_SCAN_CONTEXT_LINES` was named — in the line that read it into a
    field nobody used. The two checks are not redundant; the other one would
    have passed throughout.

    A failure here is not necessarily a bug. It is a field nobody has looked at,
    and the fix is either to wire it or to add it to `EXPLAINED` with the reason
    it is internal by design.
    """

    def test_no_unexplained_field_remains(self, monkeypatch, capsys):
        monkeypatch.setattr(unenforced, "ROOT", ROOT)
        monkeypatch.setattr(unenforced, "SRC", ROOT / "src" / "security_agent")
        monkeypatch.setattr(sys, "argv", ["unenforced.py", "--strict"])
        code = unenforced.main()
        assert code == 0, capsys.readouterr().out

    def test_every_explained_name_still_exists(self):
        """A suppression outliving its field silences a name nobody declared,
        and would sit there ready to excuse a future one that shares it."""
        declared = set()
        for path in (ROOT / "src" / "security_agent").glob("*.py"):
            for name, _line, _kind in unenforced._defined(path):
                declared.add(name)
                declared.add(name.split(".")[-1])
        # The nine bare module-constant entries predate `_defined` narrowing to
        # fields and are not declared as fields anywhere; they are listed here
        # so a genuinely stale entry still shows up.
        legacy = {"PROVIDER", "SERVER_NAME", "PROTOCOL_VERSION", "DEFAULT_PROFILE",
                  "MAX_ARGS", "MAX_ARG_CHARS", "MAX_EXCERPT_CHARS",
                  "MAX_TEXT_CHARS", "ABSENT"}
        stale = sorted(set(unenforced.EXPLAINED) - declared - legacy)
        assert not stale, "EXPLAINED names a field that no longer exists: {}".format(stale)


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
