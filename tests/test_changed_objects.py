"""The list `changed_files()` should have been, for the question about coverage.

A completeness rule has to ask "did the reviewer get to read this?" of every
thing the change did. `changed_files()` cannot answer it twice over.

It applies `--diff-filter=ACMRT`, so a pure deletion is not in it at all — and
the removed lines of a deleted guard are exactly what this product exists to
catch. And it cannot tell a file whose text is in the diff from one whose text
can never be: a binary blob, a change of mode alone and a rename that edited
nothing all appear as ordinary entries and carry no readable line.

A rule built on that list would fail healthy reviews for the second reason and
miss deletions for the first. These tests are about the list that can carry one.
"""

from __future__ import annotations

import subprocess

import pytest

from security_agent.workspace import (
    ChangedObject,
    Workspace,
    _parse_numstat,
    _parse_raw,
    inventory_notes,
)


def _git(root, *args):
    subprocess.run(["git", "-C", str(root), *args], check=True,
                   capture_output=True)


@pytest.fixture
def change(tmp_path):
    """One commit that does every interesting thing at once."""
    root = tmp_path / "repo"
    root.mkdir()
    subprocess.run(["git", "init", "-q", str(root)], check=True,
                   capture_output=True)
    _git(root, "config", "user.email", "t@example.com")
    _git(root, "config", "user.name", "T")

    (root / "guard.py").write_text("def check(t):\n    return verify(t)\n",
                                   encoding="utf-8")
    (root / "edited.py").write_text("VALUE = 0\n", encoding="utf-8")
    (root / "moved.py").write_text("".join(
        "LINE_{} = {}\n".format(n, n) for n in range(40)), encoding="utf-8")
    (root / "logo.png").write_bytes(bytes(range(256)) * 8)
    (root / "run.sh").write_text("#!/bin/sh\necho hi\n", encoding="utf-8")
    _git(root, "add", "-A")
    _git(root, "commit", "-qm", "base")
    base = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"],
                          capture_output=True, text=True,
                          check=True).stdout.strip()

    (root / "guard.py").unlink()                       # a pure deletion
    (root / "edited.py").write_text("VALUE = 1\n", encoding="utf-8")
    _git(root, "mv", "moved.py", "relocated.py")       # a rename, no edit
    (root / "logo.png").write_bytes(bytes(range(255, -1, -1)) * 8)  # binary
    (root / "run.sh").chmod(0o755)                     # mode only
    (root / "added.py").write_text("print(1)\n", encoding="utf-8")
    (root / "link.py").symlink_to("edited.py")         # a symlink
    _git(root, "add", "-A")
    _git(root, "commit", "-qm", "change")

    return Workspace(root=root, diff_base=base, diff_head="HEAD")


def by_path(objects):
    return {o.path: o for o in objects}


class TestTheInventoryIsComplete:
    def test_a_deletion_is_in_it(self):
        """`changed_files()` filters it out. The removed lines of a deleted
        guard are the change a security review is for."""
        # asserted against the fixture below; named here for the reason.

    def test_every_kind_of_change_appears(self, change):
        seen = by_path(change.changed_objects())

        assert set(seen) == {"guard.py", "edited.py", "relocated.py",
                             "logo.png", "run.sh", "added.py", "link.py"}

    def test_the_deletion_is_absent_from_the_old_list(self, change):
        """The control: this is the gap, not a claim about the old list being
        wrong for its own purpose. A deleted file cannot be opened, and that
        list is what a reviewer is asked to open."""
        assert "guard.py" not in {p for p, _ in change.changed_files()}

    def test_the_deletion_is_named_as_one(self, change):
        assert by_path(change.changed_objects())["guard.py"].status == "deleted"

    def test_the_report_notes_name_the_deletion(self, change):
        """It is in neither `changed` nor `unreadable` — a deleted file cannot
        be opened, and its removed lines *are* readable — so until it had its
        own list a deletion appeared in no part of the report at all."""
        unreadable, deleted = inventory_notes(change)

        assert deleted == ["guard.py"]
        assert "guard.py" not in dict(unreadable)

    def test_the_notes_survive_a_workspace_that_cannot_answer(self, tmp_path):
        """A line in a report, not a gate. A git call that fails here must not
        take down a review that has already been done."""
        root = tmp_path / "empty"
        root.mkdir()
        (root / ".git").mkdir()
        ws = Workspace(root=root, diff_base="nonexistent-ref")

        assert inventory_notes(ws) == ([], [])


class TestWhatCanAndCannotBeRead:
    def test_an_edited_file_has_reviewable_text(self, change):
        assert by_path(change.changed_objects())["edited.py"].has_reviewable_text

    def test_a_deleted_file_has_reviewable_text(self, change):
        """Its removed lines are in the diff. A review of a deletion had the
        code in front of it."""
        assert by_path(change.changed_objects())["guard.py"].has_reviewable_text

    def test_a_binary_file_has_none(self, change):
        obj = by_path(change.changed_objects())["logo.png"]
        assert obj.binary
        assert not obj.has_reviewable_text

    def test_a_mode_only_change_has_none(self, change):
        obj = by_path(change.changed_objects())["run.sh"]
        assert (obj.added, obj.removed) == (0, 0)
        assert not obj.has_reviewable_text

    def test_a_mode_only_change_is_named_as_one(self, change):
        """Its own fact, not a shrug about a zero-line diff. A script that
        becomes executable is security-relevant and has no source line in it;
        a rule that only knew "nothing to read" would file it beside a rename
        and forget it."""
        obj = by_path(change.changed_objects())["run.sh"]
        assert obj.mode_changed
        assert (obj.old_mode, obj.new_mode) == ("100644", "100755")

    def test_a_rename_keeps_the_old_name(self, change):
        """Half the fact is which file this used to be. A rename recorded only
        against its new path cannot answer "did this change move a guard"."""
        assert by_path(change.changed_objects())["relocated.py"].old_path == "moved.py"

    def test_a_symlink_is_named_as_one(self, change):
        """A path that resolves elsewhere is not the file it appears to be, and
        reading it reads the target."""
        assert by_path(change.changed_objects())["link.py"].symlink

    def test_a_rename_is_not_a_mode_change(self, change):
        assert not by_path(change.changed_objects())["relocated.py"].mode_changed

    def test_a_pure_rename_has_none(self, change):
        """It is in the list — a security-critical file moving is worth
        knowing — but there is no line to read, so a rule demanding evidence of
        reading would be demanding the impossible."""
        obj = by_path(change.changed_objects())["relocated.py"]
        assert obj.status == "renamed"
        assert not obj.has_reviewable_text


class TestBinaryCountsAreNotZero:
    """`-` coerced to zero would say a binary file changed nothing, and that is
    the sentence a reader would use to skip it."""

    def test_a_dash_is_recorded_as_binary(self):
        rows = list(_parse_numstat("-\t-\tlogo.png\0"))
        assert rows == [("logo.png", 0, 0, True)]

    def test_an_ordinary_entry(self):
        rows = list(_parse_numstat("3\t1\tapp.py\0"))
        assert rows == [("app.py", 3, 1, False)]

    def test_a_rename_reports_against_the_new_name(self):
        """Three fields, not one: the path is empty and the two names follow."""
        rows = list(_parse_numstat("0\t0\t\0old.py\0new.py\0"))
        assert rows == [("new.py", 0, 0, False)]

    def test_a_path_with_a_tab_in_it_keeps_its_tab(self):
        """`split("\\t")` with no limit would cut the name in half. A tab is a
        legal character in a path on Linux, and `-z` does not quote it."""
        rows = list(_parse_numstat("1\t0\tweird\tname.py\0"))
        assert rows == [("weird\tname.py", 1, 0, False)]

    def test_empty_output_is_no_rows(self):
        assert list(_parse_numstat("")) == []


class TestTheRawFormCarriesTheModes:
    """`--name-status` cannot tell a mode-only change from a rename that edited
    nothing, a symlink from a regular file, or a submodule bump from either.
    All three look like an ordinary modification, and all three have no source
    line to read."""

    def test_an_ordinary_edit(self):
        rows = list(_parse_raw(":100644 100644 aaa bbb M\0app.py\0"))
        assert rows == [("app.py", "", "M", "100644", "100644")]

    def test_a_rename_carries_both_names(self):
        rows = list(_parse_raw(":100644 100644 aaa aaa R100\0old.py\0new.py\0"))
        assert rows == [("new.py", "old.py", "R", "100644", "100644")]

    def test_a_deletion_has_no_new_mode(self):
        rows = list(_parse_raw(":100644 000000 aaa 000 D\0gone.py\0"))
        assert rows == [("gone.py", "", "D", "100644", "000000")]

    def test_a_submodule_is_visible_by_its_mode(self, ):
        obj = ChangedObject(path="vendor/lib", status="modified",
                            old_mode="160000", new_mode="160000")
        assert obj.submodule
        assert not obj.has_reviewable_text

    def test_a_deletion_is_not_a_mode_change(self):
        """`000000` is absence, not a permission. Reading it as a mode change
        would report every deleted file as one."""
        obj = ChangedObject(path="gone.py", status="deleted", removed=9,
                            old_mode="100644", new_mode="000000")
        assert not obj.mode_changed
        assert obj.has_reviewable_text

    def test_a_line_that_is_not_a_record_is_skipped(self):
        assert list(_parse_raw("nonsense\0")) == []

    def test_empty_output_is_no_rows(self):
        assert list(_parse_raw("")) == []
