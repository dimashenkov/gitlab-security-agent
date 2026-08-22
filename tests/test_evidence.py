"""Tests for the deterministic half of the hallucination check.

These matter more than they look. `locate_evidence` is the one thing standing
between a confidently-worded description of code that does not exist and a
blocked merge request, so both directions are load-bearing: it must find real
code despite formatting differences, and it must not find code that isn't there.
"""

from security_agent.evidence import (
    ChangedLines,
    changed_lines,
    evidence_span,
    excerpt,
    locate_evidence,
    normalize,
    touches_change,
)

SOURCE = '''\
import os


def get_user(request):
    user_id = request.args.get("id")
    query = "SELECT * FROM users WHERE id = " + user_id
    return db.execute(query)


def safe_lookup(request, db):
    return db.execute("SELECT * FROM users WHERE id = ?", (request.args["id"],))
'''


class TestLocateEvidence:
    def test_finds_an_exact_single_line(self):
        assert locate_evidence(SOURCE, 'query = "SELECT * FROM users WHERE id = " + user_id') == 6

    def test_finds_a_multi_line_block(self):
        evidence = (
            '    user_id = request.args.get("id")\n'
            '    query = "SELECT * FROM users WHERE id = " + user_id'
        )
        assert locate_evidence(SOURCE, evidence) == 5

    def test_ignores_indentation_differences(self):
        # The model routinely re-indents when quoting; that is not a hallucination.
        assert locate_evidence(SOURCE, 'query   =  "SELECT * FROM users WHERE id = "   + user_id') == 6

    def test_tolerates_diff_markers(self):
        evidence = '+    query = "SELECT * FROM users WHERE id = " + user_id'
        assert locate_evidence(SOURCE, evidence) == 6

    def test_matches_a_clipped_fragment_of_a_long_line(self):
        assert locate_evidence(SOURCE, "SELECT * FROM users WHERE id = ") is not None

    def test_rejects_code_that_is_not_there(self):
        assert locate_evidence(SOURCE, 'os.system("rm -rf " + user_input)') is None

    def test_rejects_a_paraphrase(self):
        # Same meaning, different code. This is the failure mode the check exists
        # for, and tolerating it would defeat the whole layer.
        assert locate_evidence(SOURCE, 'query = f"SELECT * FROM users WHERE id = {user_id}"') is None

    def test_rejects_lines_that_exist_but_not_consecutively(self):
        evidence = "import os\n    return db.execute(query)"
        assert locate_evidence(SOURCE, evidence) is None

    def test_empty_evidence_is_not_a_match(self):
        assert locate_evidence(SOURCE, "") is None
        assert locate_evidence(SOURCE, "   \n  \n") is None

    def test_empty_file_is_not_a_match(self):
        assert locate_evidence("", "anything") is None


class TestNormalize:
    def test_collapses_all_whitespace(self):
        assert normalize("  a\t b   c  ") == "a b c"


class TestEvidenceSpan:
    def test_counts_non_empty_lines(self):
        assert evidence_span("one\n\ntwo\n") == 2

    def test_never_returns_zero(self):
        assert evidence_span("") == 1


DIFF = '''\
diff --git a/app/views.py b/app/views.py
index 1111111..2222222 100644
--- a/app/views.py
+++ b/app/views.py
@@ -10,6 +10,8 @@ def index():
     return render(request)


+def get_user(request):
+    return db.execute("SELECT * FROM users WHERE id = " + request.args["id"])
+
 def other():
     pass
diff --git a/README.md b/README.md
--- a/README.md
+++ b/README.md
@@ -1,2 +1,3 @@
 # Project
+A new line.
 Existing text.
'''


class TestChangedLines:
    def test_maps_each_file_to_its_changed_lines(self):
        result = changed_lines(DIFF)
        assert result.added["app/views.py"] == {13, 14, 15}
        assert result.added["README.md"] == {2}

    def test_ignores_the_file_header_plus_signs(self):
        # `+++ b/path` starts with '+' but is not an added line; counting it
        # would shift every line number in the file by one.
        assert 0 not in changed_lines(DIFF).added["app/views.py"]

    def test_handles_a_deleted_file(self):
        diff = "--- a/gone.py\n+++ /dev/null\n@@ -1,2 +0,0 @@\n-x = 1\n-y = 2\n"
        assert not changed_lines(diff)

    def test_empty_diff(self):
        assert not changed_lines("")


CHANGED = ChangedLines(added={"app/views.py": {13, 14, 15}}, removed_at={})


class TestTouchesChange:

    def test_true_on_an_added_line(self):
        assert touches_change("app/views.py", 14, 1, CHANGED)

    def test_true_just_outside_within_slack(self):
        # A weakness is often introduced by an added line a little above the sink.
        assert touches_change("app/views.py", 17, 1, CHANGED, slack=3)

    def test_false_far_from_the_change(self):
        assert not touches_change("app/views.py", 400, 1, CHANGED)

    def test_false_for_a_file_not_in_the_diff(self):
        assert not touches_change("app/models.py", 14, 1, CHANGED)

    def test_false_when_there_is_no_diff_at_all(self):
        assert not touches_change("app/views.py", 14, 1, ChangedLines())


class TestExcerpt:
    def test_returns_a_numbered_window(self):
        body, start, stop = excerpt(SOURCE, 6, radius=1)
        assert start == 5 and stop == 7
        assert "6 |" in body

    def test_clamps_to_the_file(self):
        _, start, stop = excerpt(SOURCE, 1, radius=100)
        assert start == 1
        assert stop == len(SOURCE.splitlines())

    def test_handles_an_empty_file(self):
        assert excerpt("", 5) == ("", 0, 0)


DELETION_ONLY_DIFF = '''\
diff --git a/git/refs/symbolic.py b/git/refs/symbolic.py
--- a/git/refs/symbolic.py
+++ b/git/refs/symbolic.py
@@ -168,8 +168,6 @@ class SymbolicReference(object):
         """Return: (str(sha), str(target_ref_path)) if available."""
-        if ".." in str(ref_path):
-            raise ValueError(f"Invalid reference '{ref_path}'")
         tokens: Union[None, List[str], Tuple[str, str]] = None
         repodir = _git_dir(repo, ref_path)
'''


class TestDeletionsAreAttributed:
    """A change that only removes lines is still that change's responsibility.

    Counting added lines alone is the obvious implementation and it is wrong:
    removing a security control produces a diff with no added lines at all. A
    real merge request reverting GitPython's CVE-2023-41040 guard was found and
    confirmed by the agent, then waved through as "pre-existing" — the finding
    was right and the attribution threw it away.
    """

    def test_a_deletion_only_diff_is_not_empty(self):
        result = changed_lines(DELETION_ONLY_DIFF)
        assert result.removed_at["git/refs/symbolic.py"], "a pure deletion attributed nothing"

    def test_the_deletion_anchors_where_the_code_was_removed(self):
        # Hunk starts at new-side 168; one context line precedes the deletions.
        assert changed_lines(DELETION_ONLY_DIFF).removed_at["git/refs/symbolic.py"] == {169}

    def test_a_finding_beside_the_deletion_is_attributed_to_the_change(self):
        changed = changed_lines(DELETION_ONLY_DIFF)
        # The sink sits a couple of lines below where the guard used to be.
        assert touches_change("git/refs/symbolic.py", 171, 1, changed)

    def test_a_finding_far_from_the_deletion_is_not(self):
        changed = changed_lines(DELETION_ONLY_DIFF)
        assert not touches_change("git/refs/symbolic.py", 900, 1, changed)

    def test_additions_and_deletions_are_both_counted(self):
        diff = ("--- a/x.py\n+++ b/x.py\n@@ -10,3 +10,3 @@\n"
                " keep\n-old_line\n+new_line\n keep\n")
        c = changed_lines(diff)
        assert c.added["x.py"] == {11} and c.removed_at["x.py"] == {11}

    def test_a_deletion_at_the_top_of_a_file_does_not_anchor_to_zero(self):
        diff = "--- a/x.py\n+++ b/x.py\n@@ -1,2 +0,0 @@\n-first\n-second\n"
        assert changed_lines(diff).removed_at["x.py"] == {1}


class TestDeletionReachIsAsymmetric:
    """A removed guard protects what comes after it, never what came before.

    So a deletion reaches downward much further than an addition does, and
    barely upward at all. The numbers come from the case that exposed this: the
    GitPython sink sat four lines below the deleted `..` check, which a
    symmetric three-line window missed by one.
    """

    changed = ChangedLines(added={}, removed_at={"a.py": {100}})

    def test_reaches_well_below_the_deletion(self):
        assert touches_change("a.py", 112, 1, self.changed)

    def test_stops_eventually(self):
        assert not touches_change("a.py", 130, 1, self.changed)

    def test_barely_reaches_above(self):
        assert touches_change("a.py", 98, 1, self.changed)
        assert not touches_change("a.py", 90, 1, self.changed)

    def test_additions_stay_symmetric_and_tight(self):
        added = ChangedLines(added={"a.py": {100}}, removed_at={})
        assert touches_change("a.py", 103, 1, added)
        assert touches_change("a.py", 97, 1, added)
        assert not touches_change("a.py", 112, 1, added)

    def test_a_multi_line_finding_counts_its_whole_span(self):
        added = ChangedLines(added={"a.py": {100}}, removed_at={})
        # A five-line quote starting at 94 ends at 98, within slack of 100.
        assert touches_change("a.py", 94, 5, added)
