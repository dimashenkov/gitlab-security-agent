"""Tests for the deterministic half of the hallucination check.

These matter more than they look. `locate_evidence` is the one thing standing
between a confidently-worded description of code that does not exist and a
blocked merge request, so both directions are load-bearing: it must find real
code despite formatting differences, and it must not find code that isn't there.
"""

import pytest

from security_agent.evidence import (
    ChangedLines,
    EvidenceProblem,
    changed_lines,
    evidence_span,
    excerpt,
    locate_evidence,
    normalize,
    touches_change,
)


def missing(file_text, evidence, claimed=0):
    """True when the quote cannot be tied to one place — the new failure mode."""
    try:
        locate_evidence(file_text, evidence, claimed)
        return False
    except EvidenceProblem:
        return True

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

    def test_a_clipped_fragment_matches_when_it_is_unique(self):
        assert locate_evidence(
            SOURCE, 'query = "SELECT * FROM users WHERE id = "') == 6

    def test_rejects_code_that_is_not_there(self):
        assert missing(SOURCE, 'os.system("rm -rf " + user_input)')

    def test_rejects_a_paraphrase(self):
        # Same meaning, different code. This is the failure mode the check exists
        # for, and tolerating it would defeat the whole layer.
        assert missing(SOURCE, 'query = f"SELECT * FROM users WHERE id = {user_id}"')

    def test_rejects_lines_that_exist_but_not_consecutively(self):
        evidence = "import os\n    return db.execute(query)"
        assert missing(SOURCE, evidence)

    def test_empty_evidence_is_not_a_match(self):
        assert missing(SOURCE, "")
        assert missing(SOURCE, "   \n  \n")

    def test_empty_file_is_not_a_match(self):
        assert missing("", "anything")


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

    def test_a_header_inside_a_hunk_is_content(self):
        """The neighbour of the test above, and the one it did not imply.

        A `+++ b/…` line outside a hunk names a file; inside a hunk it is a
        line somebody added, and reading it as a header gives that author's
        remaining additions away to a file that does not exist. The chain this
        breaks is in `test_diff_structure.py`.
        """
        # The forged line is an *added* line, so the header counts it — which
        # is what git would write, and what `changed_lines` now requires. The
        # first version of this test injected the line and left the count
        # alone; that is a header claiming fewer lines than its body has, and
        # the parser refuses one now for reasons that have nothing to do with
        # the question here.
        diff = (DIFF
                .replace('@@ -10,6 +10,8 @@', '@@ -10,6 +10,9 @@')
                .replace('+def get_user(request):',
                         '+++ b/attacker/choice.py\n+def get_user(request):'))
        result = changed_lines(diff)

        assert "attacker/choice.py" not in result.files()
        assert result.added["app/views.py"] == {13, 14, 15, 16}

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


# The header says 8 old lines and 6 new, and the body has to have them. This
# fixture was an abbreviation of the real diff — three context lines short —
# and it passed only because the parser did not check. `changed_lines` refuses
# a diff that ends inside a hunk now, so an abbreviated one would be refused
# here for the same reason a truncated one is refused in production.
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
         path = join_path(repodir, ref_path)
         if not os.path.isfile(path):
             return (None, None)
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


class TestAmbiguousEvidenceIsRefused:
    """The citation check has to prove *where*, not just *whether*.

    It used to return the first match anywhere in the file, which meant a quote
    like `return value` proved that similar text occurred somewhere and then
    attached the finding to an unrelated line — taking the location and the
    change attribution with it. Ambiguity is now an answer.
    """

    def test_a_fragment_appearing_twice_is_refused(self):
        # This substring is in both the vulnerable line and the safe
        # parameterised one, so on its own it identifies neither.
        with pytest.raises(EvidenceProblem, match="appears 2 times"):
            locate_evidence(SOURCE, "SELECT * FROM users WHERE id = ")

    def test_the_claimed_line_can_settle_it(self):
        # The agent's own line number is routinely a few off but not tens off,
        # so it disambiguates when it points clearly at one occurrence.
        assert locate_evidence(SOURCE, "SELECT * FROM users WHERE id = ", 6) == 6
        assert locate_evidence(SOURCE, "SELECT * FROM users WHERE id = ", 11) == 11

    def test_a_claimed_line_between_two_matches_settles_nothing(self):
        text = "a = 1\n" * 40 + "sink(user_input, extra)\n" + "b = 2\n" * 5 + "sink(user_input, extra)\n"
        # Equidistant from both: guessing here is what this exists to stop.
        with pytest.raises(EvidenceProblem):
            locate_evidence(text, "sink(user_input, extra)", 44)

    def test_a_quote_too_short_to_identify_anything_is_refused(self):
        with pytest.raises(EvidenceProblem, match="too short"):
            locate_evidence(SOURCE, "return")

    def test_a_unique_quote_still_matches(self):
        assert locate_evidence(
            SOURCE, 'query = "SELECT * FROM users WHERE id = " + user_id') == 6

    def test_absent_code_says_so_rather_than_something_vaguer(self):
        with pytest.raises(EvidenceProblem, match="does not appear"):
            locate_evidence(SOURCE, 'os.system("rm -rf " + user_input)')
