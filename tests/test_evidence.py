"""Tests for the deterministic half of the hallucination check.

These matter more than they look. `locate_evidence` is the one thing standing
between a confidently-worded description of code that does not exist and a
blocked merge request, so both directions are load-bearing: it must find real
code despite formatting differences, and it must not find code that isn't there.
"""

from security_agent.evidence import (
    added_lines,
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


class TestAddedLines:
    def test_maps_each_file_to_its_added_lines(self):
        result = added_lines(DIFF)
        assert result["app/views.py"] == {13, 14, 15}
        assert result["README.md"] == {2}

    def test_ignores_the_file_header_plus_signs(self):
        # `+++ b/path` starts with '+' but is not an added line; counting it
        # would shift every line number in the file by one.
        assert 0 not in added_lines(DIFF)["app/views.py"]

    def test_handles_a_deleted_file(self):
        diff = "--- a/gone.py\n+++ /dev/null\n@@ -1,2 +0,0 @@\n-x = 1\n-y = 2\n"
        assert added_lines(diff) == {}

    def test_empty_diff(self):
        assert added_lines("") == {}


CHANGED = {"app/views.py": {13, 14, 15}}


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
        assert not touches_change("app/views.py", 14, 1, {})


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
