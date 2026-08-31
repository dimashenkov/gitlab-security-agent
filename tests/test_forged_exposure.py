"""A merge request could write its own record of what the reviewer had read.

`_paths_in_diff` scanned the whole diff body for anything matching
`^(?:\\+\\+\\+ b|--- a)/(.+)$`. Every line of added content in a unified diff
begins with `+`, so a change that added the literal line

    +++ b/payments/authorise.py

to any file of its own produced an exposure record for `payments/authorise.py`.

Exposure is what `gate._reviewed_nothing` reads to tell a review that stopped
early from one that never started, and it is the record the report shows for
what reached the reviewer. The forgery pointed the wrong way — it made a thinner
review look like a fuller one — and it was written by the author of the code
under review.

The same class of defect the evidence layer already documents: a regular
expression over attacker-controlled text, where the format has structure that
says exactly where a header may appear. The fix is to read the structure.
"""

from __future__ import annotations

from security_agent.tools import _paths_in_diff

REAL = """\
diff --git a/app/handler.py b/app/handler.py
index 1111111..2222222 100644
--- a/app/handler.py
+++ b/app/handler.py
@@ -1,3 +1,6 @@
 def handle(request):
+    # nothing to see here
+++ b/payments/authorise.py
--- a/payments/authorise.py
+    return request
"""


class TestAChangeCannotWriteItsOwnCoverage:
    def test_content_shaped_like_a_header_is_not_an_exposure(self):
        assert _paths_in_diff(REAL) == ["app/handler.py"]

    def test_the_file_that_really_is_there_is_still_recorded(self):
        assert "app/handler.py" in _paths_in_diff(REAL)

    def test_a_second_real_file_after_the_forgery_is_still_found(self):
        """The parser must resume at the next `diff --git`, or one crafted hunk
        would hide every file after it — the same lie in the other direction."""
        body = REAL + """\
diff --git a/lib/auth.py b/lib/auth.py
--- a/lib/auth.py
+++ b/lib/auth.py
@@ -1 +1 @@
-old
+new
"""
        assert _paths_in_diff(body) == ["app/handler.py", "lib/auth.py"]


class TestTheOrdinaryReadingsStillWork:
    def test_an_edit_names_its_file_once(self):
        body = """\
diff --git a/a.py b/a.py
--- a/a.py
+++ b/a.py
@@ -1 +1 @@
-x
+y
"""
        assert _paths_in_diff(body) == ["a.py"]

    def test_a_deletion_is_recorded_from_the_a_side(self):
        """Its bytes are in the diff — every removed line of it — so the review
        had the code in front of it. Reading only the `+++` side recorded
        nothing, and a deletion-only change was about to be called an absent
        review."""
        body = """\
diff --git a/gone.py b/gone.py
deleted file mode 100644
--- a/gone.py
+++ /dev/null
@@ -1,2 +0,0 @@
-def check(token):
-    return verify(token)
"""
        assert _paths_in_diff(body) == ["gone.py"]

    def test_an_addition_is_recorded_from_the_b_side(self):
        body = """\
diff --git a/new.py b/new.py
new file mode 100644
--- /dev/null
+++ b/new.py
@@ -0,0 +1 @@
+print(1)
"""
        assert _paths_in_diff(body) == ["new.py"]

    def test_a_quoted_path_is_decoded(self):
        r"""Git escapes quotes, backslashes and control characters whatever
        `core.quotePath` says. A path recorded in its escaped form is a path
        nothing will ever match."""
        body = (
            'diff --git "a/src/caf\\303\\251.py" "b/src/caf\\303\\251.py"\n'
            '--- "a/src/caf\\303\\251.py"\n'
            '+++ "b/src/caf\\303\\251.py"\n'
            '@@ -1 +1 @@\n-x\n+y\n'
        )
        assert _paths_in_diff(body) == ["src/café.py"]

    def test_a_trailing_space_survives(self):
        """A legal name on Linux. Git terminates such a path with one tab, and
        removing more than that tab produces a key nothing looks up."""
        body = (
            "diff --git a/handler .py b/handler .py\n"
            "--- a/handler .py\t\n"
            "+++ b/handler .py\t\n"
            "@@ -1 +1 @@\n-x\n+y\n"
        )
        assert _paths_in_diff(body) == ["handler .py"]

    def test_an_empty_body_is_no_exposure(self):
        assert _paths_in_diff("") == []
