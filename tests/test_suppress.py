"""Tests for accepted-risk suppression.

A suppression file is a security control in its own right: too strict and teams
delete the job, too loose and it silences the gate. The rules worth pinning down
are that entries must be justified, that expiry actually expires, and that a
suppressed finding is moved rather than deleted.
"""

import datetime as dt

import pytest

from conftest import make_candidate
from security_agent.suppress import SuppressionError, apply, load


def write(tmp_path, text):
    path = tmp_path / ".security-agent-ignore.yml"
    path.write_text(text, encoding="utf-8")
    return path


class TestLoading:
    def test_a_missing_file_is_not_an_error(self, tmp_path):
        rules, warnings = load(tmp_path / "nope.yml")
        assert rules == [] and warnings == []

    def test_an_empty_file_is_not_an_error(self, tmp_path):
        rules, warnings = load(write(tmp_path, ""))
        assert rules == [] and warnings == []

    def test_loads_a_fingerprint_entry(self, tmp_path):
        rules, _ = load(write(tmp_path, """
ignore:
  - fingerprint: abc123
    reason: Accepted; the endpoint is internal only.
"""))
        assert len(rules) == 1
        assert rules[0].fingerprint == "abc123"

    def test_requires_a_reason(self, tmp_path):
        # An accepted risk with no recorded reason is indistinguishable from a
        # mistake six months later.
        with pytest.raises(SuppressionError, match="needs a `reason`"):
            load(write(tmp_path, "ignore:\n  - fingerprint: abc123\n"))

    def test_requires_a_matcher(self, tmp_path):
        with pytest.raises(SuppressionError, match="at least one of"):
            load(write(tmp_path, "ignore:\n  - reason: because\n"))

    def test_rejects_invalid_yaml(self, tmp_path):
        with pytest.raises(SuppressionError, match="not valid YAML"):
            load(write(tmp_path, "ignore: [unclosed\n"))

    def test_rejects_a_wrong_top_level_shape(self, tmp_path):
        with pytest.raises(SuppressionError, match="`ignore:` list"):
            load(write(tmp_path, "rules: []\n"))

    def test_rejects_a_bad_expiry_date(self, tmp_path):
        with pytest.raises(SuppressionError, match="YYYY-MM-DD"):
            load(write(tmp_path, """
ignore:
  - fingerprint: abc123
    reason: temporary
    expires: next tuesday
"""))


class TestExpiry:
    content = """
ignore:
  - fingerprint: abc123
    reason: Waiting on the upstream fix.
    expires: 2026-01-01
"""

    def test_an_unexpired_rule_applies(self, tmp_path):
        rules, warnings = load(write(tmp_path, self.content), today=dt.date(2025, 6, 1))
        assert len(rules) == 1 and warnings == []

    def test_an_expired_rule_stops_applying_and_says_so(self, tmp_path):
        rules, warnings = load(write(tmp_path, self.content), today=dt.date(2026, 6, 1))
        assert rules == []
        assert "expired" in warnings[0]


class TestMatching:
    def test_matches_by_fingerprint(self, tmp_path):
        candidate = make_candidate()
        rules, _ = load(write(tmp_path, """
ignore:
  - fingerprint: {}
    reason: Accepted.
""".format(candidate.fingerprint)))
        kept, suppressed = apply([candidate], rules)
        assert kept == [] and len(suppressed) == 1
        assert "Accepted." in suppressed[0].suppressed_by

    def test_matches_by_path_glob(self, tmp_path):
        candidate = make_candidate(file="tests/fixtures/sample.py")
        rules, _ = load(write(tmp_path, """
ignore:
  - path: tests/**
    reason: Test fixtures are not production code.
"""))
        kept, suppressed = apply([candidate], rules)
        assert len(suppressed) == 1 and kept == []

    def test_matches_by_path_and_category_together(self, tmp_path):
        rules, _ = load(write(tmp_path, """
ignore:
  - path: app/**
    category: secrets
    reason: Placeholder credentials only.
"""))
        secrets = make_candidate(file="app/config.py", category="secrets")
        injection = make_candidate(file="app/config.py", category="injection")
        kept, suppressed = apply([secrets, injection], rules)
        assert len(suppressed) == 1
        assert kept[0].finding.category == "injection"

    def test_a_non_matching_rule_leaves_findings_alone(self, tmp_path):
        rules, _ = load(write(tmp_path, """
ignore:
  - fingerprint: deadbeef
    reason: Something else.
"""))
        kept, suppressed = apply([make_candidate()], rules)
        assert len(kept) == 1 and suppressed == []

    def test_suppressed_findings_are_moved_not_deleted(self, tmp_path):
        # They still appear in the report; they are only removed from the gate.
        candidate = make_candidate()
        rules, _ = load(write(tmp_path, """
ignore:
  - fingerprint: {}
    reason: Accepted risk, tracked in SEC-123.
""".format(candidate.fingerprint)))
        _, suppressed = apply([candidate], rules)
        assert suppressed[0] is candidate
        assert "SEC-123" in suppressed[0].suppressed_by


class TestFingerprintStability:
    def test_survives_the_finding_moving_in_the_file(self):
        # An accepted-risk entry must not stop matching because unrelated edits
        # pushed the code down a few lines.
        assert make_candidate(line=10).fingerprint == make_candidate(line=400).fingerprint

    def test_survives_reworded_prose(self):
        assert (make_candidate(description="One wording.").fingerprint
                == make_candidate(description="Another wording entirely.").fingerprint)

    def test_differs_across_files(self):
        assert (make_candidate(file="a.py").fingerprint
                != make_candidate(file="b.py").fingerprint)

    def test_differs_across_categories(self):
        assert (make_candidate(category="injection").fingerprint
                != make_candidate(category="xss").fingerprint)


class TestFingerprintSurvivesRewording:
    """The fingerprint is the only escape hatch a blocking gate has.

    Measuring five runs over an identical diff produced five different
    fingerprints for the same weakness, because the title was part of the hash
    and the model rewords a title every time. An accepted risk recorded in the
    ignore file stopped matching on the next run and blocked the merge again.
    """

    def test_a_reworded_title_keeps_the_fingerprint(self):
        a = make_candidate(title="Removal of '..' guard reintroduces path traversal")
        b = make_candidate(title="Reverted CVE-2023-41040 fix: path traversal returns")
        assert a.fingerprint == b.fingerprint

    def test_reworded_prose_keeps_the_fingerprint(self):
        a = make_candidate(description="One wording.", exploit_scenario="A path.")
        b = make_candidate(description="Another entirely.", exploit_scenario="B path.")
        assert a.fingerprint == b.fingerprint

    def test_quoting_extra_lines_keeps_the_fingerprint(self):
        # Only the first quoted line anchors it, so a run that quotes three
        # lines and a run that quotes two still agree.
        a = make_candidate(evidence="db.execute(sql)")
        b = make_candidate(evidence="db.execute(sql)\n    return cursor.fetchall()")
        assert a.fingerprint == b.fingerprint

    def test_indentation_and_diff_markers_do_not_matter(self):
        a = make_candidate(evidence="    db.execute(sql)")
        b = make_candidate(evidence="+db.execute(sql)")
        assert a.fingerprint == b.fingerprint

    def test_different_code_gives_a_different_fingerprint(self):
        a = make_candidate(evidence="db.execute(sql)")
        b = make_candidate(evidence="os.system(cmd)")
        assert a.fingerprint != b.fingerprint

    def test_the_same_code_in_another_file_is_a_different_finding(self):
        a = make_candidate(file="a.py", evidence="db.execute(sql)")
        b = make_candidate(file="b.py", evidence="db.execute(sql)")
        assert a.fingerprint != b.fingerprint


class TestASuppressionCannotExcuseItsOwnChange:
    """A merge request must not introduce a weakness and the entry excusing it.

    Keeping the file in the repository is deliberate — the person who is blocked
    has to be able to unblock themselves, or the gate gets switched off. But the
    entry takes effect from the next change onward, so it cannot be used on
    itself. Approval by a code owner is the other half; this is the half that
    does not depend on how the project is configured.
    """

    def _rules(self, tmp_path, candidate):
        return load(write(tmp_path, """
ignore:
  - fingerprint: {}
    reason: Accepted.
""".format(candidate.fingerprint)))[0]

    def test_it_does_not_apply_when_the_change_edits_the_file(self, tmp_path):
        candidate = make_candidate()
        rules = self._rules(tmp_path, candidate)
        kept, suppressed = apply([candidate], rules, self_added=True)
        assert kept == [candidate] and suppressed == []

    def test_it_applies_normally_otherwise(self, tmp_path):
        candidate = make_candidate()
        rules = self._rules(tmp_path, candidate)
        kept, suppressed = apply([candidate], rules, self_added=False)
        assert suppressed == [candidate] and kept == []

    def test_the_default_is_to_apply(self, tmp_path):
        candidate = make_candidate()
        _, suppressed = apply([candidate], self._rules(tmp_path, candidate))
        assert suppressed == [candidate]
