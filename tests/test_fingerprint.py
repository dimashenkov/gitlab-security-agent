from __future__ import annotations


class TestAnchorsCarryIdentity:
    """An anchor decides whether an accepted risk still applies.

    A line shared by half the file would make that decision wrongly and
    silently, in the direction that hides a finding — so length is not the
    test. `if err != nil {` is fifteen characters and appears in every function
    of a Go file.
    """

    @staticmethod
    def _finding(evidence):
        from security_agent.models import Finding

        return Finding.from_dict({
            "title": "t", "severity": "high", "confidence": "high",
            "category": "injection", "file": "a.go", "line": 1,
            "impact": "code_execution", "reachable_without_authentication": "yes",
            "requires_user_interaction": "no", "evidence": evidence,
            "description": "d", "exploit_scenario": "e", "recommendation": "r",
        })

    def test_boilerplate_is_not_an_anchor(self):
        finding = self._finding("if err != nil {\n} else {\nreturn result")
        assert finding.anchors == []

    def test_a_line_naming_something_is_an_anchor(self):
        finding = self._finding("rows, err := s.db.QueryContext(r.Context(),")
        assert len(finding.anchors) == 1

    def test_two_findings_sharing_only_boilerplate_are_not_the_same(self):
        """The failure the length rule allowed: an accepted risk on one
        weakness silencing an unrelated one in the same file and category."""
        one = self._finding("if err != nil {\nuserQuery(name)")
        two = self._finding("if err != nil {\nadminReset(token)")
        assert not (set(one.fingerprints) & set(two.fingerprints))

    def test_a_run_quoting_from_a_later_line_still_matches(self):
        """The drift that was measured: three runs quoted a call, one started
        a line later at the expression inside it."""
        whole = self._finding(
            'rows, err := s.db.QueryContext(r.Context(),\n'
            '    fmt.Sprintf("SELECT id FROM accounts WHERE r = \'%s\'", region))')
        part = self._finding(
            'fmt.Sprintf("SELECT id FROM accounts WHERE r = \'%s\'", region))')
        assert set(whole.fingerprints) & set(part.fingerprints)

    def test_the_printed_fingerprint_is_a_single_stable_value(self):
        finding = self._finding("userQuery(name)\nadminReset(token)")
        assert finding.fingerprint == finding.fingerprints[0]
        assert len(finding.fingerprint) == 16
