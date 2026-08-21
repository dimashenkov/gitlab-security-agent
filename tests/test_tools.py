"""Tests for `report_finding` — layer 1 of the hallucination check in place.

The behaviour under test is the contract the whole gate rests on: a finding is
only recorded once the code it cites has been found in the repository.
"""

import json

import pytest

from conftest import make_finding
from security_agent.tools import (
    MAX_CITATION_ATTEMPTS,
    REPORT_FINDING,
    Session,
    dispatch,
    load_finding_schema,
    read_only_tool_definitions,
    tool_definitions,
)
from security_agent.workspace import Workspace

REAL_EVIDENCE = 'return db.execute("SELECT * FROM users WHERE id = " + user_id)'


@pytest.fixture
def ws(git_repo):
    return Workspace(root=git_repo, excludes=())


@pytest.fixture
def session():
    return Session()


def report(ws, session, **overrides):
    finding = make_finding(**overrides)
    args = {
        "title": finding.title, "severity": finding.severity,
        "confidence": finding.confidence, "category": finding.category,
        "file": finding.file, "line": finding.line, "evidence": finding.evidence,
        "description": finding.description,
        "exploit_scenario": finding.exploit_scenario,
        "recommendation": finding.recommendation,
    }
    return dispatch(ws, session, REPORT_FINDING, args)


class TestAcceptsRealFindings:
    def test_records_a_finding_whose_evidence_exists(self, ws, session):
        result = report(ws, session, evidence=REAL_EVIDENCE, line=3)
        assert not result.is_error
        assert len(session.candidates) == 1
        assert "Evidence verified" in result.content

    def test_corrects_a_wrong_line_number(self, ws, session):
        # The agent counted hunk offsets by hand and got it wrong; the quote is
        # authoritative, so the line is fixed rather than the finding rejected.
        report(ws, session, evidence=REAL_EVIDENCE, line=99)
        candidate = session.candidates[0]
        assert candidate.line == 3
        assert candidate.line_corrected_from == 99


class TestRejectsHallucinations:
    def test_rejects_evidence_that_is_not_in_the_file(self, ws, session):
        result = report(ws, session, evidence='os.system("rm -rf /" + user_input)')
        assert result.is_error
        assert session.candidates == []
        assert "does not appear" in result.content

    def test_shows_what_is_actually_there(self, ws, session):
        # The correction has to be actionable, or the agent just re-reports the
        # same invented code.
        result = report(ws, session, evidence="something invented", line=3)
        assert "SELECT * FROM users" in result.content

    def test_rejects_a_file_that_does_not_exist(self, ws, session):
        result = report(ws, session, file="app/imaginary.py")
        assert result.is_error
        assert session.candidates == []
        assert "no readable file" in result.content

    def test_suggests_a_real_path_with_the_same_name(self, ws, session):
        result = report(ws, session, file="wrong/dir/views.py")
        assert "app/views.py" in result.content

    def test_drops_a_claim_that_fails_twice(self, ws, session):
        for _ in range(MAX_CITATION_ATTEMPTS):
            result = report(ws, session, evidence="still invented")
        assert result.is_error
        assert "Dropped" in result.content
        assert session.candidates == []
        assert len(session.rejected) == 1
        assert session.rejected[0].reason == "evidence-not-found"

    def test_a_dropped_path_claim_is_recorded(self, ws, session):
        for _ in range(MAX_CITATION_ATTEMPTS):
            report(ws, session, file="app/imaginary.py")
        assert session.rejected[0].reason == "unknown-path"

    def test_rejects_a_path_outside_the_repository(self, ws, session):
        result = report(ws, session, file="../../etc/passwd")
        assert result.is_error
        assert session.candidates == []


class TestDeduplication:
    def test_the_same_finding_twice_is_recorded_once(self, ws, session):
        report(ws, session, evidence=REAL_EVIDENCE)
        result = report(ws, session, evidence=REAL_EVIDENCE)
        assert not result.is_error
        assert "Already recorded" in result.content
        assert len(session.candidates) == 1
        assert session.duplicates_dropped == 1

    def test_different_findings_in_one_file_are_both_kept(self, ws, session):
        report(ws, session, evidence=REAL_EVIDENCE, title="SQL injection")
        report(ws, session, evidence=REAL_EVIDENCE, title="Missing authorization check",
               category="authn-authz")
        assert len(session.candidates) == 2


class TestMalformedInput:
    def test_missing_fields_are_reported_not_raised(self, ws, session):
        result = dispatch(ws, session, REPORT_FINDING, {"title": "only a title"})
        assert result.is_error
        assert "required" in result.content

    def test_a_non_object_input_is_handled(self, ws, session):
        result = dispatch(ws, session, REPORT_FINDING, "not a dict")
        assert result.is_error

    def test_an_unknown_tool_name_is_handled(self, ws, session):
        result = dispatch(ws, session, "rm_rf", {})
        assert result.is_error
        assert "No tool named" in result.content


class TestToolDefinitions:
    def test_finding_schema_comes_from_the_schema_file(self, tmp_path):
        # The tool schema is derived from prompts/findings.schema.json so the two
        # cannot drift; this is the check that the derivation still works.
        from pathlib import Path

        prompts = Path(__file__).resolve().parents[1] / "prompts"
        schema = load_finding_schema(prompts)
        assert schema["type"] == "object"
        assert "evidence" in schema["properties"]
        assert "evidence" in schema["required"]

    def test_report_finding_is_strict(self, tmp_path):
        from pathlib import Path

        prompts = Path(__file__).resolve().parents[1] / "prompts"
        tools = tool_definitions(load_finding_schema(prompts), diff_available=True)
        report_tool = next(t for t in tools if t["name"] == REPORT_FINDING)
        assert report_tool["strict"] is True
        assert report_tool["input_schema"]["additionalProperties"] is False

    def test_diff_tools_are_absent_without_a_diff(self, tmp_path):
        from pathlib import Path

        prompts = Path(__file__).resolve().parents[1] / "prompts"
        names = {t["name"] for t in tool_definitions(
            load_finding_schema(prompts), diff_available=False)}
        assert "get_diff" not in names
        assert "read_file" in names

    def test_the_verifier_cannot_create_findings(self, tmp_path):
        names = {t["name"] for t in read_only_tool_definitions(diff_available=True)}
        assert REPORT_FINDING not in names
        assert {"read_file", "search_code", "list_directory"} <= names

    def test_tool_definitions_are_json_serialisable(self, tmp_path):
        from pathlib import Path

        prompts = Path(__file__).resolve().parents[1] / "prompts"
        tools = tool_definitions(load_finding_schema(prompts), diff_available=True)
        json.dumps(tools)  # would raise if a stray object leaked into a schema


class TestReadOnlyTools:
    def test_read_file_records_what_was_examined(self, ws, session):
        dispatch(ws, session, "read_file", {"path": "app/views.py"})
        assert "app/views.py" in session.files_examined

    def test_search_returns_matches(self, ws, session):
        result = dispatch(ws, session, "search_code", {"pattern": "SELECT"})
        assert not result.is_error
        assert "app/views.py" in result.content

    def test_an_invalid_regex_becomes_an_error_result_not_a_crash(self, ws, session):
        result = dispatch(ws, session, "search_code", {"pattern": "([unclosed"})
        assert result.is_error

    def test_git_log_works(self, ws, session):
        result = dispatch(ws, session, "git_log", {})
        assert "initial" in result.content
