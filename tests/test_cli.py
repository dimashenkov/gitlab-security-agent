"""End-to-end runs through `main()`.

This is the only place the whole thing is exercised the way CI runs it: real
argument parsing, real config, real artifacts on disk, and the exit code the
runner acts on. The exit code is the product — everything else is explanation.
"""

import json
from pathlib import Path

import pytest

from fakes import FakeClient, FakeResponse, json_text, text, tool_use
from security_agent import cli
from security_agent.gate import EXIT_ERROR, EXIT_FINDINGS, EXIT_OK
from security_agent.models import VERDICT_CONFIRMED, VERDICT_REFUTED

PROMPTS = Path(__file__).resolve().parents[1] / "prompts"
REAL_EVIDENCE = 'return db.execute("SELECT * FROM users WHERE id = " + user_id)'

FINDING_ARGS = {
    "title": "SQL injection in get_user",
    "severity": "high",
    "confidence": "high",
    "category": "injection",
    "file": "app/views.py",
    "line": 3,
    "evidence": REAL_EVIDENCE,
    "description": "The id parameter is concatenated into a SQL string.",
    "exploit_scenario": "An anonymous caller sends ?id=1 OR 1=1 and reads every row.",
    "recommendation": "Use a parameterised query.",
}

CI_KEYS = [
    "CI_MERGE_REQUEST_IID", "CI_MERGE_REQUEST_LABELS", "CI_API_V4_URL",
    "CI_PROJECT_ID", "CI_MERGE_REQUEST_DIFF_BASE_SHA", "SECURITY_SCAN_FAIL_ON",
    "SECURITY_SCAN_MODE", "SECURITY_SCAN_VERIFY", "SECURITY_SCAN_GITLAB_TOKEN",
    "SECURITY_SCAN_PROMPT_DIR", "SECURITY_SCAN_OUTPUT_DIR",
]


@pytest.fixture(autouse=True)
def ci_env(monkeypatch, tmp_path):
    for key in CI_KEYS:
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    monkeypatch.setenv("SECURITY_SCAN_PROMPT_DIR", str(PROMPTS))


def verdict_response(status):
    return FakeResponse([json_text({
        "verdict": status, "reasoning": "Checked the callers.",
        "corrected_severity": "", "corrected_confidence": "",
    })], stop_reason="end_turn")


def install_client(monkeypatch, script, verifier_script=None):
    """Replace the SDK constructor with one that returns a scripted client."""
    import anthropic

    client = FakeClient(script, verifier_script)
    monkeypatch.setattr(anthropic, "Anthropic", lambda **kwargs: client)
    return client


def run(repo, *args):
    return cli.main(["--repo", str(repo), "--mode", "repo", "--no-comment", *args])


class TestExitCodes:
    def test_a_clean_review_exits_zero(self, git_repo, monkeypatch, tmp_path):
        install_client(monkeypatch, [FakeResponse([text("Nothing found.")],
                                                  stop_reason="end_turn")])
        assert run(git_repo, "--output-dir", str(tmp_path / "out")) == EXIT_OK

    def test_a_high_finding_blocks(self, git_repo, monkeypatch, tmp_path):
        install_client(
            monkeypatch,
            [FakeResponse([tool_use("report_finding", FINDING_ARGS, id="t1")],
                          stop_reason="tool_use"),
             FakeResponse([text("One finding.")], stop_reason="end_turn")],
            [verdict_response(VERDICT_CONFIRMED)] * 2,
        )
        assert run(git_repo, "--output-dir", str(tmp_path / "out")) == EXIT_FINDINGS

    def test_a_refuted_finding_does_not_block(self, git_repo, monkeypatch, tmp_path):
        install_client(
            monkeypatch,
            [FakeResponse([tool_use("report_finding", FINDING_ARGS, id="t1")],
                          stop_reason="tool_use"),
             FakeResponse([text("One finding.")], stop_reason="end_turn")],
            [verdict_response(VERDICT_REFUTED)] * 2,
        )
        assert run(git_repo, "--output-dir", str(tmp_path / "out")) == EXIT_OK

    def test_an_incomplete_review_exits_two(self, git_repo, monkeypatch, tmp_path):
        # Distinct from 1: this is the pipeline owner's problem, not the author's.
        install_client(monkeypatch, [FakeResponse([tool_use("git_log", {}, id="t1")],
                                                  stop_reason="tool_use")])
        assert run(git_repo, "--max-turns", "1", "--output-dir", str(tmp_path / "out")) == EXIT_ERROR

    def test_a_hallucinated_finding_never_blocks(self, git_repo, monkeypatch, tmp_path):
        # The whole point of layer 1: invented code cannot stop a merge.
        invented = dict(FINDING_ARGS, evidence='os.system("rm -rf /" + user_input)')
        install_client(monkeypatch, [
            FakeResponse([tool_use("report_finding", invented, id="t1")],
                         stop_reason="tool_use"),
            FakeResponse([tool_use("report_finding", invented, id="t2")],
                         stop_reason="tool_use"),
            FakeResponse([text("Withdrawn.")], stop_reason="end_turn"),
        ])
        assert run(git_repo, "--output-dir", str(tmp_path / "out")) == EXIT_OK


class TestArtifacts:
    def test_writes_the_report_and_the_json(self, git_repo, monkeypatch, tmp_path):
        out = tmp_path / "out"
        install_client(
            monkeypatch,
            [FakeResponse([tool_use("report_finding", FINDING_ARGS, id="t1")],
                          stop_reason="tool_use"),
             FakeResponse([text("Reviewed.")], stop_reason="end_turn")],
            [verdict_response(VERDICT_CONFIRMED)] * 2,
        )
        run(git_repo, "--output-dir", str(out))

        report = (out / "report.md").read_text(encoding="utf-8")
        payload = json.loads((out / "findings.json").read_text(encoding="utf-8"))

        assert "SQL injection in get_user" in report
        assert REAL_EVIDENCE in report
        assert payload["counts"]["blocking"] == 1
        assert payload["findings"][0]["file"] == "app/views.py"

    def test_the_artifact_says_which_commits_were_read(self, git_repo, monkeypatch, tmp_path):
        """A finding is a claim about code at a moment.

        Without the moment it cannot be checked: `HEAD` and a branch name point
        somewhere different tomorrow, and an accepted risk recorded against one
        revision has to be traceable to it. The artifact recorded mode, model,
        prompts and policy — and not this.
        """
        out = tmp_path / "out"
        install_client(monkeypatch, [FakeResponse([text("Nothing found.")],
                                                  stop_reason="end_turn")])
        run(git_repo, "--output-dir", str(out))

        revision = json.loads((out / "findings.json").read_text())["revision"]
        assert revision["head_sha"], "no commit recorded for what was reviewed"
        assert len(revision["head_sha"]) == 40, revision["head_sha"]
        # Both forms: the symbolic one is what the pipeline was configured
        # with, the SHA is the only part that identifies a commit.
        assert revision["head"]
        assert revision["mode"] in ("diff", "repo")
        # A whole-repository review has no base, and must not invent one.
        if revision["mode"] == "repo":
            assert revision["base"] == "" and revision["base_sha"] == ""

    def test_artifacts_are_written_even_when_the_review_fails(self, git_repo, monkeypatch, tmp_path):
        out = tmp_path / "out"
        install_client(monkeypatch, [FakeResponse([tool_use("git_log", {}, id="t1")],
                                                  stop_reason="tool_use")])
        run(git_repo, "--max-turns", "1", "--output-dir", str(out))

        assert (out / "report.md").is_file()
        assert json.loads((out / "findings.json").read_text())["complete"] is False


class TestFlagOverrides:
    def test_fail_on_none_turns_the_gate_off(self, git_repo, monkeypatch, tmp_path):
        install_client(
            monkeypatch,
            [FakeResponse([tool_use("report_finding", FINDING_ARGS, id="t1")],
                          stop_reason="tool_use"),
             FakeResponse([text("One finding.")], stop_reason="end_turn")],
            [verdict_response(VERDICT_CONFIRMED)] * 2,
        )
        code = run(git_repo, "--fail-on", "none", "--output-dir", str(tmp_path / "out"))
        assert code == EXIT_OK

    def test_no_verify_skips_the_verifier(self, git_repo, monkeypatch, tmp_path):
        client = install_client(monkeypatch, [
            FakeResponse([tool_use("report_finding", FINDING_ARGS, id="t1")],
                         stop_reason="tool_use"),
            FakeResponse([text("One finding.")], stop_reason="end_turn"),
        ])
        run(git_repo, "--no-verify", "--output-dir", str(tmp_path / "out"))
        assert client.verifier_requests == []

    def test_an_invalid_flag_value_is_rejected_by_the_parser(self, git_repo):
        with pytest.raises(SystemExit):
            cli.main(["--repo", str(git_repo), "--fail-on", "catastrophic"])

    def test_a_bad_environment_value_exits_two_without_calling_the_api(
        self, git_repo, monkeypatch, tmp_path
    ):
        monkeypatch.setenv("SECURITY_SCAN_FAIL_ON", "hihg")
        client = install_client(monkeypatch, [])
        assert run(git_repo, "--output-dir", str(tmp_path / "out")) == EXIT_ERROR
        assert client.requests == []


class TestSkipHatches:
    def test_the_skip_label_skips_the_review(self, git_repo, monkeypatch, tmp_path):
        monkeypatch.setenv("CI_MERGE_REQUEST_IID", "42")
        monkeypatch.setenv("CI_MERGE_REQUEST_LABELS", "urgent,skip-ai-security")
        client = install_client(monkeypatch, [])

        assert run(git_repo, "--output-dir", str(tmp_path / "out")) == EXIT_OK
        assert client.requests == []

    def test_an_unrelated_label_does_not_skip(self, git_repo, monkeypatch, tmp_path):
        monkeypatch.setenv("CI_MERGE_REQUEST_LABELS", "urgent")
        install_client(monkeypatch, [FakeResponse([text("Nothing.")], stop_reason="end_turn")])
        assert run(git_repo, "--output-dir", str(tmp_path / "out")) == EXIT_OK


class TestCredentials:
    def test_missing_credentials_exit_two_before_any_work(
        self, git_repo, monkeypatch, tmp_path
    ):
        for key in ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_PROFILE"):
            monkeypatch.delenv(key, raising=False)
        monkeypatch.setattr(cli, "_has_credentials", lambda: False)
        client = install_client(monkeypatch, [])

        assert run(git_repo, "--output-dir", str(tmp_path / "out")) == EXIT_ERROR
        assert client.requests == []


class TestSuppressionThroughTheCli:
    def test_an_ignore_entry_removes_a_finding_from_the_gate(
        self, git_repo, monkeypatch, tmp_path
    ):
        from conftest import make_candidate

        # The fingerprint is anchored on the quoted code, so the suppression
        # entry has to be derived from the same evidence the agent reports.
        fingerprint = make_candidate(
            category=FINDING_ARGS["category"],
            file=FINDING_ARGS["file"],
            evidence=FINDING_ARGS["evidence"],
        ).fingerprint
        (git_repo / ".security-agent-ignore.yml").write_text(
            "ignore:\n  - fingerprint: {}\n    reason: Accepted, tracked in SEC-1.\n".format(
                fingerprint),
            encoding="utf-8",
        )
        out = tmp_path / "out"
        install_client(
            monkeypatch,
            [FakeResponse([tool_use("report_finding", FINDING_ARGS, id="t1")],
                          stop_reason="tool_use"),
             FakeResponse([text("One finding.")], stop_reason="end_turn")],
            [verdict_response(VERDICT_CONFIRMED)] * 2,
        )

        assert run(git_repo, "--output-dir", str(out)) == EXIT_OK
        payload = json.loads((out / "findings.json").read_text(encoding="utf-8"))
        # Suppressed, not deleted: still visible to a human in the report.
        assert payload["counts"]["suppressed"] == 1
        assert "SEC-1" in (out / "report.md").read_text(encoding="utf-8")

    def test_a_broken_ignore_file_exits_two(self, git_repo, monkeypatch, tmp_path):
        (git_repo / ".security-agent-ignore.yml").write_text(
            "ignore:\n  - fingerprint: abc\n", encoding="utf-8")  # no reason
        client = install_client(monkeypatch, [])

        assert run(git_repo, "--output-dir", str(tmp_path / "out")) == EXIT_ERROR
        assert client.requests == []


class TestUnexpectedFailures:
    def test_a_crash_exits_two_not_one(self, git_repo, monkeypatch, tmp_path):
        # Exit 1 means "blocking findings" in this tool's vocabulary. If an
        # uncaught exception reached the interpreter, a crash would be
        # indistinguishable from a vulnerability, and someone would go looking
        # for a security bug that does not exist.
        import anthropic

        def explode(**kwargs):
            raise RuntimeError("something unforeseen")

        monkeypatch.setattr(anthropic, "Anthropic", explode)
        assert run(git_repo, "--output-dir", str(tmp_path / "out")) == EXIT_ERROR

    def test_a_crash_is_logged_with_its_traceback(self, git_repo, monkeypatch, tmp_path, caplog):
        import anthropic

        monkeypatch.setattr(anthropic, "Anthropic",
                            lambda **kw: (_ for _ in ()).throw(RuntimeError("boom")))
        run(git_repo, "--output-dir", str(tmp_path / "out"))
        assert "crashed" in caplog.text


class TestTheReportPathIsNotContributorControlled:
    """The report is written by a job holding a GitLab token.

    The default output directory sits inside the checkout and the file names are
    fixed, so a committed symlink at that path would redirect both writes
    somewhere of the contributor's choosing. Refused rather than resolved:
    resolving it would work, which is exactly the problem.
    """

    def test_a_symlinked_output_directory_is_refused(self, git_repo, monkeypatch, tmp_path):
        elsewhere = tmp_path / "elsewhere"
        elsewhere.mkdir()
        planted = git_repo / ".security-scan"
        planted.symlink_to(elsewhere)

        install_client(monkeypatch, [FakeResponse([text("Nothing.")], stop_reason="end_turn")])
        code = cli.main(["--repo", str(git_repo), "--mode", "repo", "--no-comment",
                         "--output-dir", str(planted)])

        assert code == EXIT_ERROR
        assert not (elsewhere / "report.md").exists()

    def test_a_symlinked_report_file_is_refused(self, git_repo, monkeypatch, tmp_path):
        out = git_repo / "out"
        out.mkdir()
        target = tmp_path / "captured.md"
        (out / "report.md").symlink_to(target)

        install_client(monkeypatch, [FakeResponse([text("Nothing.")], stop_reason="end_turn")])
        code = cli.main(["--repo", str(git_repo), "--mode", "repo", "--no-comment",
                         "--output-dir", str(out)])

        assert code == EXIT_ERROR
        assert not target.exists()

    def test_an_ordinary_directory_still_works(self, git_repo, monkeypatch, tmp_path):
        out = tmp_path / "plain"
        install_client(monkeypatch, [FakeResponse([text("Nothing.")], stop_reason="end_turn")])
        assert cli.main(["--repo", str(git_repo), "--mode", "repo", "--no-comment",
                         "--output-dir", str(out)]) == EXIT_OK
        assert (out / "report.md").is_file()
