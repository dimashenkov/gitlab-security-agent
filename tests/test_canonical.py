"""The line between the decision and the provider, drawn on a real artifact.

Every test here starts from `build_json` rather than from a hand-written dict.
A partition tested against a dict someone typed proves that the partition
agrees with the typist; the failure it needs to catch is a field that exists in
the real artifact and was never classified.

Two directions are asserted, and they are not the same assertion:

* telemetry must leave the canonical result — otherwise two honest runners
  never agree and the conformance test gets deleted for being noisy;
* everything else must stay — otherwise the comparison quietly stops covering
  the thing it was built for, and nothing fails.

The second is the dangerous one, so `TELEMETRY_PATHS` is an allowlist: a key
added tomorrow is compared until someone argues it should not be.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from fakes import FakeClient, FakeResponse, json_text, text, tool_use
from security_agent.agent import SecurityAgent
from security_agent.canonical import (
    ABSENT,
    TELEMETRY_PATHS,
    canonical_bytes,
    differences,
    identical,
    lookup,
    split,
    telemetry_leaks,
)
from security_agent.config import Config, GitLabContext
from security_agent.gate import decide
from security_agent.models import VERDICT_CONFIRMED
from security_agent.report import build_json
from security_agent.verify import verify_candidates
from security_agent.workspace import Workspace

PROMPTS = Path(__file__).resolve().parents[1] / "prompts"
EVIDENCE = 'return db.execute("SELECT * FROM users WHERE id = " + user_id)'

FINDING_ARGS = {
    "title": "SQL injection in get_user",
    "severity": "high",
    "confidence": "high",
    "category": "injection",
    "file": "app/views.py",
    "line": 3,
    "evidence": EVIDENCE,
    "description": "The id parameter is concatenated into a SQL string.",
    "exploit_scenario": "An anonymous caller sends ?id=1 OR 1=1 and reads every row.",
    "recommendation": "Use a parameterised query with a bound parameter.",
}


@pytest.fixture
def cfg(tmp_path):
    return Config(
        prompt_dir=PROMPTS,
        output_dir=tmp_path / "out",
        gitlab=GitLabContext(project_path="group/project"),
        post_comment=False,
        verify_votes=1,
    )


@pytest.fixture
def artifact(cfg, git_repo):
    """One real review, all the way to the JSON a runner would write."""
    ws = Workspace(root=git_repo, excludes=(), diff_base="", diff_head="HEAD")
    client = FakeClient(
        script=[
            FakeResponse([tool_use("report_finding", FINDING_ARGS, id="t1")],
                         stop_reason="tool_use"),
            FakeResponse([text("Reviewed the user lookup path.")],
                         stop_reason="end_turn"),
        ],
        verifier_script=[FakeResponse([json_text({
            "verdict": VERDICT_CONFIRMED,
            "reasoning": "Traced the call chain and confirmed it.",
            "corrected_severity": "", "corrected_confidence": "",
            "control_search": "Looked for a validating caller in app/ and "
                              "found none; the sink is reached directly.",
            "entry_point": "app/views.py:14 via the public handler",
        })], stop_reason="end_turn")],
    )
    agent = SecurityAgent(cfg, ws, client=client)
    outcome = agent.run("diff", "go")
    verify_candidates(cfg, ws, client, agent.candidates)
    outcome.reported = agent.candidates
    body = build_json(cfg, outcome, decide(cfg, outcome))
    # The shape `_record_the_reuse` writes back, added here because a fresh
    # review has no `reuse` block by construction — and the parametrised test
    # below is the one that would catch a declared telemetry path matching
    # nothing. Without it, `reuse` would be exempted from exactly the check
    # that exists to notice an exclusion nobody applies.
    body["reuse"] = {
        "source_generated_at": body["generated_at"],
        "reused_at": "2026-09-03T09:00:00+00:00",
        "count": 1,
    }
    return body


# --------------------------------------------- telemetry leaves, and only it


def test_a_real_artifact_leaves_no_telemetry_in_the_canonical_half(artifact):
    """The check that fails when the artifact is restructured and a declared
    path stops matching. Without it the exclusion silently stops applying and
    the byte comparison starts failing for a reason nobody guesses."""
    canonical, _ = split(artifact)

    assert telemetry_leaks(canonical) == []


@pytest.mark.parametrize("path", TELEMETRY_PATHS)
def test_every_declared_telemetry_path_is_real_and_actually_leaves(artifact, path):
    """Two failures in one, and they look identical from the outside: a typo
    that matches nothing reads as a working exclusion, and so does a path that
    is found but not removed. Parametrised so the failure names the entry."""
    canonical, _ = split(artifact)

    assert lookup(artifact, path) is not ABSENT, \
        "{} matched nothing in a real artifact".format(path)
    assert lookup(canonical, path) is ABSENT, \
        "{} was found and not removed".format(path)


def test_the_decision_stays_in_the_canonical_half(artifact):
    canonical, _ = split(artifact)

    assert canonical["verdict"]["exit_code"] == artifact["verdict"]["exit_code"]
    assert canonical["findings"][0]["evidence"] == EVIDENCE
    assert canonical["stop_reason"] == artifact["stop_reason"]
    assert canonical["complete"] is artifact["complete"]
    assert canonical["identity"] == artifact["identity"]
    assert canonical["settings"] == artifact["settings"]
    assert canonical["stage_metrics"] == artifact["stage_metrics"]


def test_the_requested_model_is_canonical_and_the_served_one_is_not(artifact):
    """`model_requested` is part of the review's identity, so it is compared.
    What answered carries provider-side detail — a dated variant, a fallback —
    that identity deliberately excludes."""
    canonical, telemetry = split(artifact)

    assert "model_requested" in canonical["provenance"]
    assert "models_served" not in canonical["provenance"]
    assert "models_served" in telemetry["provenance"]


def test_split_does_not_modify_the_artifact_it_was_given(artifact):
    """`write_artifacts` and the comparison read the same object. A partition
    that consumed its input would empty the file that gets written."""
    before = json.dumps(artifact, sort_keys=True)
    split(artifact)

    assert json.dumps(artifact, sort_keys=True) == before


def test_absent_telemetry_is_not_an_error(artifact):
    """A runner that cannot report usage has no `usage` key. Demanding one
    turns "this runner cannot tell us" into a crash."""
    stripped = {k: v for k, v in artifact.items() if k not in ("usage", "turns_detail")}

    canonical, telemetry = split(stripped)
    assert "usage" not in telemetry
    assert canonical["verdict"] == artifact["verdict"]


# ------------------------------------------- what the comparison must notice


def test_two_runners_differing_only_in_telemetry_agree(artifact):
    """The whole purpose, in one assertion. Different tokens, different cost,
    different served model, different clock — same review."""
    other = json.loads(json.dumps(artifact))
    other["generated_at"] = "2030-01-01T00:00:00+00:00"
    other["usage"] = {"note": "not reported by this runner"}
    other["turns_detail"] = []
    other["model"] = "claude-opus-5-20991231"
    other["provenance"]["models_served"] = ["claude-opus-5-20991231"]
    other["provenance"]["model_substituted"] = True
    other["stop_detail"] = "the CLI exited 0"
    other["coverage"]["turns"] = 99
    for call in other["coverage"]["tool_calls"]:
        call["turn"] = 42

    assert identical(artifact, other), differences(artifact, other)


def test_a_different_exit_code_is_caught(artifact):
    other = json.loads(json.dumps(artifact))
    other["verdict"]["exit_code"] = 0

    assert not identical(artifact, other)
    assert any("verdict.exit_code" in d for d in differences(artifact, other))


def test_a_different_verdict_on_one_finding_is_caught(artifact):
    """Deep inside a list of objects — the place a shallow comparison misses."""
    other = json.loads(json.dumps(artifact))
    other["findings"][0]["verification"]["verdict"] = "refuted"

    named = differences(artifact, other)
    assert any("findings[0]" in d and "verdict" in d for d in named), named


def test_a_missing_finding_is_caught(artifact):
    other = json.loads(json.dumps(artifact))
    other["findings"] = []

    assert any("findings" in d and "entries" in d
               for d in differences(artifact, other))


def test_an_unclassified_new_key_is_compared(artifact):
    """The direction-of-failure rule. A field nobody classified must make a
    test fail and someone look, not vanish from the comparison."""
    other = json.loads(json.dumps(artifact))
    other["runner_note"] = "added next week by whoever writes the runner"

    assert not identical(artifact, other)
    assert any("runner_note" in d for d in differences(artifact, other))


def test_key_order_alone_never_fails_a_comparison(artifact):
    """A conformance failure that turns out to be dictionary order teaches a
    team to stop reading conformance failures."""
    reversed_order = dict(reversed(list(artifact.items())))

    assert canonical_bytes(artifact) == canonical_bytes(reversed_order)


def test_a_type_change_is_reported_as_one(artifact):
    """`complete: false` and `complete: "false"` are the same length in a diff
    and opposite in meaning."""
    other = json.loads(json.dumps(artifact))
    other["complete"] = str(other["complete"])

    assert any("complete" in d and "str" in d
               for d in differences(artifact, other))
