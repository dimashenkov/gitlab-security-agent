"""What makes two reviews the same review, and when an old one may be reused.

Anthropic's action answers the cost question by running once per pull request,
keyed on a cache marker. That is too coarse — a new commit is new code, and
their own tracker carries a report of prefix cache matching skipping new
commits, which is that failure arriving.

Most of the tests below are about refusing to reuse. A stale artifact served
for code it never saw is a false green, and this project's whole discipline is
that "not checked" must never look like "checked and clean".
"""

from __future__ import annotations

import pytest

from security_agent.config import Config
from security_agent.identity import digest, reusable, review_identity
from security_agent.models import Provenance, Revision


def revision(**overrides) -> Revision:
    body = dict(mode="diff", base="main", head="HEAD",
                base_sha="a" * 40, head_sha="b" * 40)
    body.update(overrides)
    return Revision(**body)


def provenance(**overrides) -> Provenance:
    body = dict(model_requested="claude-opus-5", system_prompt_sha="sys1",
                verifier_prompt_sha="ver1", schema_sha="sch1",
                agent_version="0.1.0")
    body.update(overrides)
    return Provenance(**body)


def identity(cfg=None, **overrides) -> dict:
    return review_identity(cfg or Config(), revision(**overrides.pop("rev", {})),
                           provenance(**overrides.pop("prov", {})))


def artifact(identity_value, complete=True, exit_code=1, exposures=None) -> dict:
    """A finished review's artifact. It has exposures because a review has
    them — `gate._reviewed_nothing` will not let a run with none exit 0."""
    return {"complete": complete, "identity": identity_value,
            "verdict": {"exit_code": exit_code},
            "coverage": {"exposures": [["app/views.py", "get_diff"]]
                         if exposures is None else exposures}}


# ------------------------------------------------------------ what it covers


def test_an_unchanged_review_is_reusable():
    before = identity()
    assert reusable(artifact(before), identity()) is True


@pytest.mark.parametrize("field,value", [
    ("head_sha", "c" * 40),
    ("base_sha", "c" * 40),
    ("mode", "repo"),
])
def test_a_different_revision_is_a_different_review(field, value):
    """A new commit is new code. The same commit against a different base is a
    different diff, which is the case a per-pull-request cache gets wrong."""
    before = identity()
    assert reusable(artifact(before), identity(rev={field: value})) is False


@pytest.mark.parametrize("field", [
    "system_prompt_sha", "verifier_prompt_sha", "schema_sha",
    "agent_version", "model_requested",
])
def test_a_different_reviewer_is_a_different_review(field):
    """The prompts are read from disk at run time, so they move without a diff.
    That is exactly why their hashes are in the identity."""
    before = identity()
    assert reusable(artifact(before), identity(prov={field: "changed"})) is False


@pytest.mark.parametrize("field,value", [
    ("fail_on", "medium"),
    ("min_confidence", "low"),
    ("gate_pre_existing", True),
    ("gate_removed_controls", False),
    ("verify", False),
    ("verify_votes", 5),
    ("effort", "low"),
])
def test_a_different_policy_is_a_different_review(field, value):
    """The gate settings decide which findings get verified at all, so a
    result produced under one policy is not a result under another — even when
    the code is identical."""
    before = identity()
    changed = Config(**{field: value})
    assert reusable(artifact(before), identity(changed)) is False


def test_changing_the_exclusions_is_a_different_review():
    """It changes what the model was allowed to see, without changing a line
    of code — the quietest way for two results to stop being comparable."""
    before = identity()
    narrower = Config(excludes=("*.lock",))
    assert reusable(artifact(before), identity(narrower)) is False


def test_ungated_categories_are_compared_as_a_set_not_an_order():
    """Two operators writing the same policy in a different order wrote the
    same policy."""
    first = identity(Config(ungated_categories=("dos", "xss")))
    second = identity(Config(ungated_categories=("xss", "dos")))
    assert digest(first) == digest(second)


# ------------------------------------------------------- when to refuse


def test_an_incomplete_artifact_is_never_reused():
    """It is not a cheaper result, it is an absent one. Caching it as an answer
    is the confusion that turned three reviews which never ran into a recall
    figure."""
    before = identity()
    assert reusable(artifact(before, complete=False), identity()) is False


def test_an_artifact_with_no_identity_is_never_reused():
    """Older artifacts predate the field. Absent is not the same as matching."""
    assert reusable({"complete": True}, identity()) is False


def test_an_artifact_from_a_run_that_examined_nothing_is_never_reused():
    """`complete` cannot tell a review from a run that never read anything.

    A run stopped by the skip label finishes, exits 0, and writes an artifact
    with no exposures at all — nothing reached the reviewer. Served back out of
    the cache it becomes a clean bill of health for code nobody looked at, and
    "did not check" reading as "checked and clean" is the one confusion this
    tool exists to prevent.

    Today that particular route is blocked by an accident: the skip records an
    empty revision, so its identity cannot match a real run's. This is the rule
    that makes it safe on purpose, and it stays true if the skip is ever taught
    to record which commits it declined to review — which a reader would want.

    An artifact written before exposures were recorded also has none, so it
    stops being reusable and the next run is paid for. That is the direction to
    fail in: the cost of being wrong the other way is a stale all-clear.
    """
    before = identity()
    assert reusable(artifact(before, exposures=[]), identity()) is False
    assert reusable(artifact(before), identity()) is True


def test_the_served_model_is_not_part_of_the_key():
    """A server-side fallback can substitute a model mid-review, so the served
    model is a fact about a finished run and cannot key one that has not
    started. It stays in provenance, and `baseline.py` refuses a comparison
    across it — different question, same field.
    """
    assert "models_served" not in str(identity())
    served = identity(prov={"models_served": ["claude-sonnet-5"]})
    assert digest(served) == digest(identity())


# ------------------- the policy that decides which findings are even reported


def test_accepting_a_risk_changes_the_review():
    """An artifact produced before an entry was added still lists the findings
    that entry silences, and one produced before an entry expired still hides
    what it no longer covers. Reusing either answers a question nobody asked.

    Reuse was also *decided* before the rules were read, so the comparison had
    nothing to compare even once this field existed.
    """
    before = review_identity(Config(), revision(), provenance(), "")
    after = review_identity(Config(), revision(), provenance(), "abc123")

    assert digest(before) != digest(after)
    assert not reusable({"complete": True, "identity": before}, after)


@pytest.mark.parametrize("field,value", [
    ("fail_on_incomplete", False),
    ("verify_max_findings", 5),
    ("verify_model", "claude-haiku-4-5"),
    ("verify_effort", "low"),
    ("diff_ceiling_bytes", 1024),
])
def test_a_setting_that_changes_the_answer_changes_the_identity(field, value):
    """Each of these was absent while the docstring said a field left out is a
    field that can change without anyone being told. One decides the exit code
    of a truncated run, one decides which findings are verified at all, two
    decide the verdicts, and one decides how much of the change was seen."""
    base = review_identity(Config(), revision(), provenance())
    changed = review_identity(Config(**{field: value}), revision(), provenance())

    assert digest(base) != digest(changed), field


def test_the_artifact_records_what_the_comparison_reads():
    """Recorded on one side only, no artifact would ever match, and reuse would
    silently never happen — a cost regression that looks like nothing."""
    from security_agent.gate import decide
    from security_agent.models import ScanOutcome
    from security_agent.report import build_json

    cfg = Config(post_comment=False)
    outcome = ScanOutcome(mode="diff")
    outcome.suppressions_digest = "abc123"

    stored = build_json(cfg, outcome, decide(cfg, outcome))["identity"]

    assert stored["settings"]["suppressions"] == "abc123"


def test_a_rewritten_reason_is_a_different_policy():
    """The reason is the only field a person reads when deciding whether an
    accepted risk still makes sense, so a review reused across a rewritten one
    is reused across a changed justification.

    Left out at first, on an argument that turned out to conflate two
    workflows: reuse is controlled by `--no-reuse`, and `--force` belongs to
    the baseline comparison.
    """
    from security_agent.cli import _suppression_digest
    from security_agent.suppress import Rule

    original = [Rule(fingerprint="ab12", reason="tracked in SEC-4412")]
    reworded = [Rule(fingerprint="ab12", reason="accepted by the platform team")]

    assert _suppression_digest(original) != _suppression_digest(reworded)


def test_reformatting_the_file_is_not_a_different_policy():
    """A digest that moved for whitespace or order would refuse every reuse,
    which is how a control gets switched off for being noisy."""
    from security_agent.cli import _suppression_digest
    from security_agent.suppress import Rule

    one = [Rule(fingerprint="ab12", reason="tracked  in   SEC-4412"),
           Rule(path="vendor/*", reason="third party")]
    other = [Rule(path="vendor/*", reason="third party"),
             Rule(fingerprint="ab12", reason="tracked in SEC-4412")]

    assert _suppression_digest(one) == _suppression_digest(other)
