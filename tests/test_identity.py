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


def artifact(identity_value, complete=True, exit_code=1) -> dict:
    return {"complete": complete, "identity": identity_value,
            "verdict": {"exit_code": exit_code}}


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


def test_the_served_model_is_not_part_of_the_key():
    """A server-side fallback can substitute a model mid-review, so the served
    model is a fact about a finished run and cannot key one that has not
    started. It stays in provenance, and `baseline.py` refuses a comparison
    across it — different question, same field.
    """
    assert "models_served" not in str(identity())
    served = identity(prov={"models_served": ["claude-sonnet-5"]})
    assert digest(served) == digest(identity())
