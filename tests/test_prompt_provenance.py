"""Two guarantees that were written down and not enforced.

**A change must not be able to rewrite the rules it is reviewed under.** The
prompts are what keep repository content from being read as instructions, and
`resolved_prompt_dir` documented that three times while checking only that two
files exist. Anthropic's action ships the same hole as a feature: its
false-positive instructions are read from a path inside the checkout, so on a
`pull_request` build the author of the change supplies the rules used to filter
findings about it.

**The prompts themselves are the product.** An edit removing the verbatim
evidence rule, or the block that tells the model repository text is data,
passes every other test in this suite. Asserted here by concept rather than by
sentence — a snapshot would make an ordinary rewording fail without saying
which guarantee vanished.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from security_agent.config import Config, prompt_dir_risk
from security_agent.vocabulary import categories

ROOT = Path(__file__).resolve().parents[1]


# ------------------------------------------- rules the change cannot rewrite


def test_prompts_outside_the_reviewed_tree_are_silent(tmp_path):
    repo = tmp_path / "repo"
    prompts = tmp_path / "agent" / "prompts"
    repo.mkdir(parents=True)
    prompts.mkdir(parents=True)

    assert prompt_dir_risk(prompts, repo, ["app/views.py"]) is None


def test_a_change_that_edits_the_prompts_is_refused(tmp_path):
    """The narrow case that actually matters. Not "the prompts are in the
    tree" — that is the author's own workflow — but "this change edits them"."""
    repo = tmp_path / "repo"
    prompts = repo / "prompts"
    prompts.mkdir(parents=True)

    risk = prompt_dir_risk(prompts, repo, ["app/views.py", "prompts/system.md"])
    assert risk.startswith("REFUSE")
    assert "prompts/system.md" in risk


def test_prompts_inside_the_tree_but_untouched_only_warn(tmp_path):
    """Running from a source checkout puts them inside by construction. That
    is untidy, not exploitable, and refusing it would break the one deployment
    this project actually has."""
    repo = tmp_path / "repo"
    prompts = repo / "prompts"
    prompts.mkdir(parents=True)

    risk = prompt_dir_risk(prompts, repo, ["app/views.py"])
    assert risk is not None
    assert not risk.startswith("REFUSE")


def test_a_sibling_directory_with_a_shared_prefix_is_not_inside(tmp_path):
    """`/repo-backup` starts with `/repo` and is a different directory."""
    repo = tmp_path / "repo"
    prompts = tmp_path / "repo-backup" / "prompts"
    repo.mkdir(parents=True)
    prompts.mkdir(parents=True)

    assert prompt_dir_risk(prompts, repo, ["prompts/system.md"]) is None


# ------------------------------------------------ the prompts as the product


@pytest.fixture(scope="module")
def system_prompt() -> str:
    return (Config().resolved_prompt_dir() / "system.md").read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def verifier_prompt() -> str:
    return (Config().resolved_prompt_dir() / "verifier.md").read_text(encoding="utf-8")


def test_the_reviewer_is_told_repository_text_is_data(system_prompt):
    """The single instruction standing between a comment in the diff and the
    agent's behaviour. Three of four injection payloads moved the verdict when
    it was last measured."""
    lowered = system_prompt.lower()
    assert "instruction" in lowered
    assert any(phrase in lowered for phrase in
               ("data, not", "not instructions", "never instructions",
                "as data")), "no statement that repository content is data"


def test_the_reviewer_is_told_to_quote_code_verbatim(system_prompt):
    """Layer 1 rejects a finding whose quote is not in the file. Without this
    instruction the agent produces paraphrases and every finding is dropped."""
    lowered = system_prompt.lower()
    assert "verbatim" in lowered
    assert "paraphras" in lowered or "from memory" in lowered


def test_the_reviewer_is_told_to_follow_the_code_not_the_hunk(system_prompt):
    """A diff hunk almost never contains the control that settles the question.
    This is the instruction the whole tool-using design exists to serve."""
    lowered = system_prompt.lower()
    assert "caller" in lowered
    assert "search_code" in lowered or "search" in lowered


def test_the_verifier_is_told_to_refute(verifier_prompt):
    """A verifier that summarises rather than attacks is a second opinion that
    agrees by construction."""
    assert "refute" in verifier_prompt.lower()


def test_the_verifier_must_say_what_it_searched_for(verifier_prompt):
    """The rule that turned the Winter false positive into a refutation. It is
    enforced in code as well, so this guards the half a person reads."""
    lowered = verifier_prompt.lower()
    assert "control_search" in lowered or "what you looked for" in lowered


def test_every_impact_the_schema_allows_is_explained_to_the_model(system_prompt):
    """Severity is derived from `impact`, so a value the model is never told
    about is a severity it can never produce — the failure that scored seven
    cases against categories the agent could not emit."""
    import json

    schema = json.loads(
        (Config().resolved_prompt_dir() / "findings.schema.json").read_text())
    impacts = schema["properties"]["findings"]["items"]["properties"]["impact"]["enum"]

    missing = [value for value in impacts if value not in system_prompt]
    assert not missing, "impacts the prompt never mentions: {}".format(missing)


def test_the_category_vocabulary_has_one_source():
    """It lives in the schema and is read from there. A second list in a prompt
    is how the corpus came to score against names the agent cannot emit."""
    assert "open-redirect" in categories()
    assert len(set(categories())) == len(categories())


def test_the_reviewer_is_told_to_read_a_control_not_name_it(system_prompt):
    """Measured true once, on `go-sql-decoy-01`: a real sanitiser on the call
    path that strips markup and never touches a quote. This is here to keep it
    true rather than to make it so."""
    lowered = system_prompt.lower()
    assert "neutralises" in lowered or "neutralizes" in lowered
    assert "read it" in lowered


def test_local_network_access_is_not_a_reason_to_drop_a_finding(system_prompt):
    """The one instruction taken from upstream that pushes toward *more*
    findings. The measured failure mode here is missing things."""
    lowered = system_prompt.lower()
    assert "local-network" in lowered or "local network" in lowered
    assert "trust boundary" in lowered


def test_the_repository_conventions_instruction_carries_its_caveat(system_prompt):
    """Without the second half, convention-following becomes cargo cult: a
    deviation from a pattern that is not a security control is not a finding."""
    lowered = system_prompt.lower()
    assert "deviation is a lead, not proof" in lowered
