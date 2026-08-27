"""Choosing who runs the review, and never choosing it for the operator.

Two runners exist. `anthropic-api` is what CI uses and what costs money;
`claude-cli` shells out to the developer's own client on the subscription they
already pay for. The whole value of the second one is that a local review is
free, and the whole risk of it is that a failure quietly becomes a bill.

So there is no `auto`. A mode whose job is to decide which of two billing
arrangements to charge is a decision about money taken on somebody's behalf,
and `--provider` is two words. If the chosen runner cannot run, the review
fails.

The fallback is prevented twice, in different ways, because an intention is not
a control: the code refuses rather than switching, and the API key is removed
from the environment the client runs in — so even a path nobody thought of has
nothing to authenticate with.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from security_agent import cli
from security_agent.config import PROVIDER_API, PROVIDER_CLI, PROVIDERS, Config

PROMPTS = Path(__file__).resolve().parents[1] / "prompts"


def _args(*extra):
    return cli._parse_args(list(extra))


# ------------------------------------------------------------ what is offered


def test_there_is_no_automatic_choice():
    """The mode this project refuses to have. A safe `auto` still adds a branch
    to the thing that decides spending, to save two words."""
    assert "auto" not in PROVIDERS
    assert set(PROVIDERS) == {PROVIDER_API, PROVIDER_CLI}


def test_the_default_is_the_paid_path_that_ci_already_uses():
    """Changing the default would change what every existing pipeline runs."""
    assert Config().provider == PROVIDER_API


def test_an_unknown_provider_is_refused_by_the_parser():
    with pytest.raises(SystemExit):
        _args("--provider", "openai")


def test_the_flag_reaches_the_configuration():
    assert cli._build_config(_args("--provider", PROVIDER_CLI)).provider == PROVIDER_CLI


def test_the_profile_reaches_the_configuration():
    assert cli._build_config(_args("--profile", "probe")).profile == "probe"


def test_probe_is_offered_and_cannot_conclude():
    """It is small enough to run on every save, which is the same thing as
    saying it usually stops early. A profile that usually stops early must not
    be able to render a verdict."""
    from security_agent.budget import PROFILES

    assert PROFILES["probe"].conclusive is False


# --------------------------------------------------------- no silent fallback


def test_a_missing_cli_fails_the_run_and_never_reaches_the_api(
        tmp_path, git_repo, monkeypatch, caplog):
    """The defect this guards is not a crash, it is a charge.

    A runner that could not start and quietly used the paid path would produce
    a correct review and an unexpected bill — and the operator would have no
    way to know which account answered.
    """
    import anthropic

    from security_agent import runner_claude_code

    monkeypatch.setattr(runner_claude_code, "cli_available", lambda executable="claude": None)

    def refuse(*_args, **_kwargs):
        raise AssertionError("the API client was constructed on the CLI path")

    monkeypatch.setattr(anthropic, "Anthropic", refuse)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-should-never-be-used")

    code = cli.main([
        "--repo", str(git_repo), "--mode", "repo", "--provider", PROVIDER_CLI,
        "--no-comment", "--output-dir", str(tmp_path / "out"), "--quiet",
    ])

    assert code == 2
    # And it stopped for *this* reason. Without naming it, the assertion above
    # would pass on any exit-2 the run happened to reach first, and "never
    # reached the API" would be true by accident rather than by design.
    assert "will not fall back" in caplog.text


def test_the_refusal_says_why_and_names_the_rule(monkeypatch):
    from security_agent import runner_claude_code

    monkeypatch.setattr(runner_claude_code, "cli_available", lambda executable="claude": None)

    problem = cli._cli_provider_problem(Config(provider=PROVIDER_CLI))

    assert "will not fall back" in problem
    assert PROVIDER_CLI in problem


def test_no_api_key_is_not_an_error_on_the_cli_path(monkeypatch, tmp_path, git_repo):
    """The credential check is skipped rather than widened. This runner
    authenticates as the developer through the client they installed, and an
    API key in the environment is the one thing it must not reach for."""
    from security_agent import runner_claude_code

    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setattr(runner_claude_code, "cli_available", lambda executable="claude": None)

    problem = cli._cli_provider_problem(Config(provider=PROVIDER_CLI))

    # It fails for the missing command, not for the missing key.
    assert "credentials" not in problem
    assert "PATH" in problem
