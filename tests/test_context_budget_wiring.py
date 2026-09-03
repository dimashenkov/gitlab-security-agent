"""A budget nobody can switch on is a budget that measures and never saves.

`ContextBudget` was built, tested twenty-four ways, and reachable from no
configuration at all: every production `Session` took the unbounded default, and
the only way to set a limit was to assign the field in a test. That is the shape
this repository keeps finding in its own code — a mechanism whose tests pass
because they construct the state the product never reaches.

These tests follow the setting from the environment to the process that can
actually refuse a result. On the CLI path that process is the child: the tool
results land there, so a limit configured in the parent and not passed down
would read as enforced and enforce nothing.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from security_agent.config import Config, ConfigError, GitLabContext
from security_agent.context_budget import ContextBudget

PROMPTS = Path(__file__).resolve().parents[1] / "prompts"


def _cfg(**kw) -> Config:
    cfg = Config(gitlab=GitLabContext(), **kw)
    return cfg


class TestTheSettingIsRead:
    def test_absent_is_unbounded(self, monkeypatch):
        monkeypatch.delenv("SECURITY_SCAN_MAX_CONTEXT", raising=False)
        assert Config.from_env().max_context_tokens == 0

    def test_it_comes_from_the_environment(self, monkeypatch):
        monkeypatch.setenv("SECURITY_SCAN_MAX_CONTEXT", "80000")
        monkeypatch.setenv("SECURITY_SCAN_MAX_CONTEXT_SOFT", "60000")
        cfg = Config.from_env()
        assert (cfg.max_context_tokens, cfg.max_context_soft_tokens) == (80000, 60000)


class TestAConfigurationThatCannotFireIsRefused:
    """Not ignored. A limit that never fires still reads like one, and the
    person who set it will believe it did something."""

    def test_a_soft_limit_above_the_hard_one(self):
        cfg = _cfg(max_context_tokens=1000, max_context_soft_tokens=2000)
        with pytest.raises(ConfigError, match="could never fire"):
            cfg.validate()

    def test_a_soft_limit_with_no_hard_one(self):
        cfg = _cfg(max_context_soft_tokens=2000)
        with pytest.raises(ConfigError, match="without"):
            cfg.validate()

    def test_a_negative_limit(self):
        cfg = _cfg(max_context_tokens=-1)
        with pytest.raises(ConfigError, match="negative"):
            cfg.validate()

    def test_the_ordinary_pair_is_accepted(self):
        _cfg(max_context_tokens=110_000, max_context_soft_tokens=80_000).validate()


class TestTheDerivedSoftLimit:
    def test_a_hard_limit_alone_derives_one(self):
        """Visibly a default — three quarters — rather than a precise-looking
        constant nobody measured. The number that belongs here comes from
        telemetry across real reviews, and there is none yet."""
        budget = ContextBudget.configured(100_000)
        assert budget.soft == 75_000
        assert budget.hard == 100_000

    def test_a_given_soft_limit_wins(self):
        assert ContextBudget.configured(100_000, 40_000).soft == 40_000

    def test_zero_hard_is_unbounded_and_invents_no_soft_limit(self):
        budget = ContextBudget.configured(0, 40_000)
        assert not budget.bounded
        assert budget.soft == 0


class TestItReachesTheProcessThatCanRefuse:
    def test_the_api_runner_configures_its_session(self, git_repo):
        from security_agent.agent import SecurityAgent
        from security_agent.workspace import Workspace

        cfg = _cfg(max_context_tokens=50_000, max_context_soft_tokens=30_000)
        agent = SecurityAgent(cfg, Workspace(root=git_repo), client=object())

        assert agent.session.context.hard == 50_000
        assert agent.session.context.soft == 30_000

    def test_the_child_is_told(self, tmp_path):
        """The one that matters: `get_diff` runs in the child, so the child is
        the only process that can keep a result out of the conversation."""
        from security_agent.budget import Allowance
        from security_agent.runner_claude_code import Handoff, build_mcp_config

        config = build_mcp_config(
            prompt_dir=PROMPTS,
            repo=tmp_path,
            base_sha="a" * 40,
            head_sha="b" * 40,
            tool_set="reviewer",
            allowance=Allowance("reviewer", 100),
            handoff=Handoff(tmp_path, "run-1", "digest"),
            max_context_tokens=110_000,
            max_context_soft_tokens=80_000,
        )

        from security_agent.runner_claude_code import SERVER_KEY

        args = config["mcpServers"][SERVER_KEY]["args"]
        assert args[args.index("--max-context") + 1] == "110000"
        assert args[args.index("--max-context-soft") + 1] == "80000"

    def test_the_child_builds_the_budget_it_was_given(self, git_repo):
        from security_agent.mcp_server import build_server

        server = build_server(root=git_repo, max_context_tokens=110_000,
                              max_context_soft_tokens=80_000)

        assert server.session.context.hard == 110_000
        assert server.session.context.soft == 80_000

    def test_the_child_refuses_a_limit_that_could_never_fire(self, tmp_path):
        from security_agent.mcp_server import build_server

        with pytest.raises(ValueError, match="never fire"):
            build_server(root=tmp_path, max_context_tokens=1000,
                         max_context_soft_tokens=2000)
