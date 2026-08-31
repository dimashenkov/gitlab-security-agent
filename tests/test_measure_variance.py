"""`tools/measure_variance.py` could not be run at all, and nothing said so.

It is the obvious thing to reach for when run-to-run variance is finally wanted.
When it was reached for on 2026-08-30 it turned out to invoke
`python -m security_agent` with no provider, which takes the Messages API path
and needs an `ANTHROPIC_API_KEY` — a key the owner ruled out permanently that
same day. The tool had no flag to say otherwise and no test that ran its command
builder, so a 219-line instrument sat in `tools/` looking usable.

These tests do not run a review. They check the command that would be run, and
the labelling of the cost column, which is a notional API price whenever the
subscription paid for the run.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

import pytest

TOOLS = Path(__file__).resolve().parents[1] / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import measure_variance  # noqa: E402


def args(**overrides):
    base = {"repo": "/tmp/repo", "base": None, "head": None, "effort": None,
            "provider": "claude-cli"}
    base.update(overrides)
    return argparse.Namespace(**base)


def command_for(namespace, monkeypatch):
    """The argv `run_once` would execute, without executing it."""
    seen = {}

    class Result:
        returncode = 2
        stderr = "stopped before doing anything"
        stdout = ""

    def fake_run(cmd, **kwargs):
        seen["cmd"] = cmd
        return Result()

    monkeypatch.setattr(measure_variance.subprocess, "run", fake_run)
    measure_variance.run_once(namespace, 0)
    return seen["cmd"]


class TestItAsksForAProvider:
    def test_the_default_is_the_path_that_needs_no_api_key(self, monkeypatch):
        """The defect, as a test: no provider meant the paid API path."""
        cmd = command_for(args(), monkeypatch)
        assert "--provider" in cmd
        assert cmd[cmd.index("--provider") + 1] == "claude-cli"

    def test_the_paid_path_is_still_reachable_by_name(self, monkeypatch):
        cmd = command_for(args(provider="anthropic-api"), monkeypatch)
        assert cmd[cmd.index("--provider") + 1] == "anthropic-api"

    def test_the_parser_refuses_a_provider_that_does_not_exist(self, capsys):
        parser = argparse.ArgumentParser()
        parser.add_argument("--provider", default="claude-cli",
                            choices=("claude-cli", "anthropic-api"))
        with pytest.raises(SystemExit):
            parser.parse_args(["--provider", "openai"])

    def test_a_diff_run_still_carries_its_base(self, monkeypatch):
        cmd = command_for(args(base="main", head="feature"), monkeypatch)
        assert cmd[cmd.index("--base") + 1] == "main"
        assert cmd[cmd.index("--head") + 1] == "feature"
        assert cmd[cmd.index("--mode") + 1] == "diff"


def run_with_cost(index, usage_cost):
    """A completed run, shaped the way `summarise` reads one."""
    return {
        "ok": True, "index": index, "seconds": 30.0, "exit_code": 1,
        "payload": {
            "usage": usage_cost,
            "coverage": {"turns": 4},
            "verdict": {"blocking_fingerprints": ["a" * 16]},
            "findings": [{"fingerprint": "a" * 16, "severity": "high",
                          "confidence": "high", "title": "a finding"}],
        },
    }


class TestTheCostColumnSaysWhoPaid:
    """`total_cost_usd` on a subscription is a list price, not a bill.

    Three wrong rules about the weekly limit were built by reading a notional
    figure as money spent. The column names itself now.
    """

    @pytest.fixture()
    def priced(self, monkeypatch):
        monkeypatch.setattr(measure_variance, "cost_of", lambda usage: 1.25)
        return [run_with_cost(0, {}), run_with_cost(1, {})]

    def test_the_subscription_path_calls_it_notional(self, capsys, priced):
        measure_variance.summarise(priced, "claude-cli")
        out = capsys.readouterr().out
        assert "cost (notional)" in out
        assert "not an amount anyone was charged" in out

    def test_the_api_path_does_not(self, capsys, priced):
        measure_variance.summarise(priced, "anthropic-api")
        out = capsys.readouterr().out
        assert "cost (notional)" not in out
        assert "not an amount anyone was charged" not in out

    def test_the_default_is_notional(self, capsys, priced):
        measure_variance.summarise(priced)
        assert "cost (notional)" in capsys.readouterr().out

    def test_unreported_usage_is_absent_not_zero(self, capsys, monkeypatch):
        """A run nobody measured must not drag the median to the floor."""
        monkeypatch.setattr(measure_variance, "cost_of", lambda usage: None)
        measure_variance.summarise([run_with_cost(0, {})], "claude-cli")
        out = capsys.readouterr().out
        assert "absent, not $0.000" in out
        assert "$0.000 median" not in out
