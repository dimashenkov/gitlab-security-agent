"""`tools/spend.py` reports what reviews cost, and the honesty is the feature.

The number it prints is one this project has already got wrong three times.
`total_cost_usd` is reported by the Claude Code CLI on a subscription too — a
two-token reply on a Max plan came back as $0.29 — so on that path it is API list
price for the tokens used and nobody was charged it. Three wrong rules about the
weekly allowance were built by reading it as money spent.

So the tests below are not about arithmetic. They are about the four ways the
report could lie: adding a bill to a list price, calling an unreported run free,
deciding who paid from the size of the number, and going quiet when a file
cannot be read.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

TOOLS = Path(__file__).resolve().parents[1] / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import spend  # noqa: E402


def artifact(tmp_path, name, *, provider="claude-cli", cost=1.25,
             subscription="max", when="2026-08-30T12:00:00+00:00",
             usage=None):
    provenance = {"provider": provider, "model_requested": "claude-opus-5",
                  "auth_method": "claude.ai" if subscription else "",
                  "auth_subscription": subscription}
    if cost is not None:
        provenance["reported_cost_usd"] = cost
    body = {"generated_at": when, "provenance": provenance,
            "usage": usage if usage is not None else {
                "input_tokens": 10, "output_tokens": 20,
                "cache_read_tokens": 300, "cache_write_tokens": 40,
                "unreported_stages": 0}}
    path = tmp_path / name
    path.write_text(json.dumps(body), encoding="utf-8")
    return path


class TestBilledAndNotionalNeverMerge:
    def test_the_two_columns_are_reported_separately(self, tmp_path, capsys):
        rows = spend.artifacts([
            artifact(tmp_path, "a.json", provider="anthropic-api",
                     subscription="", cost=2.00),
            artifact(tmp_path, "b.json", provider="claude-cli", cost=3.00),
        ])
        spend.summarise(rows)
        out = capsys.readouterr().out
        assert "2.00" in out and "3.00" in out
        assert "5.00" not in out, "a bill and a list price were added together"
        assert "are not added" in out

    def test_who_paid_comes_from_the_provider_not_the_number(self, tmp_path):
        """A big number on a subscription is still not a bill."""
        expensive = spend.artifacts([artifact(
            tmp_path, "a.json", provider="claude-cli", cost=999.0)])[0]
        assert not spend.billed(expensive)
        assert "notional" in spend.who_paid(expensive)

    def test_an_api_run_is_billed_even_when_it_cost_almost_nothing(self, tmp_path):
        cheap = spend.artifacts([artifact(
            tmp_path, "a.json", provider="anthropic-api", subscription="",
            cost=0.001)])[0]
        assert spend.billed(cheap)
        assert "billed" in spend.who_paid(cheap)

    def test_the_subscription_is_named_when_it_is_known(self, tmp_path):
        row = spend.artifacts([artifact(tmp_path, "a.json", subscription="max")])[0]
        assert "max" in spend.who_paid(row)


class TestAbsentIsNotZero:
    def test_a_run_that_reported_no_cost_is_counted_apart(self, tmp_path, capsys):
        rows = spend.artifacts([
            artifact(tmp_path, "a.json", cost=None),
            artifact(tmp_path, "b.json", cost=2.00),
        ])
        spend.summarise(rows)
        out = capsys.readouterr().out
        assert "Absent, not $0.00" in out
        assert "1 run(s) reported no cost" in out

    def test_it_does_not_drag_the_median(self, tmp_path, capsys):
        """Padding with zero makes an unmeasured run look like a cheap one."""
        rows = spend.artifacts([
            artifact(tmp_path, "a.json", cost=None),
            artifact(tmp_path, "b.json", cost=2.00),
            artifact(tmp_path, "c.json", cost=4.00),
        ])
        spend.summarise(rows)
        out = capsys.readouterr().out
        assert "$3.00 median" in out, "the median moved toward a floor of zero"

    def test_cost_of_returns_none_rather_than_zero(self, tmp_path):
        row = spend.artifacts([artifact(tmp_path, "a.json", cost=None)])[0]
        assert spend.cost_of(row) is None

    def test_a_genuine_zero_is_kept(self, tmp_path):
        row = spend.artifacts([artifact(tmp_path, "a.json", cost=0.0)])[0]
        assert spend.cost_of(row) == 0.0


class TestItAdmitsWhatItCouldNotSee:
    def test_unreported_stages_are_named(self, tmp_path, capsys):
        rows = spend.artifacts([artifact(
            tmp_path, "a.json",
            usage={"input_tokens": 1, "unreported_stages": 2})])
        spend.summarise(rows)
        assert "token counts above are a floor" in capsys.readouterr().out

    def test_an_unreadable_file_is_reported_not_swallowed(self, tmp_path, capsys):
        good = artifact(tmp_path, "a.json")
        bad = tmp_path / "broken.json"
        bad.write_text("{not json", encoding="utf-8")
        rows = spend.artifacts([good, bad])
        assert len(rows) == 1
        spend.summarise(rows, unreadable=1)
        assert "1 file(s) could not be read" in capsys.readouterr().out

    def test_no_artifacts_is_exit_two_not_a_zero_report(self, capsys):
        """Nothing to read is not "you spent nothing"."""
        assert spend.summarise([]) == 2
        assert "No artifacts found" in capsys.readouterr().out


class TestGrouping:
    def test_by_month_collapses_days(self, tmp_path, capsys):
        rows = spend.artifacts([
            artifact(tmp_path, "a.json", when="2026-08-01T00:00:00+00:00"),
            artifact(tmp_path, "b.json", when="2026-08-30T00:00:00+00:00"),
        ])
        spend.summarise(rows, by="month")
        out = capsys.readouterr().out
        assert "2026-08 " in out
        assert "2026-08-01" not in out

    def test_a_run_with_no_timestamp_is_named_not_dropped(self, tmp_path, capsys):
        rows = spend.artifacts([artifact(tmp_path, "a.json", when="")])
        spend.summarise(rows)
        assert "undated" in capsys.readouterr().out
