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

TOOLS = Path(__file__).resolve().parents[1] / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import spend  # noqa: E402


def artifact(tmp_path, name, *, provider="claude-cli", cost=1.25,
             subscription="max", when="2026-08-30T12:00:00+00:00",
             usage=None, auth_method=None):
    if auth_method is None:
        auth_method = "claude.ai" if subscription else "api-key"
    provenance = {"provider": provider, "model_requested": "claude-opus-5",
                  "auth_method": auth_method,
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

    def test_who_paid_comes_from_the_login_not_the_number(self, tmp_path):
        """A big number on a subscription is still not a bill."""
        expensive = spend.artifacts([artifact(
            tmp_path, "a.json", provider="claude-cli", cost=999.0)])[0]
        assert not spend.billed(expensive)
        assert "notional" in spend.who_paid(expensive)

    def test_a_cli_run_on_an_api_key_login_is_charged(self, tmp_path):
        """The defect: `claude-cli` is how it was launched, not who paid.

        The first version keyed on the provider and reported this as notional —
        a bill, filed under list price, by the tool written to keep them apart.
        """
        row = spend.artifacts([artifact(
            tmp_path, "a.json", provider="claude-cli", subscription="",
            auth_method="api-key")])[0]
        assert spend.paid_by(row) == spend.CHARGED
        assert spend.billed(row)

    def test_an_unestablished_login_is_neither(self, tmp_path):
        row = spend.artifacts([artifact(
            tmp_path, "a.json", subscription="", auth_method="")])[0]
        assert spend.paid_by(row) == spend.UNKNOWN
        assert not spend.billed(row)
        assert "not established" in spend.who_paid(row)

    def test_a_subscription_needs_both_the_method_and_the_plan(self, tmp_path):
        row = spend.artifacts([artifact(
            tmp_path, "a.json", subscription="", auth_method="claude.ai")])[0]
        assert spend.paid_by(row) == spend.UNKNOWN

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
    def test_unreported_stages_are_named_beside_real_counts(self, tmp_path, capsys):
        """The old version said "the token counts above are a floor" while the
        table carried no token columns at all, and this test passed against it."""
        rows = spend.artifacts([artifact(
            tmp_path, "a.json",
            usage={"input_tokens": 1, "output_tokens": 2,
                   "cache_read_tokens": 3, "cache_write_tokens": 4,
                   "unreported_stages": 2})])
        spend.summarise(rows)
        out = capsys.readouterr().out
        assert "tokens: input 1" in out, "the floor claim needs counts to qualify"
        assert "A floor, not a total" in out
        assert "2 stage(s) ran without reporting" in out

    def test_the_four_counts_are_never_summed_into_one(self, tmp_path, capsys):
        """Cache reads are a tenth of the input rate and writes are twice it."""
        rows = spend.artifacts([artifact(
            tmp_path, "a.json",
            usage={"input_tokens": 1, "output_tokens": 1,
                   "cache_read_tokens": 1, "cache_write_tokens": 1,
                   "unreported_stages": 0})])
        spend.summarise(rows)
        out = capsys.readouterr().out
        assert "tokens: input 1 · output 1" in out
        assert "dominated by the cheapest" in out

    def test_an_unreadable_file_is_reported_not_swallowed(self, tmp_path, capsys):
        good = artifact(tmp_path, "a.json")
        bad = tmp_path / "broken.json"
        bad.write_text("{not json", encoding="utf-8")
        rows = spend.artifacts([good, bad])
        assert len(rows) == 1
        spend.summarise(rows, unreadable=1)
        assert "1 file(s) could not be read" in capsys.readouterr().out

    def test_no_records_is_exit_two_not_a_zero_report(self, capsys):
        """Nothing to read is not "you spent nothing"."""
        assert spend.summarise([]) == 2
        assert "not the same as nothing having been spent" in capsys.readouterr().out

    def test_the_artifact_source_admits_it_is_a_selected_sample(self, tmp_path, capsys):
        """This repository keeps an artifact for the members that failed.

        Saying so in a test docstring and not in the output is how "22 runs"
        gets read as total spend.
        """
        spend.summarise(spend.artifacts([artifact(tmp_path, "a.json")]),
                        source="artifacts")
        assert "not total spend" in capsys.readouterr().out


class TestTheQueueLogIsASeparateSource:
    """The corpus kept an artifact only for members that failed.

    So the artifacts are a biased sample of the spend, and the queue's own log
    is the complete one. They are read separately and never added: a review can
    appear in both, nothing keys them together, and summing them would inflate
    the single number this tool exists to state carefully.
    """

    def log(self, tmp_path, *rows):
        path = tmp_path / "log.jsonl"
        path.write_text("\n".join(json.dumps(r) for r in rows) + "\n",
                        encoding="utf-8")
        return path

    def review(self, **over):
        row = {"kind": "review", "case_id": "c", "member": "unsafe",
               "started_at": "2026-08-30T12:00:00+00:00",
               "notional_api_cost": 1.5, "usage_reported": True,
               "input_tokens": 10, "output_tokens": 20,
               "cache_read_tokens": 30, "cache_write_tokens": 40}
        row.update(over)
        return row

    def test_a_review_row_becomes_a_notional_run(self, tmp_path):
        rows = spend.queue_rows(self.log(tmp_path, self.review()))
        assert len(rows) == 1
        assert not spend.billed(rows[0])
        assert spend.cost_of(rows[0]) == 1.5

    def test_a_window_row_is_not_a_review(self, tmp_path):
        rows = spend.queue_rows(self.log(
            tmp_path, {"kind": "window", "window_termination": "refused"}))
        assert rows == []

    def test_a_row_without_a_cost_reports_none_not_zero(self, tmp_path):
        rows = spend.queue_rows(self.log(
            tmp_path, self.review(notional_api_cost=None)))
        assert spend.cost_of(rows[0]) is None

    def test_an_unreported_usage_block_is_an_admitted_gap(self, tmp_path):
        """`usage_reported: false` is a run whose figures never arrived."""
        rows = spend.queue_rows(self.log(
            tmp_path, self.review(usage_reported=False)))
        assert spend.unreported_stages(rows[0]) == 1

    def test_an_unparseable_line_is_counted_not_swallowed(self, tmp_path, capsys):
        """The artifact path promised unreadable records are reported; this one
        had the same obligation and dropped them in silence."""
        path = tmp_path / "log.jsonl"
        path.write_text("not json\n" + json.dumps(self.review()) + "\n",
                        encoding="utf-8")
        rows = spend.queue_rows(path)
        assert len(rows) == 1
        assert spend.QUEUE_SKIPPED == 1
        spend.summarise(rows, source="queue", skipped_lines=spend.QUEUE_SKIPPED)
        assert "1 line(s) of the queue log did not parse" in capsys.readouterr().out

    def test_a_row_carrying_its_login_is_classified(self, tmp_path):
        rows = spend.queue_rows(self.log(tmp_path, self.review(
            auth_method="claude.ai", auth_subscription="max")))
        assert spend.paid_by(rows[0]) == spend.NOTIONAL_

    def test_a_row_written_before_the_queue_recorded_it_stays_unknown(self, tmp_path):
        """Old rows say `claude-cli` and nothing about the login. Reading that
        as a subscription is the guess this whole tool refuses."""
        rows = spend.queue_rows(self.log(tmp_path, self.review()))
        assert spend.paid_by(rows[0]) == spend.UNKNOWN

    def test_a_missing_log_is_empty_not_an_error(self, tmp_path):
        assert spend.queue_rows(tmp_path / "absent.jsonl") == []


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

    def test_an_offset_timestamp_is_grouped_by_its_utc_day(self, tmp_path, capsys):
        """`2026-08-31T01:00+03:00` is 2026-08-30 in UTC and sorts as the 31st.

        Every other tool here compares the text. This one parses, because a
        report about money should not file a run under the wrong day.
        """
        rows = spend.artifacts([artifact(
            tmp_path, "a.json", when="2026-08-31T01:00:00+03:00")])
        spend.summarise(rows)
        out = capsys.readouterr().out
        assert "2026-08-30" in out
        assert "2026-08-31" not in out

    def test_a_timestamp_without_an_offset_is_undated_rather_than_guessed(self):
        """Assuming UTC moves a run between days on someone else's machine."""
        assert spend.instant("2026-08-30T12:00:00") is None
        assert spend.instant("2026-08-30T12:00:00Z") is not None


class TestTheCommandItself:
    """Codex's objection: the tests validated helpers, not the CLI.

    Several passed on values handed to `summarise` directly — the unreadable-file
    count among them, which `main()` has to compute and pass on and which no test
    made it do. These drive `main()` and read what it printed.
    """

    def test_it_reports_on_the_files_it_is_given(self, tmp_path, capsys):
        good = artifact(tmp_path, "a.json", cost=2.00)
        assert spend.main([str(good)]) == 0
        assert "2.00" in capsys.readouterr().out

    def test_it_counts_the_files_it_could_not_read(self, tmp_path, capsys):
        """`main()` computes this; passing it to `summarise` by hand did not."""
        good = artifact(tmp_path, "a.json")
        bad = tmp_path / "broken.json"
        bad.write_text("{not json", encoding="utf-8")
        spend.main([str(good), str(bad)])
        assert "1 file(s) could not be read" in capsys.readouterr().out

    def test_a_path_that_does_not_exist_is_exit_two(self, tmp_path, capsys):
        assert spend.main([str(tmp_path / "absent.json")]) == 2
        assert "not the same as nothing having been spent" in capsys.readouterr().out

    def test_since_keeps_the_later_run_and_drops_the_earlier(self, tmp_path, capsys):
        old = artifact(tmp_path, "a.json", when="2026-07-01T12:00:00+00:00", cost=9.99)
        new = artifact(tmp_path, "b.json", when="2026-08-30T12:00:00+00:00", cost=1.11)
        spend.main([str(old), str(new), "--since", "2026-08-01"])
        out = capsys.readouterr().out
        assert "1.11" in out
        assert "9.99" not in out

    def test_since_keeps_a_run_whose_stamp_cannot_be_read(self, tmp_path, capsys):
        """A filter that silently removes what it cannot parse makes the report
        shorter and says nothing."""
        undated = artifact(tmp_path, "a.json", when="", cost=1.11)
        spend.main([str(undated), "--since", "2026-08-01"])
        out = capsys.readouterr().out
        assert "undated" in out
        assert "1.11" in out

    def test_the_detail_view_names_who_paid_per_run(self, tmp_path, capsys):
        row = artifact(tmp_path, "a.json", subscription="max")
        spend.main([str(row), "--detail"])
        out = capsys.readouterr().out
        assert "who paid" in out
        assert "subscription (max)" in out
