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
import os
import sys
from pathlib import Path

import pytest

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

    @pytest.mark.parametrize("cost", ["1.25", True, -1, float("nan"),
                                      {"usd": 1}])
    def test_a_malformed_queue_cost_is_carried_through_not_sanitised(
            self, tmp_path, cost):
        """Codex, 2026-09-06: this reader filtered on
        `isinstance(..., (int, float))`, which dropped a present-but-unreadable
        `"1.25"` — so it reached the report as "no cost recorded" and printed a
        floor — and let `True` through as `$1.00`. Sanitising here takes the
        judgement away from the one function that makes it."""
        rows = spend.queue_rows(self.log(
            tmp_path, self.review(notional_api_cost=cost)))
        assert "reported_cost_usd" in rows[0]["provenance"], (
            "a present value was dropped, so the report cannot tell it from "
            "a run that recorded nothing")
        assert spend.cost_of(rows[0]) is None

    def test_an_absent_queue_cost_stays_absent(self, tmp_path):
        row = self.review()
        del row["notional_api_cost"]
        rows = spend.queue_rows(self.log(tmp_path, row))
        assert "reported_cost_usd" not in rows[0]["provenance"]

    def test_the_producers_own_spelling_of_absent_is_absent(self, tmp_path):
        """Codex, 2026-09-06: `run_queue.py` always writes the key and puts
        `None` in it when the provider reported nothing, so a presence check
        alone filed every such row as a malformed cost — an indeterminate hole
        where the floor belongs. Checked against the producer rather than
        against a test that deletes the key, which is not what it writes."""
        rows = spend.queue_rows(self.log(
            tmp_path, self.review(notional_api_cost=None)))
        assert spend.cost_state(rows[0]) == "absent"

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
        assert spend.main([str(good), "--breakdown"]) == 0
        assert "2.00" in capsys.readouterr().out

    def test_it_counts_the_files_it_could_not_read(self, tmp_path, capsys):
        """`main()` computes this; passing it to `summarise` by hand did not."""
        good = artifact(tmp_path, "a.json")
        bad = tmp_path / "broken.json"
        bad.write_text("{not json", encoding="utf-8")
        spend.main([str(good), str(bad), "--breakdown"])
        assert "1 file(s) could not be read" in capsys.readouterr().out

    def test_a_path_that_does_not_exist_is_exit_two(self, tmp_path, capsys):
        assert spend.main([str(tmp_path / "absent.json"), "--breakdown"]) == 2
        out = capsys.readouterr().out
        # The sentence moved to the headline when it was put in front of every
        # report. A file that could not be read is a problem with the records,
        # not an empty ledger, and the line now says which of the two it is.
        assert "nothing here can be trusted to add up" in out
        assert "could not be read" in out

    def test_since_keeps_the_later_run_and_drops_the_earlier(self, tmp_path, capsys):
        old = artifact(tmp_path, "a.json", when="2026-07-01T12:00:00+00:00", cost=9.99)
        new = artifact(tmp_path, "b.json", when="2026-08-30T12:00:00+00:00", cost=1.11)
        spend.main([str(old), str(new), "--since", "2026-08-01", "--breakdown"])
        out = capsys.readouterr().out
        assert "1.11" in out
        assert "9.99" not in out

    def test_since_keeps_a_run_whose_stamp_cannot_be_read(self, tmp_path, capsys):
        """A filter that silently removes what it cannot parse makes the report
        shorter and says nothing."""
        undated = artifact(tmp_path, "a.json", when="", cost=1.11)
        spend.main([str(undated), "--since", "2026-08-01", "--breakdown"])
        out = capsys.readouterr().out
        assert "undated" in out
        assert "1.11" in out

    def test_the_detail_view_names_who_paid_per_run(self, tmp_path, capsys):
        row = artifact(tmp_path, "a.json", subscription="max")
        spend.main([str(row), "--detail"])
        out = capsys.readouterr().out
        assert "who paid" in out
        assert "subscription (max)" in out


def vendor_record(tmp_path, name="grok-adjudication.json", *,
                  vendor="nobody-has-mapped-this",
                  block="cases", calls=(("c1", "req-1", 0.006),)):
    body = {"vendor": vendor, "started_at": "2026-09-05T10:00:00+00:00",
            block: {work: {"request_id": request, "cost_usd": cost,
                           "asked_at": "2026-09-05T10:00:00+00:00"}
                    for work, request, cost in calls}}
    path = tmp_path / name
    path.write_text(json.dumps(body), encoding="utf-8")
    return path


class TestTheOneFigure:
    """The owner asked for one figure, a breakdown only when he asks for it,
    and the figure in every report from here on. So it must never read as an
    answer when it is not one."""

    def test_it_prints_one_line_and_not_the_table(self, tmp_path, capsys):
        row = artifact(tmp_path, "a.json", subscription="max")
        spend.main([str(row)])
        out = capsys.readouterr().out
        assert out.startswith("Spend:")
        assert "notional $" not in out

    def test_zero_charged_is_not_printed_while_anything_is_unestablished(
            self, tmp_path, capsys):
        """Codex, 2026-09-05: `$0.00 charged` printed while paid subscription
        capacity was demonstrably consumed invites "nothing was spent", and
        this counter cannot establish that."""
        row = artifact(tmp_path, "a.json", subscription="", auth_method="")
        code = spend.main([str(row)])
        out = capsys.readouterr().out
        assert "indeterminate" in out
        assert "$0.00 charged" not in out
        assert code == 2

    def test_zero_charged_is_printed_when_everything_is_established(
            self, tmp_path, capsys):
        """The other half. A subscription run whose login the artifact names is
        classified, so the figure is real and it is zero."""
        row = artifact(tmp_path, "a.json", subscription="max")
        code = spend.main([str(row)])
        out = capsys.readouterr().out
        assert "$0.00 charged" in out
        assert "flat subscription" in out
        assert code == 0

    def test_it_names_what_it_cannot_count(self, tmp_path, capsys):
        row = artifact(tmp_path, "a.json", subscription="max")
        spend.main([str(row)])
        out = capsys.readouterr().out
        assert "not counted anywhere" in out
        assert "the agent session itself" in out

    def test_a_vendor_with_no_established_arrangement_stops_the_figure(
            self, tmp_path, capsys):
        calls = spend.vendor_calls([vendor_record(tmp_path)])
        code = spend.one_figure([], calls)
        out = capsys.readouterr().out
        assert "indeterminate" in out
        assert "1 nobody-has-mapped-this call(s)" in out
        assert "whether one more raises a bill" in out
        assert code == 2

    def test_a_call_with_no_request_id_is_a_ledger_problem_not_a_row(
            self, tmp_path):
        """The billing identity is `(vendor, request_id)`. A call that cannot
        be keyed cannot be told from another, so counting it risks both
        double-counting and hiding a duplicate."""
        path = tmp_path / "grok-adjudication.json"
        path.write_text(json.dumps({
            "vendor": "xai", "cases": {"c1": {"cost_usd": 0.006}}}),
            encoding="utf-8")
        calls = spend.vendor_calls([path])
        assert calls["calls"] == {}
        assert any("no `request_id`" in p for p in calls["problems"])

    def test_the_same_response_twice_is_refused_not_summed(self, tmp_path):
        a = vendor_record(tmp_path, "a.json", calls=(("c1", "req-1", 0.006),))
        b = vendor_record(tmp_path, "b.json", calls=(("c2", "req-1", 0.006),))
        calls = spend.vendor_calls([a, b])
        assert len(calls["calls"]) == 1
        assert any("repeats a response already counted" in p
                   for p in calls["problems"])

    def test_work_ids_are_not_billing_ids(self, tmp_path):
        """Two different cases carrying one response id is one charge. Keying
        by the case id would have made it two."""
        path = vendor_record(tmp_path, calls=(("c1", "req-1", 0.006),
                                              ("c2", "req-1", 0.006)))
        assert len(spend.vendor_calls([path])["calls"]) == 1

    def test_a_record_holding_neither_call_block(self, tmp_path):
        path = tmp_path / "x.json"
        path.write_text(json.dumps({"vendor": "xai"}), encoding="utf-8")
        problems = spend.vendor_calls([path])["problems"]
        assert any("it takes exactly one" in p for p in problems)

    def test_a_record_naming_no_vendor(self, tmp_path):
        path = tmp_path / "x.json"
        path.write_text(json.dumps({"cases": {}}), encoding="utf-8")
        problems = spend.vendor_calls([path])["problems"]
        assert any("records no vendor" in p for p in problems)

    def test_named_paths_do_not_drag_in_the_repositorys_own_records(
            self, tmp_path, capsys):
        """A caller who passed paths asked about those. Folding the repo's own
        vendor records into that answer reports spending nobody asked about —
        and in a test, spending from a tree the test did not write."""
        row = artifact(tmp_path, "a.json", subscription="max")
        spend.main([str(row)])
        assert "xai" not in capsys.readouterr().out


    def test_a_named_vendor_ledger_is_read_as_one(self, tmp_path, capsys):
        """Codex, 2026-09-05: passing `[]` whenever the caller named anything
        meant somebody pointing this tool at `grok-adjudication.json` got it
        parsed as a review artifact — wrong classification, and a diagnostic
        about the wrong thing."""
        path = vendor_record(tmp_path)
        spend.main([str(path)])
        out = capsys.readouterr().out
        assert "1 nobody-has-mapped-this call(s)" in out

    def test_a_vendor_ledger_is_not_also_counted_as_a_review(
            self, tmp_path, capsys):
        """One record, one kind. It was read as both: the metered calls in one
        column and one nameless 'review' in the other, from one file."""
        path = vendor_record(tmp_path)
        spend.main([str(path)])
        out = capsys.readouterr().out
        assert "review(s) whose login" not in out

    def test_it_is_recognised_by_content_not_by_name(self, tmp_path, capsys):
        """A caller who renamed the file still means the same thing."""
        path = vendor_record(tmp_path, "whatever.json")
        spend.main([str(path)])
        assert "1 nobody-has-mapped-this call(s)" in capsys.readouterr().out

    def test_a_review_artifact_named_like_a_ledger_is_still_a_review(
            self, tmp_path, capsys):
        """And the other direction, which a name check would get wrong."""
        row = artifact(tmp_path, "grok-adjudication.json", subscription="max")
        spend.main([str(row)])
        out = capsys.readouterr().out
        assert "$0.00 charged" in out
        assert "xai" not in out

    def test_nothing_seen_is_not_nothing_spent(self, capsys):
        """The invariant `summarise` has carried since it was written, and this
        path had lost it. Codex, 2026-09-05: with no artifacts, no vendor
        ledgers and no errors the headline said "$0.00 charged — every call the
        counter saw runs on a flat subscription" about no calls at all, and
        exited 0."""
        code = spend.one_figure([], {"calls": {}, "problems": []})
        out = capsys.readouterr().out
        assert "indeterminate" in out
        assert "no records were found" in out
        assert "not the same as nothing having been spent" in out
        assert "$0.00 charged" not in out
        assert code == 2

    def test_an_empty_report_still_names_what_it_cannot_count(self, capsys):
        spend.one_figure([], {"calls": {}, "problems": []})
        assert "the agent session itself" in capsys.readouterr().out

    @pytest.mark.parametrize("unreadable,skipped", [(1, 0), (0, 2), (0, -1)])
    def test_only_unreadable_records_is_not_an_empty_ledger(
            self, capsys, unreadable, skipped):
        """Codex, 2026-09-05, on the shortcut itself: it checked the rows and
        the vendor calls and not the failure counters, so an invocation holding
        only an unreadable artifact printed "no records were found" — a
        different and more comfortable sentence than "records existed and could
        not be read"."""
        code = spend.one_figure([], {"calls": {}, "problems": []},
                                unreadable=unreadable, skipped_lines=skipped)
        out = capsys.readouterr().out
        assert "no records were found" not in out
        assert "ledger:" in out
        assert "$0.00 charged" not in out
        assert code == 2

    def test_the_figure_is_in_the_breakdown_too(self, tmp_path, capsys):
        """The owner asked for the figure in every report, and a breakdown is
        still a report. Codex, 2026-09-05: the breakdown and detail paths went
        straight to the table, so vendor costs shrank to a call count and
        vendor ledger failures never reached the exit code."""
        row = artifact(tmp_path, "a.json", subscription="max")
        code = spend.main([str(row), "--breakdown"])
        out = capsys.readouterr().out
        assert out.startswith("Spend:")
        assert "notional $" in out
        assert code == 0

    def test_a_vendor_only_ledger_is_not_reported_as_no_records(
            self, tmp_path, capsys):
        """It ran `summarise([])` and printed "no records were found" about a
        file holding the only calls in the report."""
        path = vendor_record(tmp_path)
        code = spend.main([str(path), "--breakdown"])
        out = capsys.readouterr().out
        assert out.startswith("Spend:")
        assert "1 nobody-has-mapped-this call(s)" in out
        # The assertion this test was missing, and the whole point of it: the
        # table denied the calls the headline had just named.
        assert "no records were found" not in out.lower()
        assert "No review artifacts in this report" in out
        assert code == 2

    def test_unreadable_reviews_are_not_reported_as_vendor_only(
            self, tmp_path, capsys):
        """Codex, 2026-09-05: "the metered calls above are the whole of it" is
        true of a vendor-only ledger and false of a report whose review records
        existed and could not be read. There were none, and I could not see
        them, are the two answers this tool exists to keep apart."""
        bad = tmp_path / "broken.json"
        bad.write_text("{not json", encoding="utf-8")
        spend.main([str(bad), "--breakdown"])
        out = capsys.readouterr().out
        assert "the whole of it" not in out
        assert "could not be read rather than because there were none" in out

    def test_a_malformed_vendor_only_ledger_is_not_nothing_at_all(
            self, tmp_path, capsys):
        """Codex, 2026-09-05: the branch asked about `vendor["calls"]` and not
        `vendor["problems"]`, so a readable but invalid vendor-only ledger —
        no calls, one problem — claimed "no metered calls, there were none"
        immediately above the line reporting the malformed record."""
        path = tmp_path / "both.json"
        path.write_text(json.dumps({
            "vendor": "xai",
            "cases": {"c1": {"request_id": "r1", "cost_usd": 0.006}},
            "findings": {"f1": {"request_id": "r2", "cost_usd": 0.006}},
        }), encoding="utf-8")
        spend.main([str(path), "--breakdown"])
        out = capsys.readouterr().out
        # The wrong branch's own sentence, not a substring the right one also
        # contains — "there were none" appears in both.
        assert "no metered calls" not in out
        assert "1 record(s) failed" in out
        assert "could not be read rather than because there were none" in out

    def test_a_round_s_own_log_is_read(self, tmp_path, capsys, monkeypatch):
        """`run_queue --round N` rebinds the log to
        `measurements/round-N/log.jsonl`, and this tool named one path.

        A whole round's rows were invisible to the one command that answers
        "what has this cost" — 52 pairs in a file it never opened.
        """
        import json as _json

        monkeypatch.setattr(spend, "ROOT", tmp_path)
        monkeypatch.setattr(spend, "QUEUE_LOG", "measurements/queue/log.jsonl")
        monkeypatch.setattr(spend, "VENDOR_GLOBS", ())
        directory = tmp_path / "measurements" / "round-2"
        directory.mkdir(parents=True)
        (directory / "log.jsonl").write_text(_json.dumps({
            "kind": "review", "case_id": "a-case", "member": "safe",
            "notional_api_cost": 0.5, "auth_method": "claude.ai",
            "auth_subscription": "max"}) + "\n", encoding="utf-8")

        spend.main(["--breakdown", "--source", "queue"])
        out = capsys.readouterr().out

        # The row was read: one call, seen and placed against a subscription.
        # Without the round glob the counter saw nothing at all.
        assert "(1 of them)" in out, out
        assert "no vendor calls" not in out

    def test_a_run_that_made_no_call_is_not_a_missing_price(self, tmp_path,
                                                            capsys,
                                                            monkeypatch):
        """The artifact records `usage.requests` and this tool never read it.

        So all eight of today's unpriced runs — every one `requests: 0` with
        `stop_reason: error` — were reported as "recorded no cost at all",
        which reads as a price nobody wrote down and made the whole figure a
        floor. It cost nothing because nothing was asked of anybody, and the
        field that says so is in the same file.
        """
        import json as _json

        monkeypatch.setattr(spend, "VENDOR_GLOBS", ())
        body = {"generated_at": "2026-08-30T12:00:00+00:00",
                "provenance": {"provider": "claude-cli",
                               "model_requested": "claude-opus-5"},
                "usage": {"requests": 0, "input_tokens": 0,
                          "output_tokens": 0},
                "findings": []}
        path = tmp_path / "findings.json"
        path.write_text(_json.dumps(body), encoding="utf-8")

        spend.main([str(path)])
        headline = capsys.readouterr().out.splitlines()[0]

        assert "made no provider call at all" in headline, headline
        assert "recorded no cost at all" not in headline

    def test_a_run_with_no_requests_field_is_still_a_missing_price(
            self, tmp_path, capsys, monkeypatch):
        """The control, and the third state. A run that records no `requests`
        key at all has said nothing about whether it called anybody, and
        reading that absence as zero would be the mistake this file is
        about."""
        import json as _json

        monkeypatch.setattr(spend, "VENDOR_GLOBS", ())
        body = {"generated_at": "2026-08-30T12:00:00+00:00",
                "provenance": {"provider": "claude-cli",
                               "model_requested": "claude-opus-5"},
                "usage": {"input_tokens": 10, "output_tokens": 5},
                "findings": []}
        path = tmp_path / "findings.json"
        path.write_text(_json.dumps(body), encoding="utf-8")

        spend.main([str(path)])
        headline = capsys.readouterr().out.splitlines()[0]

        assert "recorded no cost at all" in headline, headline
        assert "made no provider call" not in headline

    def test_one_file_named_twice_is_one_call(self, tmp_path, capsys,
                                              monkeypatch):
        """`tools/spend.py PATH PATH` printed `$10.00 charged, from 2 metered
        call(s)` for one $5.00 call — flatly, no `≥`, no qualification, exit 0.

        A hard link, or `a/../a/x.json` beside `a/x.json`, does the same. The
        duplicate warning that exists only fires when a file literally named
        `rows.json` is present, so nothing caught it. Identity is the inode,
        not the path text.
        """
        monkeypatch.setattr(spend, "VENDOR_GLOBS", ())
        one = artifact(tmp_path, "a.json", cost=5.0,
                       provider="anthropic-api", subscription=None)

        assert spend.main([str(one), str(one)]) == 0
        out = capsys.readouterr().out
        assert "$5.00" in out, out
        assert "$10.00" not in out

        # And the same file reached by a second path spelling.
        indirect = tmp_path / "sub" / ".." / "a.json"
        (tmp_path / "sub").mkdir()
        spend.main([str(one), str(indirect)])
        assert "$5.00" in capsys.readouterr().out

    def test_two_different_files_still_add_up(self, tmp_path, capsys,
                                              monkeypatch):
        """The control. Without it the deduplication above could drop every
        file after the first and the total would be silently short."""
        monkeypatch.setattr(spend, "VENDOR_GLOBS", ())
        first = artifact(tmp_path, "a.json", cost=5.0,
                         provider="anthropic-api", subscription=None)
        second = artifact(tmp_path, "b.json", cost=3.0,
                          provider="anthropic-api", subscription=None)

        spend.main([str(first), str(second)])
        assert "$8.00" in capsys.readouterr().out

    def test_a_healthy_round_log_does_not_hide_a_broken_queue_log(
            self, tmp_path, capsys, monkeypatch):
        """`QUEUE_SKIPPED` is a module global that `queue_rows` resets on entry
        and sets on exit, and `main` read it once after the loop.

        So with more than one log only the *last* one's count survived: a
        healthy round log erased the unparseable lines in the queue's own, and
        the headline printed `$0.00 charged` with exit 0 — the sentence this
        file exists never to print while anything is unestablished.

        The two tests written when the round logs were added covered one log
        each and never both. This is the combination they carried between
        them.
        """
        import json as _json

        monkeypatch.setattr(spend, "ROOT", tmp_path)
        monkeypatch.setattr(spend, "VENDOR_GLOBS", ())
        clean = _json.dumps({
            "kind": "review", "started_at": "2026-09-09T10:00:00+00:00",
            "case_id": "c1", "member": "safe", "auth_method": "claude.ai",
            "auth_subscription": "max", "usage_reported": True,
            "notional_api_cost": 1.0}) + "\n"

        queue = tmp_path / "measurements" / "queue"
        queue.mkdir(parents=True)
        (queue / "log.jsonl").write_text(
            clean + "{ this line does not parse\n{ nor this one\n",
            encoding="utf-8")
        rounds = tmp_path / "measurements" / "round-7"
        rounds.mkdir(parents=True)
        (rounds / "log.jsonl").write_text(clean, encoding="utf-8")

        assert spend.main(["--breakdown", "--source", "queue"]) == 2
        out = capsys.readouterr().out
        assert "$0.00 charged" not in out
        assert "2 line(s) of the queue log did not parse" in out

    def test_an_unreadable_log_beside_a_healthy_one_still_says_so(
            self, tmp_path, capsys, monkeypatch):
        """The `-1` sentinel means "could not be read at all" and has to
        survive being mixed with a number: a log nobody could open is not
        fewer bad lines than a log with two."""
        import json as _json
        import os

        monkeypatch.setattr(spend, "ROOT", tmp_path)
        monkeypatch.setattr(spend, "VENDOR_GLOBS", ())
        clean = _json.dumps({
            "kind": "review", "started_at": "2026-09-09T10:00:00+00:00",
            "case_id": "c1", "member": "safe", "auth_method": "claude.ai",
            "auth_subscription": "max", "usage_reported": True,
            "notional_api_cost": 1.0}) + "\n"

        queue = tmp_path / "measurements" / "queue"
        queue.mkdir(parents=True)
        broken = queue / "log.jsonl"
        broken.write_text(clean, encoding="utf-8")
        os.chmod(broken, 0o000)
        rounds = tmp_path / "measurements" / "round-7"
        rounds.mkdir(parents=True)
        (rounds / "log.jsonl").write_text(clean, encoding="utf-8")

        try:
            assert spend.main(["--breakdown", "--source", "queue"]) == 2
            out = capsys.readouterr().out
            assert "$0.00 charged" not in out
            assert "could not be read at all" in out
        finally:
            os.chmod(broken, 0o644)

    def test_an_entirely_empty_breakdown_says_so_plainly(
            self, tmp_path, capsys, monkeypatch):
        """No reviews, no metered calls, and nothing that failed. `--source
        queue` reads the repository's own log rather than a named path, so
        both it and the vendor globs are pointed at nothing here."""
        monkeypatch.setattr(spend, "QUEUE_LOG", "absent/log.jsonl")
        monkeypatch.setattr(spend, "VENDOR_GLOBS", ())
        spend.main(["--breakdown", "--source", "queue"])
        out = capsys.readouterr().out
        assert "no vendor calls" in out
        assert "the whole of it" not in out

    def test_a_vendor_ledger_failure_reaches_the_exit_code_in_a_breakdown(
            self, tmp_path, capsys):
        good = artifact(tmp_path, "a.json", subscription="max")
        bad = tmp_path / "grok.json"
        bad.write_text(json.dumps({"vendor": "xai",
                                   "cases": {"c1": {"cost_usd": 0.006}}}),
                       encoding="utf-8")
        code = spend.main([str(good), str(bad), "--breakdown"])
        assert "no `request_id`" in capsys.readouterr().out
        assert code == 2

    def test_a_broken_log_does_not_haunt_the_next_call(self, tmp_path):
        """Codex, 2026-09-05: the absent-file branch returned without resetting
        `QUEUE_SKIPPED`, so a run that had found a broken log left `-1` behind
        and the next call — with no log at all — reported that earlier failure
        as its own. Module state outliving the call it describes is a wrong
        answer waiting for a second invocation."""
        broken = tmp_path / "log.jsonl"
        broken.write_text("{not json\n", encoding="utf-8")
        spend.queue_rows(broken)
        assert spend.QUEUE_SKIPPED == 1

        spend.queue_rows(tmp_path / "absent.jsonl")
        assert spend.QUEUE_SKIPPED == 0

    def test_a_ledger_failure_alone_stops_the_figure(self, tmp_path, capsys):
        """Codex, 2026-09-05: an unreadable artifact, a malformed queue line, a
        call with no `request_id`, a duplicated response — each left the
        headline saying "$0.00 charged, every call runs on a flat subscription"
        while the line beneath it reported the error and the exit code was 2.
        Records that cannot be trusted to add up do not justify a number,
        whatever the reason they cannot.
        """
        good = artifact(tmp_path, "a.json", subscription="max")
        bad = tmp_path / "broken.json"
        bad.write_text("{not json", encoding="utf-8")

        code = spend.main([str(good), str(bad)])
        out = capsys.readouterr().out
        assert "indeterminate" in out
        assert "$0.00 charged" not in out
        assert "nothing here can be trusted to add up" in out
        assert code == 2

    def test_a_path_that_does_not_exist_stops_the_figure(self, tmp_path, capsys):
        """The simplest one, and the CLI tests were all switched to
        `--breakdown`, which left this default path uncovered."""
        code = spend.main([str(tmp_path / "absent.json")])
        out = capsys.readouterr().out
        assert "indeterminate" in out
        assert "$0.00 charged" not in out
        assert code == 2

    def test_a_ledger_with_both_call_blocks_is_still_a_ledger(
            self, tmp_path, capsys):
        """Codex, 2026-09-05: the detector asked `any` and the reader required
        exactly one, so a file carrying both `cases` and `findings` was
        excluded from the reviews as a ledger and then refused as a ledger — it
        disappeared from both counts and left only an error. One predicate now.
        """
        path = tmp_path / "both.json"
        path.write_text(json.dumps({
            "vendor": "xai",
            "cases": {"c1": {"request_id": "r1", "cost_usd": 0.006}},
            "findings": {"f1": {"request_id": "r2", "cost_usd": 0.006}},
        }), encoding="utf-8")
        assert spend._looks_like_a_vendor_ledger(path)
        problems = spend.vendor_calls([path])["problems"]
        assert any("it takes exactly one" in p for p in problems)

        code = spend.main([str(path)])
        out = capsys.readouterr().out
        assert "ledger:" in out
        assert "review(s) whose login" not in out
        assert code == 2

    @pytest.mark.parametrize("body", [
        {"vendor": "   ", "cases": {}},
        {"cases": {}},
        {"vendor": 3, "findings": {}},
        # A block of the wrong type. Codex, 2026-09-05: asking for the right
        # type is still validation, and validation in the discriminator sends
        # a malformed record to the reader that cannot describe it.
        {"cases": []},
        {"vendor": "xai", "cases": None},
    ])
    def test_a_ledger_naming_no_vendor_is_still_routed_to_the_ledger_reader(
            self, tmp_path, capsys, body):
        """Codex, 2026-09-05: the discriminator asked `_vendor_blocks`, which
        requires a usable vendor, so a ledger that named none was routed to the
        review reader and came back as an unclassified review rather than the
        "records no vendor" ledger problem it is. A malformed record of a kind
        is still a record of that kind."""
        path = tmp_path / "blank.json"
        path.write_text(json.dumps(body), encoding="utf-8")
        assert spend._looks_like_a_vendor_ledger(path)

        spend.main([str(path)])
        out = capsys.readouterr().out
        # Which ledger complaint depends on what is wrong — no vendor, or a
        # vendor with an unusable block. Either is a ledger problem, and the
        # thing being pinned is that it is not counted as a review.
        assert "records no vendor" in out or "it takes exactly one" in out
        assert "review(s) whose login" not in out

    def test_a_review_that_happens_to_hold_a_cases_key_stays_a_review(
            self, tmp_path, capsys):
        """The other direction of the same discriminator: `provenance` is what
        a review carries, and asking for its absence keeps one on the review
        side where its login can still be read."""
        body = json.loads(artifact(tmp_path, "a.json",
                                   subscription="max").read_text())
        body["cases"] = {"c1": {}}
        path = tmp_path / "b.json"
        path.write_text(json.dumps(body), encoding="utf-8")

        assert not spend._looks_like_a_vendor_ledger(path)
        spend.main([str(path)])
        out = capsys.readouterr().out
        assert "$0.00 charged" in out
        assert "records no vendor" not in out

    def test_the_line_says_what_it_covers_and_when(self, tmp_path, capsys):
        """A bare figure quoted in a report is about something as of some time,
        and two identical reports written on different days would otherwise
        carry different numbers with nothing saying why."""
        row = artifact(tmp_path, "a.json", subscription="max")
        spend.main([str(row)])
        out = capsys.readouterr().out
        assert "scope:" in out
        assert "1 named path(s)" in out
        assert "as of" in out

    def test_since_discloses_that_it_filters_only_half(self, tmp_path, capsys):
        """`--since` filters the review rows and not the vendor calls, so the
        two halves of one figure cover different windows. Said out loud rather
        than left for the reader to discover."""
        row = artifact(tmp_path, "a.json", subscription="max")
        spend.main([str(row), "--since", "2026-08-01"])
        out = capsys.readouterr().out
        assert "filters the reviews and not the vendor calls" in out


class TestAFlatVendorIsCountedAndNotSummed:
    """Established by the owner on 2026-09-06: SuperGrok Lite, €20 a month, so
    one more call moves no bill. The figure in each record is list price for
    tokens nobody was charged for — the same shape as Claude Code's, and the
    most tempting number in the file because it looks exactly like an invoice.
    """

    def test_the_arrangement_is_recorded_with_its_date(self):
        entry = spend.BILLING_ARRANGEMENT["xai"]
        assert entry["kind"] == spend.FLAT
        assert entry["established"] == "2026-09-06"

    def test_a_flat_call_is_counted_and_its_figure_is_not(
            self, tmp_path, capsys):
        path = vendor_record(tmp_path, vendor="xai",
                             calls=(("c1", "r1", 0.006), ("c2", "r2", 0.006)))
        code = spend.main([str(path)])
        out = capsys.readouterr().out
        assert "$0.00 charged" in out
        assert "flat subscription (2 of them)" in out
        assert "0.0120" not in out, "a flat figure was added to the total"
        assert "0.0062" not in out, "a flat figure reached the headline"
        assert "indeterminate" not in out
        assert code == 0

    # `None` is not in this list: it is the JSON spelling of "no value" and is
    # absent, not malformed, on both the vendor and the review side.
    @pytest.mark.parametrize("cost", ["bad", True, -1, float("nan")])
    def test_a_bad_cost_on_a_flat_call_is_a_note_not_a_refusal(
            self, tmp_path, capsys, cost):
        """Adjudicated with Codex on 2026-09-06, against his first position.

        For a FLAT arrangement `cost_usd` is neither added nor used to
        classify, so its contents cannot make the money answer unknowable.
        Refusing over it would conflate record hygiene with arithmetic
        integrity. It is surfaced because the arrangement can change, and from
        that day the same value is load-bearing and blocking.
        """
        path = vendor_record(tmp_path, vendor="xai",
                             calls=(("c1", "r1", cost),))
        code = spend.main([str(path)])
        out = capsys.readouterr().out
        assert "noted, and it changes no number above" in out
        assert "because this vendor is flat" in out
        assert "indeterminate" not in out
        assert code == 0

    def test_the_same_bad_cost_on_a_metered_call_does_refuse(
            self, tmp_path, capsys, monkeypatch):
        """The other side of the ruling: change the arrangement and the same
        value stops the figure."""
        monkeypatch.setitem(spend.BILLING_ARRANGEMENT, "xai",
                            {"kind": spend.METERED, "established": "test"})
        path = vendor_record(tmp_path, vendor="xai",
                             calls=(("c1", "r1", "bad"),))
        code = spend.main([str(path)])
        out = capsys.readouterr().out
        assert "indeterminate" in out
        assert code == 2

    def test_an_arrangement_this_tool_cannot_read_is_not_a_licence_to_pick_one(
            self, tmp_path, capsys, monkeypatch):
        """A `kind` the tool does not know is nobody having established it —
        not a reason to choose the cheaper reading."""
        monkeypatch.setitem(spend.BILLING_ARRANGEMENT, "xai",
                            {"kind": "probably free", "established": "x"})
        path = vendor_record(tmp_path, vendor="xai")
        code = spend.main([str(path)])
        out = capsys.readouterr().out
        assert "indeterminate" in out
        assert code == 2


class TestAFloorIsNotAnAnswer:
    """A run that recorded no cost at all cannot move a total it contributes
    nothing to, so it does not stop the figure — but it happened, and printing
    its absence as nothing is "absent is not zero" one level up."""

    def test_the_figure_is_marked_as_a_floor(self, tmp_path, capsys):
        priced = artifact(tmp_path, "a.json", subscription="", cost=2.00,
                          auth_method="api-key")
        # Not a subscription row: a review whose path is flat has a notional
        # cost, and an absent notional cost cannot bound a charged total. The
        # floor is for a run that *could* have been charged and said nothing.
        silent = artifact(tmp_path, "b.json", cost=None, subscription="",
                          auth_method="")
        code = spend.main([str(priced), str(silent)])
        out = capsys.readouterr().out
        assert out.startswith("Spend: ≥ ")
        assert "a floor, not the answer" in out
        assert "1 run(s) recorded no cost at all" in out
        assert code == 2

    def test_a_complete_ledger_carries_no_floor_mark(self, tmp_path, capsys):
        priced = artifact(tmp_path, "a.json", subscription="", cost=2.00,
                          auth_method="api-key")
        code = spend.main([str(priced)])
        out = capsys.readouterr().out
        assert "≥" not in out
        assert "floor" not in out
        assert "$2.00 charged" in out
        assert code == 0

    @pytest.mark.parametrize("cost", [-1, "1.25", float("nan"),
                                      float("inf"), True])
    def test_a_malformed_cost_is_not_a_floor(self, tmp_path, capsys, cost):
        """Codex, 2026-09-06: `cost_of` returns `None` both for an absent cost
        and for one that is present and unreadable, so `-1` or `"1.25"` was
        printed as a floor. A floor says "at least this much"; a malformed
        amount cannot be bounded at all."""
        row = artifact(tmp_path, "a.json", subscription="",
                       auth_method="api-key", cost=cost)
        code = spend.main([str(row)])
        out = capsys.readouterr().out
        assert "indeterminate" in out
        assert "floor" not in out
        assert "where a cost belongs" in out
        assert code == 2

    def test_the_table_agrees_with_the_headline_about_a_bad_cost(
            self, tmp_path, capsys):
        """Codex, 2026-09-06: `summarise` filed every unusable cost under
        "reported no cost at all", so the headline said the figure could not be
        established while the table underneath called the same row absent —
        two readers of one row disagreeing inside one report."""
        row = artifact(tmp_path, "a.json", subscription="",
                       auth_method="api-key", cost="1.25")
        spend.main([str(row), "--breakdown"])
        out = capsys.readouterr().out
        assert "indeterminate" in out
        assert "reported no cost at all" not in out
        assert "other than money where a cost belongs" in out
        assert "are in neither column" in out

    def test_the_table_still_says_absent_for_a_run_with_no_cost(
            self, tmp_path, capsys):
        row = artifact(tmp_path, "a.json", cost=None, subscription="",
                       auth_method="")
        spend.main([str(row), "--breakdown"])
        out = capsys.readouterr().out
        assert "reported no cost at all, and are in neither money column" in out
        assert "other than money where a cost belongs" not in out

    def test_a_null_cost_is_a_floor_and_not_a_hole(self, tmp_path, capsys):
        """The whole point of the split, through the CLI: `null` is the JSON
        spelling of "no value" and belongs with the runs that recorded
        nothing, which bound the total from below."""
        path = tmp_path / "a.json"
        path.write_text(json.dumps({
            "generated_at": "2026-08-30T12:00:00+00:00",
            "provenance": {"provider": "claude-cli", "auth_method": "",
                           "reported_cost_usd": None},
            "usage": {}}), encoding="utf-8")
        code = spend.main([str(path)])
        out = capsys.readouterr().out
        assert "a floor, not the answer" in out
        assert "where a cost belongs" not in out
        assert code == 2

    def test_a_subscription_review_with_no_cost_is_not_a_floor(
            self, tmp_path, capsys):
        """A review whose path is flat has a notional cost, and an absent
        notional cost cannot bound a charged total. The floor is for a run that
        could have been charged and said nothing."""
        row = artifact(tmp_path, "a.json", subscription="max", cost=None)
        code = spend.main([str(row)])
        out = capsys.readouterr().out
        assert "floor" not in out
        assert "flat subscription" in out
        assert code == 0

    def test_a_subscription_review_with_a_bad_cost_is_a_note(
            self, tmp_path, capsys):
        """Codex, 2026-09-06: the cost was judged before who paid, so a review
        on a named subscription with a malformed notional figure made the whole
        figure indeterminate — while the identical case on a flat vendor was a
        note. The same rule now applies to both sides."""
        row = artifact(tmp_path, "a.json", subscription="max", cost="1.25")
        code = spend.main([str(row)])
        out = capsys.readouterr().out
        assert "noted, and it changes no number above" in out
        assert "because that path is flat" in out
        assert "indeterminate" not in out
        assert code == 0

    def test_the_detail_view_tells_absent_from_unreadable(
            self, tmp_path, capsys):
        """The fourth reader of the same three-way answer. Codex, 2026-09-06:
        it rendered both as "not reported", so `--detail` showed a malformed
        `"1.25"` as a run that reported nothing while the headline above called
        the figure indeterminate over it."""
        bad = artifact(tmp_path, "a.json", subscription="max", cost="1.25")
        none = artifact(tmp_path, "b.json", subscription="max", cost=None)
        spend.main([str(bad), str(none), "--detail"])
        out = capsys.readouterr().out
        assert "unreadable" in out
        assert "not reported" in out

    def test_only_anthropic_is_absent_from_the_arrangement_table(self):
        """It had a third `kind`, `per-row`, which the table's own invariant
        does not admit. Its arrangement is per row, and `paid_by` decides it."""
        assert "anthropic" not in spend.BILLING_ARRANGEMENT
        for name, entry in spend.BILLING_ARRANGEMENT.items():
            assert entry is None or entry["kind"] in (spend.FLAT,
                                                      spend.METERED), name

    def test_a_cost_nobody_can_place_still_stops_the_figure(
            self, tmp_path, capsys):
        """The other half of the split: a run that recorded no cost is a floor,
        a run that recorded a cost and no login is money this tool can see and
        cannot assign, and only the second stops the figure."""
        row = artifact(tmp_path, "a.json", cost=2.00, subscription="",
                       auth_method="")
        code = spend.main([str(row)])
        out = capsys.readouterr().out
        assert "indeterminate" in out
        assert "recorded a cost and no login to place it against" in out
        assert code == 2


class TestMoneyIsNotRoundedAway:
    """A single model call costs about $0.006, and two decimals rendered every
    one of them as `$0.00`, which reads as free. Codex, 2026-09-05."""

    def test_a_small_amount_keeps_its_digits(self):
        assert spend.money(0.00621486) == "$0.0062"

    def test_an_amount_too_small_to_show_says_so(self):
        assert spend.money(0.00001) == "<$0.0001"

    def test_zero_is_zero(self):
        assert spend.money(0.0) == "$0.0000"

    def test_a_large_amount_stays_readable(self):
        assert spend.money(53.0) == "$53.00"


class TestACostThatIsNotMoney:
    """`float(value)` accepted a negative, an infinity and a nan. A negative
    reduces a total; one nan turns every total containing it into nan."""

    @pytest.mark.parametrize("value", [-1, float("inf"), float("-inf"),
                                       float("nan"), True, "1.25", None])
    def test_it_is_not_a_cost(self, value):
        assert spend.cost_of(
            {"provenance": {"reported_cost_usd": value}}) is None

    def test_a_real_cost_still_reads(self):
        assert spend.cost_of({"provenance": {"reported_cost_usd": 0.5}}) == 0.5

    @pytest.mark.parametrize("plan", [1, True, "   ", ["max"], {"p": "max"}])
    def test_a_subscription_that_is_not_a_name_is_unknown(
            self, tmp_path, capsys, plan):
        """Codex, 2026-09-05, immediately after the auth_method fix: any truthy
        value counted, so `"auth_subscription": 1` classified the run as a
        subscription and the command printed "$0.00 charged" and exited 0 from
        provenance nobody could read — the false answer this tool exists to
        prevent, from the one branch that produces it."""
        assert spend.paid_by({"provenance": {
            "auth_method": "claude.ai",
            "auth_subscription": plan}}) == spend.UNKNOWN

        row = artifact(tmp_path, "a.json", subscription=plan,
                       auth_method="claude.ai")
        code = spend.main([str(row)])
        out = capsys.readouterr().out
        assert "indeterminate" in out
        assert "$0.00 charged" not in out
        assert code == 2

    def test_two_signals_that_disagree_establish_nothing(
            self, tmp_path, capsys):
        """Codex, 2026-09-05: the API path and a subscription login cannot both
        be true of one run, and the provider won because it was asked first —
        so a contradictory record was reported as billed on the strength of one
        half of it."""
        assert spend.paid_by({"provenance": {
            "provider": "anthropic-api", "auth_method": "claude.ai",
            "auth_subscription": "max"}}) == spend.UNKNOWN

        row = artifact(tmp_path, "a.json", provider="anthropic-api",
                       auth_method="claude.ai", subscription="max")
        code = spend.main([str(row)])
        out = capsys.readouterr().out
        assert "indeterminate" in out
        assert code == 2

    @pytest.mark.parametrize("prov", [
        {"provider": "anthropic-api", "auth_method": "claude.ai",
         "auth_subscription": "max"},
        {"auth_method": "api-key", "auth_subscription": "max"},
        {"auth_method": "console", "auth_subscription": "max"},
        {"provider": "anthropic-api", "auth_subscription": "max"},
        # `claude.ai` is subscription evidence in its own right, and the
        # gathering counted only a named plan — so this came back charged from
        # a record whose two halves disagree.
        {"provider": "anthropic-api", "auth_method": "claude.ai"},
    ])
    def test_every_contradiction_establishes_nothing(self, prov):
        """Codex found this class twice in two rounds. The first version let
        `provider == anthropic-api` decide over a `claude.ai` login; the fix
        for that was another special case, which left `api-key` beside a named
        plan resolving by branch order in exactly the same way. A contradiction
        is not a thing to rank — it is a thing nobody established."""
        assert spend.paid_by({"provenance": prov}) == spend.UNKNOWN

    @pytest.mark.parametrize("prov,expected", [
        ({"auth_method": "api-key"}, "charged"),
        ({"auth_method": "console"}, "charged"),
        ({"provider": "anthropic-api"}, "charged"),
        ({"auth_method": "claude.ai", "auth_subscription": "max"},
         "notional"),
        # A plan recorded beside no login says which subscription exists, not
        # that this run drew on it.
        ({"auth_subscription": "max"}, "unknown"),
        ({"auth_method": "claude.ai"}, "unknown"),
        ({}, "unknown"),
    ])
    def test_the_signals_that_do_settle_it(self, prov, expected):
        """The other side of the rule above, so it cannot pass by refusing
        every record."""
        assert spend.paid_by({"provenance": prov}) == expected

    def test_the_api_path_alone_is_still_charged(self):
        """The other half, so the rule above cannot pass by refusing every
        billed run."""
        assert spend.paid_by({"provenance": {
            "provider": "anthropic-api",
            "auth_method": "api-key"}}) == spend.CHARGED

    def test_a_named_plan_still_classifies(self, tmp_path, capsys):
        """The other half, so the rule above cannot pass by refusing every
        subscription."""
        assert spend.paid_by({"provenance": {
            "auth_method": "claude.ai",
            "auth_subscription": "max"}}) == spend.NOTIONAL_

    @pytest.mark.parametrize("method", [1, ["claude.ai"], {"a": 1}, True])
    def test_an_auth_method_that_is_not_a_name_is_unknown_not_a_crash(
            self, tmp_path, capsys, method):
        """Codex, 2026-09-05: `.strip()` was called on whatever was truthy, so
        `"auth_method": 1` raised `AttributeError` and the command printed
        neither a figure nor a diagnostic — a crash where "I could not tell"
        belongs, in the function whose whole job is telling those apart."""
        assert spend.paid_by(
            {"provenance": {"auth_method": method}}) == spend.UNKNOWN

        path = tmp_path / "a.json"
        path.write_text(json.dumps({
            "generated_at": "2026-08-30T12:00:00+00:00",
            "provenance": {"provider": "claude-cli", "auth_method": method,
                           "reported_cost_usd": 1.25},
            "usage": {}}), encoding="utf-8")
        code = spend.main([str(path)])
        out = capsys.readouterr().out
        assert "indeterminate" in out
        assert code == 2

    def test_a_null_vendor_cost_is_a_floor_like_a_review_with_none(
            self, tmp_path, capsys, monkeypatch):
        """Codex, 2026-09-06: the vendor path had its own spelling of the
        three-way split and made a `null` cost an indeterminate hole, while
        the identical case on the review side was a floor. One function decides
        it now, and this pins the two sides agreeing."""
        monkeypatch.setitem(spend.BILLING_ARRANGEMENT, "xai",
                            {"kind": spend.METERED, "established": "test"})
        path = tmp_path / "x.json"
        path.write_text(json.dumps({
            "vendor": "xai",
            "cases": {"c1": {"request_id": "r1", "cost_usd": None}}}),
            encoding="utf-8")
        code = spend.main([str(path)])
        out = capsys.readouterr().out
        assert "a floor, not the answer" in out
        assert "indeterminate" not in out
        assert code == 2

    @pytest.mark.parametrize("value", [-1, float("inf"), float("nan"), True,
                                       "0.006"])
    def test_a_vendor_ledger_goes_through_the_same_predicate(
            self, tmp_path, capsys, value, monkeypatch):
        """Codex, 2026-09-05, on the version that had fixed only the reviews:
        the vendor path read `isinstance(..., (int, float))` and added whatever
        it found, so a ledger for a vendor with an established arrangement
        could print a total reduced by a negative, or `nan`, and exit 0."""
        monkeypatch.setitem(spend.BILLING_ARRANGEMENT, "xai",
                            {"kind": spend.METERED, "established": "test"})
        path = tmp_path / "x.json"
        path.write_text(json.dumps({
            "vendor": "xai",
            "cases": {"c1": {"request_id": "r1", "cost_usd": value}}}),
            encoding="utf-8")

        code = spend.main([str(path)])
        out = capsys.readouterr().out
        assert "where money belongs" in out
        # The headline only. The value itself appears further down, named as
        # the thing that could not be read — which is the point.
        assert "nan" not in out.splitlines()[0].lower()
        assert "inf" not in out.splitlines()[0].lower()
        # And the headline must not say a number. Codex, 2026-09-05: the
        # unpriced count reached the ledger line and not the decision, so one
        # metered call recording `nan` printed "$0.00 charged — every call runs
        # on a flat subscription", contradicting the diagnostic three lines
        # below it.
        assert "indeterminate" in out
        assert "$0.00 charged" not in out
        assert "other than money where a cost belongs" in out
        assert code == 2

    def test_a_priced_vendor_call_reaches_the_figure(
            self, tmp_path, capsys, monkeypatch):
        """The other half: with an arrangement established and real money in
        the record, the line is a number rather than `indeterminate`."""
        monkeypatch.setitem(spend.BILLING_ARRANGEMENT, "xai",
                            {"kind": spend.METERED, "established": "test"})
        path = tmp_path / "x.json"
        path.write_text(json.dumps({
            "vendor": "xai",
            "cases": {"c1": {"request_id": "r1", "cost_usd": 0.00621486}}}),
            encoding="utf-8")

        code = spend.main([str(path)])
        out = capsys.readouterr().out
        assert "$0.0062 charged" in out
        assert "indeterminate" not in out
        assert code == 0


class TestAFileOfManyRuns:
    """The 27 ordinary-changes reviews were invisible to this counter.

    `ordinary_noise.py` writes one `rows.json` holding every run it made, and
    `artifacts()` kept only bodies that were objects — so the array fell
    through an `isinstance(body, dict)` with nothing said, and the figure
    quoted in every report was missing a whole measurement. The defect is the
    project's own recurring one: a container read for its contents before
    anything asked what it was, and its absence taken for agreement.
    """

    def rows_file(self, tmp_path, body):
        path = tmp_path / "rows.json"
        path.write_text(json.dumps(body), encoding="utf-8")
        return path

    def run(self, cost=0.5):
        return {"case_id": "c", "cost_usd": cost,
                "provenance": {"provider": "claude-cli",
                               "model_requested": "claude-opus-5",
                               "auth_method": "claude.ai",
                               "auth_subscription": "max",
                               "reported_cost_usd": cost}}

    def test_an_array_of_runs_is_read_as_that_many_runs(self, tmp_path):
        path = self.rows_file(tmp_path, [self.run(), self.run(), self.run()])
        rows, unreadable = spend.read_runs([path])
        assert len(rows) == 3
        assert unreadable == 0

    def test_each_run_keeps_a_path_that_says_which_one_it_was(self, tmp_path):
        """One file, many runs: `_path` is what the report prints when a row
        looks wrong, and three rows all naming the same file cannot be told
        apart by the person who has to go and look."""
        path = self.rows_file(tmp_path, [self.run(), self.run()])
        rows = spend.artifacts([path])
        assert rows[0]["_path"].endswith("[0]")
        assert rows[1]["_path"].endswith("[1]")

    def test_an_array_of_something_else_is_unreadable_not_empty(self, tmp_path):
        """"I could not tell" and "nothing was spent here" are different
        answers, and this tool exists to keep them apart. Counted per record,
        which is the unit a file of many runs is measured in."""
        path = self.rows_file(tmp_path, ["c1", "c2", "c3"])
        rows, unreadable = spend.read_runs([path])
        assert rows == []
        assert unreadable == 3

    def test_a_mixed_file_does_not_swallow_the_elements_it_drops(self,
                                                                 tmp_path):
        """Codex, 2026-09-06. The first version kept a file whenever *one*
        element looked like a run and threw the rest away in a list
        comprehension, so a half-corrupt file reported zero unreadable and a
        total that quietly missed part of itself."""
        path = self.rows_file(tmp_path, [self.run(), "c2", 7, self.run()])
        rows, unreadable = spend.read_runs([path])
        assert len(rows) == 2
        assert unreadable == 2

    def test_an_object_that_is_not_a_run_is_not_read_as_one(self, tmp_path):
        """The classifier was applied to array elements only, so any object at
        all — a summary, a scorer's output — became a review with no cost
        reported, which is a sentence this tool prints and means."""
        path = tmp_path / "summary.json"
        path.write_text(json.dumps({"recall": 0.78, "cases": 27}),
                        encoding="utf-8")
        rows, unreadable = spend.read_runs([path])
        assert rows == []
        assert unreadable == 1


class TestOneRunIsCountedOnce:
    """A run can be written twice — as its own kept `findings.json`, and as a
    row in the `rows.json` its runner keeps beside it. Reading both counts its
    cost twice, which is exactly what this tool refuses between the artifacts
    and the queue log. Codex found the new shape had no such guard,
    2026-09-06."""

    def run(self, cost=0.5, provider="claude-cli"):
        return {"cost_usd": cost,
                "provenance": {"provider": provider,
                               "reported_cost_usd": cost,
                               "auth_method": "claude.ai",
                               "auth_subscription": "max"}}

    def test_nothing_is_folded_because_nothing_keys_a_run(self, tmp_path):
        """Two rules were tried on 2026-09-06 and both were wrong.

        By directory: two $5.00 metered artifacts under a rows file of one
        subscription run were counted as $0.00. By provider and cost: three
        distinct $5.00 API runs — one row, two artifacts — collapsed to $5.00,
        and the tests written for that rule encoded it as correct, which is how
        a test stops being a check.

        No field in these artifacts keys a run. Both directions of error follow
        from guessing at the join, so the join is not guessed at.
        """
        rows = tmp_path / "rows.json"
        rows.write_text(json.dumps([self.run(5.0, provider="anthropic-api")]),
                        encoding="utf-8")
        others = []
        for name in ("run-a", "run-b"):
            directory = tmp_path / name
            directory.mkdir()
            artifact = directory / "findings.json"
            artifact.write_text(
                json.dumps(self.run(5.0, provider="anthropic-api")),
                encoding="utf-8")
            others.append(artifact)

        kept, folded = spend.fold_representations([*others, rows])
        assert folded == []
        assert set(kept) == {rows, *others}

        runs, _ = spend.read_runs(kept)
        assert len(runs) == 3, "three distinct runs collapsed to fewer"

    def test_the_lower_bound_is_dropped_when_a_run_may_be_counted_twice(
            self, tmp_path, capsys):
        """`gpt-6-astra`, 2026-09-06, second gate: `≥` asserts a lower bound
        and a duplicate breaks it the other way.

        One $5.00 run written in both shapes, beside one run that reported no
        cost at all, printed "≥ $10.00 charged" — against $6.00 if that silent
        run cost a dollar. A warning three lines below cannot repair an
        inequality in the headline, so the headline stops making one.
        """
        (tmp_path / "kept").mkdir()
        metered = {"cost_usd": 5.0,
                   "provenance": {"provider": "anthropic-api",
                                  "reported_cost_usd": 5.0,
                                  "auth_method": "api-key",
                                  "auth_subscription": ""}}
        silent = {"provenance": {"provider": "anthropic-api",
                                 "auth_method": "api-key",
                                 "auth_subscription": ""}}
        (tmp_path / "rows.json").write_text(json.dumps([metered, silent]),
                                            encoding="utf-8")
        (tmp_path / "kept" / "findings.json").write_text(json.dumps(metered),
                                                         encoding="utf-8")

        spend.main([str(tmp_path / "rows.json"),
                    str(tmp_path / "kept" / "findings.json")])
        out = capsys.readouterr().out
        headline = out.splitlines()[0]
        assert "≥" not in headline, headline
        assert "a floor, not the answer" not in headline
        assert "counted twice" in out

    def test_a_duplicate_is_named_even_when_nothing_else_is_missing(
            self, tmp_path, capsys):
        """The state the first fix missed, found by printing all eight of them
        side by side instead of reasoning about them.

        With metered runs, no silent ones and a possible duplicate, the
        headline came out as a flat exact charge: "$5.00 charged" for something
        that could be $2.50. Both qualifying sentences hung off the presence of
        a silent run, so the duplicate went unmentioned whenever every run
        happened to report its cost.
        """
        (tmp_path / "kept").mkdir()
        metered = {"cost_usd": 5.0,
                   "provenance": {"provider": "anthropic-api",
                                  "reported_cost_usd": 5.0,
                                  "auth_method": "api-key",
                                  "auth_subscription": ""}}
        (tmp_path / "rows.json").write_text(json.dumps([metered]),
                                            encoding="utf-8")
        (tmp_path / "kept" / "findings.json").write_text(json.dumps(metered),
                                                         encoding="utf-8")

        spend.main([str(tmp_path / "rows.json"),
                    str(tmp_path / "kept" / "findings.json")])
        headline = capsys.readouterr().out.splitlines()[0]
        assert "not established as a total" in headline, headline
        # "would be", not "is". Coexistence in a directory is not duplication,
        # and the tests in this class build three distinct runs of equal cost
        # to make that point — a warning stating it as observed fact would
        # contradict them. Codex, fourth gate, 2026-09-06.
        assert "would be counted twice" in headline

    def test_the_bound_stays_when_nothing_can_be_double_counted(
            self, tmp_path, capsys):
        """The control. Without it this test could pass on a tool that never
        prints the bound at all."""
        silent = {"provenance": {"provider": "anthropic-api",
                                 "auth_method": "api-key",
                                 "auth_subscription": ""}}
        path = tmp_path / "rows.json"
        path.write_text(json.dumps([
            {"cost_usd": 5.0,
             "provenance": {"provider": "anthropic-api",
                            "reported_cost_usd": 5.0,
                            "auth_method": "api-key",
                            "auth_subscription": ""}},
            silent]), encoding="utf-8")

        spend.main([str(path)])
        headline = capsys.readouterr().out.splitlines()[0]
        assert "≥" in headline, headline

    def test_both_shapes_in_one_place_is_reported_not_silent(self, tmp_path,
                                                             capsys):
        """The double count cannot be resolved here, so it is named. A report
        that is silent about it cannot be told from one where the question does
        not arise."""
        (tmp_path / "kept").mkdir()
        run = {"cost_usd": 0.5,
               "provenance": {"provider": "claude-cli",
                              "reported_cost_usd": 0.5,
                              "auth_method": "claude.ai",
                              "auth_subscription": "max"}}
        (tmp_path / "rows.json").write_text(json.dumps([run]),
                                            encoding="utf-8")
        (tmp_path / "kept" / "findings.json").write_text(json.dumps(run),
                                                         encoding="utf-8")

        spend.main([str(tmp_path / "rows.json"),
                    str(tmp_path / "kept" / "findings.json")])
        out = capsys.readouterr().out
        assert "cannot be established here" in out
        assert "if one does it is counted twice" in out
        assert "Nothing in these records keys a run" in out

    def test_a_file_that_is_neither_is_counted_too(self, tmp_path):
        path = tmp_path / "n.json"
        path.write_text("3", encoding="utf-8")
        rows, unreadable = spend.read_runs([path])
        assert rows == [] and unreadable == 1

    def test_the_unreadable_count_does_not_go_negative(self, tmp_path, capsys):
        """It was `len(paths) - len(rows)`, which one file of 27 runs turns
        into -26 — printed to the owner as a negative number of files that
        could not be read."""
        path = tmp_path / "rows.json"
        run = {"cost_usd": 0.5,
               "provenance": {"provider": "claude-cli",
                              "reported_cost_usd": 0.5,
                              "auth_method": "claude.ai",
                              "auth_subscription": "max"}}
        path.write_text(json.dumps([run] * 27), encoding="utf-8")
        spend.main([str(path)])
        out = capsys.readouterr().out
        assert "-26" not in out
        assert "could not be read" not in out


class TestTheCorpusRowsAreASourceOfTheirOwn:
    """131 of the 154 money-bearing files were outside every glob this tool
    uses, and 221 member records in them carry a price summing to $131.05.

    The tool that answers "what has this cost" did not know the files existed
    — the shape it exists to catch, in itself. Codex, 2026-09-09, choosing how
    to close it: *"B. It accepts incomplete overall coverage: unkeyed sources
    remain unsummed. Heading must claim 'separately observed, unpriced token
    usage'. It must not claim total spend, deduplicated usage, or inclusion in
    the artifact-derived floor."*

    Folding them into the artifact totals was refused on a count: all 22 kept
    `findings.json` artifacts have a row for the same `(case, member)`, and
    neither side carries a `run_id`. A glob would have counted every one of
    those runs twice — the defect that once reported `$10.00` for a `$5.00`
    purchase.
    """

    def _row(self, root, name, *members):
        body = {"case_id": "c", "members": {
            role: {"cost": cost, "usage": {
                "requests": 1, "input_tokens": 10, "output_tokens": 20,
                "cache_read_tokens": 300, "cache_write_tokens": 40}}
            for role, cost in members}}
        path = root / "measurements" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(body), encoding="utf-8")
        return path

    def test_it_reads_what_no_other_source_does(self, tmp_path):
        self._row(tmp_path, "batch.json", ("safe", 1.25), ("unsafe", 2.75))

        totals = spend.corpus_rows_usage(tmp_path)

        assert totals["members"] == 2
        assert totals["priced"] == 2
        assert totals["usd"] == 4.00
        assert totals["requests"] == 2

    def test_the_artifact_globs_are_not_read_here(self, tmp_path):
        """The control, and the whole reason this is a separate source: a
        file the artifact reader already covers must not be counted again."""
        for name in ("findings.json", "rows.json"):
            self._row(tmp_path, name, ("safe", 9.99))

        assert spend.corpus_rows_usage(tmp_path)["members"] == 0

    def test_a_record_with_no_price_is_absent_and_not_zero(self, tmp_path):
        """`unpriced`, not a zero folded into the sum. A run whose price was
        never written down is a missing value, and this file's whole subject
        is that the two are different answers."""
        self._row(tmp_path, "batch.json", ("safe", None), ("unsafe", 3.00))

        totals = spend.corpus_rows_usage(tmp_path)

        assert totals["priced"] == 1
        assert totals["unpriced"] == 1
        assert totals["usd"] == 3.00

    def test_a_boolean_cost_is_not_a_dollar(self, tmp_path):
        """`True` is an `int` in Python and would add one dollar to a bill.
        The guard is `isinstance(cost, bool)`, and this is the input for it.

        It lands in `rejected_price`, not `unpriced`: the record carries a
        value and this reader refused it, which is not the same as a record
        that carries none.
        """
        self._row(tmp_path, "batch.json", ("safe", True))

        totals = spend.corpus_rows_usage(tmp_path)

        assert totals["usd"] == 0.0
        assert totals["rejected_price"] == 1
        assert totals["unpriced"] == 0

    def test_a_results_wrapper_is_read(self, tmp_path):
        """One of the three shapes written in this tree. Reading it as a
        single row would report a whole file as nothing."""
        path = tmp_path / "measurements" / "wrapped.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"results": [
            {"case_id": "c", "members": {"safe": {
                "cost": 5.00,
                "usage": {"requests": 1, "input_tokens": 1,
                          "output_tokens": 1, "cache_read_tokens": 1,
                          "cache_write_tokens": 1}}}}]}), encoding="utf-8")

        assert spend.corpus_rows_usage(tmp_path)["usd"] == 5.00

    def test_an_unreadable_file_is_counted_and_not_skipped(self, tmp_path):
        """"I could not read it" is a third answer. Counting it silently as
        nothing is what makes a floor read like a total."""
        path = tmp_path / "measurements" / "broken.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{not json", encoding="utf-8")

        assert spend.corpus_rows_usage(tmp_path)["unreadable"] == 1

    def test_two_names_for_one_file_are_one_file(self, tmp_path):
        """A hard link makes `glob` hand over the same bytes twice.

        This source's whole justification is that it does not double count,
        and `$5.00` became `$10.00` from two names for one file — the exact
        figure this tool was once caught reporting. `read_runs` already keys
        on `(st_dev, st_ino)` for the artifact source; the rule was argued for
        here at length and not applied. Codex, 2026-09-09.
        """
        first = self._row(tmp_path, "a.json", ("safe", 5.00))
        # `Path.hardlink_to` is 3.10; this runs on 3.9.
        os.link(str(first), str(tmp_path / "measurements" / "alias.json"))

        totals = spend.corpus_rows_usage(tmp_path)

        assert totals["files"] == 1
        assert totals["usd"] == 5.00

    def test_a_malformed_members_block_does_not_take_the_report_down(
            self, tmp_path):
        """`members` as a list raised `AttributeError`.

        `unread_note` calls this on *every* headline path, so one malformed
        file under `measurements/` took down the single line the owner reads
        in every report. A counter that cannot be run is worse than one that
        counts short. Found 2026-09-09 by running the shapes a file can have
        rather than the shape it should have.
        """
        path = tmp_path / "measurements" / "x.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"case_id": "c", "members": ["nope"]}),
                        encoding="utf-8")

        totals = spend.corpus_rows_usage(tmp_path)

        assert totals["members"] == 0
        assert totals["unreadable"] == 1

    @pytest.mark.parametrize("cost", [float("nan"), float("inf"), -5.0,
                                      "5.00", True])
    def test_a_refused_price_is_not_an_absent_one(self, tmp_path, cost):
        """`nan`, a negative, a string and a bool all landed in `unpriced`,
        which prints "carry usage and no price" — about a record that carries
        one. `LIMITATIONS.md` called `nan` an unreadable value in the same
        breath, so the file and its own documentation disagreed. The earlier
        test asserted `unpriced == 1` and so encoded the conflation. Codex,
        2026-10."""
        self._row(tmp_path, "x.json", ("safe", cost))

        totals = spend.corpus_rows_usage(tmp_path)

        assert totals["rejected_price"] == 1
        assert totals["unpriced"] == 0
        assert totals["usd"] == 0.0

    def test_an_absent_price_is_still_absent(self, tmp_path):
        """The control, and the other half of the distinction: a member with
        no `cost` key at all is a missing value, not a refused one."""
        path = tmp_path / "measurements" / "x.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"case_id": "c", "members": {"safe": {
            "usage": {"requests": 1}}}}), encoding="utf-8")

        totals = spend.corpus_rows_usage(tmp_path)

        assert totals["unpriced"] == 1
        assert totals["rejected_price"] == 0

    def test_a_member_that_cannot_be_read_is_counted(self, tmp_path):
        """A member that is not an object, or whose `usage` is not one, was
        dropped in silence — so a file could hold four members, contribute
        two, and report nothing missing. Codex, 2026-10."""
        path = tmp_path / "measurements" / "x.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"case_id": "c", "members": {
            "safe": "not an object",
            "unsafe": {"cost": 1.0, "usage": "not an object"},
        }}), encoding="utf-8")

        totals = spend.corpus_rows_usage(tmp_path)

        assert totals["unusable_members"] == 2
        assert totals["members"] == 0

    def test_a_file_of_only_unusable_members_is_unreadable(self, tmp_path,
                                                           monkeypatch,
                                                           capsys):
        """`unusable_members` was counted and changed nothing about its file.

        So a file whose only member could not be read landed in no state at
        all and the command exited 0 — the count said something was missing
        and the exit code said everything was fine. Codex, 2026-10.
        """
        monkeypatch.setattr(spend, "ROOT", tmp_path)
        path = tmp_path / "measurements" / "x.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"case_id": "c",
                                    "members": {"safe": "not an object"}}),
                        encoding="utf-8")

        totals = spend.corpus_rows_usage(tmp_path)
        assert totals["files"] == 0
        assert totals["unreadable"] == 1
        assert spend.main(["--source", "rows"]) == 2
        capsys.readouterr()

    def test_a_usable_member_beside_an_unusable_one_is_partial(self,
                                                               tmp_path):
        """The other half: the file did yield a record, and it is still short
        by one. Read in part, not read whole."""
        path = tmp_path / "measurements" / "x.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"case_id": "c", "members": {
            "safe": "not an object",
            "unsafe": {"cost": 1.0, "usage": {"requests": 1}},
        }}), encoding="utf-8")

        totals = spend.corpus_rows_usage(tmp_path)

        assert totals["files"] == 1
        assert totals["partial"] == 1
        assert totals["members"] == 1

    def test_a_refused_field_makes_the_read_partial(self, tmp_path,
                                                    monkeypatch, capsys):
        """The refusal was recorded and the command still exited 0.

        That contradicts what exit 0 means here and what `partial` is defined
        as, three lines of documentation away. One invariant covers both
        refusals — a price and a count — rather than two rules that can drift.
        Codex, 2026-10, named this as the single thing that had to change
        before the work could be committed.
        """
        monkeypatch.setattr(spend, "ROOT", tmp_path)
        path = tmp_path / "measurements" / "x.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"case_id": "c", "members": {"safe": {
            "cost": "5.00",
            "usage": {"requests": "many", "input_tokens": 1,
                      "output_tokens": 1, "cache_read_tokens": 1,
                      "cache_write_tokens": 1}}}}), encoding="utf-8")

        totals = spend.corpus_rows_usage(tmp_path)
        assert totals["partial"] == 1
        assert totals["rejected_price"] == 1
        assert totals["unusable_counts"] == 1

        assert spend.main(["--source", "rows"]) == 2
        capsys.readouterr()

    @pytest.mark.parametrize("member", [
        {"cost": "5.00", "usage": {"requests": 1}},
        {"cost": 1.0, "usage": {"requests": "many"}},
    ])
    def test_either_refusal_alone_is_enough(self, tmp_path, member):
        """One invariant, so a price refused on its own and a count refused on
        its own both reach it. Two rules would drift; this is the test that
        notices if they are ever split again."""
        path = tmp_path / "measurements" / "x.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"case_id": "c",
                                    "members": {"safe": member}}),
                        encoding="utf-8")

        assert spend.corpus_rows_usage(tmp_path)["partial"] == 1

    def test_a_file_whose_members_all_read_is_not_partial(self, tmp_path):
        """The control. Without it the two above could be satisfied by
        calling every file partial, which makes the exit code useless."""
        self._row(tmp_path, "x.json", ("safe", 1.0), ("unsafe", 2.0))

        totals = spend.corpus_rows_usage(tmp_path)

        assert totals["partial"] == 0
        assert totals["unusable_members"] == 0

    def test_a_non_row_beside_a_good_row_is_not_lost(self, tmp_path):
        """Only the all-or-nothing case was reported, so an object nobody
        could place vanished when it shared a file with a row. Measured: no
        file in this tree is that shape, so the hole is closed rather than
        waited for. Codex, 2026-10."""
        path = tmp_path / "measurements" / "x.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps([
            {"case_id": "c", "members": {"safe": {
                "cost": 1.0, "usage": {"requests": 1}}}},
            {"foo": "bar"},
        ]), encoding="utf-8")

        totals = spend.corpus_rows_usage(tmp_path)

        assert totals["members"] == 1
        assert totals["files"] == 1
        assert totals["not_rows"] == 1

    def test_an_ordinary_price_is_still_summed(self, tmp_path):
        """The control. A guard that refuses everything is not a guard."""
        self._row(tmp_path, "x.json", ("safe", 5.00))

        assert spend.corpus_rows_usage(tmp_path)["usd"] == 5.00

    def test_a_token_count_that_is_not_a_number_is_named(self, tmp_path):
        """A float count was dropped in silence while the member still
        counted — an undercount with nothing saying so. A string is refused
        and said."""
        path = tmp_path / "measurements" / "x.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"case_id": "c", "members": {"safe": {
            "cost": 1.0,
            "usage": {"requests": "many", "input_tokens": 2.5,
                      "output_tokens": 1, "cache_read_tokens": 1,
                      "cache_write_tokens": 1}}}}), encoding="utf-8")

        totals = spend.corpus_rows_usage(tmp_path)

        # The float is real arithmetic and counts; the string does not, and
        # the fact that something was refused is recorded rather than lost.
        assert totals["input_tokens"] == 2.5
        assert totals["requests"] == 0
        assert totals["unusable_counts"] == 1

    def test_the_refused_counts_are_printed_and_not_only_counted(
            self, tmp_path, monkeypatch, capsys):
        """`unusable_counts` was collected and printed nowhere.

        A refused value that is counted and not said makes the token figures
        read as complete when they are short — the qualification that does not
        travel with the number, which is the defect this file repaired twice
        today before doing it a third time itself.
        """
        monkeypatch.setattr(spend, "ROOT", tmp_path)
        path = tmp_path / "measurements" / "x.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"case_id": "c", "members": {"safe": {
            "cost": 1.0, "usage": {"requests": "many", "input_tokens": 1,
                                   "output_tokens": 1, "cache_read_tokens": 1,
                                   "cache_write_tokens": 1}}}}),
            encoding="utf-8")

        spend.main(["--source", "rows"])
        out = capsys.readouterr().out

        assert "not usable numbers" in out

    def test_it_is_silent_when_every_count_was_usable(self, tmp_path,
                                                     monkeypatch, capsys):
        """The control. A line that always prints is not a qualification."""
        monkeypatch.setattr(spend, "ROOT", tmp_path)
        path = tmp_path / "measurements" / "x.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"case_id": "c", "members": {"safe": {
            "cost": 1.0, "usage": {"requests": 1, "input_tokens": 1,
                                   "output_tokens": 1, "cache_read_tokens": 1,
                                   "cache_write_tokens": 1}}}}),
            encoding="utf-8")

        spend.main(["--source", "rows"])

        assert "not usable numbers" not in capsys.readouterr().out

    @pytest.mark.parametrize("body", [
        [["not", "a", "row"]],
        {"results": {"case_id": "c", "members": {"safe": {"cost": 5}}}},
        "a bare string",
    ])
    def test_a_file_of_no_known_shape_is_not_an_empty_source(self, tmp_path,
                                                             body):
        """It parsed, matched nothing, and left the count at zero with exit 0.

        "I read it and there was nothing" about a file nobody could read is
        the same sentence this project exists to refuse everywhere else. The
        second case is worse than silence: a `results` key holding one row
        rather than a list made the wrapper itself get read as the row, so a
        file plainly holding a measurement came out empty. Codex, 2026-09-09.
        """
        path = tmp_path / "measurements" / "x.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(body), encoding="utf-8")

        totals = spend.corpus_rows_usage(tmp_path)

        assert totals["members"] == 0
        assert totals["unreadable"] == 1

    def test_a_file_about_something_else_is_a_third_answer(self, tmp_path):
        """`{"foo": "bar"}` passed as "a readable source with nothing in it".

        68 files in this repository are exactly that — a panel, a replay, a
        report — so calling them unreadable would make the real corpus exit 2
        on every invocation and the check would be switched off. They are a
        third state: parsed, understood, and about something else. Codex,
        2026-09-09; the count is measured, not guessed.
        """
        path = tmp_path / "measurements" / "panels.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"panels": [1, 2]}), encoding="utf-8")

        totals = spend.corpus_rows_usage(tmp_path)

        assert totals["not_rows"] == 1
        assert totals["unreadable"] == 0
        assert totals["files"] == 0

    def test_one_file_with_two_bad_rows_is_one_unreadable_file(self,
                                                               tmp_path):
        """`unreadable` counts files and was incremented per row, so a single
        file holding two malformed rows reported "2 file(s) could not be
        read" — the reader inflating its own figure for how much it missed.
        Codex, 2026-09-09."""
        path = tmp_path / "measurements" / "x.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps([{"case_id": "a", "members": []},
                                    {"case_id": "b", "members": []}]),
                        encoding="utf-8")

        assert spend.corpus_rows_usage(tmp_path)["unreadable"] == 1

    def test_a_file_read_in_part_says_so(self, tmp_path):
        """One usable row beside one this reader cannot parse.

        `seen_here` won, so the broken row vanished and the file counted as
        fully understood — absence read as agreement, in the reader written
        against it. Found 2026-10 by asking what a file with *both* does,
        which is a question neither the tests nor three review rounds had put.
        """
        path = tmp_path / "measurements" / "x.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps([
            {"case_id": "a", "members": {"safe": {
                "cost": 1.0, "usage": {"requests": 1}}}},
            {"case_id": "b", "members": []},
        ]), encoding="utf-8")

        totals = spend.corpus_rows_usage(tmp_path)

        # What came out is kept; what did not is named.
        assert totals["members"] == 1
        assert totals["partial"] == 1
        assert totals["unreadable"] == 0
        assert totals["files"] == 1

    def test_a_file_carrying_three_facts_reports_all_three(self, tmp_path,
                                                           monkeypatch,
                                                           capsys):
        """These are not five exclusive states — they are facts, and a file
        can carry several.

        Written as an `elif` chain first: `good row + malformed row + non-row
        object` matched the `not_rows` arm, so `partial` was never set and the
        run exited 0 over a file it had read in half. One arm of a chain
        swallowing another is the same loss as a missing branch, and only
        running every combination showed it — found 2026-10 by doing that
        rather than by reasoning about which case might collide.
        """
        monkeypatch.setattr(spend, "ROOT", tmp_path)
        path = tmp_path / "measurements" / "x.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps([
            {"case_id": "a", "members": {"safe": {
                "cost": 1.0, "usage": {"requests": 1}}}},
            {"case_id": "b", "members": []},
            {"foo": "bar"},
        ]), encoding="utf-8")

        totals = spend.corpus_rows_usage(tmp_path)
        assert totals["files"] == 1
        assert totals["partial"] == 1
        assert totals["not_rows"] == 1
        assert totals["unreadable"] == 0

        # And every one of them reaches the reader, with exit 2 for the half
        # that was not read.
        code = spend.main(["--source", "rows"])
        out = capsys.readouterr().out
        assert code == 2
        assert "read in part" in out
        assert "about something else" in out

    def test_a_file_read_whole_is_not_partial(self, tmp_path):
        """The control. A flag that fires on a healthy file is a flag that
        makes the exit code useless."""
        self._row(tmp_path, "x.json", ("safe", 1.0), ("unsafe", 2.0))

        assert spend.corpus_rows_usage(tmp_path)["partial"] == 0

    def test_a_partial_read_is_not_exit_zero(self, tmp_path, monkeypatch,
                                             capsys):
        """The figure is under by an amount nobody knows, and "I could not
        check" must not leave with the code for "here is the answer"."""
        monkeypatch.setattr(spend, "ROOT", tmp_path)
        path = tmp_path / "measurements" / "x.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps([
            {"case_id": "a", "members": {"safe": {
                "cost": 1.0, "usage": {"requests": 1}}}},
            {"case_id": "b", "members": []},
        ]), encoding="utf-8")

        code = spend.main(["--source", "rows"])

        assert code == 2
        assert "read in part" in capsys.readouterr().out

    def test_the_heading_claims_no_price_when_none_was_recorded(
            self, tmp_path, monkeypatch, capsys):
        """Over a source whose members all carry usage and no `cost`, the
        heading announced "a recorded price" and the next line said the
        opposite — two sentences about one run contradicting each other three
        lines apart. Codex, 2026-09-09."""
        monkeypatch.setattr(spend, "ROOT", tmp_path)
        self._row(tmp_path, "x.json", ("safe", None))

        spend.main(["--source", "rows"])
        out = capsys.readouterr().out

        assert "a recorded price" not in out
        assert "carry usage and no price" in out

    def test_the_heading_names_the_price_when_there_is_one(self, tmp_path,
                                                           monkeypatch,
                                                           capsys):
        """The control. A heading that never mentions a price would hide the
        figure this source exists to surface."""
        monkeypatch.setattr(spend, "ROOT", tmp_path)
        self._row(tmp_path, "x.json", ("safe", 5.00))

        spend.main(["--source", "rows"])

        assert "a recorded price" in capsys.readouterr().out

    def test_an_empty_list_is_a_readable_file_with_nothing_in_it(
            self, tmp_path):
        """The control. A batch that legitimately recorded no rows is not a
        file this reader failed to understand, and calling it unreadable would
        make the exit code useless."""
        path = tmp_path / "measurements" / "x.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("[]", encoding="utf-8")

        assert spend.corpus_rows_usage(tmp_path)["unreadable"] == 0

    def test_a_dangling_symlink_is_counted_as_unreadable(self, tmp_path):
        """The unreadable test used invalid JSON, which is a different branch.

        Codex, 2026-09-09: removing the `stat()` accounting would not fail it.
        A dangling symlink is the ordinary way a real repository reaches that
        branch — `glob` lists the name and `stat` follows it and raises — so
        the state is one a tree can hold rather than one only a test can
        build.
        """
        (tmp_path / "measurements").mkdir(parents=True, exist_ok=True)
        os.symlink(str(tmp_path / "measurements" / "gone.json"),
                   str(tmp_path / "measurements" / "dangling.json"))

        totals = spend.corpus_rows_usage(tmp_path)

        assert totals["members"] == 0
        assert totals["unreadable"] == 1

    def test_a_symlinked_directory_alias_is_one_file(self, tmp_path):
        """The implementation claims a symlinked alias is deduplicated and
        only a hard link was tested. Codex, 2026-09-09: an untested half of a
        claim is a claim."""
        self._row(tmp_path, "a.json", ("safe", 5.00))
        os.symlink(str(tmp_path / "measurements"),
                   str(tmp_path / "measurements" / "mirror"))

        totals = spend.corpus_rows_usage(tmp_path)

        assert totals["files"] == 1
        assert totals["usd"] == 5.00

    def test_two_different_files_are_two_files(self, tmp_path):
        """The control. Deduplicating by content or by size would collapse
        two genuine runs that happen to look alike."""
        self._row(tmp_path, "a.json", ("safe", 5.00))
        self._row(tmp_path, "b.json", ("safe", 5.00))

        totals = spend.corpus_rows_usage(tmp_path)

        assert totals["files"] == 2
        assert totals["usd"] == 10.00


class TestTheHeadlineNamesWhatItDidNotRead:
    """The line said "$0.00 charged — every call the counter saw" while 356
    member records sat in a source no glob here touches.

    True, and the count beside it read as the whole. The qualification travels
    with the figure, not with the breakdown, because the line is the only
    place most readers look.
    """

    def _tree(self, root):
        path = root / "measurements" / "batch.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"case_id": "c", "members": {"safe": {
            "cost": 1.0,
            "usage": {"requests": 1, "input_tokens": 1, "output_tokens": 1,
                      "cache_read_tokens": 1, "cache_write_tokens": 1}}}}),
            encoding="utf-8")

    def test_the_headline_says_another_source_holds_more(self, tmp_path,
                                                         monkeypatch, capsys):
        monkeypatch.setattr(spend, "ROOT", tmp_path)
        self._tree(tmp_path)

        spend.one_figure([], {"calls": [], "problems": []}, source="artifacts")

        assert "--source rows" in capsys.readouterr().out

    def test_it_is_silent_when_there_is_nothing_more(self, tmp_path,
                                                    monkeypatch, capsys):
        """The control. A clause that always prints is not a qualification,
        it is noise, and the next reader learns to skip the line."""
        monkeypatch.setattr(spend, "ROOT", tmp_path)
        (tmp_path / "measurements").mkdir(parents=True, exist_ok=True)

        spend.one_figure([], {"calls": [], "problems": []}, source="artifacts")

        assert "--source rows" not in capsys.readouterr().out

    def test_a_source_of_nothing_but_unreadable_files_still_speaks(
            self, tmp_path, monkeypatch, capsys):
        """The note returned nothing whenever `members` was zero, whatever
        `unreadable` said.

        So a corpus of nothing but unparseable files produced "no records were
        found" — on the empty-ledger branch this note exists to repair, and
        the branch where the omission is worst. Absence read as agreement, in
        the line written against absence being read as agreement. Codex,
        2026-09-09.
        """
        monkeypatch.setattr(spend, "ROOT", tmp_path)
        path = tmp_path / "measurements" / "broken.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{not json", encoding="utf-8")

        spend.one_figure([], {"calls": [], "problems": []}, source="artifacts")
        out = capsys.readouterr().out

        assert "could not be read at all" in out
        assert "--source rows" in out

    def test_the_rows_source_does_not_exit_zero_over_a_file_it_skipped(
            self, tmp_path, monkeypatch, capsys):
        """It printed that the figure is under its own source and returned 0.

        "I could not check" and "here is the answer" are different answers and
        this repository gives them different exit codes. Codex, 2026-09-09.
        """
        monkeypatch.setattr(spend, "ROOT", tmp_path)
        path = tmp_path / "measurements" / "broken.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{not json", encoding="utf-8")

        assert spend.main(["--source", "rows"]) == 2

    def test_the_heading_claims_nothing_about_who_paid(self, tmp_path,
                                                       monkeypatch, capsys):
        """A row carries no provider, no login and no billing arrangement, so
        this reader cannot say whether anything was charged.

        Two wordings were refused before this one: the ruling's "unpriced",
        which stopped being true when 221 rows turned out to carry a price,
        and then "charged to nobody", which is `BILLING_ARRANGEMENT`'s answer
        and not visible from a row. Codex, 2026-09-09: *"Any copied, future,
        or API-funded row gets falsely classified."* No test asserted the
        heading at all, which is how a claim reached it twice.
        """
        monkeypatch.setattr(spend, "ROOT", tmp_path)
        path = tmp_path / "measurements" / "x.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"case_id": "c", "members": {"safe": {
            "cost": 5.0, "usage": {"requests": 1}}}}), encoding="utf-8")

        spend.main(["--source", "rows"])
        out = capsys.readouterr().out

        assert "cannot place against any billing arrangement" in out
        assert "charged to nobody" not in out
        assert "flat subscription" not in out

    @pytest.mark.parametrize("extra", [
        ["--since", "2099-01-01"], ["--detail"], ["--breakdown"],
    ])
    def test_a_flag_this_source_cannot_honour_is_refused(self, tmp_path,
                                                         monkeypatch, capsys,
                                                         extra):
        """`--since`, `--detail` and `--breakdown` were accepted here and did
        nothing, so a filtered invocation printed figures for the whole
        repository and exited 0. A flag accepted and ignored is worse than one
        rejected: the reader believes a filter applied. Codex, 2026-09-09."""
        monkeypatch.setattr(spend, "ROOT", tmp_path)
        (tmp_path / "measurements").mkdir(parents=True, exist_ok=True)

        code = spend.main(["--source", "rows", *extra])
        out = capsys.readouterr().out

        assert code == 2
        assert "accepted and ignored" in out

    def test_a_readable_rows_source_is_exit_zero(self, tmp_path, monkeypatch):
        """The control. An exit code that is never 0 is a check nobody can
        satisfy, and it gets dropped from the pipeline rather than fixed."""
        monkeypatch.setattr(spend, "ROOT", tmp_path)
        path = tmp_path / "measurements" / "batch.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"case_id": "c", "members": {"safe": {
            "cost": 1.0,
            "usage": {"requests": 1, "input_tokens": 1, "output_tokens": 1,
                      "cache_read_tokens": 1, "cache_write_tokens": 1}}}}),
            encoding="utf-8")

        assert spend.main(["--source", "rows"]) == 0
