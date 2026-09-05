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


def vendor_record(tmp_path, name="grok-adjudication.json", *, vendor="xai",
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
        assert "1 xai call(s)" in out
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
        assert "1 xai call(s)" in out

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
        assert "1 xai call(s)" in capsys.readouterr().out

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
        assert "1 xai call(s)" in out
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

    def test_an_entirely_empty_breakdown_says_so_plainly(
            self, tmp_path, capsys, monkeypatch):
        """No reviews, no metered calls, and nothing that failed. `--source
        queue` reads the repository's own log rather than a named path, so
        both it and the vendor globs are pointed at nothing here."""
        monkeypatch.setattr(spend, "QUEUE_LOG", "absent/log.jsonl")
        monkeypatch.setattr(spend, "VENDOR_GLOBS", ())
        spend.main(["--breakdown", "--source", "queue"])
        out = capsys.readouterr().out
        assert "no metered calls" in out
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

    @pytest.mark.parametrize("value", [-1, float("inf"), float("nan"), True,
                                       "0.006", None])
    def test_a_vendor_ledger_goes_through_the_same_predicate(
            self, tmp_path, capsys, value, monkeypatch):
        """Codex, 2026-09-05, on the version that had fixed only the reviews:
        the vendor path read `isinstance(..., (int, float))` and added whatever
        it found, so a ledger for a vendor with an established arrangement
        could print a total reduced by a negative, or `nan`, and exit 0."""
        monkeypatch.setitem(spend.BILLING_ARRANGEMENT, "xai",
                            {"metered": "every call", "established": "test"})
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
                            {"metered": "every call", "established": "test"})
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
