"""What a run cost, and the difference between $0.00 and nobody saying.

Every one of the 38 member runs in `measurements/*.json` records

    "usage": {"requests": 0, "input_tokens": 0, "output_tokens": 0,
              "cache_read_tokens": 0, "cache_write_tokens": 0}

and a `cost` of `0.0`. Those batches were run through the Claude Code CLI —
the filenames and the commit history say so; only four of the 38 members
carry `provenance.provider`, so the artifacts alone do not establish it for
the other 34. The runner parses the CLI's usage block into `CliResult.usage`
and never puts it on the outcome, so the artifact recorded "the provider did
not tell us" as "it used nothing" — this project's own absent-versus-zero
rule broken inside the record the rule is about. `budget.py` has printed
"Model token usage: not reported by this runner" for the same gap since it
was written; the artifact beside it said the review was free.

Then `pair_corpus.cost_of` indexed the four counts straight out of that block,
priced them at $0.00, and summed them into a batch total. A corpus run that
cost real money reported `total cost $0.00 across 5 pairs`, and the number
came from an artifact, so by this project's own rules it was believed.

The second defect was the first one level up, and it was in the fix. Deriving
"was this reported" from `requests > 0` is a proxy for the event and not the
event: it called a response carrying no figures a request, it called real
tokens held without a counted request unreported and then wrote `null` over
them, and — the one that mattered — `merge` lost the unknown half, so a review
whose verifier reported nothing presented the review stage's cost as the whole
review's cost. Three states, not two.

Which test catches what:

* Most of the tests below fail against the implementation before the fix, and
  each names the failure it catches in its own docstring. They were verified
  by reverting the change and watching them fail, not by assertion.
* Four are PRESERVATION tests and are marked as such. They pass against the
  broken code too, and are here so that the fix cannot be satisfied by
  answering "not reported" to everything — the direction of error that would
  make a measured review unreadable.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from pair_corpus import add_costs, cost_of, cost_summary, notional_summary, report

from security_agent.config import Config
from security_agent.gate import decide
from security_agent.models import Candidate, Finding, ScanOutcome, Usage
from security_agent.report import build_json, render_markdown

MEASUREMENTS = Path(__file__).resolve().parents[1] / "measurements"

# The exact block the five CLI batches stored, byte for byte. A fixture that
# paraphrased it would stop testing the thing that is actually on disk.
STORED_BLOCK = {"requests": 0, "input_tokens": 0, "output_tokens": 0,
                "cache_read_tokens": 0, "cache_write_tokens": 0}

RATES = (15.0, 75.0)


class _Reply:
    """The `usage` attribute of a Messages API response, as `Usage.add` reads it."""

    def __init__(self, input_tokens=0, output_tokens=0,
                 cache_read_input_tokens=0, cache_creation_input_tokens=0):
        self.input_tokens = input_tokens
        self.output_tokens = output_tokens
        self.cache_read_input_tokens = cache_read_input_tokens
        self.cache_creation_input_tokens = cache_creation_input_tokens


def _outcome(usage: Usage) -> ScanOutcome:
    outcome = ScanOutcome(mode="diff", model="claude-opus-5")
    outcome.usage = usage
    outcome.reported = [Candidate(finding=Finding.from_dict({
        "title": "SQL injection in user lookup", "category": "injection",
        "severity": "high", "confidence": "high", "file": "app/views.py",
        "line": 14, "impact": "broad_data_access",
        "reachable_without_authentication": "yes",
        "requires_user_interaction": "no",
        "evidence": 'db.execute("SELECT * FROM users WHERE id = " + user_id)',
        "description": "User input is concatenated into a query.",
        "exploit_scenario": "An anonymous caller reads every row.",
        "recommendation": "Use a parameterised query.",
    }))]
    return outcome


def _spent() -> Usage:
    tally = Usage()
    tally.add(_Reply(input_tokens=4000, output_tokens=6000,
                     cache_read_input_tokens=120000,
                     cache_creation_input_tokens=33000))
    return tally


# ------------------------------------------------------- the value type


def test_a_run_nobody_reported_has_no_cost_rather_than_a_zero_one():
    """`0.0` is a price. A review that reported nothing does not have one.

    Before: `Usage().cost_usd(...)` returned `0.0`, so every caller could add
    an unmeasured review into a total and print the result as a bill.
    """
    assert Usage().cost_usd(*RATES) is None


def test_a_run_that_reported_still_gets_its_figure():
    """PRESERVATION. Passes before the fix too — the old `cost_usd` returned
    this figure as well. Kept so the fix cannot be satisfied by answering
    "not reported" to everything."""
    cost = _spent().cost_usd(*RATES)
    assert cost is not None and cost > 0


def test_a_response_that_said_zero_tokens_is_priced_at_zero():
    """PRESERVATION, and the boundary of the one below it. A provider that
    answered and reported zero has reported: the four names are present and
    carry `0`. Zero is then a price and not a gap."""
    tally = Usage()
    tally.add(_Reply())
    assert tally.reported is True
    assert tally.unreported_stages == 0
    assert tally.cost_usd(*RATES) == 0.0


def test_a_response_carrying_no_figures_at_all_is_a_gap_not_a_request():
    """The proxy showing through: `requests` counted the call, not the answer.

    `Usage().add(object())` left `requests == 1` beside four zeros, so the
    run read as reported and priced at a confident $0.00 — the original
    defect, rebuilt inside its own fix. The absence of the four names is the
    evidence, and `or 0` on each one erased it.
    """
    tally = Usage()
    tally.add(object())
    assert tally.reported is False
    assert tally.unreported_stages == 1
    assert tally.cost_usd(*RATES) is None


def test_tokens_held_without_a_counted_request_are_not_thrown_away():
    """A fix for losing figures must not itself lose figures.

    `Usage(input_tokens=100)` has `requests == 0`, so a `reported` derived
    from `requests` alone called it unmeasured — and `to_dict` then wrote
    `null` over a hundred real tokens.
    """
    tally = Usage(input_tokens=100)
    assert tally.reported is True
    assert tally.to_dict()["input_tokens"] == 100
    assert tally.cost_usd(*RATES) > 0


def test_the_stored_block_says_it_did_not_measure_anything():
    """The five-zero block on disk must read as an absence, not as a free run."""
    assert Usage.from_dict(STORED_BLOCK).reported is False
    assert cost_of(STORED_BLOCK) is None


def test_a_hand_written_reported_flag_cannot_claim_a_measurement():
    """`reported` is derived, so writing the word does not make it so.

    The recurring defect in this repository is a check satisfied by a shape
    rather than by the thing; a `usage` block asserting `"reported": true`
    over four nulls is exactly that shape.

    What this does NOT establish, and the docstring on `from_dict` used to
    imply: re-deriving is not forgery protection. The figures the derivation
    reads are in the same file, so an artifact edited to say `"requests": 1`
    reads back as measured and prices at zero. The test below pins that, so
    nobody reads this one as a guarantee it does not give. What re-deriving
    buys is narrower and real — a stale or truncated artifact cannot claim
    more than its own numbers support.
    """
    forged = dict(STORED_BLOCK, reported=True)
    assert Usage.from_dict(forged).reported is False
    assert cost_of(forged) is None


def test_editing_the_figures_themselves_is_outside_what_this_can_see():
    """Stated rather than left for somebody to discover as a hole.

    `requests` and `unreported_stages` are the inputs the conclusions are
    derived from, and they sit in the artifact next to everything else. An
    artifact somebody chose to rewrite can say what it likes. The guarantee is
    against staleness and truncation, not against a person with an editor.
    """
    measured = Usage.from_dict(dict(STORED_BLOCK, requests=1))
    assert measured.reported is True
    assert measured.complete is True

    healed = {k: v for k, v in STORED_BLOCK.items() if k != "unreported_stages"}
    assert Usage.from_dict(dict(healed, requests=1, unreported_stages=0)).complete


def test_a_hand_written_complete_flag_cannot_hide_a_gap():
    """`complete` is a conclusion too, and is re-derived rather than read."""
    block = dict(STORED_BLOCK, requests=3, input_tokens=1000,
                 unreported_stages=1, complete=True)
    assert Usage.from_dict(block).complete is False
    assert cost_of(block) is None


# --------------------------------------- a total that remembers its holes


def test_merging_an_unreported_stage_into_a_reported_one_does_not_lose_it():
    """The defect one level up: `merge` dropped the unknown half.

    A reported stage plus an unreported one gave `requests > 0`, so the total
    read as fully measured and the reported half was printed as the whole.
    """
    total = Usage()
    total.merge(_spent())
    total.merge(Usage.unreported_stage())

    assert total.reported is True
    assert total.complete is False
    assert total.cost_usd(*RATES) is None, "a partial total must not price"
    assert total.partial_cost_usd(*RATES) > 0, "but the floor is real and kept"


def test_a_review_whose_verifier_reported_nothing_is_not_priced_as_a_whole():
    """`verify_cli.verify_candidates_with_cli` returns no `Usage` by design
    while still incrementing `metrics.verified`. So the stage happened, and
    nothing about its cost came back — and `total_usage()` merged an empty
    accumulator, which is indistinguishable from a stage that never ran."""
    outcome = _outcome(_spent())
    outcome.turns = 4
    outcome.metrics.verified = 2          # a panel sat
    assert outcome.verification_usage.reported is False   # and said nothing

    total = outcome.total_usage()
    assert total.unreported_stages == 1
    assert total.cost_usd(*RATES) is None
    assert total.partial_cost_usd(*RATES) > 0


def test_a_stage_that_never_ran_is_not_counted_as_a_gap():
    """PRESERVATION. The over-correction: treating every empty accumulator as
    a hole would make every review without verification unpriceable."""
    outcome = _outcome(_spent())
    outcome.turns = 4
    assert outcome.metrics.verified == 0   # no panel was asked for

    total = outcome.total_usage()
    assert total.complete is True
    assert total.cost_usd(*RATES) > 0


def test_a_reviewer_that_ran_and_reported_nothing_is_a_gap():
    """The Claude Code path: turns were taken and no figure came back. The
    artifact must record the hole, not merely an empty `Usage`."""
    outcome = _outcome(Usage())
    outcome.turns = 7

    total = outcome.total_usage()
    assert total.unreported_stages == 1
    assert total.reported is False
    assert total.cost_usd(*RATES) is None


def test_a_partial_total_survives_the_round_trip_through_the_artifact(tmp_path):
    """A gap that is written and not read back is a gap that heals itself.

    `cost_of` re-scores a stored artifact, and without `unreported_stages`
    coming back it would price a partial total as a whole one.
    """
    outcome = _outcome(_spent())
    outcome.turns = 4
    outcome.metrics.verified = 2
    cfg = Config(output_dir=tmp_path, post_comment=False)
    block = build_json(cfg, outcome, decide(cfg, outcome))["usage"]

    assert block["complete"] is False
    assert block["unreported_stages"] == 1
    assert cost_of(block) is None


# ------------------------------------------------------------ the artifact


def test_the_artifact_records_the_absence_and_not_four_zeros(tmp_path):
    """`usage` in the stored JSON must be unmistakable to a reader who skims.

    Before: `{"requests": 0, "input_tokens": 0, ...}` — a run of zero tokens
    and a run nobody measured were the same document.
    """
    cfg = Config(output_dir=tmp_path, post_comment=False)
    outcome = _outcome(Usage())
    usage = build_json(cfg, outcome, decide(cfg, outcome))["usage"]

    assert usage["reported"] is False
    for key in ("input_tokens", "output_tokens",
                "cache_read_tokens", "cache_write_tokens"):
        assert usage[key] is None, "{} is 0, which prices the run".format(key)


def test_the_artifact_still_records_the_numbers_when_there_are_numbers(tmp_path):
    """PRESERVATION. The opposite over-correction: answering "not reported" to
    everything would satisfy every regression test in this file."""
    cfg = Config(output_dir=tmp_path, post_comment=False)
    outcome = _outcome(_spent())
    usage = build_json(cfg, outcome, decide(cfg, outcome))["usage"]

    assert usage["reported"] is True
    assert usage["input_tokens"] == 4000
    assert usage["cache_write_tokens"] == 33000
    assert usage["requests"] == 1


# ----------------------------------------------- the merge request comment


def test_the_comment_does_not_price_a_review_it_could_not_measure(tmp_path):
    """The meta line under the verdict said `~$0.00` on every CLI review."""
    cfg = Config(output_dir=tmp_path, post_comment=False)
    outcome = _outcome(Usage())
    markdown = render_markdown(cfg, outcome, decide(cfg, outcome))

    assert "$0.00" not in markdown
    assert "cost not reported by this runner" in markdown


def test_the_comment_does_not_print_a_row_of_zero_tokens(tmp_path):
    """`0 in · 0 out · 0 read from cache` is a claim, and it was a false one."""
    cfg = Config(output_dir=tmp_path, post_comment=False)
    outcome = _outcome(Usage())
    markdown = render_markdown(cfg, outcome, decide(cfg, outcome))

    assert "0 in · 0 out" not in markdown
    assert "**Tokens:** not reported by this runner" in markdown


def test_the_comment_prices_a_review_that_was_measured(tmp_path):
    """PRESERVATION. Passes before the fix too — this rendering was already
    correct. Kept so the fix cannot be satisfied by refusing to price
    anything."""
    cfg = Config(output_dir=tmp_path, post_comment=False)
    outcome = _outcome(_spent())
    markdown = render_markdown(cfg, outcome, decide(cfg, outcome))

    assert "not reported by this runner" not in markdown
    assert "4,000 in · 6,000 out" in markdown


def test_the_comment_calls_a_partly_measured_review_a_floor(tmp_path):
    """The half-measured review, all the way to the comment a person reads.

    Before, the meta line said `~$1.94` and the token row printed the review
    stage's figures with nothing to say a whole stage was missing from them.
    A total covering one of two stages, presented as the total.
    """
    cfg = Config(output_dir=tmp_path, post_comment=False)
    outcome = _outcome(_spent())
    outcome.turns = 4
    outcome.metrics.verified = 2
    markdown = render_markdown(cfg, outcome, decide(cfg, outcome))

    assert "at least ~$" in markdown
    assert "1 stage(s) reported nothing" in markdown
    assert "this is a floor and not the total" in markdown
    # The figure must never appear as a bare total anywhere in the comment.
    meta = next(line for line in markdown.splitlines() if " mode · " in line)
    assert "at least" in meta


# ----------------------------------------------------------- the batch total


def test_a_sum_with_an_unknown_part_is_unknown():
    """A pair is two runs. Half a sum is not the sum."""
    assert add_costs([1.5, None]) is None
    assert add_costs([1.5, 0.5]) == 2.0


def test_a_batch_that_measured_nothing_does_not_total_zero_dollars():
    """The line `total cost $0.00 across 5 pairs` over five paid batches."""
    line = cost_summary([None, None, None, None, None], "pair")
    assert "$0.00" not in line
    assert "NOT REPORTED" in line


def test_a_partly_measured_batch_names_what_is_missing_beside_the_figure():
    """The case that hides: a real number standing for half the runs.

    Summing the known parts and printing the count of all of them is how an
    unmeasured half disappears — the reader sees a figure and cannot tell.
    """
    line = cost_summary([1.0, None, 2.0], "pair")
    assert "$3.00" in line
    assert "2 of 3" in line
    assert "could not be costed" in line
    # Not "reported no usage". The first go batch had all twelve runs report
    # their review stage and this line still said five of six pairs reported
    # nothing — because the verifier is a second CLI invocation returning no
    # `Usage`, so the pair's total is incomplete and refuses to price itself.
    # The arithmetic was right and the sentence named the wrong cause, which is
    # the failure this module exists to prevent, in its own output.
    assert "reported no usage" not in line


def test_the_corpus_report_refuses_to_call_an_unmeasured_run_free(capsys):
    """End of the chain: what `tools/pair_corpus.py` prints after a batch."""
    report([
        {"case_id": "go-sql-01", "language": "go", "family": "injection",
         "pair_success": True, "safe_false_positive": False, "unsafe_recall": True,
         "cost": None, "size_delta": 0.0},
        {"case_id": "py-cmd-02", "language": "python", "family": "injection",
         "pair_success": True, "safe_false_positive": False, "unsafe_recall": True,
         "cost": None, "size_delta": 0.0},
    ])
    out = capsys.readouterr().out
    assert "$0.00" not in out
    assert "NOT REPORTED" in out


# ------------------------------- the figure the provider did give, named


def _row(**provenances) -> dict:
    return {"members": {name: {"provenance": prov}
                        for name, prov in provenances.items()}}


def test_a_figure_the_cli_did_report_is_not_thrown_away_as_unreported():
    """`reported_cost_usd` is in four stored runs and nothing read it.

    Answering "not reported" over a run whose provider gave a number is the
    opposite error to the one being fixed, and this project takes its figures
    from artifacts.
    """
    line = notional_summary([_row(safe={"reported_cost_usd": 0.42},
                                  unsafe={"reported_cost_usd": 0.29})])
    assert "$0.71" in line
    assert "2 of those 2 runs" in line


def test_the_notional_figure_is_never_offered_as_the_bill():
    """A two-token reply on a Max plan came back as $0.29. It billed nothing."""
    line = notional_summary([_row(safe={"reported_cost_usd": 0.42})])
    assert "not what was billed" in line
    assert "not the figure above" in line


def test_runs_from_before_the_field_existed_produce_no_line():
    """Silence, not a $0.00 line, for the batches that predate the field."""
    assert notional_summary([_row(safe={"agent_version": "0.1.0"})]) == ""


def test_the_notional_figure_stays_out_of_the_total(capsys):
    """Two quantities, two lines. Summing them would bill a subscription."""
    report([
        {"case_id": "rb-g65v", "language": "ruby", "family": "injection",
         "pair_success": True, "safe_false_positive": False, "unsafe_recall": True,
         "cost": None, "size_delta": 0.0,
         "members": {"safe": {"provenance": {"reported_cost_usd": 0.43}},
                     "unsafe": {"provenance": {"reported_cost_usd": 0.29}}}},
    ])
    out = capsys.readouterr().out
    assert "NOT REPORTED" in out
    assert "$0.72" in out
    # The two must never end up on one line, which is what makes the notional
    # figure readable as the total.
    total_line = next(line for line in out.splitlines() if "total cost" in line)
    assert "$" not in total_line


# ------------------------------------------------- against what is on disk


def test_no_stored_member_run_is_priced_as_a_free_review():
    """The chain, over the artifacts themselves rather than over a fixture.

    Each of the 38 members recorded five zeros, and `cost_of` returned `0.0`
    for every one — which is what made the batch totals believable. A stored
    run must now come back either as a real figure or as "not reported", and
    never as an exact zero.
    """
    members = [
        (path.name, row.get("case_id"), name, body.get("usage"))
        for path in sorted(MEASUREMENTS.glob("*.json"))
        for row in json.loads(path.read_text(encoding="utf-8"))
        for name, body in (row.get("members") or {}).items()
    ]
    if not members:
        pytest.skip("no stored batches to read")

    priced_free = [
        "{}:{}:{}".format(batch, case, member)
        for batch, case, member, usage in members
        if cost_of(usage or {}) == 0.0
    ]
    assert not priced_free, (
        "these stored runs price at exactly $0.00: {}".format(priced_free[:5]))


def test_a_stage_that_counted_its_own_silence_is_not_counted_twice():
    """`add()` given a response carrying none of the four token fields records
    a gap. `total_usage` then added another for the same stage, because it
    asked whether the stage had *reported* rather than whether it had recorded
    anything at all — so the artifact said two stages reported nothing where
    one did.

    The total stayed correctly incomplete throughout, which is why this
    survived: the conclusion was right and the number beside it was not, and
    the number is what somebody would try to reproduce.
    """
    outcome = ScanOutcome(mode="diff")
    outcome.turns = 3
    outcome.usage.add(object())          # ran, said nothing: one gap, recorded

    total = outcome.total_usage()
    assert total.complete is False
    assert total.unreported_stages == 1


def test_a_stage_that_ran_and_recorded_nothing_at_all_is_still_a_gap():
    """The other side of the same condition, so narrowing it cannot make the
    gap disappear: an accumulator nobody touched, for a stage that ran."""
    outcome = ScanOutcome(mode="diff")
    outcome.turns = 3

    total = outcome.total_usage()
    assert total.complete is False
    assert total.unreported_stages == 1


# ------------------------ the block the CLI actually sends


CLI_BLOCK = {"input_tokens": 4421, "output_tokens": 7478,
             "cache_creation_input_tokens": 41134,
             "cache_read_input_tokens": 158506}


def test_the_block_the_cli_sends_is_read_whole():
    """Parsed for a fortnight and read by nobody.

    `CliResult.usage` held this from the day it was added and nothing ever
    took it, which is why all 38 stored member runs wrote five zeros. The four
    names come from the CLI's own session transcripts under
    `~/.claude/projects/` — 1729 blocks, every one the Messages API spelling —
    rather than from a guess about which of two documented spellings it uses.
    """
    usage = Usage.from_provider(CLI_BLOCK)

    assert usage.reported is True
    assert usage.complete is True
    assert usage.requests == 1
    assert usage.input_tokens == 4421
    assert usage.output_tokens == 7478
    # The two that a partial read would have dropped, and they are the large
    # ones: 200k of cache against 12k of plain tokens here.
    assert usage.cache_write_tokens == 41134
    assert usage.cache_read_tokens == 158506


@pytest.mark.parametrize("block", [
    {k: v for k, v in CLI_BLOCK.items() if k != "cache_read_input_tokens"},
    {k: v for k, v in CLI_BLOCK.items() if k != "cache_creation_input_tokens"},
    {"inputTokens": 4421, "outputTokens": 7478,
     "cacheCreationInputTokens": 41134, "cacheReadInputTokens": 158506},
    {"input_tokens": 4421, "output_tokens": None,
     "cache_creation_input_tokens": 41134, "cache_read_input_tokens": 158506},
    "not a block", None, {},
])
def test_a_shape_it_cannot_read_whole_is_a_gap_and_never_a_part(block):
    """All four or none, and the reason is the whole point of this module.

    Reading the two plain counts without the two cache counts understates the
    cost by most of it — 12k against 200k in the block above — and an
    understated figure reads as measured. So an unexpected shape produces
    "this runner reported nothing", which is true, rather than a number that
    is not. The camelCase case is the one that would have happened had the
    spelling been guessed from the neighbouring `modelUsage`.
    """
    usage = Usage.from_provider(block)

    assert usage.reported is False
    assert usage.complete is False
    assert usage.counted == 0
    assert usage.cost_usd(3.0, 15.0) is None


def test_a_run_that_genuinely_used_nothing_is_still_a_report():
    """The boundary in the other direction: four names carrying zero is a
    provider saying zero, which is not the same as a provider saying nothing."""
    usage = Usage.from_provider({name: 0 for name in Usage.CLI_FIELDS})

    assert usage.reported is True
    assert usage.complete is True
    assert usage.cost_usd(3.0, 15.0) == 0.0
