"""Every state of every checker in `tools/d013_order.py`, and the refusals.

The tool answers whether an action D-013 orders may be done yet. Three kinds of
failure are worth more than the rest, and they are what most of this file is
for:

* **A state rendered as `done` when it is not.** `cannot tell`, `waiting`,
  `guard_failed`, `blocked_on_owner` and `done_when undefined` are five
  different answers, and each has its own test here. The one that has already
  cost this project a day is `classify_alarms`: every alarm carried a ruling,
  none named a cause, and the step was reported complete.
* **`done_when: undefined` collapsed into "not done".** It is the third answer
  — "this cannot be determined" — and it exits 2, not 1.
* **The tool reporting on a shorter list than DECISIONS.md names.** A step in
  the block with no checker, a checker with no step, a guard naming a metric
  nobody computes, a criterion reworded without its checker, and — the defect
  Codex found in the first implementation — a field in the block the parser
  silently drops.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import d013_order as order_tool  # noqa: E402

# --------------------------------------------------------------------------
# fixtures: a block, a decisions file, a context


BLOCK = """\
# d013-order
open_questions:
  - id: q_guard
    asked_of: owner
    text: what happens when the guard fails
answered_questions:
  - id: q_fork
    answered_by: owner
    answered_on: 2026-09-04
    text: step 5 is an exception to the boxed rule
generations:
  disjoint: required
  records: [configuration_digest, case_ids]
  on_overlap: refuse
steps:
  - id: freeze
    requires: []
    done_when: undefined
  - id: adjudicate_30
    requires: [freeze]
    done_when: undefined
  - id: extend_to_100
    requires: [adjudicate_30]
    guard: fewer than 5 of the 30 are unclear
    guard_field: unclear_count
    guard_below: 5
    guard_failure_blocked_on: q_guard
    done_when: undefined
  - id: classify_alarms
    requires: []
    needs_field: failure_mode
    needs_vocabulary_first: true
    vocabulary: [a, b, reachability-discipline]
    done_when: every alarm carries a non-empty failure_mode
  - id: tune
    requires: [extend_to_100, classify_alarms]
    undefined_predicates: [close to the boundary, broad]
    next_generation: required
    done_when: undefined
  - id: sonnet_gate
    requires: [extend_to_100, classify_alarms]
    done_when: undefined
"""

# The same order with a criterion named for every step. Five of the six are
# `undefined` in the real document, which is the honest state and also means
# their checkers never run — so the tests that exercise waiting, the guard and
# the violation detector use this variant together with the `criteria` fixture.
CRITERIA = {
    "freeze": "the freeze artifact verifies",
    # "claim a human", not "by hand", even in a fixture nobody reads twice.
    # The phrase is the one Codex blocked a commit over: a self-reported field
    # printed as a finding is how a claim becomes a fact a few readers later,
    # and a fixture is where the careless wording survives longest.
    "adjudicate_30": "thirty verdicts are filled and claim a human",
    "extend_to_100": "a hundred verdicts are filled and claim a human",
    "tune": "the two conditions hold",
    "sonnet_gate": "the gate has a written result",
}


def defined_block() -> str:
    block = BLOCK
    for step_id, sentence in CRITERIA.items():
        block = block.replace(
            "  - id: {}\n".format(step_id),
            "  - id: {}\n    XDONEX: {}\n".format(step_id, sentence))
    block = block.replace("    done_when: undefined\n", "")
    return block.replace("XDONEX", "done_when")


@pytest.fixture
def criteria(monkeypatch):
    for step_id, sentence in CRITERIA.items():
        monkeypatch.setitem(order_tool.DONE_WHEN_IMPLEMENTED, step_id, sentence)


def decisions_text(block: str = BLOCK) -> str:
    return (
        "# The decisions\n\n"
        "## D-012 · something else\n\nbody\n\n"
        "## D-013 · The stop rule\n\n"
        "### The order\n\n"
        "1. **Freeze** the configuration.\n"
        "3. **Extend to 100** if fewer than 5 of the 30 are `unclear`.\n\n"
        "```yaml\n" + block + "```\n\n"
        "### The fields the schema asks for\n\nmore body\n\n"
        "## D-014 · the next one\n\ntail\n"
    )


def write_decisions(tmp_path: Path, block: str = BLOCK) -> Path:
    path = tmp_path / "DECISIONS.md"
    path.write_text(decisions_text(block), encoding="utf-8")
    return path


def parse(block: str = BLOCK) -> order_tool.Order:
    return order_tool.parse_order(decisions_text(block))


def context(tmp_path: Path, **kwargs) -> order_tool.Context:
    # Written once. Rewriting it on every call would undo an edit a test made
    # on purpose — which is how the "D-013 changed since the freeze" test
    # passed against a file that had been silently restored underneath it.
    existing = tmp_path / "DECISIONS.md"
    kwargs.setdefault("decisions", existing if existing.is_file()
                      else write_decisions(tmp_path))
    kwargs.setdefault("freeze", tmp_path / "freeze.json")
    kwargs.setdefault("generations", tmp_path / "generations.json")
    return order_tool.Context(root=tmp_path, **kwargs)


def step_of(order: order_tool.Order, ident: str) -> order_tool.Step:
    return next(s for s in order.steps if s.id == ident)


def alarms(fired, rulings, field="failure_mode", **extra):
    """An alarm reader the tests inject, matching `Context.alarm_reader`."""
    def read(needs_field: str):
        assert needs_field == field
        return dict(order_tool.classify_alarm_counts(fired, rulings, needs_field),
                    rows=len(fired), **extra)
    return read


# --------------------------------------------------------------------------
# the block: found, and refused when it cannot be read


class TestFindingTheBlock:
    def test_found_by_its_marker_not_by_position(self):
        text = decisions_text().replace(
            "### The order\n", "### The order\n\n```python\nx = 1\n```\n")
        first = next(s.id for s in order_tool.parse_order(text).steps)
        assert first == "freeze"

    def test_absent_block_refuses_and_names_the_remedy(self):
        with pytest.raises(order_tool.OrderError) as caught:
            order_tool.parse_order("# nothing here\n")
        assert "no machine-readable order" in str(caught.value)
        assert "will not fall back to parsing the prose" in str(caught.value)

    def test_two_blocks_refuse(self):
        text = decisions_text() + "\n```yaml\n" + BLOCK + "```\n"
        with pytest.raises(order_tool.OrderError, match="exactly"):
            order_tool.parse_order(text)

    def test_unterminated_fence_is_a_refusal_not_an_empty_block(self):
        with pytest.raises(order_tool.OrderError, match="unterminated"):
            order_tool.fenced_blocks("```yaml\nsteps: []\n")


class TestUnknownFieldsAreARefusal:
    """The defect Codex found: a parser that keeps `id` and `requires` and
    drops the rest reports a step as ready that the block says is not."""

    def test_unknown_key_in_a_step(self):
        block = BLOCK.replace("  - id: tune\n",
                              "  - id: tune\n    blocked_on_ow: q_guard\n")
        with pytest.raises(order_tool.OrderError) as caught:
            parse(block)
        assert "blocked_on_ow" in str(caught.value)
        assert "does not act on" in str(caught.value)

    def test_unknown_key_at_the_top_level(self):
        with pytest.raises(order_tool.OrderError, match="notes"):
            parse(BLOCK.replace("steps:\n", "notes: hello\nsteps:\n"))

    def test_unknown_key_in_an_open_question(self):
        with pytest.raises(order_tool.OrderError, match="urgency"):
            parse(BLOCK.replace("    asked_of: owner\n",
                                "    asked_of: owner\n    urgency: high\n"))

    def test_unknown_key_in_an_answered_question(self):
        with pytest.raises(order_tool.OrderError, match="mood"):
            parse(BLOCK.replace("    answered_by: owner\n",
                                "    answered_by: owner\n    mood: relieved\n"))

    def test_unknown_key_in_generations(self):
        with pytest.raises(order_tool.OrderError, match="strictness"):
            parse(BLOCK.replace("  disjoint: required\n",
                                "  disjoint: required\n  strictness: high\n"))


class TestTheShapeOfAStep:
    def test_missing_requires_is_refused_not_defaulted(self):
        with pytest.raises(order_tool.OrderError) as caught:
            parse(BLOCK.replace("  - id: freeze\n    requires: []\n",
                                "  - id: freeze\n"))
        assert "will not guess" in str(caught.value)

    def test_missing_done_when_is_refused_not_defaulted(self):
        block = BLOCK.replace(
            "  - id: sonnet_gate\n    requires: [extend_to_100, classify_alarms]"
            "\n    done_when: undefined\n",
            "  - id: sonnet_gate\n    requires: [extend_to_100, classify_alarms]\n")
        with pytest.raises(order_tool.OrderError) as caught:
            parse(block)
        assert "done_when" in str(caught.value)
        assert "not the same claim" in str(caught.value)

    def test_requires_naming_an_unknown_step(self):
        with pytest.raises(order_tool.OrderError, match="not a step id"):
            parse(BLOCK.replace("requires: [freeze]", "requires: [thaw]"))

    def test_a_step_requiring_itself(self):
        with pytest.raises(order_tool.OrderError, match="requires itself"):
            parse(BLOCK.replace(
                "  - id: adjudicate_30\n    requires: [freeze]",
                "  - id: adjudicate_30\n    requires: [adjudicate_30]"))

    def test_a_cycle(self):
        with pytest.raises(order_tool.OrderError, match="cycle"):
            parse(BLOCK.replace("  - id: freeze\n    requires: []",
                                "  - id: freeze\n    requires: [extend_to_100]"))

    def test_a_duplicate_step_id(self):
        with pytest.raises(order_tool.OrderError, match="appears twice"):
            parse(BLOCK + "  - id: freeze\n    requires: []\n"
                          "    done_when: undefined\n")

    def test_half_a_guard_is_refused(self):
        with pytest.raises(order_tool.OrderError) as caught:
            parse(BLOCK.replace("    guard_below: 5\n", ""))
        assert "needs all four" in str(caught.value)

    def test_guard_below_must_be_a_number(self):
        with pytest.raises(order_tool.OrderError, match="must be a number"):
            parse(BLOCK.replace("guard_below: 5", "guard_below: five"))

    def test_guard_failure_must_name_a_written_question(self):
        with pytest.raises(order_tool.OrderError, match="open_questions"):
            parse(BLOCK.replace("guard_failure_blocked_on: q_guard",
                                "guard_failure_blocked_on: q_nowhere"))

    def test_blocked_on_owner_must_name_a_written_question(self):
        block = BLOCK.replace("  - id: tune\n",
                              "  - id: tune\n    blocked_on_owner: whatever\n")
        with pytest.raises(order_tool.OrderError, match="open_questions"):
            parse(block)

    def test_blocked_on_owner_may_name_an_answered_question(self):
        block = BLOCK.replace("  - id: tune\n",
                              "  - id: tune\n    blocked_on_owner: q_fork\n")
        assert step_of(parse(block), "tune").blocked_on_owner == "q_fork"

    def test_an_open_question_with_no_text(self):
        with pytest.raises(order_tool.OrderError, match="text"):
            parse(BLOCK.replace(
                "    text: what happens when the guard fails\n", ""))

    def test_an_answer_with_no_author_or_date(self):
        with pytest.raises(order_tool.OrderError, match="answered_on"):
            parse(BLOCK.replace("    answered_on: 2026-09-04\n", ""))

    def test_a_question_both_open_and_answered(self):
        with pytest.raises(order_tool.OrderError, match="stale"):
            parse(BLOCK.replace("  - id: q_fork\n", "  - id: q_guard\n"))

    def test_needs_vocabulary_first_must_be_a_boolean(self):
        with pytest.raises(order_tool.OrderError, match="true or false"):
            parse(BLOCK.replace("needs_vocabulary_first: true",
                                "needs_vocabulary_first: yes please"))

    def test_next_generation_takes_only_the_value_it_acts_on(self):
        with pytest.raises(order_tool.OrderError, match="next_generation"):
            parse(BLOCK.replace("next_generation: required",
                                "next_generation: maybe"))


class TestTheGenerationsRule:
    def test_a_rule_it_cannot_enforce_is_refused(self):
        with pytest.raises(order_tool.OrderError, match="disjoint"):
            parse(BLOCK.replace("disjoint: required", "disjoint: preferred"))

    def test_a_warning_it_cannot_issue_is_refused(self):
        with pytest.raises(order_tool.OrderError, match="on_overlap"):
            parse(BLOCK.replace("on_overlap: refuse", "on_overlap: warn"))

    def test_records_must_name_fields(self):
        with pytest.raises(order_tool.OrderError, match="records"):
            parse(BLOCK.replace("records: [configuration_digest, case_ids]",
                                "records: []"))

    def test_it_is_reported_declared_and_unenforceable(self, tmp_path):
        result = order_tool.check_generations(
            context(tmp_path), parse().generations)
        assert result.state == order_tool.UNKNOWN
        assert "not enforceable" in result.evidence
        assert "aliases" in result.evidence

    def test_no_rule_at_all_is_also_cannot_tell(self, tmp_path):
        assert order_tool.check_generations(context(tmp_path), None).state == \
            order_tool.UNKNOWN


class TestDivergenceBetweenTheBlockAndTheCheckers:
    def test_a_step_the_tool_has_no_checker_for(self):
        block = BLOCK + "  - id: publish\n    requires: []\n" \
                        "    done_when: undefined\n"
        problems = order_tool.divergence(parse(block))
        assert any("'publish'" in p and "no checker" in p for p in problems)

    def test_a_checker_for_a_step_the_document_dropped(self):
        block = BLOCK.replace(
            "  - id: sonnet_gate\n    requires: [extend_to_100, classify_alarms]"
            "\n    done_when: undefined\n", "")
        problems = order_tool.divergence(parse(block))
        assert any("'sonnet_gate'" in p and "no longer names it" in p
                   for p in problems)

    def test_a_guard_naming_a_metric_nobody_computes(self):
        problems = order_tool.divergence(
            parse(BLOCK.replace("guard_field: unclear_count",
                                "guard_field: vibes")))
        assert any("'vibes'" in p for p in problems)

    def test_a_criterion_the_tool_does_not_implement(self):
        """`sonnet_gate` and not `freeze`: freeze has a criterion now.

        Written against `freeze` while every step but one was `undefined`, so
        the test passed for a reason that expired the moment a checker was
        wired to it — it then produced "the criterion was reworded", which is
        the *other* refusal. The step used here has to be one the tool
        genuinely implements nothing for, or this tests the wrong branch.
        """
        block = BLOCK.replace(
            "  - id: sonnet_gate\n    requires: [extend_to_100, "
            "classify_alarms]\n    done_when: undefined\n",
            "  - id: sonnet_gate\n    requires: [extend_to_100, "
            "classify_alarms]\n    done_when: it feels measured\n")
        assert "it feels measured" in block, "the fixture moved under this test"
        problems = order_tool.divergence(parse(block))
        assert any("implements no criterion" in p for p in problems)

    def test_backticks_inside_the_block_do_not_end_it(self):
        """A closing fence must match the one that opened it.

        Any line starting with three backticks used to toggle the fence, so a
        scalar containing one truncated the block and the parser read the
        prefix as the whole order — dropping, here, the `open_questions` that
        keep a step stopped. Losing a restriction is the permissive direction.
        """
        block = BLOCK.replace(
            "    text: what happens when the guard fails\n",
            "    text: >-\n      ```\n      what happens when the guard fails\n")
        assert block != BLOCK, "the fixture moved under this test"
        order = parse(block)
        assert order.questions, "the open question was lost with the truncation"
        assert [s.id for s in order.steps] == [s.id for s in parse().steps]

    def test_a_bare_fence_deep_in_a_scalar_does_not_end_the_block(self):
        """Six spaces and nothing but backticks.

        The first repair matched the fence after `lstrip()`, which closes on
        any indent — so this line, which CommonMark does not accept as a
        closer, still truncated the block. The test written with it used
        ```` ```what happens… ````, whose trailing text prevents closure either
        way, so it asserted the fix and covered neither case. Codex, twice on
        the same function, and the second time on the test as well.
        """
        block = BLOCK.replace(
            "    text: what happens when the guard fails\n",
            "    text: |-\n      the guard fails\n      ```\n")
        assert block != BLOCK, "the fixture moved under this test"
        order = parse(block)
        assert order.questions, "the open question was lost with the truncation"
        assert [s.id for s in order.steps] == [s.id for s in parse().steps]

    def test_a_key_written_twice_is_refused_not_resolved(self):
        """The refusal of unknown fields runs after the load, and by then a
        duplicate has already been resolved in silence.

        Codex, 2026-09-04. `yaml.safe_load` keeps the last of two identical
        keys and says nothing, so a second `requires:` replaced the first and
        the whole order flattened — no unknown field, no schema error, no
        warning. Verified before the fix: the block below parsed, and
        `adjudicate_30.requires` came out `[]`.
        """
        block = BLOCK.replace(
            "  - id: adjudicate_30\n    requires: [freeze]\n",
            "  - id: adjudicate_30\n    requires: [freeze]\n    requires: []\n")
        assert block != BLOCK, "the fixture moved under this test"
        with pytest.raises(order_tool.OrderError) as caught:
            parse(block)
        assert "twice" in str(caught.value)

    def test_a_merge_key_is_refused_with_a_remedy(self):
        """`<<:` is the duplicate's other route, and it already failed — badly.

        It raised "could not determine a constructor for the tag merge", which
        says nothing about what to do, and a refusal with no remedy is answered
        by rewording the input past it. Checked by hand alongside anchors:
        `&x` / `*x` reuse a *value* and hide nothing, so they still parse.
        """
        block = BLOCK.replace(
            "  - id: freeze\n    requires: []\n",
            "  - &tpl\n    id: freeze\n    requires: []\n", 1).replace(
            "  - id: adjudicate_30\n",
            "  - <<: *tpl\n    id: adjudicate_30\n", 1)
        assert "<<: *tpl" in block, "the fixture moved under this test"
        with pytest.raises(order_tool.OrderError) as caught:
            parse(block)
        assert "merge key" in str(caught.value)
        assert "write each step's fields out" in str(caught.value)

    def test_a_criterion_reworded_without_its_checker(self):
        block = BLOCK.replace(
            "done_when: every alarm carries a non-empty failure_mode",
            "done_when: most alarms carry a failure_mode")
        problems = order_tool.divergence(parse(block))
        assert any("reworded" in p for p in problems)

    def test_the_real_decisions_file_and_this_tool_agree(self):
        """The chain, not the links. Adding a step or rewording a criterion in
        DECISIONS.md must fail here rather than produce a shorter report."""
        real = order_tool.parse_order(
            (ROOT / "DECISIONS.md").read_text(encoding="utf-8"))
        assert order_tool.divergence(real) == []

    def test_no_step_depends_on_one_that_can_never_be_done(self):
        """A prerequisite with no criterion is a permanent prohibition.

        The defect this pins, found by Codex on 2026-09-04: `freeze` carried
        `done_when: undefined`, and since a step with no criterion can never be
        reported done nor satisfy another step's `requires`, `adjudicate_30`
        could never start, and neither could anything behind it. The order was
        unreachable and read as "cannot tell" — the whole graph blocked, with
        completed artifacts still invisible.

        `undefined` on a *leaf* is honest: `tune` and `sonnet_gate` carry it
        because nothing records their completion, and nothing waits on them.
        The failure is `undefined` on something another step needs.
        """
        real = order_tool.parse_order(
            (ROOT / "DECISIONS.md").read_text(encoding="utf-8"))
        # `criterion_undefined`, not `done_when is None`: the parser refuses a
        # step with no `done_when` at all, so the absent case never reaches
        # here and a test written against `None` is a test of an empty set.
        # Written that way first, and it passed while the defect was present.
        undefined = {s.id for s in real.steps if s.criterion_undefined}
        assert "sonnet_gate" in undefined, (
            "this test is only meaningful while some step is undefined; if "
            "every step now has a criterion, delete it rather than let it "
            "pass on an empty set")
        depended_on = {need for s in real.steps for need in s.requires}
        blocked = sorted(undefined & depended_on)
        assert not blocked, (
            "step(s) {} have `done_when: undefined` and are required by "
            "another step, so no path through the order can ever open".format(
                blocked))

    def test_the_prose_threshold_and_the_block_threshold_agree(self):
        """`guard_below` is the only number the checker acts on, and the prose
        states it in English above the block. The two drift silently."""
        section = order_tool.d013_section_text(ROOT / "DECISIONS.md")
        assert section is not None
        prose = re.search(r"fewer than (\d+) of the (\d+)", section)
        assert prose is not None, "D-013 no longer states the guard in prose"
        real = order_tool.parse_order(
            (ROOT / "DECISIONS.md").read_text(encoding="utf-8"))
        assert step_of(real, "extend_to_100").guard_below == int(prose.group(1))
        assert order_tool.target_from_id("adjudicate_30") == int(prose.group(2))


# --------------------------------------------------------------------------
# done_when: the third answer


class TestDoneWhenUndefined:
    def test_it_is_its_own_state_and_not_not_done(self, tmp_path):
        ctx = context(tmp_path, alarm_reader=alarms([], []))
        results = order_tool.evaluate(ctx, parse())
        assert results["freeze"].state == order_tool.UNDEFINED_CRITERION
        assert results["freeze"].state != order_tool.NOT_DONE

    def test_it_names_what_is_missing_and_what_would_fix_it(self, tmp_path):
        ctx = context(tmp_path, alarm_reader=alarms([], []))
        results = order_tool.evaluate(ctx, parse())
        evidence = results["freeze"].evidence
        assert "names no artifact" in evidence
        assert "work rather than wording" in evidence

    def test_it_never_satisfies_another_steps_requires(self, tmp_path):
        ctx = context(tmp_path, alarm_reader=alarms([], []))
        order = parse()
        results = order_tool.evaluate(ctx, order)
        code, reasons = order_tool.decide(order, results, "adjudicate_30")
        assert code == 2
        assert any("freeze is done_when undefined" in line for line in reasons)

    def test_the_checker_is_not_even_consulted(self, tmp_path, monkeypatch):
        """No fallback that infers completion from artifacts the block does not
        name: the criterion is absent, so nothing is derived."""
        called = []
        monkeypatch.setitem(
            order_tool.CHECKERS, "freeze",
            lambda c, s: called.append(1) or order_tool.Result(
                order_tool.DONE, "inferred"))
        ctx = context(tmp_path, alarm_reader=alarms([], []))
        results = order_tool.evaluate(ctx, parse())
        assert called == []
        assert results["freeze"].state == order_tool.UNDEFINED_CRITERION

    def test_it_is_listed_apart_from_the_workable_and_the_stopped(self,
                                                                 tmp_path):
        ctx = context(tmp_path, alarm_reader=alarms([], []))
        order = parse()
        results = order_tool.evaluate(ctx, order)
        workable, stopped, undetermined = order_tool.next_steps(order, results)
        assert workable == ["classify_alarms"]
        assert stopped == []
        assert set(undetermined) == {"freeze", "adjudicate_30",
                                     "extend_to_100", "tune", "sonnet_gate"}

    def test_status_over_the_real_repository_exits_two(self, capsys):
        code = order_tool.main(["status"])
        out = capsys.readouterr().out
        assert code == 2
        assert order_tool.UNDEFINED_CRITERION in out


# --------------------------------------------------------------------------
# the freeze


def frozen_root(tmp_path: Path) -> Path:
    """A tree carrying every file the freeze digests."""
    for name, _why in order_tool.FROZEN_INPUTS:
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("content of {}\n".format(name), encoding="utf-8")
    agent = tmp_path / "src" / "security_agent"
    agent.mkdir(parents=True, exist_ok=True)
    (agent / "__init__.py").write_text('__version__ = "9.9.9"\n',
                                       encoding="utf-8")
    return tmp_path


def good_freeze(ctx: order_tool.Context) -> dict:
    """A record of what is actually here, not a plausible-looking one.

    `configuration` used to be the literal `{"model_requested": "opus"}`. That
    made every freeze test agree with a record no `freeze` run would ever
    write, and it hid the defect Codex found on 2026-09-04: the checker only
    asked whether a model was written down, never whether it was still the one
    this shell would ask for. A fixture that cannot drift cannot catch drift.
    """
    section = ctx.d013_section()
    configuration, error = order_tool.resolved_configuration(ctx.root)
    assert error is None, error
    return {
        "schema": order_tool.FREEZE_SCHEMA,
        "created_at": "2026-09-04T00:00:00+00:00",
        "owner_acknowledgement": "the owner, 2026-09-04",
        "git": {"commit": "a" * 40, "dirty": False, "dirty_paths": {}},
        "d013": {"text": section, "digest": order_tool.sha256_text(section)},
        "configuration": configuration,
        "inputs": {name: {"digest": order_tool.sha256_file(ctx.root / name)}
                   for name, _why in order_tool.FROZEN_INPUTS},
        "derived": {"reviewer": order_tool.tree_digest(
            ctx.root / "src" / "security_agent", "*.py")},
    }


class TestTheFreezeChecker:
    def test_absent_is_not_done_and_names_the_command(self, tmp_path):
        ctx = context(frozen_root(tmp_path))
        result = order_tool.check_freeze(ctx, None)
        assert result.state == order_tool.NOT_DONE
        assert "d013_order.py freeze" in result.evidence

    def test_a_directory_where_the_file_should_be_is_cannot_tell(self, tmp_path):
        root = frozen_root(tmp_path)
        (root / "freeze.json").mkdir()
        assert order_tool.check_freeze(context(root), None).state == \
            order_tool.UNKNOWN

    def test_unparseable_is_cannot_tell_not_not_done(self, tmp_path):
        root = frozen_root(tmp_path)
        (root / "freeze.json").write_text("{oh dear", encoding="utf-8")
        assert order_tool.check_freeze(context(root), None).state == \
            order_tool.UNKNOWN

    def test_a_foreign_schema_is_cannot_tell(self, tmp_path):
        root = frozen_root(tmp_path)
        body = good_freeze(context(root))
        body["schema"] = "something/else"
        (root / "freeze.json").write_text(json.dumps(body), encoding="utf-8")
        assert order_tool.check_freeze(context(root), None).state == \
            order_tool.UNKNOWN

    def test_a_complete_freeze_verifies(self, tmp_path):
        root = frozen_root(tmp_path)
        (root / "freeze.json").write_text(
            json.dumps(good_freeze(context(root))), encoding="utf-8")
        assert order_tool.check_freeze(context(root), None).state == \
            order_tool.DONE

    def test_a_frozen_input_that_changed(self, tmp_path):
        root = frozen_root(tmp_path)
        (root / "freeze.json").write_text(
            json.dumps(good_freeze(context(root))), encoding="utf-8")
        (root / "prompts" / "system.md").write_text("edited\n", encoding="utf-8")
        result = order_tool.check_freeze(context(root), None)
        assert result.state == order_tool.NOT_DONE
        assert "prompts/system.md: changed since the freeze" in result.evidence

    def test_a_freeze_that_lists_almost_nothing(self, tmp_path):
        """A record with its entries deleted verified clean.

        Codex, 2026-09-04: `_freeze_problems` walked `inputs.items()` — what
        the *record* holds — so a freeze naming one file agreed with itself
        perfectly and reported `done`. The nine deleted entries had nothing
        left to disagree with. Every name in `FROZEN_INPUTS` must be present,
        not merely consistent where present.
        """
        root = frozen_root(tmp_path)
        body = good_freeze(context(root))
        kept = order_tool.FROZEN_INPUTS[0][0]
        body["inputs"] = {kept: body["inputs"][kept]}
        (root / "freeze.json").write_text(json.dumps(body), encoding="utf-8")
        result = order_tool.check_freeze(context(root), None)
        assert result.state == order_tool.NOT_DONE
        assert "names no digest for" in result.evidence
        assert kept not in result.evidence.split("names no digest for")[1]

    def test_the_model_changed_after_the_freeze(self, tmp_path):
        """The one change a freeze most needs to see moves no file on disk.

        The checker asked only whether `model_requested` was written down, so
        exporting a different model after the freeze left it verifying clean.
        Recorded *and compared*, or the freeze does not cover the reviewer.
        """
        root = frozen_root(tmp_path)
        body = good_freeze(context(root))
        body["configuration"] = dict(body["configuration"])
        body["configuration"]["model_requested"] = "claude-haiku-4-5"
        (root / "freeze.json").write_text(json.dumps(body), encoding="utf-8")
        result = order_tool.check_freeze(context(root), None)
        assert result.state == order_tool.NOT_DONE
        assert "model_requested" in result.evidence

    def test_a_frozen_input_that_vanished(self, tmp_path):
        root = frozen_root(tmp_path)
        (root / "freeze.json").write_text(
            json.dumps(good_freeze(context(root))), encoding="utf-8")
        (root / "tools" / "pair_corpus.py").unlink()
        result = order_tool.check_freeze(context(root), None)
        assert result.state == order_tool.NOT_DONE
        assert "frozen and now unreadable" in result.evidence

    def test_d013_edited_after_the_freeze(self, tmp_path):
        root = frozen_root(tmp_path)
        (root / "freeze.json").write_text(
            json.dumps(good_freeze(context(root))), encoding="utf-8")
        (root / "DECISIONS.md").write_text(
            decisions_text().replace("### The fields the schema asks for",
                                     "### A new subsection\n\nand a sentence\n\n"
                                     "### The fields the schema asks for"),
            encoding="utf-8")
        result = order_tool.check_freeze(context(root), None)
        assert result.state == order_tool.NOT_DONE
        assert "D-013 has changed since the freeze" in result.evidence

    def test_an_edit_outside_d013_does_not_break_the_freeze(self, tmp_path):
        root = frozen_root(tmp_path)
        (root / "freeze.json").write_text(
            json.dumps(good_freeze(context(root))), encoding="utf-8")
        (root / "DECISIONS.md").write_text(
            decisions_text() + "\n## D-015 · unrelated\n\nbody\n",
            encoding="utf-8")
        assert order_tool.check_freeze(context(root), None).state == \
            order_tool.DONE

    def test_no_inputs_recorded_at_all_is_refused(self, tmp_path):
        """The empty case is the one that slips through a "does anything
        contradict this" check, so it is required rather than forbidden."""
        root = frozen_root(tmp_path)
        body = good_freeze(context(root))
        body["inputs"] = {}
        (root / "freeze.json").write_text(json.dumps(body), encoding="utf-8")
        result = order_tool.check_freeze(context(root), None)
        assert result.state == order_tool.NOT_DONE
        assert "no `inputs` digests recorded" in result.evidence

    def test_an_unsigned_freeze_is_not_a_freeze(self, tmp_path):
        root = frozen_root(tmp_path)
        body = good_freeze(context(root))
        body["owner_acknowledgement"] = "   "
        (root / "freeze.json").write_text(json.dumps(body), encoding="utf-8")
        result = order_tool.check_freeze(context(root), None)
        assert result.state == order_tool.NOT_DONE
        assert "owner_acknowledgement" in result.evidence

    def test_a_dirty_tree_with_nothing_captured(self, tmp_path):
        root = frozen_root(tmp_path)
        body = good_freeze(context(root))
        body["git"] = {"commit": "b" * 40, "dirty": True, "dirty_paths": {}}
        (root / "freeze.json").write_text(json.dumps(body), encoding="utf-8")
        result = order_tool.check_freeze(context(root), None)
        assert result.state == order_tool.NOT_DONE
        assert "does not describe what ran" in result.evidence

    def test_the_reviewer_source_moving_is_caught(self, tmp_path):
        root = frozen_root(tmp_path)
        (root / "freeze.json").write_text(
            json.dumps(good_freeze(context(root))), encoding="utf-8")
        (root / "src" / "security_agent" / "extra.py").write_text(
            "x = 1\n", encoding="utf-8")
        result = order_tool.check_freeze(context(root), None)
        assert result.state == order_tool.NOT_DONE
        assert "reviewer's source changed" in result.evidence


class TestWritingTheFreeze:
    def test_it_refuses_without_an_acknowledgement(self, tmp_path):
        body, refusals = order_tool.build_freeze(
            context(frozen_root(tmp_path)), "", False)
        assert body is None
        assert any("--acknowledge" in line for line in refusals)

    def test_every_refusal_names_a_remedy(self, tmp_path):
        _body, refusals = order_tool.build_freeze(
            context(frozen_root(tmp_path)), "", False)
        assert refusals
        for line in refusals:
            assert len(line) > 40, line

    def test_it_will_not_overwrite_an_existing_freeze(self, tmp_path, capsys):
        root = frozen_root(tmp_path)
        target = root / "freeze.json"
        target.write_text("{}", encoding="utf-8")
        code = order_tool.main([
            "--root", str(root), "--decisions", str(write_decisions(root)),
            "freeze", "--out", str(target), "--acknowledge", "me"])
        assert code == 2
        assert "already exists" in capsys.readouterr().err


class TestReadingTheSection:
    def test_the_yaml_comment_in_the_block_does_not_end_the_section(self,
                                                                    tmp_path):
        """The order block's first line is `# d013-order`. Read as a markdown
        heading it truncated the section at the fence, so the freeze recorded
        D-013 down to that line and everything after it — the machine-readable
        order itself — could be edited without the freeze noticing."""
        path = write_decisions(tmp_path)
        section = order_tool.d013_section_text(path)
        assert section is not None
        assert "d013-order" in section
        assert "The fields the schema asks for" in section

    def test_a_deep_bare_fence_does_not_move_what_the_freeze_digests(
            self, tmp_path):
        """The live control, not its neighbour — and it failed the other way.

        `fenced_blocks` was repaired for indentation, fence length and tildes;
        this scanner kept a cruder copy — toggling on any line whose first
        non-space characters were three backticks — and it is the one the
        freeze takes D-013's digest through. Codex, 2026-09-04.

        The first version of this test asserted the section was not
        *truncated*, and passed under the old logic too: measured with the old
        scanner restored, the stray fence toggles the state off, the real
        closing fence toggles it back on, and the rest of the file then counts
        as fenced — so the section runs past `## D-014` instead of stopping
        short. Over-inclusion, not truncation, and the assertion that separates
        them is the neighbour's absence. A test that passes on the defect is
        not a test.
        """
        path = write_decisions(
            tmp_path,
            BLOCK.replace("    text: what happens when the guard fails\n",
                          "    text: |-\n      the guard fails\n      ```\n"))
        section = order_tool.d013_section_text(path)
        assert section is not None
        assert "The fields the schema asks for" in section
        assert "sonnet_gate" in section
        assert "D-014" not in section, (
            "the fence state inverted and the section swallowed the next "
            "decision — the freeze would then be broken by editing D-014")

    def test_an_unterminated_fence_is_refused_not_answered(self, tmp_path):
        """Two readers of one file disagreed about where D-013 ends.

        `parse_order` refused a document with an unterminated fence; this
        reader returned the section anyway, running to the end of the file and
        swallowing every decision after D-013. The freeze would then digest
        them too, and editing an unrelated decision would break it with no way
        to see why. Measured before the fix: the section came back holding
        `D-014`.
        """
        path = tmp_path / "DECISIONS.md"
        path.write_text(
            "## D-013 · the rule\n\n```yaml\n# d013-order\nsteps: []\n\n"
            "## D-014 · the next one\n\ntail\n", encoding="utf-8")
        with pytest.raises(order_tool.OrderError) as caught:
            order_tool.d013_section_text(path)
        assert "unterminated" in str(caught.value)

    def test_the_next_top_level_heading_ends_it(self, tmp_path):
        section = order_tool.d013_section_text(write_decisions(tmp_path))
        assert "D-014" not in section
        assert "D-012" not in section

    def test_a_file_without_d013_gives_none(self, tmp_path):
        path = tmp_path / "other.md"
        path.write_text("## D-001 · something\n", encoding="utf-8")
        assert order_tool.d013_section_text(path) is None


class TestTheDigestHelpers:
    def test_an_unreadable_file_digests_to_none_not_to_empty(self, tmp_path):
        """Two unreadable files must not compare equal. `round.digest_of`
        returns "" here, which would verify a deleted input as unchanged."""
        assert order_tool.sha256_file(tmp_path / "gone") is None

    def test_the_tree_digest_moves_when_a_file_is_renamed(self, tmp_path):
        (tmp_path / "a.py").write_text("x\n", encoding="utf-8")
        before = order_tool.tree_digest(tmp_path, "*.py")
        (tmp_path / "a.py").rename(tmp_path / "b.py")
        assert order_tool.tree_digest(tmp_path, "*.py") != before


# --------------------------------------------------------------------------
# the ordinary corpus


def ordinary(tmp_path: Path, cases: dict, drawn=None) -> dict:
    directory = tmp_path / "ordinary"
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "adjudications.yml").write_text(
        yaml.safe_dump({"cases": cases}), encoding="utf-8")
    ids = list(cases) if drawn is None else list(drawn)
    (directory / "manifest.json").write_text(
        json.dumps({"selected": [{"case_id": c} for c in ids]}),
        encoding="utf-8")
    return {"ordinary_dir": directory}


def case(verdict="ordinary", by="human"):
    return {"verdict": verdict, "adjudicated_by": by}


class TestTheAdjudicationChecker:
    def _step(self):
        return step_of(parse(), "adjudicate_30")

    def test_no_directory_is_cannot_tell_never_not_done(self, tmp_path):
        """Work the tool was not shown is not work that did not happen."""
        result = order_tool.check_adjudicate_30(context(tmp_path), self._step())
        assert result.state == order_tool.UNKNOWN
        assert "--ordinary-dir" in result.evidence

    def test_a_named_file_that_is_not_there(self, tmp_path):
        ctx = context(tmp_path, ordinary_dir=tmp_path / "nope")
        assert order_tool.check_adjudicate_30(ctx, self._step()).state == \
            order_tool.UNKNOWN

    def test_a_manifest_describing_a_different_sample(self, tmp_path):
        cases = {"c{}".format(i): case() for i in range(30)}
        ctx = context(tmp_path, **ordinary(tmp_path, cases,
                                           drawn=["c0", "elsewhere"]))
        result = order_tool.check_adjudicate_30(ctx, self._step())
        assert result.state == order_tool.UNKNOWN
        assert "do not describe one sample" in result.evidence

    def test_too_few_cases(self, tmp_path):
        ctx = context(tmp_path, **ordinary(
            tmp_path, {"c{}".format(i): case() for i in range(29)}))
        result = order_tool.check_adjudicate_30(ctx, self._step())
        assert result.state == order_tool.NOT_DONE
        assert "29 case(s) adjudicated, 30 required" in result.evidence

    def test_a_null_verdict_never_counts_as_ordinary(self, tmp_path):
        cases = {"c{}".format(i): case() for i in range(30)}
        cases["c0"]["verdict"] = None
        ctx = context(tmp_path, **ordinary(tmp_path, cases))
        result = order_tool.check_adjudicate_30(ctx, self._step())
        assert result.state == order_tool.NOT_DONE
        assert "unfilled" in result.evidence

    def test_a_missing_verdict_key_is_the_same_as_a_null_one(self, tmp_path):
        cases = {"c{}".format(i): case() for i in range(30)}
        del cases["c0"]["verdict"]
        ctx = context(tmp_path, **ordinary(tmp_path, cases))
        assert order_tool.check_adjudicate_30(ctx, self._step()).state == \
            order_tool.NOT_DONE

    def test_a_verdict_outside_the_vocabulary(self, tmp_path):
        cases = {"c{}".format(i): case() for i in range(30)}
        cases["c0"]["verdict"] = "probably fine"
        ctx = context(tmp_path, **ordinary(tmp_path, cases))
        result = order_tool.check_adjudicate_30(ctx, self._step())
        assert result.state == order_tool.NOT_DONE
        assert "not one of" in result.evidence

    def test_a_model_adjudicating_is_refused(self, tmp_path):
        cases = {"c{}".format(i): case() for i in range(30)}
        cases["c0"]["adjudicated_by"] = "model"
        ctx = context(tmp_path, **ordinary(tmp_path, cases))
        result = order_tool.check_adjudicate_30(ctx, self._step())
        assert result.state == order_tool.NOT_DONE
        assert "without a single model call" in result.evidence

    def test_a_missing_adjudicated_by_is_not_a_human(self, tmp_path):
        cases = {"c{}".format(i): case() for i in range(30)}
        del cases["c0"]["adjudicated_by"]
        ctx = context(tmp_path, **ordinary(tmp_path, cases))
        assert order_tool.check_adjudicate_30(ctx, self._step()).state == \
            order_tool.NOT_DONE

    def test_thirty_filled_and_claiming_human_is_done(self, tmp_path):
        """The name carries the claim too.

        It was `test_thirty_filled_by_hand_is_done`, and Codex blocked a second
        commit over it after the messages were fixed: a test name is read far
        more often than the assertion under it, so "by hand" would have gone on
        asserting what no artifact establishes.
        """
        ctx = context(tmp_path, **ordinary(
            tmp_path, {"c{}".format(i): case() for i in range(30)}))
        result = order_tool.check_adjudicate_30(ctx, self._step())
        assert result.state == order_tool.DONE
        assert "30 case(s)" in result.evidence

    def test_the_case_count_comes_from_the_step_id(self):
        assert order_tool.target_from_id("adjudicate_30") == 30
        assert order_tool.target_from_id("extend_to_100") == 100
        assert order_tool.target_from_id("freeze") is None


class TestTheGuard:
    """The guard is evaluated generically from the block, and only for a step
    whose criterion is defined — hence the `criteria` fixture."""

    def _ctx(self, tmp_path, cases):
        root = frozen_root(tmp_path)
        where = ordinary(root, cases)
        (root / "freeze.json").write_text(
            json.dumps(good_freeze(context(root, **where))), encoding="utf-8")
        return context(root, alarm_reader=alarms([], []), **where)

    def test_a_failing_guard_is_its_own_state(self, tmp_path, criteria):
        cases = {"c{}".format(i): case("unclear" if i < 5 else "ordinary")
                 for i in range(30)}
        ctx = self._ctx(tmp_path, cases)
        order = parse(defined_block())
        result = order_tool.evaluate(ctx, order)["extend_to_100"]
        assert result.state == order_tool.GUARD_FAILED
        assert result.stopped_by == order_tool.STOP_GUARD
        assert "q_guard" in result.evidence

    def test_a_passing_guard_lets_the_checker_answer(self, tmp_path, criteria):
        cases = {"c{}".format(i): case("unclear" if i < 4 else "ordinary")
                 for i in range(30)}
        ctx = self._ctx(tmp_path, cases)
        result = order_tool.evaluate(
            ctx, parse(defined_block()))["extend_to_100"]
        assert result.state == order_tool.NOT_DONE
        assert "30 case(s) adjudicated, 100 required" in result.evidence

    def test_the_metric_refuses_to_count_a_null_verdict(self, tmp_path):
        ctx = context(tmp_path, **ordinary(
            tmp_path, {"c0": case(), "c1": case(None)}))
        value, why = order_tool.metric_unclear_count(ctx)
        assert value is None
        assert "unfilled" in why


# --------------------------------------------------------------------------
# the alarms on the fixed member


def ruling(case_id, member="safe", verdict="real", **extra):
    return dict({"case_id": case_id, "member": member, "verdict": verdict},
                **extra)


class TestTheAlarmChecker:
    def setup_method(self):
        self.step = step_of(parse(), "classify_alarms")

    def test_a_reader_that_could_not_read_is_cannot_tell(self, tmp_path):
        ctx = context(tmp_path, alarm_reader=lambda field: {"error": "no rows"})
        assert order_tool.check_classify_alarms(ctx, self.step).state == \
            order_tool.UNKNOWN

    def test_an_empty_numerator_is_cannot_tell_not_done(self, tmp_path):
        """Nothing fired means the rows were not read, not that there is
        nothing to classify."""
        ctx = context(tmp_path, alarm_reader=alarms([], []))
        result = order_tool.check_classify_alarms(ctx, self.step)
        assert result.state == order_tool.UNKNOWN
        assert "not that there is nothing to classify" in result.evidence

    def test_rulings_without_causes_are_not_done(self, tmp_path):
        """The live defect: 20 alarms, 21 rulings, 0 `failure_mode`, reported
        complete on the strength of the rulings."""
        fired = ["c{}".format(i) for i in range(20)]
        rulings = [ruling(c) for c in fired] + [ruling("c0")]
        ctx = context(tmp_path, alarm_reader=alarms(fired, rulings))
        result = order_tool.check_classify_alarms(ctx, self.step)
        assert result.state == order_tool.NOT_DONE
        assert "20 ruled and 0 carrying a `failure_mode`" in result.evidence
        assert "a verdict does not answer what the tuning step asks" in \
            result.evidence

    def test_a_vocabulary_the_block_does_not_declare(self, tmp_path):
        """Counting distinct values off the rulings cannot establish that the
        vocabulary was fixed *in advance*.

        Codex, 2026-09-04: the old check asked for two or more distinct values
        among the rows, which is satisfied the moment somebody classifies two
        cases differently — the invented-to-fit case it existed to catch. The
        list is read from the block now, so the freeze that digests D-013 is
        what makes "fixed beforehand" checkable.
        """
        step = order_tool.Step({"id": "classify_alarms", "requires": [],
                                "needs_field": "failure_mode",
                                "needs_vocabulary_first": True,
                                "done_when": "every alarm carries a "
                                             "non-empty failure_mode"})
        fired = ["c0", "c1"]
        rulings = [ruling("c0", failure_mode="one"),
                   ruling("c1", failure_mode="another")]
        ctx = context(tmp_path, alarm_reader=alarms(fired, rulings))
        result = order_tool.check_classify_alarms(ctx, step)
        assert result.state == order_tool.NOT_DONE
        assert "declares no vocabulary" in result.evidence

    def test_a_cause_outside_the_declared_vocabulary(self, tmp_path):
        fired = ["c0", "c1"]
        rulings = [ruling("c0", failure_mode="a"),
                   ruling("c1", failure_mode="invented-on-the-spot")]
        ctx = context(tmp_path, alarm_reader=alarms(fired, rulings))
        result = order_tool.check_classify_alarms(ctx, self.step)
        assert result.state == order_tool.NOT_DONE
        assert "invented-on-the-spot" in result.evidence

    def test_an_unruled_alarm(self, tmp_path):
        fired = ["c0", "c1"]
        rulings = [ruling("c0", failure_mode="a"), ruling("c0", failure_mode="b")]
        ctx = context(tmp_path, alarm_reader=alarms(fired, rulings))
        result = order_tool.check_classify_alarms(ctx, self.step)
        assert result.state == order_tool.NOT_DONE
        assert "no ruling at all" in result.evidence

    def test_a_ruled_alarm_with_no_cause_among_others_that_have_one(self,
                                                                   tmp_path):
        fired = ["c0", "c1", "c2"]
        rulings = [ruling("c0", failure_mode="a"), ruling("c1", failure_mode="b"),
                   ruling("c2")]
        ctx = context(tmp_path, alarm_reader=alarms(fired, rulings))
        result = order_tool.check_classify_alarms(ctx, self.step)
        assert result.state == order_tool.NOT_DONE
        assert "no named cause" in result.evidence

    def test_every_alarm_with_a_cause_is_done(self, tmp_path):
        fired = ["c0", "c1"]
        rulings = [ruling("c0", failure_mode="a"), ruling("c1", failure_mode="b")]
        ctx = context(tmp_path, alarm_reader=alarms(fired, rulings))
        assert order_tool.check_classify_alarms(ctx, self.step).state == \
            order_tool.DONE

    def test_an_empty_cause_string_does_not_count(self, tmp_path):
        fired = ["c0", "c1"]
        rulings = [ruling("c0", failure_mode="a"),
                   ruling("c1", failure_mode="   ")]
        ctx = context(tmp_path, alarm_reader=alarms(fired, rulings))
        assert order_tool.check_classify_alarms(ctx, self.step).state == \
            order_tool.NOT_DONE

    def test_a_cause_on_the_unsafe_member_does_not_count_for_the_safe_one(self):
        counts = order_tool.classify_alarm_counts(
            ["c0"], [ruling("c0", member="unsafe", failure_mode="a")],
            "failure_mode")
        assert counts["unruled"] == ["c0"]

    def test_the_field_name_comes_from_the_block(self, tmp_path):
        block = BLOCK.replace("needs_field: failure_mode", "needs_field: cause")
        block = block.replace(
            "done_when: every alarm carries a non-empty failure_mode",
            "done_when: undefined")
        step = step_of(parse(block), "classify_alarms")
        ctx = context(tmp_path, alarm_reader=alarms(
            ["c0", "c1"], [ruling("c0", cause="a"), ruling("c1", cause="b")],
            field="cause"))
        assert order_tool.check_classify_alarms(ctx, step).state == \
            order_tool.DONE

    def test_a_step_with_no_needs_field_is_cannot_tell(self, tmp_path):
        block = BLOCK.replace("    needs_field: failure_mode\n", "")
        step = step_of(parse(block), "classify_alarms")
        ctx = context(tmp_path, alarm_reader=alarms(["c0"], []))
        result = order_tool.check_classify_alarms(ctx, step)
        assert result.state == order_tool.UNKNOWN
        assert "needs_field" in result.evidence

    def test_it_reports_the_live_repository_as_not_done(self):
        """No injection: the shipped adjudications, the shipped rows."""
        ctx = order_tool.Context(root=ROOT)
        result = order_tool.check_classify_alarms(
            ctx, step_of(order_tool.parse_order(
                (ROOT / "DECISIONS.md").read_text(encoding="utf-8")),
                "classify_alarms"))
        assert result.state == order_tool.NOT_DONE
        assert "20 ruled and 0 carrying a `failure_mode`" in result.evidence
        assert "a verdict does not answer what the tuning step asks" in \
            result.evidence


# --------------------------------------------------------------------------
# tune, the gate, and the states the framework computes


class TestTuneAndTheGate:
    def test_tune_reports_mutation_of_the_frozen_closure(self, tmp_path):
        root = frozen_root(tmp_path)
        (root / "freeze.json").write_text(
            json.dumps(good_freeze(context(root))), encoding="utf-8")
        (root / "prompts" / "verifier.md").write_text("edited\n",
                                                      encoding="utf-8")
        result = order_tool.check_tune(context(root), step_of(parse(), "tune"))
        assert result.state == order_tool.NOT_DONE
        assert "no tuning whatsoever" in result.evidence

    def test_tune_without_a_freeze_is_manual_required(self, tmp_path):
        result = order_tool.check_tune(context(tmp_path),
                                       step_of(parse(), "tune"))
        assert result.state == order_tool.MANUAL
        assert "close to the boundary" in result.evidence

    def test_the_sonnet_gate_has_no_artifact_and_says_so(self, tmp_path):
        result = order_tool.check_sonnet_gate(context(tmp_path),
                                              step_of(parse(), "sonnet_gate"))
        assert result.state == order_tool.UNKNOWN
        assert "no artifact records it" in result.evidence

    def test_undefined_predicates_and_next_generation_forbid_done(
            self, tmp_path, monkeypatch, criteria):
        """A checker saying `done` for a step carrying either is overruled."""
        order = parse(defined_block())
        monkeypatch.setitem(
            order_tool.CHECKERS, "tune",
            lambda c, s: order_tool.Result(order_tool.DONE, "somebody tuned"))
        results = {name: order_tool.Result(order_tool.DONE, "")
                   for name in ("freeze", "adjudicate_30", "extend_to_100",
                                "classify_alarms")}
        result = order_tool.state_of(context(tmp_path), order,
                                     step_of(order, "tune"), results)
        assert result.state == order_tool.MANUAL
        assert "never done" in result.evidence
        assert "next_generation" in result.evidence

    def test_a_step_blocked_on_an_open_question(self, tmp_path, criteria):
        block = defined_block().replace(
            "  - id: sonnet_gate\n",
            "  - id: sonnet_gate\n    blocked_on_owner: q_guard\n")
        order = parse(block)
        ctx = context(tmp_path, alarm_reader=alarms([], []))
        result = order_tool.state_of(ctx, order, step_of(order, "sonnet_gate"),
                                     order_tool.evaluate(ctx, parse(block)))
        assert result.state == order_tool.BLOCKED_OWNER
        assert result.stopped_by == order_tool.STOP_OPEN_QUESTION
        assert "q_guard" in result.evidence

    def test_a_step_pointing_at_an_answered_question_is_not_blocked(
            self, tmp_path, criteria):
        block = defined_block().replace(
            "  - id: sonnet_gate\n",
            "  - id: sonnet_gate\n    blocked_on_owner: q_fork\n")
        order = parse(block)
        ctx = context(tmp_path, alarm_reader=alarms([], []))
        result = order_tool.evaluate(ctx, order)["sonnet_gate"]
        assert result.state != order_tool.BLOCKED_OWNER


class TestWaitingIsItsOwnAnswer:
    def test_a_step_waiting_on_a_prerequisite(self, tmp_path, criteria):
        ctx = context(frozen_root(tmp_path), alarm_reader=alarms([], []))
        result = order_tool.evaluate(ctx, parse(defined_block()))["adjudicate_30"]
        assert result.state == order_tool.WAITING
        assert result.stopped_by == order_tool.STOP_PREREQUISITE
        assert "freeze" in result.evidence

    def test_the_stops_are_never_the_same_string(self, tmp_path, criteria):
        cases = {"c{}".format(i): case("unclear") for i in range(30)}
        root = frozen_root(tmp_path)
        where = ordinary(root, cases)
        (root / "freeze.json").write_text(
            json.dumps(good_freeze(context(root, **where))), encoding="utf-8")
        block = defined_block().replace(
            "  - id: sonnet_gate\n",
            "  - id: sonnet_gate\n    blocked_on_owner: q_guard\n")
        ctx = context(root, alarm_reader=alarms([], []), **where)
        results = order_tool.evaluate(ctx, parse(block))
        assert results["extend_to_100"].stopped_by == order_tool.STOP_GUARD
        assert results["sonnet_gate"].stopped_by == \
            order_tool.STOP_OPEN_QUESTION
        assert results["adjudicate_30"].stopped_by is None

    def test_a_step_done_out_of_order_is_a_violation(self):
        order = parse()
        results = {
            "freeze": order_tool.Result(order_tool.NOT_DONE, "absent"),
            "adjudicate_30": order_tool.Result(order_tool.DONE, "30 ruled"),
            "extend_to_100": order_tool.Result(order_tool.WAITING, ""),
            "classify_alarms": order_tool.Result(order_tool.DONE, ""),
            "tune": order_tool.Result(order_tool.MANUAL, ""),
            "sonnet_gate": order_tool.Result(order_tool.UNKNOWN, ""),
        }
        assert order_tool.violations(order, results) == [
            "adjudicate_30 is done while freeze is not done"]


# --------------------------------------------------------------------------
# the decision an action gets


class TestDeciding:
    def _results(self, **states):
        body = {name: order_tool.Result(state, "because")
                for name, state in states.items()}
        body.setdefault(order_tool.GENERATIONS,
                        order_tool.Result(order_tool.DONE, "ledger fine"))
        return body

    def test_every_prerequisite_done_permits(self):
        results = self._results(
            freeze=order_tool.DONE, adjudicate_30=order_tool.DONE,
            extend_to_100=order_tool.DONE, classify_alarms=order_tool.DONE,
            tune=order_tool.MANUAL, sonnet_gate=order_tool.UNKNOWN)
        code, _reasons = order_tool.decide(parse(), results, "extend_to_100")
        assert code == 0

    def test_a_missing_prerequisite_prohibits(self):
        results = self._results(
            freeze=order_tool.NOT_DONE, adjudicate_30=order_tool.WAITING,
            extend_to_100=order_tool.WAITING, classify_alarms=order_tool.NOT_DONE,
            tune=order_tool.MANUAL, sonnet_gate=order_tool.UNKNOWN)
        code, reasons = order_tool.decide(parse(), results, "adjudicate_30")
        assert code == 1
        assert any("freeze is not done" in line for line in reasons)

    def test_an_unestablished_prerequisite_is_exit_two(self):
        results = self._results(
            freeze=order_tool.UNKNOWN, adjudicate_30=order_tool.WAITING,
            extend_to_100=order_tool.WAITING, classify_alarms=order_tool.DONE,
            tune=order_tool.MANUAL, sonnet_gate=order_tool.UNKNOWN)
        code, _reasons = order_tool.decide(parse(), results, "adjudicate_30")
        assert code == 2

    def test_an_undefined_criterion_prerequisite_is_exit_two_not_one(self):
        """The third answer, kept out of the not-done bucket."""
        results = self._results(
            freeze=order_tool.UNDEFINED_CRITERION,
            adjudicate_30=order_tool.UNDEFINED_CRITERION,
            extend_to_100=order_tool.UNDEFINED_CRITERION,
            classify_alarms=order_tool.NOT_DONE,
            tune=order_tool.UNDEFINED_CRITERION,
            sonnet_gate=order_tool.UNDEFINED_CRITERION)
        code, _reasons = order_tool.decide(parse(), results, "adjudicate_30")
        assert code == 2

    def test_a_blocked_step_is_prohibited_even_with_prerequisites_done(self):
        results = self._results(
            freeze=order_tool.DONE, adjudicate_30=order_tool.DONE,
            extend_to_100=order_tool.DONE, classify_alarms=order_tool.DONE,
            tune=order_tool.BLOCKED_OWNER, sonnet_gate=order_tool.UNKNOWN)
        code, reasons = order_tool.decide(parse(), results, "tune")
        assert code == 1
        assert any("tune is blocked_on_owner" in line for line in reasons)

    def test_a_failed_guard_prohibits_the_step_it_guards(self):
        results = self._results(
            freeze=order_tool.DONE, adjudicate_30=order_tool.DONE,
            extend_to_100=order_tool.GUARD_FAILED,
            classify_alarms=order_tool.DONE, tune=order_tool.MANUAL,
            sonnet_gate=order_tool.UNKNOWN)
        code, _reasons = order_tool.decide(parse(), results, "extend_to_100")
        assert code == 1

    def test_spend_is_denied_without_a_freeze(self):
        results = self._results(
            freeze=order_tool.NOT_DONE, adjudicate_30=order_tool.WAITING,
            extend_to_100=order_tool.WAITING, classify_alarms=order_tool.NOT_DONE,
            tune=order_tool.MANUAL, sonnet_gate=order_tool.UNKNOWN)
        code, reasons = order_tool.decide(parse(), results, "spend")
        assert code == 1
        assert any("freeze" in line for line in reasons)

    def test_spend_is_denied_while_generations_cannot_be_enforced(self):
        """`adjudicate_30` done, so the ledger is the *only* thing missing.

        It was `not done` here, which made the answer exit 1 — a definite
        prohibition — for a reason this test was not about. The test then
        passed on the old gate only because that gate ignored `adjudicate_30`
        entirely: an assertion resting on the defect beside the one it names.
        """
        results = self._results(
            freeze=order_tool.DONE, adjudicate_30=order_tool.DONE,
            extend_to_100=order_tool.NOT_DONE,
            classify_alarms=order_tool.NOT_DONE,
            tune=order_tool.MANUAL, sonnet_gate=order_tool.UNKNOWN)
        results[order_tool.GENERATIONS] = order_tool.Result(
            order_tool.UNKNOWN, "declared and not enforceable")
        code, reasons = order_tool.decide(parse(), results, "spend")
        assert code == 2
        assert any(order_tool.GENERATIONS in line for line in reasons)

    def test_spend_is_refused_while_the_thirty_are_not_adjudicated(self):
        """The defect this pins: `spend` asked only for the freeze.

        Codex, 2026-09-04. `EXTRA_ACTIONS["spend"]` named `freeze` and the
        generations ledger and nothing else, so the first paid run was
        permitted the moment a freeze existed — while step 2, which D-013
        requires to happen "without a single model call", was still not done.
        The test that stood here asserted exactly that, so the gate was wrong
        and pinned wrong together; it is replaced rather than adjusted.
        """
        results = self._results(
            freeze=order_tool.DONE, adjudicate_30=order_tool.NOT_DONE,
            extend_to_100=order_tool.WAITING, classify_alarms=order_tool.NOT_DONE,
            tune=order_tool.MANUAL, sonnet_gate=order_tool.UNKNOWN)
        results[order_tool.GENERATIONS] = order_tool.Result(
            order_tool.DONE, "a ledger exists")
        code, reasons = order_tool.decide(parse(), results, "spend")
        assert code == 1
        assert any("adjudicate_30" in line for line in reasons)

    def test_spend_is_refused_when_the_guard_on_the_hundred_failed(self):
        """`extend_to_100` cannot be *done* before the run it gates, so its
        completion is not required — but its guard is the decision's condition
        for running the hundred at all, and a failed guard must stop the
        spending rather than be stepped over."""
        results = self._results(
            freeze=order_tool.DONE, adjudicate_30=order_tool.DONE,
            extend_to_100=order_tool.GUARD_FAILED,
            classify_alarms=order_tool.NOT_DONE,
            tune=order_tool.MANUAL, sonnet_gate=order_tool.UNKNOWN)
        results[order_tool.GENERATIONS] = order_tool.Result(
            order_tool.DONE, "a ledger exists")
        code, reasons = order_tool.decide(parse(), results, "spend")
        assert code == 1
        assert any("extend_to_100" in line for line in reasons)

    def test_spend_is_permitted_once_the_thirty_and_the_ledger_hold(self):
        results = self._results(
            freeze=order_tool.DONE, adjudicate_30=order_tool.DONE,
            extend_to_100=order_tool.NOT_DONE,
            classify_alarms=order_tool.NOT_DONE,
            tune=order_tool.MANUAL, sonnet_gate=order_tool.UNKNOWN)
        results[order_tool.GENERATIONS] = order_tool.Result(
            order_tool.DONE, "a ledger exists")
        code, _reasons = order_tool.decide(parse(), results, "spend")
        assert code == 0

    def test_doing_a_step_that_is_not_done_is_exactly_what_is_permitted(self):
        """Refusing `check classify_alarms` because classify_alarms is not
        done, and then printing "do this instead: classify_alarms", is the tool
        arguing with itself. What forbids the doing is a stop, not a state."""
        results = self._results(
            freeze=order_tool.DONE, adjudicate_30=order_tool.DONE,
            extend_to_100=order_tool.WAITING,
            classify_alarms=order_tool.NOT_DONE, tune=order_tool.MANUAL,
            sonnet_gate=order_tool.UNKNOWN)
        code, _reasons = order_tool.decide(parse(), results, "classify_alarms")
        assert code == 0

    def test_an_unknown_action_is_exit_two_and_lists_the_known_ones(self):
        order = parse()
        results = self._results(**{s.id: order_tool.DONE for s in order.steps})
        code, reasons = order_tool.decide(order, results, "go")
        assert code == 2
        assert "spend" in reasons[0]


# --------------------------------------------------------------------------
# the command line, end to end


class TestTheCommandLine:
    def _argv(self, root: Path, *rest: str):
        return ["--root", str(root), "--decisions", str(root / "DECISIONS.md"),
                "--freeze-file", str(root / "freeze.json"),
                "--generations", str(root / "generations.json"), *rest]

    def test_status_prints_every_step_and_both_question_lists(self, tmp_path,
                                                              capsys):
        root = frozen_root(tmp_path)
        write_decisions(root)
        order_tool.main(self._argv(root, "status"))
        out = capsys.readouterr().out
        for name in ("freeze", "adjudicate_30", "extend_to_100",
                     "classify_alarms", "tune", "sonnet_gate", "generations"):
            assert name in out
        assert "Open questions" in out
        assert "Answered:" in out

    def test_a_block_with_a_step_the_tool_cannot_check_exits_two(self, tmp_path,
                                                                 capsys):
        root = frozen_root(tmp_path)
        write_decisions(root, BLOCK + "  - id: publish\n    requires: []\n"
                                      "    done_when: undefined\n")
        code = order_tool.main(self._argv(root, "status"))
        assert code == 2
        assert "no checker" in capsys.readouterr().err

    def test_json_carries_the_state_the_stop_and_the_criterion(self, tmp_path,
                                                               capsys):
        root = frozen_root(tmp_path)
        write_decisions(root)
        order_tool.main(self._argv(root, "--json", "status"))
        body = json.loads(capsys.readouterr().out)
        by_id = {s["id"]: s for s in body["steps"]}
        assert by_id["freeze"]["state"] == order_tool.UNDEFINED_CRITERION
        assert by_id["freeze"]["done_when"] == "undefined"
        assert by_id["classify_alarms"]["done_when"].startswith("every alarm")
        assert {q["id"] for q in body["open_questions"]} == {"q_guard"}
        assert {a["id"] for a in body["answered_questions"]} == {"q_fork"}
        assert body["generations"]["state"] == order_tool.UNKNOWN
        assert "freeze" in body["undetermined"]

    def test_a_refusal_in_json_still_carries_exit_two(self, tmp_path, capsys):
        root = frozen_root(tmp_path)
        write_decisions(root, "# d013-order\nsteps: []\n")
        code = order_tool.main(self._argv(root, "--json", "status"))
        assert code == 2
        assert json.loads(capsys.readouterr().out)["exit"] == 2

    def test_check_spend_denies_today(self, tmp_path, capsys):
        root = frozen_root(tmp_path)
        write_decisions(root)
        code = order_tool.main(self._argv(root, "check", "spend"))
        assert code == 2
        assert "NOT ESTABLISHED" in capsys.readouterr().out

    def test_the_real_repository_answers_without_crashing(self, capsys):
        """The chain: the shipped DECISIONS.md and the shipped artifacts.

        `code in (0, 1, 2)` was the whole assertion, and those are every code
        the tool can return — a test that passes on any answer, including one
        produced by a crash caught and turned into an exit. Codex, 2026-09-04.
        Pinned to what is true of this repository today: nothing is frozen, so
        `status` cannot establish where we are, and the first two steps it can
        name are the two that wait for nothing.
        """
        code = order_tool.main(["status"])
        out = capsys.readouterr().out
        assert code == 2, out
        assert "D-013" in out
        assert "Next: freeze, classify_alarms" in out

    def test_the_real_repository_denies_spending_today(self, capsys):
        code = order_tool.main(["check", "spend"])
        capsys.readouterr()
        assert code != 0
