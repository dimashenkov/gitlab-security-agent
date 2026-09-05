"""The inputs of a step are a different question from what records it done.

`tools/d013_order.py` answered only the second. `state_of` returns at
`step.criterion_undefined` before any checker runs, so for `tune` and
`sonnet_gate` — the two steps whose `done_when` is `undefined` — every checker
below that line was unreachable. Measured on 2026-09-05 against the real
`DECISIONS.md`: neither checker's message appeared anywhere in `evaluate()`.

That mattered because `check_tune` is not only words. It calls
`_frozen_closure_mutated`, the one file-backed diagnostic the step has: whether
the frozen configuration has drifted since the freeze, which is the trace
tuning leaves. It was dead code with a green test over it — the test called the
checker directly, which production never does.

Three defects came out of making it reachable, and each has a case here:

* `_frozen_closure_mutated` returned `Optional[str]`, and **three** different
  absences returned `None`: no freeze file, a freeze that would not parse, and
  a body that is not an object. The caller rendered every `None` as "the frozen
  closure shows no mutation", so an unreadable `freeze.json` asserted that
  nothing had drifted.
* The drift filter kept two sentences, `changed since the freeze` and
  `D-013 has changed`. A freeze whose recorded inputs have since been deleted
  produces `frozen and now unreadable`, which matches neither — so a freeze
  pointing at files that no longer exist reported that every digest still
  matched. A freeze with no `inputs` block at all reported the same, about no
  digests.
* The message claimed "no mutation **after a result**". Nothing in that
  function reads a result.

Everything here goes through `evaluate()` rather than calling a preflight or a
checker, because calling one directly is exactly the mistake that let the dead
code stand.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import d013_order as order_tool  # noqa: E402

from test_d013_order import BLOCK, context, decisions_text, parse  # noqa: E402

# Every field the comparison reads out of a reference's environment. A
# reference recording an environment object without them used to pass
# validation, and the loop that holds a challenger to the environment skipped
# each field the reference had left out — so the fixtures say all four.
ENVIRONMENT = {"system_prompt": "aaa", "verifier_prompt": "bbb",
               "findings_schema": "ccc", "agent_version": "0.1.0"}


def evidence_for(ctx, step_id, block=BLOCK):
    """The rendered answer for one step, from the whole evaluation.

    Deliberately not `preflight_of` and not `CHECKERS[...]`. A test that calls
    either proves a helper; the defect this file exists for is production
    returning before the helper is ever called.
    """
    order = parse(block)
    return order_tool.evaluate(ctx, order)[step_id]


def freeze_body(ctx, **over):
    """A freeze record that `_freeze_problems` finds nothing wrong with.

    Built by satisfying every requirement rather than by trimming until the
    tool stops complaining — the first version omitted `derived.reviewer` and
    `configuration`, and the intact case failed. That failure is the new rule
    working: under the old two-sentence filter this same incomplete record
    would have been reported as a closure whose digests all still matched.
    """
    reviewer = ctx.root / "src" / "security_agent"
    reviewer.mkdir(parents=True, exist_ok=True)
    (reviewer / "cli.py").write_text("frozen reviewer\n", encoding="utf-8")

    now_config, config_error = order_tool.resolved_configuration(ctx.root)
    assert config_error is None, config_error

    section = ctx.d013_section()
    body = {
        # Codex, 2026-09-05: the first version of this fixture had no
        # `schema`, and the intact tests passed anyway — which is how the
        # missing schema check in `_frozen_closure_mutated` was found. A
        # fixture that omits what the code should demand hides the omission.
        "schema": order_tool.FREEZE_SCHEMA,
        "created_at": "2026-09-05T00:00:00+00:00",
        "owner_acknowledgement": "the owner, 2026-09-05",
        "git": {"commit": "0" * 40, "dirty": False},
        "d013": {"text": section, "digest": order_tool.sha256_text(section)},
        "inputs": {},
        "configuration": dict(now_config),
    }
    for name, _ in order_tool.FROZEN_INPUTS:
        target = ctx.root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("frozen body of {}\n".format(name), encoding="utf-8")
        body["inputs"][name] = {"digest": order_tool.sha256_file(target)}
    # After the loop, not before: `src/security_agent/gate.py` is one of
    # FROZEN_INPUTS and lands in the directory this digest covers. Computing it
    # first gave a record that reported the reviewer's source as changed.
    body["derived"] = {"reviewer": order_tool.tree_digest(reviewer, "*.py")}
    body.update(over)
    return body


def write_freeze(ctx, body):
    ctx.freeze.write_text(json.dumps(body), encoding="utf-8")


class TestThePreflightIsReached:
    """The defect itself: production returned before consulting anything."""

    def test_drift_reaches_the_report_through_evaluate(self, tmp_path):
        ctx = context(tmp_path)
        body = freeze_body(ctx)
        name = order_tool.FROZEN_INPUTS[0][0]
        (ctx.root / name).write_text("edited after the freeze\n",
                                     encoding="utf-8")
        write_freeze(ctx, body)

        result = evidence_for(ctx, "tune")
        assert "changed since the freeze" in result.evidence, (
            "the drift the freeze records was computed and never printed — "
            "which is the state this file was written against")
        assert name in result.evidence

    def test_an_intact_closure_also_reaches_the_report(self, tmp_path):
        """The other half of the same fixture pair.

        Without it a preflight that always says `blocked` would pass the test
        above, and the report would be right by accident.
        """
        ctx = context(tmp_path)
        write_freeze(ctx, freeze_body(ctx))
        result = evidence_for(ctx, "tune")
        assert "still matches what is on disk" in result.evidence
        assert "changed since the freeze" not in result.evidence

    def test_the_state_is_still_undefined_criterion(self, tmp_path):
        """A preflight can describe inputs and can never make a step done."""
        ctx = context(tmp_path)
        write_freeze(ctx, freeze_body(ctx))
        result = evidence_for(ctx, "tune")
        assert result.state == order_tool.UNDEFINED_CRITERION
        assert "inputs established" in result.evidence
        assert "completion criterion remains undefined" in result.evidence
        assert "ready" not in result.evidence

    def test_an_established_preflight_does_not_satisfy_a_requires(self, tmp_path):
        """`tune` requires nothing of anybody, but the rule is general: a step
        whose inputs are established is still not `done`, so anything waiting
        on it keeps waiting."""
        ctx = context(tmp_path)
        write_freeze(ctx, freeze_body(ctx))
        results = order_tool.evaluate(ctx, parse())
        assert results["tune"].state != order_tool.DONE


class TestAbsenceIsNotAgreement:
    """Four freeze records that establish nothing, and used to say `intact`."""

    def test_an_unreadable_freeze_is_not_an_intact_one(self, tmp_path):
        ctx = context(tmp_path)
        ctx.freeze.write_text("{ this is not json", encoding="utf-8")
        result = evidence_for(ctx, "tune")
        assert "could not be read" in result.evidence
        assert "not evidence that the closure is intact" in result.evidence
        assert "still matches" not in result.evidence

    def test_a_freeze_that_is_not_an_object(self, tmp_path):
        ctx = context(tmp_path)
        ctx.freeze.write_text("[1, 2, 3]", encoding="utf-8")
        result = evidence_for(ctx, "tune")
        assert "where an object is required" in result.evidence
        assert "still matches" not in result.evidence

    def test_frozen_inputs_that_have_since_been_deleted(self, tmp_path):
        """The one the two-sentence filter let through.

        `frozen and now unreadable` is neither `changed since the freeze` nor
        `D-013 has changed`, so a freeze naming files that no longer exist
        reported that every digest still matched.
        """
        ctx = context(tmp_path)
        body = freeze_body(ctx)
        # One file, and one that is not under `src/security_agent`: deleting
        # anything there moves the reviewer's tree digest and produces
        # "changed since the freeze", which is drift and a different answer.
        # The case being pinned is a frozen input that is simply gone.
        gone = next(name for name, _ in order_tool.FROZEN_INPUTS
                    if not name.startswith("src/security_agent/"))
        (ctx.root / gone).unlink()
        write_freeze(ctx, body)

        result = evidence_for(ctx, "tune")
        assert "frozen and now unreadable" in result.evidence
        assert "does not support a comparison" in result.evidence
        assert "still matches" not in result.evidence

    def test_a_freeze_with_no_inputs_recorded(self, tmp_path):
        ctx = context(tmp_path)
        body = freeze_body(ctx)
        body["inputs"] = {}
        write_freeze(ctx, body)
        result = evidence_for(ctx, "tune")
        assert "does not support a comparison" in result.evidence
        assert "still matches" not in result.evidence

    def test_a_freeze_with_no_schema_declared(self, tmp_path):
        """`check_freeze` refuses an artifact whose schema it does not read.
        This function called `_freeze_problems` directly and skipped that, so a
        record the authoritative checker rejects outright was read field by
        field and reported as an intact closure."""
        ctx = context(tmp_path)
        body = freeze_body(ctx)
        del body["schema"]
        write_freeze(ctx, body)
        result = evidence_for(ctx, "tune")
        assert "declares schema None" in result.evidence
        assert "not interpreted at all" in result.evidence
        assert "still matches" not in result.evidence

    def test_a_freeze_declaring_a_schema_this_tool_does_not_read(self, tmp_path):
        ctx = context(tmp_path)
        write_freeze(ctx, freeze_body(ctx, schema="d013-freeze/99"))
        result = evidence_for(ctx, "tune")
        assert "d013-freeze/99" in result.evidence
        assert "still matches" not in result.evidence

    def test_an_invalid_record_that_also_shows_drift_is_not_drift(self, tmp_path):
        """Codex, 2026-09-05, second gate pass on this change.

        The drift branch ran first, so a record missing its
        `owner_acknowledgement` and carrying one mismatched digest was reported
        as a mutated closure. That asserts something moved away from a freeze —
        from a file that was never a freeze, so there is nothing to have moved
        away from. Validity is asked first now.
        """
        ctx = context(tmp_path)
        body = freeze_body(ctx)
        del body["owner_acknowledgement"]
        name = order_tool.FROZEN_INPUTS[0][0]
        (ctx.root / name).write_text("edited after the freeze\n",
                                     encoding="utf-8")
        write_freeze(ctx, body)

        result = evidence_for(ctx, "tune")
        assert "does not support a comparison" in result.evidence
        assert "a freeze nobody signed" in result.evidence
        assert "cannot be read as drift" in result.evidence
        assert "has been mutated since" not in result.evidence
        assert order_tool.PRE_BLOCKED not in result.evidence

    def test_no_freeze_at_all_is_cannot_tell(self, tmp_path):
        ctx = context(tmp_path)
        assert not ctx.freeze.exists()
        result = evidence_for(ctx, "tune")
        assert order_tool.PRE_CANNOT_TELL in result.evidence
        assert "no closure to compare against" in result.evidence
        assert "still matches" not in result.evidence


class TestTheClaimIsNotWiderThanTheEvidence:
    def test_intact_does_not_claim_a_result_was_measured(self, tmp_path):
        """The wording said "no mutation after a result". Nothing here reads
        a result, and the sentence is the whole finding."""
        ctx = context(tmp_path)
        write_freeze(ctx, freeze_body(ctx))
        result = evidence_for(ctx, "tune")
        assert "after a result" not in result.evidence
        assert "nothing here reads a result" in result.evidence


class TestNeitherTypeHasATruthValue:
    """Both are three-or-four-way answers, and this repository has measured
    what happens when such a thing is readable as a boolean: three of the four
    spellings fail closed and the one that proceeds is `is False`, which is
    what somebody writes when trying to be careful."""

    def test_closure_state(self, tmp_path):
        state = order_tool.ClosureState(order_tool.CLOSURE_UNREADABLE, "why")
        with pytest.raises(TypeError, match="not a boolean"):
            bool(state)

    def test_preflight(self):
        pre = order_tool.Preflight(order_tool.PRE_CANNOT_TELL, "why")
        with pytest.raises(TypeError, match="not a boolean"):
            bool(pre)

    def test_an_unknown_preflight_state_is_refused_where_it_is_written(self):
        with pytest.raises(ValueError, match="unknown preflight state"):
            order_tool.Preflight("probably fine", "why")


class TestThePreflightIsTotal:
    def test_every_step_gets_one_of_the_four_states(self, tmp_path):
        ctx = context(tmp_path)
        for step in parse().steps:
            answer = order_tool.preflight_of(ctx, step)
            assert answer.state in order_tool.PRE_STATES
            assert answer.why.strip()

    def test_a_step_with_no_entry_says_so_rather_than_returning_nothing(
            self, tmp_path):
        ctx = context(tmp_path)
        answer = order_tool.preflight_of(ctx, parse().steps[0])
        assert answer.state == order_tool.PRE_NOT_APPLICABLE
        assert "no preflight is declared" in answer.why

    def test_a_raising_preflight_is_cannot_tell_not_established(
            self, tmp_path, monkeypatch):
        def explode(ctx, step):
            raise RuntimeError("the artifact moved")

        monkeypatch.setitem(order_tool.PREFLIGHT, "tune", explode)
        ctx = context(tmp_path)
        answer = order_tool.preflight_of(ctx, next(
            s for s in parse().steps if s.id == "tune"))
        assert answer.state == order_tool.PRE_CANNOT_TELL
        assert "the artifact moved" in answer.why


class TestTheSonnetGateBaseline:
    """The other half, and the one D-013's prose got wrong.

    The document said the step has `done_when: undefined` because
    `sentinel_compare.py` stores nothing. Measured: the comparator refuses the
    committed reference before it looks at a single run, because the reference
    is retired — its rows carry no `models_verified`. Storage is the second
    obstacle; a reader acting on it first would add a flag and be no closer.
    """

    def sonnet_block(self, path):
        return BLOCK.replace(
            "  - id: sonnet_gate\n",
            "  - id: sonnet_gate\n    reference: {}\n".format(path))

    def test_a_retired_reference_is_blocked_and_names_the_reason(self, tmp_path):
        ctx = context(tmp_path)
        ref = tmp_path / "ref.json"
        ref.write_text(json.dumps({
            "cases": {}, "comparable": [], "threshold": {},
            "retired": {"why": "no row carries models_verified"},
        }), encoding="utf-8")

        result = evidence_for(ctx, "sonnet_gate", self.sonnet_block("ref.json"))
        assert order_tool.PRE_BLOCKED in result.evidence
        assert "no row carries models_verified" in result.evidence

    def test_the_real_committed_reference_is_reported_retired(self):
        """Against the repository's own artifact, not a fixture. This is the
        fact that makes the ~$40 Sonnet run impossible today, and it was
        invisible in `status` until the preflight existed."""
        ctx = order_tool.Context(root=ROOT)
        order = order_tool.parse_order(
            ctx.decisions.read_text(encoding="utf-8"))
        result = order_tool.evaluate(ctx, order)["sonnet_gate"]
        assert "retired and is not a baseline" in result.evidence
        assert "No arrangement passes" in result.evidence

    def test_a_step_naming_no_reference_is_cannot_tell(self, tmp_path):
        ctx = context(tmp_path)
        result = evidence_for(ctx, "sonnet_gate")  # BLOCK names none
        assert order_tool.PRE_CANNOT_TELL in result.evidence
        assert "names no `reference`" in result.evidence
        assert order_tool.PRE_ESTABLISHED not in result.evidence

    def test_a_missing_reference_file_is_cannot_tell_not_blocked(self, tmp_path):
        """"The baseline is retired" and "I could not open the baseline" are
        different answers, and only the first is a finding about the gate."""
        ctx = context(tmp_path)
        result = evidence_for(ctx, "sonnet_gate",
                              self.sonnet_block("nowhere.json"))
        assert order_tool.PRE_CANNOT_TELL in result.evidence
        assert "could not be read" in result.evidence

    def test_a_symlink_out_of_the_tree_is_refused_at_the_read(self, tmp_path):
        """Codex, 2026-09-05, seventh gate pass.

        The parser refuses `..` and absolute paths, which is a check on the
        text. A path with neither still leaves the tree through a symlink
        inside it, and the preflight then reads a file nothing in the
        repository records. Checked where the file is opened, because a
        lexical check made earlier says nothing about what the filesystem does
        at the moment of the read.
        """
        outside = tmp_path.parent / "outside-the-tree"
        outside.mkdir(exist_ok=True)
        (outside / "ref.json").write_text(
            json.dumps({"cases": {}, "comparable": [],
                        "threshold": {"rule_version": 2, "reject_at_net": 1,
                                      "confirmations_required": 2}}),
            encoding="utf-8")

        ctx = context(tmp_path)
        link = ctx.root / "measurements"
        link.symlink_to(outside, target_is_directory=True)

        result = evidence_for(ctx, "sonnet_gate",
                              self.sonnet_block("measurements/ref.json"))
        assert order_tool.PRE_CANNOT_TELL in result.evidence
        assert "outside" in result.evidence
        assert "without containing '..'" in result.evidence

    def test_an_unusable_reference_is_blocked_with_the_comparator_s_words(
            self, tmp_path):
        """The order tool does not restate the comparator's rules. It asks it,
        so the two cannot drift — and a rule the comparator adds later reaches
        this report without an edit here."""
        ctx = context(tmp_path)
        ref = tmp_path / "ref.json"
        ref.write_text(json.dumps({
            "cases": {}, "comparable": [],
            "threshold": {"rule_version": 1, "reject_at_net": 2,
                          "confirmations_required": 2},
        }), encoding="utf-8")
        result = evidence_for(ctx, "sonnet_gate", self.sonnet_block("ref.json"))
        assert order_tool.PRE_BLOCKED in result.evidence
        assert "rule version 1" in result.evidence

    def test_established_never_says_ready_and_names_what_is_still_missing(
            self, tmp_path):
        """A usable baseline says a comparison could be attempted. It does not
        say one was run, and it does not say anything would record it — which
        is the storage point D-013 named, kept as the second obstacle."""
        import sentinel_compare

        ctx = context(tmp_path)
        ref = tmp_path / "ref.json"
        ref.write_text("{}", encoding="utf-8")

        def usable(path):
            return sentinel_compare.ReferenceState(
                sentinel_compare.REF_USABLE,
                "the baseline at {} describes a comparison".format(path),
                path, {"threshold": {}}, "d" * 64)

        original = sentinel_compare.validate_reference
        sentinel_compare.validate_reference = usable
        try:
            result = evidence_for(ctx, "sonnet_gate",
                                  self.sonnet_block("ref.json"))
        finally:
            sentinel_compare.validate_reference = original

        assert "inputs established" in result.evidence
        assert "not that one was run" in result.evidence
        assert "not that anything would record it" in result.evidence
        assert "ready" not in result.evidence
        assert result.state == order_tool.UNDEFINED_CRITERION


class TestTheReferenceFieldIsCheckedWhereItIsWritten:
    """Codex, 2026-09-05, sixth gate pass.

    The new field went into `Step` past every rule `_check_rest` exists for.
    `reference: false` was accepted and then reported downstream as "the
    decision names no reference" — the *absent* case wearing the clothes of a
    written one, so an author who declared a baseline and mistyped it would be
    told none had been declared.
    """

    def block_with(self, value):
        return BLOCK.replace(
            "  - id: sonnet_gate\n",
            "  - id: sonnet_gate\n    reference: {}\n".format(value))

    @pytest.mark.parametrize("value", ["false", "0", "[]", "{}", "''"])
    def test_a_reference_that_is_not_a_path_is_refused_at_parse_time(
            self, value):
        with pytest.raises(order_tool.OrderError) as caught:
            order_tool.parse_order(
                decisions_text(self.block_with(value)))
        assert "must be a path" in str(caught.value)
        assert "as though no baseline had been named" in str(caught.value)

    @pytest.mark.parametrize("value", [
        "/etc/passwd",
        "../outside/ref.json",
        "measurements/../../ref.json",
    ])
    def test_a_reference_outside_the_repository_is_refused(self, value):
        with pytest.raises(order_tool.OrderError) as caught:
            order_tool.parse_order(
                decisions_text(self.block_with(value)))
        assert "must be relative to the repository" in str(caught.value)

    def test_the_stored_value_is_the_one_that_was_validated(self):
        """Codex, 2026-09-05, ninth gate pass: `_check_rest` judged the
        stripped text and `Step` kept the original, so a value with surrounding
        whitespace passed the containment rules and then addressed a different
        pathname."""
        order = order_tool.parse_order(decisions_text(
            self.block_with('"  measurements/reference/x.json  "')))
        step = next(s for s in order.steps if s.id == "sonnet_gate")
        assert step.reference == "measurements/reference/x.json"

    def test_the_real_document_declares_a_usable_one(self):
        text = (ROOT / "DECISIONS.md").read_text(encoding="utf-8")
        step = next(s for s in order_tool.parse_order(text).steps
                    if s.id == "sonnet_gate")
        assert step.reference == "measurements/reference/sentinel-opus.json"
        assert (ROOT / step.reference).is_file()


class TestValidateReferenceIsTotal:
    """Codex, 2026-09-05, fourth gate pass. `validate_reference` promises its
    callers that a bad reference is reported and not raised, and the promise
    held only for files that happened to carry the keys it indexed."""

    def state_of(self, tmp_path, body):
        import sentinel_compare

        path = tmp_path / "ref.json"
        path.write_text(body, encoding="utf-8")
        return sentinel_compare.validate_reference(path)

    def test_retired_true_with_nothing_else(self, tmp_path):
        """`{"retired": true}` raised `KeyError('cases')` — a traceback out of
        the CLI where a controlled refusal belongs. It is answered before
        anything is indexed now, and `true` is a marker with no reason in it,
        so the answer is that the marker cannot be read."""
        import sentinel_compare

        state = self.state_of(tmp_path, '{"retired": true}')
        assert state.state == sentinel_compare.REF_UNUSABLE
        assert "says neither that it is a baseline nor why it is not" \
            in state.why

    def test_a_retirement_object_with_a_reason_is_reported_retired(
            self, tmp_path):
        import sentinel_compare

        state = self.state_of(
            tmp_path, '{"retired": {"why": "no models_verified anywhere"}}')
        assert state.state == sentinel_compare.REF_RETIRED
        assert "no models_verified anywhere" in state.why

    def test_a_retirement_object_without_a_reason_is_still_retired(
            self, tmp_path):
        """A non-empty object that forgot `why` is a retirement somebody
        recorded badly, not a live baseline. It says so and stays retired."""
        import sentinel_compare

        state = self.state_of(tmp_path, '{"retired": {"on": "2026-09-01"}}')
        assert state.state == sentinel_compare.REF_RETIRED
        assert "no reason recorded" in state.why

    @pytest.mark.parametrize("marker", [
        '"yes"', "false", "null", "0", '""', "[]", "{}",
    ])
    def test_a_retirement_marker_nobody_can_read(self, tmp_path, marker):
        """Codex, 2026-09-05, fifth gate pass.

        The check was `if retired:`, so every falsey spelling — `false`,
        `null`, `0`, `""`, `[]`, `{}` — was treated exactly like a file that
        never mentioned retirement, and an otherwise well-formed reference
        carrying one was classified usable. The field that decides whether a
        baseline is a baseline, answering "yes" to an absence.
        """
        import sentinel_compare

        state = self.state_of(
            tmp_path,
            '{"cases": {}, "comparable": [], "retired": %s}' % marker)
        assert state.state != sentinel_compare.REF_USABLE
        assert "says neither that it is a baseline nor why it is not" \
            in state.why
        assert "Omit the key to say the reference is live" in state.why

    def test_omitting_the_key_is_the_way_to_say_not_retired(self, tmp_path):
        """The other half: the accepted spelling must still get through to the
        checks below, or the rule above would refuse every live baseline."""
        import sentinel_compare

        state = self.state_of(tmp_path, '{"cases": {}, "comparable": []}')
        assert state.state == sentinel_compare.REF_UNUSABLE
        assert "no usable `threshold`" in state.why

    @pytest.mark.parametrize("body", [
        "{}",
        '{"cases": []}',
        '{"cases": {}, "comparable": {}}',
        '{"cases": {}, "comparable": [], "threshold": 2}',
    ])
    def test_a_reference_missing_or_misshaping_a_required_block(
            self, tmp_path, body):
        import sentinel_compare

        state = self.state_of(tmp_path, body)
        assert state.state == sentinel_compare.REF_UNUSABLE
        assert "nothing below could be checked" in state.why

    @pytest.mark.parametrize("digest", [None, "", "   ", 3, ["d"]])
    def test_a_case_with_no_usable_digest(self, tmp_path, digest):
        """Codex, 2026-09-05, twenty-sixth round, and the mirror image of the
        defect that moved the challenger checks to the boundary.

        `read_run` compares every challenger row against
        `expected[case_id]["case_digest"]` for every case the reference holds,
        and nothing required the field — so a record without it passed
        `validate_reference` as usable and raised `KeyError` from inside a
        function whose caller had just been told the baseline was fine.
        """
        import sentinel_compare

        state = self.state_of(tmp_path, self.one_case_reference(
            case_digest=digest,
            shape={"pass-a": {"missed": False, "false_alarm": False},
                   "pass-b": {"missed": False, "false_alarm": False}}))
        assert state.state == sentinel_compare.REF_UNUSABLE
        assert "for `case_digest`, so nothing says which version" in state.why

    def test_an_unstable_case_is_structurally_checked_too(self, tmp_path):
        """The comparable loop covered `comparable`, and `read_run` reads the
        digest of every case the reference holds — unstable included."""
        import sentinel_compare

        state = self.state_of(tmp_path, json.dumps({
            "comparable": ["one"], "unstable_under_reference": ["two"],
            "environment": ENVIRONMENT,
            "model": "claude-opus-5", "verifier_model": "claude-opus-5",
            "threshold": {"rule_version": 2, "reject_at_net": 1,
                          "confirmations_required": 2},
            "cases": {
                "one": {"outcomes": {"pass-a": True, "pass-b": True},
                        "case_digest": "d" * 16,
                        "unstable_under_reference": False,
                        "shape": {"pass-a": {"missed": False,
                                             "false_alarm": False},
                                  "pass-b": {"missed": False,
                                             "false_alarm": False}}},
                # No digest, and it is the unstable one.
                "two": {"outcomes": {"pass-a": True, "pass-b": False},
                        "unstable_under_reference": True,
                        "shape": {"pass-a": {"missed": False,
                                             "false_alarm": False},
                                  "pass-b": {"missed": True,
                                             "false_alarm": False}}},
            },
        }))
        assert state.state == sentinel_compare.REF_UNUSABLE
        assert "two: the reference records None for `case_digest`" in state.why

    def test_an_unstable_case_may_disagree_with_itself(self, tmp_path):
        """The other half of the same loop split. Agreement is demanded of the
        comparable cases only — an unstable case is *defined* by its two
        passes disagreeing, and requiring agreement of it would refuse every
        reference that records one honestly."""
        import sentinel_compare

        state = self.state_of(tmp_path, json.dumps({
            "comparable": ["one"], "unstable_under_reference": ["two"],
            "environment": ENVIRONMENT,
            "model": "claude-opus-5", "verifier_model": "claude-opus-5",
            "observed_models": {"safe": ["opus"]},
            "threshold": {"rule_version": 2, "reject_at_net": 1,
                          "confirmations_required": 2},
            "cases": {
                "one": {"outcomes": {"pass-a": True, "pass-b": True},
                        "case_digest": "d" * 16,
                        "unstable_under_reference": False,
                        "shape": {"pass-a": {"missed": False,
                                             "false_alarm": False},
                                  "pass-b": {"missed": False,
                                             "false_alarm": False}}},
                "two": {"outcomes": {"pass-a": True, "pass-b": False},
                        "case_digest": "e" * 16,
                        "unstable_under_reference": True,
                        "shape": {"pass-a": {"missed": False,
                                             "false_alarm": False},
                                  "pass-b": {"missed": True,
                                             "false_alarm": False}}},
            },
        }))
        assert state.state == sentinel_compare.REF_USABLE, state.why

    def test_a_stable_case_labelled_unstable_is_refused(self, tmp_path):
        """Codex, 2026-09-05, twenty-seventh round.

        The validator proved the comparable cases agree with themselves and
        never proved the unstable ones disagree, so a perfectly stable case
        could be listed as unstable, pass the partition check, and be dropped
        from the comparison. A sample narrowed by a word — the same thing this
        file already refuses under the name "a case dropped from both".
        """
        import sentinel_compare

        state = self.state_of(tmp_path, json.dumps({
            "comparable": ["one"], "unstable_under_reference": ["two"],
            "environment": ENVIRONMENT,
            "model": "claude-opus-5", "verifier_model": "claude-opus-5",
            "threshold": {"rule_version": 2, "reject_at_net": 1,
                          "confirmations_required": 2},
            "cases": {
                "one": {"outcomes": {"pass-a": True, "pass-b": True},
                        "case_digest": "d" * 16,
                        "unstable_under_reference": False,
                        "shape": {"pass-a": {"missed": False,
                                             "false_alarm": False},
                                  "pass-b": {"missed": False,
                                             "false_alarm": False}}},
                # Agrees with itself, and is excluded anyway.
                "two": {"outcomes": {"pass-a": True, "pass-b": True},
                        "case_digest": "e" * 16,
                        "unstable_under_reference": True,
                        "shape": {"pass-a": {"missed": False,
                                             "false_alarm": False},
                                  "pass-b": {"missed": False,
                                             "false_alarm": False}}},
            },
        }))
        assert state.state == sentinel_compare.REF_UNUSABLE
        assert "narrows the sample by a word" in state.why

    @pytest.mark.parametrize("flag,listed", [
        (True, False),   # the flag says unstable, the list does not
        (False, True),   # the list says unstable, the flag does not
        (None, False),   # the flag is absent
        ("yes", False),  # the flag is not a verdict
    ])
    def test_the_two_spellings_of_instability_must_agree(
            self, tmp_path, flag, listed):
        """Codex, 2026-09-05, twenty-ninth round.

        The same fact is written twice — a per-case flag and membership of the
        top-level list — and only the list was checked, so a stable case could
        carry the flag while sitting in `comparable`. Two spellings of one
        thing agree or one of them is decoration.
        """
        import sentinel_compare

        outcomes = ({"pass-a": True, "pass-b": False} if listed
                    else {"pass-a": True, "pass-b": True})
        record = {"outcomes": outcomes, "case_digest": "d" * 16,
                  "shape": {"pass-a": {"missed": False, "false_alarm": False},
                            "pass-b": {"missed": False, "false_alarm": False}}}
        if flag is not None:
            record["unstable_under_reference"] = flag

        state = self.state_of(tmp_path, json.dumps({
            "comparable": [] if listed else ["one"],
            "unstable_under_reference": ["one"] if listed else [],
            "environment": ENVIRONMENT,
            "model": "claude-opus-5", "verifier_model": "claude-opus-5",
            "threshold": {"rule_version": 2, "reject_at_net": 1,
                          "confirmations_required": 2},
            "cases": {"one": record},
        }))
        assert state.state == sentinel_compare.REF_UNUSABLE
        assert ("The same fact written two ways has to say the same thing"
                in state.why
                or "no comparable cases" in state.why)

    def test_a_case_listed_twice_among_the_unstable_ones(self, tmp_path):
        """The rule the comparable list already carried. `set()` collapses a
        repeat silently, while the number this file prints for how many cases
        were unstable counts the list. Codex, 2026-09-05."""
        import sentinel_compare

        record = {"outcomes": {"pass-a": True, "pass-b": False},
                  "case_digest": "e" * 16,
                  "unstable_under_reference": True,
                  "shape": {"pass-a": {"missed": False, "false_alarm": False},
                            "pass-b": {"missed": True, "false_alarm": False}}}
        state = self.state_of(tmp_path, json.dumps({
            "comparable": ["one"],
            "unstable_under_reference": ["two", "two"],
            "environment": ENVIRONMENT,
            "model": "claude-opus-5", "verifier_model": "claude-opus-5",
            "threshold": {"rule_version": 2, "reject_at_net": 1,
                          "confirmations_required": 2},
            "cases": {
                "one": {"outcomes": {"pass-a": True, "pass-b": True},
                        "case_digest": "d" * 16,
                        "unstable_under_reference": False,
                        "shape": {"pass-a": {"missed": False,
                                             "false_alarm": False},
                                  "pass-b": {"missed": False,
                                             "false_alarm": False}}},
                "two": record,
            },
        }))
        assert state.state == sentinel_compare.REF_UNUSABLE
        assert "reports one exclusion as two" in state.why

    @pytest.mark.parametrize("field", ["model", "verifier_model"])
    @pytest.mark.parametrize("value", [None, "", 3, ["opus"]])
    def test_a_reference_that_does_not_name_its_models(
            self, tmp_path, field, value):
        """Codex, 2026-09-05, thirty-first round.

        `compare()` refuses a reference naming no `verifier_model`, but only
        once challenger runs are in hand — so `validate_reference` called such
        a baseline usable and the order tool reported the Sonnet gate's inputs
        as established for a file the comparison was certain to reject. The
        same precondition-only-on-the-spending-path defect as the two-pass
        agreement check, one field over.
        """
        import sentinel_compare

        body = json.loads(self.one_case_reference(
            shape={"pass-a": {"missed": False, "false_alarm": False},
                   "pass-b": {"missed": False, "false_alarm": False}}))
        if value is None:
            body.pop(field, None)
        else:
            body[field] = value

        state = self.state_of(tmp_path, json.dumps(body))
        assert state.state == sentinel_compare.REF_UNUSABLE
        assert "for `{}`, so it does not say which model".format(field) \
            in state.why

    @pytest.mark.parametrize("field", ["system_prompt", "verifier_prompt",
                                       "findings_schema", "agent_version"])
    def test_an_environment_missing_a_field_the_comparison_reads(
            self, tmp_path, field):
        """Codex, 2026-09-05, thirty-second round.

        `{"host": "x"}` satisfied "records an environment" while recording none
        of the four fields the comparison actually holds a challenger to — and
        that loop skipped every field the reference had left out. So a baseline
        with an environment object full of nothing gave every challenger a free
        pass on the prompts, the schema and the agent version, and a run that
        changed all four would have been reported as a model comparison.
        """
        import sentinel_compare

        body = json.loads(self.one_case_reference(
            shape={"pass-a": {"missed": False, "false_alarm": False},
                   "pass-b": {"missed": False, "false_alarm": False}}))
        body["environment"] = {k: v for k, v in ENVIRONMENT.items()
                               if k != field}

        state = self.state_of(tmp_path, json.dumps(body))
        assert state.state == sentinel_compare.REF_UNUSABLE
        assert "for `{}`".format(field) in state.why
        assert "a part left out is a part nobody checks" in state.why

    def test_a_reference_whose_two_passes_failed_differently(self, tmp_path):
        """Codex, 2026-09-05, eleventh gate pass.

        `_reference_shape` asks whether the reference's two passes agree about
        *how* a case failed. That is a fact about the reference alone, and it
        was only asked inside the comparison loop — so `validate_reference`
        answered `usable`, and the order tool would have reported the Sonnet
        gate's inputs as established, for a baseline `compare()` was certain to
        refuse before reading a single challenger row.
        """
        import sentinel_compare

        state = self.state_of(tmp_path, json.dumps({
            "comparable": ["one"],
            "unstable_under_reference": [],
            "environment": ENVIRONMENT,
            "model": "claude-opus-5", "verifier_model": "claude-opus-5",
            "threshold": {"rule_version": 2, "reject_at_net": 1,
                          "confirmations_required": 2},
            "cases": {"one": {
                "outcomes": {"pass-a": True, "pass-b": True},
                "case_digest": "d" * 16,
                "unstable_under_reference": False,
                "shape": {"pass-a": {"missed": True, "false_alarm": False},
                          "pass-b": {"missed": False, "false_alarm": False}},
            }},
        }))
        assert state.state == sentinel_compare.REF_UNUSABLE
        assert "failed differently in its two passes" in state.why

    def one_case_reference(self, **case):
        return json.dumps({
            "comparable": ["one"],
            "unstable_under_reference": [],
            "environment": ENVIRONMENT,
            "model": "claude-opus-5", "verifier_model": "claude-opus-5",
            "threshold": {"rule_version": 2, "reject_at_net": 1,
                          "confirmations_required": 2},
            "cases": {"one": dict(
                {"outcomes": {"pass-a": True, "pass-b": True},
                 "case_digest": "d" * 16,
                 "unstable_under_reference": False}, **case)},
        })

    @pytest.mark.parametrize("shape", [
        {"pass-a": {"missed": True, "false_alarm": False}},
        {"only-one": {"missed": True, "false_alarm": False}},
        {"a": {"missed": True, "false_alarm": False},
         "b": {"missed": True, "false_alarm": False}},
        {},
    ])
    def test_agreement_needs_both_passes_by_name(self, tmp_path, shape):
        """Codex, 2026-09-05, twelfth gate pass.

        `_reference_shape` reduced the shapes it found to a set and accepted
        any set of size one, so a case recording *one* shape read as two
        passes agreeing — the missing pass supplying the agreement. The same
        absence-as-agreement the whole file is about, inside the check for it.
        """
        import sentinel_compare

        state = self.state_of(tmp_path, self.one_case_reference(shape=shape))
        assert state.state == sentinel_compare.REF_UNUSABLE
        assert "takes both passes by name" in state.why

    @pytest.mark.parametrize("value", [None, 1, "missed", [], True])
    def test_a_pass_that_is_not_an_object_is_unusable_not_unknown(
            self, tmp_path, value):
        """Codex, 2026-09-05, thirteenth gate pass.

        `"pass-a": null` reached `shape.get(...)`, raised `AttributeError`, and
        the catch-all turned a known-malformed reference into `cannot tell`.
        The catch-all exists for shapes nobody listed; a shape somebody can
        name belongs in the list, or "I could not check" starts absorbing
        answers that were available.
        """
        import sentinel_compare

        state = self.state_of(tmp_path, self.one_case_reference(
            shape={"pass-a": value, "pass-b": value}))
        assert state.state == sentinel_compare.REF_UNUSABLE
        assert "where an object with `missed` and `false_alarm` is required" \
            in state.why

    @pytest.mark.parametrize("record", [None, 1, "ordinary", []])
    def test_a_case_record_that_is_not_an_object(self, tmp_path, record):
        import sentinel_compare

        state = self.state_of(tmp_path, json.dumps({
            "comparable": ["one"], "unstable_under_reference": [],
            "environment": ENVIRONMENT,
            "model": "claude-opus-5", "verifier_model": "claude-opus-5",
            "threshold": {"rule_version": 2, "reject_at_net": 1,
                          "confirmations_required": 2},
            "cases": {"one": record},
        }))
        assert state.state == sentinel_compare.REF_UNUSABLE
        assert "where a record with `outcomes` and `shape` is required" \
            in state.why

    def test_a_comparable_id_the_cases_block_does_not_hold(self, tmp_path):
        """Codex, 2026-09-05, fourteenth gate pass: `cases[case_id]` raised
        `KeyError`, which the catch-all reported as "could not tell" about a
        reference that plainly names a case it does not hold."""
        import sentinel_compare

        state = self.state_of(tmp_path, json.dumps({
            "comparable": ["one"], "unstable_under_reference": [],
            "environment": ENVIRONMENT,
            "model": "claude-opus-5", "verifier_model": "claude-opus-5",
            "threshold": {"rule_version": 2, "reject_at_net": 1,
                          "confirmations_required": 2},
            "cases": {},
        }))
        assert state.state == sentinel_compare.REF_UNUSABLE
        assert "names a case it does not hold" in state.why

    @pytest.mark.parametrize("body,expected", [
        # `outcomes` as a list: exactly the right `set()`, no `.items()`.
        ({"cases": {"one": {"outcomes": ["pass-a", "pass-b"]}}},
         "it takes two to"),
        # `missing` as a number: `sorted()` cannot walk it.
        ({"missing": 5}, "where a list of case ids is required"),
        ({"missing": {"one": True}}, "where a list of case ids is required"),
        # a case id that is not a name: it cannot be looked up at all.
        ({"comparable": [["one"]]}, "where case ids are required"),
        ({"comparable": [None]}, "where case ids are required"),
        # `unstable_under_reference` as a scalar: `set()` refuses it. And
        # `null`, and absent — the first fix here exempted both, which is the
        # class reintroduced inside the sweep written to end it.
        ({"unstable_under_reference": 3},
         "where a list of case ids is required"),
        ({"unstable_under_reference": None},
         "has not said that none were"),
        ({"unstable_under_reference": [1, 2]},
         "where a list of case ids is required"),
        # `environment` as anything truthy used to pass.
        ({"environment": "the laptop"}, "records no environment"),
        ({"environment": 1}, "records no environment"),
    ])
    def test_a_container_read_before_anything_asked_what_it_is(
            self, tmp_path, body, expected):
        """Codex found five of these one per round on 2026-09-05.

        The class is "a container read for its contents before anything asked
        whether it is that container", and fixing an instance leaves the class.
        They are repaired together and pinned together.
        """
        import sentinel_compare

        base = {
            "comparable": ["one"], "unstable_under_reference": [],
            "environment": ENVIRONMENT,
            "model": "claude-opus-5", "verifier_model": "claude-opus-5",
            "threshold": {"rule_version": 2, "reject_at_net": 1,
                          "confirmations_required": 2},
            "cases": {"one": {
                "outcomes": {"pass-a": True, "pass-b": True},
                "case_digest": "d" * 16,
                "shape": {"pass-a": {"missed": False, "false_alarm": False},
                          "pass-b": {"missed": False, "false_alarm": False}},
            }},
        }
        base.update(body)
        state = self.state_of(tmp_path, json.dumps(base))
        assert state.state == sentinel_compare.REF_UNUSABLE, state.why
        assert expected in state.why

    def test_a_reference_that_never_mentions_the_unstable_cases(self, tmp_path):
        """Absence, not a misshapen value — the half the sweep first missed."""
        import sentinel_compare

        state = self.state_of(tmp_path, json.dumps({
            "comparable": ["one"], "environment": {"host": "x"},
            "threshold": {"rule_version": 2, "reject_at_net": 1,
                          "confirmations_required": 2},
            "cases": {"one": {
                "outcomes": {"pass-a": True, "pass-b": True},
                "case_digest": "d" * 16,
                "shape": {"pass-a": {"missed": False, "false_alarm": False},
                          "pass-b": {"missed": False, "false_alarm": False}},
            }},
        }))
        assert state.state == sentinel_compare.REF_UNUSABLE
        assert "has not said that none were" in state.why

    def test_an_unexpected_exception_is_cannot_tell_not_a_verdict(
            self, tmp_path, monkeypatch):
        import sentinel_compare

        def explode(reference):
            raise RuntimeError("a shape nobody listed")

        monkeypatch.setattr(sentinel_compare, "_reference_problems", explode)
        state = self.state_of(tmp_path, '{"cases": {}, "comparable": []}')
        assert state.state == sentinel_compare.REF_CANNOT_TELL
        assert "a gap in the checks above rather than a verdict" in state.why

    def test_the_state_has_no_truth_value(self, tmp_path):
        with pytest.raises(TypeError, match="not a boolean"):
            bool(self.state_of(tmp_path, "{}"))

    def test_an_unknown_state_is_refused_where_it_is_written(self):
        import sentinel_compare

        with pytest.raises(ValueError, match="unknown reference state"):
            sentinel_compare.ReferenceState("probably fine", "why", "p")


class TestTheMapsAgreeWithTheDocument:
    """The invariant that would have caught the dead code, and none of the
    3121 tests standing before this file did."""

    def test_every_preflight_key_names_a_step_the_document_declares(self):
        named = {s.id for s in parse().steps}
        for key in order_tool.PREFLIGHT:
            assert key in named, (
                "PREFLIGHT has an entry for {!r} and DECISIONS.md names no "
                "such step — an entry nothing dispatches to is the same "
                "defect one level along".format(key))

    def test_every_preflight_key_names_an_undefined_step(self):
        """A step with a real `done_when` reaches its checker, so a preflight
        there would be a second unreachable place to put a check."""
        undefined = {s.id for s in parse().steps if s.criterion_undefined}
        for key in order_tool.PREFLIGHT:
            assert key in undefined, (
                "{!r} has a defined criterion, so `state_of` runs its checker "
                "and never consults PREFLIGHT".format(key))

    def test_every_undefined_step_in_the_real_document_has_a_preflight(self):
        """The reverse direction, and the one that was missing.

        Codex, 2026-09-05, third gate pass: the subset test alone passed while
        `sonnet_gate` had no entry at all, so the step stayed exactly as
        invisible as before the mechanism was built. A map that is a subset of
        the right thing is not the right thing.

        If a step legitimately has nothing on disk to speak about, the answer
        is an entry that says so, not an absence — because an absence here and
        an absence there read identically in the report.
        """
        text = (ROOT / "DECISIONS.md").read_text(encoding="utf-8")
        undefined = {s.id for s in order_tool.parse_order(text).steps
                     if s.criterion_undefined}
        assert undefined, "the fixture for this test has gone stale"
        missing = sorted(undefined - set(order_tool.PREFLIGHT))
        assert not missing, (
            "{} has `done_when: undefined` and no PREFLIGHT entry, so "
            "`state_of` returns before anything looks at its inputs — which "
            "is the defect this file was written for".format(missing))

    def test_the_real_document_agrees_too(self):
        """Against `DECISIONS.md` itself, not the fixture. The fixture can be
        edited to agree with the code, and has been."""
        text = (ROOT / "DECISIONS.md").read_text(encoding="utf-8")
        named = {s.id for s in order_tool.parse_order(text).steps}
        assert set(order_tool.PREFLIGHT) <= named
