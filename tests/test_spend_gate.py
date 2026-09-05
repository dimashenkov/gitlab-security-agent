"""The broker that stands between a billable request and the order.

Every test is written against a way this could look like a control and not be:
a caller reading the decision as a boolean, an undetermined answer taken for a
yes, a class of spending nobody mapped falling through to a question about a
different step, and the order itself failing in a way that reads as permission.

Nothing here spends: `d013_order` is replaced wherever an answer is needed.
"""

from __future__ import annotations

import contextlib
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import spend_gate as sg  # noqa: E402


def answer(monkeypatch, code, reasons=("because",)):
    monkeypatch.setattr(sg, "_ask_the_order",
                        lambda step, **kw: (code, list(reasons)))


def raises(monkeypatch, exc):
    def boom(step, **kw):
        raise exc
    monkeypatch.setattr(sg, "_ask_the_order", boom)


# --------------------------------------------------------------------------
# The decision is not a boolean, which is the point of it
# --------------------------------------------------------------------------

def test_a_decision_cannot_be_used_as_a_boolean(monkeypatch):
    """Measured 2026-09-05: of four ways to read a True/False/None return,
    three fail closed and the one that spends is `is False` — what somebody
    writes when trying to be careful. Codex added a worse one: a
    `(verdict, reason)` tuple is always truthy unless it is unpacked.

    So the decision has no truth value, and the wrong spelling is a TypeError
    where it is written rather than a wrong answer where it matters.
    """
    answer(monkeypatch, 0)
    decision = sg.authorise("classify_alarms")
    with pytest.raises(TypeError) as exc:
        bool(decision)
    assert "not a boolean" in str(exc.value)
    assert ".require()" in str(exc.value)


def test_require_returns_quietly_when_permitted(monkeypatch):
    answer(monkeypatch, 0)
    decision = sg.authorise("classify_alarms")
    assert decision.require() is decision
    assert decision.state == sg.PERMITTED


@pytest.mark.parametrize("code, state", [
    (1, sg.REFUSED),
    (2, sg.UNDETERMINED),
])
def test_require_raises_for_a_refusal_and_for_an_unknown_alike(
        code, state, monkeypatch):
    """`SpendRefused` for both, because a caller that has to tell them apart
    is a caller implementing the policy this class exists to hold."""
    answer(monkeypatch, code)
    decision = sg.authorise("classify_alarms")
    assert decision.state == state
    with pytest.raises(sg.SpendRefused):
        decision.require()


def test_the_refusal_names_which_of_the_two_it_is(monkeypatch):
    """Told apart in the message, not in the control flow."""
    answer(monkeypatch, 1)
    with pytest.raises(sg.SpendRefused) as exc:
        sg.authorise("classify_alarms").require()
    assert "REFUSED" in str(exc.value)

    answer(monkeypatch, 2)
    with pytest.raises(sg.SpendRefused) as exc:
        sg.authorise("classify_alarms").require()
    assert "UNDETERMINED" in str(exc.value)


# --------------------------------------------------------------------------
# Anything that is not a yes
# --------------------------------------------------------------------------

@pytest.mark.parametrize("exc", [
    ImportError("no module named d013_order"),
    OSError("DECISIONS.md could not be read"),
    RuntimeError("the block is malformed"),
    ValueError("an evaluator raised"),
])
def test_an_order_that_cannot_answer_has_not_said_yes(exc, monkeypatch):
    """The module missing, the file unreadable, the block malformed, an
    evaluator raising: none is permission, and a crash must never borrow the
    exit code for success."""
    raises(monkeypatch, exc)
    decision = sg.authorise("classify_alarms")
    assert decision.state == sg.UNDETERMINED
    assert type(exc).__name__ in decision.why
    with pytest.raises(sg.SpendRefused):
        decision.require()


@pytest.mark.parametrize("code", [3, -1, 99])
def test_an_exit_code_this_gate_does_not_know_is_not_permission(
        code, monkeypatch):
    """A code added to the order later must not inherit a yes from a
    translation written before it existed."""
    answer(monkeypatch, code)
    decision = sg.authorise("classify_alarms")
    assert decision.state == sg.UNDETERMINED
    assert "does not know" in decision.why


def test_a_class_nobody_declared_is_refused(monkeypatch):
    answer(monkeypatch, 0)
    decision = sg.authorise("something_invented")
    assert decision.state == sg.UNDETERMINED
    assert "no such class" in decision.why


# --------------------------------------------------------------------------
# The mapping, which is where the first proposal was wrong
# --------------------------------------------------------------------------

def test_an_unmapped_class_does_not_fall_back_to_the_generic_step(
        monkeypatch):
    """`spend` in D-013 means one specific thing: the paid run that extends
    the corpus to a hundred, and it requires `adjudicate_30` to be done.
    Asking it about a tool it does not order would answer a different question
    — and a refusal that is right by accident teaches nobody anything.
    Codex, 2026-09-05: "B wrongly erases legitimate step-specific ordering."
    """
    asked = []
    monkeypatch.setattr(sg, "_ask_the_order",
                        lambda step, **kw: asked.append(step) or (0, []))
    decision = sg.authorise("pair_corpus_review")
    assert asked == [], "it asked the order about a step that does not order it"
    assert decision.state == sg.UNDETERMINED
    assert decision.step is None
    assert "a decision, not a default" in decision.why


def test_every_declared_step_is_one_the_order_knows():
    """A renamed step must fail here rather than quietly permitting.

    The mapping is written out; nothing derives it from the order, so nothing
    would notice a step disappearing except this.
    """
    import d013_order as order

    known = set(order.EXTRA_ACTIONS) | {
        step.id for step in order.parse_order(
            (ROOT / "DECISIONS.md").read_text(encoding="utf-8")).steps}
    named = {step for step in sg.SPEND_CLASSES.values() if step is not None}
    assert named <= known, sorted(named - known)


def test_the_unmapped_classes_are_named_rather_than_absent():
    """A paid tool missing from the table would get `no such class`, which is
    also a refusal — but the table is the record of what was considered, and
    absence there is indistinguishable from an oversight."""
    unmapped = {name for name, step in sg.SPEND_CLASSES.items()
                if step is None}
    assert unmapped == {"pair_corpus_review", "injection_corpus", "run_queue",
                        "experiment_run", "verifier_replay",
                        "measure_variance", "ablation", "stability"}


# Every module that can start a billable request, and the class it names.
# Written out rather than discovered: a tool added later must fail the sweep
# below and be put here deliberately, not be absorbed by a pattern.
BILLING_MODULES = ("grok_adjudicate", "classify_alarms", "pair_corpus",
                   "injection_corpus", "run_queue", "experiment",
                   "verifier_replay", "measure_variance", "ablation",
                   "stability")


def test_every_class_is_named_by_a_tool_that_spends():
    """A class nobody calls reads as coverage.

    I collapsed `run_queue` and `experiment_run` into `pair_corpus_review`
    because all three end at the same `review`, and Codex refused it: a class
    says *why* spending is authorised, not which function performs it, and a
    queue measurement and a frozen experiment can be ordered differently.
    Restored, and each now passes its own class down.
    """
    named = {__import__(name).SPEND_CLASS for name in BILLING_MODULES}
    named.add("extend_corpus")      # no tool yet; the run it orders is D-013's
    assert set(sg.SPEND_CLASSES) == named, sorted(
        set(sg.SPEND_CLASSES) ^ named)


def test_no_tool_starts_a_paid_process_without_asking_the_broker():
    """The inventory test the first version was not.

    "Every declared class is named by a tool" rewards collapsing classes
    together; it says nothing about a tool that spends and names none. This
    sweeps the other way: every module that builds a `security_agent` command
    or an Anthropic client must mention `spend_gate`. Codex, 2026-09-05, after
    finding three such paths.
    """
    root = ROOT / "tools"
    missing = []
    for name in BILLING_MODULES:
        text = (root / (name + ".py")).read_text(encoding="utf-8")
        if "spend_gate" not in text and "spend_class" not in text:
            missing.append(name)
    assert missing == [], missing


def test_the_sweep_would_notice_a_new_paid_tool():
    """The list above is written out, so a tool that bills and is not on it
    passes silently. This is what makes that a failure instead.

    Two ways to bill, because the first version only knew one. Looking for a
    literal `security_agent` command or an Anthropic client missed
    `stability.py`, which bills by importing `pair_corpus.review` — and I had
    broken it: the new required argument turned every stability run into a
    caught `TypeError` instead of a review. Codex, 2026-09-05.
    """
    root = ROOT / "tools"
    direct, indirect = [], []
    for path in sorted(root.glob("*.py")):
        # Only `spend_gate` itself is excused, and only because it names the
        # things it guards. `compare_scanners` was excused here too until it
        # was checked: it runs semgrep and codeql, which are local and free,
        # so it needs no exemption — and an exemption by name would have
        # hidden the day it started billing.
        if path.stem in BILLING_MODULES or path.stem == "spend_gate":
            continue
        text = path.read_text(encoding="utf-8")
        if '"-m", "security_agent"' in text or "anthropic.Anthropic(" in text:
            direct.append(path.stem)
        if "from pair_corpus import" in text and (
                "review" in text.split("from pair_corpus import")[1]
                .splitlines()[0]
                or "run_case" in text.split("from pair_corpus import")[1]
                .splitlines()[0]):
            indirect.append(path.stem)
    assert direct == [], (
        "these start a billable process and are not in BILLING_MODULES: "
        "{}".format(direct))
    assert indirect == [], (
        "these import a function that bills and are not in BILLING_MODULES: "
        "{}".format(indirect))


def test_every_billing_module_declares_a_class_the_broker_knows():
    """Renamed. It was called "still imports and calls" and only imported.

    Python validates a missing required argument when the call executes, not
    when the module loads, so this could never have caught the drift it was
    written for. The tests below make the call. Codex, 2026-09-05.
    """
    for name in BILLING_MODULES:
        module = __import__(name)
        assert module.SPEND_CLASS in sg.SPEND_CLASSES, name


# The modules that bill by calling `pair_corpus.review`, and how to reach that
# call. Each is exercised with `review` replaced, so a caller that stopped
# passing its class fails here rather than turning into a caught `TypeError`.
def _stability_run(module, tmp_path):
    module.one_run({"_dir": tmp_path, "case_id": "c"}, "safe", 0)


def _injection_run(module, tmp_path):
    module.build_and_review({"_dir": tmp_path, "case_id": "c"}, "safe",
                            tmp_path / "w")


def _pair_run(module, tmp_path):
    module.run_case({"_dir": tmp_path, "case_id": "c"})


@pytest.mark.parametrize("name, drive", [
    ("stability", _stability_run),
    ("injection_corpus", _injection_run),
    ("pair_corpus", _pair_run),
])
def test_a_review_caller_passes_its_own_class(name, drive, monkeypatch,
                                              tmp_path):
    """`stability.py` called `review` without a class and swallowed the
    `TypeError` as "review failed" — an error report where a crash belongs,
    and the suite stayed green through it."""
    module = __import__(name)
    seen = {}

    def fake_review(repo, base, head, out, provider="", profile="", *,
                    spend_class):
        seen["class"] = spend_class
        return {"ok": False, "error": "not run"}

    monkeypatch.setattr(module, "review", fake_review, raising=False)
    monkeypatch.setattr(module, "build_repo",
                        lambda *a, **k: (tmp_path, "b", "h"), raising=False)
    # The fixture is thin on purpose; what matters is that `review` was
    # reached and what it was given, not that the rest of the run completes.
    with contextlib.suppress(Exception):
        drive(module, tmp_path)
    assert seen.get("class") == module.SPEND_CLASS, (
        "{} reached `review` without passing its own class".format(name))


# --------------------------------------------------------------------------
# Against the live order, no replacement — the answers a caller really gets
# --------------------------------------------------------------------------

# --------------------------------------------------------------------------
# The wiring, which is the only part that can stop money moving
# --------------------------------------------------------------------------

@pytest.mark.parametrize("module_name, spend_class", [
    ("grok_adjudicate", "adjudicate_ordinary"),
    ("classify_alarms", "classify_alarms"),
])
def test_a_refusal_stops_the_call_rather_than_reporting_after_it(
        module_name, spend_class, monkeypatch):
    """The whole point: no process is started when the order says no.

    A tool that asks and then spends anyway on a later path is the theatre
    this replaced. `subprocess.run` is made to fail the test if it is reached
    at all, rather than asserted about afterwards.
    """
    module = __import__(module_name)
    assert spend_class == module.SPEND_CLASS

    def must_not_run(*args, **kwargs):
        raise AssertionError("a billable call was started after a refusal")

    monkeypatch.setattr(module.subprocess, "run", must_not_run)
    monkeypatch.setattr(sg, "_ask_the_order", lambda step, **kw: (1, ["no"]))

    with pytest.raises(sg.SpendRefused):
        if module_name == "grok_adjudicate":
            module.ask("diff --git a/x b/x\n+x\n", timeout=1)
        else:
            module.ask("a ruling", timeout=1)


@pytest.mark.parametrize("module_name", ["grok_adjudicate", "classify_alarms"])
def test_an_undetermined_answer_stops_the_call_too(module_name, monkeypatch):
    """`undetermined` is the one this repository keeps getting wrong."""
    module = __import__(module_name)

    def must_not_run(*args, **kwargs):
        raise AssertionError("a billable call was started on an unknown answer")

    monkeypatch.setattr(module.subprocess, "run", must_not_run)
    monkeypatch.setattr(sg, "_ask_the_order", lambda step, **kw: (2, ["?"]))

    with pytest.raises(sg.SpendRefused):
        if module_name == "grok_adjudicate":
            module.ask("diff --git a/x b/x\n+x\n", timeout=1)
        else:
            module.ask("a ruling", timeout=1)


@pytest.mark.parametrize("code", [1, 2])
def test_pair_corpus_review_does_not_bill_when_refused(code, monkeypatch,
                                                       tmp_path):
    """The bypass Codex found: three paths reached `security_agent` here.

    `pair_corpus.review` is the lowest point `run_case`,
    `run_queue.run_one` (by subprocess) and `injection_corpus.build_and_review`
    share. Gating only the command-line entry points left all three able to
    bill without passing the broker.
    """
    import pair_corpus

    def must_not_run(*args, **kwargs):
        raise AssertionError("a billable review was started after a refusal")

    monkeypatch.setattr(pair_corpus.subprocess, "run", must_not_run)
    monkeypatch.setattr(sg, "_ask_the_order", lambda step, **kw: (code, ["x"]))
    with pytest.raises(sg.SpendRefused):
        pair_corpus.review(tmp_path, "base", "head", tmp_path / "out",
                           spend_class="pair_corpus_review")


@pytest.mark.parametrize("code", [1, 2])
def test_measure_variance_does_not_bill_when_refused(code, monkeypatch,
                                                     tmp_path):
    """One of three paths Codex found still reaching `security_agent`."""
    import measure_variance

    def must_not_run(*args, **kwargs):
        raise AssertionError("a billable run was started after a refusal")

    import argparse

    monkeypatch.setattr(measure_variance.subprocess, "run", must_not_run)
    monkeypatch.setattr(sg, "_ask_the_order", lambda step, **kw: (code, ["x"]))
    # Deliberately empty: the refusal comes before anything is read off it, so
    # a Namespace carrying nothing is enough — and if the check ever moves
    # after the command is built, this stops passing.
    with pytest.raises(sg.SpendRefused):
        measure_variance.run_once(argparse.Namespace(), 0)


@pytest.mark.parametrize("code", [1, 2])
def test_ablation_does_not_bill_when_refused(code, monkeypatch, tmp_path):
    import ablation

    def must_not_run(*args, **kwargs):
        raise AssertionError("a billable run was started after a refusal")

    monkeypatch.setattr(ablation.subprocess, "run", must_not_run)
    monkeypatch.setattr(sg, "_ask_the_order", lambda step, **kw: (code, ["x"]))
    with pytest.raises(sg.SpendRefused):
        ablation.review(tmp_path, "base", "head", tmp_path / "out", {})


@pytest.mark.parametrize("code", [1, 2])
def test_verifier_replay_does_not_build_a_client_when_refused(
        code, monkeypatch, tmp_path):
    """The gate is before the client is constructed, not after."""
    import verifier_replay

    class MustNotBeBuilt:
        def __init__(self, *args, **kwargs):
            raise AssertionError("an API client was built after a refusal")

    monkeypatch.setattr(verifier_replay.anthropic, "Anthropic",
                        MustNotBeBuilt)
    monkeypatch.setattr(sg, "_ask_the_order", lambda step, **kw: (code, ["x"]))
    # The tool's own function, not `authorise` called again here: a test that
    # invokes the broker itself passes whether or not the tool ever does.
    # Deliberately given nothing usable — the refusal comes first, so if the
    # check ever moves after the repository is built this stops passing.
    with pytest.raises(sg.SpendRefused):
        verifier_replay.one_run(None, {}, "safe", tmp_path, None, 0)


def test_run_queue_passes_its_own_class_down():
    """A collapsed class would let a queue measurement borrow the corpus
    run's authorisation. Read from the command it builds, not from a comment.
    """
    import run_queue

    assert run_queue.SPEND_CLASS == "run_queue"
    source = (ROOT / "tools" / "run_queue.py").read_text(encoding="utf-8")
    assert '"--spend-class", SPEND_CLASS' in source


def test_the_pair_corpus_cli_only_accepts_a_declared_class():
    """A typo becomes a refusal at the command line rather than an unknown
    class resolved at the moment of spending."""
    import pair_corpus

    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr(sys, "argv", [
        "pair_corpus.py", str(ROOT / "corpus-real"),
        "--provider", "claude-cli", "--spend-class", "not_a_class"])
    try:
        with pytest.raises(SystemExit) as exit_:
            pair_corpus.main()
        assert exit_.value.code == 2, "argparse refuses an undeclared choice"
    finally:
        monkeypatch.undo()


def test_review_will_not_run_without_a_named_class():
    """No default. A default would put the policy back in one place for
    callers that mean different things."""
    import inspect

    import pair_corpus

    parameter = inspect.signature(pair_corpus.review).parameters["spend_class"]
    assert parameter.default is inspect.Parameter.empty
    assert parameter.kind is inspect.Parameter.KEYWORD_ONLY


def test_the_live_order_answers_all_three_ways():
    """Not a fixture: the three states have to be reachable against the real
    `DECISIONS.md`, or the translation is untested where it is used."""
    states = {name: sg.authorise(name).state for name in sg.SPEND_CLASSES}
    assert states["classify_alarms"] == sg.PERMITTED
    assert states["extend_corpus"] == sg.REFUSED
    assert states["pair_corpus_review"] == sg.UNDETERMINED
