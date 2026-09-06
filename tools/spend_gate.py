#!/usr/bin/env python3
"""The one place a billable request asks whether it is allowed.

Development tooling. It imports `d013_order` and nothing from `src/`, makes no
network call of its own, and nothing in `src/` or in CI depends on it.

## Why this is a broker and not a check in six `main()` functions

That was the first proposal, and Codex refused it on 2026-09-05: putting the
check at six command-line entry points **moves the theatre rather than ending
it**. `pair_corpus.review()` is already imported and called directly by
`experiment.py` and `injection_corpus.py`, so two of the six paid paths never
touch the entry point that would have been guarded, and any future caller can
do the same.

Enforcement belongs at the lowest shared operation that can start a billable
request, and it re-asks immediately before *every* request rather than once at
startup — a check at startup and a spend a minute later are separated by
everything that can change in between.

## Three states, and a return value with no truth value

`d013_order.py` already answers three ways: permitted, refused, and *not
established* — and its own words for the third are "treat as denial for
anything that spends money".

Measured on 2026-09-05, against expectation: of the four ways a caller might
read a `True/False/None` return, three fail closed on `None` — including the
careless `if permitted:`, because `None` is falsey. The one that spends is
`if permitted is False:`, which is what somebody writes when they are *trying*
to be careful about a three-way answer. And Codex named a worse one: a
`(verdict, reason)` tuple is **always truthy** if the caller forgets to unpack
it, so the safe-looking spelling becomes the unsafe one.

So `authorise()` returns a `Decision`, and `Decision` has no truth value at
all: `if decision:` raises rather than guesses. The only way to act on it is
`decision.require()`, which raises for refusal *and* for indeterminacy. Callers
do not implement the policy branch, because every defect above is a caller
implementing the policy branch.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Dict, Optional

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

PERMITTED = "permitted"
REFUSED = "refused"
UNDETERMINED = "undetermined"

# Every class of spending this repository can do, and the D-013 step that
# orders it. `None` means D-013 names no step for it — which is a gap to be
# closed by a decision, never a default to fall through.
#
# Not `spend` as a fallback. `spend` in `d013_order.py` means one specific
# thing — the paid run that extends the corpus to a hundred — and it requires
# `adjudicate_30` to be *done*. Asking it before adjudicating the thirty would
# get `PROHIBITED` for a reason that has nothing to do with the question, and a
# refusal that is right by accident teaches nobody anything. Codex, 2026-09-05:
# "B wrongly erases legitimate step-specific ordering."
SPEND_CLASSES: Dict[str, Optional[str]] = {
    "adjudicate_ordinary": "adjudicate_30",
    "classify_alarms": "classify_alarms",
    "extend_corpus": "spend",
    # Named, and deliberately unmapped. D-013 orders the ordinary-corpus work
    # and says nothing about these, so there is no honest step to point at.
    # They fail closed and the refusal says what would resolve it.
    #
    # A class says **why** spending is authorised, not which function performs
    # it. I collapsed `run_queue` and `experiment_run` into
    # `pair_corpus_review` because all three end at `pair_corpus.review`, and
    # Codex refused it on 2026-09-05: a queue measurement and a frozen
    # experiment can be ordered differently while sharing a mechanism, so
    # collapsing them trades a policy identity for an implementation one. The
    # class travels from the caller that has the reason.
    "pair_corpus_review": None,
    "injection_corpus": None,
    "run_queue": None,
    "experiment_run": None,
    "verifier_replay": None,
    "measure_variance": None,
    "ablation": None,
    "stability": None,
    # Authorised by a **decision**, not by a step of D-013's ordering. D-014
    # governs the noise measurement over the sealed ordinary sample, and D-013
    # orders nothing about it — the owner narrowed the goal on 2026-09-06 and
    # dropped the rest of that programme, so asking `spend` or `adjudicate_30`
    # about this would get an answer to a different question.
    #
    # The refusal message for an unmapped class already said what resolves one:
    # "deciding what orders this class of spending and recording that in
    # DECISIONS.md". This is that, and the gate now reads it rather than
    # treating the sentence as advice nobody acts on.
    "ordinary_noise": {"decision": "D-014"},
}

# What a decision has to say before it authorises anything. `active` and
# nothing else: a superseded or proposed entry is a decision that was made and
# then unmade, or one nobody has made yet.
AUTHORISING_STATE = "active"


class SpendRefused(RuntimeError):
    """Raised instead of spending. Never caught to spend anyway."""


class Decision:
    """Permitted, refused, or not established — and not a boolean.

    `__bool__` raises on purpose. Every defect this class exists for is a
    caller writing its own branch over a value that has a truth value, so this
    one has none: `if decision:` is a `TypeError` at the moment it is written,
    not a wrong answer at the moment it matters.
    """

    __slots__ = ("spend_class", "state", "step", "why")

    def __init__(self, state, spend_class, step, why):
        self.state = state
        self.spend_class = spend_class
        self.step = step
        self.why = why

    def __bool__(self):
        raise TypeError(
            "a spend decision is not a boolean: it is {!r}. Call .require(), "
            "which raises for a refusal and for an undetermined answer alike."
            .format(self.state))

    def __repr__(self):
        return "Decision({!r}, {!r}, step={!r})".format(
            self.state, self.spend_class, self.step)

    def require(self):
        """Return quietly if permitted; raise otherwise. There is no third
        outcome, because a caller that has to distinguish them is a caller
        implementing policy."""
        if self.state == PERMITTED:
            return self
        raise SpendRefused("{}: {}\n{}".format(
            "REFUSED" if self.state == REFUSED
            else "AUTHORISATION UNDETERMINED",
            self.spend_class, self.why))


def authorise(spend_class: str, **order_kwargs) -> Decision:
    """Ask the order about one class of spending. Never raises for a `no`.

    Anything that goes wrong on the way to an answer is `undetermined`, which
    `require()` treats exactly as a refusal. An order tool that cannot be
    imported, cannot parse its own decision file, or crashes has not said yes,
    and this repository keeps "I could not check" apart from "it is clean"
    everywhere else.
    """
    if spend_class not in SPEND_CLASSES:
        return Decision(
            UNDETERMINED, spend_class, None,
            "no such class of spending is declared in spend_gate.py. Add it "
            "with the D-013 step that orders it, or with `None` and the "
            "reason, rather than spending against a name nobody has mapped.")

    step = SPEND_CLASSES[spend_class]

    # A class authorised by a decision rather than by a step of the order.
    # Checked here and not delegated to `d013_order`, which knows one document
    # and would answer about a step this class does not have.
    if isinstance(step, dict):
        name = step.get("decision")
        try:
            state, authorises = _decision_state(name, spend_class)
        except Exception as exc:
            return Decision(UNDETERMINED, spend_class, name,
                            "the decision {} could not be read ({}: {}), and "
                            "an unreadable authorisation is not one".format(
                                name, type(exc).__name__, exc))
        if state is None:
            return Decision(UNDETERMINED, spend_class, name,
                            "{} names {} and DECISIONS.md holds no such "
                            "entry".format(spend_class, name))
        if state != AUTHORISING_STATE:
            return Decision(REFUSED, spend_class, name,
                            "{} is {!r} rather than {!r}, so it does not "
                            "authorise anything".format(
                                name, state, AUTHORISING_STATE))
        # **The decision has to say the class by name.** Codex, 2026-09-06:
        # inferring "governs this class" from an active state meant any
        # unrelated active decision, placed in the mapping, permitted spending
        # — the mapping was the only thing binding them, and the mapping is
        # written here rather than there. Now both ends name each other.
        if authorises != spend_class:
            return Decision(REFUSED, spend_class, name,
                            "{} authorises {!r} and this is {!r}. A decision "
                            "that does not name the class is a decision about "
                            "something else".format(
                                name, authorises, spend_class))
        return Decision(PERMITTED, spend_class, name,
                        "{} is active and names this class".format(name))

    if step is None:
        return Decision(
            UNDETERMINED, spend_class, None,
            "D-013 names no step that orders this, so nothing can say whether "
            "it is permitted yet. Falling back to the generic `spend` action "
            "would ask a different question and get an answer that is right "
            "by accident. Resolving it means deciding what orders this class "
            "of spending and recording that in DECISIONS.md — a decision, not "
            "a default.")

    try:
        code, reasons = _ask_the_order(step, **order_kwargs)
    except Exception as exc:
        # Every way this can go wrong lands here on purpose: the module missing,
        # `DECISIONS.md` unreadable, the block malformed, an evaluator raising.
        # None of them is a yes, and this repository never returns the answer
        # for "clean" when it means "I could not check".
        return Decision(UNDETERMINED, spend_class, step,
                        "the order could not be asked about {} ({}: {}), "
                        "which is not the same as saying yes".format(
                            step, type(exc).__name__, exc))

    # 0, 1, 2 are the order's own exit codes, and its own words for 2 are
    # "treat as denial for anything that spends money". Anything outside the
    # three is undetermined rather than assumed: a new code added later must
    # not inherit permission from this translation.
    state = {0: PERMITTED, 1: REFUSED, 2: UNDETERMINED}.get(code, UNDETERMINED)
    why = "\n".join("  - {}".format(r) for r in reasons) if reasons else (
        "the order gave no reason")
    if state is UNDETERMINED and code not in (0, 1, 2):
        why = "the order answered with an exit code this gate does not know " \
              "({}), so nothing established that spending is permitted".format(
                  code)
    return Decision(state, spend_class, step, why)


def _decision_state(name, spend_class=None):
    """`(state, authorises)` for one decision, or `(None, None)` if absent.

    Read through `check_decisions`, which knows the heading and table format.
    Parsing it again here would be a second reader of one document, and the
    weaker reader would be the one deciding whether money moves.

    **The whole document is validated first.** Codex, 2026-09-06: reading one
    entry's `State` and nothing else meant a malformed decision that kept
    `State: active` still authorised spending — the field survives edits the
    rest of the entry does not. A document this checker reports problems in has
    not authorised anything.
    """
    import check_decisions

    text = (ROOT / "DECISIONS.md").read_text(encoding="utf-8")
    # A heading the checker cannot read is an entry nobody can see, and it
    # would come back from here as "no such decision" — which reads as a
    # missing authorisation when it is an unreadable one. Refused instead, and
    # the caller turns it into `undetermined`.
    unparsed = check_decisions.unparsed_headings(text)
    if unparsed:
        raise RuntimeError(
            "DECISIONS.md holds {} heading(s) this parser cannot read ({}), "
            "so it cannot say whether {} is among them".format(
                len(unparsed), "; ".join(unparsed[:2]), name))
    problems = check_decisions.check(text, run_tests=False)
    if problems:
        raise RuntimeError(
            "DECISIONS.md has {} problem(s) — {} — and a document that does "
            "not check out has not authorised anything".format(
                len(problems), "; ".join(problems[:2])))

    seen = [e for e in check_decisions.parse(text) if e.id == name]
    if len(seen) > 1:
        raise RuntimeError(
            "DECISIONS.md holds {} entries called {}, so nothing says which "
            "one authorises".format(len(seen), name))
    if not seen:
        return (None, None)
    return (seen[0].fields.get("State"), seen[0].fields.get("Authorises"))


def _ask_the_order(step, **order_kwargs):
    """`(exit_code, reasons)` from the order, through its own evaluation path.

    In-process rather than by running the command line: a subprocess would put
    a shell, a `PATH` and an interpreter between the question and the answer,
    and each of those can fail in a way that has to be told apart from `no`.
    Whatever this raises becomes `undetermined` in the caller.
    """
    import d013_order as order

    ctx = order.Context(**order_kwargs) if order_kwargs else order.Context(
        root=ROOT)
    text = ctx.decisions.read_text(encoding="utf-8")
    parsed = order.parse_order(text)
    problems = order.divergence(parsed)
    if problems:
        raise RuntimeError("the order and the tool disagree: {}".format(
            " / ".join(problems)))
    results = order.evaluate(ctx, parsed)
    return order.decide(parsed, results, step)
