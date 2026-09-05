#!/usr/bin/env python3
"""Whether an action D-013 orders is permitted yet, answered from artifacts.

D-013 names the steps and what each one waits for. On 2026-09-04 the assistant
worked on the second step for an hour without having read that the first comes
first, and changed the rule itself four times the same day — which is exactly
what the first step, "freeze the configuration and this rule", exists to
prevent. Nothing was spent, so it was repairable. This tool exists so that next
time the answer comes from the artifacts and not from somebody's memory.

    tools/d013_order.py check <action>     0 permitted / 1 prohibited / 2 unclear
    tools/d013_order.py status             every step, its state and its evidence
    tools/d013_order.py freeze --out ...   writes the first step's artifact

Exit 2 means the tool did not get to an answer — the evidence is incomplete, or
the rule is inconsistent with the checkers. **A caller that spends money must
treat exit 2 as denial.** "I could not check" and "it is clean" are different
answers, and this repository exists because they get conflated.

## Where the order comes from

Not from the prose, and not from this file. `DECISIONS.md` carries a fenced
```yaml block whose first line is the marker `# d013-order`. The block is found
by that marker rather than by position or by counting fences, so editing the
section around it does not change the answer.

The prose was tried first and could not be parsed. It said "doubly adjudicate"
where the owner had decided on one adjudicator, quoted 22 alarms where 20
reproduce, and called a step "in parallel" while numbering it fourth.
Automating that would have frozen the contradictions rather than the order.

**A second copy of the order living in Python is a copy that drifts.** So this
file holds no step list, no thresholds and no field names — it holds a checker
per step id and takes every number, field name and question out of the block.

## What the block carries, and why a missing field is a refusal

    open_questions:        questions in DECISIONS.md nobody has answered. A step
                           names one; no work clears it, only an answer.
    steps:
      id                   stable, no ordinals
      requires             must be `done` before this step
      guard / guard_field  a condition in the prose and the metric that decides
      guard_below          it. It says when the step RUNS. What a failure MEANS
                           is one of the next two, exactly one, never both.
      guard_failure_       the id of an open question, while the decision has
        blocked_on         not said what a failed guard means.
      on_guard_failed      the outcome, once it has. Checked against the
                           outcomes a decision has named, so a value nobody
                           decided cannot be written here and acted on.
      blocked_on_owner     the id of an open question. Never ready, never done.
      requires_no_open_    the step may not be taken while ANY question in the
        questions          file is unanswered. `freeze` carries it: it digests
                           D-013, so an answer would invalidate the record.
      undefined_predicates words no program evaluates. A step carrying any of
                           these may be reported *not started*, never *done*.
      needs_field          the field the step's evidence must carry, by name.
      needs_vocabulary_    the field's values must come from a vocabulary
        first              written before the classifying starts. No step
                           carries it — see D-013 on the post-hoc codebook.
      vocabulary           the permitted values, when the step declares them.
      forbidden_values     values a decision has ruled OUT, as against a list
                           of the only ones allowed. The open-ended shape: the
                           codebook is post-hoc, so an exhaustive permitted
                           list would claim a precommitment nobody made.
      done_when            what records that this step finished, or `undefined`
                           — which is never done and never satisfies another
                           step's `requires`.

**A field this tool does not understand is a refusal, not a shrug.** The first
implementation of this parser kept `id` and `requires` and silently dropped
everything else, which would have reported `tune` as ready — exactly the false
readiness the decision exists to prevent. So an unknown key at the top level, in
a step or in an open question exits 2, and so does a key that is understood but
cannot be evaluated (a `guard_field` naming a metric this tool does not
compute).

## The states, and the three stops kept apart

    done               an artifact establishes it
    not done           an artifact establishes that it has not happened
    cannot tell        no artifact settles it — never rendered as `done`
    waiting            a prerequisite is not done yet
    guard_failed       the guard's condition does not hold. What follows comes
                       from the step: `on_guard_failed` names the outcome the
                       decision chose, or `guard_failure_blocked_on` names the
                       question nobody has answered. The state is the same;
                       the evidence says which of the two it is.
    blocked_on_owner   an unanswered question in DECISIONS.md; no work clears it
    manual_required    the mechanical part holds, the rest is a judgement no
                       artifact records

Waiting, guard-failed and blocked-on-owner are three different answers, and
merging any two of them answers a question nobody asked. An unenforceable step
reported as `done` is worse than one reported honestly, because `done` is what a
hook reads.

## The freeze artifact

`measurements/ordinary-v1/freeze.json`, written by the `freeze` subcommand.

**Canonical values, not only hashes.** A file of digests makes drift detectable
and the frozen state unrecoverable: it can say "something changed" and cannot
say what was frozen. So the freeze records the D-013 section's text as well as
its digest, the resolved configuration rather than a pointer at the config
file, the commit and whether the tree was dirty, and an explicit owner
acknowledgement — plus digests of every file whose content decides what a run
means, so that "still frozen" is checkable rather than asserted.

A dirty tree is refused unless every dirty path is captured explicitly with its
digest: a freeze taken over uncommitted edits records a commit that does not
describe what ran.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

import yaml

ROOT = Path(__file__).resolve().parents[1]

BLOCK_MARKER = "# d013-order"
FREEZE_SCHEMA = "d013-freeze/1"
DEFAULT_FREEZE = "measurements/ordinary-v1/freeze.json"

DONE = "done"
NOT_DONE = "not done"
UNKNOWN = "cannot tell"
WAITING = "waiting"
GUARD_FAILED = "guard_failed"
BLOCKED_OWNER = "blocked_on_owner"
MANUAL = "manual_required"
UNDEFINED_CRITERION = "done_when undefined"

STATES = (DONE, NOT_DONE, UNKNOWN, WAITING, GUARD_FAILED, BLOCKED_OWNER,
          MANUAL, UNDEFINED_CRITERION)

# The literal that says no artifact has been named for a step's completion.
# Codex, third round: `requires` expresses order and nothing said what records
# that a step *finished*, so "a checker cannot report false readiness" was
# itself unenforced. A step whose criterion is undefined is never reported done
# and never satisfies another step's `requires`. It is **not** "not done" — it
# is "this cannot be determined", the third answer this project keeps having to
# add back, and it exits 2 rather than 1.
UNDEFINED = "undefined"

# The `done_when` sentence this tool actually evaluates, per step. The
# criterion lives in DECISIONS.md; this is the tool's claim about which
# sentence its checker implements, and `divergence` refuses when the two differ.
# Without it a reworded criterion would keep the old checker silently.
_ADJUDICATED_DONE_WHEN = (
    "the manifest and the adjudication file cover the same sample, the cases "
    "carry a verdict of ordinary / not_ordinary / unclear, every one names an "
    "adjudicator the amendment permits, and the sample belongs to a generation "
    "the ledger records as disjoint from every earlier one")

DONE_WHEN_IMPLEMENTED: Dict[str, str] = {
    "freeze": ("a freeze record exists, an owner has acknowledged it, and "
               "every digest in it still matches what is on disk, including "
               "the digest of D-013 itself"),
    "adjudicate_30": _ADJUDICATED_DONE_WHEN,
    "extend_to_100": _ADJUDICATED_DONE_WHEN,
    "classify_alarms": "every alarm carries a non-empty failure_mode",
}

# The three stops, named apart. The kind travels with the state so that a
# reader — or the `--json` consumer — never has to infer which of them it is.
STOP_PREREQUISITE = "prerequisite"
STOP_GUARD = "guard"
STOP_OPEN_QUESTION = "open_question"

# States that prohibit an action outright, as against states that merely fail
# to establish it. The first group is exit 1; the second is exit 2, which a
# caller that spends money must also treat as denial.
DEFINITE_BLOCKERS = (NOT_DONE, BLOCKED_OWNER, GUARD_FAILED)

# Every key this tool acts on. Anything else in the block is a refusal: a
# parser that drops what it does not recognise reports the step as though the
# field had never been written.
TOP_LEVEL_KEYS = frozenset({"steps", "open_questions", "answered_questions",
                            "generations"})
QUESTION_KEYS = frozenset({"id", "asked_of", "text"})
ANSWER_KEYS = frozenset({"id", "answered_by", "answered_on", "text"})
# What this tool can actually do, as against what a block declares. These are
# not derived from anything and nothing derives from them: they are the
# behaviours the code implements, one per key, and they exist so that a
# declaration and its expectation cannot be changed together into something
# nobody wrote code for. Codex, 2026-09-04: changing `GENERATIONS_CONTRACT`
# and the block in step made parsing and divergence agree while
# `_change_identity` folded repository and commit regardless.
GENERATIONS_IMPLEMENTED = {
    "disjoint": ("required",),
    "status_values": (("current", "scored", "discarded"),),
    "adjudicable_status": ("current",),
    "identity": ("repo_and_commit_folded",),
    "on_overlap": ("refuse",),
    "on_repeat": ("refuse",),
}

GENERATIONS_CONTRACT = {
    "disjoint": "required",
    "records": ["id", "status", "case_identities"],
    "status_values": ["current", "scored", "discarded"],
    "adjudicable_status": "current",
    "identity": "repo_and_commit_folded",
    "on_overlap": "refuse",
    "on_repeat": "refuse",
}

# Derived, never restated. Codex, 2026-09-04: the contract constant was one
# of five places the shape was written down, so changing it moved what
# `divergence` expected and not what anything enforced. Every other statement
# of the shape now reads from it.
GENERATIONS_KEYS = frozenset(GENERATIONS_CONTRACT)
# What a failed guard may be declared to mean. One value, because D-013 states
# one: 5 or more unclear of the 30 makes the ordinary result invalid and the
# outcome undecided, and no case is redrawn. A second value belongs here only
# when a decision has named it — the list is short on purpose, so that a guard
# outcome nobody decided cannot be written into the block and acted on.
GUARD_OUTCOMES = frozenset({"undecided"})

# Vendors a model adjudicator may come from, per the owner's amendment to
# step 2 on 2026-09-04. One entry, and the list is short on purpose: the
# permission is about the vendor, not about being a model. Anthropic is absent
# deliberately — a Claude adjudicator shares the model family with the reviewer
# whose findings are scored, and that is the independence the rule protects.
PERMITTED_MODEL_VENDORS = frozenset({"xai"})

STEP_KEYS = frozenset({
    "id", "requires", "guard", "guard_field", "guard_below",
    "guard_failure_blocked_on", "on_guard_failed",
    "blocked_on_owner", "undefined_predicates",
    "needs_field", "needs_vocabulary_first", "next_generation", "done_when",
    "vocabulary", "requires_no_open_questions", "forbidden_values",
    # The baseline a step is measured against, named by the decision rather
    # than hard-coded here. A step that declares none gets `cannot tell` from
    # its preflight, which is the honest answer and not a default path.
    #
    # What it does *not* do: `sentinel_compare.py` takes its reference as a
    # positional argument, so nothing binds the file this tool reports on to
    # the file somebody eventually compares against. An earlier comment here
    # said the two "cannot inspect different files"; Codex refused it on
    # 2026-09-05, and it survived one round after the same sentence had been
    # corrected in DECISIONS.md and LIMITATIONS.md — a claim repeated in three
    # places is corrected in three places or it is still there.
    "reference",
})

# The one value of `next_generation` this tool can act on. Anything else is a
# refusal rather than a shrug: a step declaring a requirement nobody enforces
# is the false readiness the block exists to prevent.
NEXT_GENERATION_VALUES = ("required",)

# Where the ledger of generations lives. Nothing writes it yet, and that is
# reported rather than passed over: "the changes behind a result are never
# scored again" is a claim nothing enforces until something records which
# changes each generation scored.
DEFAULT_GENERATIONS = "measurements/ordinary-v1/generations.json"
GENERATIONS = "generations"

VERDICT_VALUES = ("ordinary", "not_ordinary", "unclear")

# Every file whose content decides what a paid run means. D-013 freezes "model,
# prompts, schema, verifier, gate, scorer, revision"; Codex added the sampling
# machinery on 2026-09-04, because the eligibility, stratification and drawing
# rules decide which changes are measured at all, and an edit to them between
# the freeze and the result changes the estimand without touching a prompt.
FROZEN_INPUTS: Tuple[Tuple[str, str], ...] = (
    ("prompts/system.md", "the reviewer's prompt"),
    ("prompts/verifier.md", "the verifier's prompt"),
    ("prompts/findings.schema.json", "the findings schema"),
    ("src/security_agent/gate.py", "the gate that turns findings into an exit code"),
    ("corpus-real/adjudications.yml", "the rulings a score is read through"),
    ("tools/pair_corpus.py", "the scorer"),
    ("tools/artifact.py", "the scorer's shared reader"),
    ("tools/check_accounted.py", "the accounting the scorer is read against"),
    ("tools/stop_rule.py", "the rule's own arithmetic"),
    ("tools/ordinary_corpus.py", "eligibility, stratification and the draw"),
)


# --------------------------------------------------------------------------
# digests


def sha256_file(path: Path) -> Optional[str]:
    """The digest, or `None` when the file cannot be read.

    `None`, never `""`. `round.digest_of` returns the empty string on `OSError`
    and is not reused here for that reason: an empty digest compares equal to
    another empty digest, so two unreadable files would verify as "unchanged"
    and a deleted frozen input would pass the freeze check. Absence is not
    agreement, and the caller has to say what it does about it.
    """
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return None


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def tree_digest(directory: Path, pattern: str) -> Optional[str]:
    """One digest over every matching file, path included.

    The path is hashed alongside the content so that renaming a module — or
    adding one — moves the digest. Hashing contents alone let a file that
    changed places look identical to one that did not.
    """
    if not directory.is_dir():
        return None
    parts = []
    for path in sorted(directory.rglob(pattern)):
        one = sha256_file(path)
        if one is None:
            return None
        parts.append("{}:{}".format(path.relative_to(directory), one))
    return sha256_text("|".join(parts))


# --------------------------------------------------------------------------
# the order block


class OrderError(Exception):
    """The rule cannot be read or is inconsistent. Always exit 2, never 1."""


class Question:
    def __init__(self, raw: Dict[str, Any]):
        self.id: str = raw["id"]
        self.asked_of: str = raw["asked_of"]
        self.text: str = " ".join(str(raw["text"]).split())

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return "Question({!r})".format(self.id)


class Answer:
    """A question the owner has closed, kept in the block rather than deleted.

    A step may still reference it. Deleting the question and leaving the
    reference would make the step look blocked on nothing; keeping the answer
    lets the tool say "answered on this date, by this person, thus" instead.
    """

    def __init__(self, raw: Dict[str, Any]):
        self.id: str = raw["id"]
        self.answered_by: str = raw["answered_by"]
        self.answered_on: str = str(raw["answered_on"])
        self.text: str = " ".join(str(raw["text"]).split())

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return "Answer({!r})".format(self.id)


class Step:
    """One step of the order, exactly as the block declares it."""

    def __init__(self, raw: Dict[str, Any]):
        self.raw = raw
        self.id: str = raw["id"]
        self.requires: List[str] = raw["requires"]
        self.guard: Optional[str] = raw.get("guard")
        self.guard_field: Optional[str] = raw.get("guard_field")
        self.guard_below: Optional[float] = raw.get("guard_below")
        self.guard_failure_blocked_on: Optional[str] = raw.get(
            "guard_failure_blocked_on")
        self.on_guard_failed: Optional[str] = raw.get("on_guard_failed")
        self.blocked_on_owner: Optional[str] = raw.get("blocked_on_owner")
        self.undefined_predicates: List[str] = raw.get(
            "undefined_predicates") or []
        self.needs_field: Optional[str] = raw.get("needs_field")
        self.needs_vocabulary_first: bool = raw.get(
            "needs_vocabulary_first") is True
        self.next_generation: Optional[str] = raw.get("next_generation")
        self.done_when: str = raw["done_when"]
        # The permitted values, written in the decision rather than inferred
        # from what has already been classified. Absent is the honest state
        # today: nobody has written one.
        self.vocabulary: List[str] = list(raw.get("vocabulary") or [])
        # Values a decision has ruled out, as against a list of the only ones
        # allowed. `fix-incomplete` is here because it describes the corpus's
        # fix and not a way the reviewer failed: the reviewer may be entirely
        # right that the weakness persists. Recorded as corpus validity
        # instead, and refused as a cause.
        self.forbidden_values: List[str] = list(
            raw.get("forbidden_values") or [])
        # A step that cannot be taken while any question in this file is
        # unanswered. `freeze` carries it because the freeze digests D-013:
        # answering a question edits the text that was frozen, so a freeze
        # taken with one open is invalid from the owner's next sentence.
        self.requires_no_open_questions: bool = \
            raw.get("requires_no_open_questions") is True
        # Repository-relative, and read only as text here: what it points at is
        # judged by the tool that owns the format, not by this one.
        self.reference: Optional[str] = raw.get("reference")

    @property
    def criterion_undefined(self) -> bool:
        return self.done_when.strip() == UNDEFINED

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return "Step({!r})".format(self.id)


class Order:
    def __init__(self, steps: List[Step], questions: Dict[str, Question],
                 answers: Dict[str, Answer],
                 generations: Optional[Dict[str, Any]]):
        self.steps = steps
        self.questions = questions
        self.answers = answers
        self.generations = generations

    def question(self, ident: Optional[str]) -> Optional[Question]:
        return self.questions.get(ident) if ident else None

    def answer(self, ident: Optional[str]) -> Optional[Answer]:
        return self.answers.get(ident) if ident else None


def fence_transition(line: str, opener: str) -> Tuple[Optional[str], bool]:
    """What this line does to a fence: opens one, closes `opener`, or neither.

    **One implementation, used by both scanners.** There were two, and only one
    of them was repaired: `fenced_blocks` learnt CommonMark's rules while
    `d013_section_text` went on toggling on any line whose first non-space
    characters were three backticks. That second scanner is the one the freeze
    digests D-013 with, so a stray fence-like line could shorten the frozen
    text and let everything after it change without the freeze noticing — the
    exact defect a test already pinned for a different cause. Codex, 2026-09-04.

    The rules kept, and each was a hole when it was missing: at most three
    spaces of indent (`lstrip()` accepted any); the same fence character, at
    least as long as the opener; an empty info string on the closer; and no
    backtick in a backtick fence's info string, which CommonMark forbids and
    which would otherwise open a fence on a line of prose quoting code.

    Returns `(opened, closes)` — `opened` is the fence that a *new* block would
    start with, and `closes` says whether this line ends the one `opener`
    started. A line can be both when nothing is open yet, and the caller
    decides by its own state which reading applies.
    """
    match = re.match(r"( {0,3})(`{3,}|~{3,})(.*)$", line)
    if match is None:
        return None, False
    fence, info = match.group(2), match.group(3)
    closes = bool(opener) and fence[0] == opener[0] \
        and len(fence) >= len(opener) and not info.strip()
    opens = None if (fence[0] == "`" and "`" in info) else fence
    return opens, closes


def fenced_blocks(text: str) -> List[str]:
    """The bodies of every fenced block in a markdown file.

    Written here rather than borrowed from `check_decisions.blank_fences`,
    which blanks the blocks so the prose can be parsed — the opposite need.

    A fence closes only on the **same character, at least as long** as the one
    that opened it, and an opening fence's info string is not a closer. The
    first version toggled on any line starting with three backticks, so a line
    inside a YAML scalar could end the block early and the parser would then
    read a prefix as though it were the whole order — losing, say, the
    `open_questions` that keep a step stopped. Codex, 2026-09-04.
    """
    blocks: List[str] = []
    body: Optional[List[str]] = None
    opener = ""
    for line in text.splitlines():
        opened, closed = fence_transition(line, opener)
        if opened and body is None:
            opener = opened
            body = []
            continue
        if closed and body is not None:
            blocks.append("\n".join(body))
            body = None
            opener = ""
            continue
        if body is not None:
            body.append(line)
    # An unterminated fence is a broken document, not an empty block: handing
    # back what was collected would return a truncated order as if it were the
    # whole one.
    if body is not None:
        raise OrderError(
            "the markdown has an unterminated ``` fence, so the order block "
            "cannot be delimited — close the fence in DECISIONS.md")
    return blocks


def find_order_block(text: str) -> str:
    """The one block marked `# d013-order`, found by its marker."""
    found = [b for b in fenced_blocks(text)
             if b.strip().splitlines()[:1] == [BLOCK_MARKER]]
    if not found:
        raise OrderError(
            "DECISIONS.md has no machine-readable order: no fenced block whose "
            "first line is `{}`. Add the block under D-013's \"### The order\" "
            "— this tool will not fall back to parsing the prose, which "
            "carried four contradictions on 2026-09-04.".format(BLOCK_MARKER))
    if len(found) > 1:
        raise OrderError(
            "DECISIONS.md has {} blocks marked `{}` and there must be exactly "
            "one — delete the copies, keeping the one under \"### The order\"."
            .format(len(found), BLOCK_MARKER))
    return found[0]


def _reject_unknown(where: str, entry: Dict[str, Any],
                    allowed: frozenset) -> None:
    """Any key this tool does not act on stops it.

    The first parser kept `id` and `requires` and dropped the rest in silence,
    which would have reported a step blocked on an unanswered question as ready
    to run. A field nobody reads is worse than a field nobody wrote.
    """
    unknown = sorted(set(entry) - allowed)
    if unknown:
        raise OrderError(
            "{} carries {} which this tool does not act on. It refuses rather "
            "than dropping them: a field silently ignored reports the step as "
            "though it had never been written. Either teach "
            "tools/d013_order.py the field, or remove it from the block. "
            "Known: {}".format(where, ", ".join(repr(k) for k in unknown),
                               ", ".join(sorted(allowed))))


class _NoDuplicateKeys(yaml.SafeLoader):
    """A loader that refuses a repeated key instead of keeping the last one.

    `yaml.safe_load` resolves a duplicate silently and quietly: the last
    occurrence wins and nothing is reported. Codex, 2026-09-04, on this file —
    the refusal of unknown fields runs *after* loading, so it never sees the
    key that was overwritten. A second `requires:` on one step therefore
    replaced the first, and

        - id: adjudicate_30
          requires: [freeze]
          requires: []

    parsed as a step waiting for nothing. The whole order can be flattened that
    way with no unknown field, no schema error and no warning — the block's
    protections all sit downstream of a value that has already been thrown
    away.

    This is the same shape the project keeps finding elsewhere: something
    missing read as agreement. Here the *first* value goes missing, and its
    absence reads as though it had never been written.
    """


def _refuse_duplicate_keys(loader, node, deep=False):
    seen = set()
    for key_node, _ in node.value:
        # `<<:` merges another mapping in, which puts values under keys that
        # were never written here — the same invisibility as a duplicate, by a
        # different route. It already failed, but with "could not determine a
        # constructor for the tag merge", which tells the author nothing about
        # what to do. A refusal without a remedy gets reworded past.
        if key_node.tag == "tag:yaml.org,2002:merge":
            raise OrderError(
                "the order block uses a YAML merge key `<<` (line {}). It "
                "puts fields on a step that are not written on it, which is "
                "the same invisibility this loader refuses duplicates for — "
                "write each step's fields out".format(
                    key_node.start_mark.line + 1))
        key = loader.construct_object(key_node, deep=deep)
        if key in seen:
            raise OrderError(
                "the order block sets {!r} twice in one mapping (line {}). "
                "YAML would keep only the last, so the first is discarded "
                "without a word — write the key once".format(
                    key, key_node.start_mark.line + 1))
        seen.add(key)
    return yaml.SafeLoader.construct_mapping(loader, node, deep=deep)


_NoDuplicateKeys.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _refuse_duplicate_keys)


def parse_order(text: str) -> Order:
    """The steps and the open questions, with every field required or refused."""
    body = find_order_block(text)
    try:
        data = yaml.load(body, Loader=_NoDuplicateKeys)
    except yaml.YAMLError as exc:
        raise OrderError(
            "the order block is not valid YAML: {}".format(exc)) from exc
    if not isinstance(data, dict):
        raise OrderError("the order block is not a mapping")
    _reject_unknown("the order block", data, TOP_LEVEL_KEYS)

    questions = _parse_questions(data.get("open_questions"))
    answers = _parse_answers(data.get("answered_questions"), questions)
    generations = _parse_generations(data.get("generations"))

    if "steps" not in data:
        raise OrderError("the order block has no `steps:` key")
    raw = data["steps"]
    if not isinstance(raw, list) or not raw:
        raise OrderError("`steps:` must be a non-empty list")

    steps: List[Step] = []
    seen: Dict[str, int] = {}
    for index, entry in enumerate(raw, start=1):
        if not isinstance(entry, dict):
            raise OrderError("step {} is not a mapping".format(index))
        ident = entry.get("id")
        if not isinstance(ident, str) or not ident.strip():
            raise OrderError("step {} has no usable `id`".format(index))
        ident = ident.strip()
        _reject_unknown("step {!r}".format(ident), entry, STEP_KEYS)
        if ident in seen:
            raise OrderError("step id {!r} appears twice, at {} and {}".format(
                ident, seen[ident], index))
        seen[ident] = index
        normal = dict(entry)
        normal["id"] = ident
        if isinstance(entry.get("reference"), str):
            # Stored as validated. Codex, 2026-09-05: `_check_rest` judged the
            # stripped text and `Step` kept the original, so a value with
            # surrounding whitespace passed the containment rules and then
            # addressed a different pathname.
            normal["reference"] = entry["reference"].strip()
        normal["requires"] = _id_list(entry, "requires", ident)
        _check_guard(entry, ident, questions)
        _check_rest(entry, ident, questions, answers)
        steps.append(Step(normal))

    known = {s.id for s in steps}
    for step in steps:
        for need in step.requires:
            if need not in known:
                raise OrderError(
                    "step {!r} requires {!r}, which is not a step id in the "
                    "block".format(step.id, need))
            if need == step.id:
                raise OrderError("step {!r} requires itself".format(step.id))
    order = Order(steps, questions, answers, generations)
    order_steps_topologically(steps)      # raises on a cycle
    return order


def _parse_questions(raw: Any) -> Dict[str, Question]:
    if raw is None:
        return {}
    if not isinstance(raw, list):
        raise OrderError("`open_questions:` must be a list")
    out: Dict[str, Question] = {}
    for index, entry in enumerate(raw, start=1):
        if not isinstance(entry, dict):
            raise OrderError("open question {} is not a mapping".format(index))
        ident = entry.get("id")
        if not isinstance(ident, str) or not ident.strip():
            raise OrderError("open question {} has no `id`".format(index))
        ident = ident.strip()
        _reject_unknown("open question {!r}".format(ident), entry,
                        QUESTION_KEYS)
        for key in ("asked_of", "text"):
            if not isinstance(entry.get(key), str) or not entry[key].strip():
                raise OrderError(
                    "open question {!r} has no `{}` — a question with no text, "
                    "or nobody it is asked of, cannot be reported to anybody"
                    .format(ident, key))
        if ident in out:
            raise OrderError("open question id {!r} appears twice".format(ident))
        out[ident] = Question(dict(entry, id=ident))
    return out


def _parse_answers(raw: Any, questions: Dict[str, Question]
                   ) -> Dict[str, Answer]:
    if raw is None:
        return {}
    if not isinstance(raw, list):
        raise OrderError("`answered_questions:` must be a list")
    out: Dict[str, Answer] = {}
    for index, entry in enumerate(raw, start=1):
        if not isinstance(entry, dict):
            raise OrderError("answered question {} is not a mapping"
                             .format(index))
        ident = entry.get("id")
        if not isinstance(ident, str) or not ident.strip():
            raise OrderError("answered question {} has no `id`".format(index))
        ident = ident.strip()
        _reject_unknown("answered question {!r}".format(ident), entry,
                        ANSWER_KEYS)
        for key in ("answered_by", "answered_on", "text"):
            if entry.get(key) in (None, ""):
                raise OrderError(
                    "answered question {!r} has no `{}` — an answer with no "
                    "author, date or text cannot be told from an assertion"
                    .format(ident, key))
        if ident in out:
            raise OrderError("answered question id {!r} appears twice"
                             .format(ident))
        if ident in questions:
            raise OrderError(
                "{!r} is listed as both open and answered — one of the two "
                "entries is stale, and a step referencing it would get "
                "whichever this tool happened to read first".format(ident))
        out[ident] = Answer(dict(entry, id=ident))
    return out


def _parse_generations(raw: Any) -> Optional[Dict[str, Any]]:
    """The rule that separates a fresh draw from a re-reading.

    The owner decided on 2026-09-04 that tuning is permitted and the next
    measurement must be on changes never scored before. Without a record of
    which changes each generation scored, that is a claim nothing enforces —
    which is the defect this file exists to catch. So the shape is validated
    here and the ledger is checked below; a value this tool cannot enforce is
    refused rather than accepted and ignored.
    """
    if raw is None:
        return None
    if not isinstance(raw, dict):
        raise OrderError("`generations:` must be a mapping")
    _reject_unknown("`generations`", raw, GENERATIONS_KEYS)
    if raw.get("disjoint") != GENERATIONS_CONTRACT["disjoint"]:
        raise OrderError(
            "`generations.disjoint` is {!r}; this tool enforces only "
            "{!r}. Anything else is a rule it would accept and not "
            "apply".format(raw.get("disjoint"),
                           GENERATIONS_CONTRACT["disjoint"]))
    if raw.get("on_overlap") != GENERATIONS_CONTRACT["on_overlap"]:
        raise OrderError(
            "`generations.on_overlap` is {!r}; this tool enforces only "
            "'refuse'. A warning it cannot issue is not an enforcement"
            .format(raw.get("on_overlap")))
    records = raw.get("records")
    if not isinstance(records, list) or not records or \
            not all(isinstance(name, str) and name.strip() for name in records):
        raise OrderError(
            "`generations.records` must be a non-empty list of field names — "
            "they are what a generation has to carry for a later draw to be "
            "shown disjoint from it")
    # Every declared key carried through, not three of them. Returning a
    # filtered dict dropped the rest silently — the defect this tool exists to
    # refuse, inside the tool. `divergence` then reported them as missing from
    # a block that declared them. Codex, 2026-09-04.
    out = dict(raw)
    out["records"] = [name.strip() for name in records]
    return out


def _id_list(entry: Dict[str, Any], key: str, ident: str) -> List[str]:
    if key not in entry:
        raise OrderError(
            "step {!r} has no `{}:` key. Write `{}: []` if it waits for "
            "nothing — omitting the key and meaning that are indistinguishable, "
            "and this tool will not guess.".format(ident, key, key))
    value = entry[key]
    if value is None or not isinstance(value, list):
        raise OrderError(
            "step {!r}: `{}` must be a list (use `[]` for none)".format(
                ident, key))
    names = []
    for item in value:
        if not isinstance(item, str) or not item.strip():
            raise OrderError(
                "step {!r} has an entry under `{}` that is not a step id"
                .format(ident, key))
        names.append(item.strip())
    return names


def _check_guard(entry: Dict[str, Any], ident: str,
                 questions: Dict[str, Question]) -> None:
    """A guard is all four fields or none of them.

    Three of the four would leave a condition nobody can evaluate looking like
    a step with no condition — the permissive reading, and the one that lets a
    guarded step run unguarded.
    """
    # The fourth key says what a failed guard *means*, and it is one of two
    # shapes: `guard_failure_blocked_on`, naming an open question, while the
    # decision has not said; or `on_guard_failed`, once it has. Exactly one,
    # never both — carrying both would be a step that is simultaneously waiting
    # for an answer and acting on one.
    outcome_keys = ("guard_failure_blocked_on", "on_guard_failed")
    keys = ("guard", "guard_field", "guard_below")
    present = [k for k in keys + outcome_keys if k in entry]
    if not present:
        return
    stated = [k for k in outcome_keys if k in entry]
    if len(stated) != 1:
        raise OrderError(
            "step {!r} declares {} of {} — a guarded step needs exactly one: "
            "`guard_failure_blocked_on` while the decision has not said what a "
            "failed guard means, `on_guard_failed` once it has".format(
                ident, ", ".join(stated) or "neither",
                " and ".join(outcome_keys)))
    missing = [k for k in keys if k not in entry]
    if missing:
        raise OrderError(
            "step {!r} declares {} and not {} — a guard needs all four, or a "
            "condition nobody can evaluate reads as no condition at all"
            .format(ident, ", ".join(present), ", ".join(missing)))
    if not isinstance(entry["guard"], str) or not entry["guard"].strip():
        raise OrderError("step {!r}: `guard` must state the condition"
                         .format(ident))
    if not isinstance(entry["guard_field"], str) or \
            not entry["guard_field"].strip():
        raise OrderError("step {!r}: `guard_field` must name a metric"
                         .format(ident))
    if isinstance(entry["guard_below"], bool) or \
            not isinstance(entry["guard_below"], (int, float)):
        raise OrderError("step {!r}: `guard_below` must be a number"
                         .format(ident))
    if "guard_failure_blocked_on" in entry:
        blocked = entry["guard_failure_blocked_on"]
        if not isinstance(blocked, str) or blocked.strip() not in questions:
            raise OrderError(
                "step {!r}: `guard_failure_blocked_on` is {!r}, which is not an "
                "id under `open_questions`. The prose says when the step runs "
                "and not what happens when the guard fails; that gap has to be "
                "a written question, not a default in this tool".format(
                    ident, blocked))
    else:
        outcome = entry["on_guard_failed"]
        if not isinstance(outcome, str) or outcome.strip() not in GUARD_OUTCOMES:
            raise OrderError(
                "step {!r}: `on_guard_failed` is {!r}; this tool acts on {}. A "
                "value it cannot act on is a decision it would have to invent"
                .format(ident, outcome, ", ".join(sorted(GUARD_OUTCOMES))))


def _check_rest(entry: Dict[str, Any], ident: str,
                questions: Dict[str, Question],
                answers: Dict[str, Answer]) -> None:
    if "undefined_predicates" in entry:
        value = entry["undefined_predicates"]
        if not isinstance(value, list) or not value:
            raise OrderError(
                "step {!r}: `undefined_predicates` must be a non-empty list"
                .format(ident))
    if "blocked_on_owner" in entry:
        value = entry["blocked_on_owner"]
        # Either list will do: an answered question keeps its entry, and a step
        # still pointing at it is reported as answered rather than as blocked.
        # Deleting the question and leaving the reference would make the step
        # look blocked on nothing.
        if not isinstance(value, str) or (
                value.strip() not in questions and value.strip() not in answers):
            raise OrderError(
                "step {!r}: `blocked_on_owner` is {!r}, which is not an id "
                "under `open_questions` or `answered_questions` — a step "
                "blocked on a question nobody wrote down cannot be reported to "
                "the person who has to answer it".format(ident, value))
    if "needs_field" in entry and (not isinstance(entry["needs_field"], str)
                                   or not entry["needs_field"].strip()):
        raise OrderError("step {!r}: `needs_field` must name a field"
                         .format(ident))
    if "reference" in entry:
        # Codex, 2026-09-05: the new field went straight into `Step` and past
        # every rule this function exists for. `reference: false` or `[]` was
        # accepted and then reported downstream as "the decision names no
        # reference", which is the *absent* case wearing the clothes of a
        # written one — an author who declared a baseline and mistyped it would
        # be told none was declared.
        value = entry["reference"]
        if not isinstance(value, str) or not value.strip():
            raise OrderError(
                "step {!r}: `reference` is {!r} and it must be a path. A value "
                "the tool cannot use is refused here rather than reported "
                "later as though no baseline had been named at all"
                .format(ident, value))
        text = value.strip()
        # Repository-relative, and that is checked rather than documented. An
        # absolute path or one climbing out of the tree would have the order
        # tool judging a file outside the repository whose state nothing else
        # here records.
        if PurePosixPath(text).is_absolute() or Path(text).is_absolute() \
                or ".." in PurePosixPath(text).parts:
            raise OrderError(
                "step {!r}: `reference` is {!r}; it must be relative to the "
                "repository and must not climb out of it, or the order would "
                "be judging a file nothing else here records"
                .format(ident, text))
    # Both booleans, and both validated: `is True` reads "true" and 1 and
    # anything else as *off*, so an author who wrote `requires_no_open_questions:
    # "true"` would get a step that silently lost its protection. The parser's
    # own rule is that a field it understands but cannot act on is a refusal.
    for flag in ("needs_vocabulary_first", "requires_no_open_questions"):
        if flag in entry and not isinstance(entry[flag], bool):
            raise OrderError(
                "step {!r}: `{}` is {!r}; it must be true or false. A quoted "
                "or numeric value reads as false and the step loses the rule "
                "without a word".format(ident, flag, entry[flag]))

    # Both are lists of names, and `list(...)` in the constructor would have
    # accepted a mapping (its keys), a number (an error), or a mixed list — so
    # `forbidden_values: {fix-incomplete: true}` would have silently become
    # `["fix-incomplete"]` and a stray integer would have compared equal to
    # nothing. A rule this tool enforces has to have a shape it checked.
    for listed in ("vocabulary", "forbidden_values"):
        if listed not in entry:
            continue
        values = entry[listed]
        if not isinstance(values, list) or not all(
                isinstance(v, str) and v.strip() for v in values):
            raise OrderError(
                "step {!r}: `{}` must be a list of non-empty names; it is {!r}"
                .format(ident, listed, values))
        if not values:
            # An empty list is a key that reads as a rule and forbids nothing.
            # `vocabulary: []` was exactly that once, and it made a step
            # impossible rather than unfinished. Leave the key out instead.
            raise OrderError(
                "step {!r}: `{}` is empty — a key that states a rule and "
                "applies to nothing. Leave it out, or name the values"
                .format(ident, listed))
        if len(set(values)) != len(values):
            raise OrderError(
                "step {!r}: `{}` repeats a name — one of them does nothing, "
                "and which one is not visible from the block".format(
                    ident, listed))
    # Required, not defaulted. A step with no `done_when` is a step whose
    # completion nothing records, and letting it default to anything is the
    # false readiness this key was added to stop.
    if "done_when" not in entry or not isinstance(entry["done_when"], str) \
            or not entry["done_when"].strip():
        raise OrderError(
            "step {!r} has no `done_when:`. Write `done_when: {}` if no "
            "artifact records that it finished — that is an honest state with "
            "its own exit code, and omitting the key is not the same claim"
            .format(ident, UNDEFINED))
    if "next_generation" in entry and \
            entry["next_generation"] not in NEXT_GENERATION_VALUES:
        raise OrderError(
            "step {!r}: `next_generation` is {!r}; this tool acts on {} and "
            "refuses anything else rather than declaring a requirement it does "
            "not apply".format(ident, entry["next_generation"],
                               ", ".join(NEXT_GENERATION_VALUES)))


def order_steps_topologically(steps: Sequence[Step]) -> List[Step]:
    """Block order, with every prerequisite ahead of its dependant."""
    by_id = {s.id: s for s in steps}
    placed: List[Step] = []
    state: Dict[str, int] = {}

    def visit(step: Step, trail: List[str]) -> None:
        mark = state.get(step.id, 0)
        if mark == 2:
            return
        if mark == 1:
            raise OrderError("the order has a cycle: {}".format(
                " -> ".join([*trail, step.id])))
        state[step.id] = 1
        for need in step.requires:
            visit(by_id[need], [*trail, step.id])
        state[step.id] = 2
        placed.append(step)

    for step in steps:
        visit(step, [])
    return placed


def transitive_requirements(steps: Sequence[Step], ident: str) -> List[str]:
    by_id = {s.id: s for s in steps}
    out: List[str] = []
    queue = list(by_id[ident].requires)
    while queue:
        need = queue.pop(0)
        if need in out:
            continue
        out.append(need)
        queue.extend(by_id[need].requires)
    return out


def target_from_id(ident: str) -> Optional[int]:
    """The number the step id carries, e.g. `adjudicate_30` -> 30.

    Taken from the id rather than written here, so that changing the size of
    the corpus in `DECISIONS.md` changes what the checker demands. A step id
    with no number gets `None`, and its checker says so instead of assuming.
    """
    found = re.findall(r"\d+", ident)
    return int(found[-1]) if found else None


# --------------------------------------------------------------------------
# the context every checker reads


class Result:
    def __init__(self, state: str, evidence: str,
                 stopped_by: Optional[str] = None):
        if state not in STATES:
            raise ValueError("unknown state {!r}".format(state))
        self.state = state
        self.evidence = evidence
        self.stopped_by = stopped_by

    def as_dict(self) -> Dict[str, Optional[str]]:
        return {"state": self.state, "evidence": self.evidence,
                "stopped_by": self.stopped_by}

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return "Result({!r}, {!r})".format(self.state, self.evidence)


class Context:
    """Everything a checker is allowed to read, and where it lives.

    The ordinary corpus lives outside the repository today
    (`/tmp/ordinary-clones/`), so its location is a flag rather than a
    constant. Absent, the checker says `cannot tell` — never `not done`: work
    the tool was not shown is not work that did not happen.
    """

    def __init__(self, root: Path = ROOT, decisions: Optional[Path] = None,
                 freeze: Optional[Path] = None,
                 ordinary_dir: Optional[Path] = None,
                 ordinary_manifest: Optional[Path] = None,
                 ordinary_adjudications: Optional[Path] = None,
                 generations: Optional[Path] = None,
                 alarm_reader: Optional[Callable[[str], Dict[str, Any]]] = None):
        self.root = Path(root)
        self.decisions = Path(decisions) if decisions else self.root / "DECISIONS.md"
        self.freeze = Path(freeze) if freeze else self.root / DEFAULT_FREEZE
        self.generations = (Path(generations) if generations
                            else self.root / DEFAULT_GENERATIONS)
        self.ordinary_dir = Path(ordinary_dir) if ordinary_dir else None
        self._manifest = Path(ordinary_manifest) if ordinary_manifest else None
        self._adjudications = (Path(ordinary_adjudications)
                               if ordinary_adjudications else None)
        self.alarm_reader = alarm_reader
        self._cache: Dict[str, Any] = {}

    @property
    def ordinary_manifest(self) -> Optional[Path]:
        if self._manifest is not None:
            return self._manifest
        if self.ordinary_dir is not None:
            return self.ordinary_dir / "manifest.json"
        return None

    @property
    def ordinary_adjudications(self) -> Optional[Path]:
        if self._adjudications is not None:
            return self._adjudications
        if self.ordinary_dir is not None:
            return self.ordinary_dir / "adjudications.yml"
        return None

    def cached(self, key: str, produce: Callable[[], Any]) -> Any:
        if key not in self._cache:
            self._cache[key] = produce()
        return self._cache[key]

    def d013_section(self) -> Optional[str]:
        return self.cached("d013", lambda: d013_section_text(self.decisions))

    def ordinary_cases(self) -> Tuple[Optional[Dict[str, Any]], str]:
        """The adjudication file's cases, or `None` and why not."""
        return self.cached("ordinary_cases", self._read_ordinary_cases)

    def _read_ordinary_cases(self) -> Tuple[Optional[Dict[str, Any]], str]:
        path = self.ordinary_adjudications
        if path is None:
            return None, (
                "no ordinary-corpus adjudication file was named — pass "
                "`--ordinary-dir DIR` (the corpus lives outside the repository "
                "today) or set D013_ORDINARY_DIR")
        if not path.is_file():
            return None, "{} is not a readable file".format(path)
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as exc:
            return None, "{} could not be parsed: {}".format(path, exc)
        if not isinstance(data, dict):
            return None, "{} is not a mapping".format(path)
        cases = data.get("cases")
        if not isinstance(cases, dict):
            return None, "{} has no `cases:` mapping".format(path)
        return cases, "read {} case(s) from {}".format(len(cases), path)

    def alarms(self, needs_field: str) -> Dict[str, Any]:
        """The alarm-on-the-fix picture, from the measurement artifacts.

        Injectable so the tests can exercise every state without a corpus. The
        real reader is imported lazily: `artifact` pulls in `security_agent`,
        and a tool that cannot import it must still answer about the steps that
        do not need it.
        """
        if self.alarm_reader is not None:
            return self.alarm_reader(needs_field)
        return self.cached("alarms:" + needs_field,
                           lambda: read_alarms(self.root, needs_field))


def read_alarms(root: Path, needs_field: str) -> Dict[str, Any]:
    """Cases whose latest row alarmed on the fixed member, and their rulings."""
    tools = str(Path(root) / "tools")
    src = str(Path(root) / "src")
    for entry in (tools, src):
        if entry not in sys.path:
            sys.path.insert(0, entry)
    try:
        import stop_rule
        from artifact import independence, load_adjudications
    except Exception as exc:                   # reported, never hidden
        return {"error": "the measurement readers could not be imported: "
                         "{}".format(exc)}
    try:
        rows = stop_rule.latest_rows()
        rulings = load_adjudications(Path(root) / "corpus-real")
    except Exception as exc:
        return {"error": "the measurement artifacts could not be read: "
                         "{}".format(exc)}
    # `is True`, never `bool(...)`: `pair_corpus` writes this field only on the
    # success path, so a review that crashed carries `None` — and `bool(None)`
    # is `False`, which would score a run that never happened as "no alarm".
    fired = sorted(case for case, row in rows.items()
                   if row.get("safe_false_positive") is True)
    try:
        independent = independence(rulings)
    except Exception:
        independent = None
    return dict(classify_alarm_counts(fired, rulings, needs_field),
                rows=len(rows), independence=independent)


def classify_alarm_counts(fired: Sequence[str],
                          rulings: Sequence[Dict[str, Any]],
                          needs_field: str) -> Dict[str, Any]:
    """Which alarms are ruled, and which of those name a cause.

    Split out from the reader so the tests can drive it with rows they build,
    and because the distinction it draws is the whole point of the step. A
    ruling answers whether a finding is *correct* — `real`, `not_real`,
    `incidental`. The tuning step asks whether the alarms share a **cause**, and
    a correctness verdict does not answer that. On 2026-09-04 all 20 alarms
    carried a ruling, 20 of the 21 rulings said `real`, none carried a
    `failure_mode`, and the step was reported done on the strength of the
    rulings alone.
    """
    ruled: Dict[str, int] = {}
    caused: Dict[str, int] = {}
    vocabulary: Dict[str, int] = {}
    for row in rulings or []:
        if not isinstance(row, dict) or row.get("member") != "safe":
            continue
        case_id = row.get("case_id")
        value = row.get(needs_field)
        # Required, not forbidden: a missing key, `None` and `""` are all "no
        # cause named", and only a non-empty string says otherwise.
        named = isinstance(value, str) and bool(value.strip())
        if named:
            key = value.strip()
            vocabulary[key] = vocabulary.get(key, 0) + 1
        if not case_id:
            continue
        ruled[case_id] = ruled.get(case_id, 0) + 1
        if named:
            caused[case_id] = caused.get(case_id, 0) + 1
    return {
        "fired": list(fired),
        "unruled": [case for case in fired if case not in ruled],
        "uncaused": [case for case in fired if case not in caused],
        "vocabulary": vocabulary,
    }


def d013_section_text(decisions: Path) -> Optional[str]:
    """The D-013 section, heading included, or `None` if it is not there.

    Delimited by the next `## ` or `# ` heading. `###` does not end it: the
    section's own subsections are part of what is frozen, and the block this
    tool reads lives in one of them.

    **Fenced blocks are skipped when looking for that heading.** The order
    block's first line is `# d013-order`, a YAML comment — read as a heading it
    ended the section right there, so the freeze recorded D-013 down to the
    fence and everything after it, the machine-readable order included, could
    be edited without the freeze noticing. Caught by
    `tests/test_d013_order.py::test_d013_edited_after_the_freeze`.
    """
    try:
        text = decisions.read_text(encoding="utf-8")
    except OSError:
        return None
    lines = text.splitlines()
    start = None
    for index, line in enumerate(lines):
        if line.startswith("## D-013"):
            start = index
            break
    if start is None:
        return None
    end = len(lines)
    opener = ""
    for index in range(start + 1, len(lines)):
        line = lines[index]
        # The same fence rules as `fenced_blocks`, from the same function.
        # This scanner had its own, cruder copy, and it is the one the freeze
        # digest is taken through — see `fence_transition`.
        opened, closed = fence_transition(line, opener)
        if opener and closed:
            opener = ""
            continue
        if not opener and opened:
            opener = opened
            continue
        if opener:
            continue
        if line.startswith("## ") or (line.startswith("# ")
                                      and not line.startswith("## ")):
            end = index
            break
    else:
        # Ran to the end of the file with a fence still open. `parse_order`
        # refuses this document and this function used to return the section
        # anyway — silently swallowing every decision after D-013, so the
        # freeze would digest them too and editing an unrelated decision would
        # break it. Two readers of one file disagreeing about where it ends is
        # not a state to answer from. Codex, 2026-09-04, on the edges.
        if opener:
            raise OrderError(
                "the D-013 section has an unterminated {} fence, so where it "
                "ends cannot be established — close the fence in {}".format(
                    opener, decisions))
    return "\n".join(lines[start:end]).rstrip() + "\n"


# --------------------------------------------------------------------------
# guard metrics: the numbers a `guard_field` names


def metric_unclear_count(ctx: Context) -> Tuple[Optional[float], str]:
    cases, why = ctx.ordinary_cases()
    if cases is None:
        return None, why
    counts = _verdict_counts(cases)
    if counts["missing"]:
        return None, (
            "{} of {} verdicts are still unfilled, so the unclear count is not "
            "final — a null verdict must never be read as `ordinary`".format(
                counts["missing"], len(cases)))
    return float(counts["unclear"]), "{} of {} adjudicated `unclear`".format(
        counts["unclear"], len(cases))


GUARD_METRICS: Dict[str, Callable[[Context], Tuple[Optional[float], str]]] = {
    "unclear_count": metric_unclear_count,
}


# --------------------------------------------------------------------------
# the checkers


def check_freeze(ctx: Context, step: Step) -> Result:
    """The artifact exists, and everything it froze still matches.

    A freeze that cannot be re-verified is an assertion, not a freeze.
    """
    return ctx.cached("freeze_result", lambda: _check_freeze(ctx))


def _check_freeze(ctx: Context) -> Result:
    path = ctx.freeze
    if not path.exists():
        return Result(NOT_DONE, (
            "no freeze artifact at {} — run `tools/d013_order.py freeze --out "
            "{}` before anything that spends money".format(path, path)))
    if not path.is_file():
        return Result(UNKNOWN, "{} exists and is not a file".format(path))
    try:
        body = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return Result(UNKNOWN, "{} could not be read: {}".format(path, exc))
    if not isinstance(body, dict):
        return Result(UNKNOWN, "{} is not a JSON object".format(path))
    if body.get("schema") != FREEZE_SCHEMA:
        return Result(UNKNOWN, (
            "{} declares schema {!r}, this tool reads {!r} — re-freeze, or "
            "point `--freeze-file` at the right artifact".format(
                path, body.get("schema"), FREEZE_SCHEMA)))

    problems = _freeze_problems(ctx, body)
    if problems:
        tail = ("; and {} more".format(len(problems) - 6)
                if len(problems) > 6 else "")
        return Result(NOT_DONE, (
            "the freeze at {} no longer describes what is on disk: {}{}".format(
                path, "; ".join(problems[:6]), tail)))
    return Result(DONE, (
        "{} verifies: {} frozen input(s) unchanged, the D-013 section matches "
        "its recorded text, commit {} acknowledged by {!r}".format(
            path, len(body.get("inputs") or {}),
            (body.get("git") or {}).get("commit", "?"),
            body.get("owner_acknowledgement"))))


def _freeze_problems(ctx: Context, body: Dict[str, Any]) -> List[str]:
    """Every way the recorded freeze and the working tree disagree.

    Required, not forbidden. The first draft asked "does anything contradict
    the freeze", which passes a freeze with no inputs recorded at all — the
    empty case is the one that slips through, and it is the shape this
    repository keeps finding in itself.
    """
    problems: List[str] = []

    ack = body.get("owner_acknowledgement")
    if not isinstance(ack, str) or not ack.strip():
        problems.append("no `owner_acknowledgement` — a freeze nobody signed "
                        "is a file, not a decision")

    git = body.get("git")
    if not isinstance(git, dict) or not isinstance(git.get("commit"), str) \
            or not git.get("commit", "").strip():
        problems.append("no `git.commit` recorded")
    else:
        dirty = git.get("dirty")
        if dirty is not True and dirty is not False:
            problems.append("`git.dirty` is neither true nor false")
        elif dirty is True:
            captured = git.get("dirty_paths")
            if not isinstance(captured, dict) or not captured:
                problems.append(
                    "the tree was dirty at freeze time and `git.dirty_paths` "
                    "captures nothing — the commit does not describe what ran")

    section = body.get("d013")
    now = ctx.d013_section()
    if not isinstance(section, dict) or not isinstance(section.get("text"), str):
        problems.append("the D-013 section text was not recorded")
    elif not isinstance(section.get("digest"), str):
        problems.append("the D-013 section digest was not recorded")
    elif sha256_text(section["text"]) != section["digest"]:
        problems.append("the recorded D-013 text does not match its own digest")
    elif now is None:
        problems.append("D-013 cannot be found in {} now".format(ctx.decisions))
    elif sha256_text(now) != section["digest"]:
        problems.append(
            "D-013 has changed since the freeze — the rule the run is measured "
            "against is not the rule that was frozen")

    inputs = body.get("inputs")
    if not isinstance(inputs, dict) or not inputs:
        problems.append("no `inputs` digests recorded")
    else:
        # Every name this tool freezes must be *in* the record, not merely
        # agree with it where present. Codex, 2026-09-04: the first version
        # walked `inputs.items()`, so a record with nine of its ten entries
        # deleted verified clean — the missing entries had nothing to
        # disagree with. Require the thing; do not forbid its opposite.
        missing = [name for name, _ in FROZEN_INPUTS if name not in inputs]
        if missing:
            problems.append(
                "the freeze names no digest for {} — a freeze is only as wide "
                "as what it lists, and what it omits is not frozen".format(
                    ", ".join(sorted(missing))))
        for name, recorded in sorted(inputs.items()):
            if not isinstance(recorded, dict) or \
                    not isinstance(recorded.get("digest"), str):
                problems.append("{}: no digest recorded".format(name))
                continue
            current = sha256_file(ctx.root / name)
            if current is None:
                problems.append("{}: frozen and now unreadable".format(name))
            elif current != recorded["digest"]:
                problems.append("{}: changed since the freeze".format(name))

    derived = body.get("derived")
    if not isinstance(derived, dict) or "reviewer" not in derived:
        problems.append("no `derived.reviewer` digest recorded")
    else:
        current = tree_digest(ctx.root / "src" / "security_agent", "*.py")
        if current is None:
            problems.append("the reviewer's source cannot be digested now")
        elif current != derived.get("reviewer"):
            problems.append(
                "the reviewer's source changed since the freeze — "
                "`agent_version` moves only when somebody bumps it, this does "
                "not")

    configuration = body.get("configuration")
    if not isinstance(configuration, dict) or \
            not configuration.get("model_requested"):
        problems.append("no resolved configuration recorded (model, verifier, "
                        "verify on/off)")
    else:
        # Recorded *and compared*. The first version checked only that a model
        # was written down, so exporting a different `SECURITY_SCAN_MODEL`
        # after the freeze left it verifying clean — the one change a freeze
        # most needs to notice, since it moves no file on disk. Codex,
        # 2026-09-04.
        now_config, config_error = resolved_configuration(ctx.root)
        if config_error is not None:
            problems.append(
                "the configuration cannot be resolved now, so the freeze "
                "cannot be compared against it: {}".format(config_error))
        else:
            drifted = sorted(
                key for key in set(configuration) | set(now_config)
                if configuration.get(key) != now_config.get(key))
            if drifted:
                problems.append(
                    "the resolved configuration differs from the freeze on {} "
                    "— this shell would ask for something else than the one "
                    "that was frozen".format(", ".join(drifted)))
    return problems


def check_adjudicate_30(ctx: Context, step: Step) -> Result:
    """A manifest and an adjudication file naming a permitted adjudicator."""
    return _check_adjudicated(ctx, step.id)


def check_extend_to_100(ctx: Context, step: Step) -> Result:
    """The extension, once the guard in the block has let it through.

    The guard — "fewer than 5 of the 30 are unclear" — is evaluated generically
    from the block before this runs, so the number lives in `DECISIONS.md` and
    not here.
    """
    return _check_adjudicated(ctx, step.id)





def _declared_generations(spec) -> Optional[str]:
    """The block's `generations:` must say what the checker enforces.

    It did not: the block declared `records: [configuration_digest, case_ids]`
    while the checker required `id`, `status` and `case_identities` and never
    looked at a digest — so a ledger written to the documented shape was
    refused, and the documented shape described a control nobody implemented.
    The contract is one constant now, and a divergence is a refusal rather
    than a surprise at the first ledger.

    **And every value is enforced by being the only one accepted.** Codex,
    2026-09-04, on the version before this: centralising the constant
    centralised the *declaration* and not the behaviour — `identity`,
    `on_repeat`, `on_overlap` and `disjoint` were validated while the code did
    the one thing unconditionally, so changing the contract and the block
    together would have changed nothing. This tool implements exactly one
    behaviour for each, so any other declaration is a rule it would accept and
    not apply, and it is refused here. A mutation test covers every key.
    """
    if not isinstance(spec, dict):
        return None
    wrong = []
    for key, allowed in sorted(GENERATIONS_IMPLEMENTED.items()):
        declared = GENERATIONS_CONTRACT.get(key)
        value = tuple(declared) if isinstance(declared, list) else declared
        if value not in allowed:
            wrong.append(
                "the contract says `{}` is {!r} and this tool implements only "
                "{}. A value nothing applies is a rule in name".format(
                    key, declared,
                    ", ".join(repr(a) for a in allowed)))
    for key, expected in sorted(GENERATIONS_CONTRACT.items()):
        if key not in spec:
            wrong.append("`{}` is missing".format(key))
        elif spec[key] != expected:
            wrong.append("`{}` is {!r} and this tool enforces {!r}".format(
                key, spec[key], expected))
    unknown = sorted(set(spec) - set(GENERATIONS_CONTRACT))
    for key in unknown:
        wrong.append("`{}` is declared and nothing acts on it".format(key))
    if wrong:
        return ("the block's `generations:` does not describe what this tool "
                "enforces: {}".format("; ".join(wrong)))
    return None


def _change_identity(repo, commit):
    """The one normalisation, borrowed rather than repeated.

    `ordinary_corpus.identity` folds a repository path to lower case and a sha
    to lower hex, which is what makes `AutoMapper/AutoMapper` and
    `automapper/automapper` one change rather than two. A second copy here
    would drift from it, and the drift would be silent in the permissive
    direction: two spellings of one change would look disjoint.
    """
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import ordinary_corpus
    return ordinary_corpus.identity(repo, commit)


def _generation_problem(ctx: Context) -> Optional[str]:
    """Why this sample's generation cannot be established, or `None`.

    Today it is always the first reason: no ledger exists. That is deliberately
    not treated as permission — the amendment says the absent ledger blocks the
    run rather than excusing overlap — and it is why this returns a sentence
    rather than a boolean.

    This docstring used to say all six of D-013's open semantics were unbuilt,
    while a comment forty lines below listed four. Both cannot be right, and a
    docstring that overstates a gap is the mirror of one that overstates a
    control. What is actually here:

    * **alias equality, partly.** The comparison goes through
      `ordinary_corpus.identity`, which folds case and surrounding whitespace
      and nothing else. `github.com/o/a`, `github.com/o/a.git`,
      `https://github.com/o/a`, an ssh remote and a shortened sha are five
      identities for one change, so a repeat spelled any of the other four
      passes as unseen. Measured on 2026-09-05, not read off the source, and
      pinned by `test_the_identity_fold_covers_nothing_else`.

      How much this costs today was measured too: of the 3056 records in the
      pool behind `ordinary-v1`, none carries any of those spellings, so
      widening the fold would move nothing now. It is a hazard for a pool built
      differently — a different clone, a URL form — rather than a live one.
    * **unbuilt:** what a `case_id` names, digest coverage, who writes a record
      and when overlap is checked (one protocol, not two), which generation
      owns which result, and the seventh D-013 does not name — concurrency and
      crash recovery, without which every other semantic can hold while two
      overlapping paid runs proceed. Codex, 2026-09-05.
    """
    path = ctx.generations
    if path is None:
        return ("no generations ledger was named, so this sample cannot be "
                "shown to be disjoint from one already scored — and the thirty "
                "discarded on 2026-09-04 would otherwise satisfy this step")
    if not path.exists():
        return ("no generations ledger at {} — the amendment requires the "
                "thirty already scored to be seeded as generation one and a "
                "new draw to be disjoint from them. The absent ledger blocks "
                "the run; it does not excuse the overlap".format(path))

    try:
        body = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return "{} could not be read: {}".format(path, exc)
    generations = body.get("generations") if isinstance(body, dict) else None
    if not isinstance(generations, list) or not generations:
        return ("{} records no generations — an empty ledger is not evidence "
                "that nothing was scored before".format(path))

    # Disjointness *is* computable, and only the edges D-013 leaves open are
    # not: what a case id names, digest coverage, who writes a record, when
    # overlap is checked. The identity used here is `ordinary_corpus.identity`,
    # which is the alias normalisation every other call site uses — the same
    # one that folds `AutoMapper/AutoMapper` onto `automapper/automapper`.
    seen, current, problems = {}, None, []
    per_generation = []
    for index, generation in enumerate(generations):
        if not isinstance(generation, dict):
            problems.append("generation {} is not an object".format(index))
            continue
        ident = generation.get("id")
        rows = generation.get("case_identities")
        if not isinstance(ident, str) or not ident.strip():
            problems.append("generation {} has no id".format(index))
        if not isinstance(rows, list) or not rows:
            problems.append("generation {!r} lists no cases — a generation "
                            "that scored nothing is not a generation".format(
                                ident))
            continue
        status = generation.get("status")
        if status not in GENERATIONS_CONTRACT["status_values"]:
            problems.append(
                "generation {!r} has status {!r}; it must be one of {}. A "
                "generation with no state can be replayed as though it were "
                "the run in progress".format(
                    ident, status,
                    ", ".join(GENERATIONS_CONTRACT["status_values"])))
        keys = set()
        for row in rows:
            if not isinstance(row, list) or len(row) != 2:
                problems.append("generation {!r} holds a case that is not a "
                                "[repo, commit] pair".format(ident))
                continue
            key = _change_identity(row[0], row[1])
            if key is None:
                problems.append("generation {!r} holds an unreadable "
                                "identity".format(ident))
                continue
            if key in keys:
                # Collapsing a repeat would let a generation of 29 changes
                # answer for 30 case ids and still pass the count.
                problems.append(
                    "generation {!r} lists {}@{} twice".format(
                        ident, key[0], key[1]))
                continue
            keys.add(key)
        overlap = sorted(k for k in keys if k in seen)
        if overlap:
            problems.append(
                "generation {!r} scores {} change(s) an earlier generation "
                "already scored, the first being {}@{} from {!r}".format(
                    ident, len(overlap), overlap[0][0], overlap[0][1],
                    seen[overlap[0]]))
        for key in keys:
            seen.setdefault(key, ident)
        per_generation.append((ident, keys, status))
        current = ident
    if problems:
        return "; ".join(problems)
    if current is None:
        return "{} records no usable generation".format(path)

    # **And this sample must be one of those generations.** Checking only that
    # some ledger is internally disjoint leaves the gate open: a ledger holding
    # one unrelated generation would satisfy it, and any thirty cases — the
    # ones the owner's amendment discarded included — would pass. Codex found
    # it, and found that the fixtures had encoded the permissiveness too.
    drawn, why = _sample_identities(ctx)
    if drawn is None:
        return why
    for ident, keys, status in per_generation:
        if keys != drawn:
            continue
        if status == GENERATIONS_CONTRACT["adjudicable_status"]:
            return None
        return ("the drawn sample is generation {!r}, whose status is {!r}. "
                "A generation already scored or discarded cannot be "
                "adjudicated again — that is the replay the ledger "
                "exists to stop".format(ident, status))
    return ("the drawn sample is not any generation in {}: {} change(s) drawn, "
            "and the generations hold {}. A sample that belongs to no "
            "generation has no evidence of being new".format(
                path, len(drawn),
                ", ".join("{} in {!r}".format(len(k), i)
                          for i, k, _ in per_generation) or "nothing"))


def _sample_identities(ctx: Context):
    """The drawn sample as normalised identities, or `None` and why not."""
    path = ctx.ordinary_manifest
    if path is None:
        return None, ("no manifest was named, so the sample cannot be matched "
                      "to a generation — pass `--ordinary-dir DIR`")
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return None, "{} could not be read: {}".format(path, exc)
    selected = manifest.get("selected") if isinstance(manifest, dict) else None
    if not isinstance(selected, list) or not selected:
        return None, "{} has no `selected` list".format(path)
    keys, missing, repeated = set(), 0, []
    for row in selected:
        key = _change_identity((row or {}).get("repo"),
                               (row or {}).get("commit")) \
            if isinstance(row, dict) else None
        if key is None:
            missing += 1
            continue
        if key in keys:
            # A set would swallow this, and thirty case ids over twenty-nine
            # changes would then match a twenty-nine-identity generation and
            # still satisfy the separate count of thirty.
            repeated.append(key)
            continue
        keys.add(key)
    if repeated:
        return None, ("{} draws {}@{} twice; a repeated change is one change "
                      "counted as two".format(path, repeated[0][0],
                                              repeated[0][1]))
    if missing:
        return None, ("{} of {} selected row(s) in {} carry no repository and "
                      "commit, so the sample cannot be matched to a "
                      "generation".format(missing, len(selected), path))
    return keys, ""


def _check_adjudicated(ctx: Context, step_id: str) -> Result:
    """One shape for both corpus steps: N cases, every verdict filled in, and
    every record *naming an adjudicator the amendment permits*.

    The wording is not fussiness. This said "filled by hand", and what the
    artifact carries is a self-report: a model-assisted adjudication records the
    same field if whoever wrote it says so. Nothing can establish that no model
    was consulted, so nothing here says it was not — D-013 states the same limit
    beside the criterion. Codex blocked a commit over the old phrasing, and it
    was right to: a checker that prints a claim as a finding is how "the records
    say a human" becomes "a human did it" three readers later.

    **And the sample must belong to a generation the ledger records as disjoint.**
    Without that, the thirty discarded on 2026-09-04 still satisfy this step: the
    criterion could not tell a fresh draw from the pilot the owner's amendment
    threw out, so `extend_to_100` became reachable and step 3 passed by the
    machine-readable rule while the prose forbade it. Codex found it in the
    amendment that created it.
    """
    ledger = _generation_problem(ctx)
    if ledger is not None:
        return Result(UNKNOWN, ledger)

    target = target_from_id(step_id)
    if target is None:
        return Result(UNKNOWN, (
            "the step id {!r} carries no case count, and this tool takes the "
            "number from the id rather than keeping a second copy of it"
            .format(step_id)))
    cases, why = ctx.ordinary_cases()
    if cases is None:
        return Result(UNKNOWN, why)

    disagreement = _manifest_agreement(ctx, cases)
    if disagreement is not None:
        return Result(UNKNOWN, disagreement)

    counts = _verdict_counts(cases)
    if len(cases) != target:
        # Equality, not a floor. `< target` passed 31 unique rows with 31
        # adjudications against a matching generation — a sample nobody drew,
        # answering for one nobody counted. Codex, 2026-09-04.
        return Result(NOT_DONE, "{} case(s) adjudicated, exactly {} required"
                      .format(len(cases), target))
    if counts["missing"]:
        return Result(NOT_DONE, (
            "{} of {} verdicts are still unfilled — a null verdict must never "
            "count as `ordinary`".format(counts["missing"], len(cases))))
    if counts["bad"]:
        return Result(NOT_DONE, "{} verdict(s) are not one of {}".format(
            counts["bad"], ", ".join(VERDICT_VALUES)))
    if counts["by_model"]:
        return Result(NOT_DONE, (
            "{} case(s) name an adjudicator the amendment does not permit. "
            "D-013 allows `human`, or `model` with `vendor: xai` — Grok, whose "
            "vendor produced neither the findings nor these rules. A Claude "
            "adjudicator is not permitted at all: it shares the model family "
            "with the reviewer, which is the independence the rule is about. "
            "And a case with no `adjudicated_by` counts here: no author "
            "recorded is not an author".format(counts["by_model"])))
    return Result(DONE, (
        "{} case(s), every verdict filled and every record naming a permitted "
        "adjudicator: {} ordinary, {} not_ordinary, {} unclear. What the "
        "records *claim* is all this establishes — no artifact shows which "
        "model was consulted, or whether one was".format(
            len(cases), counts["ordinary"], counts["not_ordinary"],
            counts["unclear"])))


def _verdict_counts(cases: Dict[str, Any]) -> Dict[str, int]:
    counts = {name: 0 for name in VERDICT_VALUES}
    counts["missing"] = 0
    counts["bad"] = 0
    counts["by_model"] = 0
    for case in cases.values():
        if not isinstance(case, dict):
            counts["bad"] += 1
            continue
        verdict = case.get("verdict")
        if verdict is None:
            counts["missing"] += 1
        elif verdict in VERDICT_VALUES:
            counts[verdict] += 1
        else:
            counts["bad"] += 1
        # Required, not forbidden: a case with no `adjudicated_by` at all is
        # not adjudicated by anybody, it is a case with no author recorded.
        #
        # `human`, or `model` with `vendor: xai`. The owner amended step 2 on
        # 2026-09-04 to permit a third-vendor adjudicator — Grok — and the
        # vendor is required because the permission is *about* the vendor: a
        # Claude adjudicator shares the model family with the reviewer whose
        # findings are being scored, which is the independence at issue. Left
        # requiring `human` for one round after the amendment, so the newly
        # permitted path could never make the step done; Codex caught it.
        if not _permitted_adjudicator(case):
            counts["by_model"] += 1
    return counts


def _permitted_adjudicator(case: Dict[str, Any]) -> bool:
    who = case.get("adjudicated_by")
    if who == "human":
        return True
    # Not `!= "human"` inverted: a bare `model` with no vendor names nobody,
    # and this file's recurring defect is a missing field reading as consent.
    return who == "model" and case.get("vendor") in PERMITTED_MODEL_VENDORS


def _manifest_agreement(ctx: Context, cases: Dict[str, Any]) -> Optional[str]:
    """`None` when the manifest and the rulings describe the same sample."""
    path = ctx.ordinary_manifest
    if path is None:
        return ("no manifest was named, so the adjudicated cases cannot be "
                "shown to be the drawn sample — pass `--ordinary-dir DIR`")
    if not path.is_file():
        return "{} is not a readable file".format(path)
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return "{} could not be read: {}".format(path, exc)
    selected = manifest.get("selected") if isinstance(manifest, dict) else None
    if not isinstance(selected, list):
        return "{} has no `selected` list".format(path)
    # Counted, not collapsed. A set here let a manifest of 31 rows with one
    # case id repeated over two distinct changes agree with 30 adjudications
    # and pass the count — the third place today where a set swallowed
    # something that had to be counted. Codex, 2026-09-04.
    malformed = sum(1 for entry in selected if not isinstance(entry, dict))
    if malformed:
        # Dropped silently before, so thirty good rows plus one bad one
        # compared equal to thirty and passed.
        return ("{} of {} selected row(s) in {} are not objects; a row the "
                "comparison cannot read is not a row that agrees".format(
                    malformed, len(selected), path))
    ids = [entry.get("case_id") for entry in selected]
    repeated = sorted({i for i in ids if ids.count(i) > 1})
    if repeated:
        return ("{} names case id {!r} on {} rows; one id over two changes is "
                "two changes wearing one name".format(
                    path, repeated[0], ids.count(repeated[0])))
    drawn = set(ids)
    ruled = set(cases)
    if drawn != ruled:
        return ("the manifest draws {} case(s) and the adjudication file "
                "carries {}, and they are not the same set ({} drawn but "
                "unruled, {} ruled but undrawn) — the two artifacts do not "
                "describe one sample".format(
                    len(drawn), len(ruled), len(drawn - ruled),
                    len(ruled - drawn)))
    return None


def check_classify_alarms(ctx: Context, step: Step) -> Result:
    """Every alarm on the fixed member has a **cause** named for it.

    Waits for nothing — that is what "in parallel" in the prose means, and it
    is why the block gives it `requires: []`. The count is measured, not
    quoted: the prose said 22 for a day, and 20 reproduce in the latest rows,
    21 counting every row ever written.

    "Classified" is not "ruled". A ruling says whether the finding is correct;
    the tuning step asks whether the alarms show a broad, independently
    repeated cause, and only the field the block names under `needs_field`
    answers that. On 2026-09-04 this step was reported done because all 20
    alarms carried a ruling — and none of those rulings named a cause.
    Requiring the ruling and not the cause is the checker that would have
    confirmed the mistake instead of catching it.
    """
    field = step.needs_field
    if field is None:
        return Result(UNKNOWN, (
            "the block does not say which field records the cause for {!r}; "
            "add `needs_field:` to the step rather than letting this tool pick "
            "a name".format(step.id)))
    data = ctx.alarms(field)
    if "error" in data:
        return Result(UNKNOWN, data["error"])
    fired = data.get("fired")
    unruled = data.get("unruled")
    uncaused = data.get("uncaused")
    if not isinstance(fired, list) or not isinstance(unruled, list) \
            or not isinstance(uncaused, list):
        return Result(UNKNOWN, (
            "the alarm reader did not return the three lists this step is read "
            "from (fired, unruled, uncaused)"))
    if not fired:
        return Result(UNKNOWN, (
            "no case in {} measurement row(s) records "
            "`safe_false_positive: true` — an empty numerator here means the "
            "rows were not read, not that there is nothing to classify"
            .format(data.get("rows", 0))))

    vocabulary = data.get("vocabulary") or {}
    seen = (" Values of `{}` present: {}.".format(
        field, ", ".join(sorted(vocabulary))) if vocabulary else
        " No `{}` value appears anywhere in the file.".format(field))
    note = ""
    independence = data.get("independence")
    if isinstance(independence, dict):
        note = " ({} of the rulings are independent of the model that produced "\
               "the findings.)".format(independence.get("independent", "?"))

    # The vocabulary has to exist before the classifying starts, or it gets
    # invented to fit what is already written.
    #
    # Read from the block, not counted off the rows. The first version asked
    # whether two or more distinct values appeared in the rulings, which cannot
    # establish "fixed in advance" — it is satisfied the moment somebody
    # classifies two cases differently, which is exactly the invented-to-fit
    # case it was meant to catch. Codex, 2026-09-04. Declared in the block, the
    # list is inside the D-013 text the freeze digests, so "fixed before the
    # classifying" becomes something an artifact can settle.
    if step.needs_vocabulary_first:
        declared = step.vocabulary
        if len(declared) < 2:
            return Result(NOT_DONE, (
                "the block declares no vocabulary for `{}` — add a "
                "`vocabulary:` list to the step naming the permitted "
                "values.{} A vocabulary counted off the rulings is not one: it "
                "would be satisfied by the very thing it exists to prevent. {} "
                "of {} alarm(s) name a cause.{}".format(
                    field, seen, len(fired) - len(uncaused), len(fired), note)))
        stray = sorted(set(vocabulary) - set(declared))
        if stray:
            return Result(NOT_DONE, (
                "{} value(s) of `{}` are not in the vocabulary the block "
                "declares: {}. Either the value is wrong or the vocabulary is "
                "no longer the one that was fixed.{}".format(
                    len(stray), field, ", ".join(stray), note)))
    banned = sorted(set(vocabulary) & set(step.forbidden_values))
    if banned:
        return Result(NOT_DONE, (
            "{} value(s) of `{}` name something the decision rules out as a "
            "cause: {}. `fix-incomplete` describes the corpus's fix and not a "
            "way the reviewer failed — the reviewer may be entirely right that "
            "the weakness persists — and D-013 records it as corpus validity "
            "instead.{}".format(len(banned), field, ", ".join(banned), note)))

    if unruled:
        return Result(NOT_DONE, (
            "{} of {} alarm(s) on the fixed member have no ruling at all for "
            "their safe member in corpus-real/adjudications.yml: {}{}".format(
                len(unruled), len(fired), ", ".join(sorted(unruled)[:5]), note)))
    if uncaused:
        return Result(NOT_DONE, (
            "{} alarm(s) on the fixed member, {} ruled and {} carrying a `{}`: "
            "{} case(s) have a correctness verdict and no named cause, and a "
            "verdict does not answer what the tuning step asks.{}{}".format(
                len(fired), len(fired) - len(unruled),
                len(fired) - len(uncaused), field, len(uncaused), seen, note)))
    return Result(DONE, (
        "{} case(s) alarm on the fixed member and every one carries a ruling "
        "naming a `{}`.{}{}".format(len(fired), field, seen, note)))


PRE_NOT_APPLICABLE = "not applicable"
PRE_BLOCKED = "blocked"
PRE_CANNOT_TELL = "cannot tell"
PRE_ESTABLISHED = "established"

PRE_STATES = (PRE_NOT_APPLICABLE, PRE_BLOCKED, PRE_CANNOT_TELL,
              PRE_ESTABLISHED)


class Preflight:
    """What stands between a step and being *attemptable* — a different
    question from what would record it as finished.

    Today the two are collapsed: `state_of` returns at `criterion_undefined`
    before any checker runs, so for `tune` and `sonnet_gate` the tool reports
    only that no artifact would record completion. Everything else about them —
    that the Sonnet gate has no usable baseline, that the frozen closure may
    have drifted — is computed by code the tool never reaches.

    The answer is **total**: every step consulted gets one of four states, and
    `not applicable` is stated rather than left as silence. Codex, 2026-09-05:
    an optional result makes silence mean "no preflight applies", "everything
    passed", and "somebody forgot to check" at once, and prose in an evidence
    string cannot carry that difference to a later caller.

    `established` never means ready. It means the inputs this step needs exist
    and are usable; the completion criterion is a separate matter and stays
    undefined. Nothing here can make a step `done`, and nothing here can
    satisfy another step's `requires`.
    """

    __slots__ = ("state", "why")

    def __init__(self, state, why):
        if state not in PRE_STATES:
            raise ValueError("unknown preflight state {!r}".format(state))
        self.state = state
        self.why = why

    def __bool__(self):
        raise TypeError(
            "a preflight result is not a boolean: it is {!r}. `established` "
            "means the inputs exist, not that the step may be reported done."
            .format(self.state))

    def __repr__(self):
        return "Preflight({!r})".format(self.state)


def preflight_tune(ctx: Context, step: Step) -> Preflight:
    """The one thing about `tune` an artifact settles.

    `check_tune` computes this and is unreachable: `state_of` returns at
    `criterion_undefined` first. Measured on 2026-09-05 against the real
    DECISIONS.md — the checker's message never appears in `evaluate()`. So the
    drift detector, which is the only file-backed part of this step, was dead
    code with a green test over it.
    """
    closure = _frozen_closure_mutated(ctx)
    if closure.state == CLOSURE_MUTATED:
        return Preflight(PRE_BLOCKED, closure.why)
    if closure.state == CLOSURE_UNREADABLE:
        return Preflight(PRE_CANNOT_TELL, closure.why)
    if closure.state == CLOSURE_ABSENT:
        return Preflight(PRE_CANNOT_TELL, closure.why)
    return Preflight(PRE_ESTABLISHED, closure.why)


def preflight_sonnet_gate(ctx: Context, step: Step) -> Preflight:
    """Whether there is a baseline to hold a challenger against.

    D-013's prose gives the reason this step has no `done_when` as
    "`tools/sentinel_compare.py` prints a verdict and stores nothing". That is
    true and is the *second* obstacle. The operative one, measured on
    2026-09-05 by calling the comparator against the committed reference:

        REFUSED: this reference is retired and is not a baseline: its rows
        carry no `models_verified` ... No arrangement passes.

    A reader acting on the storage sentence would add a `--json` flag and be
    exactly as far from a completable step as before. So the order reports what
    actually blocks it — and asks `sentinel_compare`, which owns the format,
    rather than reimplementing its rules here.
    """
    if not step.reference:
        return Preflight(PRE_CANNOT_TELL, (
            "the decision names no `reference` for {!r}, so nothing says which "
            "baseline this gate would be measured against. Naming one is a "
            "decision recorded in DECISIONS.md, not a path guessed here"
            .format(step.id)))

    # The parser refuses an absolute path and one spelled with `..`, and that
    # is a check on the *text*. Codex, 2026-09-05: a path with neither can
    # still leave the tree through a symlink inside it, and this function would
    # then judge a file nothing in the repository records.
    #
    # What this check establishes, stated no wider than it is: **at the moment
    # it runs**, the reference resolves inside the tree. It is not coupled to
    # the open that follows — Codex's next round named the gap precisely, that
    # the file or an ancestor can be replaced between the resolve here and the
    # `read_text` in `sentinel_compare`, and `read_text` would follow the new
    # link. Closing that would mean descriptor-relative, no-follow traversal.
    #
    # Not built, and the reason is written here rather than left implied: this
    # is a development tool, run by the person who owns the working tree, and
    # everything it reads — `DECISIONS.md`, the comparator, this file — is
    # already trusted at that level. The check is worth having against a
    # mistake and a stale symlink; it is not a boundary against an adversary
    # holding write access to any part of the tree, and calling it one would be
    # the claim-wider-than-the-evidence this repository exists to catch.
    #
    # Codex, 2026-09-05, on the first wording: "anyone who can win the race can
    # edit DECISIONS.md" is not true either — write access confined to
    # `measurements/` wins the race and grants neither. The conclusion stands
    # on the trust model, not on a claim about what such an attacker could also
    # reach.
    root = ctx.root.resolve()
    path = (ctx.root / step.reference).resolve()
    try:
        path.relative_to(root)
    except ValueError:
        return Preflight(PRE_CANNOT_TELL, (
            "the reference {!r} resolved to {}, which is outside {} — the "
            "order would be judging a file nothing here records. A path may "
            "leave the tree through a symlink without containing '..', so the "
            "spelling was not enough".format(step.reference, path, root)))

    try:
        import sentinel_compare
    except Exception as exc:
        return Preflight(PRE_CANNOT_TELL, (
            "the comparator could not be imported ({}: {}), so the baseline "
            "was not judged".format(type(exc).__name__, exc)))

    state = sentinel_compare.validate_reference(path)
    if state.state == sentinel_compare.REF_USABLE:
        # Deliberately narrow, and never the word "ready". A usable baseline
        # says a comparison could be attempted; it says nothing about whether
        # one was run, what it cost, or what would record the answer — and
        # this step still has no `done_when`.
        return Preflight(PRE_ESTABLISHED, (
            "{} (digest {}). This says a comparison could be attempted, not "
            "that one was run and not that anything would record it".format(
                state.why, (state.digest or "?")[:12])))
    if state.state == sentinel_compare.REF_CANNOT_TELL:
        return Preflight(PRE_CANNOT_TELL, state.why)
    return Preflight(PRE_BLOCKED, state.why)


# One entry per step whose `done_when` is `undefined` and which has inputs an
# artifact can speak about. A step absent from this map is reported
# `not applicable` explicitly rather than by silence.
PREFLIGHT: Dict[str, Callable[[Context, Step], Preflight]] = {
    "tune": preflight_tune,
    "sonnet_gate": preflight_sonnet_gate,
}


def preflight_of(ctx: Context, step: Step) -> Preflight:
    """Total: every step gets an answer, including the ones with no entry."""
    run = PREFLIGHT.get(step.id)
    if run is None:
        return Preflight(PRE_NOT_APPLICABLE, (
            "no preflight is declared for {!r}: nothing on disk speaks to "
            "whether its inputs exist".format(step.id)))
    try:
        return run(ctx, step)
    except Exception as exc:
        # Same rule as everywhere else here: a preflight that raised has not
        # established anything, and must not be reported as though it had.
        return Preflight(PRE_CANNOT_TELL, (
            "the preflight for {!r} raised {}: {} — nothing was established"
            .format(step.id, type(exc).__name__, exc)))


def check_tune(ctx: Context, step: Step) -> Result:
    """Never `done`, and for a reason worth printing.

    The block marks this step `blocked_on_owner`, which the generic machinery
    reports before this runs, so ordinarily nothing here is reached. What is
    left for the checker is the one thing an artifact *can* settle: whether the
    frozen closure has been mutated while results already exist. That is not
    proof that somebody tuned — nothing can prove that — it is the trace tuning
    leaves, and the boxed rule's "no tuning whatsoever" is already broken when
    it appears.
    """
    closure = _frozen_closure_mutated(ctx)
    if closure.state == CLOSURE_MUTATED:
        return Result(NOT_DONE, closure.why)
    if closure.state == CLOSURE_UNREADABLE:
        # Not folded into the sentence below. "I could not look" and "I looked
        # and nothing moved" are different answers, and this tool reports the
        # difference everywhere else.
        return Result(UNKNOWN, closure.why)
    return Result(MANUAL, (
        "not mechanically decidable: the conditions are {} — words no program "
        "evaluates — and the scorer that would place the ordinary changes "
        "against the boundary does not exist. On the one part an artifact "
        "settles: {}".format(
            ", ".join(repr(p) for p in step.undefined_predicates)
            or "judgements no artifact records", closure.why)))


def check_sonnet_gate(ctx: Context, step: Step) -> Result:
    """No artifact establishes this step, and saying so is the honest answer.

    `tools/sentinel_compare.py` prints a verdict and exits 0 or 1; it writes
    nothing a later reader can check, so there is no file that says the gate
    ran, on which reference, or how it came out. Reporting `not done` would
    assert something this tool cannot see, and `done` is out of the question.
    `cannot tell` denies — which is right, because the gate spends money.
    """
    return Result(UNKNOWN, (
        "D-013 names this step and no artifact records it: "
        "`tools/sentinel_compare.py` prints its verdict and stores nothing, so "
        "nothing on disk says whether the gate ran, against which reference, or "
        "how it came out. Give it a written result — a file under measurements/ "
        "carrying the reference, the comparison and the verdict — and this "
        "checker can answer; until then it denies rather than guessing"))


# The map the divergence refusal is computed against. One entry per step id in
# DECISIONS.md's block, and the tool refuses rather than reporting on a shorter
# list than the decision names.
CHECKERS: Dict[str, Callable[[Context, Step], Result]] = {
    "freeze": check_freeze,
    "adjudicate_30": check_adjudicate_30,
    "extend_to_100": check_extend_to_100,
    "classify_alarms": check_classify_alarms,
    "tune": check_tune,
    "sonnet_gate": check_sonnet_gate,
}

# Actions that are not steps. A step id is itself an action ("may I do this
# now"); these are the other things a caller asks about. `spend` is the hook's
# entry point: any command that buys a review runs the frozen configuration, so
# it presupposes that there is one.
EXTRA_ACTIONS: Dict[str, List[str]] = {
    # Spending buys a scored generation, so it presupposes a frozen
    # configuration, the thirty adjudicated with **every record naming a
    # permitted adjudicator** — which is as much as any artifact shows — and
    # a ledger that can
    # tell a fresh draw from a re-reading. The ledger is inferred from the
    # decision rather than written in the block: D-013 says "without both
    # recorded there is no way to tell a fresh draw from a re-reading, and the
    # decision becomes a claim nothing enforces".
    #
    # `adjudicate_30` and not `freeze`. The first version asked only for the
    # freeze, and Codex found that it would permit the first paid run the
    # moment a freeze existed — while step 2, which D-013 requires to happen
    # "without a single model call", was still not done. A test asserted that
    # behaviour, so the gate was wrong and pinned wrong at once.
    #
    # Not `extend_to_100`: that step is *done* only once a hundred cases have
    # been adjudicated, which is after the run it would be gating. Requiring it
    # would make spending impossible rather than ordered.
    "spend": ["adjudicate_30", GENERATIONS],
}

# Steps whose **guard** must not have failed for an action to be permitted,
# as against steps that must be done. `extend_to_100` is guarded on "fewer
# than 5 of the 30 are unclear", and that guard is the decision's condition for
# running the hundred — but the step cannot be required *done* before the run
# that fills it. So its guard is checked and its completion is not.
EXTRA_ACTION_GUARDS: Dict[str, List[str]] = {
    "spend": ["extend_to_100"],
}


def check_generations(ctx: Context, spec: Optional[Dict[str, Any]]) -> Result:
    """The ledger that separates a fresh draw from a re-reading.

    Not a step — a standing requirement the block states at the top level. The
    owner decided on 2026-09-04 that tuning is permitted and that the next
    measurement is on changes never scored before. That sentence is enforceable
    only if something records which changes each generation scored, and today
    nothing does. Reported as not started rather than written here: this tool
    does not invent the record it is supposed to check.
    """
    if spec is None:
        return Result(UNKNOWN, (
            "the block states no `generations:` rule, so there is nothing to "
            "read — and nothing keeping a later draw from re-reading changes "
            "an earlier one scored"))
    return Result(UNKNOWN, (
        "declared and not enforceable. The block asks for {} and refuses an "
        "overlapping draw, and D-013 lists six ways a draw could satisfy every "
        "word of that and still be a re-reading: whether a case_id names the "
        "change or a row that can be regenerated with a new id, whether two "
        "aliases of one commit compare equal, what the configuration digest "
        "covers, who writes a generation record and where it is authoritative, "
        "when overlap is checked, and which generation belongs to which "
        "result. None is filled by guessing. No record exists at {} either. "
        "This tool reads the requirement and does not pretend to apply it — a "
        "check that looked like a control here would be the exact defect "
        "D-013 exists to catch".format(", ".join(spec["records"]),
                                       ctx.generations)))


CLOSURE_ABSENT = "absent"
CLOSURE_UNREADABLE = "unreadable"
CLOSURE_INTACT = "intact"
CLOSURE_MUTATED = "mutated"


class ClosureState:
    """What the freeze record says about drift — four answers, not two.

    It has no truth value on purpose. The previous shape was
    `Optional[str]`, and three different absences returned `None`: no freeze
    file, a freeze that would not read or parse, and a freeze whose body is not
    an object. The one caller turned every `None` into the sentence "the frozen
    closure shows no mutation", so an unreadable `freeze.json` produced a
    statement that nothing had drifted. That is this repository's recurring
    defect sitting inside the detector written to catch drift, and a boolean or
    an optional cannot express the difference — so this does not offer one.
    """

    __slots__ = ("state", "why")

    def __init__(self, state, why):
        self.state = state
        self.why = why

    def __bool__(self):
        raise TypeError(
            "a closure state is not a boolean: it is {!r}. Compare `.state` "
            "against CLOSURE_MUTATED, CLOSURE_UNREADABLE, CLOSURE_ABSENT or "
            "CLOSURE_INTACT — an unreadable freeze is not an intact one."
            .format(self.state))

    def __repr__(self):
        return "ClosureState({!r})".format(self.state)


def _frozen_closure_mutated(ctx: Context) -> ClosureState:
    """Whether a frozen input changed, whether nothing was frozen, or whether
    the freeze itself could not be read. Never collapses the last two."""
    if not ctx.freeze.is_file():
        # No freeze, so no closure to mutate. The freeze step reports that;
        # saying it twice would let a caller read "no mutation" as "frozen".
        return ClosureState(CLOSURE_ABSENT, (
            "no freeze record exists at {}, so there is no closure to compare "
            "against — which is not the same as a closure that has not moved"
            .format(ctx.freeze)))
    try:
        body = json.loads(ctx.freeze.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return ClosureState(CLOSURE_UNREADABLE, (
            "the freeze record at {} could not be read ({}: {}), so nothing "
            "was compared. This is not evidence that the closure is intact"
            .format(ctx.freeze, type(exc).__name__, exc)))
    if not isinstance(body, dict):
        return ClosureState(CLOSURE_UNREADABLE, (
            "the freeze record at {} holds {} where an object is required, so "
            "no digest in it could be checked. This is not evidence that the "
            "closure is intact".format(ctx.freeze, type(body).__name__)))

    # The same refusal `check_freeze` makes, and it was missing here. Codex,
    # 2026-09-05: this function called `_freeze_problems` directly, so a record
    # the authoritative freeze checker rejects outright — a legacy schema, a
    # foreign artifact, no `schema` key at all — was still read field by field
    # and could be reported as an intact closure. The fixture written for the
    # intact case in this very change carried no `schema` and demonstrated it.
    #
    # `_freeze_problems` asks what each field says. It never asks whether the
    # fields mean what this tool thinks they mean.
    if body.get("schema") != FREEZE_SCHEMA:
        return ClosureState(CLOSURE_UNREADABLE, (
            "the freeze record at {} declares schema {!r} and this tool reads "
            "{!r}, so its fields were not interpreted at all. This is not "
            "evidence that the closure is intact".format(
                ctx.freeze, body.get("schema"), FREEZE_SCHEMA)))

    problems = _freeze_problems(ctx, body)
    drift = [p for p in problems
             if "changed since the freeze" in p or "D-013 has changed" in p]
    invalid = [p for p in problems if p not in drift]

    # Validity is asked *before* drift, and Codex found it the other way round
    # on 2026-09-05: a record missing its `owner_acknowledgement` and carrying
    # one mismatched digest was reported as a mutated closure. That asserts
    # something moved away from a freeze — from a file that was never a freeze,
    # so there is nothing for anything to have moved away from.
    #
    # Every sentence here is also a reason the comparison did not happen, not
    # evidence that it happened and found nothing. The drift filter above used
    # to be the whole test, and it keeps exactly two sentences: a freeze whose
    # recorded inputs have since been *deleted* produces "frozen and now
    # unreadable", which matches neither, so the answer was "every digest still
    # matches what is on disk" about files that were gone. A freeze with no
    # `inputs` block at all answered the same way, about no digests.
    #
    # Require the thing rather than forbidding its opposite: intact means the
    # record is complete and every comparison in it succeeded.
    if invalid:
        also = (" It also shows {} apparent drift sentence(s), which cannot "
                "be read as drift from a record that is not a valid freeze."
                .format(len(drift)) if drift else "")
        return ClosureState(CLOSURE_UNREADABLE, (
            "the freeze record at {} does not support a comparison: {} — so "
            "nothing was established about drift either way.{}".format(
                ctx.freeze, "; ".join(sorted(invalid)[:4]), also)))

    if drift:
        return ClosureState(CLOSURE_MUTATED, (
            "the frozen closure has been mutated since {}: {} — the "
            "configuration that produced the results is not the one on disk, "
            "which is what the boxed rule's 'no tuning whatsoever' forbids"
            .format(body.get("created_at", "the freeze"), "; ".join(drift[:4]))))

    # Deliberately narrow. This says the digests recorded in the freeze still
    # match what is on disk. It does not say a measurement was made under them
    # — the earlier wording claimed "no mutation after a result", and nothing
    # here reads a result.
    return ClosureState(CLOSURE_INTACT, (
        "every digest recorded in the freeze of {} still matches what is on "
        "disk, and the record names all of them. It does not follow that any "
        "result was measured under them — nothing here reads a result".format(
            body.get("created_at", "the freeze"))))


def divergence(order: Order) -> List[str]:
    named = {s.id for s in order.steps}
    known = set(CHECKERS)
    out = []
    declared = _declared_generations(order.generations)
    if declared is not None:
        out.append(declared)
    for missing in sorted(named - known):
        out.append(
            "DECISIONS.md names step {!r} and this tool has no checker for it "
            "— add one to CHECKERS in tools/d013_order.py, or remove the step "
            "from the block".format(missing))
    for extra in sorted(known - named):
        out.append(
            "this tool has a checker for step {!r} and DECISIONS.md no longer "
            "names it — delete the checker, or restore the step to the block"
            .format(extra))
    for step in order.steps:
        # A criterion the document states and this tool does not implement is
        # the same defect as a step with no checker: the answer would be about
        # a rule nobody applied. Reworded criteria have to come back here.
        if not step.criterion_undefined:
            implemented = DONE_WHEN_IMPLEMENTED.get(step.id)
            if implemented is None:
                out.append(
                    "step {!r} states `done_when: {}` and this tool implements "
                    "no criterion for it — add it to DONE_WHEN_IMPLEMENTED in "
                    "tools/d013_order.py together with the checker that "
                    "evaluates it".format(step.id, step.done_when))
            elif " ".join(step.done_when.split()) != implemented:
                out.append(
                    "step {!r} states `done_when: {}` and this tool implements "
                    "{!r} — the criterion was reworded and the checker was "
                    "not; make them agree".format(
                        step.id, step.done_when, implemented))
        if step.guard_field and step.guard_field not in GUARD_METRICS:
            # A guard nobody evaluates is a guard that is not there, and the
            # step it guards would run unguarded — the permissive direction.
            out.append(
                "step {!r} is guarded on {!r} and this tool computes no such "
                "metric — add it to GUARD_METRICS in tools/d013_order.py, or "
                "name a metric that exists".format(step.id, step.guard_field))
    return out


# --------------------------------------------------------------------------
# evaluation


def state_of(ctx: Context, order: Order, step: Step,
             results: Dict[str, Result]) -> Result:
    """One step's state, with the three stops kept apart.

    Order matters and it is the decision's, not this file's.

    `blocked_on_owner` outranks everything: no work clears it, and the block
    says such a step is never ready and never done. Then the checker runs — if
    it says `done`, that is reported even when a prerequisite is missing,
    because "done out of order" is a violation somebody has to see rather than
    a state to hide. Only when the work is not done do the two waiting answers
    apply, prerequisite before guard, and each named as itself.

    A step carrying `undefined_predicates` may be reported *not started*, never
    *done*, so a checker returning `done` for one is overruled here.
    """
    question = order.question(step.blocked_on_owner)
    if question is not None:
        return Result(BLOCKED_OWNER, (
            "blocked on the unanswered question {!r}, asked of {}: {}. No "
            "prerequisite and no amount of work clears it — only an answer, "
            "and it is not this tool's to give".format(
                question.id, question.asked_of, question.text)),
            stopped_by=STOP_OPEN_QUESTION)

    # Blocked by *any* open question, not one named question. `freeze` carries
    # this because the freeze digests D-013 itself: answering a question edits
    # the frozen text, so a freeze taken with one still open is invalid from
    # the next sentence the owner writes. The tool reported `freeze` as the
    # first thing to do while the guard-failure question was open, and it was
    # right about the order and wrong about the moment.
    if step.requires_no_open_questions and order.questions:
        return Result(BLOCKED_OWNER, (
            "{} question(s) in D-013 are unanswered — {} — and this step "
            "records a digest of D-013, so freezing now produces a record that "
            "an answer invalidates. Not a prerequisite: no work clears it"
            .format(len(order.questions),
                    ", ".join(sorted(order.questions)))),
            stopped_by=STOP_OPEN_QUESTION)

    if step.criterion_undefined:
        # Never done, and never "not done" either. Nothing in DECISIONS.md says
        # what records that this step finished, so the tool has no criterion to
        # apply — running its checker anyway would derive completion from
        # artifacts the decision never named. Exit 2, not 1.
        #
        # The outstanding prerequisites are named alongside rather than instead:
        # a step can both lack a criterion and be waiting, and reporting only
        # the waiting would hide the deeper of the two.
        outstanding = [need for need in transitive_requirements(order.steps, step.id)
                       if results[need].state != DONE]
        also = (" It is also waiting for {}, none of which is done.".format(
            ", ".join(outstanding)) if outstanding else "")
        # The inputs are a separate question from the criterion, and until now
        # this branch answered neither. It still returns UNDEFINED_CRITERION —
        # nothing below can make the step done, satisfy another step's
        # `requires`, or move it out of `undetermined` in `next_steps` — but
        # what it says now includes what the step is actually waiting on.
        pre = preflight_of(ctx, step)
        inputs = " Its inputs, which are a different question: {} — {}.".format(
            "inputs established; the completion criterion remains undefined"
            if pre.state == PRE_ESTABLISHED else pre.state, pre.why)
        return Result(UNDEFINED_CRITERION, (
            "`done_when: {}` — DECISIONS.md names no artifact that records this "
            "step as finished, so it can be neither reported done nor used to "
            "satisfy another step's `requires`. Filling it in means naming an "
            "artifact, which is work rather than wording.{}{}".format(
                UNDEFINED, also, inputs)))

    result = CHECKERS[step.id](ctx, step)
    if result.state == DONE:
        # Two reasons a step may never be reported done, and each names itself.
        # `undefined_predicates` are words no program evaluates;
        # `next_generation: required` means what follows this step is a fresh
        # measurement, so "done" would describe a state that does not exist.
        never_done = []
        if step.undefined_predicates:
            never_done.append("predicates no program evaluates ({})".format(
                ", ".join(repr(p) for p in step.undefined_predicates)))
        if step.next_generation:
            never_done.append(
                "`next_generation: {}`, which makes what follows a fresh "
                "measurement rather than a finished step".format(
                    step.next_generation))
        if never_done:
            result = Result(MANUAL, (
                "the mechanical part holds — {} — but this step carries {}, so "
                "it may be reported not started and never done".format(
                    result.evidence, " and ".join(never_done))))
    if result.state == DONE:
        return result

    outstanding = [need for need in transitive_requirements(order.steps, step.id)
                   if results[need].state != DONE]
    if outstanding:
        return Result(WAITING, (
            "waiting for {}, which {} {} — not the same thing as a failed "
            "guard or an unanswered question".format(
                ", ".join(outstanding),
                "is" if len(outstanding) == 1 else "are",
                ", ".join(sorted({results[n].state for n in outstanding})))),
            stopped_by=STOP_PREREQUISITE)

    if step.guard_field:
        metric = GUARD_METRICS[step.guard_field]
        value, why = metric(ctx)
        if value is None:
            return Result(UNKNOWN, "the guard {!r} cannot be evaluated: {}"
                          .format(step.guard, why))
        if not value < step.guard_below:
            question = order.question(step.guard_failure_blocked_on)
            if question is not None:
                return Result(GUARD_FAILED, (
                    "the guard {!r} does not hold: {}, which is not below {}. "
                    "The decision says when this step runs and not what happens "
                    "when the guard fails — that is the open question {!r}, "
                    "asked of {}: {}".format(
                        step.guard, why, step.guard_below, question.id,
                        question.asked_of, question.text)),
                    stopped_by=STOP_GUARD)
            return Result(GUARD_FAILED, (
                "the guard {!r} does not hold: {}, which is not below {}. The "
                "decision says the outcome is `{}`: the pilot stands with its "
                "unclear counts by stratum, the ordinary result is invalid, and "
                "no case is replaced or redrawn now that its verdict is known"
                .format(step.guard, why, step.guard_below,
                        step.on_guard_failed)),
                stopped_by=STOP_GUARD)

    return result


def evaluate(ctx: Context, order: Order) -> Dict[str, Result]:
    results: Dict[str, Result] = {}
    for step in order_steps_topologically(order.steps):
        results[step.id] = state_of(ctx, order, step, results)
    # Not a step, and kept beside them so `spend` can require it and `status`
    # can print it. A standing requirement reported nowhere is a requirement
    # nobody meets.
    if order.generations is not None or GENERATIONS in _extra_names():
        results[GENERATIONS] = check_generations(ctx, order.generations)
    return results


def _extra_names() -> List[str]:
    return [name for names in EXTRA_ACTIONS.values() for name in names]


def violations(order: Order, results: Dict[str, Result]) -> List[str]:
    """A step reported `done` while something it waits for is definitely not."""
    out = []
    for step in order.steps:
        if results[step.id].state != DONE:
            continue
        for need in transitive_requirements(order.steps, step.id):
            if results[need].state in DEFINITE_BLOCKERS:
                out.append("{} is done while {} is {}".format(
                    step.id, need, results[need].state))
    return out


def next_steps(order: Order, results: Dict[str, Result]
               ) -> Tuple[List[str], List[str], List[str]]:
    """(workable now, stopped and by which stop, criterion undefined).

    Three lists rather than two. A step whose `done_when` is undefined is not
    "next": nothing would record that doing it had finished it, so putting it
    in the workable list would send somebody to work toward a state the
    decision cannot recognise.
    """
    workable: List[str] = []
    stopped: List[str] = []
    undetermined: List[str] = []
    for step in order_steps_topologically(order.steps):
        result = results[step.id]
        if result.state == DONE:
            continue
        if result.state == UNDEFINED_CRITERION:
            undetermined.append(step.id)
        elif result.stopped_by is not None:
            stopped.append("{} ({}: {})".format(
                step.id, result.state, result.stopped_by))
        elif any(results[need].state != DONE
                 for need in transitive_requirements(order.steps, step.id)):
            stopped.append("{} ({}: {})".format(
                step.id, result.state, STOP_PREREQUISITE))
        else:
            workable.append(step.id)
    return workable, stopped, undetermined


def decide(order: Order, results: Dict[str, Result],
           action: str) -> Tuple[int, List[str]]:
    """Permitted (0), prohibited (1), or not established (2), with reasons.

    A definite prohibition outranks an unknown: a prerequisite known not to
    have happened, a guard that does not hold, or a question the owner has not
    answered are all things the decision says stop the work. Anything merely
    unsettled is exit 2, which a caller that spends money must also treat as
    denial.
    """
    by_id = {s.id: s for s in order.steps}
    reasons: List[str] = []
    blocked = False
    unsettled = False

    if action in EXTRA_ACTIONS:
        wanted: List[str] = []
        for name in EXTRA_ACTIONS[action]:
            if name not in results:
                return 2, ["the action {!r} presupposes {!r}, which "
                           "DECISIONS.md no longer names".format(action, name)]
            wanted.append(name)
            if name in by_id:
                wanted.extend(transitive_requirements(order.steps, name))
        for name in EXTRA_ACTION_GUARDS.get(action, []):
            if name not in results:
                return 2, ["the action {!r} is gated on the guard of {!r}, "
                           "which DECISIONS.md no longer names".format(
                               action, name)]
            if results[name].state == GUARD_FAILED:
                blocked = True
                reasons.append("{} is {}: {}".format(
                    name, GUARD_FAILED, results[name].evidence))
        self_state = None
    elif action in results:
        wanted = (transitive_requirements(order.steps, action)
                  if action in by_id else [])
        self_state = results[action].state
    else:
        known = sorted(set(results) | set(EXTRA_ACTIONS))
        return 2, ["{!r} is not an action this tool knows. Known: {}".format(
            action, ", ".join(known))]

    for name in dict.fromkeys(wanted):
        state = results[name].state
        if state == DONE:
            continue
        if state in DEFINITE_BLOCKERS:
            blocked = True
        else:
            unsettled = True
        reasons.append("{} is {}: {}".format(name, state,
                                             results[name].evidence))

    # The step's own state, and only the parts of it that forbid *doing* the
    # step. `not done` is not one of them — a step that has not happened is
    # precisely the one somebody is asking permission to do, and refusing it
    # while printing "do this instead: <the same step>" is the tool arguing
    # with itself. What forbids the doing is a stop the decision put there.
    if self_state in (BLOCKED_OWNER, GUARD_FAILED):
        blocked = True
        reasons.append("{} is {}: {}".format(action, self_state,
                                             results[action].evidence))
    elif self_state in (MANUAL, UNDEFINED_CRITERION):
        unsettled = True
        reasons.append("{} is {}: {}".format(action, self_state,
                                             results[action].evidence))

    if blocked:
        return 1, reasons
    if unsettled:
        return 2, reasons
    return 0, reasons


# --------------------------------------------------------------------------
# the freeze subcommand


def git_state(root: Path) -> Dict[str, Any]:
    def run(*args: str) -> Optional[str]:
        try:
            done = subprocess.run(("git", *args), cwd=str(root), check=False,
                                  capture_output=True, text=True, timeout=30)
        except (OSError, subprocess.SubprocessError):
            return None
        if done.returncode != 0:
            return None
        return done.stdout
    head = run("rev-parse", "HEAD")
    status = run("status", "--porcelain")
    if head is None or status is None:
        return {"commit": None, "dirty": None, "paths": None}
    paths = [line[3:].strip() for line in status.splitlines() if line.strip()]
    return {"commit": head.strip(), "dirty": bool(paths), "paths": paths}


def build_freeze(ctx: Context, acknowledgement: str, acknowledge_dirty: bool
                 ) -> Tuple[Optional[Dict[str, Any]], List[str]]:
    """The freeze body, or `None` and the refusals that stopped it."""
    refusals: List[str] = []

    section = ctx.d013_section()
    if section is None:
        refusals.append(
            "D-013 was not found in {} — the rule being frozen has to be in "
            "the file before it can be frozen".format(ctx.decisions))

    if not acknowledgement.strip():
        refusals.append(
            "no acknowledgement given — pass `--acknowledge \"...\"` naming who "
            "is freezing this and on what date")

    git = git_state(ctx.root)
    if git["commit"] is None:
        refusals.append(
            "the git revision could not be read — a freeze with no revision "
            "cannot be recovered; run this inside the repository")
    elif git["dirty"] and not acknowledge_dirty:
        refusals.append(
            "the working tree is dirty in {} path(s) and a freeze over "
            "uncommitted edits records a commit that does not describe what "
            "ran. Commit first, or re-run with `--acknowledge-dirty` to "
            "capture every dirty path and its digest in the artifact"
            .format(len(git["paths"])))

    inputs: Dict[str, Any] = {}
    for name, why in FROZEN_INPUTS:
        digest = sha256_file(ctx.root / name)
        if digest is None:
            refusals.append(
                "{} is named as frozen and cannot be read — a freeze with a "
                "hole in it is not a freeze".format(name))
            continue
        inputs[name] = {"digest": digest, "why": why}

    reviewer = tree_digest(ctx.root / "src" / "security_agent", "*.py")
    if reviewer is None:
        refusals.append("the reviewer's source under src/security_agent could "
                        "not be digested")

    configuration, config_error = resolved_configuration(ctx.root)
    if config_error is not None:
        refusals.append(config_error)

    if refusals:
        return None, refusals

    dirty_paths = {}
    if git["dirty"]:
        for name in git["paths"]:
            dirty_paths[name] = sha256_file(ctx.root / name) or "unreadable"

    return {
        "schema": FREEZE_SCHEMA,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "owner_acknowledgement": acknowledgement.strip(),
        "git": {"commit": git["commit"], "dirty": bool(git["dirty"]),
                "dirty_paths": dirty_paths},
        # The text, not only its digest. Digests make drift detectable and the
        # frozen state unrecoverable: a freeze that can say "something changed"
        # and cannot say what was frozen answers half the question.
        "d013": {"text": section, "digest": sha256_text(section)},
        "configuration": configuration,
        "inputs": inputs,
        "derived": {"reviewer": reviewer},
        "tools": {"python": sys.version.split()[0],
                  "d013_order": FREEZE_SCHEMA},
    }, []


def resolved_configuration(root: Path) -> Tuple[Dict[str, Any], Optional[str]]:
    """The models this shell would actually ask for, resolved not read.

    An unset `SECURITY_SCAN_VERIFY_MODEL` means the reviewer's own model and an
    unset `SECURITY_SCAN_MODEL` means Opus — resolution, not lookup. Recording
    the environment instead of the resolved values would freeze two blanks.
    """
    src = str(Path(root) / "src")
    if src not in sys.path:
        sys.path.insert(0, src)
    try:
        from security_agent.config import Config
    except Exception as exc:
        return {}, "the configuration could not be imported: {}".format(exc)
    try:
        cfg = Config.from_env()
    except Exception as exc:
        return {}, ("the configuration does not resolve in this shell: {} — "
                    "fix the environment before freezing".format(exc))
    init = Path(root) / "src" / "security_agent" / "__init__.py"
    try:
        version = init.read_text(encoding="utf-8").split(
            '__version__ = "')[1].split('"')[0]
    except (OSError, IndexError):
        version = "unknown"
    return {
        "model_requested": getattr(cfg, "model", None),
        "verifier_requested": getattr(cfg, "verifier_model", None),
        "provider": getattr(cfg, "provider", None),
        # A string, not a bool: `False -> True` in a list of digests reads as a
        # digest that went missing.
        "verify": "on" if getattr(cfg, "verify", False) else "off",
        "agent_version": version,
    }, None


def cmd_freeze(ctx: Context, args: argparse.Namespace) -> int:
    out = Path(args.out) if args.out else ctx.freeze
    if out.exists() and not args.replace:
        print("Refusing: {} already exists. A freeze silently replaced is a "
              "freeze nobody can compare against — move it aside, or pass "
              "`--replace` if you mean to start a new round.".format(out),
              file=sys.stderr)
        return 2
    body, refusals = build_freeze(ctx, args.acknowledge or "",
                                  args.acknowledge_dirty)
    if body is None:
        print("Refusing to freeze:", file=sys.stderr)
        for line in refusals:
            print("  - {}".format(line), file=sys.stderr)
        return 2
    try:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(body, indent=2, sort_keys=True) + "\n",
                       encoding="utf-8")
    except OSError as exc:
        print("Could not write {}: {}".format(out, exc), file=sys.stderr)
        return 2
    print("Frozen into {}: {} input(s), reviewer digest {}, commit {}.".format(
        out, len(body["inputs"]), body["derived"]["reviewer"][:12],
        body["git"]["commit"][:12]))
    print("Verify at any time with `tools/d013_order.py check freeze`.")
    return 0


# --------------------------------------------------------------------------
# rendering


def render(order: Order, results: Dict[str, Result], broken: Sequence[str],
           workable: Sequence[str], stopped: Sequence[str],
           undetermined: Sequence[str]) -> str:
    lines = ["D-013 · the order, from the artifacts", ""]
    for step in order.steps:
        result = results[step.id]
        waits = ", ".join(step.requires) if step.requires else "nothing"
        lines.append("  {:<16} {:<19} waits for: {}".format(
            step.id, result.state, waits))
        lines.append("      {}".format(result.evidence))
    lines.append("")
    if broken:
        lines.append("THE ORDER IS BROKEN:")
        for line in broken:
            lines.append("  - {}".format(line))
        lines.append("")
    if GENERATIONS in results:
        result = results[GENERATIONS]
        lines.append("  {:<16} {:<19} a standing requirement, not a step"
                     .format(GENERATIONS, result.state))
        lines.append("      {}".format(result.evidence))
        lines.append("")
    lines.append("Next: {}".format(", ".join(workable) if workable
                                   else "nothing that can be worked on"))
    if stopped:
        lines.append("Stopped: {}".format(", ".join(stopped)))
    if undetermined:
        lines.append("Cannot be determined ({}): {}".format(
            UNDEFINED_CRITERION, ", ".join(undetermined)))
    if order.questions:
        lines.append("")
        lines.append("Open questions, for the owner and nobody else:")
        for question in order.questions.values():
            lines.append("  {} — {}".format(question.id, question.text))
    if order.answers:
        lines.append("")
        lines.append("Answered:")
        for answer in order.answers.values():
            lines.append("  {} — {} ({}, {})".format(
                answer.id, answer.text, answer.answered_by, answer.answered_on))
    return "\n".join(lines)


def _payload(order: Order, results: Dict[str, Result], broken: Sequence[str],
             workable: Sequence[str], stopped: Sequence[str],
             undetermined: Sequence[str]) -> Dict[str, Any]:
    body = {
        "steps": [{"id": s.id, "requires": s.requires,
                   "done_when": s.done_when,
                   **results[s.id].as_dict()} for s in order.steps],
        "open_questions": [{"id": q.id, "asked_of": q.asked_of,
                            "text": q.text} for q in order.questions.values()],
        "answered_questions": [
            {"id": a.id, "answered_by": a.answered_by,
             "answered_on": a.answered_on, "text": a.text}
            for a in order.answers.values()],
        "violations": list(broken),
        "next": list(workable),
        "stopped": list(stopped),
        "undetermined": list(undetermined),
    }
    if GENERATIONS in results:
        body[GENERATIONS] = results[GENERATIONS].as_dict()
    return body


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Whether an action D-013 orders is permitted yet.")
    parser.add_argument("--root", default=str(ROOT))
    parser.add_argument("--decisions", default=None)
    parser.add_argument("--freeze-file", default=None,
                        help="the freeze artifact (default {})".format(
                            DEFAULT_FREEZE))
    parser.add_argument(
        "--ordinary-dir", default=os.environ.get("D013_ORDINARY_DIR"),
        help="directory holding the ordinary corpus manifest.json and "
             "adjudications.yml; it lives outside the repository today")
    parser.add_argument("--ordinary-manifest", default=None)
    parser.add_argument("--ordinary-adjudications", default=None)
    parser.add_argument("--generations", default=None,
                        help="the generation ledger (default {})".format(
                            DEFAULT_GENERATIONS))
    parser.add_argument("--json", action="store_true",
                        help="machine-readable output for a PreToolUse hook")

    sub = parser.add_subparsers(dest="command", required=True)
    check = sub.add_parser("check", help="may this action be done now")
    check.add_argument("action", help="a step id, or `spend`")
    sub.add_parser("status", help="every step, its state and its evidence")
    frz = sub.add_parser("freeze", help="write the freeze artifact")
    frz.add_argument("--out", default=None)
    frz.add_argument("--acknowledge", default=None,
                     help="who is freezing this, and when")
    frz.add_argument("--acknowledge-dirty", action="store_true")
    frz.add_argument("--replace", action="store_true")

    args = parser.parse_args(argv)
    ctx = Context(
        root=Path(args.root),
        decisions=args.decisions,
        freeze=args.freeze_file,
        ordinary_dir=args.ordinary_dir,
        ordinary_manifest=args.ordinary_manifest,
        ordinary_adjudications=args.ordinary_adjudications,
        generations=args.generations,
    )

    try:
        text = ctx.decisions.read_text(encoding="utf-8")
    except OSError as exc:
        return _refuse(args, "{} could not be read: {}. Point `--decisions` at "
                             "the file that carries D-013.".format(
                                 ctx.decisions, exc))
    try:
        order = parse_order(text)
    except OrderError as exc:
        return _refuse(args, str(exc))

    problems = divergence(order)
    if problems:
        return _refuse(args, " / ".join(problems))

    # Inside the refusal, not beside it. `check_freeze` reads the D-013 section
    # and that reader now refuses an unterminated fence rather than returning a
    # section that runs to the end of the file — which would have escaped here
    # as a traceback and exited 1, "prohibited", for something that is "cannot
    # tell". A crash must never borrow another answer's exit code.
    try:
        results = evaluate(ctx, order)
    except OrderError as exc:
        return _refuse(args, str(exc))
    broken = violations(order, results)
    workable, stopped, undetermined = next_steps(order, results)

    if args.command == "freeze":
        # Asked *after* the block is read, and this was the whole defect: the
        # freeze command used to return before `parse_order` ran, so `status`
        # could say `blocked_on_owner` while `freeze` wrote the artifact anyway.
        # A tool that reports a stop and then steps over it is worse than one
        # that reports nothing. Codex, 2026-09-04.
        code, reasons = decide(order, results, "freeze")
        if code != 0:
            print("Refusing to freeze:", file=sys.stderr)
            for line in reasons:
                print("  - {}".format(line), file=sys.stderr)
            return code
        return cmd_freeze(ctx, args)

    if args.command == "status":
        code = 0
        if broken:
            code = 1
        elif any(r.state in (UNKNOWN, UNDEFINED_CRITERION)
                 for r in results.values()):
            # A state nobody could establish can hide a violation, and this
            # tool does not report "clean" for "I could not check" — nor for
            # "the decision never said what would record this".
            code = 2
        if args.json:
            print(json.dumps(dict(_payload(order, results, broken, workable,
                                           stopped, undetermined),
                                  command="status", exit=code), indent=2))
        else:
            print(render(order, results, broken, workable, stopped,
                         undetermined))
        return code

    code, reasons = decide(order, results, args.action)
    if args.json:
        print(json.dumps(dict(_payload(order, results, broken, workable,
                                       stopped, undetermined),
                              command="check", action=args.action,
                              permitted=code == 0, exit=code,
                              reasons=reasons), indent=2))
        return code
    if code == 0:
        print("PERMITTED: {} — every prerequisite is done.".format(args.action))
    else:
        print("{}: {}".format(
            "PROHIBITED" if code == 1 else
            "NOT ESTABLISHED (treat as denial for anything that spends money)",
            args.action))
        for line in reasons:
            print("  - {}".format(line))
        if workable:
            print("  Do this instead: {}".format(", ".join(workable)))
    return code


def _refuse(args: argparse.Namespace, message: str) -> int:
    """Exit 2 with a remedy. A refusal with no way out gets worked around."""
    if getattr(args, "json", False):
        print(json.dumps({"command": getattr(args, "command", None),
                          "exit": 2, "error": message}, indent=2))
    else:
        print("Cannot answer: {}".format(message), file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
