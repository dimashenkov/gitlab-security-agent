"""Turning a set of findings into a pipeline verdict.

Kept separate from reporting on purpose: what gets *shown* and what gets
*blocked* are different decisions, and conflating them produces a gate that
either hides findings it will not block on, or blocks on everything it shows.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, List

from .config import Config
from .models import (
    CONFIDENCE_ORDER,
    REVIEW_PERFORMED,
    SEVERITY_ORDER,
    STOP_EXPLANATIONS,
    STOP_INCONCLUSIVE,
    Candidate,
    ScanOutcome,
    confidence_rank,
    recognised,
    severity_rank,
)

# Exit codes. 1 means "the code has a problem", 2 means "the check itself did
# not run properly" — a distinction worth keeping, because the first is the
# author's to fix and the second is the pipeline owner's.
EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2


@dataclass
class Decision:
    exit_code: int
    reason: str
    blocking: List[Candidate] = field(default_factory=list)
    non_blocking_reasons: List[str] = field(default_factory=list)
    # Findings that would otherwise have been judged on their merits but belong
    # to a category this project does not gate on. Carried on the decision so
    # the report can mark them individually: a high-severity finding sitting
    # under a green pipeline needs to say which setting let it through, next to
    # the finding, not in a footnote.
    policy_excluded: List[Candidate] = field(default_factory=list)
    # **Whether the review's coverage was partial, adjudicated once here.**
    # The report used to ask `outcome.complete`, which is only the stop reason,
    # while `_partial` counts three things — so a truncated diff or a context
    # refusal printed "✅ no findings reported" over a review that had not seen
    # the change. The banner's own comment says a warning further down does not
    # undo a green tick at the top.
    #
    # Carried rather than recomputed: a renderer reaching into `_partial` would
    # be a second place deciding what partial means, and the two would drift.
    # Codex, on the batched round for six unchecked claims, 2026-09-07.
    partial: bool = False

    @property
    def blocked(self) -> bool:
        return self.exit_code != EXIT_OK


def blocking_findings(cfg: Config, outcome: ScanOutcome) -> List[Candidate]:
    """Which reported findings actually stop the merge.

    A finding blocks when it is severe enough, confident enough, and the change
    under review is responsible for it. Everything filtered out here still
    appears in the report — it is excluded from the gate, not from view.
    """
    threshold = cfg.fail_threshold
    if threshold is None:
        return []

    minimum_severity = severity_rank(threshold)
    minimum_confidence = confidence_rank(cfg.min_confidence)

    ungated = {c.lower() for c in cfg.ungated_categories}

    blocking = []
    for candidate in outcome.reported:
        if not candidate.in_changed_lines and not cfg.gate_pre_existing:
            continue

        # A category the project has decided not to gate on takes precedence
        # over every rule below, including the removed-control one. A team that
        # has ruled out a whole class of weakness has ruled out guards for that
        # class too, and a knob with an unstated exception is worse than one
        # that does exactly what its name says. The finding is still reported in
        # full; only its power to stop the merge is withheld.
        if candidate.finding.category.lower() in ungated:
            continue

        # A change that deletes a security control blocks on that alone. The
        # question there is not how bad the resulting weakness scores but why a
        # guard someone deliberately added is being taken away, and that belongs
        # to the author of the change rather than to a severity scale. Measured:
        # a merge request reverting the fix for CVE-2023-41040 was found and
        # confirmed on five runs out of five and blocked on none of them,
        # because three independent reads agreed it rated below the threshold.
        if candidate.removes_control and cfg.gate_removed_controls:
            blocking.append(candidate)
            continue
        # **And the flag is only ever set by the verifier panel.** `verify.py`
        # returns before `_partition` when verification is off, so with
        # `SECURITY_SCAN_VERIFY=false` no candidate can carry
        # `removes_control` and the rule above is unreachable — the finding
        # then falls to the severity comparison and the report says it passed
        # for being *below the threshold*, which is a sentence about a number
        # that never decided anything. A rule that disappears without a word
        # is worse than one that was never written: the run looks the same.
        #
        # Not read from a stop reason or a spelling. `_control_unevaluated`
        # asks the accounting question — could this rule have been evaluated
        # at all — and `decide` turns that into a said-out-loud incompleteness
        # rather than a silent pass.

        # A value nobody recognises is not a value below the threshold. Both
        # ranks return -1 for an unknown word, and `-1 < minimum` was letting a
        # `confidence` of "High" — one capital letter — carry a `critical`
        # finding past the gate: rendered as CRITICAL in the report, absent
        # from `blocking_fingerprints`, exit 0. `recognised()` is asked first,
        # so an unparseable rating fails toward blocking and says so, rather
        # than silently passing.
        if recognised(candidate.severity, SEVERITY_ORDER) and (
                severity_rank(candidate.severity) < minimum_severity):
            continue
        if recognised(candidate.confidence, CONFIDENCE_ORDER) and (
                confidence_rank(candidate.confidence) < minimum_confidence):
            continue
        blocking.append(candidate)
    return blocking


def policy_excluded(cfg: Config, outcome: ScanOutcome) -> List[Candidate]:
    """Reported findings whose category this project has chosen not to gate on."""
    ungated = {c.lower() for c in cfg.ungated_categories}
    if not ungated:
        return []
    return [c for c in outcome.reported if c.finding.category.lower() in ungated]


# Endings `fail_on_incomplete` may not override. One entry, and the reason it is
# a set rather than an `if` is that the next one will be added by somebody who
# finds this line rather than by somebody who remembers the rule.
NEVER_FORGIVEN = frozenset({STOP_INCONCLUSIVE})


def _readable_change(outcome: ScanOutcome) -> bool:
    """Was there anything in this change a reviewer could have opened?

    The first version of the branch below asked only whether anything changed,
    and a change made entirely of binary files has no text: `get_diff` emits
    `Binary files a/x and b/x differ` with no `+++` line, so no exposure is
    recorded and none could be. Refusing that is refusing a review that did
    everything available to it.

    A rename of a text file is deliberately *not* exempt. The diff carries no
    content for a pure rename either, but the file is readable and a rename can
    move code out of a protected path — a reviewer that opened nothing has not
    reviewed it.

    **A deletion counts, and until 2026-09-09 it did not.** `coverage.changed`
    is filled from a `--diff-filter=ACMRT` call, and `workspace.py` says on the
    line that builds it that a pure deletion is therefore not in the list at
    all. So a merge request whose only change was `git rm` of a guard, reviewed
    by a run that called `finish_review` on its first turn, reached
    `_reviewed_nothing` true, `_partial` false and this predicate false — and
    came out `exit 0`, "No security findings." The same file *modified* instead
    exits 2 with "none reached the reviewer". The one change a security review
    exists to catch was the one the aggregate dropped.

    Deleted paths are counted here rather than in `coverage.changed` because a
    deleted file cannot be opened: it belongs to what had to be *accounted
    for*, which is the question this predicate asks, and not to what had to be
    read.

    **And a whole-repository review has something to open by definition.**
    `coverage.changed` is filled only on the diff path — `agent.py` and
    `runner_claude_code.py` both guard it with `mode == "diff"` — so in repo
    mode this returned `False`, `_partial` was `False`, and the branch that
    refuses a review which opened nothing could not fire at all. Measured
    2026-09-09: `mode="repo"`, no exposures, `finish_review` on the first turn,
    `exit 0` and "✅ no findings reported". The identical run in diff mode
    exits 2.

    That is not a corner. `Config.resolve_mode` returns `repo` whenever the
    mode is `auto` and there is no merge-request id — which is every ordinary
    branch pipeline, and on GitHub every `push` event. So the job that gates
    the merge runs in repo mode on a large share of installations, and every
    hole closed on the diff path had a twin here that was open.

    `False` about a whole tree means "there was nothing anybody could have
    opened", and about a repository that is never true.

    **Adjudicated, and closed.** The repair turns 15 of this repository's own
    tests red — the exit-code tests, the artifact test, the suppression tests,
    the verification handoff — because every one of them drives a fake model
    that replies once and calls no tool, which is exactly the state this branch
    refuses in diff mode. So the question was not mechanical: *is a repo-mode
    review that made no tool call a pass?*

    Codex, 2026-09-09: *"Repo mode with zero exposures must not pass. Repo mode
    is a claim about an entire repository, so a completed response without
    receiving repository content is not a review. The 15 failing tests are
    stale fixtures. Do not preserve an unsafe product contract to accommodate
    mocks."*

    The fixtures were given a reviewer that reads something.
    """
    if outcome.mode != "diff":
        return True
    # **Both lists, filtered the same way.** `unreadable` was subtracted from
    # `changed` and not from `deleted`, and `inventory_notes` can put one path
    # in both — a deleted binary, a removed submodule. So a binary-only
    # deletion counted as a readable change, and a completed review with no
    # exposure was refused for failing to open something that cannot be
    # opened. Codex, 2026-09-09. A *textual* deletion stays reviewable: its
    # removed lines are in the diff, and it is not in `unreadable`.
    #
    # **Source is not subtracted.** Codex, 2026-09-09. The exemption above is
    # for material that is unreadable *and* not source — an image, a rename, a
    # mode bit — where "nobody opened it" is not a gap. A `.js` git calls
    # binary is a gap, and subtracting it here said the opposite: a change made
    # only of withheld source counted as a change with nothing in it to open.
    # It still ends partial, but through the branch that names the file rather
    # than through the one that says nothing was readable, so the reader is
    # told which file was never shown.
    unreadable = ({path for path, _ in outcome.coverage.unreadable}
                  - set(outcome.coverage.unreadable_source))
    return bool((set(outcome.coverage.changed)
                 | set(outcome.coverage.deleted)) - unreadable)


def _reviewed_nothing(outcome: ScanOutcome) -> bool:
    """Did this run open no part of the change at all?

    The difference between a review that stopped early and a review that never
    started, which `fail_on_incomplete` was treating as one thing.

    That flag is a policy about *partial* coverage: the agent read six of ten
    files, the operator knows which six, and letting the pipeline through while
    the limits are tuned is their call about their own risk. It says so, and
    that reasoning is sound for every ending where work happened — a turn
    limit, a budget that ran out mid-search, a truncated diff.

    It is not sound when nothing happened. The CLI failing to start, the MCP
    server never coming up, a terminal object that will not parse: there is no
    partial coverage to weigh, and "no blocking findings" over a review that
    opened no file is the sentence this whole product exists to prevent. Six of
    the eight ways the local runner can fail reached exit 0 through that flag.

    Read from coverage accounting rather than from the stop reason, because a
    set of stop reasons can only be right about the endings somebody thought to
    add to it — and this repository has now been caught four times by a check
    that knew a list of spellings. Whether a file was opened is a fact about
    the run, and it stays true for endings nobody has invented yet.

    `exposures` and nothing else, after two readings of the alternatives.

    Not `tool_calls`. A tool call is an *attempt*, and the record keeps the
    failures: a read the budget refused, a path that did not exist, a search
    that matched nothing. `list_changed_files` then `finish_review` is two
    calls and no code seen. Counting attempts would let a session that reached
    the repository and got nothing out of it pass as work.

    Not `files_examined`, which means files the agent opened *by name*. A
    whole-change `get_diff` puts thirty files in front of the model without
    opening one, and `search_code` returns lines from files nobody named. That
    list answers "nothing" for a review that read the entire change.

    Not a reported finding either, though it is tempting. A finding proves its
    citation exists — `report_finding` validates the quoted lines against the
    file — which is a fact about the quote and not about whether the change was
    investigated. Nothing in `report_finding` records an exposure, so a finding
    is not evidence that any of the change reached the model.

    `exposures` is the one record of what actually arrived, through any of the
    three channels that can carry it. It is proof of inspection and only that:
    whether the inspection went far enough is the completeness question, which
    `finish_review`, the profile and the budget answer separately and more
    strictly. This is the sanity check underneath them — the one that says the
    MCP server came up and the reviewer got something to read.

    **Of the change, not of anything.** `not outcome.exposures` asks an
    emptiness question where the question is membership, so bytes from files
    *outside* the change satisfied it. Measured 2026-09-09: two changed files,
    the only exposures a `search_code` that matched `README.md` and
    `docs/x.md`, and the merge request comment read "✅ no findings reported"
    over a change of which nothing was delivered.

    No attacker is needed. The reviewer orients with a search, the matches land
    in unchanged files, it judges the change trivial and calls `finish_review`
    without ever calling `get_diff` — a cheaper model's failure mode, which is
    the shape this repository has just spent a trial measuring.

    A deleted file counts as part of the change: its removed lines are in the
    diff, and `get_diff` records an exposure for it. When neither list is
    populated the membership question has no answer, so the emptiness question
    is asked instead — that is the repo-mode case, and `_readable_change`
    carries it.
    """
    accountable = set(outcome.coverage.changed) | set(outcome.coverage.deleted)
    if not accountable:
        return not outcome.exposures
    return not any(path in accountable for path, _channel in outcome.exposures)


def _partial(outcome: ScanOutcome) -> bool:
    """Did this run fail to cover the change it claims to have reviewed?

    Two ways, and until now only one of them reached here. The agent can stop
    early — that is `stop_reason`. Or the change can be larger than the diff the
    reviewer is shown: `Workspace._bounded` cuts at a ceiling and records it,
    and everything after the cut was never put in front of the model. The run
    then ends `completed`, the coverage accounting says every changed file was
    accounted for, and the gate exits 0 — "checked and clean" over the first
    part of a change. That is the failure this product exists to prevent, and
    the only thing standing in front of it was a warning in the report.

    Read from `coverage.diff_truncated` rather than from the notice appended to
    the diff, because the notice is text in the model's context and an author
    can write the same sentence into a file. The flag is accounting.

    It is deliberately *not* in `NEVER_FORGIVEN`. A profile that cannot conclude
    is a property of the configuration and no run of it means anything; a
    truncated diff is a property of one change, and the operator has real moves
    — split the change, or narrow the review with `--path`. A ceiling nobody can
    get past would make a large legitimate change permanently unmergeable, and a
    gate that cannot be satisfied gets deleted rather than obeyed. So it fails
    loudly by default and stays forgivable by the same documented flag as every
    other partial review.

    `SECURITY_SCAN_DIFF_CEILING_BYTES` stood in that list and is not a third
    move: it raises how many bytes the workspace reads, while
    `tools.MAX_DIFF_CHARS` independently bounds what the model is shown and has
    no setting behind it. Measured on 2026-09-08 with the byte ceiling raised
    fifty times above it — the workspace read the change whole and the result
    was still trimmed. `_why_partial` therefore names the two moves that work
    and says this one does not; `LIMITATIONS.md` carries what is left over.
    """
    return (not outcome.complete
            or outcome.coverage.diff_truncated
            or outcome.coverage.context_refusals > 0
            # **Source the reviewer could not be shown.** Codex, 2026-09-09:
            # git decides `binary` from the bytes, so one NUL in a comment
            # turns a `.js` into "Binary files … differ" — and
            # `_readable_change` subtracted it while `_reviewed_nothing`'s
            # `accountable` did not, so one *other* readable file satisfied
            # the gate for the whole change. Exit 0, "No security findings",
            # over a file nobody saw. The second half of the `.gitattributes`
            # bypass, reached without `.gitattributes`.
            #
            # A real image is not this: `unreadable_source` asks whether the
            # path is source, so a PNG stays a disclosed non-source change and
            # blocks nothing. Three states, which is the ruling.
            or bool(outcome.coverage.unreadable_source)
            or _nothing_was_readable(outcome))


def _nothing_was_readable(outcome: ScanOutcome) -> bool:
    """A change with something in it, and nothing in it a reviewer could read.

    `_readable_change` was written to *exempt* this from the "reviewed nothing"
    refusal, on the reasoning that a run which opened nothing because there was
    nothing openable did everything available to it. That reasoning is about
    the reviewer's conduct and it is fair; the exit code is about the change,
    and it was answering a different question. Nothing inspectable is not
    evidence of no findings, and the run was exiting 0 with "No security
    findings." over material nobody could look at.

    Reached on 2026-09-07 from an attack rather than from an asset commit: one
    line of `.gitattributes` saying `* -diff` made every file read as binary,
    and the unconditional green was the second of the two ways that line
    disarmed the gate. `--attr-source` closes the attack; this closes the
    unconditional green, because the next way of making a change unreadable
    should not find it waiting. Codex was stricter here than the proposal put
    to it, 2026-09-07.

    Partial rather than never-forgiven: a repository whose merge requests are
    genuinely assets has a real move, which is
    `SECURITY_SCAN_FAIL_ON_INCOMPLETE=false` or a scope that excludes them. A
    gate that cannot be satisfied gets deleted rather than obeyed.
    """
    if not outcome.coverage.changed:
        return False
    return not _readable_change(outcome)


def truncation_remedy(code: Callable[[str], str] = lambda text: text) -> str:
    """What an author can do about a diff that was cut, written once.

    **Once because it drifted.** This sentence lived in two hand-written
    copies, one here and one in `report.py`, describing the same run to the
    same person through two channels. Six gate rounds on 2026-09-08 found it
    wrong in five different ways, and twice a repair landed in one copy and not
    the other — so the two documents a reader has about one run disagreed about
    what to do next. A test asserting selected substrings in each could not
    catch that, because each copy was self-consistent. Codex asked for exactly
    this shape: build the explanation once, render Markdown separately, and
    assert normalised equality.

    `code` wraps identifiers for the channel: the identity function for a job
    log, `rendering.code_span` for a merge-request comment. Nothing else about
    the sentence may differ between them.

    Every clause is qualified because the unqualified version of it was wrong:

    * Reading the files back does not recover the change — `read_file` returns
      the reviewed revision, so a removed line is not in it.
    * `--path` helps only for files whose own diff fits. A file bigger than the
      limit is cut identically when asked for alone, whether it was the file
      the cut landed inside or a later one that was dropped entirely.
    * `SECURITY_SCAN_DIFF_CEILING_BYTES` lifts the workspace's byte ceiling
      only. `tools.MAX_DIFF_CHARS` bounds what the model is shown, has no
      setting behind it, and is the smaller of the two by default.

    Both cuts are described rather than one being named, because neither
    caller knows which happened: `_handle_get_diff` has `DiffCut.mid_file` and
    `ws.last_diff_truncated` and collapses both into one flag. Carrying that
    through is the better repair and is recorded in `LIMITATIONS.md`.
    """
    # **The opening clause names no limit either**, for the same reason the
    # rest of the sentence is conditional. It said "larger than the reviewer
    # can be shown", which is one of the two — and with
    # `SECURITY_SCAN_DIFF_CEILING_BYTES` set below `MAX_DIFF_CHARS` the diff
    # can fit what the reviewer is shown and still be cut while the workspace
    # reads it. The same for a `path`-scoped call on a file that fits the
    # display limit. Codex, eighth gate round, 2026-09-08.
    # And it does not claim the reviewer stopped there. `diff_truncated` is
    # sticky across every `get_diff` in the run and is set by a `path`-scoped
    # call too, so "it saw the first part of the change and no more" describes
    # a run that may have gone on to read several other files whole. What the
    # flag establishes is narrower: at least one diff was cut, and the lines
    # past that cut were never delivered. Codex, ninth gate round.
    return (
        "at least one diff was cut before all of it reached the reviewer, so "
        "some changed lines were never delivered. What it did not see cannot be "
        "recovered afterwards — reading the files back gives the state after "
        "the change, not the change. {path} helps only for the files whose own "
        "diff fits the limit; any file whose change is larger than that has to "
        "have the change to it split, because asking for that file alone is "
        "cut in the same place. Raising {ceiling} helps only when the "
        "workspace byte ceiling is what cut the diff; it does not move the "
        "fixed limit on how much the reviewer is shown, and that limit is the "
        "smaller of the two by default".format(
            path=code("--path"),
            ceiling=code("SECURITY_SCAN_DIFF_CEILING_BYTES")))


def _why_partial(outcome: ScanOutcome) -> str:
    """The sentence naming which of the three happened, for the author to act on.

    Each is named separately because the remedy is different: nothing about turn
    limits tells anyone to split a merge request, and nothing about a large
    change tells anyone to raise a context limit.

    A refusal is named first when there is one. It is the newest of the three
    and the easiest to miss, and a run can carry it *and* have stopped early —
    reporting only the stop reason would send the author to the wrong setting.
    """
    hidden = outcome.coverage.unreadable_source
    if hidden:
        # Named first when there is one, and with the paths: the remedy is
        # not a setting but a look at the file. A reader told only "the review
        # is incomplete" has nothing to act on, and the whole point of this
        # state is that a person can see which file was never shown.
        return ("{} changed source file(s) could not be read — git treats "
                "them as binary, which one NUL byte is enough to do: {}"
                .format(len(hidden), ", ".join(sorted(hidden)[:4])))
    refusals = outcome.coverage.context_refusals
    if refusals:
        also = ("" if outcome.complete else
                ", and the review then stopped before finishing ({})".format(
                    STOP_EXPLANATIONS.get(outcome.stop_reason,
                                          "reason not recorded")))
        return (
            "{} tool result(s) were larger than the review's remaining context "
            "budget and were not returned, so the reviewer asked for code it "
            "never saw{}. Narrow those reads, or raise the context limit, for a "
            "complete reading".format(refusals, also))
    if not outcome.complete:
        return STOP_EXPLANATIONS.get(outcome.stop_reason, "the review did not complete")
    # Before the truncation sentence, because a change with nothing readable in
    # it was never truncated — the fall-through would send the author to split
    # a change that is not too large. The audit that found this one also found
    # this function being skipped in the forgiven branch, which is the same
    # mistake in the other direction: a cause named that did not happen.
    if _nothing_was_readable(outcome):
        return (
            "every file in this change is binary or otherwise unreadable, so "
            "there was no code for the reviewer to read and the result says "
            "nothing about it. If this repository's changes are genuinely "
            "assets, exclude them from the review or set "
            "SECURITY_SCAN_FAIL_ON_INCOMPLETE=false")
    # **The remedy named here has to be one that works.** It said "read the
    # oversized file in windows", which is the same wrong advice the tool note
    # gave and Codex refused on the gate for that change — `read_file` returns
    # the reviewed revision, so it cannot show a removed line and cannot tell
    # an added one from a line that was always there. It answers a different
    # question while looking like an answer, and the reader stops.
    #
    # **The third slot is empty on purpose, and it took three attempts.** It
    # held "read the oversized file in windows", which cannot show a removed
    # line. It then held `SECURITY_SCAN_DIFF_CEILING_BYTES` flatly, and Codex
    # measured that too: the setting moves `Workspace.diff_ceiling`, which is
    # how many *bytes* the workspace will read, while `tools.MAX_DIFF_CHARS`
    # independently trims what the model is shown and is a module constant. A
    # single file over 120,000 characters stays partial at any value of it.
    #
    # It then said the setting "does not help here", and that was too strong in
    # the other direction: **two ceilings can cut a diff and this function
    # cannot tell which one did.** `_handle_get_diff` knows — `trimmed` is the
    # character limit and `ws.last_diff_truncated` is the byte limit — and
    # collapses both into one `diff_truncated` flag before the gate sees it. So
    # the sentence is conditional, which is what the code can support. Codex,
    # fifth gate round, 2026-09-08; carrying the cause through `Coverage` is
    # the better repair and is written down rather than done here.
    #
    # **The two remaining moves are not interchangeable either**, and listing
    # them side by side was the last thing wrong here. `--path` narrows the
    # review to fewer files, which is a real move when the cut dropped later
    # *files*; it does nothing when one file's own diff is over the limit,
    # because asking for that file alone reaches the identical limit. Only
    # splitting the change to that file helps then. Codex, sixth gate round,
    # 2026-09-08, having noticed that the sentence recommended `--path`
    # immediately after naming the case it cannot serve.
    #
    # Both cases are described rather than one being chosen, because this
    # function cannot tell them apart: `_handle_get_diff` knows — `DiffCut`
    # carries `mid_file` — and does not pass it on. That, and the two ceilings
    # below, are the same missing distinction and are recorded together in
    # `LIMITATIONS.md`.
    return truncation_remedy()


def decide(cfg: Config, outcome: ScanOutcome) -> Decision:
    """The pipeline verdict for this run."""
    # An incomplete review has no opinion worth acting on. Reporting "no
    # blocking findings" after the agent ran out of turns would be the single
    # most damaging thing this tool could do, because it looks exactly like a
    # pass.
    # Some endings are not the operator's to forgive.
    #
    # `SECURITY_SCAN_FAIL_ON_INCOMPLETE=false` exists so a team can let a
    # truncated review through while they tune the limits — a policy choice
    # about *their* risk. `probe` is not that. It is six turns and no verifiers,
    # sized to stop early, and it says of itself that it cannot conclude. A flag
    # meaning "accept partial reviews" turning that into exit 0 would let a
    # profile documented as never conclusive hand out clean passes.
    if outcome.stop_reason in NEVER_FORGIVEN:
        return Decision(
            partial=_partial(outcome),
            exit_code=EXIT_ERROR,
            reason=(
                "{}. No setting makes this a pass: it is a property of the "
                "profile, not a policy about partial reviews.".format(
                    STOP_EXPLANATIONS.get(outcome.stop_reason,
                                          "the review could not conclude"))),
        )

    # `or`, not `and`. The conjunction asked the question only of a run that
    # had already admitted to stopping early — so a review that ended cleanly
    # on its first turn, having opened nothing at all, walked past every branch
    # below and came out as "No security findings." over a changed file nothing
    # read. That is the sentence this product exists to prevent, reachable in
    # the gate that prevents it: a reviewer that calls `finish_review`
    # immediately, or a provider that returns `end_turn` before any tool call,
    # produced a green pipeline over unread code.
    #
    # Every test that passed `exposures=[]` also passed a stop reason that made
    # the run partial, so the combination that matters — finished, and nothing
    # opened — was never asked about.
    # `_nothing_was_readable` is excluded here on purpose. It makes `_partial`
    # true, and this branch is the unforgivable one — so without the exclusion
    # a change made only of assets would be refused with "no setting makes it
    # a pass", which is stricter than the adjudication asked for and would make
    # the gate unsatisfiable for a repository of images. Opening nothing is the
    # *expected* conduct when there is nothing to open; what is not acceptable
    # is calling the result a pass, and the forgivable branch below does that.
    # **A run that did not perform a review is not a review that opened
    # nothing.** The two non-performed dispositions — a label waiver and a
    # change with nothing reviewable — reach here with no exposures by design,
    # and widening `_readable_change` to cover repo mode made this branch fire
    # on them: the skip label exited 2 instead of 0, which is the escape hatch
    # turned into a block, and the first of the seven things Codex's own
    # adjudication said the `review_status` repair must not break. Caught by
    # the suite on 2026-09-09, one edit after it was introduced.
    if (outcome.review_status == REVIEW_PERFORMED
            and _reviewed_nothing(outcome)
            and not _nothing_was_readable(outcome)
            and (_partial(outcome) or _readable_change(outcome))):
        detail = " ({})".format(outcome.stop_detail) if outcome.stop_detail else ""
        if _partial(outcome):
            reason = (
                "{}{}, and no part of the change is recorded as having "
                "reached the reviewer. There is no partial coverage to weigh, "
                "so no setting makes it a pass.".format(
                    _why_partial(outcome), detail))
        else:
            # A different sentence, because it is a different thing. The run
            # did not stop early — it ended, saying it was done, having opened
            # nothing. `_why_partial` would have guessed at a limit that was
            # never hit and sent the reader to look for it.
            reason = (
                "the review reported itself finished{} without opening any "
                "part of the change: {} file(s) changed and none reached the "
                "reviewer. A verdict over code nothing read is not a verdict, "
                "and no setting makes it a pass.".format(
                    detail, len(outcome.coverage.changed)))
        return Decision(partial=_partial(outcome), exit_code=EXIT_ERROR, reason=reason)

    if _partial(outcome) and cfg.fail_on_incomplete:
        explanation = _why_partial(outcome)
        detail = " ({})".format(outcome.stop_detail) if outcome.stop_detail else ""
        return Decision(
            partial=_partial(outcome),
            exit_code=EXIT_ERROR,
            reason=(
                "Review incomplete — {}{}. The result cannot be treated as a "
                "pass. Set SECURITY_SCAN_FAIL_ON_INCOMPLETE=false to allow "
                "partial reviews through.".format(explanation, detail)
            ),
        )

    blocking = blocking_findings(cfg, outcome)

    # **A rule that could not be evaluated is an incomplete review**, not a
    # silent pass. `removes_control` is set only inside the verifier panel, so
    # with verification off the removed-control rule is unreachable and a
    # change that takes a guard away falls to the severity comparison — where
    # the report says it passed for being below the threshold, a sentence
    # about a number that never decided anything.
    #
    # Forgivable by the same documented flag as every other partial review:
    # turning verification off is a real configuration a team may choose, and
    # a gate that cannot be satisfied gets deleted rather than obeyed. What is
    # not negotiable is that it says so.
    # **After the blocking check, and only when nothing blocks.** The
    # rule matters when it would otherwise change the outcome; a finding
    # that blocks on its own merits is not made more blocked by a rule
    # nobody could evaluate, and reporting incompleteness there replaced
    # `exit 1, this finding blocks` with `exit 2, something could not be
    # checked` — a different sentence about a run that was answering
    # correctly. Caught by a conformance test one edit after it was
    # introduced.
    if (not blocking and _control_rule_unevaluated(cfg, outcome)
            and cfg.fail_on_incomplete):
        return Decision(
            partial=True,
            exit_code=EXIT_ERROR,
            reason=(
                "Review incomplete — SECURITY_SCAN_GATE_REMOVED_CONTROLS is "
                "on and verification is off, and the removed-control rule is "
                "decided only by the verifier panel. A change that removes a "
                "guard would pass here as though it had been weighed and "
                "found below the severity threshold. Turn verification on, "
                "turn the rule off, or set "
                "SECURITY_SCAN_FAIL_ON_INCOMPLETE=false to allow partial "
                "reviews through."),
        )

    notes = _non_blocking_notes(cfg, outcome, blocking)
    excluded = policy_excluded(cfg, outcome)

    if blocking:
        # Two different rules can block, and the message has to name the one
        # that actually applied. A finding stopped for deleting a guard is
        # often below the severity threshold, and telling its author it was
        # "at or above the threshold" sends them to argue with the wrong number.
        removed = [c for c in blocking if c.removes_control]
        rated = [c for c in blocking if not c.removes_control]

        parts = []
        if removed:
            parts.append(
                "{} finding(s) where this change removes an existing security "
                "control ({})".format(len(removed), _levels(removed))
            )
        if rated:
            parts.append(
                "{} finding(s) at or above the {} threshold with at least {} "
                "confidence ({})".format(
                    len(rated), cfg.fail_on, cfg.min_confidence, _levels(rated))
            )

        return Decision(
            partial=_partial(outcome),
            exit_code=EXIT_FINDINGS,
            reason="; ".join(parts) + ".",
            blocking=blocking,
            non_blocking_reasons=notes,
            policy_excluded=excluded,
        )

    if _partial(outcome):
        # Named even when it is forgiven. "Coverage is partial" is the whole
        # difference between this exit 0 and a clean one, and the sentence
        # carries which of the two produced it.
        # **The cause, from the function that knows all of them.** This branch
        # had its own two-case guess — "too large", or the stop reason — while
        # `_why_partial` sits above it naming every cause and ordering them by
        # which remedy the reader needs. So a review partial only because of
        # context refusals was told the change was too large, sending the
        # operator to the diff ceiling for a context-limit problem; and a
        # change with nothing readable in it would have been told the same.
        # A category omitted from a message is the same defect as a category
        # omitted from a count. Found by the audit of 2026-09-07.
        why = outcome.stop_detail if not outcome.complete and outcome.stop_detail \
            else _why_partial(outcome)
        return Decision(
            partial=_partial(outcome),
            exit_code=EXIT_OK,
            reason=(
                "No blocking findings, but the review did not complete ({}). "
                "Coverage is partial.".format(why)
            ),
            non_blocking_reasons=notes,
            policy_excluded=excluded,
        )

    if outcome.reported:
        return Decision(
            partial=_partial(outcome),
            exit_code=EXIT_OK,
            # **"None blocking", not "none at or above the threshold".** The
            # sentence asserted severity was the reason whatever the reason
            # was — it was printed about a withheld `critical` whose finding
            # had been filed as pre-existing. Which rule applied is in
            # `non_blocking_reasons`, one reason per finding, and that is where
            # a reader can act on it. Codex, 2026-09-07.
            # `cfg.fail_on` was still being passed here after the sentence
            # stopped naming the threshold. Harmless to `format`, and exactly
            # the kind of leftover that makes a reader think the threshold is
            # in the sentence somewhere.
            reason="{} finding(s) reported, none blocking under the configured policy.".format(
                len(outcome.reported)),
            non_blocking_reasons=notes,
            policy_excluded=excluded,
        )

    return Decision(
        partial=_partial(outcome),
        exit_code=EXIT_OK,
        reason="No security findings.",
        non_blocking_reasons=notes,
    )


def _levels(candidates: List[Candidate]) -> str:
    counts = {}
    for candidate in candidates:
        counts[candidate.severity] = counts.get(candidate.severity, 0) + 1
    return ", ".join(
        "{} {}".format(count, level)
        for level, count in sorted(counts.items(), key=lambda kv: -severity_rank(kv[0]))
    )


def _control_rule_unevaluated(cfg: Config, outcome: ScanOutcome) -> bool:
    """Could the removed-control rule have been evaluated on this run at all?

    `removes_control` is set in one place — `verify.py`, inside the panel — and
    `verify_candidates` returns before it whenever verification is off. So
    with `SECURITY_SCAN_VERIFY=false` the rule at the top of
    `blocking_findings` is unreachable, and a change that removes a guard
    falls through to the severity comparison. The report then says it passed
    for being *below the threshold*: a sentence about a number that never
    decided anything, and the same wrong attribution the comment beside that
    rule was written to prevent, in the other direction.

    Asked of the configuration rather than of the candidates, because "no
    candidate carried the flag" is exactly what an evaluated rule that found
    nothing also looks like. The two are different answers and this is the
    only thing that can tell them apart.
    """
    if not cfg.gate_removed_controls or not outcome.reported:
        return False
    if not cfg.verify:
        return True
    # **And verification running is not verification answering.** Three more
    # routes reach the gate with the flag never assigned, and the first is the
    # worst: when every seat errors, `verify._decide` returns before it is set
    # at all. The finding then falls to the severity comparison and the report
    # says it passed for being below the threshold — the same sentence about a
    # number that never decided anything, arriving by a different road than
    # the one this predicate was written to close an hour earlier.
    #
    # Asked of the votes rather than of a list of endings: a candidate with no
    # *usable* vote had no panel, whether because every seat failed or because
    # it was past `SECURITY_SCAN_VERIFY_MAX` and stamped without one. A set of
    # spellings can only be right about the endings somebody thought to add to
    # it, and this repository has been caught that way four times.
    # `candidate.votes and …`: a candidate with no votes at all was never
    # sent to a panel, and that is `_worth_verifying`'s decision — the
    # product's own judgement that this finding does not need one. A candidate
    # *sent* and unable to answer is the different thing, and the one this is
    # about.
    #
    # The remaining route — past `SECURITY_SCAN_VERIFY_MAX`, stamped
    # `confirmed` with no panel — is not caught here and is named in the
    # candidate's own `verdict_reason` and in `metrics.verification_over_limit`
    # instead. Recorded in `LIMITATIONS.md` rather than folded in, because
    # widening this to "no votes" makes every unverified informational finding
    # an incomplete review.
    return any(candidate.votes
               and not [v for v in candidate.votes if not v.error]
               for candidate in outcome.reported)


def _non_blocking_notes(
    cfg: Config, outcome: ScanOutcome, blocking: List[Candidate]
) -> List[str]:
    """Say out loud what was found but deliberately not gated on.

    Without this, a report showing four findings and a green pipeline reads as a
    bug rather than as policy.
    """
    notes: List[str] = []
    blocked_ids = {id(c) for c in blocking}
    withheld = [c for c in outcome.reported if id(c) not in blocked_ids]

    # Each withheld finding is attributed to one reason, not to every rule that
    # would independently have withheld it. A low-severity finding in an
    # excluded category counted under both headings makes four findings look
    # like seven, and a reader who notices the arithmetic stops trusting the
    # rest of the numbers. Policy exclusion is decided first, so it wins.
    ungated_names = {c.lower() for c in cfg.ungated_categories}
    withheld_by_policy = [
        c for c in withheld if c.finding.category.lower() in ungated_names]
    withheld = [
        c for c in withheld if c.finding.category.lower() not in ungated_names]

    if cfg.fail_threshold is None:
        if outcome.reported:
            notes.append(
                "{} finding(s) reported but SECURITY_SCAN_FAIL_ON=none, so "
                "nothing blocks the merge.".format(len(outcome.reported))
            )
        return notes

    low_severity = sum(
        1 for c in withheld
        if severity_rank(c.severity) < severity_rank(cfg.fail_on)
    )
    low_confidence = sum(
        1 for c in withheld
        if severity_rank(c.severity) >= severity_rank(cfg.fail_on)
        and confidence_rank(c.confidence) < confidence_rank(cfg.min_confidence)
    )
    pre_existing = sum(
        1 for c in withheld
        if not c.in_changed_lines
        and severity_rank(c.severity) >= severity_rank(cfg.fail_on)
        and confidence_rank(c.confidence) >= confidence_rank(cfg.min_confidence)
    )

    by_policy: dict = {}
    for candidate in withheld_by_policy:
        name = candidate.finding.category.lower()
        by_policy[name] = by_policy.get(name, 0) + 1
    if by_policy:
        # Named per category rather than totalled: "3 not gated" invites the
        # reader to assume a bug, where "3 in denial_of_service" points at the
        # setting that produced it.
        notes.append(
            "{} in categor{} excluded by SECURITY_SCAN_UNGATED_CATEGORIES ({})".format(
                sum(by_policy.values()), "y" if len(by_policy) == 1 else "ies",
                ", ".join(sorted(by_policy))))

    if low_severity:
        notes.append("{} below the {} severity threshold".format(low_severity, cfg.fail_on))
    if low_confidence:
        notes.append(
            "{} below {} confidence (including any downgraded during "
            "verification)".format(low_confidence, cfg.min_confidence)
        )
    # **The removed-control switch, named beside the findings it released.**
    # Its two siblings above and below both name themselves; this one did
    # not, so a finding that would have blocked for taking a guard away came
    # out under "below the severity threshold" with nothing pointing at the
    # setting that let it through. The report then reads as a bug rather than
    # as policy, which is the whole reason this function exists.
    released_controls = [c for c in outcome.reported
                         if getattr(c, "removes_control", False)
                         and c not in blocking]
    if released_controls and not cfg.gate_removed_controls:
        notes.append(
            "{} removing an existing security control (set "
            "SECURITY_SCAN_GATE_REMOVED_CONTROLS=true to gate on these)"
            .format(len(released_controls)))

    if pre_existing and not cfg.gate_pre_existing:
        notes.append(
            "{} pre-existing, not introduced by this change (set "
            "SECURITY_SCAN_GATE_PRE_EXISTING=true to gate on these)".format(pre_existing)
        )
    if outcome.refuted:
        notes.append("{} refuted during verification".format(len(outcome.refuted)))
    if outcome.suppressed:
        notes.append(
            "{} suppressed by {}".format(len(outcome.suppressed), cfg.ignore_file)
        )
    return notes
