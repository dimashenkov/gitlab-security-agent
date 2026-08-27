"""What is left of a review whose process was killed.

The second runner drives the review through the `claude` CLI, with our tools
answering from a child process. When that child ends normally it writes an
authoritative document and this file is ignored. When it is *killed* — a
wall-clock timeout, an out-of-memory kill, the CLI dying mid-turn — there is no
such document, and the only thing anybody can read afterwards is what was
appended to disk as the run went along.

That is what this is, and its defining property is that it is **never
authoritative**. A killed run did not complete: it exits 2 and reports no
verdict, whatever this file contains. The journal answers "how far did it get",
which is a question a person asks while diagnosing, and it must never answer
"what did it find", which is a question the gate asks.

Three things follow from that, and each of them is here because getting it
wrong produces a confident wrong answer rather than a visible failure:

* **A record that is still in a buffer when the kill arrives never happened.**
  Every record is one line, appended and flushed on its own; nothing is batched
  and no handle is held across the child's lifetime.
* **A start is not a result.** "Called `read_file`" and "`read_file` returned"
  are separate records joined by a call id. Written as one record updated in
  place, a run killed mid-call would leave a complete-looking line describing a
  call whose outcome nobody knows — which is exactly the misreading this
  design exists to prevent. The reader reports an unmatched start as *started,
  outcome unknown*.
* **A cut line is discarded, named and counted, never repaired.** The last
  line of a killed run is usually half-written. Guessing at its contents would
  invent a record; silently dropping it would hide one. It is reported as a
  line that could not be read.

The reader deliberately returns something that cannot become gateable state.
Its types carry the text a person needs and not the fields a finding is made
of, so there is no route from a trace back into the pipeline — not a route
nobody should take, a route that does not exist.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Set, Tuple

from .rendering import Rendered
from .rendering import code_span as _code_span
from .rendering import plain as _plain

# Record kinds. Values are written to disk, so renaming one makes every journal
# written before the rename unreadable — the reader counts an unrecognised kind
# rather than guessing at it.
KIND_RUN_STARTED = "run_started"
KIND_TOOL_STARTED = "tool_started"
KIND_TOOL_FINISHED = "tool_finished"
KIND_FINDING_ACCEPTED = "finding_accepted"
KIND_CLAIM_REJECTED = "claim_rejected"
KIND_REVIEW_FINISHED = "review_finished"
KIND_VERDICT_SUBMITTED = "verdict_submitted"

# Everything written here is bounded. A journal is read by a person after a
# crash, often through `tail`, and one `report_finding` call carries a whole
# finding — evidence, exploit scenario, recommendation. Unbounded records would
# make the trace of a hundred-call run unreadable and would put a copy of the
# model's prose in a file whose whole point is brevity.
MAX_TEXT_CHARS = 300
MAX_ARG_CHARS = 200
MAX_ARGS = 12
MAX_EXCERPT_CHARS = 80


class CrashJournalError(Exception):
    """The journal cannot be opened where it was asked to go."""


def _clip(value: Any, limit: int) -> str:
    text = " ".join(str(value if value is not None else "").split())
    return text if len(text) <= limit else text[:limit - 1] + "…"


class CrashJournal:
    """Appends one line per event, for the case where nothing else survives.

    Every method is best-effort in one direction only: a journal that cannot be
    written must never take down the run it is documenting, so write failures
    are counted and swallowed. The opposite trade — losing the run to keep the
    diagnostics honest — would mean an unwritable log directory turns a working
    review into no review at all.

    The file is opened, appended to and closed per record. Holding a handle
    would be faster by an amount nobody can measure at tens of records per run,
    and would leave one more piece of state to reason about across the fork into
    the child process that this journal exists to survive.
    """

    def __init__(self, path: Path, *, run_id: str,
                 clock: Callable[[], float] = time.time) -> None:
        """Claim a fresh file, and stamp every record with the run that wrote it.

        Appending to a journal that already exists is the failure this refuses.
        A second run at the same path would interleave with the first, and the
        reader — which pairs calls by id and looks for holes in the sequence —
        would fold both into one trace: findings from a run that finished
        yesterday presented as progress made by the run that died today. It
        cannot produce a verdict, but it can produce a confident and false
        account of one, which is worse than an empty file.

        Two defences, because the file is only half the problem. The path must
        not already exist, and every record carries `run_id`, so a journal
        assembled by hand from two files is still separable by the reader.
        """
        self.path = Path(path)
        self.run_id = str(run_id)
        self.write_failures = 0
        self._clock = clock
        self._seq = 0
        self._calls = 0
        # Two separate attempts, and they must stay separate. `mkdir` on a path
        # whose parent is a *file* raises `FileExistsError` too — `exist_ok`
        # only forgives an existing directory — so folding these together
        # reported an unwritable location as "this journal already exists",
        # which is a confident answer to a question nobody asked.
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
        except OSError:
            self.write_failures += 1
            return

        try:
            # Exclusive: the file must not be there already. Truncating instead
            # would destroy the record of the previous run, which is sometimes
            # the one somebody is trying to read.
            os.close(os.open(str(self.path),
                             os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600))
        except FileExistsError:
            raise CrashJournalError(
                "{} already exists; a crash journal is written once per run and "
                "appending would merge two runs into one trace".format(self.path)
            ) from None
        except OSError:
            # Every other filesystem problem is counted and survived, like a
            # failed write: the journal is diagnostics, and a review must not be
            # lost to the thing that was only supposed to describe it.
            self.write_failures += 1

    # ------------------------------------------------------------- the record

    def run_started(self, *, mode: str = "", model: str = "",
                    revision: str = "") -> None:
        """What was about to be reviewed, before any of it happened.

        Without this a journal from a run killed during start-up is an empty
        file, and an empty file cannot tell a reader whether the run never
        started or the disk was never written to.
        """
        self._emit(
            KIND_RUN_STARTED,
            mode=_clip(mode, MAX_TEXT_CHARS),
            model=_clip(model, MAX_TEXT_CHARS),
            revision=_clip(revision, MAX_TEXT_CHARS),
        )

    def tool_started(self, name: str, arguments: Optional[Dict[str, Any]] = None,
                     *, call_id: str = "", turn: int = 0) -> str:
        """A call is about to run. Returns the id `tool_finished` must be given.

        The id is returned rather than only accepted so a caller with no id of
        its own still gets a start and a finish that can be paired. A caller
        that has the provider's `tool_use` id should pass it: the journal is
        then joinable against the provider's own transcript.
        """
        self._calls += 1
        identifier = _clip(call_id, MAX_TEXT_CHARS) or "call-{}".format(self._calls)
        self._emit(
            KIND_TOOL_STARTED,
            call_id=identifier,
            turn=int(turn) if isinstance(turn, int) else 0,
            name=_clip(name, MAX_TEXT_CHARS),
            arguments=_clip_arguments(arguments),
        )
        return identifier

    def tool_finished(self, call_id: str, *, summary: str = "",
                      is_error: bool = False) -> None:
        """A call came back. `summary` is the one-line audit text of the result."""
        self._emit(
            KIND_TOOL_FINISHED,
            call_id=_clip(call_id, MAX_TEXT_CHARS),
            summary=_clip(summary, MAX_TEXT_CHARS),
            is_error=bool(is_error),
        )

    def finding_accepted(self, *, title: str, file: str, line: int = 0,
                         severity: str = "", confidence: str = "",
                         fingerprint: str = "") -> None:
        """A claim that passed the citation check and became a candidate.

        Only enough to say what was claimed and where. The evidence, the
        description, the exploit scenario and the recommendation are all
        deliberately absent: they are what a finding is *made of*, and leaving
        them out is what stops a trace being turned back into one.
        """
        self._emit(
            KIND_FINDING_ACCEPTED,
            title=_clip(title, MAX_TEXT_CHARS),
            file=_clip(file, MAX_TEXT_CHARS),
            line=int(line) if isinstance(line, int) else 0,
            severity=_clip(severity, MAX_TEXT_CHARS),
            confidence=_clip(confidence, MAX_TEXT_CHARS),
            fingerprint=_clip(fingerprint, MAX_TEXT_CHARS),
        )

    def claim_rejected(self, *, title: str, file: str, reason: str,
                       detail: str = "") -> None:
        """A claim the citation check refused, and why.

        Kept for the same reason the finished report keeps rejections: a run
        that quietly discards half of what the reviewer said cannot be
        diagnosed, and the reasons are the signal for whether the prompt or the
        tools need work.
        """
        self._emit(
            KIND_CLAIM_REJECTED,
            title=_clip(title, MAX_TEXT_CHARS),
            file=_clip(file, MAX_TEXT_CHARS),
            reason=_clip(reason, MAX_TEXT_CHARS),
            detail=_clip(detail, MAX_TEXT_CHARS),
        )

    def review_finished(self, *, summary: str = "",
                        unresolved: Sequence[str] = ()) -> None:
        """The reviewer stated it was done — which the process being killed does not undo.

        A run can sign off and still be killed afterwards, during verification
        or while writing its artifacts. Recording the sign-off says how far it
        got; it does not make the run complete, and the rendering says so.
        """
        self._emit(
            KIND_REVIEW_FINISHED,
            summary=_clip(summary, MAX_TEXT_CHARS),
            unresolved=[_clip(item, MAX_TEXT_CHARS) for item in (unresolved or ())],
        )

    def verdict_submitted(self, *, verdict: str = "", reasoning: str = "") -> None:
        """A verifier cast its one vote. Only meaningful in a verifier's journal."""
        self._emit(
            KIND_VERDICT_SUBMITTED,
            verdict=_clip(verdict, MAX_TEXT_CHARS),
            reasoning=_clip(reasoning, MAX_TEXT_CHARS),
        )

    # -------------------------------------------------------------- the write

    def _emit(self, kind: str, **fields: Any) -> None:
        self._seq += 1
        record: Dict[str, Any] = {
            "seq": self._seq, "run": self.run_id, "kind": kind,
            "at": round(self._clock(), 3)}
        record.update(fields)
        # ASCII only, deliberately. A kill can cut the file at any byte, and an
        # ASCII line cannot be cut in the middle of a character — so a
        # half-written record fails to parse as JSON, which is reported, rather
        # than decoding into replacement characters, which looks like data.
        line = json.dumps(record, ensure_ascii=True, sort_keys=True, default=str)
        try:
            with open(self.path, "a", encoding="utf-8") as handle:
                handle.write(line + "\n")
                # Not for tidiness: a record sitting in this process's buffer
                # when SIGKILL arrives is a record that did not happen, and the
                # events worth reading are precisely the last ones.
                handle.flush()
        except OSError:
            self.write_failures += 1


def _clip_arguments(arguments: Optional[Dict[str, Any]]) -> Dict[str, str]:
    if not isinstance(arguments, dict):
        return {}
    out: Dict[str, str] = {}
    for key in sorted(arguments)[:MAX_ARGS]:
        out[_clip(key, MAX_ARG_CHARS)] = _clip(arguments[key], MAX_ARG_CHARS)
    return out


# ------------------------------------------------------------------ the trace


@dataclass(frozen=True)
class TracedCall:
    """One tool call, and whether anyone knows how it ended."""

    seq: int
    call_id: str
    turn: int
    name: str
    arguments: Tuple[Tuple[str, str], ...]
    started_at: float
    finished: bool = False
    summary: str = ""
    is_error: bool = False
    finished_at: float = 0.0


@dataclass(frozen=True)
class TracedResult:
    """A result whose call id matches no start in this file.

    Not an error to be normalised away. It means either that the start was lost
    or that the ids do not line up, and both are worth a reader's attention —
    so it is shown as what it is rather than folded in beside real calls.
    """

    seq: int
    call_id: str
    summary: str
    is_error: bool
    at: float


@dataclass(frozen=True)
class TracedFinding:
    """What was claimed, in the words that were journalled — nothing more.

    There is no evidence, description, exploit scenario or recommendation here,
    and that is the point: those fields are required to build a finding, so a
    type without them cannot be turned into one no matter who tries.
    """

    seq: int
    title: str
    file: str
    line: int
    severity: str
    confidence: str
    fingerprint: str


@dataclass(frozen=True)
class TracedRejection:
    seq: int
    title: str
    file: str
    reason: str
    detail: str


@dataclass(frozen=True)
class UnreadableLine:
    """A line the reader refused to guess at."""

    line: int
    byte_count: int
    reason: str
    excerpt: str


@dataclass(frozen=True)
class PartialTrace:
    """How far a killed run got. Never a result, and structurally unable to be one.

    Every field is text, a number, or a tuple of frozen records of text and
    numbers. Nothing here is a `Session`, holds one, or carries the fields one
    would need — so the honest thing a caller can do with a trace is print it,
    because it is the only thing a caller *can* do with it.
    """

    path: str
    present: bool = False
    run_id: str = ""
    # Records in the file stamped with some other run, and sequence numbers
    # that repeated or went backwards. Truncation can only lose the tail, so it
    # can make a hole and never either of these: both mean the file is not one
    # writer's output in order, and a trace that quietly merged them would read
    # exactly as truthfully as one that did not.
    foreign_runs: Tuple[str, ...] = ()
    disordered_sequence_numbers: Tuple[int, ...] = ()
    mode: str = ""
    model: str = ""
    revision: str = ""
    started_at: float = 0.0
    last_record_at: float = 0.0
    records_read: int = 0
    calls: Tuple[TracedCall, ...] = ()
    unmatched_results: Tuple[TracedResult, ...] = ()
    findings_claimed: Tuple[TracedFinding, ...] = ()
    claims_rejected: Tuple[TracedRejection, ...] = ()
    review_finished: bool = False
    review_summary: str = ""
    unresolved: Tuple[str, ...] = ()
    verdict: str = ""
    verdict_reasoning: str = ""
    unreadable: Tuple[UnreadableLine, ...] = ()
    missing_sequence_numbers: Tuple[int, ...] = ()

    @property
    def unfinished_calls(self) -> Tuple[TracedCall, ...]:
        """Calls that started and never reported back — where the run was killed."""
        return tuple(call for call in self.calls if not call.finished)

    @property
    def elapsed_seconds(self) -> float:
        return max(0.0, self.last_record_at - self.started_at)


def read_trace(path: Path) -> PartialTrace:
    """Read a journal into a trace, surviving anything the file happens to contain.

    Nothing in here raises. The caller is already handling a killed run and is
    about to exit 2; a reader that threw on a truncated file would replace a
    diagnosis with a stack trace at precisely the moment the diagnosis is the
    only thing left.
    """
    target = Path(path)
    try:
        data = target.read_bytes()
        present = True
    except OSError:
        data = b""
        present = False

    raw_lines = data.split(b"\n")
    # A journal that ends in a newline ends cleanly; that final empty element is
    # the newline, not a lost record. Only one is dropped, so a genuinely blank
    # line stays visible as a line that could not be read.
    if raw_lines and raw_lines[-1] == b"":
        raw_lines.pop()

    state = _Reader()
    for number, raw in enumerate(raw_lines, start=1):
        state.consume(number, raw)
    return state.finish(str(target), present)


class _Reader:
    """The accumulating half of `read_trace`, kept apart from the parsing rules."""

    def __init__(self) -> None:
        self.records = 0
        self.seqs: List[int] = []
        # The run that wrote the first record. Anything else in the file is
        # somebody else's, and is named rather than folded in.
        self.run_id = ""
        self.foreign_runs: Set[str] = set()
        self.disordered: List[int] = []
        self.mode = ""
        self.model = ""
        self.revision = ""
        self.first_at = 0.0
        self.last_at = 0.0
        self.calls: List[Dict[str, Any]] = []
        self.pending: Dict[str, int] = {}
        self.unmatched: List[TracedResult] = []
        self.findings: List[TracedFinding] = []
        self.rejections: List[TracedRejection] = []
        self.finished = False
        self.summary = ""
        self.unresolved: Tuple[str, ...] = ()
        self.verdict = ""
        self.reasoning = ""
        self.unreadable: List[UnreadableLine] = []

    def consume(self, number: int, raw: bytes) -> None:
        text = raw.decode("utf-8", errors="replace")
        if not text.strip():
            self._unreadable(number, raw, "blank line")
            return
        try:
            record = json.loads(text)
        except ValueError:
            # The usual shape of a killed run: the last line stops mid-token.
            self._unreadable(number, raw, "not valid JSON — most likely cut short")
            return
        if not isinstance(record, dict):
            self._unreadable(number, raw, "not a JSON object")
            return

        handler = _HANDLERS.get(str(record.get("kind") or ""))
        if handler is None:
            self._unreadable(
                number, raw,
                "unrecognised record kind {}".format(
                    _clip(record.get("kind"), 40) or "(absent)"))
            return

        run = _text(record.get("run"))
        if not self.run_id:
            self.run_id = run
        elif run and run != self.run_id:
            # Two runs in one file. The writer refuses to append to an existing
            # journal, so this means the file was assembled some other way —
            # copied, concatenated, edited. Naming the foreign lines is the
            # difference between a trace of one death and a confident account
            # mixing two runs, which reads exactly as truthfully and is not.
            self.foreign_runs.add(run)
            self._unreadable(
                number, raw, "written by a different run ({})".format(_clip(run, 40)))
            return

        self.records += 1
        seq = _int(record.get("seq"))
        if seq:
            if self.seqs and seq <= self.seqs[-1]:
                # Truncation can only lose the tail, so it can make a hole and
                # never a repeat or a step backwards. Either of those means the
                # file is not one writer's output in order.
                self.disordered.append(seq)
            self.seqs.append(seq)
        at = _float(record.get("at"))
        if at:
            self.first_at = self.first_at or at
            self.last_at = max(self.last_at, at)
        handler(self, record)

    # ------------------------------------------------------------- per record

    def _run_started(self, record: Dict[str, Any]) -> None:
        self.mode = _text(record.get("mode"))
        self.model = _text(record.get("model"))
        self.revision = _text(record.get("revision"))

    def _tool_started(self, record: Dict[str, Any]) -> None:
        call_id = _text(record.get("call_id"))
        arguments = record.get("arguments")
        pairs = tuple(
            (_text(key), _text(value))
            for key, value in sorted((arguments or {}).items())
        ) if isinstance(arguments, dict) else ()
        self.pending[call_id] = len(self.calls)
        self.calls.append({
            "seq": _int(record.get("seq")),
            "call_id": call_id,
            "turn": _int(record.get("turn")),
            "name": _text(record.get("name")),
            "arguments": pairs,
            "started_at": _float(record.get("at")),
        })

    def _tool_finished(self, record: Dict[str, Any]) -> None:
        call_id = _text(record.get("call_id"))
        index = self.pending.pop(call_id, None)
        if index is None:
            self.unmatched.append(TracedResult(
                seq=_int(record.get("seq")), call_id=call_id,
                summary=_text(record.get("summary")),
                is_error=bool(record.get("is_error")), at=_float(record.get("at"))))
            return
        self.calls[index].update({
            "finished": True,
            "summary": _text(record.get("summary")),
            "is_error": bool(record.get("is_error")),
            "finished_at": _float(record.get("at")),
        })

    def _finding_accepted(self, record: Dict[str, Any]) -> None:
        self.findings.append(TracedFinding(
            seq=_int(record.get("seq")),
            title=_text(record.get("title")),
            file=_text(record.get("file")),
            line=_int(record.get("line")),
            severity=_text(record.get("severity")),
            confidence=_text(record.get("confidence")),
            fingerprint=_text(record.get("fingerprint")),
        ))

    def _claim_rejected(self, record: Dict[str, Any]) -> None:
        self.rejections.append(TracedRejection(
            seq=_int(record.get("seq")),
            title=_text(record.get("title")),
            file=_text(record.get("file")),
            reason=_text(record.get("reason")),
            detail=_text(record.get("detail")),
        ))

    def _review_finished(self, record: Dict[str, Any]) -> None:
        self.finished = True
        self.summary = _text(record.get("summary"))
        raw = record.get("unresolved")
        self.unresolved = tuple(
            _text(item) for item in raw) if isinstance(raw, list) else ()

    def _verdict_submitted(self, record: Dict[str, Any]) -> None:
        self.verdict = _text(record.get("verdict"))
        self.reasoning = _text(record.get("reasoning"))

    # -------------------------------------------------------------- the trace

    def _unreadable(self, number: int, raw: bytes, reason: str) -> None:
        self.unreadable.append(UnreadableLine(
            line=number, byte_count=len(raw), reason=reason,
            excerpt=_clip(raw.decode("utf-8", errors="replace"), MAX_EXCERPT_CHARS),
        ))

    def finish(self, path: str, present: bool) -> PartialTrace:
        return PartialTrace(
            path=path,
            present=present,
            run_id=self.run_id,
            foreign_runs=tuple(sorted(self.foreign_runs)),
            disordered_sequence_numbers=tuple(self.disordered),
            mode=self.mode,
            model=self.model,
            revision=self.revision,
            started_at=self.first_at,
            last_record_at=self.last_at,
            records_read=self.records,
            calls=tuple(TracedCall(**call) for call in self.calls),
            unmatched_results=tuple(self.unmatched),
            findings_claimed=tuple(self.findings),
            claims_rejected=tuple(self.rejections),
            review_finished=self.finished,
            review_summary=self.summary,
            unresolved=self.unresolved,
            verdict=self.verdict,
            verdict_reasoning=self.reasoning,
            unreadable=tuple(self.unreadable),
            missing_sequence_numbers=_gaps(self.seqs),
        )


_HANDLERS: Dict[str, Callable[[_Reader, Dict[str, Any]], None]] = {
    KIND_RUN_STARTED: _Reader._run_started,
    KIND_TOOL_STARTED: _Reader._tool_started,
    KIND_TOOL_FINISHED: _Reader._tool_finished,
    KIND_FINDING_ACCEPTED: _Reader._finding_accepted,
    KIND_CLAIM_REJECTED: _Reader._claim_rejected,
    KIND_REVIEW_FINISHED: _Reader._review_finished,
    KIND_VERDICT_SUBMITTED: _Reader._verdict_submitted,
}


def _gaps(seqs: Sequence[int]) -> Tuple[int, ...]:
    """Sequence numbers that should be in the file and are not.

    Truncation removes the tail, so it never leaves a hole. A hole therefore
    means a record that was written between two survivors is absent — a
    swallowed write failure is one cause, and so are editing, copying selected
    lines, and corruption. Worth naming, not worth diagnosing from here.

    It is also not a complete check. A write that failed *last* leaves no hole,
    because there is no later number to reveal it; that case is what
    `write_failures` on the writer is for, and it does not survive the kill.
    """
    if not seqs:
        return ()
    seen = set(seqs)
    return tuple(n for n in range(1, max(seqs) + 1) if n not in seen)


def _text(value: Any) -> str:
    return _clip(value, MAX_TEXT_CHARS)


def _int(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return 0
    return int(value)


def _float(value: Any) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return 0.0
    return float(value)


# ------------------------------------------------------------- the rendering


def render_trace(trace: PartialTrace) -> Rendered:
    """The trace as Markdown, written so it cannot be read as a verdict.

    Every model-written string on this page — a title, a search pattern, a
    rejection reason — was produced while summarising code that the author of
    the merge request wrote, so all of it goes through the report's escapers.
    Nothing here is laid out as a table: `_plain` deliberately leaves `|`
    alone, which is right for a paragraph and would let a chosen title split a
    row into columns.
    """
    lines: List[str] = [
        "## ⚠️ AI security review was killed before it finished",
        "",
        "> [!WARNING]",
        "> **This is not a result.** The review process was killed — a time "
        "limit, an out-of-memory kill, or the CLI itself dying — so it reached "
        "no conclusion and produced no verdict. What follows is the record it "
        "appended as it went: how far it got, not what it found. Nothing here "
        "was verified, nothing here blocks or clears anything, and code that "
        "is not mentioned was not necessarily examined.",
    ]
    lines += _trace_meta(trace)

    if not trace.present:
        lines += [
            "",
            "No journal file was written at {}. The run was killed before it "
            "recorded anything, or it could not write to that path — from here "
            "the two are indistinguishable.".format(_code_span(trace.path)),
        ]
        return "\n".join(lines).rstrip() + "\n"

    if not trace.records_read:
        lines += [
            "",
            "The journal is empty. The run was killed before it recorded its "
            "first event.",
        ]

    lines += _trace_calls(trace)
    lines += _trace_findings(trace)
    lines += _trace_rejections(trace)
    lines += _trace_sign_off(trace)
    lines += _trace_unreadable(trace)
    return Rendered("\n".join(lines).rstrip() + "\n")


def _trace_meta(trace: PartialTrace) -> List[str]:
    bits: List[str] = []
    if trace.mode:
        bits.append("{} mode".format(_plain(trace.mode)))
    if trace.model:
        bits.append(_plain(trace.model))
    if trace.revision:
        bits.append(_plain(trace.revision))
    unfinished = len(trace.unfinished_calls)
    bits.append("{} tool call{} started".format(
        len(trace.calls), "" if len(trace.calls) == 1 else "s"))
    bits.append("{} finished".format(len(trace.calls) - unfinished))
    if unfinished:
        bits.append("{} outcome unknown".format(unfinished))
    bits.append("{} finding{} claimed".format(
        len(trace.findings_claimed),
        "" if len(trace.findings_claimed) == 1 else "s"))
    if trace.unreadable:
        bits.append("{} line{} unreadable".format(
            len(trace.unreadable), "" if len(trace.unreadable) == 1 else "s"))
    if trace.started_at:
        bits.append("last record {}".format(
            datetime.fromtimestamp(trace.last_record_at, tz=timezone.utc)
            .strftime("%Y-%m-%d %H:%M:%S UTC")))
    return ["", "_{}_".format(" · ".join(bits))]


def _trace_calls(trace: PartialTrace) -> List[str]:
    if not trace.calls and not trace.unmatched_results:
        return []
    lines = ["", "### How far it got", ""]
    for call in trace.calls:
        lines.append("- {} {}{}{}".format(
            "⏳" if not call.finished else ("⚠️" if call.is_error else "•"),
            _code_span(call.name),
            _arguments(call.arguments),
            _outcome(trace, call),
        ))
    for result in trace.unmatched_results:
        # Named, not hidden. It means a start was lost or the ids disagree, and
        # quietly listing it beside real calls would invent a call that this
        # file never recorded beginning.
        lines.append(
            "- ❓ a result for call id {} arrived with no matching start — "
            "{}".format(_code_span(result.call_id) if result.call_id else "(none)",
                        _plain(result.summary) or "no summary recorded"))
    return lines


def _arguments(arguments: Tuple[Tuple[str, str], ...]) -> str:
    if not arguments:
        return ""
    return " " + " ".join(
        "{}={}".format(_plain(key), _code_span(value)) for key, value in arguments)


def _outcome(trace: PartialTrace, call: TracedCall) -> str:
    if not call.finished:
        return " — **started, outcome unknown.** Nothing recorded that it returned."
    detail = _plain(call.summary) or "no summary recorded"
    when = ""
    if call.finished_at and trace.started_at:
        when = " (+{:.1f}s)".format(call.finished_at - trace.started_at)
    return " — {}{}".format(detail, when)


def _trace_findings(trace: PartialTrace) -> List[str]:
    if not trace.findings_claimed:
        return []
    lines = [
        "", "### Claims recorded before the run was killed", "",
        "_Each of these passed the check that the code it quotes exists, and "
        "nothing further. None was verified, none was rated, and none of them "
        "gates anything — a killed run reports no findings._", "",
    ]
    for finding in trace.findings_claimed:
        located = "{}:{}".format(finding.file, finding.line) if finding.line \
            else finding.file
        lines.append("- {} — {}{}".format(
            _plain(finding.title) or "(untitled)",
            _code_span(located),
            " · claimed {}".format(_plain(finding.severity))
            if finding.severity else "",
        ))
    return lines


def _trace_rejections(trace: PartialTrace) -> List[str]:
    if not trace.claims_rejected:
        return []
    lines = ["", "### Claims the citation check refused", ""]
    for claim in trace.claims_rejected:
        lines.append("- {} in {} — {}".format(
            _plain(claim.title) or "(untitled)",
            _code_span(claim.file),
            _plain(claim.reason) or "no reason recorded"))
    return lines


def _trace_sign_off(trace: PartialTrace) -> List[str]:
    lines: List[str] = []
    if trace.review_finished:
        lines += [
            "", "### The reviewer had signed off", "",
            "The reviewer recorded that it was finished, and the process was "
            "killed afterwards — while verifying, while writing its report, or "
            "somewhere else this journal cannot see. The run still did not "
            "complete.", "",
            "> " + (_plain(trace.review_summary) or "no summary recorded"),
        ]
        if trace.unresolved:
            lines += ["", "**It had not settled:**", ""]
            lines += ["- {}".format(_plain(item)) for item in trace.unresolved]
    if trace.verdict:
        lines += [
            "", "### A verdict was submitted", "",
            "- {} — {}".format(
                _plain(trace.verdict),
                _plain(trace.verdict_reasoning) or "no reasoning recorded"),
        ]
    return lines


def _trace_unreadable(trace: PartialTrace) -> List[str]:
    lines: List[str] = []
    if trace.unreadable:
        lines += [
            "", "### Lines that could not be read", "",
            "_{} line{} discarded. A killed process usually stops mid-write, so "
            "the last line of a journal is often half of one. Discarding it can "
            "lose a record; repairing it would invent one._".format(
                len(trace.unreadable),
                "" if len(trace.unreadable) == 1 else "s"), "",
        ]
        for bad in trace.unreadable:
            lines.append("- line {} ({} bytes) — {}: {}".format(
                bad.line, bad.byte_count, _plain(bad.reason),
                _code_span(bad.excerpt)))
    if trace.missing_sequence_numbers:
        lines += [
            "", "**Records missing from the middle of the file:** {}. Not lost "
            "to truncation, which only ever removes the tail. A write that "
            "failed and was swallowed to keep the run alive is one cause; so "
            "are editing, copying part of the file, and corruption.".format(
                ", ".join(str(n) for n in trace.missing_sequence_numbers)),
        ]
    if trace.disordered_sequence_numbers:
        lines += [
            "", "**Sequence numbers repeat or go backwards** at {}. One writer "
            "appending in order cannot produce that, so this file is not one "
            "run's output — read everything above as coming from more than one "
            "source.".format(
                ", ".join(str(n) for n in trace.disordered_sequence_numbers)),
        ]
    if trace.foreign_runs:
        lines += [
            "", "**Records from {} other run(s) were found and excluded:** {}. "
            "The writer refuses to append to an existing journal, so this file "
            "was assembled some other way.".format(
                len(trace.foreign_runs),
                ", ".join(_code_span(run) for run in trace.foreign_runs)),
        ]
    return lines
