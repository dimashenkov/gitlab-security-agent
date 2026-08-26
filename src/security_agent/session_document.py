"""Carrying one finished `Session` out of a child process and into the parent.

The second runner drives the review through the `claude` CLI, which spawns our
tools as a child process. Everything the gate reads afterwards — the
candidates, the claims that were rejected and why, what was examined, the
counters, the sign-off — accumulates inside that child and dies with it. A file
is the only channel out.

Every way a file can be wrong here is a quiet way. A document left over from
yesterday's revision parses perfectly and answers a question nobody asked. A
document truncated by a killed process parses down to its last complete object
and reads as a short review. A document whose quoted evidence was edited still
carries the fingerprint the accepted-risk file matches on, so it silences a
finding it no longer describes. None of those announce themselves, and all of
them render the same way: a finished review with fewer findings in it. That is
the one outcome this project does not tolerate, because "checked and clean" and
"did not get an answer" must never look alike.

So the document is bound to the run that produced it, and validated on the way
back in: every enumerated word against the vocabulary that defines it, every
derived value recomputed from the facts it was derived from rather than
believed, and every refusal an exception. Returning an empty `Session` from a
bad document would hand the gate a clean review, which is why nothing here ever
returns one.
"""

from __future__ import annotations

import contextlib
import json
import os
import tempfile
from dataclasses import fields as dataclass_fields
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from .models import (
    CONFIDENCE_ORDER,
    SEVERITY_ORDER,
    VERDICT_CONFIRMED,
    VERDICT_REFUTED,
    VERDICT_UNCERTAIN,
    Candidate,
    Finding,
    RejectedClaim,
    StageMetrics,
    ToolCallRecord,
    Vote,
)
from .panel import decide
from .severity import BASE_SEVERITY
from .tools import MIN_SUMMARY_CHARS, Session
from .vocabulary import categories

# Bumped whenever the shape below changes in a way an older reader would
# misread. A reader that guesses at an unfamiliar shape is worse than one that
# stops: the fields it guesses wrong are the ones that decide the gate.
SCHEMA_VERSION = 1

VERDICTS: Tuple[str, ...] = (VERDICT_CONFIRMED, VERDICT_UNCERTAIN, VERDICT_REFUTED)
YES_NO_UNCLEAR: Tuple[str, ...] = ("yes", "no", "unclear")
# The impact words the severity table can rate. Taken from the table rather
# than from the schema file because the table is the only consumer: an impact
# it cannot rate is an impact nothing downstream can use.
IMPACTS: Tuple[str, ...] = tuple(BASE_SEVERITY)
SEVERITIES: Tuple[str, ...] = tuple(SEVERITY_ORDER)
CONFIDENCES: Tuple[str, ...] = tuple(CONFIDENCE_ORDER)
# The same words plus "", which on a verifier's correction means "I agree with
# the reviewer" and is the value most votes carry.
OPTIONAL_IMPACTS: Tuple[str, ...] = (*IMPACTS, "")
OPTIONAL_YES_NO_UNCLEAR: Tuple[str, ...] = (*YES_NO_UNCLEAR, "")
OPTIONAL_CONFIDENCES: Tuple[str, ...] = (*CONFIDENCES, "")
# "" is a real attribution — the cited code is in neither the additions nor the
# deletions of this change, which is how a pre-existing weakness is recorded.
ATTRIBUTIONS: Tuple[str, ...] = ("added", "deleted", "")
CHANNELS: Tuple[str, ...] = ("submit_verdict", "final_message", "")

_FINDING_FIELDS: Tuple[str, ...] = (
    "title", "severity", "confidence", "category", "file", "line", "impact",
    "reachable_without_authentication", "requires_user_interaction", "evidence",
    "description", "exploit_scenario", "recommendation",
)

_VOTE_FIELDS: Tuple[str, ...] = (
    "verdict", "reasoning", "corrected_impact", "corrected_reachable",
    "corrected_interaction", "corrected_confidence", "removes_control",
    "control_search", "entry_point", "files_read", "exposures", "error",
    "channel", "served_models",
)

_CANDIDATE_FIELDS: Tuple[str, ...] = (
    "finding", "fingerprint", "fingerprints", "evidence_located_line",
    "line_corrected_from", "in_changed_lines", "path_verified", "attributed_by",
    "votes", "verdict", "verdict_reason", "removes_control", "severity",
    "confidence", "suppressed_by", "severity_derivation",
)

# Every field of `Session`, mapped to the key that carries it. The mapping is a
# named constant rather than a shape implied by the encoder so that a field
# added to `Session` and forgotten here fails a test instead of quietly not
# reaching the parent — a dropped field renders as a review that did not find
# what it found.
SESSION_FIELDS: Dict[str, str] = {
    "candidates": "candidates",
    "rejected": "rejected",
    "tool_calls": "tool_calls",
    "files_examined": "files_examined",
    "exposures": "exposures",
    "duplicates_dropped": "duplicates_dropped",
    "turn": "turn",
    "metrics": "metrics",
    "finished": "finished",
    "final_summary": "final_summary",
    "unresolved": "unresolved",
    "verdict": "verdict",
    "_attempts": "citation_attempts",
}

# The verdict payload keeps the schema's own key names, because it is stored as
# the arguments `submit_verdict` was called with and `verify._vote_from_payload`
# reads it under those names. Only the constrained ones are listed; the rest is
# prose.
_VERDICT_PAYLOAD_ENUMS: Dict[str, Tuple[str, ...]] = {
    "verdict": VERDICTS,
    "corrected_impact": OPTIONAL_IMPACTS,
    "corrected_reachable_without_authentication": OPTIONAL_YES_NO_UNCLEAR,
    "corrected_requires_user_interaction": OPTIONAL_YES_NO_UNCLEAR,
    "corrected_confidence": OPTIONAL_CONFIDENCES,
    "removes_existing_control": ("yes", "no", ""),
}

_ABSENT = object()


class SessionDocumentError(Exception):
    """The document cannot be trusted to be this run's finished session.

    One type for every refusal, so a caller cannot accidentally handle "the
    file is not there" and miss "the file is for another revision". Both mean
    the same thing to the gate: there is no answer, and a run without an answer
    must not exit as a clean one.
    """


# ------------------------------------------------------------------- writing


def write_session(
    path: Path,
    session: Session,
    *,
    run_id: str,
    revision: Any,
    config_digest: str,
) -> None:
    """Write `session` as this run's document, or leave the path untouched.

    Serialised in full before the file is opened, so a session holding
    something unserialisable produces an exception and no file at all rather
    than a prefix. Then written to a temporary neighbour, flushed to the disk,
    and renamed over the destination in one step — a reader either sees the
    previous document or this one, never half of either.

    `revision` is anything carrying `base_sha` and `head_sha`; `models.Revision`
    is what the runners have.
    """
    try:
        body = json.dumps(
            _document(session, run_id, revision, config_digest),
            indent=2, ensure_ascii=False, sort_keys=True,
        ) + "\n"
    except (TypeError, ValueError) as exc:
        raise SessionDocumentError(
            "this session holds something that is not JSON and cannot be "
            "written to {}: {}".format(path, exc)) from exc

    path = Path(path)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        # In the destination directory, because `os.replace` is only atomic
        # within one filesystem and /tmp is routinely a different one.
        handle_fd, temporary = tempfile.mkstemp(
            dir=str(path.parent), prefix=path.name + ".", suffix=".part")
    except OSError as exc:
        raise SessionDocumentError(
            "cannot write the session document to {}: {}".format(path, exc)) from exc

    try:
        with os.fdopen(handle_fd, "w", encoding="utf-8") as handle:
            handle.write(body)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except OSError as exc:
        _discard(temporary)
        raise SessionDocumentError(
            "cannot write the session document to {}: {}".format(path, exc)) from exc
    except BaseException:
        # Including an interrupt. A killed writer that leaves its `.part`
        # behind invites the next reader to find two files and pick one.
        _discard(temporary)
        raise


def _discard(temporary: str) -> None:
    with contextlib.suppress(OSError):
        os.unlink(temporary)


def _document(
    session: Session, run_id: str, revision: Any, config_digest: str
) -> Dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        # What this document is an answer about. Each of these changes the
        # answer without changing anything a reader would notice.
        "run_id": str(run_id),
        "base_sha": _sha(revision, "base_sha"),
        "head_sha": _sha(revision, "head_sha"),
        "config_digest": str(config_digest),
        # The writer's statement that it got to the end. It is redundant with
        # the atomic rename today and it is here because the rename is one
        # implementation detail away from not being atomic, and because a
        # reader should be able to say "this document is finished" from the
        # document rather than from trust in how it was produced. Whether the
        # *review* finished is a different question and lives in
        # `session.finished`.
        "complete": True,
        "session": _encode_session(session),
    }


def _sha(revision: Any, name: str) -> str:
    return str(getattr(revision, name, "") or "")


def _encode_session(session: Session) -> Dict[str, Any]:
    # Checked here and not only in a test. A test catches this on the branch it
    # runs on; a field added to `Session` on another branch, or a package built
    # from a tree whose tests nobody ran, reaches the parent as a default —
    # an empty candidate list, a `False` sign-off — and the parent has no way to
    # know it is looking at less than the child had. This project's contract is
    # that what could not be done fails visibly, and that has to hold at
    # runtime, not at test time.
    declared = set(SESSION_FIELDS)
    actual = {field.name for field in dataclass_fields(Session)}
    if declared != actual:
        raise SessionDocumentError(
            "the session document does not describe this Session: {} are not "
            "written, {} are written and no longer exist. Add them to "
            "SESSION_FIELDS and to the encoder.".format(
                sorted(actual - declared) or "none",
                sorted(declared - actual) or "none"))

    encoded = _encoded_session(session)
    missing = set(SESSION_FIELDS.values()) - set(encoded)
    if missing:
        raise SessionDocumentError(
            "the encoder produced no value for {}; a field declared and not "
            "written is a field that silently arrives as its default".format(
                sorted(missing)))
    return encoded


def _encoded_session(session: Session) -> Dict[str, Any]:
    return {
        "candidates": [_encode_candidate(c) for c in session.candidates],
        "rejected": [
            {"title": r.title, "file": r.file, "reason": r.reason, "detail": r.detail}
            for r in session.rejected
        ],
        "tool_calls": [
            {"turn": c.turn, "name": c.name, "arguments": c.arguments,
             "summary": c.summary, "is_error": c.is_error}
            for c in session.tool_calls
        ],
        "files_examined": list(session.files_examined),
        "exposures": [list(pair) for pair in session.exposures],
        "duplicates_dropped": session.duplicates_dropped,
        "turn": session.turn,
        "metrics": _encode_metrics(session.metrics),
        "finished": session.finished,
        "final_summary": session.final_summary,
        "unresolved": list(session.unresolved),
        "verdict": session.verdict,
        # The per-claim retry counter. It decides nothing after the run, and it
        # is here because a loader that drops the fields it judges unimportant
        # is a loader nobody can point at and say what it keeps.
        "citation_attempts": dict(session._attempts),
    }


def _encode_metrics(metrics: StageMetrics) -> Dict[str, int]:
    return {f.name: getattr(metrics, f.name) for f in dataclass_fields(StageMetrics)}


def _encode_candidate(candidate: Candidate) -> Dict[str, Any]:
    finding = candidate.finding
    return {
        "finding": {name: getattr(finding, name) for name in _FINDING_FIELDS},
        # Written to be checked rather than to be read back. The loader derives
        # both again from the quoted evidence and refuses a document whose
        # stated identity does not follow from its own text — a fingerprint is
        # what an accepted risk is recorded against, so a document that can
        # carry an identity detached from the code it describes can silence a
        # finding it never saw.
        "fingerprint": finding.fingerprint,
        "fingerprints": list(finding.fingerprints),
        "evidence_located_line": candidate.evidence_located_line,
        "line_corrected_from": candidate.line_corrected_from,
        "in_changed_lines": candidate.in_changed_lines,
        "path_verified": candidate.path_verified,
        "attributed_by": candidate.attributed_by,
        "votes": [_encode_vote(v) for v in candidate.votes],
        "verdict": candidate.verdict,
        "verdict_reason": candidate.verdict_reason,
        "removes_control": candidate.removes_control,
        "severity": candidate.severity,
        "confidence": candidate.confidence,
        "suppressed_by": candidate.suppressed_by,
        "severity_derivation": candidate.severity_derivation,
    }


def _encode_vote(vote: Vote) -> Dict[str, Any]:
    encoded = {name: getattr(vote, name) for name in _VOTE_FIELDS}
    encoded["files_read"] = list(vote.files_read)
    encoded["served_models"] = list(vote.served_models)
    encoded["exposures"] = [list(pair) for pair in vote.exposures]
    return encoded


# ------------------------------------------------------------------- reading


def read_session(
    path: Path,
    *,
    run_id: str,
    revision: Any,
    config_digest: str,
) -> Session:
    """Return the session this document holds, or refuse to return anything.

    Every disagreement between the document and the run the caller is in the
    middle of is a refusal naming the field that disagreed. There is no partial
    success: the alternative to a session here is an exception, never an empty
    session, because an empty session is a clean review.
    """
    path = Path(path)
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise SessionDocumentError(
            "no session document at {}: {}. The review process wrote nothing, "
            "so nothing about it is known.".format(path, exc)) from exc

    try:
        document = json.loads(raw)
    except ValueError as exc:
        # A killed writer and a hand-edited file arrive here together, and the
        # gate treats them the same way.
        raise SessionDocumentError(
            "{} is not readable as JSON: {}".format(path, exc)) from exc

    if not isinstance(document, dict):
        raise SessionDocumentError(
            "{} holds {}, not a session document".format(path, _kind(document)))

    _check_binding(document, path, run_id, revision, config_digest)
    payload = document.get("session")
    if not isinstance(payload, dict):
        raise SessionDocumentError(
            "{}: the `session` object is missing — this is valid JSON but not a "
            "session document".format(path))
    return _decode_session(payload, str(path))


def _check_binding(
    document: Dict[str, Any],
    path: Path,
    run_id: str,
    revision: Any,
    config_digest: str,
) -> None:
    """Is this document an answer to the question being asked right now?

    A document from another revision or another configuration parses, reads as
    a review, and describes code this run is not looking at. It is not a
    cheaper answer, it is the wrong answer, and the only thing separating the
    two is this comparison.
    """
    version = document.get("schema_version")
    if version != SCHEMA_VERSION:
        # First, because every check below assumes it knows where to look.
        raise SessionDocumentError(
            "{}: schema_version is {!r}, and this agent writes and reads "
            "version {}".format(path, version, SCHEMA_VERSION))

    if document.get("complete") is not True:
        raise SessionDocumentError(
            "{}: the document carries no completion marker, so the process that "
            "wrote it did not reach the end".format(path))

    for key, expected in (
        ("run_id", str(run_id)),
        ("base_sha", _sha(revision, "base_sha")),
        ("head_sha", _sha(revision, "head_sha")),
        ("config_digest", str(config_digest)),
    ):
        actual = document.get(key)
        if actual != expected:
            raise SessionDocumentError(
                "{}: {} is {!r} in this document and {!r} in this run — the "
                "document describes a different review".format(
                    path, key, actual, expected))

    # The same rule the session payload and every nested record already follow,
    # applied to the envelope. Without it a document written by a later version
    # can carry top-level meaning this reader does not know about — a scope, a
    # provider, a policy — and be accepted as though it said nothing.
    _only(document, ("schema_version", "run_id", "base_sha", "head_sha",
                     "config_digest", "complete", "session"), str(path))


def _decode_session(payload: Dict[str, Any], where: str) -> Session:
    _only(payload, SESSION_FIELDS.values(), where)

    candidates = [
        _decode_candidate(item, "{}: candidate {}".format(where, index))
        for index, item in enumerate(_items(payload, "candidates", where), start=1)
    ]
    metrics = _decode_metrics(_field(payload, "metrics", where), where + ": metrics")

    session = Session(
        candidates=candidates,
        rejected=[
            _decode_rejected(item, "{}: rejected claim {}".format(where, index))
            for index, item in enumerate(_items(payload, "rejected", where), start=1)
        ],
        tool_calls=[
            _decode_tool_call(item, "{}: tool call {}".format(where, index))
            for index, item in enumerate(_items(payload, "tool_calls", where), start=1)
        ],
        files_examined=_strings(payload, "files_examined", where),
        exposures=_pairs(payload, "exposures", where),
        duplicates_dropped=_count(payload, "duplicates_dropped", where),
        turn=_count(payload, "turn", where),
        metrics=metrics,
        finished=_flag(payload, "finished", where),
        final_summary=_text(payload, "final_summary", where),
        unresolved=_strings(payload, "unresolved", where),
        verdict=_decode_verdict_payload(_field(payload, "verdict", where), where),
        _attempts=_counters(payload, "citation_attempts", where),
    )

    if session.finished and len(session.final_summary.strip()) < MIN_SUMMARY_CHARS:
        # `finish_review` refuses a sign-off shorter than this, so a document
        # holding one was not produced by that tool.
        raise SessionDocumentError(
            "{}: the session is marked finished but its summary is {} "
            "characters, and no sign-off shorter than {} is accepted".format(
                where, len(session.final_summary.strip()), MIN_SUMMARY_CHARS))

    if session.candidates and session.verdict is not None:
        # A reviewer has no `submit_verdict` and a verifier has no
        # `report_finding`; the two tool sets are disjoint on purpose. A
        # document holding both was assembled rather than recorded.
        raise SessionDocumentError(
            "{}: the session both reported findings and cast a verifier's "
            "verdict, which no single session can do".format(where))

    if metrics.citations_accepted != len(session.candidates):
        # One place records both, one line apart. They disagree only when the
        # document was edited — and the edit that matters is the one that
        # removes a finding, which nothing else here would notice.
        raise SessionDocumentError(
            "{}: {} accepted citations were counted but {} candidates are "
            "present; findings have been added or removed".format(
                where, metrics.citations_accepted, len(session.candidates)))

    return session


def _decode_metrics(payload: Any, where: str) -> StageMetrics:
    """Counters only, so the check is that each is a count.

    Named per field rather than splatted, so a document naming a metric this
    version does not have is a refusal instead of a `TypeError` from far away.
    """
    payload = _object(payload, where)
    names = tuple(f.name for f in dataclass_fields(StageMetrics))
    _only(payload, names, where)
    return StageMetrics(**{name: _count(payload, name, where) for name in names})


def _decode_rejected(payload: Any, where: str) -> RejectedClaim:
    payload = _object(payload, where)
    _only(payload, ("title", "file", "reason", "detail"), where)
    return RejectedClaim(
        title=_text(payload, "title", where),
        file=_text(payload, "file", where),
        reason=_text(payload, "reason", where),
        detail=_text(payload, "detail", where),
    )


def _decode_tool_call(payload: Any, where: str) -> ToolCallRecord:
    payload = _object(payload, where)
    _only(payload, ("turn", "name", "arguments", "summary", "is_error"), where)
    return ToolCallRecord(
        turn=_count(payload, "turn", where),
        name=_text(payload, "name", where),
        arguments=_object(_field(payload, "arguments", where), where + ".arguments"),
        summary=_text(payload, "summary", where),
        is_error=_flag(payload, "is_error", where),
    )


def _decode_finding(payload: Any, where: str) -> Finding:
    payload = _object(payload, where)
    _only(payload, _FINDING_FIELDS, where)
    return Finding(
        title=_text(payload, "title", where),
        severity=_choice(payload, "severity", where, SEVERITIES),
        confidence=_choice(payload, "confidence", where, CONFIDENCES),
        category=_choice(payload, "category", where, categories()),
        file=_text(payload, "file", where),
        line=_count(payload, "line", where),
        # "" is allowed and no other unrecognised word is. An absent impact is
        # a state the severity table already handles, by declining to derive
        # and saying so; an impact word nothing recognises would be believed
        # here and then silently rated by the reviewer's own label.
        impact=_choice(payload, "impact", where, OPTIONAL_IMPACTS),
        reachable_without_authentication=_choice(
            payload, "reachable_without_authentication", where, YES_NO_UNCLEAR),
        requires_user_interaction=_choice(
            payload, "requires_user_interaction", where, YES_NO_UNCLEAR),
        evidence=_text(payload, "evidence", where),
        description=_text(payload, "description", where),
        exploit_scenario=_text(payload, "exploit_scenario", where),
        recommendation=_text(payload, "recommendation", where),
    )


def _decode_vote(payload: Any, where: str) -> Vote:
    payload = _object(payload, where)
    _only(payload, _VOTE_FIELDS, where)
    return Vote(
        verdict=_choice(payload, "verdict", where, VERDICTS),
        reasoning=_text(payload, "reasoning", where),
        corrected_impact=_choice(
            payload, "corrected_impact", where, OPTIONAL_IMPACTS),
        corrected_reachable=_choice(
            payload, "corrected_reachable", where, OPTIONAL_YES_NO_UNCLEAR),
        corrected_interaction=_choice(
            payload, "corrected_interaction", where, OPTIONAL_YES_NO_UNCLEAR),
        corrected_confidence=_choice(
            payload, "corrected_confidence", where, OPTIONAL_CONFIDENCES),
        removes_control=_choice(payload, "removes_control", where, ("yes", "no", "")),
        control_search=_text(payload, "control_search", where),
        entry_point=_text(payload, "entry_point", where),
        files_read=_strings(payload, "files_read", where),
        exposures=_pairs(payload, "exposures", where),
        error=_text(payload, "error", where),
        channel=_choice(payload, "channel", where, CHANNELS),
        served_models=_strings(payload, "served_models", where),
    )


def _decode_candidate(payload: Any, where: str) -> Candidate:
    payload = _object(payload, where)
    _only(payload, _CANDIDATE_FIELDS, where)

    finding = _decode_finding(_field(payload, "finding", where), where + ": finding")
    candidate = Candidate(
        finding=finding,
        evidence_located_line=_optional_count(payload, "evidence_located_line", where),
        line_corrected_from=_optional_count(payload, "line_corrected_from", where),
        in_changed_lines=_flag(payload, "in_changed_lines", where),
        path_verified=_flag(payload, "path_verified", where),
        attributed_by=_choice(payload, "attributed_by", where, ATTRIBUTIONS),
        votes=[
            _decode_vote(item, "{}: vote {}".format(where, index))
            for index, item in enumerate(_items(payload, "votes", where), start=1)
        ],
        verdict=_choice(payload, "verdict", where, VERDICTS),
        verdict_reason=_text(payload, "verdict_reason", where),
        removes_control=_flag(payload, "removes_control", where),
        # Both are passed in, which is what stops `__post_init__` from deriving
        # over them. What they should have been is checked below instead.
        severity=_choice(payload, "severity", where, SEVERITIES),
        confidence=_choice(payload, "confidence", where, CONFIDENCES),
        suppressed_by=_text(payload, "suppressed_by", where),
        severity_derivation=_text(payload, "severity_derivation", where),
    )

    _check_identity(payload, candidate, where)

    if candidate.refuted and candidate.removes_control:
        # A refuted finding is not evidence that a control was removed; the
        # panel only ever sets the flag on a claim it did not refute.
        raise SessionDocumentError(
            "{}: refuted, and marked as removing an existing control — the "
            "panel does not produce that combination".format(where))

    if candidate.attributed_by == "deleted" and not candidate.in_changed_lines:
        # Attribution to a deletion is how the change is held responsible for
        # the code; a claim carrying it while marked pre-existing has had one
        # of the two edited, and pre-existing is the side that does not block.
        raise SessionDocumentError(
            "{}: attributed to a deletion in this change and marked as not part "
            "of the change".format(where))

    # Last, so the checks above keep naming the contradiction they were written
    # for. Every one of them describes a shape this recomputation would also
    # reject, in a message about a single field.
    _check_derived_disposition(candidate, where)

    return candidate


def _check_identity(payload: Dict[str, Any], candidate: Candidate, where: str) -> None:
    """Recompute the fingerprints instead of believing the ones written down.

    Identity is derived from the category, the path, and the quoted code, and
    it is what an accepted risk is recorded against. A document free to state
    an identity that does not follow from its own text is a document that can
    borrow the identity of a finding a team has already agreed to live with,
    and that finding never appears again.
    """
    finding = candidate.finding
    for key, recomputed in (
        ("fingerprint", finding.fingerprint),
        ("fingerprints", list(finding.fingerprints)),
    ):
        claimed = _field(payload, key, where)
        if claimed != recomputed:
            raise SessionDocumentError(
                "{}: {} is {!r}, but the finding's own category, path and "
                "quoted code give {!r}".format(where, key, claimed, recomputed))


def _check_derived_disposition(candidate: Candidate, where: str) -> None:
    """Run the panel again on the recorded votes and compare, field by field.

    Everything verification decides — the verdict, the severity and how it was
    reached, the confidence, and whether a control was removed — is a pure
    function of the finding and the votes, both of which are written in this
    record. So there is exactly one disposition this record can carry, and it
    can be computed rather than believed.

    This used to *bound* those fields instead: accept any severity the recorded
    facts and their corrections could justify, and any confidence the reviewer
    or some vote had written down. The bound is wider than the rule, and a code
    review named the gap. Three confirming votes, one proposing `low`
    confidence and two silent: silence counts as agreement with the claim, so
    the panel's median is `high` — but `low` appeared in a vote, so the bound
    accepted a stored `low`, and `low` is under the gate. The same shape of hole
    stood open for severity, for the verdict itself (three confirmations and a
    stored `uncertain`), and for the removed-control flag.

    The old comment justified bounding by saying that recomputing would put a
    second definition of a majority in the codebase. That was the right worry
    and the wrong conclusion: the majority rule now lives in `panel`, and both
    the run and this loader call it.

    A candidate that was never verified carries no votes, and the panel leaves
    it exactly where it arrived — so the same comparison covers it, without
    knowing anything about why verification was skipped.
    """
    expected = decide(candidate.finding, candidate.votes)

    # `verdict_reason` is deliberately absent: it is prose, and for a finding
    # that was never verified it is written by the caller that skipped it
    # rather than by the panel. Nothing reads it to decide anything.
    for name, stored, recomputed in (
        ("verdict", candidate.verdict, expected.verdict),
        ("severity", candidate.severity, expected.severity),
        ("severity_derivation", candidate.severity_derivation,
         expected.severity_derivation),
        ("confidence", candidate.confidence, expected.confidence),
        ("removes_control", candidate.removes_control, expected.removes_control),
    ):
        if stored != recomputed:
            raise SessionDocumentError(
                "{}: {} is {!r}, and this finding with its {} recorded vote(s) "
                "derives {!r} — a disposition this record cannot produce".format(
                    where, name, stored, len(candidate.votes), recomputed))


def _decode_verdict_payload(payload: Any, where: str) -> Optional[Dict[str, Any]]:
    """The verifier's one submitted vote, as the arguments it was called with.

    Kept in the schema's own shape because `verify._vote_from_payload` reads it
    that way, and converting it here would put a second reading of a verdict in
    the codebase. What is checked is what that reader depends on: a word it
    recognises in every constrained field, so a verdict cannot arrive as
    something it will silently drop.
    """
    if payload is None:
        return None
    payload = _object(payload, where + ": verdict")
    if not str(payload.get("verdict", "")).strip():
        raise SessionDocumentError(
            "{}: a verdict was submitted with no `verdict` in it".format(where))
    # The schema is exact — `additionalProperties` is false — so a key outside
    # it never came from a verifier answering the question it was asked. Letting
    # one through would carry meaning past every check below it.
    #
    # Imported here rather than at the top: `verify` pulls in the Anthropic SDK,
    # and this module is read by the child process on the path that costs
    # nothing. Restating the key set instead would be a second definition of a
    # verdict, which is the drift the whole module is written against.
    from .verify import VERDICT_SCHEMA

    _only(payload, VERDICT_SCHEMA["properties"], where + ": verdict")
    for key, allowed in _VERDICT_PAYLOAD_ENUMS.items():
        if key in payload:
            _choice(payload, key, where + ": verdict", allowed)
    return dict(payload)


# ------------------------------------------------------------------- readers
#
# Each of these refuses rather than coerces. `int("3")` and `str(None)` are the
# conversions that let a document mean something it does not say.


def _kind(value: Any) -> str:
    return "null" if value is None else type(value).__name__


def _object(value: Any, where: str) -> Dict[str, Any]:
    if not isinstance(value, dict):
        raise SessionDocumentError(
            "{} is {}, not an object".format(where, _kind(value)))
    return value


def _only(payload: Dict[str, Any], allowed: Iterable[str], where: str) -> None:
    extra = sorted(set(payload) - set(allowed))
    if extra:
        raise SessionDocumentError(
            "{}: unknown field(s) {} — a document carrying fields this version "
            "does not read is a document this version does not understand"
            .format(where, ", ".join(repr(name) for name in extra)))


def _field(payload: Dict[str, Any], key: str, where: str) -> Any:
    value = payload.get(key, _ABSENT)
    if value is _ABSENT:
        raise SessionDocumentError("{}: `{}` is missing".format(where, key))
    return value


def _text(payload: Dict[str, Any], key: str, where: str) -> str:
    value = _field(payload, key, where)
    if not isinstance(value, str):
        raise SessionDocumentError(
            "{}: `{}` is {}, not a string".format(where, key, _kind(value)))
    return value


def _choice(
    payload: Dict[str, Any], key: str, where: str, allowed: Sequence[str]
) -> str:
    value = _text(payload, key, where)
    if value not in allowed:
        raise SessionDocumentError(
            "{}: `{}` is {!r}, which is not one of {}".format(
                where, key, value, ", ".join(repr(word) for word in allowed)))
    return value


def _flag(payload: Dict[str, Any], key: str, where: str) -> bool:
    value = _field(payload, key, where)
    if not isinstance(value, bool):
        raise SessionDocumentError(
            "{}: `{}` is {}, not true or false".format(where, key, _kind(value)))
    return value


def _count(payload: Dict[str, Any], key: str, where: str) -> int:
    value = _field(payload, key, where)
    # `isinstance(True, int)` is true, and a boolean where a counter belongs is
    # a shape error worth seeing rather than a 1.
    if isinstance(value, bool) or not isinstance(value, int):
        raise SessionDocumentError(
            "{}: `{}` is {}, not a whole number".format(where, key, _kind(value)))
    if value < 0:
        raise SessionDocumentError(
            "{}: `{}` is {}, and nothing here counts backwards".format(
                where, key, value))
    return value


def _optional_count(payload: Dict[str, Any], key: str, where: str) -> Optional[int]:
    if _field(payload, key, where) is None:
        return None
    return _count(payload, key, where)


def _counters(payload: Dict[str, Any], key: str, where: str) -> Dict[str, int]:
    mapping = _object(_field(payload, key, where), "{}: `{}`".format(where, key))
    inner = "{}: `{}`".format(where, key)
    return {_key_name(name, inner): _count(mapping, name, inner) for name in mapping}


def _key_name(name: Any, where: str) -> str:
    if not isinstance(name, str):
        raise SessionDocumentError(
            "{}: key {} is {}, not a string".format(where, name, _kind(name)))
    return name


def _items(payload: Dict[str, Any], key: str, where: str) -> List[Any]:
    value = _field(payload, key, where)
    if not isinstance(value, list):
        raise SessionDocumentError(
            "{}: `{}` is {}, not a list".format(where, key, _kind(value)))
    return value


def _strings(payload: Dict[str, Any], key: str, where: str) -> List[str]:
    out = []
    for index, item in enumerate(_items(payload, key, where)):
        if not isinstance(item, str):
            raise SessionDocumentError(
                "{}: `{}`[{}] is {}, not a string".format(
                    where, key, index, _kind(item)))
        out.append(item)
    return out


def _pairs(payload: Dict[str, Any], key: str, where: str) -> List[tuple]:
    """(path, channel) pairs, restored as tuples.

    JSON has no tuple, and the difference is not cosmetic: exposures are
    compared for membership and put into sets, so a list where a tuple belongs
    would record the same file twice and make "was this payload ever seen"
    answer differently on the two sides of the process boundary.
    """
    out = []
    for index, item in enumerate(_items(payload, key, where)):
        if not isinstance(item, list) or len(item) != 2 or not all(
                isinstance(part, str) for part in item):
            raise SessionDocumentError(
                "{}: `{}`[{}] is not a (path, channel) pair".format(
                    where, key, index))
        out.append((item[0], item[1]))
    return out
