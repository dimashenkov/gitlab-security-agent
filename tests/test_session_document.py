"""What the parent is allowed to believe about a document a child wrote.

The `claude` CLI runner puts a process boundary in the middle of the review:
the session that holds the findings, the rejections, the coverage and the
sign-off is built in a child and has to arrive in the parent as a file. Every
test here writes a real session through the real writer and reads it back
through the real reader, because the failure this guards against does not live
in either half — it lives in the document surviving a round trip while meaning
something else at the other end.

The refusals get most of the space. A loader that accepts a document from
another revision, or one whose fingerprint no longer follows from its evidence,
does not fail: it produces a shorter review, and a shorter review is
indistinguishable from a clean one at the gate.
"""

from __future__ import annotations

import json
from dataclasses import fields as dataclass_fields
from pathlib import Path

import pytest

import security_agent.session_document as session_document
from conftest import make_candidate
from security_agent.models import (
    VERDICT_CONFIRMED,
    VERDICT_REFUTED,
    VERDICT_UNCERTAIN,
    RejectedClaim,
    Revision,
    ToolCallRecord,
    Vote,
)
from security_agent.session_document import (
    SCHEMA_VERSION,
    SESSION_FIELDS,
    SessionDocumentError,
    read_session,
    write_session,
)
from security_agent.tools import Session
from security_agent.verify import _decide

RUN_ID = "job-8814"
DIGEST = "3f1c9a2b7d4e6058"
REVISION = Revision(mode="mr", base="main", head="HEAD",
                    base_sha="a" * 40, head_sha="b" * 40)

SUMMARY = ("Read both changed handlers and their callers; the id is "
           "concatenated and the outbound URL is unvalidated.")


def _vote(**overrides):
    payload = {
        "verdict": VERDICT_CONFIRMED,
        "reasoning": "The caller passes the raw query string straight through.",
        "control_search": "Looked for a validator on the id in views.py and its "
                          "two callers; there is none.",
        "entry_point": "GET /users?id= reaches get_user with no session check.",
        "channel": "submit_verdict",
        "files_read": ["app/views.py", "app/urls.py"],
        "exposures": [("app/views.py", "get_diff"), ("app/urls.py", "read_file")],
        "served_models": ["claude-opus-4-1"],
    }
    payload.update(overrides)
    return Vote(**payload)


def _reviewer_session() -> Session:
    """A session shaped like one a finished review actually leaves behind."""
    session = Session()

    injection = make_candidate()
    injection.votes = [
        _vote(),
        _vote(verdict=VERDICT_UNCERTAIN, reasoning="Could not reach the caller."),
        _vote(removes_control="no"),
    ]
    injection.verdict = VERDICT_CONFIRMED
    injection.verdict_reason = "2 of 3 verifiers confirmed."

    ssrf = make_candidate(
        title="Unvalidated outbound request",
        category="ssrf",
        file="app/net.py",
        line=31,
        impact="narrow_data_access",
        reachable_without_authentication="no",
        requires_user_interaction="unclear",
        evidence="requests.get(user_url, timeout=5)",
        attributed_by="deleted",
    )
    # The three votes the flag rests on. It used to be set with no votes behind
    # it, which is a document the loader now refuses — and rightly: unanimity is
    # what turns a removed control into a blocked merge, so a flag with nothing
    # to be unanimous about is a gate decision nobody made.
    ssrf.votes = [_vote(removes_control="yes") for _ in range(3)]
    ssrf.verdict_reason = "All three verifiers saw the removed allow-list."
    ssrf.removes_control = True

    session.candidates.extend([injection, ssrf])
    session.metrics.citations_accepted = 2
    session.metrics.citations_rejected_not_found = 1
    session.metrics.lines_corrected = 1
    session.metrics.verified = 2
    session.metrics.verdicts_changed = 1

    session.rejected.append(RejectedClaim(
        title="Hard-coded key in the settings module",
        file="app/settings.py",
        reason="evidence-not-found",
        detail="the quoted line does not appear in the file",
    ))
    session.tool_calls.append(ToolCallRecord(
        turn=1, name="get_diff", arguments={"path": "app/views.py",
                                            "context_lines": 12},
        summary="diff for app/views.py",
    ))
    session.tool_calls.append(ToolCallRecord(
        turn=2, name="read_file", arguments={"path": "nope.py"},
        summary="no such file", is_error=True,
    ))
    session.note_file("app/views.py")
    session.note_file("app/net.py")
    session.note_exposure("app/views.py", "get_diff")
    session.note_exposure("app/net.py", "search_code")
    session.attempt("app/settings.py|hard-coded key in the settings module")
    session.duplicates_dropped = 1
    session.turn = 9
    session.finished = True
    session.final_summary = SUMMARY
    session.unresolved = ["Could not tell whether the proxy strips the header."]
    return session


def _verifier_session() -> Session:
    """A verifier's session: one vote, no findings of its own."""
    session = Session()
    session.turn = 4
    session.note_file("app/views.py")
    session.note_exposure("app/views.py", "get_diff")
    session.verdict = {
        "verdict": VERDICT_REFUTED,
        "reasoning": "The caller binds the id as a parameter before this line.",
        "corrected_impact": "",
        "corrected_reachable_without_authentication": "no",
        "corrected_requires_user_interaction": "",
        "corrected_confidence": "low",
        "removes_existing_control": "no",
        "control_search": "views.py:8 binds the parameter; both callers go "
                          "through it.",
        "entry_point": "GET /users?id=",
    }
    return session


def _panel_session(votes) -> Session:
    """One candidate and the panel that voted on it, with nothing else in it.

    The candidate is left exactly as the pipeline builds it — severity derived
    from the finding's own facts, confidence the reviewer's — which is the state
    a panel starts from and the state the loader reconstructs.
    """
    session = Session()
    candidate = make_candidate()
    candidate.votes = list(votes)
    session.candidates.append(candidate)
    session.metrics.citations_accepted = 1
    return session


def _write(path: Path, session: Session) -> None:
    write_session(path, session, run_id=RUN_ID, revision=REVISION,
                  config_digest=DIGEST)


def _read(path: Path, **overrides) -> Session:
    arguments = {"run_id": RUN_ID, "revision": REVISION, "config_digest": DIGEST}
    arguments.update(overrides)
    return read_session(path, **arguments)


def _tampered(path: Path, mutate) -> Path:
    """Write a valid document, then edit it the way an attacker or a bug would."""
    document = json.loads(path.read_text(encoding="utf-8"))
    mutate(document)
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


@pytest.fixture
def document(tmp_path: Path) -> Path:
    path = tmp_path / "out" / "session.json"
    _write(path, _reviewer_session())
    return path


class TestRoundTrip:
    """The parent must end up with the session the child had.

    Not "a session with the same findings in it" — the gate reads the
    attribution, the counters and the sign-off as well, and each of those
    decides something on its own.
    """

    def test_every_field_of_the_session_survives(self, document):
        original = _reviewer_session()
        loaded = _read(document)
        for field in dataclass_fields(Session):
            assert getattr(loaded, field.name) == getattr(original, field.name), (
                "{} did not survive the round trip".format(field.name))

    def test_nested_votes_survive_whole(self, document):
        """Votes cross the boundary inside candidates, so they are the part a
        shallow encoder drops without any test noticing."""
        loaded = _read(document)
        votes = loaded.candidates[0].votes
        assert [v.verdict for v in votes] == [
            VERDICT_CONFIRMED, VERDICT_UNCERTAIN, VERDICT_CONFIRMED]
        assert votes[0].control_search.startswith("Looked for a validator")
        assert votes[0].entry_point.startswith("GET /users?id=")
        assert votes[0].files_read == ["app/views.py", "app/urls.py"]
        assert votes[0].served_models == ["claude-opus-4-1"]
        assert votes[0].channel == "submit_verdict"
        assert votes[2].removes_control == "no"

    def test_exposures_come_back_as_pairs_not_lists(self, document):
        """JSON has no tuple. Exposures are membership-tested and set-compared,
        so a list here answers "was this payload ever seen" differently on the
        two sides of the process boundary."""
        loaded = _read(document)
        assert loaded.exposures == [("app/views.py", "get_diff"),
                                    ("app/net.py", "search_code")]
        assert all(isinstance(pair, tuple) for pair in loaded.exposures)
        assert all(isinstance(pair, tuple)
                   for pair in loaded.candidates[0].votes[0].exposures)

    def test_a_verifier_session_round_trips(self, tmp_path):
        """The other kind of session that crosses the boundary: one vote and no
        findings. Its payload is what the verification layer reads a verdict
        out of."""
        path = tmp_path / "verdict.json"
        _write(path, _verifier_session())
        loaded = _read(path)
        assert loaded.verdict == _verifier_session().verdict
        assert loaded.candidates == []

    def test_the_document_says_which_run_it_belongs_to(self, document):
        raw = json.loads(document.read_text(encoding="utf-8"))
        assert raw["schema_version"] == SCHEMA_VERSION
        assert raw["run_id"] == RUN_ID
        assert raw["base_sha"] == REVISION.base_sha
        assert raw["head_sha"] == REVISION.head_sha
        assert raw["config_digest"] == DIGEST
        assert raw["complete"] is True

    def test_the_document_carries_every_field_the_session_has(self, document):
        """The drift this catches: a field added to `Session` and not to the
        encoder reaches the parent as its default, which for a list of findings
        is an empty list and for a sign-off is `False`."""
        assert set(SESSION_FIELDS) == {f.name for f in dataclass_fields(Session)}
        raw = json.loads(document.read_text(encoding="utf-8"))
        assert set(raw["session"]) == set(SESSION_FIELDS.values())


class TestBinding:
    """A document is an answer to one question, and says which one.

    Every field here can differ while the document still parses and still reads
    as a review. That is the whole danger: the wrong answer arrives in the
    shape of the right one.
    """

    def test_a_document_from_another_run_is_refused(self, document):
        with pytest.raises(SessionDocumentError, match="run_id"):
            _read(document, run_id="job-8815")

    def test_a_document_from_another_base_is_refused(self, document):
        """The same head against a different base is a different diff, so it is
        a different review of the same commit."""
        other = Revision(base_sha="c" * 40, head_sha=REVISION.head_sha)
        with pytest.raises(SessionDocumentError, match="base_sha"):
            _read(document, revision=other)

    def test_a_document_from_another_head_is_refused(self, document):
        other = Revision(base_sha=REVISION.base_sha, head_sha="d" * 40)
        with pytest.raises(SessionDocumentError, match="head_sha"):
            _read(document, revision=other)

    def test_a_document_from_another_configuration_is_refused(self, document):
        """Exclusions and gate settings change which findings exist at all; a
        result produced under one configuration is not a result under another."""
        with pytest.raises(SessionDocumentError, match="config_digest"):
            _read(document, config_digest="0000000000000000")

    def test_a_document_of_another_schema_version_is_refused(self, document):
        _tampered(document, lambda d: d.update(schema_version=SCHEMA_VERSION + 1))
        with pytest.raises(SessionDocumentError, match="schema_version"):
            _read(document)

    def test_the_field_that_disagreed_is_named(self, document):
        with pytest.raises(SessionDocumentError) as caught:
            _read(document, run_id="job-8815")
        assert "run_id" in str(caught.value)
        assert "job-8815" in str(caught.value)


class TestIncompleteDocuments:
    """Absent, unfinished, or unreadable — all of them mean "no answer"."""

    def test_a_missing_document_raises_rather_than_returning_empty(self, tmp_path):
        """An empty session renders as a review that found nothing, which is
        exactly what a killed child must never produce."""
        with pytest.raises(SessionDocumentError, match="no session document"):
            _read(tmp_path / "never-written.json")

    def test_a_truncated_document_is_refused(self, document):
        raw = document.read_text(encoding="utf-8")
        document.write_text(raw[:len(raw) // 2], encoding="utf-8")
        with pytest.raises(SessionDocumentError, match="not readable as JSON"):
            _read(document)

    def test_a_document_without_the_completion_marker_is_refused(self, document):
        _tampered(document, lambda d: d.pop("complete"))
        with pytest.raises(SessionDocumentError, match="completion marker"):
            _read(document)

    def test_valid_json_that_is_not_a_session_document_is_refused(self, document):
        document.write_text(json.dumps({"findings": [], "ok": True}),
                            encoding="utf-8")
        with pytest.raises(SessionDocumentError, match="schema_version"):
            _read(document)

    def test_a_json_array_is_not_a_session_document(self, document):
        document.write_text("[]", encoding="utf-8")
        with pytest.raises(SessionDocumentError, match="not a session document"):
            _read(document)

    def test_a_bound_document_with_no_session_in_it_is_refused(self, document):
        _tampered(document, lambda d: d.pop("session"))
        with pytest.raises(SessionDocumentError, match="not a session document"):
            _read(document)


class TestDerivedStateIsRecomputed:
    """Nothing derived is believed, because a derived value is the cheap thing
    to edit: it decides the gate and it has no obvious owner in the document."""

    def test_a_tampered_fingerprint_is_refused(self, document):
        """A fingerprint is what an accepted risk is recorded against. A
        document free to state one that does not follow from its own evidence
        can borrow the identity of a finding the team already agreed to live
        with, and that finding never appears again."""
        _tampered(document, lambda d: d["session"]["candidates"][0].update(
            fingerprint="0123456789abcdef"))
        with pytest.raises(SessionDocumentError, match="fingerprint"):
            _read(document)

    def test_a_tampered_anchor_list_is_refused(self, document):
        _tampered(document, lambda d: d["session"]["candidates"][0].update(
            fingerprints=["0123456789abcdef"]))
        with pytest.raises(SessionDocumentError, match="fingerprints"):
            _read(document)

    def test_rewriting_the_evidence_breaks_the_identity_it_claims(self, document):
        """The substitution that motivates recomputing rather than reading: the
        quoted code is swapped for another file's line while the fingerprint
        stays, so the finding keeps an identity that describes code it no
        longer cites."""
        _tampered(document, lambda d: d["session"]["candidates"][0]["finding"].update(
            evidence="cursor.execute(safe_query, (user_id,))"))
        with pytest.raises(SessionDocumentError, match="quoted code"):
            _read(document)

    def test_a_severity_the_recorded_facts_cannot_produce_is_refused(self, document):
        """Severity is computed from impact, reachability and interaction, and
        the gate is a step function on it. A document that can state a severity
        its own facts do not derive can move a finding across the gate in
        either direction without touching a fact."""
        _tampered(document, lambda d: d["session"]["candidates"][0].update(
            severity="low"))
        with pytest.raises(SessionDocumentError, match="severity"):
            _read(document)

    def test_a_severity_a_verifier_corrected_is_accepted(self, tmp_path):
        """The other half of the same rule, and the one that has to hold by
        construction: the disposition is produced by the real `_decide`, so a
        loader that refused it would mean the run and the reader disagree about
        the majority rule. The rating written here is not asserted from a
        constant — it is whatever the panel actually produced."""
        session = Session()
        candidate = make_candidate()
        candidate.votes = [_vote(corrected_impact="narrow_data_access")]
        _decide(candidate)
        session.candidates.append(candidate)
        session.metrics.citations_accepted = 1

        path = tmp_path / "corrected.json"
        _write(path, session)
        loaded = _read(path).candidates[0]
        assert loaded.severity == "medium"
        assert "verifiers corrected impact" in loaded.severity_derivation

    def test_a_confidence_nobody_stated_is_refused(self, document):
        """Confidence is what the panel agreed on, and the panel is here: the
        finding's own claim and every vote cast on it. A document is free to
        write any word in the field, and the gate is a step function on it."""
        _tampered(document, lambda d: d["session"]["candidates"][1].update(
            confidence="medium"))
        with pytest.raises(SessionDocumentError, match="confidence"):
            _read(document)


class TestTheDispositionIsRecomputedNotBounded:
    """The defect a code review found: the loader bounded instead of deriving.

    It accepted any severity the recorded facts and their corrections could
    justify, and any confidence the reviewer or some vote had written down. The
    bound is wider than the rule, and every case below sits in the gap — each
    one a document the old loader accepted and no panel could have produced.
    Each is one step on the gate, which is the whole decision.
    """

    def test_a_confidence_one_hedging_vote_wrote_down_is_refused(self, tmp_path):
        """The input the review named. Three confirming votes, one proposing
        `low` and two silent — and silence is agreement with the claim, so the
        panel's median is `high`. The old bound accepted `low` because a vote
        contained the word, and `low` is under the gate: one hedging verifier
        could ungate a real finding through the document rather than through
        the panel."""
        path = tmp_path / "session.json"
        _write(path, _panel_session([
            _vote(corrected_confidence="low"), _vote(), _vote()]))
        assert _read(path).candidates[0].confidence == "high"

        _tampered(path, lambda d: d["session"]["candidates"][0].update(
            confidence="low"))
        with pytest.raises(SessionDocumentError) as raised:
            _read(path)
        assert "confidence" in str(raised.value)
        assert "'low'" in str(raised.value) and "'high'" in str(raised.value)

    def test_a_severity_only_a_minority_corrected_is_refused(self, tmp_path):
        """One of three verifiers calls it code execution and the other two say
        nothing. A correction needs a majority of the whole panel, so severity
        stays `high` — but the old bound enumerated every combination of every
        proposed fact, and `critical` was in it. A single verifier's opinion,
        stored, became a critical."""
        path = tmp_path / "session.json"
        _write(path, _panel_session([
            _vote(corrected_impact="code_execution"), _vote(), _vote()]))
        assert _read(path).candidates[0].severity == "high"

        _tampered(path, lambda d: d["session"]["candidates"][0].update(
            severity="critical"))
        with pytest.raises(SessionDocumentError) as raised:
            _read(path)
        assert "severity" in str(raised.value)
        assert "'critical'" in str(raised.value) and "'high'" in str(raised.value)

    def test_a_verdict_the_votes_do_not_add_up_to_is_refused(self, tmp_path):
        """Three confirmations and a stored `uncertain`. The old loader never
        looked at the verdict at all, and this is the cheapest edit on the
        page: `uncertain` forces confidence to `low`, `low` is under the gate,
        and the finding stays in the report saying nothing was settled."""
        path = tmp_path / "session.json"
        _write(path, _panel_session([_vote(), _vote(), _vote()]))
        assert _read(path).candidates[0].verdict == VERDICT_CONFIRMED

        _tampered(path, lambda d: d["session"]["candidates"][0].update(
            verdict=VERDICT_UNCERTAIN))
        with pytest.raises(SessionDocumentError) as raised:
            _read(path)
        assert "verdict" in str(raised.value)
        assert "'uncertain'" in str(raised.value)

    def test_a_removed_control_flag_the_panel_did_not_agree_on_is_refused(
            self, tmp_path):
        """Two of three verifiers see a removed control and the third does not
        say. The flag blocks a merge whatever the severity, so it takes
        unanimity — and the old loader checked only that a refuted finding did
        not also carry it, which left every unrefuted finding free to."""
        path = tmp_path / "session.json"
        _write(path, _panel_session([
            _vote(removes_control="yes"), _vote(removes_control="yes"), _vote()]))
        assert _read(path).candidates[0].removes_control is False

        _tampered(path, lambda d: d["session"]["candidates"][0].update(
            removes_control=True))
        with pytest.raises(SessionDocumentError) as raised:
            _read(path)
        assert "removes_control" in str(raised.value)

    def test_the_disposition_the_real_panel_produced_is_accepted(self, tmp_path):
        """The other side of every case above, and the reason there can be only
        one rule: what `_decide` writes is what this loader recomputes. A panel
        that moves severity, and a loader that agrees it moved."""
        session = _panel_session([
            _vote(corrected_impact="narrow_data_access"),
            _vote(corrected_impact="narrow_data_access"),
            _vote(verdict=VERDICT_UNCERTAIN, reasoning="Could not reach it."),
        ])
        _decide(session.candidates[0])
        path = tmp_path / "session.json"
        _write(path, session)

        loaded = _read(path).candidates[0]
        assert loaded.verdict == VERDICT_CONFIRMED
        assert loaded.severity == "medium"
        assert loaded.confidence == "high"


class TestVocabulary:
    """A word nothing recognises is not a value; it is an unchecked string.

    `severity_rank` returns -1 for one, and -1 read as a threshold is how an
    unrecognised severity stopped blocking once already.
    """

    def test_an_unknown_severity_word_is_refused(self, document):
        _tampered(document, lambda d: d["session"]["candidates"][0]["finding"].update(
            severity="catastrophic"))
        with pytest.raises(SessionDocumentError, match="catastrophic"):
            _read(document)

    def test_an_unknown_derived_severity_word_is_refused(self, document):
        _tampered(document, lambda d: d["session"]["candidates"][0].update(
            severity="severe"))
        with pytest.raises(SessionDocumentError, match="severe"):
            _read(document)

    def test_an_unknown_category_is_refused(self, document):
        """Categories come from the finding schema, and the corpus once scored
        against three names the agent can never emit."""
        _tampered(document, lambda d: d["session"]["candidates"][0]["finding"].update(
            category="authorization"))
        with pytest.raises(SessionDocumentError, match="authorization"):
            _read(document)

    def test_an_unknown_impact_is_refused(self, document):
        _tampered(document, lambda d: d["session"]["candidates"][0]["finding"].update(
            impact="total_compromise"))
        with pytest.raises(SessionDocumentError, match="total_compromise"):
            _read(document)

    def test_an_unknown_answer_to_a_yes_no_unclear_question_is_refused(self, document):
        """`unclear` is a real answer and `maybe` is not one; the severity
        table treats anything it does not recognise as no discount at all."""
        _tampered(document, lambda d: d["session"]["candidates"][0]["finding"].update(
            reachable_without_authentication="maybe"))
        with pytest.raises(SessionDocumentError, match="maybe"):
            _read(document)

    def test_an_unknown_verdict_is_refused(self, document):
        _tampered(document, lambda d: d["session"]["candidates"][0]["votes"][0].update(
            verdict="probably"))
        with pytest.raises(SessionDocumentError, match="probably"):
            _read(document)

    def test_an_unknown_verdict_in_a_verifier_payload_is_refused(self, tmp_path):
        path = tmp_path / "verdict.json"
        _write(path, _verifier_session())
        _tampered(path, lambda d: d["session"]["verdict"].update(
            corrected_confidence="certain"))
        with pytest.raises(SessionDocumentError, match="certain"):
            _read(path)

    def test_a_missing_finding_field_is_refused(self, document):
        _tampered(document, lambda d: d["session"]["candidates"][0]["finding"].pop(
            "exploit_scenario"))
        with pytest.raises(SessionDocumentError, match="exploit_scenario"):
            _read(document)

    def test_a_field_this_version_does_not_read_is_refused(self, document):
        """Silently ignoring an unknown field is how a document written by a
        newer writer reads as a smaller review here."""
        _tampered(document, lambda d: d["session"]["candidates"][0].update(
            gate_override=True))
        with pytest.raises(SessionDocumentError, match="gate_override"):
            _read(document)

    def test_a_number_where_a_string_belongs_is_refused(self, document):
        _tampered(document, lambda d: d["session"]["candidates"][0]["finding"].update(
            title=7))
        with pytest.raises(SessionDocumentError, match="not a string"):
            _read(document)

    def test_a_counter_that_runs_backwards_is_refused(self, document):
        _tampered(document, lambda d: d["session"]["metrics"].update(
            citations_rejected_not_found=-1))
        with pytest.raises(SessionDocumentError, match="backwards"):
            _read(document)

    def test_an_exposure_that_is_not_a_pair_is_refused(self, document):
        _tampered(document, lambda d: d["session"].update(
            exposures=[["app/views.py"]]))
        with pytest.raises(SessionDocumentError, match="pair"):
            _read(document)


class TestImpossibleCombinations:
    """Shapes no session can reach, which is what makes them worth checking.

    Each one is a document that was assembled rather than recorded, and each
    edits something the gate reads.
    """

    def test_removing_a_finding_contradicts_the_citation_counter(self, document):
        """The counter and the list are written one line apart in
        `report_finding`, so they disagree only when the document was edited —
        and the edit worth making is the one that removes a finding."""
        _tampered(document, lambda d: d["session"]["candidates"].pop(0))
        with pytest.raises(SessionDocumentError, match="added or removed"):
            _read(document)

    def test_a_refuted_finding_cannot_also_remove_a_control(self, document):
        _tampered(document, lambda d: d["session"]["candidates"][1].update(
            verdict="refuted"))
        with pytest.raises(SessionDocumentError, match="removing an existing control"):
            _read(document)

    def test_a_deletion_attribution_cannot_be_pre_existing(self, document):
        """Pre-existing is the side that does not block, so this is the edit
        that ungates a removed control."""
        _tampered(document, lambda d: d["session"]["candidates"][1].update(
            in_changed_lines=False))
        with pytest.raises(SessionDocumentError, match="not part of the change"):
            _read(document)

    def test_a_sign_off_shorter_than_finish_review_accepts_is_refused(self, document):
        _tampered(document, lambda d: d["session"].update(final_summary="looks fine"))
        with pytest.raises(SessionDocumentError, match="summary"):
            _read(document)

    def test_one_session_cannot_both_report_and_vote(self, document):
        """The reviewer has no `submit_verdict` and the verifier has no
        `report_finding`; the tool sets are disjoint on purpose."""
        _tampered(document, lambda d: d["session"].update(
            verdict={"verdict": "confirmed"}))
        with pytest.raises(SessionDocumentError, match="no single session can do"):
            _read(document)

    def test_a_submitted_verdict_without_a_verdict_in_it_is_refused(self, tmp_path):
        path = tmp_path / "verdict.json"
        _write(path, _verifier_session())
        _tampered(path, lambda d: d["session"]["verdict"].update(verdict=""))
        with pytest.raises(SessionDocumentError, match="no `verdict` in it"):
            _read(path)


class TestAtomicWrite:
    """A half-written document must never be readable as a whole one.

    The child is killed by turn limits, timeouts and CI cancellations, and the
    document it was in the middle of writing would otherwise be a review with
    the last few findings missing.
    """

    def test_a_failed_write_leaves_no_document_at_all(self, tmp_path):
        """The session is serialised before the file is opened, so a session
        that cannot be written produces nothing rather than a prefix."""
        session = _reviewer_session()
        session.tool_calls.append(ToolCallRecord(
            turn=3, name="read_file", arguments={"path": object()},
            summary="unserialisable"))
        path = tmp_path / "session.json"

        with pytest.raises(SessionDocumentError, match="not JSON"):
            _write(path, session)
        assert list(tmp_path.iterdir()) == []

    def test_a_write_that_fails_midway_leaves_nothing_behind(self, tmp_path,
                                                             monkeypatch):
        """The failure a temporary file introduces of its own: a `.part` left
        in the output directory, which the next reader finds alongside the real
        document with no way to tell which is which."""
        path = tmp_path / "session.json"
        monkeypatch.setattr(
            "security_agent.session_document.os.fsync",
            lambda fd: (_ for _ in ()).throw(OSError("disk full")))

        with pytest.raises(SessionDocumentError, match="disk full"):
            _write(path, _reviewer_session())
        assert list(tmp_path.iterdir()) == []

    def test_a_failed_write_leaves_the_previous_document_readable(self, document):
        """The dangerous half of a non-atomic write: the destination is
        truncated first, so a failure replaces a good answer with a broken
        one."""
        broken = _reviewer_session()
        broken.unresolved = [object()]

        with pytest.raises(SessionDocumentError):
            _write(document, broken)
        assert len(_read(document).candidates) == 2

    def test_no_temporary_file_survives_a_successful_write(self, document):
        assert [p.name for p in document.parent.iterdir()] == ["session.json"]

    def test_the_document_is_replaced_whole_on_a_second_write(self, document):
        session = _reviewer_session()
        session.candidates.pop()
        session.metrics.citations_accepted = 1
        _write(document, session)

        loaded = _read(document)
        assert len(loaded.candidates) == 1
        assert [p.name for p in document.parent.iterdir()] == ["session.json"]



class TestWhatARuntimeCheckCatchesThatATestCannot:
    """Three refusals a code review asked for after the module was written.

    Each closes the same shape of hole: something the document could carry, or
    fail to carry, that every check downstream would then never look at.
    """

    def test_a_session_field_nobody_wrote_is_refused_at_write_time(
            self, tmp_path, monkeypatch):
        """A test catches this on the branch it runs on. A field added to
        `Session` on another branch, or a package built from a tree whose tests
        nobody ran, reaches the parent as its default — an empty candidate
        list, a `False` sign-off — and the parent cannot tell."""
        monkeypatch.delitem(session_document.SESSION_FIELDS, "candidates")

        with pytest.raises(SessionDocumentError) as raised:
            _write(tmp_path / "session.json", _reviewer_session())

        assert "candidates" in str(raised.value)
        assert not (tmp_path / "session.json").exists()

    def test_an_unknown_top_level_key_is_refused(self, document):
        """The envelope now follows the rule the payload already did. A later
        version can put meaning up here — a scope, a provider, a policy — and
        this reader would otherwise accept the document as though it said
        nothing."""
        tampered = _tampered(document, lambda raw: raw.update({"policy": "lax"}))

        with pytest.raises(SessionDocumentError) as raised:
            _read(tampered)

        assert "policy" in str(raised.value)

    def test_an_unknown_key_in_a_submitted_verdict_is_refused(self, tmp_path):
        """`submit_verdict`'s schema is exact, so a key outside it never came
        from a verifier answering the question it was asked."""
        path = tmp_path / "session.json"
        _write(path, _verifier_session())
        tampered = _tampered(
            path, lambda raw: raw["session"]["verdict"].update({"override": "pass"}))

        with pytest.raises(SessionDocumentError) as raised:
            _read(tampered)

        assert "override" in str(raised.value)
