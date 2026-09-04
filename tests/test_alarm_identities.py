"""Naming the twenty findings, and the ways a name could be assumed.

Every test here is written against a way an identity could look established and
not be: a legacy row admitted because a row exists, two rulings collapsed
because their claims resemble each other, a denominator stated rather than
counted.
"""

from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import alarm_identities as ai  # noqa: E402


ALARMS = {"case-a", "case-b", "case-legacy"}


def rulings():
    return [
        {"case_id": "case-a", "member": "safe", "fingerprint": "aaaa1111",
         "file": "a.py", "claim": "a thing"},
        {"case_id": "case-b", "member": "safe", "fingerprint": "bbbb2222",
         "file": "b.py", "claim": "b thing"},
        {"case_id": "case-legacy", "member": "safe", "fingerprint": None,
         "file": "legacy.py", "claim": "something in a file"},
    ]


def identities(findings=None, **over):
    body = {
        "schema": ai.SCHEMA,
        "decided_by": "assistant",
        "decided_on": "2026-09-04",
        "findings": findings if findings is not None else [
            {"finding_id": "legacy-thing", "case_id": "case-legacy",
             "member": "safe", "fingerprint": None,
             "file": "legacy.py",
             "identity_basis": "file_and_claim",
             "claim": "something in a file",
             "decided_by": "assistant", "decided_on": "2026-09-04",
             "rationale": "one ruling, one file, one mechanism",
             "evidence_refs": ["corpus-real/adjudications.yml"]},
        ],
    }
    body.update(over)
    return body


def test_every_alarm_resolves_and_the_denominator_is_counted():
    outcome = ai.resolve(ALARMS, rulings(), identities())
    assert outcome["unresolved"] == []
    assert outcome["denominator"] == 3
    assert outcome["problems"] == []
    # The fingerprinted ones need no entry; the legacy one takes its declared
    # name rather than a synthesised one.
    assert outcome["resolved"]["case-legacy"] == "legacy-thing"
    assert outcome["resolved"]["case-a"].endswith("aaaa1111")


def test_a_legacy_row_with_no_entry_is_unresolved_not_assumed():
    """A row existing is not a name. It leaves the denominator and stays in
    the report — excluding it silently would bias toward newer runs, and
    admitting it would count a name nobody established."""
    outcome = ai.resolve(ALARMS, rulings(), identities(findings=[
        {"finding_id": "x", "case_id": "case-a", "member": "safe",
         "file": "a.py", "fingerprint": "aaaa1111",
         "decided_by": "assistant",
         "evidence_refs": ["corpus-real/adjudications.yml"]}]))
    assert outcome["unresolved"] == ["case-legacy"]
    assert outcome["denominator"] == 2


def test_an_identity_with_no_stated_ground_is_refused():
    """`identity_basis` says which field the name came from.

    Without it a weaker basis is discovered rather than disagreed with.
    """
    entry = identities()["findings"][0]
    del entry["identity_basis"]
    outcome = ai.resolve(ALARMS, rulings(), identities(findings=[entry]))
    assert any("no stated ground" in p for p in outcome["problems"])


def test_supersession_without_a_rationale_is_refused():
    """Two rulings become one finding only where the file says why.

    Inferring it from similar claims is a false automatic rule, and the
    assistant's first reading of the one real pair was wrong.
    """
    entry = dict(identities()["findings"][0], same_finding_as="revision")
    entry.pop("rationale")
    outcome = ai.resolve(ALARMS, rulings(), identities(findings=[entry]))
    assert any("never inferred" in p for p in outcome["problems"])


def test_one_case_declared_twice_is_refused():
    entry = identities()["findings"][0]
    outcome = ai.resolve(ALARMS, rulings(),
                         identities(findings=[entry, dict(entry,
                                                          finding_id="other")]))
    assert any("declared twice" in p for p in outcome["problems"])


def test_an_identity_for_something_that_did_not_alarm_is_refused():
    outcome = ai.resolve(ALARMS, rulings(), identities(findings=[
        dict(identities()["findings"][0], case_id="never-alarmed")]))
    assert any("not an alarm" in p for p in outcome["problems"])


def test_a_declared_denominator_that_does_not_count_is_refused(
        tmp_path, capsys):
    """Drives the CLI, because that is where the comparison lives.

    The first version observed independently that 3 differs from 99 and never
    ran the code that refuses it - a refusal test asserting arithmetic. Codex,
    2026-09-04.
    """
    shipped = yaml.safe_load(
        (ROOT / "measurements" / "alarm-codebook" / "identities.yml")
        .read_text(encoding="utf-8"))
    shipped["denominator"] = 99
    path = tmp_path / "identities.yml"
    path.write_text(yaml.safe_dump(shipped), encoding="utf-8")
    assert ai.main(["--identities", str(path)]) == 2
    assert "stated rather than counted" in capsys.readouterr().err


@pytest.mark.parametrize("spoil, expect", [
    ({"schema": "something-else"}, "declares schema"),
    ({"findings": []}, "records no findings"),
])
def test_a_file_this_tool_cannot_read_is_refused(tmp_path, spoil, expect):
    path = tmp_path / "identities.yml"
    path.write_text(yaml.safe_dump(identities(**spoil)), encoding="utf-8")
    with pytest.raises(ai.IdentityError) as caught:
        ai.load_identities(path)
    assert expect in str(caught.value)


def test_a_missing_file_is_refused_rather_than_defaulted(tmp_path):
    with pytest.raises(ai.IdentityError) as caught:
        ai.load_identities(tmp_path / "nothing.yml")
    assert "before classification" in str(caught.value)


def test_the_shipped_file_resolves_every_live_alarm():
    """The chain, over the real rulings rather than a fixture.

    Twenty alarms, twenty identities, and the four rows without a fingerprint
    each carrying the field their name came from.
    """
    identities_path = ROOT / "measurements" / "alarm-codebook" / "identities.yml"
    body = ai.load_identities(identities_path)
    alarming, live = ai.alarms_and_rulings(ROOT / "corpus-real")
    outcome = ai.resolve(alarming, live, body)
    assert outcome["alarms"] == 20
    assert outcome["unresolved"] == []
    assert outcome["problems"] == []
    assert outcome["denominator"] == body["denominator"] == 20
    for entry in body["findings"]:
        if not entry.get("fingerprint"):
            assert entry["identity_basis"] in ai.IDENTITY_BASES
            assert entry["evidence_refs"]


def test_the_command_line_exits_zero_over_the_shipped_file(capsys):
    assert ai.main([]) == 0
    out = capsys.readouterr().out
    assert "20 alarm(s)" in out
    assert "unresolved : 0" in out


def test_the_json_output_carries_the_denominator(capsys):
    assert ai.main(["--json"]) == 0
    body = json.loads(capsys.readouterr().out)
    assert body["denominator"] == 20
    assert body["unresolved"] == []


def test_an_unresolved_alarm_exits_two_never_one(tmp_path, capsys):
    """"Some alarm has no name" is not a finding about the reviewer."""
    path = tmp_path / "identities.yml"
    trimmed = copy.deepcopy(identities())
    trimmed["findings"] = [{"finding_id": "x", "case_id": "not-an-alarm",
                            "fingerprint": "cccc3333"}]
    path.write_text(yaml.safe_dump(trimmed), encoding="utf-8")
    assert ai.main(["--identities", str(path)]) == 2


# --------------------------------------------------------------------------
# An entry is checked against the rulings it claims to describe
#
# Codex, 2026-09-04: trusting `case_id` alone let a fabricated identity resolve
# and enter the denominator. On its first run the new check caught the
# assistant's own record, whose claim had been paraphrased rather than quoted.
# --------------------------------------------------------------------------

def test_an_identity_for_a_case_with_no_ruling_is_refused():
    outcome = ai.resolve({"case-ghost"}, rulings(), identities(findings=[
        dict(identities()["findings"][0], case_id="case-ghost")]))
    assert any("no safe-member ruling exists" in p for p in outcome["problems"])


def test_a_member_the_ruling_is_not_for_is_refused():
    """The rulings are prefiltered to `safe`, so nothing contradicted it.

    An entry declaring `member: unsafe` matched and entered the denominator:
    the field was recorded and never read. Codex, 2026-09-04.
    """
    outcome = ai.resolve(ALARMS, rulings(), identities(findings=[
        dict(identities()["findings"][0], member="unsafe")]))
    assert any("names member" in p for p in outcome["problems"])


def test_a_file_the_ruling_does_not_name_is_refused():
    outcome = ai.resolve(ALARMS, rulings(), identities(findings=[
        dict(identities()["findings"][0], file="somewhere/else.py")]))
    assert any("names file" in p for p in outcome["problems"])


def test_a_fingerprint_no_ruling_carries_is_refused():
    outcome = ai.resolve(ALARMS, rulings(), identities(findings=[
        dict(identities()["findings"][0], fingerprint="dddd4444")]))
    assert any("no ruling carries it" in p for p in outcome["problems"])


def test_a_paraphrased_claim_is_refused():
    """A paraphrase is indistinguishable from an invention."""
    outcome = ai.resolve(ALARMS, rulings(), identities(findings=[
        dict(identities()["findings"][0],
             claim="my own summary of what the ruling meant")]))
    assert any("not that field's text" in p for p in outcome["problems"])


def test_a_claim_quoted_from_a_longer_field_is_accepted():
    """Containment, not equality - and not similarity, which would be the
    inference this file refuses."""
    rows = rulings()
    rows[2]["claim"] = "Preamble. something in a file. More afterwards."
    outcome = ai.resolve(ALARMS, rows, identities())
    assert outcome["problems"] == []


def test_a_supersession_link_with_one_ruling_is_refused():
    outcome = ai.resolve(ALARMS, rulings(), identities(findings=[
        dict(identities()["findings"][0], same_finding_as="revision")]))
    assert any("only one" in p for p in outcome["problems"])


@pytest.mark.parametrize("missing", ["decided_by", "decided_on", "rationale"])
def test_a_supersession_link_missing_a_field_is_refused(missing):
    entry = dict(identities()["findings"][0], same_finding_as="revision")
    entry.pop(missing)
    outcome = ai.resolve(ALARMS, rulings(), identities(findings=[entry]))
    assert any("records no {}".format(missing) in p
               for p in outcome["problems"])


def test_a_supersession_value_this_tool_does_not_read_is_refused():
    """`not_same` and `unclear` exist so ambiguity is not forced to collapse."""
    outcome = ai.resolve(ALARMS, rulings(), identities(findings=[
        dict(identities()["findings"][0], same_finding_as="probably")]))
    assert any("this tool reads" in p for p in outcome["problems"])


def test_two_findings_sharing_an_id_are_refused():
    a = identities()["findings"][0]
    b = dict(a, case_id="case-a", file="a.py", claim="a thing")
    outcome = ai.resolve(ALARMS, rulings(), identities(findings=[a, b]))
    assert any("cannot name two findings" in p for p in outcome["problems"])


def test_an_entry_citing_no_evidence_is_refused():
    entry = dict(identities()["findings"][0])
    entry.pop("evidence_refs")
    outcome = ai.resolve(ALARMS, rulings(), identities(findings=[entry]))
    assert any("cites no evidence" in p for p in outcome["problems"])


def test_the_shipped_claims_are_the_rulings_own_words():
    """Not merely non-empty: the text has to be in the field it cites.

    The shipped-file test checked that `identity_basis` and `evidence_refs`
    were present, which a fabricated record would also satisfy.
    """
    body = ai.load_identities(
        ROOT / "measurements" / "alarm-codebook" / "identities.yml")
    _alarming, live = ai.alarms_and_rulings(ROOT / "corpus-real")
    by_case = {}
    for row in live:
        by_case.setdefault(row["case_id"], []).append(row)
    checked = 0
    for entry in body["findings"]:
        basis = entry.get("identity_basis")
        if basis not in ai.IDENTITY_BASES:
            continue
        field = "claim" if basis == "file_and_claim" else "why_malformed"
        sources = [(r.get(field) or "") for r in by_case[entry["case_id"]]]
        assert any(ai._same_text(entry["claim"], s) for s in sources), \
            entry["finding_id"]
        checked += 1
    assert checked == 3, "three legacy identities checked, not {}".format(
        checked)
