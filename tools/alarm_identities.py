#!/usr/bin/env python3
"""Which finding each alarm is about, and whether the denominator is whole.

    tools/alarm_identities.py [--identities FILE] [--corpus DIR] [--json]

D-013 step 4 records a cause for each alarm on the fixed member. A cause needs
the thing it is a cause *of* to have a stable name, and the rulings do not all
carry one: seventeen of twenty-one have a `fingerprint` and four do not. An
empty fingerprint is **absence, not a value**, so `(case_id, member, "")` would
collapse every legacy row into one finding.

So identities are decided in `measurements/alarm-codebook/identities.yml`,
frozen before anything classifies, and this reads them.

**It refuses rather than assumes.** An alarm with no fingerprint and no entry
is `identity_unresolved`: it is still reported, and it leaves the quantitative
denominator. Codex, 2026-09-04 — excluding the fingerprintless rows outright
would bias the denominator toward newer, better-recorded runs, and letting them
in because a row exists would count a name nobody established.

**Supersession is read, never inferred.** Two rulings become one finding only
where the file says so, with who decided and why. Inferring it from similar
claims is a false automatic rule; the assistant's first reading of the one pair
here was wrong, and Codex caught it by opening the rows.

Exit 0 when every alarm has an identity, 2 when any is unresolved or the file
disagrees with the rulings. Never 1: this establishes what things are called,
and "some alarm has no name" is not a finding about the reviewer.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import stop_rule  # noqa: E402
from artifact import load_adjudications  # noqa: E402

SCHEMA = "alarm-finding-identity/1"
IDENTITY_BASES = ("file_and_claim", "file_and_why_malformed")


class IdentityError(Exception):
    """The identities file cannot be used as it stands."""



SUPERSESSION = ("revision", "not_same", "unclear")


def _ruling_misses(entry: Dict[str, Any], row: Dict[str, Any],
                   field: Optional[str]) -> List[str]:
    """Which of the entry's declared fields this **one** ruling does not carry.

    Empty means this row alone backs the whole entry. `field` is the source
    field named by `identity_basis`, or `None` when the entry rests on its
    fingerprint and states no basis.
    """
    misses = []
    if entry.get("member") != row.get("member"):
        misses.append("member")
    if entry.get("file") != row.get("file"):
        misses.append("file")
    if entry.get("fingerprint") and entry["fingerprint"] != row.get(
            "fingerprint"):
        misses.append("fingerprint")
    if field is not None:
        stated = (entry.get("claim") or "").strip()
        if not stated or not _same_text(stated, (row.get(field) or "").strip()):
            misses.append("claim")
    return misses


def _entry_matches_rulings(entry: Dict[str, Any],
                           rows: List[Dict[str, Any]]) -> List[str]:
    """Does this record describe rulings that are actually there?"""
    ident = entry["finding_id"]
    out = []
    if not rows:
        return ["finding {!r} declares an identity for {!r} and no safe-member "
                "ruling exists for it".format(ident, entry.get("case_id"))]

    # A claim taken from `claim` must be in `claim`; one taken from
    # `why_malformed` must be there. The basis says which field, so the field
    # is where it is checked — otherwise `identity_basis` records a provenance
    # nobody verifies.
    basis = entry.get("identity_basis")
    field = None
    if basis in IDENTITY_BASES:
        field = "claim" if basis == "file_and_claim" else "why_malformed"
        if not (entry.get("claim") or "").strip():
            out.append("finding {!r} states no claim to check".format(ident))

    # **One ruling has to carry the whole entry.** Each declared field used to
    # be tested against its own set gathered from every ruling for the case —
    # `members`, `files`, `prints`, `sources` — four existence tests over a
    # union, none of which asked whether the *same* row satisfied the others.
    # An entry could therefore be assembled out of two different rulings and
    # resolve.
    #
    # Measured 2026-09-09 against the shipped file: `rs-8rw6-p7m8-63jp-snap` is
    # the one alarm with two safe rulings, and an entry carrying the 2026-09-02
    # row's fingerprint `06bf0112168101e4` together with the 2026-08-24 row's
    # claim "Computed fields are re-added after permission reduction" produced
    # no problems at all and entered the D-013 denominator, while the same
    # entry with an invented claim was refused. A name assembled from two
    # rulings is a name no ruling gave.
    #
    # `same_finding_as` stays a cross-row check below: a supersession link
    # legitimately spans two rulings. What may not span two is the set of
    # fields backing one name.
    misses = [_ruling_misses(entry, row, field) for row in rows]
    whole = [m for m in misses if not m]
    # `unmet` is what *no* ruling carries, which is exactly the old per-field
    # condition — so every refusal it produced is produced still, in the same
    # words, and the new sentence fires only in the gap the old code left.
    unmet = set() if whole else set.intersection(*(set(m) for m in misses))

    # The rulings handed here are already filtered to the safe member, so an
    # entry declaring `member: unsafe` would never be contradicted by them —
    # the field would be recorded and never read. Codex, 2026-09-04.
    if "member" in unmet:
        members = {r.get("member") for r in rows}
        out.append(
            "finding {!r} names member {!r} and the ruling(s) are for {}".format(
                ident, entry.get("member"),
                ", ".join(repr(m) for m in sorted(members, key=str))))

    if "file" in unmet:
        files = {r.get("file") for r in rows}
        out.append(
            "finding {!r} names file {!r} and the ruling(s) name {}".format(
                ident, entry.get("file"),
                ", ".join(repr(f) for f in sorted(files, key=str))))

    if "fingerprint" in unmet:
        out.append(
            "finding {!r} names fingerprint {!r} and no ruling carries "
            "it".format(ident, entry["fingerprint"]))

    if "claim" in unmet and (entry.get("claim") or "").strip():
        out.append(
            "finding {!r} takes its identity from `{}` and its claim is "
            "not that field's text in any ruling".format(ident, field))

    if not whole and not unmet:
        spread = sorted(set().union(*(set(m) for m in misses)))
        out.append(
            "finding {!r} is assembled from more than one ruling: each of {} "
            "appears somewhere in the {} rulings for {!r}, and no single "
            "ruling carries them together".format(
                ident, ", ".join(spread), len(rows), entry.get("case_id")))

    if entry.get("same_finding_as") and len(rows) < 2:
        out.append(
            "finding {!r} links rulings and {} exists".format(
                ident, "only one" if len(rows) == 1 else "none"))
    if not entry.get("evidence_refs"):
        out.append("finding {!r} cites no evidence".format(ident))
    if not entry.get("decided_by"):
        out.append("finding {!r} names nobody who decided it".format(ident))
    return out


def _same_text(stated: str, source: str) -> bool:
    """Whitespace-folded containment, in either direction.

    Not equality: a record may quote the operative sentence out of a longer
    `why_malformed`, and a YAML folded scalar rewraps lines. Not similarity
    either — that would be the inference this file refuses.
    """
    if not source:
        return False
    a = " ".join(stated.split()).lower()
    b = " ".join(source.split()).lower()
    return a in b or b in a


def alarms_and_rulings(corpus: Path):
    """The alarms on the fixed member and the safe-member rulings for them."""
    rows = stop_rule.latest_rows()
    alarming = {case for case, row in rows.items()
                if row.get("safe_false_positive") is True}
    rulings = [r for r in load_adjudications(corpus)
               if r.get("case_id") in alarming and r.get("member") == "safe"]
    return alarming, rulings


def load_identities(path: Path) -> Dict[str, Any]:
    if not path.is_file():
        raise IdentityError(
            "{} is not a readable file. Identities are decided before "
            "classification, not while reading its answers".format(path))
    try:
        body = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise IdentityError(
            "{} could not be parsed: {}".format(path, exc)) from exc
    if not isinstance(body, dict) or body.get("schema") != SCHEMA:
        raise IdentityError(
            "{} declares schema {!r}; this tool reads {!r}".format(
                path, (body or {}).get("schema"), SCHEMA))
    findings = body.get("findings")
    if not isinstance(findings, list) or not findings:
        raise IdentityError("{} records no findings".format(path))
    return body


def resolve(alarming, rulings, identities: Dict[str, Any]) -> Dict[str, Any]:
    """Every alarm placed against a finding, or reported unresolved."""
    declared = {}
    problems: List[str] = []
    for entry in identities["findings"]:
        if not isinstance(entry, dict):
            problems.append("a findings entry is not a mapping")
            continue
        case = entry.get("case_id")
        ident = entry.get("finding_id")
        if not isinstance(ident, str) or not ident.strip():
            problems.append("an entry for {!r} has no finding_id".format(case))
            continue
        if case in declared:
            problems.append(
                "case {!r} is declared twice; one alarm cannot be two "
                "findings here".format(case))
            continue
        # An entry without a fingerprint must say which field its identity
        # came from, so a later reader can disagree with the weaker basis
        # rather than discover it.
        if not entry.get("fingerprint") and \
                entry.get("identity_basis") not in IDENTITY_BASES:
            problems.append(
                "finding {!r} has no fingerprint and no `identity_basis` from "
                "{} — an identity with no stated ground is an assertion"
                .format(ident, ", ".join(IDENTITY_BASES)))
        if entry.get("same_finding_as"):
            if entry["same_finding_as"] not in SUPERSESSION:
                problems.append(
                    "finding {!r} says `same_finding_as: {!r}`; this tool "
                    "reads {}. `not_same` and `unclear` exist so ambiguity is "
                    "not forced to collapse".format(
                        ident, entry["same_finding_as"],
                        ", ".join(sorted(SUPERSESSION))))
            for field in ("rationale", "decided_by", "decided_on"):
                if not entry.get(field):
                    problems.append(
                        "finding {!r} links rulings and records no {}; "
                        "supersession is read, never inferred".format(
                            ident, field))
        declared[case] = entry

    by_case: Dict[str, List[Dict[str, Any]]] = {}
    for ruling in rulings:
        by_case.setdefault(ruling["case_id"], []).append(ruling)

    # **Every declared entry is checked against the rulings it claims to
    # describe.** Trusting `case_id` alone let a fabricated identity resolve
    # and enter the denominator — the checker could not tell a sound record
    # from an invented one, which is exactly "assuming something about rows it
    # did not read". Codex, 2026-09-04.
    seen_ids = {}
    for case, entry in sorted(declared.items()):
        ident = entry["finding_id"]
        if ident in seen_ids:
            problems.append(
                "finding_id {!r} is used by {!r} and {!r}; it is the "
                "classification key and cannot name two findings".format(
                    ident, seen_ids[ident], case))
        seen_ids[ident] = case
        problems.extend(_entry_matches_rulings(entry, by_case.get(case, [])))

    resolved, unresolved = {}, []
    for case in sorted(alarming):
        rows = by_case.get(case, [])
        entry = declared.get(case)
        if entry is not None:
            resolved[case] = entry["finding_id"]
            continue
        prints = {r.get("fingerprint") for r in rows if r.get("fingerprint")}
        if len(prints) == 1 and len(rows) == 1:
            resolved[case] = "{}|safe|{}".format(case, prints.pop())
            continue
        unresolved.append(case)

    for case in sorted(set(declared) - set(alarming)):
        problems.append(
            "{} declares an identity for {!r}, which is not an alarm on the "
            "fixed member".format("the identities file", case))

    return {"resolved": resolved, "unresolved": unresolved,
            "problems": problems,
            "alarms": len(alarming),
            "denominator": len(alarming) - len(unresolved)}


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--identities", default=str(
        ROOT / "measurements" / "alarm-codebook" / "identities.yml"))
    parser.add_argument("--corpus", default=str(ROOT / "corpus-real"))
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    try:
        identities = load_identities(Path(args.identities))
        alarming, rulings = alarms_and_rulings(Path(args.corpus))
    except (IdentityError, OSError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 2

    outcome = resolve(alarming, rulings, identities)
    declared_denominator = identities.get("denominator")
    if declared_denominator is not None and \
            declared_denominator != outcome["denominator"]:
        outcome["problems"].append(
            "the file declares a denominator of {} and {} alarm(s) resolve; a "
            "number stated rather than counted is the defect this project is "
            "about".format(declared_denominator, outcome["denominator"]))

    if args.json:
        print(json.dumps(outcome, indent=2, sort_keys=True))
    else:
        print("{} alarm(s) on the fixed member".format(outcome["alarms"]))
        print("  identified : {}".format(len(outcome["resolved"])))
        print("  unresolved : {}{}".format(
            len(outcome["unresolved"]),
            " — " + ", ".join(outcome["unresolved"])
            if outcome["unresolved"] else ""))
        print("  denominator: {}".format(outcome["denominator"]))
        for line in outcome["problems"]:
            print("  " + line, file=sys.stderr)

    return 2 if outcome["problems"] or outcome["unresolved"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
