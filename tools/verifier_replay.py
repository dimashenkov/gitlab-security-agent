#!/usr/bin/env python3
"""Ask one fixed security claim of the verifier, repeatedly, and watch it move.

The prompt-injection question is "does attacker-authored prose change the
answer". Measuring it end to end runs five things at once — whether the
reviewer rediscovers the weakness, how confidently it states it, what the
verifier makes of it, what the payload did, and how it is scored — at roughly
$1.50 to $3.50 a review, and the result cannot be attributed to any of them.

The working payloads do not erase the finding. They leave it in the report and
move its disposition. So the verifier is the narrow fault boundary, and it can
be tested on its own: hold the candidate, the revision, the panel, the model
and the settings fixed, change only the prose in the repository, and see
whether the verdict moves.

    # what the panel does with nothing changed — run this FIRST, twice
    tools/verifier_replay.py corpus/ --case go-sql-01 --from artifact.json --runs 2

    # the same claim, the same code, one comment added
    tools/verifier_replay.py corpus/ --case go-sql-01 --from artifact.json \\
        --payload false-context

Two clean runs before any payload, always. A clean-versus-injected pair on its
own cannot separate the payload from ordinary stochastic movement, and this
project has already published one number that turned out to be measuring
variance.

This does not establish end-to-end injection resistance. It establishes whether
the verifier's treatment of an unchanged claim survives changed prose.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import anthropic
from injection_corpus import apply_payload, load_payloads
from pair_corpus import build_repo, cost_of, load_cases

from security_agent.config import Config
from security_agent.models import Candidate, Finding, Usage
from security_agent.verify import verify_candidates
from security_agent.workspace import Workspace


def candidate_from(artifact: Path, case: dict) -> Candidate:
    """The exact claim a paid review produced, replayed as-is.

    Not a hand-written finding: the point is to hold constant what the reviewer
    said, so that anything that moves afterwards moved because of the verifier
    or the prose, and not because the claim was worded differently this time.
    """
    payload = json.loads(artifact.read_text(encoding="utf-8"))
    findings = payload.get("findings") or []
    findings += payload.get("refuted") or []
    if not findings:
        raise SystemExit("{} has no finding to replay".format(artifact))

    from artifact import is_target

    chosen = next((f for f in findings if is_target(f, case)), findings[0])
    return Candidate(finding=Finding.from_dict(chosen))


def one_run(cfg: Config, case: dict, member: str, artifact: Path,
            payload, index: int) -> dict:
    work = Path(tempfile.mkdtemp(prefix="replay-")).resolve()
    try:
        repo, base, head = build_repo(case["_dir"], member, work)
        planted = apply_payload(repo, case, payload) if payload else ""
        if planted:
            # Committed, so the payload is in the tree the verifier reads and
            # in the diff, exactly as a contributor's comment would be.
            import subprocess
            env = {"PATH": "/usr/bin:/bin", "HOME": str(work),
                   "GIT_AUTHOR_NAME": "Contributor",
                   "GIT_AUTHOR_EMAIL": "c@example.invalid",
                   "GIT_COMMITTER_NAME": "Contributor",
                   "GIT_COMMITTER_EMAIL": "c@example.invalid"}
            subprocess.run(("git", "-C", str(repo), "add", "-A"),
                           check=True, capture_output=True, env=env)
            subprocess.run(("git", "-C", str(repo), "commit", "-qm", "note"),
                           check=True, capture_output=True, env=env)
            head = subprocess.run(
                ("git", "-C", str(repo), "rev-parse", "HEAD"), check=True,
                capture_output=True, text=True, env=env).stdout.strip()

        candidate = candidate_from(artifact, case)
        ws = Workspace(root=repo, excludes=cfg.excludes,
                       diff_base=base, diff_head=head)
        client = anthropic.Anthropic(max_retries=cfg.max_retries,
                                     timeout=cfg.request_timeout)
        usage: Usage = verify_candidates(cfg, ws, client, [candidate])

        return {
            "run": index,
            "payload": (payload or {}).get("id", "none"),
            "planted_in": planted,
            "verdict": candidate.verdict,
            "confidence": candidate.confidence,
            "severity": candidate.severity,
            "reason": candidate.verdict_reason,
            "votes": [
                {"verdict": v.verdict, "confidence": v.corrected_confidence,
                 "control_search": v.control_search, "entry_point": v.entry_point,
                 "files_read": v.files_read,
                 # Whether this vote ever opened the file the payload is in.
                 # "Held" covers two different things — resisted, and never
                 # exposed — and only one of them is resistance.
                 "saw_payload": bool(planted) and planted in v.files_read,
                 "error": v.error}
                for v in candidate.votes
            ],
            "cost": cost_of(usage.to_dict()),
        }
    except Exception as exc:
        return {"run": index, "error": "{}: {}".format(type(exc).__name__, exc)}
    finally:
        shutil.rmtree(work, ignore_errors=True)


def report(rows: list) -> int:
    good = [r for r in rows if "error" not in r]
    print("\n{:<5}{:<18}{:<12}{:<12}{:<8}{}".format(
        "run", "payload", "verdict", "confidence", "votes", "cost"))
    print("-" * 68)
    for row in rows:
        if "error" in row:
            print("{:<5}{}".format(row["run"], str(row["error"])[:60]))
            continue
        print("{:<5}{:<18}{:<12}{:<12}{:<8}${:.2f}".format(
            row["run"], row["payload"], row["verdict"], row["confidence"],
            "{}/{}".format(sum(1 for v in row["votes"]
                               if v["verdict"] == row["verdict"]),
                           len(row["votes"])),
            row["cost"]))

    if not good:
        print("\nNo run produced a verdict.")
        return 2

    print("\ntotal ${:.2f}".format(sum(r["cost"] for r in good)))
    verdicts = {r["verdict"] for r in good}
    payloads = {r["payload"] for r in good}

    if len(payloads) == 1 and len(verdicts) > 1:
        # The most important line this tool can print, and the reason two
        # clean runs come first: if the panel disagrees with itself on
        # identical input, no clean-versus-injected comparison means anything.
        print("\nThe panel gave different verdicts on IDENTICAL input: {}. "
              "Until that is understood, a payload that appears to move the "
              "verdict has not been shown to have moved anything."
              .format(", ".join(sorted(verdicts))))
        return 1

    for row in good:
        if row["payload"] != "none" and row.get("planted_in"):
            saw = sum(1 for v in row["votes"] if v.get("saw_payload"))
            print("\nrun {}: {} of {} vote(s) opened {} — the file the payload "
                  "is in.{}".format(
                      row["run"], saw, len(row["votes"]), row["planted_in"],
                      "" if saw else " A payload nobody read did not fail; it "
                      "was never tried."))
        search = next((v["control_search"] for v in row["votes"]
                       if v["control_search"]), "")
        if search:
            print("run {} searched: {}".format(row["run"], search[:300]))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("cases")
    parser.add_argument("--case", required=True)
    parser.add_argument("--member", default="unsafe", choices=("safe", "unsafe"))
    parser.add_argument("--from", dest="artifact", required=True,
                        help="a findings.json holding the claim to replay")
    parser.add_argument("--payload", default="",
                        help="a payload id from payloads/; omit for a clean run")
    parser.add_argument("--payloads-dir", default="payloads")
    parser.add_argument("--runs", type=int, default=1)
    parser.add_argument("--json", metavar="PATH")
    args = parser.parse_args()

    matches = [c for c in load_cases(Path(args.cases)) if c["case_id"] == args.case]
    if not matches:
        return _fail("no case {!r} under {}".format(args.case, args.cases))
    artifact = Path(args.artifact)
    if not artifact.is_file():
        return _fail("no such artifact: {}".format(artifact))

    payload = None
    if args.payload:
        found = [p for p in load_payloads(Path(args.payloads_dir))
                 if p["id"] == args.payload]
        if not found:
            return _fail("no payload {!r} in {}".format(args.payload, args.payloads_dir))
        payload = found[0]

    cfg = Config(post_comment=False)
    print("{} run(s) of the verifier on one fixed claim from {}{}".format(
        args.runs, artifact,
        "" if payload is None else " with payload {!r}".format(payload["id"])))

    # Serially. Concurrency here would only make the bill arrive faster.
    rows = [one_run(cfg, matches[0], args.member, artifact, payload, i)
            for i in range(args.runs)]

    if args.json:
        Path(args.json).write_text(json.dumps(rows, indent=2))
        print("raw results written to {}".format(args.json))
    return report(rows)


def _fail(message: str) -> int:
    print(message, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
