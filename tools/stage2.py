#!/usr/bin/env python3
"""Where stage 2 actually stands, read from the repository.

A plan with tick-boxes is a plan that records opinion. This reads the state
instead: does the symbol exist, does the test pass, what does the journal say.
The rule it follows is the project's own — a number comes from an artifact or a
run, never from judgement — and it applies to progress as much as to coverage.

    tools/stage2.py            # everything cheap: symbols, files, journal
    tools/stage2.py --tests    # also run the targeted tests (slower, truthful)
    tools/stage2.py --full     # also run the whole suite

Four states, and the distinction between the middle two is the point:

    done        the check passed
    partial     it exists and is incomplete — a number short of its target
    todo        it has not been started
    broken      it exists and fails, which is worse than not existing

`todo` and `broken` are never merged. A runner whose conformance test errors is
not "not done yet"; it is a runner that fails a test it is expected to pass.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, List, Optional, Tuple

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src" / "security_agent"
TESTS = ROOT / "tests"

DONE, PARTIAL, TODO, BROKEN = "done", "partial", "todo", "broken"

# The fields that must never appear inside `canonical_result`. Provider
# telemetry is legitimately allowed to differ between runners; a comparison
# that includes it compares the provider rather than the decision.
TELEMETRY_FIELDS = (
    "provider", "session_id", "duration_ms", "input_tokens", "output_tokens",
    "cost_usd", "num_turns", "cache_read_input_tokens", "served_model",
)

# Stage 2, point 5. Named here so the count is not a guess: a scenario is
# covered when a test mentions its marker.
CONFORMANCE_SCENARIOS = {
    "terminal_success": "normal success",
    "malformed_json": "malformed terminal JSON",
    "missing_result": "missing terminal result",
    "unknown_status": "unknown status",
    "auth_failure": "auth / rate limit / quota",
    "killed_thinking": "wall-clock kill during model work",
    "killed_in_tool": "wall-clock kill during a tool",
    "tool_budget": "tool call budget exhausted",
    "verifier_budget": "verifier reservation exhausted",
    "forbidden_tool": "forbidden tool requested",
    "partial_finding": "partial finding then termination",
    "invalid_finding": "clean end, invalid finding data",
    "no_artifact": "process killed without an artifact",
}


@dataclass
class Result:
    state: str
    detail: str


@dataclass
class Check:
    number: str
    name: str
    target: str
    probe: Callable[[argparse.Namespace], Result]


# ------------------------------------------------------------------ helpers


def _source(name: str) -> str:
    path = SRC / name
    return path.read_text(encoding="utf-8") if path.exists() else ""


def _tests_mentioning(*needles: str) -> List[Path]:
    """Test files containing every needle. Cheap, and honest about what it is:
    evidence that a subject is written about, not that it is covered."""
    hits = []
    for path in sorted(TESTS.glob("test_*.py")):
        text = path.read_text(encoding="utf-8")
        if all(needle in text for needle in needles):
            hits.append(path)
    return hits


def _pytest(paths: List[Path], run: bool) -> Optional[Tuple[bool, str]]:
    """(passed, summary), or None when the caller asked not to spend the time."""
    if not run or not paths:
        return None
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", *[str(p) for p in paths]],
        cwd=ROOT, capture_output=True, text=True, check=False)
    tail = [line for line in proc.stdout.strip().splitlines() if line.strip()]
    return proc.returncode == 0, tail[-1] if tail else "no output"


def _from_tests(names: List[Path], run: bool, subject: str) -> Result:
    if not names:
        return Result(TODO, "no test mentions {}".format(subject))
    verdict = _pytest(names, run)
    if verdict is None:
        return Result(PARTIAL, "{} test file(s), not run — pass --tests".format(
            len(names)))
    passed, summary = verdict
    return Result(DONE if passed else BROKEN, summary)


def _journal() -> dict:
    """Reviews filed and findings still unjudged, straight from the journal."""
    root = ROOT / "journal"
    if not root.exists():
        return {"reviews": 0, "unadjudicated": 0, "findings": 0, "resolved": 0}
    reviews = unadjudicated = findings = resolved = 0
    for verdict_file in sorted(root.glob("*/verdicts.yml")):
        reviews += 1
        try:
            import yaml
            data = yaml.safe_load(verdict_file.read_text(encoding="utf-8")) or {}
        except Exception:
            continue
        for entry in (data.get("findings") or []):
            findings += 1
            verdict = str(entry.get("verdict", "unadjudicated"))
            if verdict == "unadjudicated":
                unadjudicated += 1
            elif entry.get("resolution"):
                resolved += 1
    return {"reviews": reviews, "unadjudicated": unadjudicated,
            "findings": findings, "resolved": resolved}


# ------------------------------------------------------------------- probes


def probe_budget(args) -> Result:
    if not (SRC / "budget.py").exists():
        return Result(TODO, "budget.py does not exist")
    path = TESTS / "test_budget.py"
    if not path.exists():
        return Result(PARTIAL, "budget.py written, no test file")
    return _from_tests([path], args.tests, "the budget")


def probe_canonical(args) -> Result:
    text = _source("models.py") + _source("identity.py") + _source("report.py")
    if "canonical_result" not in text:
        return Result(TODO, "no canonical_result anywhere")
    # The split only means something if telemetry stayed out of it. Read the
    # canonical section and look for fields that are allowed to differ.
    leaked = []
    for match in re.finditer(r"canonical_result[^\n]*\n((?:[ \t]+[^\n]*\n)+)", text):
        block = match.group(1)
        leaked += [f for f in TELEMETRY_FIELDS if f in block]
    if leaked:
        return Result(BROKEN, "telemetry inside canonical_result: {}".format(
            ", ".join(sorted(set(leaked)))))
    return Result(DONE, "canonical_result present, no telemetry fields in it")


def probe_runner(args) -> Result:
    text = _source("runner_claude_code.py") or _source("runners.py")
    if "ClaudeCodeRunner" not in text:
        return Result(TODO, "ClaudeCodeRunner does not exist")
    missing = [flag for flag in ("--strict-mcp-config", "--output-format")
               if flag not in text]
    if missing:
        return Result(PARTIAL, "runner exists, missing {}".format(
            ", ".join(missing)))
    return _from_tests(_tests_mentioning("ClaudeCodeRunner"), args.tests,
                       "ClaudeCodeRunner")


def probe_confinement(args) -> Result:
    """Two guarantees, counted separately: ambient config cannot reach the
    model, and a denied tool is denied rather than merely unlisted."""
    ambient = _tests_mentioning("CLAUDE.md", "ClaudeCodeRunner")
    denied = _tests_mentioning("disallowedTools") or _tests_mentioning(
        "Bash", "ClaudeCodeRunner")
    have = sum(1 for group in (ambient, denied) if group)
    if have == 0:
        return Result(TODO, "0/2 — neither ambient config nor tool denial")
    if have == 1:
        return Result(PARTIAL, "1/2 — {} covered".format(
            "ambient config" if ambient else "tool denial"))
    return _from_tests(sorted(set(ambient + denied)), args.tests, "confinement")


def probe_conformance(args) -> Result:
    files = _tests_mentioning("conformance") or list(
        TESTS.glob("test_runner_conformance.py"))
    if not files:
        return Result(TODO, "0/13 — no conformance test")
    text = "".join(p.read_text(encoding="utf-8") for p in files)
    covered = [k for k in CONFORMANCE_SCENARIOS if k in text]
    if len(covered) < len(CONFORMANCE_SCENARIOS):
        absent = [CONFORMANCE_SCENARIOS[k] for k in CONFORMANCE_SCENARIOS
                  if k not in covered]
        return Result(PARTIAL, "{}/13 — missing: {}".format(
            len(covered), "; ".join(absent[:3]) + ("…" if len(absent) > 3 else "")))
    verdict = _pytest(files, args.tests)
    if verdict is None:
        return Result(PARTIAL, "13/13 named, not run — pass --tests")
    passed, summary = verdict
    return Result(DONE if passed else BROKEN, "13/13 named — {}".format(summary))


def probe_no_fallback(args) -> Result:
    text = _source("cli.py") + _source("config.py") + _source("runners.py")
    if "claude-cli" not in text:
        return Result(TODO, "no --provider selection")
    if "auto" in re.findall(r'"(auto)"', text):
        return Result(BROKEN, "an `auto` provider exists — money decided for "
                              "the operator")
    return _from_tests(_tests_mentioning("fallback"), args.tests,
                       "the no-fallback rule")


def probe_scope(args) -> Result:
    text = _source("cli.py") + (ROOT / "tools" / "review.sh").read_text(
        encoding="utf-8")
    present = [flag for flag in ("--changed-only", "--file", "--path")
               if flag in text]
    if not present:
        return Result(TODO, "no scope control")
    if len(present) < 3:
        return Result(PARTIAL, "{}/3 — have {}".format(
            len(present), ", ".join(present)))
    return Result(DONE, "3/3 — timing comes from a real run, see the journal")


def probe_use(args) -> Result:
    j = _journal()
    if j["reviews"] == 0:
        return Result(TODO, "0/20 reviews filed")
    if j["reviews"] < 20 or j["unadjudicated"]:
        return Result(PARTIAL, "{}/20 reviews, {} finding(s) unjudged".format(
            j["reviews"], j["unadjudicated"]))
    return Result(DONE, "{} reviews, every finding judged".format(j["reviews"]))


def probe_fixes(args) -> Result:
    j = _journal()
    confirmed = j["findings"] - j["unadjudicated"]
    if j["reviews"] == 0:
        return Result(TODO, "nothing to reconcile yet")
    if confirmed == 0:
        return Result(PARTIAL, "no judged findings yet")
    limitations = (ROOT / "LIMITATIONS.md").read_text(encoding="utf-8")
    recorded = limitations.count("journal/")
    if j["resolved"] + recorded < confirmed:
        return Result(PARTIAL, "{} judged, {} resolved + {} in LIMITATIONS".format(
            confirmed, j["resolved"], recorded))
    return Result(DONE, "{} judged, all accounted for".format(confirmed))


def probe_suite(args) -> Result:
    if not args.full:
        return Result(PARTIAL, "not run — pass --full")
    proc = subprocess.run([sys.executable, "-m", "pytest", "-q"],
                          cwd=ROOT, capture_output=True, text=True, check=False)
    tail = [ln for ln in proc.stdout.strip().splitlines() if ln.strip()]
    return Result(DONE if proc.returncode == 0 else BROKEN,
                  tail[-1] if tail else "no output")


def probe_spend(args) -> Result:
    """Local runs must cost nothing. Read it from the artifacts, not from the
    intent — a runner that silently fell back to the API would still intend to
    be free."""
    root = ROOT / "journal"
    if not root.exists():
        return Result(TODO, "no runs filed")
    charged = []
    for artifact in sorted(root.glob("*/findings.json")):
        try:
            data = json.loads(artifact.read_text(encoding="utf-8"))
        except Exception:
            continue
        telemetry = data.get("provider_telemetry") or data.get("run") or {}
        if telemetry.get("provider") == "claude-cli" and telemetry.get("cost_usd"):
            charged.append(artifact.parent.name)
    if charged:
        return Result(BROKEN, "{} local run(s) were billed: {}".format(
            len(charged), ", ".join(charged[:3])))
    return Result(DONE, "no billed local run in {} artifact(s)".format(
        len(list(root.glob("*/findings.json")))))


CHECKS = [
    Check("1", "budget", "tests green", probe_budget),
    Check("2", "canonical split", "0 telemetry fields", probe_canonical),
    Check("3", "ClaudeCodeRunner", "matches on a fixed diff", probe_runner),
    Check("4", "tool confinement", "2/2", probe_confinement),
    Check("5", "conformance", "13/13", probe_conformance),
    Check("6", "no silent fallback", "exit 2, 0 API calls", probe_no_fallback),
    Check("7", "scope control", "3 flags, < 5 min", probe_scope),
    Check("8", "real use", "20 reviews, 0 unjudged", probe_use),
    Check("9", "fixes", "judged = fixed + recorded", probe_fixes),
    Check("—", "whole suite", "green", probe_suite),
    Check("—", "local spend", "$0.00", probe_spend),
]

_MARK = {DONE: "done   ", PARTIAL: "partial", TODO: "todo   ", BROKEN: "BROKEN "}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--tests", action="store_true",
                        help="run the targeted tests rather than reporting "
                             "them as unrun")
    parser.add_argument("--full", action="store_true",
                        help="also run the whole suite")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    if args.full:
        args.tests = True

    rows = []
    for check in CHECKS:
        try:
            result = check.probe(args)
        except Exception as exc:  # a probe that breaks must not read as done
            result = Result(BROKEN, "probe failed: {}".format(exc))
        rows.append((check, result))

    if args.json:
        print(json.dumps([{"number": c.number, "name": c.name,
                           "target": c.target, "state": r.state,
                           "detail": r.detail} for c, r in rows], indent=2))
        return 0

    width = max(len(c.name) for c, _ in rows)
    print("Stage 2 — the agent reviews its own repository\n")
    for check, result in rows:
        print("  {:>2}  {}  {:<{w}}  {}".format(
            check.number, _MARK[result.state], check.name, result.detail,
            w=width))

    states = [r.state for _, r in rows]
    done = states.count(DONE)
    print("\n  {} of {} at target".format(done, len(rows)))
    if BROKEN in states:
        print("  {} broken — these fail a check they are expected to "
              "pass".format(states.count(BROKEN)))
    if not args.tests:
        print("  tests not run; --tests measures instead of reporting unrun")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
