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
from typing import Callable, Dict, List, Optional, Tuple

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))

from artifact import case_digest, malformed_cases

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src" / "security_agent"
TESTS = ROOT / "tests"

DONE, PARTIAL, TODO, BROKEN = "done", "partial", "todo", "broken"

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
    """The split is only worth anything if it is exercised against a real
    artifact, so this runs the test rather than reading the source. A partition
    that agrees with a hand-written dict proves nothing about the JSON a runner
    actually writes."""
    text = _source("canonical.py")
    if "TELEMETRY_PATHS" not in text or "def split" not in text:
        return Result(TODO, "no canonical/telemetry split")
    declared = len(re.findall(r'^\s+"[a-z_.\[\]]+",\s*$', text, re.M))
    path = TESTS / "test_canonical.py"
    if not path.exists():
        return Result(PARTIAL, "{} paths declared, no test".format(declared))
    result = _from_tests([path], args.tests, "the canonical split")
    if result.state == DONE:
        result.detail = "{} telemetry paths — {}".format(declared, result.detail)
    return result


def _protocol(args, tool: str, prompt: str, test: str, subject: str) -> Result:
    """A completion protocol is three things, and any one alone is decoration.

    The tool must exist, the prompt must ask for it — severity was once derived
    from an `impact` value the prompt never mentioned, and a tool the model is
    not told to use is a tool it will not use — and the loop must act on it.
    """
    if tool not in _source("tools.py"):
        return Result(TODO, "no {}".format(tool))
    if tool not in (ROOT / "prompts" / prompt).read_text(encoding="utf-8"):
        return Result(PARTIAL, "{} exists, {} never asks for it".format(
            tool, prompt))
    path = TESTS / test
    if not path.exists():
        return Result(PARTIAL, "{} exists and is untested".format(tool))
    return _from_tests([path], args.tests, subject)


def probe_finish_review(args) -> Result:
    return _protocol(args, "finish_review", "system.md",
                     "test_finish_review.py", "the review's sign-off")


def probe_submit_verdict(args) -> Result:
    return _protocol(args, "submit_verdict", "verifier.md",
                     "test_submit_verdict.py", "the verifier's vote")


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
    """Named file only, never a grep for the word.

    The first version searched every test for "conformance" and reported 0/13
    as `partial` the moment an unrelated file mentioned it in a docstring — a
    tracker inventing progress that does not exist, which is the failure this
    whole project is about. A probe that can be satisfied by prose is not a
    measurement."""
    path = TESTS / "test_runner_conformance.py"
    files = [path] if path.exists() else []
    if not files:
        return Result(TODO, "0/13 — no test_runner_conformance.py")
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
    """Asked of the list itself, not of the source text.

    The first version searched three files for the string `"auto"` and reported
    the rule broken because `mode` has been `auto | diff | repo` since long
    before providers existed. Same root cause as the conformance probe's false
    pass, in the other direction: a check satisfied by a string rather than by
    the thing. A tracker that invents a defect teaches its reader to skip the
    line, which costs exactly as much as one that hides a defect.
    """
    import importlib
    import sys

    sys.path.insert(0, str(ROOT / "src"))
    try:
        providers = importlib.import_module("security_agent.config").PROVIDERS
    except (ImportError, AttributeError):
        return Result(TODO, "no --provider selection")

    if "claude-cli" not in providers:
        return Result(TODO, "no --provider selection")
    if "auto" in providers:
        return Result(BROKEN, "an `auto` provider exists — money decided for "
                              "the operator")
    # Both needles, for the reason in `probe_conformance`: "fallback" alone
    # matches any test that uses the word in passing.
    return _from_tests(_tests_mentioning("fallback", "claude-cli"), args.tests,
                       "the no-fallback rule")


def probe_scope(args) -> Result:
    text = _source("cli.py") + (ROOT / "tools" / "review.sh").read_text(
        encoding="utf-8")
    # Two flags, not the three the plan first named. `--path` takes an exact
    # path as readily as a glob, so a separate `--file` would have been a
    # second spelling of one idea. Adding a flag to satisfy a checklist is how
    # a measure stops measuring.
    present = [flag for flag in ("--changed-only", "--path") if flag in text]
    if not present:
        return Result(TODO, "no scope control")
    if len(present) < 2:
        return Result(PARTIAL, "1/2 — have {}".format(present[0]))
    path = TESTS / "test_scope.py"
    if not path.exists():
        return Result(PARTIAL, "2/2 flags, no test")
    return _from_tests([path], args.tests, "scope control")


def probe_use(args) -> Result:
    """Both members of every corpus pair run, and the decision preserved.

    This counted reviews of this repository's own changes until 2026-08-27,
    when the point stopped being about own code — the question it answered was
    "was this useful to you", and only the author of the code can answer it.
    The tracker kept counting the old thing for a day after the plan changed,
    which is a tracker reporting on work nobody is doing.

    Read from the batch results rather than from a journal, because the batch
    is what the plan says is done when: every pair through `--provider
    claude-cli`, results in `measurements/`, unsafe blocked and safe quiet.
    """
    # The two constructions are never scored together — in a regression pair
    # every unsafe member deletes something, so direction alone predicts the
    # answer and a removed-control rule scores well without recognising
    # anything. Counting all 47 as one number would hide that. The plan's
    # target is the 24 regression cases; the snapshot set is reported beside
    # it, not folded into it.
    # A case a hand decision has ruled unable to measure anything is not a case
    # this tracker is waiting on. `pair_corpus.py` excludes them and says so on
    # stderr; the tracker read the corpus directly and did not, so it reported
    # six pairs run where the scorer had already excluded two of them.
    excluded = malformed_cases(ROOT / "corpus-real")
    cases, snapshots = [], 0
    for path in sorted((ROOT / "corpus-real").iterdir()):
        case = path / "case.yml" if path.is_dir() else None
        if case is None or not case.exists() or path.name in excluded:
            continue
        body = yaml.safe_load(case.read_text(encoding="utf-8")) or {}
        if body.get("construction") == "regression":
            cases.append(path.name)
        else:
            snapshots += 1
    if not cases:
        return Result(TODO, "no corpus")

    # Every verdict any file holds for a case, rather than one file's.
    #
    # There is no order to take the latest by. Filename order is not run order
    # — `first-cli-pair.json` is the oldest run in `measurements/` and sorts
    # after both batches — and modification time is not a record of anything:
    # a clone, an unpacked archive or a `touch` rewrites it, so the answer
    # could change without a byte of the repository changing.
    #
    # So it does not guess. Files that agree give the answer; files that
    # disagree make the case unresolved and say so, which is this project's
    # own rule that being unable to tell is a third answer and not a verdict.
    # No two files disagree today; this is what happens when they do.
    #
    # A verdict counts only when the row says which version of the case it is
    # about and that version is the current one. One case had its weakness
    # deleted by a bug and then repaired, so a recorded failure for it was a
    # failure at reviewing code that no longer exists — and nothing in a batch
    # said so. Rows written before `case_digest` existed are neither counted
    # nor thrown away silently: they are reported as what they are, results
    # about a version nobody recorded.
    current = {name: case_digest(ROOT / "corpus-real" / name) for name in cases}
    verdicts: Dict[str, set] = {}
    undated: Dict[str, int] = {}
    for path in sorted((ROOT / "measurements").glob("*.json")):
        try:
            body = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError, ValueError):
            continue
        if isinstance(body, list):
            rows = body
        elif isinstance(body, dict):
            rows = body.get("results") or []
        else:
            continue                       # a scalar is not a batch result
        if not isinstance(rows, list):
            continue
        for row in rows:
            if not isinstance(row, dict):
                continue
            case_id = row.get("case_id")
            if not isinstance(case_id, str) or not case_id:
                continue
            if row.get("incomplete"):
                # A run that did not finish is not a result. Recording it as a
                # failure is the confusion this whole project is built to
                # avoid, and it would also make a case that later passes look
                # like a disagreement.
                continue
            digest = row.get("case_digest")
            if digest != current.get(case_id):
                # Either the case has changed since, or the run predates any
                # record of which version it saw. Both mean the same thing for
                # this count and neither is a verdict about the case as it
                # stands, but the second is worth naming rather than dropping.
                if not digest:
                    undated[case_id] = undated.get(case_id, 0) + 1
                continue
            # `is True`, not `bool(...)`. A pair passed when the scorer said
            # so, and `bool("false")` is true — a tracker that reads the string
            # "false" as a pass can be told the work is done by a typo.
            verdicts.setdefault(case_id, set()).add(
                row.get("pair_success") is True)

    run = [c for c in cases if c in verdicts]
    split = [c for c in run if len(verdicts[c]) > 1]
    passing = [c for c in run if verdicts[c] == {True}]
    stale = sorted(set(undated) - set(verdicts))
    beside = " (+{} snapshot)".format(snapshots) if snapshots else ""
    if stale:
        beside = ", {} from an unrecorded corpus version{}".format(
            len(stale), beside)
    if split:
        beside = ", {} unresolved: {}{}".format(
            len(split), ", ".join(sorted(split)[:2]), beside)
    if not run:
        return Result(TODO, "0/{} regression pairs run{}".format(
            len(cases), beside))
    if len(run) < len(cases) or len(passing) < len(run):
        return Result(PARTIAL, "{}/{} run, {} preserved{}".format(
            len(run), len(cases), len(passing), beside))
    return Result(DONE, "{}/{} pairs, decision preserved{}".format(
        len(passing), len(cases), beside))


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
    """How local runs were billed, read from the artifacts rather than assumed.

    Not "local runs cost nothing", which is what this claimed and could not
    show. It read `provider_telemetry` or `run`, containers no artifact has
    ever had, so every file was skipped and a clean sheet was reported over a
    corpus it had not read a byte of — and it tested `cost_usd` for truthiness,
    so an absent figure passed as a zero, which is this project's own
    absent-versus-zero rule broken inside the tool that checks it.

    Now: a billed local run is BROKEN, a run whose login the CLI reported as a
    subscription is what DONE means, and a run that reported neither a cost nor
    an auth method is named rather than counted either way."""
    root = ROOT / "journal"
    if not root.exists():
        return Result(TODO, "no runs filed")
    charged, silent, subscription = [], [], []
    for artifact in sorted(root.glob("*/findings.json")):
        try:
            data = json.loads(artifact.read_text(encoding="utf-8"))
        except Exception:
            continue
        # From `provenance`, which is where the artifact keeps this. It used to
        # read `provider_telemetry` or `run`, and no artifact has ever had
        # either — so every file was skipped and the probe reported a clean
        # sheet over a corpus it had not read one byte of. The container was
        # named before the field existed and nothing ever connected the two.
        prov = data.get("provenance") or {}
        if prov.get("provider") != "claude-cli":
            continue
        name = artifact.parent.name
        # Decided by the login, never by the figure. The CLI reports
        # `total_cost_usd` on a subscription too — a two-token reply on a Max
        # plan came back as $0.29 — so it is what the run *would* have cost,
        # and a probe reading it as a bill would call every subscription run
        # billed. The figure is recorded beside the verdict, not used as one.
        if prov.get("auth_method") and prov.get("auth_method") != "claude.ai":
            charged.append("{} ({})".format(name, prov["auth_method"]))
            continue
        if prov.get("auth_method") == "claude.ai" and prov.get("auth_subscription"):
            subscription.append(name)
        else:
            # No auth method recorded: a run from before the CLI was asked, or
            # one where it would not say. Named rather than counted either way
            # — the old version read a missing cost as a zero and called that
            # proof, which is this project's own absent-versus-zero rule broken
            # inside the tool that checks it.
            silent.append(name)

    if charged:
        return Result(BROKEN, "{} local run(s) were billed: {}".format(
            len(charged), ", ".join(charged[:3])))
    if not (subscription or silent):
        return Result(TODO, "no local run to read")
    if silent:
        return Result(PARTIAL, "{} run(s) on an established subscription, "
                               "{} that recorded no auth method".format(
                                   len(subscription), len(silent)))
    return Result(DONE, "{} local run(s), each on an established "
                        "subscription".format(len(subscription)))


CHECKS = [
    Check("1", "budget", "tests green", probe_budget),
    Check("2", "canonical split", "no telemetry compared", probe_canonical),
    Check("3a", "finish_review", "tool, prompt, loop", probe_finish_review),
    Check("3b", "submit_verdict", "tool, prompt, loop", probe_submit_verdict),
    Check("3", "ClaudeCodeRunner", "matches on a fixed diff", probe_runner),
    Check("4", "tool confinement", "2/2", probe_confinement),
    Check("5", "conformance", "13/13", probe_conformance),
    Check("6", "no silent fallback", "exit 2, 0 API calls", probe_no_fallback),
    Check("7", "scope control", "2 flags, tested", probe_scope),
    Check("8", "advisory pairs", "24 pairs, decision preserved", probe_use),
    Check("9", "fixes", "judged = fixed + recorded", probe_fixes),
    Check("—", "whole suite", "green", probe_suite),
    Check("—", "local billing", "established, not assumed", probe_spend),
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
    # Not "reviews its own repository" any more. Point 8 stopped being about
    # own code on 2026-08-27: the question it answered was "was this useful to
    # you", and only the author of the code can answer that.
    print("Stage 2 — the agent qualified against known advisories\n")
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
