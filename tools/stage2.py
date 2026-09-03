#!/usr/bin/env python3
"""Where stage 2 actually stands, read from the repository.

A plan with tick-boxes is a plan that records opinion. This reads the state
instead: does the symbol exist, does the test pass, what did the runs find.
The rule it follows is the project's own — a number comes from an artifact or a
run, never from judgement — and it applies to progress as much as to coverage.

    tools/stage2.py            # everything cheap: symbols, files, results
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
import ast
import json
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple
from xml.etree import ElementTree

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))

from artifact import (
    case_digest,
    instant,
    is_target,
    legacy_case_digest,
    load_adjudications,
    malformed_cases,
    ruled_incidental,
)

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


_PASSED_COUNT = re.compile(r"(\d+) passed")


def _pytest(paths: List[Path], run: bool) -> Optional[Tuple[bool, str]]:
    """(passed, summary), or None when the caller asked not to spend the time.

    A green exit code is not the same as a test having run. `pytest` exits 0
    when every test in a file is skipped — a `skipif` on a missing binary, an
    xfail marker left behind after a rewrite — and this reported `done` with
    the detail "13 skipped in 0.01s". The tracker's whole job is to say what is
    covered, so an all-skipped file being counted as covered is the failure it
    exists to catch, arriving from inside.

    So: the exit code *and* at least one test that actually passed. A run that
    collected nothing already exited 5; a run that skipped everything exits 0
    and is now caught by the count.
    """
    if not run or not paths:
        return None
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", *[str(p) for p in paths]],
        cwd=ROOT, capture_output=True, text=True, check=False)
    tail = [line for line in proc.stdout.strip().splitlines() if line.strip()]
    summary = tail[-1] if tail else "no output"
    match = _PASSED_COUNT.search(summary)
    ran = bool(match) and int(match.group(1)) > 0
    if proc.returncode == 0 and not ran:
        return False, summary + " — no test passed"
    return proc.returncode == 0, summary


def _from_tests(names: List[Path], run: bool, subject: str) -> Result:
    if not names:
        return Result(TODO, "no test mentions {}".format(subject))
    verdict = _pytest(names, run)
    if verdict is None:
        return Result(PARTIAL, "{} test file(s), not run — pass --tests".format(
            len(names)))
    passed, summary = verdict
    return Result(DONE if passed else BROKEN, summary)


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


def _scenarios_with_a_test(files: List[Path]) -> List[str]:
    """Scenario keys that name an actual test, read from the syntax tree.

    `k in text` was the test, and the text includes every comment and every
    docstring in the file. Deleting `test_auth_failure_is_not_a_clean_end` and
    leaving the words "auth failure" — or the key itself — in the module
    docstring kept the probe at 13/13: the tracker would report the scenario
    covered by the sentence describing the test that used to cover it.

    The same shape as the defect this function's own docstring already
    warned about one line up, and the warning did not stop it: a check
    satisfied by a substring is satisfied by prose. Function names are what
    `pytest` collects, so they are what gets counted.
    """
    return _scenarios_named_by(_test_names(files))


def _test_names(files: List[Path]) -> set:
    """Function names `pytest` would collect — not every `def test…` in the file.

    `ast.walk` descends into function bodies, so a helper defined inside
    another function counted as a test, and pytest never sees one. Classes
    nest, though — pytest collects `TestOuter::TestInner::test_x` — so the walk
    follows class bodies to any depth and function bodies not at all.
    """
    return _test_names_in([
        ast.parse(path.read_text(encoding="utf-8"), filename=str(path)).body
        for path in files])


def _scenarios_named_by(names) -> List[str]:
    return [key for key in CONFORMANCE_SCENARIOS
            if any(key in name for name in names)]


_CONDITIONAL = ("skip", "skipif", "xfail")


def _conditionally_run(files: List[Path]) -> set:
    """Tests carrying `skip`, `skipif` or `xfail`, by name.

    The report cannot tell these apart from a pass on its own. A `<testcase>`
    records its outcome by having a `failure`, `error` or `skipped` child, and
    an **xpassed** test — marked `xfail` and succeeding anyway — has none of
    them, so it is written exactly as an ordinary pass is. Thirteen scenarios
    marked `xfail` and quietly succeeding would have read as thirteen covered.

    So the marker is read where it is written, in the source, and a test that
    carries one does not establish coverage whichever way it ends. A scenario
    whose only test is conditional is a scenario nobody has committed to.
    """
    marked = set()

    def named(node) -> str:
        while isinstance(node, ast.Call):
            node = node.func
        while isinstance(node, ast.Attribute):
            if node.attr in _CONDITIONAL:
                return node.attr
            node = node.value
        return getattr(node, "id", "") if isinstance(node, ast.Name) else ""

    def collect(body) -> None:
        for node in body:
            if isinstance(node, ast.ClassDef):
                # A marker on the class applies to every test in it.
                if any(named(d) in _CONDITIONAL for d in node.decorator_list):
                    marked.update(_test_names_in([node.body]))
                collect(node.body)
            elif (isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                    and node.name.startswith("test")
                    and any(named(d) in _CONDITIONAL
                            for d in node.decorator_list)):
                marked.add(node.name)

    for path in files:
        collect(ast.parse(path.read_text(encoding="utf-8"),
                          filename=str(path)).body)
    return marked


def _test_names_in(bodies) -> set:
    names = set()

    def collect(body) -> None:
        for node in body:
            if isinstance(node, ast.ClassDef):
                collect(node.body)
            elif (isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                    and node.name.startswith("test")):
                names.add(node.name)

    for body in bodies:
        collect(body)
    return names


def _passing_test_names(paths: List[Path]) -> Tuple[bool, str, Optional[set]]:
    """One run, answering both questions: did it pass, and which tests passed.

    A name in the file is not a test that ran. A scenario whose only test
    carries `@pytest.mark.skip` — left behind after a rewrite, which is how
    they get there — was counted as covered: the syntax tree says the function
    exists and says nothing about pytest ever executing it. `_pytest` did not
    catch it either, because it asks only whether *some* test in the file
    passed, and twelve real ones answer that for the thirteenth.

    Read from `--junit-xml` and not from the terminal. The first version parsed
    `nodeid PASSED` lines out of `-v` output, which is written for a person: it
    breaks on a path with a space, a parameter id containing `]`, a class
    nested in a class, and any plugin that rewrites the status line. Every one
    of those breakages reports a covered scenario as uncovered — conservative,
    and still a wrong number in a tracker whose whole job is the number.

    And **one** run, not two. Asking pytest twice let the summary come from one
    execution and the coverage from another, so a flaky or differently-selected
    second run could contradict the line printed beside it.

    Returns `(passed, summary, names)`. `names` is None when the report could
    not be read — which is not the same as no test having passed, and the
    caller must not read it as coverage.
    """
    with tempfile.TemporaryDirectory() as directory:
        report = Path(directory) / "report.xml"
        proc = subprocess.run(
            [sys.executable, "-m", "pytest", "-q", "--tb=no",
             "--junit-xml={}".format(report), *[str(p) for p in paths]],
            cwd=ROOT, capture_output=True, text=True, check=False)
        tail = [line for line in proc.stdout.strip().splitlines() if line.strip()]
        summary = tail[-1] if tail else "no output"
        if not report.is_file():
            return proc.returncode == 0, summary, None
        try:
            tree = ElementTree.parse(report)
        except ElementTree.ParseError:
            return proc.returncode == 0, summary, None
        names = set()
        for case in tree.iter("testcase"):
            # A case that did not fail, error out or get skipped is one that
            # passed. Asked as "no such child", because the outcome is recorded
            # by the *presence* of a child element and there is no `<passed/>`.
            if any(case.find(kind) is not None
                   for kind in ("failure", "error", "skipped")):
                continue
            name = case.get("name") or ""
            # `test_x[param]` — the id is the test, the brackets are the case.
            names.add(name.split("[", 1)[0])
        return proc.returncode == 0, summary, names


def probe_conformance(args) -> Result:
    """Named file only, never a grep for the word.

    The first version searched every test for "conformance" and reported 0/13
    as `partial` the moment an unrelated file mentioned it in a docstring — a
    tracker inventing progress that does not exist, which is the failure this
    whole project is about. A probe that can be satisfied by prose is not a
    measurement. Which the second version still was, one level down — see
    `_scenarios_with_a_test`."""
    path = TESTS / "test_runner_conformance.py"
    files = [path] if path.exists() else []
    if not files:
        return Result(TODO, "0/13 — no test_runner_conformance.py")
    try:
        named = _scenarios_with_a_test(files)
    except SyntaxError as exc:
        return Result(BROKEN, "test_runner_conformance.py will not parse: "
                              "{}".format(exc))
    total = len(CONFORMANCE_SCENARIOS)

    def missing(covered) -> str:
        absent = [CONFORMANCE_SCENARIOS[k] for k in CONFORMANCE_SCENARIOS
                  if k not in covered]
        return "; ".join(absent[:3]) + ("…" if len(absent) > 3 else "")

    if not args.tests:
        # A name is an upper bound on coverage, never a measurement of it, and
        # without running the tests that bound is all there is.
        return Result(PARTIAL, "{}/{} named, not run — pass --tests{}".format(
            len(named), total,
            "" if len(named) == total else " · missing: " + missing(named)))

    # Run *before* answering about coverage. The count came first, and returned
    # `partial 12/13 — missing: …` for a file whose twelve tests all failed:
    # the failure was invisible, and the line beside it read like progress. A
    # broken check is not a coverage number, whatever its coverage happens to
    # be.
    passed, summary, ran = _passing_test_names(files)
    if not passed:
        return Result(BROKEN, "{}/{} named — {}".format(
            len(named), total, summary))
    if len(named) < total:
        return Result(PARTIAL, "{}/{} — missing: {}".format(
            len(named), total, missing(named)))
    if ran is None:
        # Green, and the report that says *which* tests were green could not be
        # read. Not the same as nothing having passed, and not evidence of
        # coverage either — so neither `done` nor a count.
        return Result(PARTIAL, "{n}/{n} named — {s}, but the run's report "
                               "could not be read".format(n=total, s=summary))
    if not ran:
        # Green with nothing recorded as passing is the all-skipped file the
        # old exit-code check let through, arriving by a different road.
        return Result(BROKEN, "{n}/{n} named — {s}, and no test passed"
                      .format(n=total, s=summary))

    # An xpassed test is written into the report exactly as a passing one is,
    # so the marker is read from the source and subtracted here.
    covered = _scenarios_named_by(ran - _conditionally_run(files))
    if len(covered) < total:
        return Result(PARTIAL, "{}/{} passed — named but never passed: {}"
                      .format(len(covered), total, missing(covered)))
    return Result(DONE, "{n}/{n} named — {s}".format(n=total, s=summary))


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


def result_files() -> list:
    """The **production stream**: batches at the top level, and the queue.

    It used to say "every file holding paid results", and that was false in
    both directions at once. It is not every file — the experiment writes 27
    more under `experiment-*/pass-*/` and `--round N` writes to `round-N/` —
    and it must not be, for the readers that settle a verdict.

    `tools/check_accounted.py` records why, and it was paid for: folding
    experiment rows into the verdicts made a stability experiment's pass B the
    production answer and moved `rb-g65v-27r3-5p6m` out of `LIMITATIONS.md` on
    a row nobody had checked. `experiment.py` reads its prompts from a frozen
    copy and keeps its own identity for the scorer, the reviewer and the answer
    key — none of which `case_digest` compares — so an experiment row proves a
    case was *run*, not what its answer is.

    Which is why the name of this one now says production stream, and
    `paid_result_files` below answers the other question separately. One list
    could not answer both, and a docstring claiming it did was the whole
    defect: a reader taking it at its word widens the glob and silently hands
    the verdict to an experiment.
    """
    return sorted((ROOT / "measurements").glob("*.json")) + sorted(
        (ROOT / "measurements" / "queue").glob("*.json"))


def paid_result_files() -> list:
    """Every file a paid run has written, in all four places it writes them.

    For the questions about money and about what was bought, where an
    experiment run counts exactly as much as any other: it was billed the same
    way, to the same account, and if one of them had been billed to an API key
    a reader that cannot see the file could never say so.
    """
    measurements = ROOT / "measurements"
    return sorted(set(result_files())
                  | set(measurements.glob("experiment-*/pass-*/*.json"))
                  | set(measurements.glob("round-*/*.json")))


def rows_in(body) -> list:
    """The rows a result file holds, whichever of the three shapes it is.

    A batch is a list, `{"results": [...]}` is accepted here and by
    `run_queue`, and an experiment writes one bare object per file. Handling
    only the first two is how widening a glob changes nothing: the new files
    are opened, parsed, and then read as no rows at all — the failure looks
    exactly like the fix having worked.
    """
    if isinstance(body, list):
        return [row for row in body if isinstance(row, dict)]
    if isinstance(body, dict):
        found = body.get("results")
        if isinstance(found, list):
            return [row for row in found if isinstance(row, dict)]
        return [body]
    return []


def _settle(seen: list) -> set:
    """One case's verdicts, reduced to what stands now.

    `seen` is `[(instant_or_None, passed)]`. The latest instant wins, so a
    corrected re-run *fixes* a case instead of leaving it disagreeing with its
    own past for ever — which is what the earlier rule did, and it meant a case
    could only ever be made worse by running it again.

    Two things it deliberately does not do. Rows with no time do not sort
    anywhere, so they answer only when nothing dated does. And verdicts sharing
    the latest instant are all returned: `pair_corpus` stamps whole seconds, so
    a tie is reachable, and picking between two answers recorded at the same
    moment would be inventing an order. A tie stays unresolved.
    """
    dated = [(when, ok) for when, ok in seen if when is not None]
    if not dated:
        return _without_silence({ok for _when, ok in seen})
    latest = max(when for when, _ok in dated)
    return _without_silence({ok for when, ok in dated if when == latest})


def _without_silence(answers: set) -> set:
    """Drop `None` only when it is the *whole* answer.

    `None` is `_pair_passed` saying the row does not answer — its findings are
    not a list, or hold something that is not a finding. Two wrong readings of
    that, one after the other:

    * keeping it made `{None} != {True}`, so a row that said nothing was
      counted as a row that said "missed";
    * discarding it always made `{True, None}` collapse to `{True}`, so a
      readable row at the same instant *settled* the case — and the unreadable
      one may have been a disagreeing run whose answer cannot be recovered. It
      is not evidence for the other; it is a missing answer beside it.

    So: alone it means "no verdict", and beside a real answer it means the
    instant is unresolved — which is the same rule this module already applies
    to two rows that disagree outright.
    """
    if answers == {None}:
        return set()
    return answers


def findings_list(row: dict, key: str):
    """The findings under `key`, or `None` when the row does not hold a list.

    `row.get(key) or []` was the reading, and it keeps a truthy dict or string:
    iterating a dict yields its keys, `is_target` calls `.get` on a key, and an
    `AttributeError` comes out of the tally. `None` here is the third answer —
    not "no findings", which would score the row as a miss, but "this row does
    not say", which is a different thing and belongs to a different bucket.
    """
    value = row.get(key)
    if value is None:
        return []
    if not isinstance(value, list):
        return None
    if any(not isinstance(item, dict) for item in value):
        # Filtering them out scored the row as a *miss*, which is the wrong
        # answer in the same way `False` was: `["bad"]` is a findings field
        # this cannot read, not a run that found nothing. The first version of
        # this function said so in its own docstring — "a list of strings does
        # the same thing" — and then dropped the strings and answered anyway.
        return None
    return value


def _pair_passed(row: dict, case_id: str) -> bool:
    """Did this pair discriminate, judged by the key in force now?

    The row holds what the reviewer found in each member. Whether those
    findings are the weakness the case is about is a question about the answer
    key, and the key is edited when it turns out to have named the wrong thing
    — so the boolean the scorer wrote is an answer to the key as it stood that
    afternoon.

    Falls back to the stored value only when the row predates the findings
    being recorded. That is honest rather than convenient: a row with no
    findings in it cannot be re-judged, and pretending otherwise would score
    every old result as a miss.
    """
    if "safe_findings" not in row or "unsafe_findings" not in row:
        return row.get("pair_success") is True
    unsafe = findings_list(row, "unsafe_findings")
    safe = findings_list(row, "safe_findings")
    if unsafe is None or safe is None:
        # Not `False`. A row whose findings cannot be read has not said the
        # agent missed the weakness — it has said nothing, and scoring it as a
        # failure would put a wrong answer where an absent one belongs.
        return None

    case_dir = ROOT / "corpus-real" / case_id
    try:
        case = yaml.safe_load((case_dir / "case.yml").read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError):
        return row.get("pair_success") is True

    excused = ruled_incidental(
        load_adjudications(ROOT / "corpus-real"), case_id, "safe")
    found = any(is_target(f, case) for f in unsafe)
    persists = any(is_target(f, case)
                   and f.get("fingerprint") not in excused
                   for f in safe)
    return found and not persists


def measured_outside_the_stream(current: Dict[str, set]) -> set:
    """Cases a paid run has a usable row for, in none of which is a verdict.

    Two questions, and folding them into one costs money either way. "What is
    this case's answer" has to come from the production stream. "Do we still
    owe a measurement for it" has to count every review that was bought,
    including the 27 an experiment wrote under `experiment-*/pass-*/` — and
    while nothing asked the second question, a case measured only there read as
    never run, which is a request to pay for it again. That happened twice
    before `check_accounted.py` separated them, at about a dollar each.

    Not a verdict, and deliberately not returned as one: what to do with such a
    row is a decision, and it stays visible until somebody makes it.
    """
    stream = {path.resolve() for path in result_files()}
    seen = set()
    for path in paid_result_files():
        if path.resolve() in stream:
            continue
        try:
            body = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError, ValueError):
            continue
        for row in rows_in(body):
            case_id = row.get("case_id")
            if not isinstance(case_id, str) or not case_id:
                continue
            if row.get("incomplete") or not isinstance(row.get("pair_success"), bool):
                continue
            if row.get("case_digest") in current.get(case_id, ()):
                seen.add(case_id)
    return seen


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
    # Either digest. The definition narrowed to the members so that a
    # corrected answer key stops discarding the run it was corrected
    # for, and the old whole-tree value still means the members are
    # unchanged — so accepting it keeps every result already paid for.
    current = {name: {case_digest(ROOT / "corpus-real" / name),
                      legacy_case_digest(ROOT / "corpus-real" / name)}
               for name in cases}
    verdicts: Dict[str, set] = {}
    undated: Dict[str, int] = {}
    for path in result_files():
        try:
            body = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError, ValueError):
            continue
        for row in rows_in(body):
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
            if digest not in current.get(case_id, ()):
                # Either the case has changed since, or the run predates any
                # record of which version it saw. Both mean the same thing for
                # this count and neither is a verdict about the case as it
                # stands, but the second is worth naming rather than dropping.
                if not digest:
                    undated[case_id] = undated.get(case_id, 0) + 1
                continue
            # Worked out from the findings the row holds and the key in force
            # now, rather than read from the boolean the scorer wrote at the
            # time. Two keys have been corrected since results were stored —
            # CWE-116 is not only XSS, and Winter's lowercase check is the
            # mechanism under its CSRF — and each correction left a stored
            # `pair_success` answering a question nobody asks any more.
            #
            # `is True`, not `bool(...)`, where the stored value is still used:
            # `bool("false")` is true, and a tracker that reads the string
            # "false" as a pass can be told the work is done by a typo.
            verdicts.setdefault(case_id, []).append(
                (instant(row.get("ran_at")), _pair_passed(row, case_id)))

    # A later run supersedes an earlier one, by the time recorded *in the row*
    # — not by filename order, which is not run order, and not by modification
    # time, which a clone rewrites.
    verdicts = {case_id: _settle(seen) for case_id, seen in verdicts.items()}

    run = [c for c in cases if c in verdicts]
    split = [c for c in run if len(verdicts[c]) > 1]
    passing = [c for c in run if verdicts[c] == {True}]
    stale = sorted(set(undated) - set(verdicts))
    # Bought, and with no verdict here. Named rather than counted as unrun: the
    # difference between "nobody has paid for this" and "somebody paid and
    # nothing adopted the result" is a dollar, and the tracker is what the
    # owner reads to decide what to buy next.
    unadopted = sorted(measured_outside_the_stream(
        {name: current[name] for name in cases}) - set(run))
    beside = " (+{} snapshot)".format(snapshots) if snapshots else ""
    if unadopted:
        beside = ", {} measured outside the stream and not adopted: {}{}".format(
            len(unadopted), ", ".join(unadopted[:2]), beside)
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
    """Every failing pair has a fix, a recorded limitation, or a ruling.

    Point 9 says there is no third state, and "the model simply did not catch
    it" is a reason that gets written down rather than passed over.

    Read from the pairs, because that is where a failure comes from now. It
    read `journal/` — written only by `tools/review.sh`, the flow point 8
    retired — so it said "nothing to reconcile yet" while two pairs sat failing
    in `measurements/`. The same drift as the row above it and as point 8
    itself: a check aimed at a source the current work does not produce.

    Two outcomes, as the plan says and no more: the pair passes now — which
    takes it off this list entirely — or `LIMITATIONS.md` names the case.

    A ruling in `adjudications.yml` is deliberately *not* a third one, though
    it was briefly counted as one. Every ruling is already applied before the
    pair is judged: `_pair_passed` excuses what a ruling excuses, so a ruling
    that resolved anything has moved the pair to passing and it is not here.
    What is left is a case whose rulings were applied and which failed anyway —
    `rb-g65v`'s says in as many words that it takes no effect — and a ruling
    that says why one candidate excuse was rejected is not an account of why
    the failure is acceptable. Counting it as one let the tracker report the
    point done over a current, unexplained failure, which is the third state
    point 9 exists to forbid.

    What this narrowed, stated rather than glossed: the unit is the pair, not
    the individual finding. The version that read `journal/` reconciled finding
    by finding. That is a wider net, and it is not the net point 9 asks for —
    the plan's unit is the failure, and a pair that preserved the decision did
    not fail. It does mean an incidental finding inside a passing pair is not
    surfaced here; by the project's own rule an incidental finding is only
    adjudicated when it changes a score, and one that changed a score would
    have moved the pair. The gap is real but empty in the cases we have.
    """
    failing = _failing_cases()
    if not failing:
        return Result(TODO, "nothing to reconcile yet")

    limitations = (ROOT / "LIMITATIONS.md").read_text(encoding="utf-8")
    # Bounded, not `in`. Every snapshot case is its regression twin's id with
    # `-snap` on the end, so a plain substring test let a limitation written
    # for `py-6x92-6vx4-5fwr-snap` silently account for `py-6x92-6vx4-5fwr` as
    # well — two different pairs, one sentence, and the shorter one reads as
    # explained without anybody having written about it.
    unresolved = [case_id for case_id in failing
                  if not re.search(r"(?<![\w-])" + re.escape(case_id)
                                   + r"(?![\w-])", limitations)]
    if unresolved:
        return Result(PARTIAL, "{} failing pair(s) with no fix and no recorded "
                               "limitation: {}".format(
                                   len(unresolved), ", ".join(unresolved[:3])))
    return Result(DONE, "every failing pair is accounted for")


def _failing_cases() -> list:
    """Cases whose latest counted result did not preserve the decision.

    "Latest" by the same rule the count uses. It said so before it did so: the
    function appended a case on the first failure it met and never took it off
    again, so a case that had been re-run and fixed went on being demanded an
    explanation for ever — while `probe_use` reported it passing. The two
    probes have to settle a case the same way or the tracker contradicts
    itself, and the direction it contradicted itself in was to keep asking
    about work already done.
    """
    # The same exclusion the count applies. A case ruled unable to measure
    # anything is not a failure — the ruling says so in as many words, "do not
    # count it as a failure" — and point 8 already drops it from both sides of
    # its fraction. Asking point 9 to explain a failure point 8 does not
    # record is the tracker asking about something it has itself excluded.
    excluded = malformed_cases(ROOT / "corpus-real")
    seen: Dict[str, list] = {}
    for path in result_files():
        try:
            body = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError, ValueError):
            continue
        for row in rows_in(body):
            if row.get("incomplete"):
                continue
            case_id = row.get("case_id")
            if not isinstance(case_id, str) or not case_id:
                continue
            # Against the version of the case that exists now, by the same rule
            # the count uses. Without this the Savon case was named as an
            # unreconciled failure on the strength of two runs against the
            # version whose weakness a bug in the comment stripper had deleted
            # — a failure at reviewing code that no longer exists, asked to be
            # explained.
            if case_id in excluded:
                continue
            directory = ROOT / "corpus-real" / case_id
            if not directory.is_dir():
                continue
            if row.get("case_digest") not in {case_digest(directory),
                                              legacy_case_digest(directory)}:
                continue
            # No `safe_findings` filter. `_pair_passed` already decides what
            # to do with a row that cannot be re-judged — it falls back to the
            # stored boolean — and skipping those rows here while the count
            # kept them meant a current legacy failure showed up under point 8
            # and as "nothing to reconcile yet" under point 9. Both probes read
            # a row the same way or the tracker disagrees with itself.
            seen.setdefault(case_id, []).append(
                (instant(row.get("ran_at")), _pair_passed(row, case_id)))
    # A case whose latest runs disagree is not settled as passing, so it is
    # still owed an explanation.
    return [case_id for case_id in sorted(seen)
            if _settle(seen[case_id]) != {True}]


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
    an auth method is named rather than counted either way.

    Read from `measurements/`, which is where the work lands. It read
    `journal/` — a directory only `tools/review.sh` writes, and that is the
    review-your-own-branch flow point 8 retired on 2026-08-27. So it answered
    "no runs filed" over five paid batches and would have gone on answering it
    however many more were run: a check pointed at a source the current work
    does not produce, which is the drift point 8 itself had.
    """
    # Every place a paid run lands, not the production stream only. A billed
    # run is a billed run wherever its file was written, and 27 of them — every
    # review the stability experiment bought — were outside what this probe
    # could read. It answered "each on an established subscription" over a set
    # it had not opened, which is the same clean sheet over an unread corpus
    # that this probe was rewritten once already to stop printing.
    rows = []
    for path in paid_result_files():
        try:
            body = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError, ValueError):
            continue
        rows.extend(rows_in(body))
    if not rows:
        return Result(TODO, "no runs filed")

    charged, silent, subscription = [], [], []
    for row in rows:
        # From `provenance`, which is where a run records this. It used to read
        # `provider_telemetry` or `run`, and no artifact has ever had either —
        # so every file was skipped and the probe reported a clean sheet over a
        # corpus it had not read one byte of. The container was named before
        # the field existed and nothing ever connected the two.
        members = row.get("members") or {}
        # Each member separately. The safe and unsafe members are two separate
        # executions of the CLI, and the login can differ between them — so
        # taking the first member that named a provider and reporting the pair
        # by it would hide a billed run behind a subscription one. Whichever
        # member was paid for is the one this probe exists to name.
        for member in ("unsafe", "safe"):
            prov = (members.get(member) or {}).get("provenance") or {}
            if prov.get("provider") != "claude-cli":
                continue
            name = "{} ({})".format(row.get("case_id") or "?", member)
            # Decided by the login, never by the figure. The CLI reports
            # `total_cost_usd` on a subscription too — a two-token reply on a
            # Max plan came back as $0.29 — so it is what the run *would* have
            # cost, and a probe reading it as a bill would call every
            # subscription run billed. The figure is recorded beside the
            # verdict, not used as one.
            auth = prov.get("auth_method")
            if auth and auth != "claude.ai":
                charged.append("{} {}".format(name, auth))
            elif auth == "claude.ai" and prov.get("auth_subscription"):
                subscription.append(name)
            else:
                # No auth method recorded: a run from before the CLI was
                # asked, or one where it would not say. Named rather than
                # counted either way — the old version read a missing cost as
                # a zero and called that proof, which is this project's own
                # absent-versus-zero rule broken inside the tool that checks
                # it.
                silent.append(name)

    if charged:
        return Result(BROKEN, "{} local run(s) were billed: {}".format(
            len(charged), ", ".join(charged[:3])))
    if not (subscription or silent):
        return Result(TODO, "no local run to read")
    if silent:
        # Named, not just counted. A count says how many runs nobody can
        # account for; it does not say which, and the answer to "which" is the
        # only thing anyone can act on.
        return Result(PARTIAL, "{} run(s) on an established subscription, "
                               "{} that recorded no auth method: {}".format(
                                   len(subscription), len(silent),
                                   ", ".join(silent[:3])))
    return Result(DONE, "{} local run(s), each on an established "
                        "subscription".format(len(subscription)))


CHECKS = [
    Check("1", "budget", "tests green", probe_budget),
    Check("2", "canonical split", "no telemetry compared", probe_canonical),
    Check("3a", "finish_review", "tool, prompt, loop", probe_finish_review),
    Check("3b", "submit_verdict", "tool, prompt, loop", probe_submit_verdict),
    Check("3", "ClaudeCodeRunner", "matches on a fixed diff", probe_runner),
    Check("4", "tool confinement", "2/2", probe_confinement),
    Check("5", "conformance", "every named scenario", probe_conformance),
    Check("6", "no silent fallback", "exit 2, 0 API calls", probe_no_fallback),
    Check("7", "scope control", "2 flags, tested", probe_scope),
    Check("8", "advisory pairs", "every measurable pair, decision preserved", probe_use),
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
