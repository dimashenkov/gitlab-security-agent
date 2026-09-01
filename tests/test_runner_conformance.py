"""Two runners, one decision: the same thirteen endings, compared byte for byte.

`ClaudeCodeRunner` and `SecurityAgent` share every part that decides anything —
the tools, `dispatch`, the citation check, the panel, the gate — and share none
of the plumbing that gets a model to call them. That is the arrangement this
file exists to police. Nothing stops the two paths from drifting apart in what
they *record*, and a drift there is invisible: both runners keep working, both
produce a report, and the two reports quietly answer different questions.

So each scenario below is run through both runners where it can be, and the
artifacts are compared with `canonical.canonical_bytes` — telemetry removed by
`canonical.py`'s own list, never by a list kept here. A test carrying its own
set of fields to skip grows one entry per argument and ends up skipping the
thing under test.

## Why there is a fake executable

The CLI half cannot be tested by calling functions. What breaks on that path is
the chain: the argument list, the MCP handshake, the offered set, the child's
budget, the session document, the crash journal, and the runner's reading of a
terminal JSON object it did not write. So `FakeCli` generates a small Python
program and puts it where `claude` would be. It reads the `--mcp-config` it is
handed, speaks real MCP over stdio to the real child server, makes a scripted
list of tool calls, and ends the way the scenario says — cleanly, unparseably,
or not at all. Every link between the briefing and the artifact is the real
one, and there is no model anywhere. That is also the only way the failure
endings can be tested at all: a real CLI cannot be asked to corrupt its own
output.

## What "honest" means here, and why it is asserted separately

A conformance suite that passes because both runners are equally broken is
worth nothing. Agreement is necessary and not sufficient, so every scenario
also asserts the absolute property: `complete` is true only when the run
reached the end, and a run that did not reach the end never exits 0.

## Where the two genuinely disagree today

Three defects, found by this file the first time it ran, none of them fixable
from a test. Two are in `KNOWN_DIVERGENCE` with the source change each needs;
the ledger is asserted in both directions, so fixing one fails this file and
gets the entry deleted rather than leaving a permanent exception behind. The
third — a tool budget that runs out and still renders as a completed review —
is a single strict `xfail` in `TestToolBudget`.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import anthropic
import pytest

from fakes import FakeClient, FakeResponse, text, tool_use
from security_agent.agent import SecurityAgent
from security_agent.budget import Profile, RunBudget
from security_agent.canonical import canonical_bytes, differences
from security_agent.config import Config, GitLabContext
from security_agent.crash_journal import KIND_TOOL_STARTED
from security_agent.gate import EXIT_ERROR, EXIT_FINDINGS, EXIT_OK, decide
from security_agent.models import (
    STOP_BUDGET,
    STOP_COMPLETED,
    STOP_ERROR,
    STOP_TIME_LIMIT,
    VERDICT_CONFIRMED,
    VERDICT_REFUTED,
    Revision,
)
from security_agent.report import build_json
from security_agent.runner_claude_code import ClaudeCodeRunner
from security_agent.suppress import apply as apply_suppressions
from security_agent.tools import HANDLERS
from security_agent.workspace import Workspace

PROMPTS = Path(__file__).resolve().parents[1] / "prompts"

# The thirteen endings this file is answerable for. `tools/stage2.py` counts
# coverage by looking for these strings, so each one is also part of the name of
# the test that exercises it — a marker that can drift away from the test it
# names is a marker that measures nothing. `test_every_named_scenario_has_a_test`
# holds the two together.
SCENARIOS = (
    "terminal_success", "malformed_json", "missing_result", "unknown_status",
    "auth_failure", "killed_thinking", "killed_in_tool", "tool_budget",
    "verifier_budget", "forbidden_tool", "partial_finding", "invalid_finding",
    "no_artifact",
)

EVIDENCE = 'return db.execute("SELECT * FROM users WHERE id = " + user_id)'

FINDING_ARGS = {
    "title": "SQL injection in get_user",
    "severity": "high",
    "confidence": "high",
    "category": "injection",
    "file": "app/views.py",
    "line": 3,
    "impact": "broad_data_access",
    "reachable_without_authentication": "yes",
    "requires_user_interaction": "no",
    "evidence": EVIDENCE,
    "description": "The id parameter is concatenated into a SQL string.",
    "exploit_scenario": "An anonymous caller sends ?id=1 OR 1=1 and reads every row.",
    "recommendation": "Use a parameterised query with a bound parameter.",
}

# The same claim quoting code that is not in the file. Layer 1 refuses it twice
# and the second refusal drops it for good.
INVALID_FINDING_ARGS = dict(
    FINDING_ARGS,
    evidence='return db.execute("DROP TABLE users WHERE nobody = wrote_this")',
)

SUMMARY = ("Read the user lookup path in app/views.py and traced the query "
           "construction back to its caller.")

READ = ("read_file", {"path": "app/views.py"})
FINISH = ("finish_review",
          {"summary": SUMMARY, "unresolved": ["Whether the handler is routed"]})

# `_launch` floors the CLI's timeout at one second, so nothing below that buys
# anything. Five, because the scenarios that end in a kill still have to get a
# Python interpreter up, import the package and answer a tool call first — and a
# ceiling that only just covers the setup is a test that fails on a busy machine.
KILL_PROFILE = Profile("conformance-kill", review_turns=None,
                       review_tool_calls=100, verifier_sessions=3,
                       verifier_tool_calls=15, runtime_seconds=5)
# For the one scenario that starts nothing at all and so needs no setup time.
IDLE_KILL_PROFILE = Profile("conformance-idle", review_turns=None,
                            review_tool_calls=100, verifier_sessions=3,
                            verifier_tool_calls=15, runtime_seconds=1)
# Long enough that a scenario meant to finish never races the clock.
CALM_PROFILE = Profile("conformance", review_turns=None, review_tool_calls=100,
                       verifier_sessions=3, verifier_tool_calls=15,
                       runtime_seconds=600)
# Three tool calls and no more, so the fourth is refused by the child.
TIGHT_PROFILE = Profile("conformance-tight", review_turns=None,
                        review_tool_calls=3, verifier_sessions=3,
                        verifier_tool_calls=15, runtime_seconds=600)


# ---------------------------------------------------------------- the ledger


# Paths where the two runners' canonical results genuinely disagree today, each
# with the source change that would remove it. None of these is telemetry: they
# are decision fields one runner fills in and the other leaves empty.
#
# Asserted in both directions. A new divergence fails the scenario that produced
# it; a divergence that has been fixed fails
# `test_the_known_divergence_ledger_is_still_accurate`, so the entry is deleted
# rather than outliving the defect and quietly excusing the next one to land on
# the same field.
KNOWN_DIVERGENCE = {
    # Empty, and asserted in both directions: an entry here is a promise that
    # the two runners still differ in that field, so closing a divergence
    # without deleting its entry fails this file. That is deliberate — a ledger
    # of exceptions nobody prunes becomes a list of things the comparison has
    # quietly stopped covering.
    #
    # Three lived here and are gone. `runner_claude_code` set no provenance, so
    # every CLI artifact recorded an empty one and `identity` — the key
    # `--reuse` matches on and the key `baseline.py` refuses a comparison
    # across — was blank with it. `MCPServer._call_tool` recorded no
    # `ToolCallRecord`, so the artifact's account of what the review actually
    # did was empty on a run that made dozens of calls. Both are fixed at the
    # source rather than excused here.
}

# One more, and only on a run that did not complete — which is why it is a
# separate set rather than a twelfth entry above.
#
# `canonical.py` classifies `stop_detail` as telemetry, on the stated grounds
# that the sentence explaining *how* a run failed is provider prose. It is, and
# `gate.decide` then interpolates that same prose into `verdict.reason`, which
# is compared. So the exclusion holds at one door and not at the other, and two
# honest runners can never agree on an incomplete run's `verdict.reason`.
#
# Fix in `gate.decide` rather than in `canonical.py`: `stop_detail` is already
# its own field in the artifact, so the reason does not need to carry a copy.
# Adding `verdict.reason` to `TELEMETRY_PATHS` would be the wrong repair — it
# would also stop comparing "1 finding at or above the high threshold" against
# "No security findings", which is the decision itself.
INCOMPLETE_DIVERGENCE = {
    "verdict.reason": "gate.decide interpolates the telemetry `stop_detail`",
}


def _diverging_paths(left, right):
    """The field names `differences()` reported, without their values."""
    return {entry.split(":", 1)[0] for entry in differences(left, right)}


def _allowed(artifact):
    if artifact["complete"]:
        return set(KNOWN_DIVERGENCE)
    return set(KNOWN_DIVERGENCE) | set(INCOMPLETE_DIVERGENCE)


def assert_conformant(api, cli, scenario):
    """The two artifacts agree everywhere except the ledgers above."""
    unexpected = _diverging_paths(api, cli) - _allowed(api)
    assert not unexpected, (
        "{}: the runners disagree about {} — full diff:\n  {}".format(
            scenario, sorted(unexpected), "\n  ".join(differences(api, cli))))


def assert_honest(artifact, scenario):
    """A run that did not finish never renders as finished, and never exits 0.

    Asserted for every scenario, including the ones that did finish, because the
    dangerous direction is the permissive one and the failure always wears the
    same face: `complete` true over a review that was cut short.
    """
    complete = artifact["complete"]
    assert complete is (artifact["stop_reason"] == STOP_COMPLETED), (
        "{}: complete={} with stop_reason={!r}".format(
            scenario, complete, artifact["stop_reason"]))
    if not complete:
        assert artifact["verdict"]["exit_code"] != EXIT_OK, (
            "{}: an incomplete review exited 0".format(scenario))
        assert artifact["verdict"]["blocked"] is True


# ------------------------------------------------------ the fake `claude` CLI


_FAKE_CLI = r'''#!@PYTHON@
"""A scripted MCP client standing in for the `claude` CLI. No model in it.

It does what the real client does to our server, and nothing it does not: reads
the `--mcp-config` it was handed, launches the one server named there with the
environment named there, completes the MCP handshake, calls the tools its plan
lists, and prints one terminal JSON object. Tool names go over the wire
unprefixed — `mcp__security_agent__` is the client's own addressing and never
reaches the server.

The server is launched in its own session, so a plan that kills it also kills
the `git` process it may be in the middle of running rather than orphaning one.
"""
import json
import os
import signal
import subprocess
import sys
import time

PLAN = json.loads(@PLAN@)
TRANSCRIPT = @TRANSCRIPT@
CHILD_LOG = @CHILD_LOG@
STARTED = @KIND_STARTED@

PROTOCOL = "2025-06-18"


class Server:
    def __init__(self, config_path):
        with open(config_path, encoding="utf-8") as handle:
            servers = json.load(handle)["mcpServers"]
        self.spec = servers[sorted(servers)[0]]
        self.proc = None
        self.identifier = 0
        self.log = []

    @property
    def journal(self):
        """Where the server actually writes, which is no longer the path we ask for.

        The name in the argument list is a base: the server writes
        `crash.<pid>.jsonl` beside it, because one review is no longer one
        process — the CLI starts the server once to probe it and once for the
        session, and a single exclusive path meant the probe took it and the
        session refused to start.

        This harness polls the journal to catch a call mid-flight, so reading
        the base name found nothing, the kill landed after the call had
        finished, and the test that exists to observe an unfinished call
        observed a finished one. `read_trace` resolves the same way.
        """
        args = self.spec["args"]
        base = args[args.index("--crash-journal") + 1]
        if os.path.exists(base):
            return base
        directory, name = os.path.split(base)
        stem, suffix = os.path.splitext(name)
        siblings = [os.path.join(directory, entry)
                    for entry in os.listdir(directory or ".")
                    if entry.startswith(stem + ".") and entry.endswith(suffix)]
        if not siblings:
            return base
        return max(siblings, key=os.path.getsize)

    def start(self):
        if self.proc is not None:
            return
        self.proc = subprocess.Popen(
            [self.spec["command"]] + list(self.spec["args"]),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=open(CHILD_LOG, "a", encoding="utf-8"),
            text=True,
            env=dict(self.spec.get("env") or {}),
            start_new_session=True,
        )
        self.request("initialize", {
            "protocolVersion": PROTOCOL,
            "capabilities": {},
            "clientInfo": {"name": "conformance-fake", "version": "0"},
        })
        self.send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        self.request("tools/list", {})

    def send(self, message):
        self.proc.stdin.write(json.dumps(message) + "\n")
        self.proc.stdin.flush()

    def request(self, method, params):
        self.start()
        self.identifier += 1
        self.send({"jsonrpc": "2.0", "id": self.identifier,
                   "method": method, "params": params})
        raw = self.proc.stdout.readline()
        reply = json.loads(raw) if raw.strip() else {"no_reply": True}
        self.log.append({"method": method, "params": params, "reply": reply})
        return reply

    def call(self, name, arguments):
        return self.request("tools/call", {"name": name, "arguments": arguments})

    def call_then_kill(self, name, arguments):
        """Issue a call and kill the server before its answer comes back.

        The wait is on the crash journal rather than on a clock: the server
        appends `tool_started` before it dispatches, so once that record is on
        disk the call is genuinely in flight. The plan pairs this with a tool
        call slow enough that the window is milliseconds wide.
        """
        self.start()
        self.identifier += 1
        self.send({"jsonrpc": "2.0", "id": self.identifier, "method": "tools/call",
                   "params": {"name": name, "arguments": arguments}})
        self.log.append({"method": "tools/call", "params": {"name": name},
                         "reply": {"killed_before_reply": True}})
        self.await_started(name)
        self.kill()

    def await_started(self, name, limit=30.0):
        deadline = time.time() + limit
        while time.time() < deadline:
            for record in self.records():
                if record.get("kind") == STARTED and record.get("name") == name:
                    return
        raise SystemExit("the server never journalled a start for " + name)

    def records(self):
        try:
            with open(self.journal, encoding="utf-8") as handle:
                lines = handle.readlines()
        except OSError:
            return []
        out = []
        for line in lines:
            try:
                out.append(json.loads(line))
            except ValueError:
                pass
        return out

    def close(self):
        if self.proc is None:
            return
        self.proc.stdin.close()
        self.log.append({"method": "close", "returncode": self.proc.wait(timeout=60)})
        self.proc = None

    def kill(self):
        if self.proc is None:
            return
        os.killpg(os.getpgid(self.proc.pid), signal.SIGKILL)
        self.log.append({"method": "kill", "returncode": self.proc.wait(timeout=60)})
        self.proc = None

    def flush(self):
        with open(TRANSCRIPT, "w", encoding="utf-8") as handle:
            json.dump(self.log, handle, indent=2)


def variadic(argv, flag):
    """A flag's values: everything up to the next `-`, as the CLI parses it.

    Written because the confinement tests read `build_command`'s list and
    nothing read it the way the program on the other end does. `--tools ""`
    yields `[""]`, and if a bare value ever followed it that value would land
    here — which is the failure the adjacency test describes and this is the
    only thing that would notice.
    """
    if flag not in argv:
        return None
    values = []
    for token in argv[argv.index(flag) + 1:]:
        if token.startswith("-"):
            break
        values.append(token)
    return values


# Our own tool names, substituted in from `HANDLERS` when this script is
# generated rather than typed here. The question "is this ours or a built-in"
# is asked from this side, because a list of *the CLI's* built-ins is already
# incomplete the day it is written — `AskUserQuestion` and `EnterPlanMode` were
# missing from the one this file first held — and every omission would be taken
# for an unqualified tool of ours and let through by the wildcard. What we
# offer is a fact about this repository, and it arrives here from the module
# that defines it.
OUR_TOOLS = frozenset(@OUR_TOOLS@)

# An MCP server configured on the developer's machine, which `--mcp-config`
# does not name. The fake pretends this exists so `--strict-mcp-config` has
# something to exclude: without one, the flag can only be tested by looking for
# it in the argument list, which is the defect this file is removing.
OTHER_SERVER = "mcp__somebodys_own_server__"


def confinement(argv):
    """What the flags actually permit, decided the way the CLI would decide it.

    The stand-in used to read `--mcp-config` and nothing else, so every
    confinement flag could have been deleted from `build_command` and the whole
    conformance suite would have passed — the fake had no built-in tools to be
    confined from and no other MCP server to ignore. The flags were asserted to
    be *present* and never to *do* anything.
    """
    tools = variadic(argv, "--tools")
    allowed = variadic(argv, "--allowedTools") or []
    denied = variadic(argv, "--disallowedTools") or []
    return {
        # `--tools ""` is the CLI's documented way of shipping none of the
        # built-in set. `None` means the flag was absent, which is "all of
        # them" — the state this runner must never be in.
        "built_ins": [] if tools == [""] else ("all" if tools is None else tools),
        "allowed": allowed,
        "denied": denied,
        # What the flag actually decides: whether the servers configured on
        # this machine, which `--mcp-config` does not name, are started at all.
        # Modelled separately from the permission lists, because a foreign tool
        # is already outside `--allowedTools` — so a test that only asked
        # whether the call was refused passed with the flag and without it.
        "loads_other_servers": "--strict-mcp-config" not in argv,
    }


def permitted(rules, name, server_key="security_agent"):
    """May this tool be called, in the order the CLI decides it?

    Deny first, then availability, then allow. Three attempts got here:

    * qualifying every name with our MCP prefix made `Bash` match
      `mcp__security_agent__*` and pass — the check saying yes to the one
      thing it was written to say no to;
    * deciding "is this ours" from the server's offered set refused
      `submit_verdict` here, which took the transport-level refusal off its own
      scenario: it is inside our prefix, absent from the *reviewer's* set, and
      the point is that the server refuses it;
    * deciding "is this a built-in" from `--disallowedTools` made the answer
      depend on the flag under test, so a built-in nobody denied was taken for
      an MCP tool and let through by the wildcard.

    So built-in identity comes from `BUILT_INS`, which is a fact about the CLI
    rather than about our arguments.
    """
    if name in rules["denied"]:
        return False

    if name not in OUR_TOOLS and not name.startswith("mcp__"):
        # Not ours and not another server's, so a built-in — whichever ones the
        # CLI happens to ship today.
        return rules["built_ins"] == "all" or name in rules["built_ins"]

    qualified = (name if name.startswith("mcp__")
                 else "mcp__{}__{}".format(server_key, name))
    # A server this config did not name is not in the session at all when
    # `--strict-mcp-config` is set — it is never started, which is a stronger
    # thing than its tools being forbidden.
    if qualified.startswith(OTHER_SERVER) and not rules["loads_other_servers"]:
        return False

    for pattern in rules["allowed"]:
        if pattern.endswith("*") and qualified.startswith(pattern[:-1]):
            return True
        if pattern == qualified:
            return True
    return False


def main():
    argv = sys.argv[1:]
    rules = confinement(argv)
    server = Server(argv[argv.index("--mcp-config") + 1])
    server.log.append({"method": "confinement", "rules": rules})
    server.log.append({"method": "briefing", "chars": len(sys.stdin.read())})
    try:
        for step in PLAN["steps"]:
            action = step["do"]
            if action in ("call", "call_then_kill") and not permitted(
                    rules, step["name"]):
                # What the real CLI does with a tool the flags forbid: it does
                # not make the call. Recorded rather than raised, so a plan
                # that asks for a forbidden tool produces a run with no tool
                # calls — which is what the runner would see, and what a test
                # asserting the flags *work* has to be able to observe.
                server.log.append({"method": "refused", "name": step["name"]})
                continue
            if action == "call":
                server.call(step["name"], step.get("args") or {})
            elif action == "call_then_kill":
                server.call_then_kill(step["name"], step.get("args") or {})
            elif action == "close_child":
                server.close()
            elif action == "kill_child":
                server.kill()
            elif action == "hang":
                server.flush()
                time.sleep(3600)
            else:
                raise SystemExit("unknown step " + repr(action))
    finally:
        server.flush()

    ending = PLAN["ending"]
    if ending["kind"] == "json":
        sys.stdout.write(json.dumps(ending["payload"]))
    elif ending["kind"] == "raw":
        sys.stdout.write(ending["text"])
    sys.stdout.flush()
    return int(ending.get("exit", 0))


if __name__ == "__main__":
    sys.exit(main())
'''


class FakeCli:
    """One generated `claude`, and the files it leaves for a test to read.

    The transcript is written outside the handoff directory on purpose: the
    runner deletes that directory as it returns, so anything written inside it
    is gone before an assertion can look at it.
    """

    def __init__(self, root: Path, script: dict) -> None:
        root.mkdir(parents=True, exist_ok=True)
        self.path = root / "claude"
        self.transcript_path = root / "transcript.json"
        self.child_log = root / "child.log"
        self.path.write_text(
            _FAKE_CLI
            .replace("@PYTHON@", sys.executable)
            .replace("@PLAN@", json.dumps(json.dumps(script)))
            .replace("@TRANSCRIPT@", repr(str(self.transcript_path)))
            .replace("@CHILD_LOG@", repr(str(self.child_log)))
            .replace("@KIND_STARTED@", repr(KIND_TOOL_STARTED))
            .replace("@OUR_TOOLS@", repr(sorted(HANDLERS))),
            encoding="utf-8",
        )
        self.path.chmod(0o755)

    @property
    def transcript(self):
        if not self.transcript_path.exists():
            return []
        return json.loads(self.transcript_path.read_text(encoding="utf-8"))

    def replies(self, method="tools/call"):
        return [entry["reply"] for entry in self.transcript
                if entry.get("method") == method]


def script(*steps, ending=None):
    """A list of tool calls and the way the run ends."""
    return {"steps": list(steps), "ending": ending or SUCCESS_ENDING}


def call(name, arguments=None):
    return {"do": "call", "name": name, "args": arguments or {}}


def call_then_kill(name, arguments=None):
    return {"do": "call_then_kill", "name": name, "args": arguments or {}}


CLOSE = {"do": "close_child"}
HANG = {"do": "hang"}

# The endings a CLI can present, each named for the scenario it belongs to.
SUCCESS_ENDING = {"kind": "json", "exit": 0,
                  "payload": {"type": "result", "subtype": "success",
                              "is_error": False, "result": "done"}}
MALFORMED_ENDING = {"kind": "raw", "exit": 0,
                    "text": 'Error: broke {"type":"result","subtype":"success"}'}
MISSING_RESULT_ENDING = {"kind": "json", "exit": 0,
                         "payload": {"type": "result", "duration_ms": 12}}
UNKNOWN_STATUS_ENDING = {"kind": "json", "exit": 0,
                         "payload": {"type": "result",
                                     "subtype": "compacted_and_resumed"}}
AUTH_FAILURE_ENDING = {
    "kind": "json", "exit": 1,
    "payload": {"type": "result", "subtype": "success", "is_error": True,
                "result": "Invalid API key - please run /login"},
}
# The success ending plus the usage block the CLI sends. Its four names were
# read off the binary's own session transcripts, not guessed between the two
# documented spellings.
REPORTED_USAGE_ENDING = {
    "kind": "json", "exit": 0,
    "payload": {"type": "result", "subtype": "success", "is_error": False,
                "result": "done",
                "usage": {"input_tokens": 4421, "output_tokens": 7478,
                          "cache_creation_input_tokens": 41134,
                          "cache_read_input_tokens": 158506}},
}
EXECUTION_ERROR_ENDING = {"kind": "json", "exit": 1,
                          "payload": {"type": "result",
                                      "subtype": "error_during_execution"}}

# A search that takes long enough for the kill in `call_then_kill` to land while
# the call is genuinely running: case-insensitive, alternating, and matching
# nothing, so `git grep` reads every byte of the haystack instead of stopping at
# the first hit.
SLOW_SEARCH = {"pattern": "(zzqa|zzqb|zzqc|zzqd|zzqe|zzqf|zzqg|zzqh)",
               "max_results": 1}


# ------------------------------------------------------------------ fixtures


@pytest.fixture
def cfg(tmp_path):
    """One configuration, used by both runners.

    `excludes` is emptied rather than left at its default because the CLI runner
    never passes the exclusions to its child at all — `build_mcp_config` has no
    flag for them and `mcp_server.build_server` defaults to `()` — so a default
    would make every comparison fail for a reason that has nothing to do with
    the scenario. That asymmetry is real and reported separately; it is not what
    these tests measure.
    """
    return Config(prompt_dir=PROMPTS, output_dir=tmp_path / "out",
                  gitlab=GitLabContext(), post_comment=False, excludes=(),
                  verify_votes=1)


@pytest.fixture
def workspace(git_repo):
    return Workspace(root=git_repo, excludes=(), diff_base="", diff_head="HEAD")


@pytest.fixture
def revision(workspace):
    """What both runners say they read.

    `mode="repo"` throughout: without a diff base neither runner is offered the
    diff tools, which keeps the comparison about the two runners rather than
    about which of them was handed a base.
    """
    head = workspace.git("rev-parse", "HEAD").strip()
    return Revision(mode="repo", base="", head="HEAD", base_sha="", head_sha=head)


@pytest.fixture
def haystack(git_repo):
    """A tracked file big enough that one `search_code` call takes real time.

    Only `killed_in_tool` uses it. The alternative to a slow call is a sleep,
    and a sleep in the fake CLI would not put the *server* in the middle of a
    dispatch — which is the whole state under test.
    """
    env = {"GIT_AUTHOR_NAME": "Test", "GIT_AUTHOR_EMAIL": "test@example.com",
           "GIT_COMMITTER_NAME": "Test", "GIT_COMMITTER_EMAIL": "test@example.com",
           "PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": str(git_repo)}
    (git_repo / "data").mkdir(exist_ok=True)
    (git_repo / "data" / "haystack.txt").write_text(
        ("the quick brown fox jumps over the lazy dog "
         "0123456789 abcdefghij\n") * 60_000, encoding="utf-8")
    for args in (("add", "-A"), ("commit", "-q", "-m", "haystack")):
        subprocess.run(("git", "-C", str(git_repo), *args), check=True,
                       capture_output=True, env=env)
    return git_repo / "data" / "haystack.txt"


# ------------------------------------------------------------------- running


def _artifact(cfg, outcome, candidates):
    """The findings.json a run would write, assembled exactly as `cli.py` does."""
    kept, suppressed = apply_suppressions(candidates, [], self_added=False)
    outcome.suppressed = suppressed
    outcome.refuted = [c for c in kept if c.verdict == VERDICT_REFUTED]
    outcome.reported = [c for c in kept if c.verdict != VERDICT_REFUTED]
    return build_json(cfg, outcome, decide(cfg, outcome))


class CliRun:
    def __init__(self, outcome, artifact, budget, fake):
        self.outcome = outcome
        self.artifact = artifact
        self.budget = budget
        self.fake = fake


def run_cli(cfg, workspace, revision, tmp_path, name, plan, profile=CALM_PROFILE):
    """Drive one review through the runner, with the fake CLI in `claude`'s place."""
    fake = FakeCli(tmp_path / "cli" / name, plan)
    budget = RunBudget(profile=profile, turns_enforced=False)
    subject = ClaudeCodeRunner(cfg, workspace, budget, executable=str(fake.path),
                               config_digest="conformance-digest")
    outcome = subject.run("repo", "Review this change.", revision)
    return CliRun(outcome, _artifact(cfg, outcome, list(outcome.reported)),
                  budget, fake)


class ApiRun:
    def __init__(self, outcome, artifact, agent):
        self.outcome = outcome
        self.artifact = artifact
        self.agent = agent


class ScriptedClient(FakeClient):
    """`FakeClient`, plus the ability to script a failure.

    A scripted entry that is an exception is raised instead of returned, which
    is how the API path's authentication failure is reached without teaching
    `fakes.py` about a case only this file has.
    """

    def _next(self, params):
        response = super()._next(params)
        if isinstance(response, BaseException):
            raise response
        return response


class Clock:
    """A monotonic clock that steps past the deadline after `after` readings.

    The wall-clock ceiling is the only one of the agent's limits that cannot be
    reached without either waiting or moving the clock, and a test that waits
    forty-five minutes is a test nobody runs. Everything else on the path — the
    loop, the deadline arithmetic, the stop reason — is the real code.
    """

    def __init__(self, after: int) -> None:
        self.after = after
        self.reads = 0

    def monotonic(self) -> float:
        self.reads += 1
        return 0.0 if self.reads <= self.after else 1e6


def run_api(cfg, workspace, responses, clock=None, monkeypatch=None):
    client = ScriptedClient(script=list(responses))
    agent = SecurityAgent(cfg, workspace, client=client)
    if clock is not None:
        monkeypatch.setattr("security_agent.agent.time", clock)
    outcome = agent.run("repo", "Review this change.")
    return ApiRun(outcome, _artifact(cfg, outcome, list(agent.candidates)), agent)


def turn(name, arguments, identifier):
    return FakeResponse([tool_use(name, arguments, id=identifier)],
                        stop_reason="tool_use")


def last_turn(stop_reason="end_turn", body="Reviewed the user lookup path."):
    return FakeResponse([text(body)], stop_reason=stop_reason)


class _Response:
    """The little the SDK reads off a response when building an error.

    Deliberately not an `httpx.Response`, for the reason `test_agent_degradation`
    gives: which HTTP library the SDK sits on has already changed once, and a
    test that imports the wrong one fails for a reason unrelated to the
    behaviour under test.
    """

    status_code = 401
    request = None

    @property
    def headers(self):
        return {}


def unauthorised():
    return anthropic.AuthenticationError(
        "invalid x-api-key", response=_Response(), body=None)


# ============================================================== the scenarios


class TestTerminalSuccess:
    """`terminal_success` — a review that ran to the end on both runners.

    The control case, and the only scenario where `complete` may be true.
    Without it, a suite whose every assertion is "this did not complete" passes
    over a runner that can never complete anything.
    """

    def test_terminal_success_agrees_across_runners(
            self, cfg, workspace, revision, tmp_path):
        cli = run_cli(cfg, workspace, revision, tmp_path, "terminal_success",
                      script(call(*READ), call("report_finding", FINDING_ARGS),
                             call(*FINISH), CLOSE))
        api = run_api(cfg, workspace, [
            turn(*READ, "t1"),
            turn("report_finding", FINDING_ARGS, "t2"),
            turn(*FINISH, "t3"),
        ])

        assert_conformant(api.artifact, cli.artifact, "terminal_success")
        assert_honest(cli.artifact, "terminal_success")
        assert_honest(api.artifact, "terminal_success")
        assert cli.artifact["stop_reason"] == STOP_COMPLETED
        assert cli.artifact["complete"] is True
        assert cli.artifact["finished_explicitly"] is True
        assert cli.artifact["summary"] == SUMMARY
        assert len(cli.artifact["findings"]) == 1

    def test_terminal_success_went_through_the_real_bridge(
            self, cfg, workspace, revision, tmp_path):
        """The scenario above would also pass if the fake CLI had invented the
        whole session, so this asserts what only the real chain can produce: the
        server answered every call, and the finding came back through layer 1
        having been checked against the file it cites."""
        cli = run_cli(cfg, workspace, revision, tmp_path, "terminal_success_chain",
                      script(call(*READ), call("report_finding", FINDING_ARGS),
                             call(*FINISH), CLOSE))
        replies = cli.fake.replies()

        assert len(replies) == 3
        assert all("result" in reply for reply in replies)
        assert "Evidence verified against the file" in \
               replies[1]["result"]["content"][0]["text"]
        assert cli.artifact["findings"][0]["line"] == 3
        assert cli.artifact["findings"][0]["verification"]["path_verified"] is True


class TestMalformedJson:
    """`malformed_json` — the CLI's terminal output is not a JSON document.

    CLI only. There is no equivalent on the Messages API path: the SDK hands
    back typed objects, so there is no text stream between the provider and us
    to corrupt, and the nearest thing — a stream that dies while being read —
    already has its own named ending, `transport_error`, rather than this one.

    The defect this catches is scavenging. A runner that searched the output for
    something JSON-shaped would find `{"subtype":"success"}` inside the error
    text below and report a completed review from a corrupted stream: making the
    input less parseable would have made the result more permissive.
    """

    def test_malformed_json_never_becomes_a_completed_review(
            self, cfg, workspace, revision, tmp_path):
        cli = run_cli(cfg, workspace, revision, tmp_path, "malformed_json",
                      script(call(*READ), call("report_finding", FINDING_ARGS),
                             CLOSE, ending=MALFORMED_ENDING))

        assert_honest(cli.artifact, "malformed_json")
        assert cli.artifact["stop_reason"] == STOP_ERROR
        assert "not the JSON document" in cli.artifact["stop_detail"]
        # What the child did record still arrives — the run failed, the work it
        # did is not thereby untrue — and it arrives under a stop reason that
        # says the review is unfinished.
        assert len(cli.artifact["findings"]) == 1
        assert cli.artifact["verdict"]["exit_code"] == EXIT_ERROR


class TestMissingResult:
    """`missing_result` — the terminal object names no ending at all.

    Expressible on both. The CLI prints a result object with no `subtype`; the
    API returns a response whose `stop_reason` is absent. The two arrive through
    completely different code and must reach the same verdict, because they
    answer the same question: the provider did not say how this ended, and an
    ending nobody named is not an ending anybody checked.
    """

    def test_missing_result_agrees_across_runners(
            self, cfg, workspace, revision, tmp_path):
        cli = run_cli(cfg, workspace, revision, tmp_path, "missing_result",
                      script(call(*READ), CLOSE, ending=MISSING_RESULT_ENDING))
        api = run_api(cfg, workspace,
                      [turn(*READ, "t1"), last_turn(stop_reason=None)])

        assert_conformant(api.artifact, cli.artifact, "missing_result")
        assert_honest(cli.artifact, "missing_result")
        assert_honest(api.artifact, "missing_result")
        assert cli.artifact["stop_reason"] == STOP_ERROR
        assert api.artifact["stop_reason"] == STOP_ERROR
        assert "does not recognise" in cli.artifact["stop_detail"]


class TestUnknownStatus:
    """`unknown_status` — an ending neither runner has heard of.

    Expressible on both, and the reason the allowlist shape exists twice:
    `_SUBTYPES` in the runner and `FINISHED_CLEANLY` in the agent. Under a
    denylist, a status a provider invents next month falls through to the last
    branch on both paths — and the last branch on both paths used to mean "the
    review finished".
    """

    def test_unknown_status_agrees_across_runners(
            self, cfg, workspace, revision, tmp_path):
        cli = run_cli(cfg, workspace, revision, tmp_path, "unknown_status",
                      script(call(*READ), CLOSE, ending=UNKNOWN_STATUS_ENDING))
        api = run_api(cfg, workspace, [
            turn(*READ, "t1"), last_turn(stop_reason="compacted_and_resumed")])

        assert_conformant(api.artifact, cli.artifact, "unknown_status")
        assert_honest(cli.artifact, "unknown_status")
        assert_honest(api.artifact, "unknown_status")
        assert cli.artifact["stop_reason"] == STOP_ERROR
        assert api.artifact["stop_reason"] == STOP_ERROR


class TestAuthFailure:
    """`auth_failure` — the provider refused to serve the request.

    Expressible on both, through the two shapes the same failure wears: the CLI
    prints a result that says `success` and `is_error` in one breath, and the
    API raises a 401. The contradiction on the CLI side is the interesting half
    — believing the `subtype` there would report a clean review of code the
    session was never authenticated to read.
    """

    def test_auth_failure_agrees_across_runners(
            self, cfg, workspace, revision, tmp_path):
        cli = run_cli(cfg, workspace, revision, tmp_path, "auth_failure",
                      script(call(*READ), CLOSE, ending=AUTH_FAILURE_ENDING))
        api = run_api(cfg, workspace, [turn(*READ, "t1"), unauthorised()])

        assert_conformant(api.artifact, cli.artifact, "auth_failure")
        assert_honest(cli.artifact, "auth_failure")
        assert_honest(api.artifact, "auth_failure")
        assert cli.artifact["stop_reason"] == STOP_ERROR
        assert api.artifact["stop_reason"] == STOP_ERROR
        assert cli.artifact["verdict"]["exit_code"] == EXIT_ERROR
        assert api.artifact["verdict"]["exit_code"] == EXIT_ERROR


class TestKilledThinking:
    """`killed_thinking` — the wall clock stopped the run between tool calls.

    Expressible on both: the runner kills a CLI that overruns its remaining
    time, and the agent's loop breaks on the same ceiling. Both must land on
    `time_limit` rather than on `error`. The two are not interchangeable, and
    the whole reason `stop_reason` was split into named values is that four
    incomplete runs could not be told apart from their own artifacts afterwards.

    The fake CLI shuts its MCP server down before it hangs, so the document is
    written and the partial review survives the kill. A real kill is a race
    between the two processes; this is the branch where the document won, and
    `no_artifact` is the branch where it did not.
    """

    def test_killed_thinking_agrees_across_runners(
            self, cfg, workspace, revision, tmp_path, monkeypatch):
        cli = run_cli(cfg, workspace, revision, tmp_path, "killed_thinking",
                      script(call(*READ), CLOSE, HANG), profile=KILL_PROFILE)
        api = run_api(cfg, workspace, [turn(*READ, "t1"), last_turn()],
                      clock=Clock(after=2), monkeypatch=monkeypatch)

        assert_conformant(api.artifact, cli.artifact, "killed_thinking")
        assert_honest(cli.artifact, "killed_thinking")
        assert_honest(api.artifact, "killed_thinking")
        assert cli.artifact["stop_reason"] == STOP_TIME_LIMIT
        assert api.artifact["stop_reason"] == STOP_TIME_LIMIT
        assert cli.artifact["finished_explicitly"] is False
        assert cli.artifact["coverage"]["files_examined"] == ["app/views.py"]


class TestKilledInTool:
    """`killed_in_tool` — the server died with a call still running.

    CLI only, because on the Messages API path a tool call is a function call in
    this process: there is no second process to lose, and nothing can be in
    flight across a boundary that does not exist. That asymmetry is why the
    crash journal exists at all.

    The defect this catches is the quiet one. A killed child leaves no session
    document, and a runner that read "no document" as "no findings" would render
    the most violent possible failure as the cleanest possible result.
    """

    def test_killed_in_tool_reports_progress_and_never_a_result(
            self, cfg, workspace, revision, tmp_path, haystack):
        cli = run_cli(cfg, workspace, revision, tmp_path, "killed_in_tool",
                      script(call(*READ), call_then_kill("search_code", SLOW_SEARCH),
                             HANG),
                      profile=KILL_PROFILE)

        assert_honest(cli.artifact, "killed_in_tool")
        assert cli.artifact["stop_reason"] == STOP_TIME_LIMIT
        # Nothing was handed over, so nothing may be claimed.
        assert cli.artifact["findings"] == []
        # What it managed to open *is* reported now. The child hands the session
        # over after every state change rather than at exit, because the exit it
        # was waiting for does not arrive — the CLI takes its MCP servers down
        # with it. So a killed run says how far it got instead of nothing at
        # all, and `complete` is what stops it being read as a result.
        assert cli.artifact["coverage"]["files_examined"] == ["app/views.py"]
        # The sentence and the trace are separate fields now: one is provider
        # prose the report escapes, the other a document this project rendered.
        detail = cli.artifact["stop_detail"]
        assert "time limit" in detail
        assert "This is not a result" in cli.artifact["trace_markdown"]
        assert "search_code" in cli.artifact["trace_markdown"]

    def test_killed_in_tool_leaves_the_call_unfinished_in_the_journal(
            self, cfg, workspace, revision, tmp_path, haystack):
        """The distinction the rendered trace rests on. A call turned away
        before it began must not read as one the kill interrupted, so the
        journal has to show a start with no finish — written by the real server
        during a real dispatch, not by the test."""
        cli = run_cli(cfg, workspace, revision, tmp_path, "killed_in_tool_journal",
                      script(call(*READ), call_then_kill("search_code", SLOW_SEARCH),
                             HANG),
                      profile=KILL_PROFILE)
        # The sentence and the trace are separate fields now: one is provider
        # prose the report escapes, the other a document this project rendered.
        detail = cli.artifact["stop_detail"]
        assert "time limit" in detail

        assert "2 tool calls started" in cli.artifact["trace_markdown"]
        assert "1 outcome unknown" in cli.artifact["trace_markdown"]
        assert "started, outcome unknown" in cli.artifact["trace_markdown"]


class TestToolBudget:
    """`tool_budget` — the reviewer spent its allowance and was refused.

    CLI only. The tool-call ceiling lives in the child, because the child is the
    only process that sees the calls; the Messages API path has no such ceiling
    at all — its limits are turns, wall clock and output tokens — so there is
    nothing on that side to compare against.
    """

    def test_tool_budget_refuses_the_call_and_says_why(
            self, cfg, workspace, revision, tmp_path):
        """The chain: the child counts every attempt, refuses past the ceiling,
        and answers with a tool result rather than with silence — a refusal that
        arrives as nothing is indistinguishable from a tool that hung."""
        cli = run_cli(cfg, workspace, revision, tmp_path, "tool_budget",
                      script(call(*READ), call(*READ), call(*READ), call(*READ),
                             CLOSE),
                      profile=TIGHT_PROFILE)
        replies = cli.fake.replies()

        assert len(replies) == 4
        refused = replies[3]["result"]
        assert refused["isError"] is True
        assert "budget of 3 was spent" in refused["content"][0]["text"]
        # And the parent folded the child's spend back into its own accounting.
        assert cli.budget.review.spent == 3
        assert cli.budget.review.exhausted is True

    def test_tool_budget_never_renders_as_a_completed_review(
            self, cfg, workspace, revision, tmp_path):
        cli = run_cli(cfg, workspace, revision, tmp_path, "tool_budget_honesty",
                      script(call(*READ), call(*READ), call(*READ), call(*READ),
                             CLOSE),
                      profile=TIGHT_PROFILE)

        assert cli.artifact["complete"] is False
        assert cli.artifact["verdict"]["exit_code"] != EXIT_OK

    def test_tool_budget_says_which_ceiling_stopped_the_run(
            self, cfg, workspace, revision, tmp_path):
        """Not merely "incomplete". A reader who cannot tell a truncation from
        a crash cannot decide what to do next, and the child already knew — it
        recorded the refusal, wrote it to the spend report, and exited 2 about
        it, while the parent read one key from that file and none of the rest."""
        cli = run_cli(cfg, workspace, revision, tmp_path, "tool_budget_named",
                      script(call(*READ), call(*READ), call(*READ), call(*READ),
                             CLOSE),
                      profile=TIGHT_PROFILE)

        assert cli.artifact["stop_reason"] == STOP_BUDGET
        assert "ran out of tool calls" in cli.artifact["stop_detail"]
        assert cli.artifact["finished_explicitly"] is False


class TestVerifierBudget:
    """`verifier_budget` — a claim nobody could be spared to check.

    CLI only. Verifier seats are reserved from `RunBudget`, and only the CLI
    verification path draws from one: `verify.verify_candidates` takes a client
    and no budget, so on the Messages API path there is no seat to refuse.

    The defect this catches is the one `verify_cli` is written against: a
    verifier that did not vote must never render as one that agreed. A refused
    seat produces an errored vote, `panel._verdict` counts no unusable vote in
    either direction, and the claim arrives carrying a reason that says nobody
    checked it — while still blocking the merge, because being unable to check
    a claim is not evidence against it.
    """

    def test_verifier_budget_leaves_the_claim_unverified(
            self, cfg, workspace, revision, tmp_path):
        from security_agent.verify_cli import verify_candidates_with_cli

        cli = run_cli(cfg, workspace, revision, tmp_path, "verifier_budget",
                      script(call(*READ), call("report_finding", FINDING_ARGS),
                             call(*FINISH), CLOSE))
        candidates = list(cli.outcome.reported)
        # Every seat this profile grants is already committed — the state a
        # panel of three reaches on the fourth vote it needs.
        seats = [cli.budget.reserve_verifier()
                 for _ in range(cli.budget.profile.verifier_sessions)]
        assert all(seat is not None for seat in seats)

        verify_candidates_with_cli(
            cfg, workspace, candidates, cli.budget,
            executable=str(cli.fake.path), config_digest="conformance-digest",
            revision=revision, metrics=cli.outcome.metrics)
        artifact = _artifact(cfg, cli.outcome, candidates)
        verification = artifact["findings"][0]["verification"]

        assert cli.budget.reserve_verifier() is None
        assert verification["votes"][0]["error"], "a refused seat casts no vote"
        assert "no verifier session was available" in verification["votes"][0]["error"]
        assert verification["reason"].startswith("reported unverified")
        assert cli.outcome.metrics.verification_failed == 1
        assert_honest(artifact, "verifier_budget")
        # `confirmed` here is not a claim that a verifier agreed — `panel._verdict`
        # counts an unusable vote in neither direction, so the claim arrives
        # exactly as the reviewer left it. What must not happen is the finding
        # quietly ceasing to block because nobody was free to look at it.
        assert verification["verdict"] == VERDICT_CONFIRMED
        assert artifact["verdict"]["exit_code"] == EXIT_FINDINGS


class TestForbiddenTool:
    """`forbidden_tool` — a tool the server does not offer.

    CLI only, and the asymmetry is worth stating: the offered set is enforced in
    `MCPServer._call_tool`, a transport-level check the Messages API path does
    not have. There, the tool list is what we send with the request, and
    `dispatch` will run any name in `HANDLERS` — including `submit_verdict`,
    which the reviewer's list never contained.

    Two things must hold, and they pull in opposite directions. The refusal must
    arrive as a protocol error rather than as tool output, because a refusal
    that looks like content is the one shape a model reads as "the tool ran";
    and the attempt must still be charged, because a name that costs nothing is
    a name a loop can retry for free.
    """

    def test_forbidden_tool_is_refused_as_a_protocol_error(
            self, cfg, workspace, revision, tmp_path):
        cli = run_cli(cfg, workspace, revision, tmp_path, "forbidden_tool",
                      script(call(*READ),
                             call("submit_verdict", {"verdict": "refuted"}),
                             CLOSE, ending=EXECUTION_ERROR_ENDING))
        refusal = cli.fake.replies()[1]

        assert "error" in refusal and "result" not in refusal
        assert "no tool named 'submit_verdict' is offered" in refusal["error"]["message"]
        assert cli.budget.review.spent == 2, "a refused name must still be charged"
        assert_honest(cli.artifact, "forbidden_tool")
        assert cli.artifact["stop_reason"] == STOP_ERROR
        assert cli.artifact["findings"] == []


class TestTheConfinementFlagsDoSomething:
    """The flags were asserted to be present and never to have an effect.

    Every confinement test read `build_command`'s list and compared strings.
    The stand-in parsed `--mcp-config` and nothing else, so all four flags
    could have been deleted and the whole suite would have passed — there were
    no built-in tools to be confined from and no other MCP server to ignore.
    `--allowedTools` in particular was compared against the same constant that
    built it, which moves with any rename.

    Now the stand-in reads them the way the CLI does: a variadic option takes
    everything up to the next `-`, `--tools ""` means the built-in set is
    empty, and a tool outside `--allowedTools` is not called at all.
    """

    def test_every_one_of_our_tools_still_works_with_the_built_ins_emptied(
            self, cfg, workspace, revision, tmp_path):
        """The direction that matters most. `--tools ""` disabling our own MCP
        tools would produce a review with no tool calls that reports nothing
        found — a clean sheet from a review that could not look.

        Each call, not a non-empty finding list: a run where only
        `report_finding` survived would still produce a finding, with the file
        never read and the review never signed off.
        """
        cli = run_cli(cfg, workspace, revision, tmp_path, "confinement_ours",
                      script(call(*READ), call("report_finding", FINDING_ARGS),
                             call(*FINISH), CLOSE))

        assert cli.fake.transcript[0]["rules"]["built_ins"] == []
        called = [entry["params"]["name"] for entry in cli.fake.transcript
                  if entry.get("method") == "tools/call"]
        assert called == ["read_file", "report_finding", "finish_review"]
        for reply in cli.fake.replies():
            assert "error" not in reply, reply
        assert cli.artifact["complete"] is True
        assert cli.artifact["finished_explicitly"] is True
        assert cli.artifact["findings"]

    def test_a_built_in_is_not_called_at_all(
            self, cfg, workspace, revision, tmp_path):
        """Not refused by our server — never reaching it. That is the
        difference between `--tools ""` and the two lists: an allowlist and a
        denylist both leave the tool present and reachable by anything that
        gets past a permission check."""
        cli = run_cli(cfg, workspace, revision, tmp_path, "confinement_builtin",
                      script(call("Bash", {"command": "ls"}),
                             call(*READ), call(*FINISH),
                             CLOSE))
        transcript = cli.fake.transcript

        assert any(entry.get("method") == "refused"
                   and entry.get("name") == "Bash" for entry in transcript)
        assert not any(entry.get("params", {}).get("name") == "Bash"
                       for entry in transcript), "it reached the server"

    def test_another_mcp_server_on_this_machine_is_not_in_the_session(
            self, cfg, workspace, revision, tmp_path):
        """`--strict-mcp-config` was tested by looking for it in the argument
        list, which is what this whole class exists to stop doing.

        The stand-in models what the flag decides: whether the servers
        configured on this machine are started at all. Modelled separately from
        the permission lists, because a foreign tool is already outside
        `--allowedTools` — so the first version of this test was refused with
        the flag and without it, and passed for the wrong reason.
        """
        cli = run_cli(cfg, workspace, revision, tmp_path, "confinement_strict",
                      script(call("mcp__somebodys_own_server__run", {}),
                             call(*READ), call(*FINISH), CLOSE))
        transcript = cli.fake.transcript

        assert transcript[0]["rules"]["loads_other_servers"] is False
        assert any(entry.get("method") == "refused" for entry in transcript)
        assert not any("somebodys_own_server" in str(entry.get("params", {}))
                       for entry in transcript)
        assert cli.artifact["complete"] is True

    def test_without_the_flag_the_other_server_is_not_excluded(
            self, cfg, workspace, revision, tmp_path, monkeypatch):
        """The control, and the reason the test above means anything.

        A foreign tool is outside `--allowedTools` as well, so a test that only
        asked whether the call was refused was refused with the flag and
        without it — it passed for a reason that had nothing to do with the
        flag. Here the flag is taken away and the exclusion stops happening.

        *Not excluded*, which is all this can honestly claim. There is one
        server in this harness, so a foreign call still lands on ours and is
        refused there for being unoffered — which is a fact about the stand-in
        and not about `--strict-mcp-config`. What the flag decides, and what is
        asserted, is whether the session would have loaded the other server at
        all.
        """
        from security_agent import runner_claude_code as under_test

        original = under_test.build_command
        monkeypatch.setattr(under_test, "build_command", lambda **kwargs: [
            argument for argument in original(**kwargs)
            if argument != "--strict-mcp-config"])
        # And permitted by the allowlist, which is the other half of the reason
        # the first version proved nothing: without this the call is refused by
        # `--allowedTools` whatever `--strict-mcp-config` says.
        monkeypatch.setattr(under_test, "TOOL_PREFIX", "mcp__")

        cli = run_cli(cfg, workspace, revision, tmp_path, "confinement_loose",
                      script(call("mcp__somebodys_own_server__run", {}),
                             call(*READ), call(*FINISH), CLOSE))
        transcript = cli.fake.transcript

        assert transcript[0]["rules"]["loads_other_servers"] is True
        # The exclusion the flag causes did not happen. Asserted as the absence
        # of a refusal rather than as a successful foreign call, because a
        # successful one is not reachable here — the request would land on our
        # own server and be refused for being unoffered, which would satisfy a
        # looser assertion for entirely the wrong reason.
        assert not any(entry.get("method") == "refused"
                       and "somebodys_own_server" in entry.get("name", "")
                       for entry in transcript), (
            "the foreign tool was still excluded, so the test above is not "
            "measuring the flag")


class TestTheRunnerRecordsWhatTheCliSaidItUsed:
    """The terminal object's `usage` was parsed and read by nobody.

    `CliResult.usage` was populated from the day it was added and no caller
    ever took it, so `ScanOutcome.usage` stayed a virgin `Usage` on this path
    and the artifact wrote five zeros for every run. Five batches were paid for
    and none of them can say what they cost.

    Driven through the real runner and out into a real artifact, because that
    is the hop that was missing — the parsing worked all along.
    """

    def test_the_figures_reach_the_artifact(
            self, cfg, workspace, revision, tmp_path):
        cli = run_cli(cfg, workspace, revision, tmp_path, "usage_reported",
                      script(call(*READ), call(*FINISH), ending=REPORTED_USAGE_ENDING))

        usage = cli.artifact["usage"]
        assert usage["input_tokens"] == 4421
        assert usage["cache_read_tokens"] == 158506
        assert usage["reported"] is True

    def test_a_terminal_object_with_no_usage_is_a_gap_and_not_a_zero(
            self, cfg, workspace, revision, tmp_path):
        """What every stored batch actually looks like, and it must not read
        as a run that cost nothing."""
        cli = run_cli(cfg, workspace, revision, tmp_path, "usage_absent",
                      script(call(*READ), call(*FINISH), ending=SUCCESS_ENDING))

        usage = cli.artifact["usage"]
        assert usage["reported"] is False
        assert usage["input_tokens"] is None
        assert usage["complete"] is False


class TestPartialFinding:
    """`partial_finding` — a finding recorded, then the run was cut short.

    Expressible on both, and the most dangerous shape in the set: the artifact
    carries a real finding, which makes it look like a review that reached a
    conclusion. It did not. The finding is reported and the run is still
    incomplete, so the exit code is 2 rather than 1 — the pipeline owner's
    problem, not the author's.
    """

    def test_partial_finding_agrees_across_runners(
            self, cfg, workspace, revision, tmp_path, monkeypatch):
        cli = run_cli(cfg, workspace, revision, tmp_path, "partial_finding",
                      script(call(*READ), call("report_finding", FINDING_ARGS),
                             CLOSE, HANG),
                      profile=KILL_PROFILE)
        api = run_api(cfg, workspace, [
            turn(*READ, "t1"),
            turn("report_finding", FINDING_ARGS, "t2"),
            last_turn(),
        ], clock=Clock(after=3), monkeypatch=monkeypatch)

        assert_conformant(api.artifact, cli.artifact, "partial_finding")
        assert_honest(cli.artifact, "partial_finding")
        assert_honest(api.artifact, "partial_finding")
        assert len(cli.artifact["findings"]) == 1
        assert cli.artifact["complete"] is False
        assert cli.artifact["finished_explicitly"] is False
        assert cli.artifact["verdict"]["exit_code"] == EXIT_ERROR


class TestInvalidFinding:
    """`invalid_finding` — the review ended cleanly and its claim was not real.

    Expressible on both. The run completes, which is correct, and the claim
    never becomes a finding, which is the point: layer 1 matches the quoted code
    against the file before anything is recorded, so a claim about code that is
    not there ends in `rejected_claims` and gates nothing.

    The defect this catches is a citation check that runs on one path and not
    the other. It is one function called from two places today, and a runner
    that reimplemented reporting would look identical from the outside and would
    have none of it.
    """

    def test_invalid_finding_agrees_across_runners(
            self, cfg, workspace, revision, tmp_path):
        cli = run_cli(cfg, workspace, revision, tmp_path, "invalid_finding",
                      script(call(*READ),
                             call("report_finding", INVALID_FINDING_ARGS),
                             call("report_finding", INVALID_FINDING_ARGS),
                             call(*FINISH), CLOSE))
        api = run_api(cfg, workspace, [
            turn(*READ, "t1"),
            turn("report_finding", INVALID_FINDING_ARGS, "t2"),
            turn("report_finding", INVALID_FINDING_ARGS, "t3"),
            turn(*FINISH, "t4"),
        ])

        assert_conformant(api.artifact, cli.artifact, "invalid_finding")
        assert_honest(cli.artifact, "invalid_finding")
        assert_honest(api.artifact, "invalid_finding")
        assert cli.artifact["complete"] is True
        assert cli.artifact["findings"] == []
        assert len(cli.artifact["rejected_claims"]) == 1
        assert cli.artifact["rejected_claims"][0]["reason"] == "evidence-not-found"
        assert cli.artifact["verdict"]["exit_code"] == EXIT_OK


class TestNoArtifact:
    """`no_artifact` — killed before it wrote anything at all.

    CLI only: on the Messages API path this process is the review, and a review
    that produces no outcome object produces no artifact to test. Here the CLI
    never even launches the tool server, so there is no session document, no
    spend report and no crash journal — the emptiest possible input to a runner
    whose one job is to refuse to invent a result out of it.
    """

    def test_no_artifact_is_refused_rather_than_read_as_clean(
            self, cfg, workspace, revision, tmp_path):
        cli = run_cli(cfg, workspace, revision, tmp_path, "no_artifact",
                      script(HANG), profile=IDLE_KILL_PROFILE)

        assert_honest(cli.artifact, "no_artifact")
        assert cli.artifact["stop_reason"] == STOP_TIME_LIMIT
        assert cli.artifact["findings"] == []
        assert cli.artifact["summary"] == ""
        assert cli.artifact["coverage"]["files_examined"] == []
        assert "No crash journal was written" in cli.artifact["stop_detail"]
        assert cli.artifact["verdict"]["exit_code"] == EXIT_ERROR


# --------------------------------------------------- the comparison itself


def _place(artifact, path, value):
    node = artifact
    parts = path.split(".")
    for part in parts[:-1]:
        node = node[part]
    node[parts[-1]] = value


def _lookup(artifact, path):
    node = artifact
    for part in path.split("."):
        node = node[part]
    return node


def test_the_known_divergence_ledger_is_still_accurate(
        cfg, workspace, revision, tmp_path):
    """Every entry in `KNOWN_DIVERGENCE` still describes a real disagreement.

    Asserted in the direction the scenarios cannot assert. They fail when a
    *new* divergence appears; this fails when an old one is fixed, so the entry
    is deleted rather than standing as a permanent exception that quietly
    excuses the next defect to land on the same field.

    It also ties the two comparison functions together. `differences()` is what
    a reader gets and `canonical_bytes` is what decides; a diff that reported
    nothing over artifacts whose bytes differ would make every scenario above
    pass silently. So the ledger's fields are copied across and the bytes are
    then required to be equal — which is the claim "the ledger is the whole
    difference", not merely "the diff lists these".

    The ledger is empty now, so those two steps collapse into one assertion:
    on a clean run the two runners produce the same bytes. Keeping the loop
    rather than deleting it is deliberate — the day an entry comes back, this
    test goes on saying what it always said.
    """
    cli = run_cli(cfg, workspace, revision, tmp_path, "ledger",
                  script(call(*READ), call("report_finding", FINDING_ARGS),
                         call(*FINISH), CLOSE))
    api = run_api(cfg, workspace, [
        turn(*READ, "t1"),
        turn("report_finding", FINDING_ARGS, "t2"),
        turn(*FINISH, "t3"),
    ])

    assert api.artifact["complete"] is True, "the ledger is read off a clean run"
    assert _diverging_paths(api.artifact, cli.artifact) == set(KNOWN_DIVERGENCE), (
        "the ledger no longer matches reality:\n  " +
        "\n  ".join(differences(api.artifact, cli.artifact)))

    if KNOWN_DIVERGENCE:
        assert canonical_bytes(api.artifact) != canonical_bytes(cli.artifact), (
            "the ledger names divergences that are no longer there")
    for path in KNOWN_DIVERGENCE:
        _place(cli.artifact, path, _lookup(api.artifact, path))
    assert canonical_bytes(api.artifact) == canonical_bytes(cli.artifact)


def test_the_incomplete_divergence_ledger_is_still_accurate(
        cfg, workspace, revision, tmp_path, monkeypatch):
    """The same, for the entry that only appears on a run that was cut short.

    Separate because it can only be read off an incomplete run, and folding it
    into the test above would mean loosening that one to an "at most" — which
    is the shape that stops noticing.
    """
    cli = run_cli(cfg, workspace, revision, tmp_path, "ledger_incomplete",
                  script(call(*READ), CLOSE, HANG), profile=KILL_PROFILE)
    api = run_api(cfg, workspace, [turn(*READ, "t1"), last_turn()],
                  clock=Clock(after=2), monkeypatch=monkeypatch)

    assert api.artifact["complete"] is False
    assert _diverging_paths(api.artifact, cli.artifact) == (
        set(KNOWN_DIVERGENCE) | set(INCOMPLETE_DIVERGENCE)), (
        "the ledger no longer matches reality:\n  " +
        "\n  ".join(differences(api.artifact, cli.artifact)))


def test_every_named_scenario_has_a_test():
    """The marker strings are what `tools/stage2.py` counts, so a scenario
    renamed in one place and not the other would be reported as covered."""
    source = Path(__file__).read_text(encoding="utf-8")

    for name in SCENARIOS:
        assert "def test_{}".format(name) in source, \
            "{} is named in SCENARIOS and has no test".format(name)
