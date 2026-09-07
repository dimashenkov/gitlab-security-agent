#!/usr/bin/env python3
"""Two passes over one suite, with the comparison written before either is paid for.

    tools/experiment.py freeze noise-floor
    tools/experiment.py verify noise-floor
    tools/experiment.py run noise-floor a
    tools/experiment.py run noise-floor b
    tools/experiment.py compare noise-floor

## Why this exists rather than freezing two rounds

`round.py` freezes one pass and compares it against the verdicts a case already
had. That is the right shape for "has the product moved since last month" and
the wrong shape for "does the product move on its own": two independently frozen
rounds say nothing about which pass-B row answers which pass-A row, what counts
as a disagreement, or what happens when a case is missing from one side. Those
would then be decided after the results are visible, which is how a rule gets
fitted to the disagreements it is supposed to judge.

    You would then possess 140 valid contemporary reviews but no valid
    stability experiment.

## Why it runs the cases itself

The first version drove `run_queue.py`. Five rounds of adversarial review found
twenty defects in it, and near the end the shape of them stopped looking like a
thinning list of oversights: nearly all came from two machines with separate
lifecycles disagreeing about the same files. The experiment decided what was
admissible; the queue decided what had been executed and how a failure resumed;
a result file was at once an artefact, a checkpoint and a skip signal; two sets
of manifests each held part of the truth.

The last of those defects is the argument in one line. A result produced while
conditions had changed was correctly refused *on the terminal* — and left on
disk, where a later resume counted it as an ordinary verdict.

    The transaction belongs to the experiment and the write belongs to the
    queue.

So the experiment writes its own results, and nothing is published until the
case has run and the conditions have been checked again. What that costs is
windows and resets and the resume machinery, none of which this needs: a pass is
run when the window is open, and re-running the command continues from what was
accepted. What it removes is every intermediate state those two machines could
disagree about.

## What two passes can and cannot answer

They can answer: **does any case give a different verdict with nothing changed,
and which ones.** That is a detection, and one flip is enough for it.

They cannot answer: **how often.** Two throws of a coin that land differently
prove the coin is not glued; they do not estimate how often it lands heads. A
threshold for a regression gate needs the distribution, and the distribution
needs far more passes than a subscription will pay for in a day. Anyone quoting
a rate from this file is quoting something it does not contain.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import shutil
import subprocess
import sys
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent))

import round as round_tool

# `artifact` is what puts `src` on the path, so it has to precede the
# `security_agent` import below — which the grouping happens to give for free.
from artifact import case_digest
from sentinel import read_cases

from security_agent import workspace
from security_agent.config import ConfigError
from security_agent.suppress import SuppressionError
from security_agent.suppress import load as load_suppressions

ROOT = Path(__file__).resolve().parents[1]
# Why this tool's spending is authorised. Mapped in `tools/spend_gate.py`.
SPEND_CLASS = "experiment_run"
SUITE = ROOT / "suites" / "sentinel.yml"
PASSES = ("a", "b")


def home(name: str) -> Path:
    return ROOT / "measurements" / "experiment-{}".format(name)


# How long a `--version` may take before the answer is "could not establish".
# It is a local exec of a binary already on disk, so this is generous; the
# ceiling exists because `drift` runs twice per case and a hung subprocess
# there would stall a pass that has already been paid for.
VERSION_TIMEOUT = 10.0

# The keys naming a binary rather than a file in the tree. `verify` closes with
# "Re-freeze as a new experiment, or put it back", which is the right advice for
# an edited prompt and the wrong advice for these: a `git` or a `claude` that
# has been upgraded is upgraded, and a reader who takes "put it back" literally
# downgrades the machine to rescue an experiment. Only one of the two options is
# available here, so only one is offered.
TOOLCHAIN_KEYS = frozenset({"corpus_git", "reviewer_git", "review_cli",
                            "review_cli_version"})


def digest_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()[:16]


def _today() -> date:
    """The clock `suppress.load` would use if nobody passed it one.

    A function so a test can move it. Nothing else here needs the date, and the
    reviewer's own default is the only thing this has to agree with.
    """
    return datetime.now(timezone.utc).date()


def _version_of(binary: str) -> str:
    """`binary --version`, first line, or a reason it could not be had.

    Never a bare empty string on failure. An unestablished version that renders
    like a real one is the defect this whole environment block exists against —
    two runs would compare equal on "" and the freeze would read as agreement
    with a binary nobody identified.
    """
    try:
        proc = subprocess.run((binary, "--version"), capture_output=True,
                              text=True, check=False, timeout=VERSION_TIMEOUT)
    except (OSError, subprocess.SubprocessError) as exc:
        return "unestablished: {}".format(exc)
    if proc.returncode != 0:
        return "unestablished: exit {}".format(proc.returncode)
    first = proc.stdout.strip().splitlines()
    return first[0] if first else "unestablished: it printed nothing"


def _git_identity(path: Optional[str]) -> str:
    """Which `git` a caller searching `path` would run, and what it says it is.

    `path` is `None` for the ambient search. Two different binaries answer to
    `git` in one run of this experiment and they are not the same program:
    `pair_corpus.build_repo` passes `os.environ["PATH"]` through to its
    subprocesses, while the reviewer's `workspace._git_env` pins `PATH` to the
    system directories in order to keep a repository's own configuration out of
    the read. Measured on this machine on 2026-09-07: the corpus is built with
    2.55.0 from Homebrew and reviewed with 2.50.1 from Apple. The one that
    builds the commits decides what the diff *is*; the one that reads them
    decides what the reviewer is shown.
    """
    found = shutil.which("git", path=path) if path else shutil.which("git")
    if found is None:
        return "absent"
    return "{} · {}".format(found, _version_of(found))


def _cli_version(binary: Path) -> str:
    """The CLI's version, if it can be had without running it.

    It cannot always. A version read by executing the binary is the honest
    answer and this project's own rules forbid spending, so the fallback is an
    npm-shaped `package.json` beside the resolved file, and after that an
    explicit refusal to guess. `unestablished:` is written into the value on
    purpose — that string travels into the manifest, into `drift`'s output and
    into any report quoting it, and "I could not check" must not render like
    "2.1.236".

    What still guards the upgrade when this cannot answer is `review_cli`: on
    this machine the resolved path is
    `/opt/homebrew/Caskroom/claude-code/2.1.236/claude`, so a cask upgrade moves
    it, and the recorded byte size moves with any rebuild of a 300 MB bundle.
    """
    for candidate in (binary.parent / "package.json",
                      binary.parent.parent / "package.json"):
        if not candidate.is_file():
            continue
        try:
            body = json.loads(candidate.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if not isinstance(body, dict):
            continue
        # The name is checked, because a `package.json` two directories up can
        # belong to something else entirely and its version would then be
        # recorded as the CLI's — a wrong answer, which is worse than none.
        name = str(body.get("name", ""))
        version = str(body.get("version", ""))
        if "claude" in name and version:
            return "{} {}".format(name, version)
    return ("unestablished: no version file beside {}, and the CLI is not run "
            "to ask it".format(binary))


def _cli_identity() -> Dict[str, str]:
    """Which `claude` a review would start, and what can be said about it.

    Recorded because the CLI is part of the instrument and has already changed
    what a paid run does in this project: the upgrade that split one review into
    two processes made every free check blind to a terminal reason it had never
    heard of. Nothing in the prompts, the reviewer's source or the model name
    moves when that happens.

    Resolved through `runner_claude_code.cli_available` rather than a second
    `shutil.which` here, so the recorded binary is the one the runner would
    actually start and not a lookalike found by a different rule.
    """
    from security_agent.runner_claude_code import cli_available

    found = cli_available()
    if found is None:
        return {"review_cli": "absent",
                "review_cli_version": "absent"}
    real = Path(os.path.realpath(found))
    try:
        size = real.stat().st_size
    except OSError as exc:
        return {"review_cli": "{} -> {} · unreadable: {}".format(found, real, exc),
                "review_cli_version": "unestablished: {}".format(exc)}
    return {"review_cli": "{} -> {} · {} bytes".format(found, real, size),
            "review_cli_version": _cli_version(real)}


def toolchain() -> Dict[str, str]:
    """The binaries that decide what runs, beside the files that decide what is
    read.

    The environment already digested the reviewer's source and the prompts,
    which is everything about the instrument that lives in this repository —
    and nothing about the three programs outside it that a review passes
    through. Two passes either side of a `brew upgrade` were two instruments
    and `drift` reported that nothing had moved.
    """
    return dict(
        corpus_git=_git_identity(None),
        # The reviewer's own PATH, taken from the function that builds it
        # rather than copied. A copy of that string here would agree with
        # `workspace` until somebody edited one of them, and the one this
        # recorded would then be the git nothing runs.
        reviewer_git=_git_identity(workspace._git_env()["PATH"]),
        **_cli_identity())


def suppression_state(directory: Path, ignore_file: Path,
                      today: Optional[date] = None) -> str:
    """Which accepted-risk rules are in force in this case, as a function of
    the date and nothing else.

    `suppress.load` compares each `expires` against today, so a case whose
    ignore file has not changed by one byte suppresses a finding on Monday and
    does not on Tuesday. `case_digest` covers the bytes and cannot see that:
    two passes either side of an expiry are two different gates, reported as
    the product moving on its own.

    **What is recorded is not the freeze date.** Freezing today's date and
    refusing when today differs would expire every experiment after one day,
    and this project's passes routinely wait overnight for a subscription
    window — the refusal would fire for the calendar and never for the rules.
    What is recorded is the state the expiry dates put the rules in: how many
    have already lapsed, and the earliest date on which one more will. That
    value is constant for as long as today stays between two consecutive expiry
    dates, and changes on exactly the day a rule crosses. A case with no expiry
    dates at all has a value that never changes, which is correct: nothing
    about it depends on when it is run.

    A malformed file is `unreadable` rather than an exception. The reviewer
    fails such a case too, and reporting it as movement in the middle of a paid
    pass would blame the clock for a file that was broken at the freeze.
    """
    # Defaulted here rather than left to `suppress.load`'s own default, so that
    # the freeze and every later check read one clock. Two calls to
    # `datetime.now` are the same expression and not the same value, and a test
    # that can move only one of them proves nothing about the pair.
    today = today or _today()
    parts = []
    for member in sorted(p.name for p in directory.iterdir() if p.is_dir()):
        # The overlay `build_repo` performs: everything under `change/` lands at
        # the repository root in the second commit, so a suppression file there
        # is the one the reviewer reads, and the baseline copy is the one it
        # replaced.
        for candidate in (directory / member / "change" / ignore_file,
                          directory / member / ignore_file):
            if not candidate.is_file():
                continue
            try:
                rules, expired = load_suppressions(candidate, today)
            except SuppressionError:
                parts.append("{}: unreadable".format(member))
                break
            # `load` returns the rules still in force and warns once per rule it
            # dropped for having lapsed, so the two lengths are the partition
            # this needs. The pending dates come from the survivors.
            pending = sorted(r.expires for r in rules if r.expires is not None)
            parts.append("{}: {} expired, next {}".format(
                member, len(expired), pending[0] if pending else "never"))
            break
    return "; ".join(parts) if parts else "no ignore file"


def ignore_file_name() -> Path:
    """Where the reviewer would look for accepted-risk rules.

    From the configuration rather than the literal `.security-agent-ignore.yml`,
    because `SECURITY_SCAN_IGNORE_FILE` moves it and a second copy of the
    default here is a second thing to keep in step.
    """
    from security_agent.config import Config

    return Config.from_env().ignore_file


def case_rows(cases: List[str]) -> List[Dict[str, Any]]:
    ignore = ignore_file_name()
    rows = []
    for case_id in cases:
        directory = ROOT / "corpus-real" / case_id
        manifest = directory / "case.yml"
        body = {}
        if manifest.is_file():
            import yaml
            body = yaml.safe_load(manifest.read_text(encoding="utf-8")) or {}
        rows.append({
            "case_id": case_id,
            "language": body.get("language", ""),
            "construction": body.get("construction", ""),
            "case_digest": case_digest(directory),
            # The answer key, digested separately, because `case_digest`
            # deliberately does not cover `case.yml` — and it is right not to,
            # for its own question. It asks "is this result about the code the
            # agent saw", so that correcting a category does not throw away a
            # run whose findings are still on file.
            #
            # This experiment asks something else. `expected_category` and
            # `expected_file` decide whether a finding counts, so editing them
            # between the passes changes the *scoring* while the code the agent
            # saw stays identical — and the flip would be reported as the
            # product moving on its own. Two questions, two digests.
            "answer_key_digest": (digest_file(manifest) if manifest.is_file()
                                  else "absent"),
            # Per case rather than in the environment block, because the
            # accepted-risk file lives inside the case: `build_repo`
            # materialises `corpus-real/<case>/<member>` as the repository the
            # reviewer is pointed at, and that is where `root / cfg.ignore_file`
            # resolves. One aggregate value would name no case when it moved.
            "suppression_expiry": (suppression_state(directory, ignore)
                                   if directory.is_dir() else "the case is gone"),
        })
    return rows


def scorer_digest() -> str:
    """The code that turns findings into `pair_success`.

    `agent_version` covers the reviewer and moves only when somebody bumps it.
    The scorer is a separate thing and is edited far more often: change how a
    finding is matched to a target between the passes and every flip it causes
    reads as the product moving. Nothing in the prompt hashes would show it.
    """
    parts = []
    for name in ("pair_corpus.py", "artifact.py", "check_accounted.py"):
        path = ROOT / "tools" / name
        parts.append("{}:{}".format(
            name, digest_file(path) if path.is_file() else "absent"))
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()[:16]


def reviewer_digest() -> str:
    """The reviewer's own source, not its version string.

    `agent_version` moves when somebody bumps it, and nothing forces that.
    Editing the reviewer between the passes without a bump would run different
    code on each side, and the difference would be reported as the product
    moving on its own — the sentence this experiment exists to produce, arrived
    at for the wrong reason.
    """
    source = ROOT / "src" / "security_agent"
    if not source.is_dir():
        return "absent"
    parts = []
    for path in sorted(source.rglob("*.py")):
        parts.append("{}:{}".format(path.relative_to(source), digest_file(path)))
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()[:16]


def requested_now(model: Optional[str] = None,
                  verify_model: Optional[str] = None) -> Dict[str, Any]:
    """The models this experiment will ask for, and whether it verifies.

    Resolved through `Config.from_env` rather than read from the environment
    here, because the resolution is not a lookup: an unset
    `SECURITY_SCAN_VERIFY_MODEL` means *the reviewer's own model*, and an unset
    `SECURITY_SCAN_MODEL` means Opus. Two copies of that rule is how one of
    them ends up stale.

    Recorded because `freeze` and `run` are separate commands and the shell
    between them is not the same shell. The variables written in front of
    `freeze` apply to a process that spends nothing; the two `run` invocations
    that spend $13 read whatever their own environment holds, and unset means
    Opus — the reference's own model. Every review would have been bought from
    the model the experiment exists to replace, and the only thing that would
    ever have said so is the comparator, at the end, with the money gone.

    **The arguments choose; the environment is the fallback.** That guard is
    about `run`, and `run` still holds it: it compares the recorded values
    against `Config.from_env()` before spending and exits 2 when they disagree.
    What the arguments change is that choosing the model stops being a variable
    typed in front of one command in one shell, unobserved. Asked for by the
    owner on 2026-09-07; adjudicated the same day.

    The verifier falls back to *the selected* model, not to the ambient one.
    `cfg.verifier_model` has already resolved against whatever
    `SECURITY_SCAN_MODEL` the shell held, so `--model claude-sonnet-5` with no
    verifier argument and no verifier variable would otherwise record Opus as
    the verifier while Sonnet reviews — a different instrument, recorded as
    this one. Named by Codex on the adjudication as the trap in this change.
    """
    from security_agent.config import Config
    cfg = Config.from_env()          # raises ConfigError; `main` refuses on it
    selected = model if model is not None else cfg.model
    selected_verifier = (
        verify_model if verify_model is not None
        else (cfg.verify_model or selected))
    return {
        "model_requested": selected,
        "verifier_requested": selected_verifier,
        # A string, not a bool. `drift` prints `was -> now`, and `False -> True`
        # in a list of digests reads as a digest that went missing.
        "verify": "on" if cfg.verify else "off",
    }


def environment_now(model: Optional[str] = None,
                    verify_model: Optional[str] = None) -> Dict[str, Any]:
    """What the freeze records and what every check re-computes — one
    definition, because two is how the scorer digest ended up in the manifest
    and not in the check.

    Where a value came from is deliberately **not** here. This block is
    compared field by field between two arms and against the tree at run time,
    and a provenance field would make two arms differ in something that is not
    the model — refusing a pair whose models are exactly as intended. It is
    audit metadata and lives beside the block, not in it. Codex, 2026-09-07.
    """
    return dict(round_tool.environment(), scorer=scorer_digest(),
                reviewer=reviewer_digest(), **toolchain(),
                **requested_now(model, verify_model))


def build(name: str, model: Optional[str] = None,
          verify_model: Optional[str] = None) -> Dict[str, Any]:
    cases = read_cases(SUITE)

    # One order, used by both passes. A different order per pass would mean the
    # two met the subscription's windows differently, and the comparison would
    # carry that difference as if it were the product moving.
    order = list(cases)
    random.Random(name).shuffle(order)

    return {
        "experiment": name,
        "question": (
            "With nothing changed between them, do any cases in this suite "
            "give a different verdict in the second pass than in the first?"),
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "environment": environment_now(model, verify_model),
        # Beside the environment, never inside it: this block is compared
        # between arms and against the tree, and a field recording *where* a
        # value came from would make two arms differ in something that is not
        # the model. Kept because a value that beat the shell should not do so
        # silently.
        "configuration_source": {
            "model": "argument" if model is not None else "environment",
            "verifier": ("argument" if verify_model is not None
                         else "environment"),
        },
        "suite": {
            "file": str(SUITE.relative_to(ROOT)),
            "digest": digest_file(SUITE),
            "count": len(cases),
        },
        "protocol": {
            "passes": list(PASSES),
            "order": order,
            "order_seed": name,
            "provider": "claude-cli",
            "profile": "normal",
            "primary_endpoint": (
                "per case, whether pass b's pair_success equals pass a's. "
                "Reported as agreed / flipped, with each flip named and its "
                "direction given."),
            "comparable": (
                "a case counts only if both passes produced a verdict and both "
                "rows carry the case_digest frozen here. A row about a "
                "different version of a case is not an observation of this one."),
            "missing": (
                "any case with no verdict in either pass makes the experiment "
                "incomplete. It is reported and the comparison exits 2; a "
                "partial pair is not evidence of agreement."),
            "not_answerable": (
                "how often a case flips. Two passes detect movement; they do "
                "not estimate its rate, and no threshold may be set from this."),
        },
        "counts": {"cases": len(cases), "reviews": 4 * len(cases)},
        "cases": case_rows(cases),
    }


def freeze(name: str, dry_run: bool, model: Optional[str] = None,
           verify_model: Optional[str] = None) -> int:
    path = home(name) / "manifest.json"
    if path.exists() and not dry_run:
        print("{} already exists. A frozen experiment is not rewritten — that "
              "is what freezing it was for.".format(path.relative_to(ROOT)))
        return 1

    body = build(name, model, verify_model)
    counts = body["counts"]
    if not counts["cases"]:
        # `sentinel.main` refuses an empty selection with exit 2; this had no
        # equivalent, and every command below it succeeds over nothing.
        # `sentinel.read_cases` recognises only lines that start with `- `, so
        # writing the suite as a YAML flow list — `cases: [a, b]`, legal and
        # meaning the same thing — selects no case, and the whole experiment
        # then runs: `freeze` writes a manifest with `counts.cases: 0`,
        # `verify` reports nothing has moved, `run` reports nothing left in
        # this pass, and `compare` prints "No movement observed in one paired
        # repetition" and exits 0. Zero reviews bought, reported as a suite
        # that did not move.
        print("the suite at {} names no case. Either its list is empty or it "
              "is written in a form sentinel.read_cases does not read — it "
              "takes only lines beginning with '- '. An experiment over no "
              "case runs to the end and reports that nothing moved, having "
              "bought no review at all.".format(SUITE.name), file=sys.stderr)
        return 2
    print("experiment {} · passes {} and {}".format(name, *PASSES))
    print("  {} case(s) per pass, {} review(s) in total".format(
        counts["cases"], counts["reviews"]))
    print("  one order for both passes, seeded by the experiment name")
    print("\n  endpoint: {}".format(body["protocol"]["primary_endpoint"]))
    print("  not answerable: {}".format(body["protocol"]["not_answerable"]))
    if dry_run:
        print("\nNothing written.")
        return 0

    path.parent.mkdir(parents=True, exist_ok=True)

    # A copy of the prompts, taken now and read by every pass.
    #
    # Hashing before a case and again after it compares two snapshots; it does
    # not prove the file was the same in between. An edit made and reverted
    # while a review runs — a branch switch, an editor saving and undoing — is
    # invisible to both checks and visible to the reviewer, which is the one
    # reader that matters. Reading from a copy nobody edits removes the
    # question for the prompts entirely.
    #
    # The reviewer's own source is still read live: the child imports the
    # installed package, and running a pass from a copy of it is a different
    # and larger change. `reviewer_digest` catches an edit that is still there
    # at either check, and an edit reverted mid-case remains a hole. It is
    # named here rather than left for somebody to discover.
    frozen_prompts = home(name) / "prompts"
    try:
        shutil.copytree(ROOT / "prompts", frozen_prompts, dirs_exist_ok=True)
    except OSError as exc:
        print("\ncould not freeze the prompts: {}".format(exc), file=sys.stderr)
        return 2

    if not publish(path, json.dumps(body, indent=2, ensure_ascii=False) + "\n"):
        shutil.rmtree(frozen_prompts, ignore_errors=True)
        return 2

    print("\nWritten to {}.".format(path.relative_to(ROOT)))
    print("Pass a:   tools/experiment.py run {} a".format(name))
    print("Pass b:   tools/experiment.py run {} b".format(name))
    print("Then:     tools/experiment.py compare {}".format(name))
    return 0


def publish(target: Path, text: str) -> bool:
    """Write beside the target and rename, or leave nothing behind.

    The process id is in the staging name because a fixed one lets two runs
    write over each other's staging file and then remove it in each other's
    cleanup. The existence check is immediately before the rename because
    `replace` overwrites, and a check made earlier is a check about an earlier
    moment — the rollback was taught not to delete a file it did not create, and
    publishing had to be taught not to destroy one either.
    """
    temporary = target.with_name("{}.writing.{}".format(target.name, os.getpid()))
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        temporary.write_text(text, encoding="utf-8")
        # `os.link` fails if the target exists, in one operation, which
        # `replace` after an `exists()` check does not: two runs can both see
        # nothing there and the second silently overwrites the first. The
        # window was narrowed to a line and a line is still a window — and the
        # harm is a result quietly replaced, which is the kind that leaves a
        # comparison looking perfectly ordinary.
        os.link(temporary, target)
        temporary.unlink()
        return True
    except OSError as exc:
        temporary.unlink(missing_ok=True)
        print("could not write {}: {}".format(target.relative_to(ROOT), exc),
              file=sys.stderr)
        return False


def drift(body: Dict[str, Any]) -> List[str]:
    """What has moved since the freeze, in words a reader can act on."""
    moved = []
    now = environment_now()
    absent = object()
    for key, was in body["environment"].items():
        # A sentinel, not `now.get(key)`. `get` answers `None` for a key that
        # has left the environment, so a manifest freezing `None` and an
        # environment that no longer records the key at all compared *equal* —
        # `drift` returned "nothing has moved" and `verify` exited 0, which is
        # the permission to spend. The repository's own recurring defect, in
        # the one function whose exit code authorises money.
        #
        # Latent today: every producer of `environment_now` returns a string,
        # so no manifest on disk holds a `None`. Found by a generated input,
        # which is the point of generating them.
        current = now.get(key, absent)
        if current is absent:
            moved.append("{}: {} -> the environment no longer records it"
                         .format(key, was))
        elif current != was:
            line = "{}: {} -> {}".format(key, was, current)
            if key in TOOLCHAIN_KEYS:
                # The generic closing advice is "or put it back". For a binary
                # that is not an instruction anybody should follow.
                line += (" — this is the instrument and not the tree; it cannot "
                         "be put back, and a new experiment has to be frozen")
            moved.append(line)
    if digest_file(SUITE) != body["suite"]["digest"]:
        moved.append("the sentinel suite file has been rewritten")
    ignore = ignore_file_name()
    for row in body["cases"]:
        directory = ROOT / "corpus-real" / row["case_id"]
        manifest = directory / "case.yml"
        if not directory.is_dir():
            moved.append("{}: the case is gone".format(row["case_id"]))
            continue
        if case_digest(directory) != row["case_digest"]:
            moved.append("{}: the case has been edited".format(row["case_id"]))
        key = digest_file(manifest) if manifest.is_file() else "absent"
        if key != row.get("answer_key_digest"):
            moved.append("{}: the answer key in case.yml has been edited — the "
                         "code is unchanged and the scoring is not"
                         .format(row["case_id"]))
        # Absent rather than `.get(...)` compared straight, because a manifest
        # frozen before this key existed would otherwise report `None -> no
        # ignore file`, which reads like a change and is not one. What it is, is
        # a manifest that cannot be checked here at all — said in those words.
        frozen_rules = row.get("suppression_expiry", absent)
        in_force = suppression_state(directory, ignore, _today())
        if frozen_rules is absent:
            moved.append("{}: frozen before the suppression rules' expiry state "
                         "was recorded, so nothing here can say whether one has "
                         "lapsed since. Freeze a new experiment."
                         .format(row["case_id"]))
        elif in_force != frozen_rules:
            moved.append("{}: the accepted-risk rules in force have changed: {} "
                         "-> {}. The ignore file may be identical byte for byte "
                         "— `suppress.load` compares `expires` against today, so "
                         "the same file gates differently either side of one."
                         .format(row["case_id"], frozen_rules, in_force))
    return moved


def load(name: str) -> Optional[Dict[str, Any]]:
    path = home(name) / "manifest.json"
    if not path.is_file():
        print("no experiment {} — freeze it first".format(name), file=sys.stderr)
        return None
    body = json.loads(path.read_text(encoding="utf-8"))
    if not body.get("cases"):
        # `freeze` refuses to write one now; a manifest frozen before it did is
        # still on disk, and every command reading it would succeed over
        # nothing. Refused here as well, once, for all three of them.
        print("experiment {} was frozen with no cases. Nothing was bought and "
              "nothing can be compared; a pass over no case is not a pass in "
              "which nothing moved. Re-freeze it with a suite that names "
              "cases.".format(name), file=sys.stderr)
        return None
    return body


def verify(name: str) -> int:
    """Fail closed, and say what moved.

    Checking after the fact proves nothing: a change made and reverted between
    the passes leaves the files looking untouched. This is what runs immediately
    before spending, and its exit code is the permission to spend.
    """
    body = load(name)
    if body is None:
        return 2
    moved = drift(body)
    if moved:
        print("Refusing: {} thing(s) moved since the freeze.".format(len(moved)))
        for line in moved:
            print("  {}".format(line))
        print("\nA pass run now would answer a different question from the one "
              "already paid for. Re-freeze as a new experiment, or put it back.")
        return 2
    print("nothing has moved since the freeze: {} case(s), same prompts, same "
          "schema, same scorer, same reviewer, same toolchain, same "
          "accepted-risk rules in force.".format(len(body["cases"])))
    return 0


def accepted(name: str, label: str) -> Dict[str, Any]:
    """The results this pass has already accepted, keyed by case."""
    out = {}
    for path in sorted((home(name) / "pass-{}".format(label)).glob("*.json")):
        try:
            out[path.stem] = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            out[path.stem] = {"unreadable": True}
    return out


def run(name: str, label: str, limit: Optional[int],
        only: Optional[str] = None, spend_class: str = SPEND_CLASS) -> int:
    """Run the frozen order, publishing a case only after it is still valid.

    The order matters and so does the loop: the conditions are checked before
    the case and again after it, and the result is written only if the second
    check passes. A result produced while something moved underneath it is
    discarded here rather than left on disk to be counted by a later resume,
    which is exactly what the previous design did.

    **`only` names one case and means exactly that one.** `sonnet_trial.py`
    interleaves the two arms, so the case to buy next comes from its committed
    schedule rather than from this experiment's own queue — and a caller that
    asked for one case and silently got another would record a review of the
    wrong thing under the right name. So an unknown case is refused, a case
    outside the frozen order is refused, and a case already accepted is
    reported as nothing to do rather than quietly replaced by the next one in
    the queue. Codex set that contract on 2026-09-06.
    """
    body = load(name)
    if body is None:
        return 2
    if label not in PASSES:
        print("a pass is one of {}".format(", ".join(PASSES)), file=sys.stderr)
        return 2
    if only is not None and only not in body["protocol"]["order"]:
        print("{} is not in the frozen order of experiment {}, so running it "
              "here would put a result under a protocol that never named it"
              .format(only, name), file=sys.stderr)
        return 2

    from pair_corpus import load_adjudications, load_cases, run_case

    known = {case["case_id"]: case
             for case in load_cases(ROOT / "corpus-real")}
    # Loaded and passed, not merely hashed. The manifest digests this file and
    # `drift` refuses when it moves — which stated that the rulings were part of
    # the frozen scoring environment while the scoring ignored them, because
    # `run_case` defaults to none. A description of the method that the method
    # does not follow is the shape this project keeps finding in itself.
    rulings = load_adjudications(ROOT / "corpus-real")
    have = accepted(name, label)
    queued = [c for c in body["protocol"]["order"] if c not in have]
    if only is not None:
        # Narrowed to the one case, and narrowed *after* the accepted rows are
        # read: a case already answered leaves an empty queue and the "nothing
        # left" path below, which is the truthful report. Filtering before
        # would have re-bought it.
        queued = [c for c in queued if c == only]

    print("experiment {} · pass {}".format(name, label))
    print("  {} accepted, {} to run".format(len(have), len(queued)))
    if not queued:
        print("  nothing left in this pass.")
        return 0

    # Before anything is bought, and required rather than merely compared.
    # `drift` walks the keys the manifest *has*, so a manifest frozen before
    # these keys existed would be checked against nothing and read as agreeing
    # — the shape this repository keeps finding in itself. A manifest that does
    # not name its model cannot show that this shell asks for the same one, and
    # "could not check" is not "matches".
    if not (body["environment"].get("model_requested") or ""):
        print("\nstopping: {} was frozen before the model was recorded, so "
              "there is nothing here to check this shell against. Every review "
              "in this pass would be bought from whatever SECURITY_SCAN_MODEL "
              "happens to hold, and the comparator would only say so "
              "afterwards. Freeze a new experiment.".format(name))
        return 2
    # The same argument one step further out. `drift` walks the keys the
    # manifest *has*, so a manifest frozen before the binaries were recorded is
    # checked against nothing and reads as agreeing — and the CLI is the one
    # part of the instrument that upgrades itself in the background. A pass run
    # under such a manifest cannot say which `claude` bought it.
    if not (body["environment"].get("review_cli") or ""):
        print("\nstopping: {} was frozen before the binaries were recorded, so "
              "there is nothing here to check this machine's `git` and `claude` "
              "against. An upgrade between the freeze and now would be invisible "
              "and every review in this pass would be bought from an instrument "
              "nobody identified. Freeze a new experiment.".format(name))
        return 2
    print("  model {} · verifier {} · verification {}".format(
        body["environment"]["model_requested"],
        body["environment"].get("verifier_requested", "?"),
        body["environment"].get("verify", "?")))

    # Counted rather than enumerated: it is the number of cases this
    # The cases this invocation accepted, not the ones it attempted. The loop
    # returns early on drift without accepting the case it is on, so a counter
    # over the iteration would stop one case late.
    taken = []
    for case_id in queued:
        if limit is not None and len(taken) >= limit:
            print("\nstopping after {} case(s), as asked. {} left; run the "
                  "same command again to continue.".format(
                      len(taken), len(queued) - len(taken)))
            break

        moved = drift(body)
        if moved:
            print("\nstopping before {}: {} thing(s) moved since the freeze:\n"
                  "  {}\n\nWhat has been accepted stays accepted. Put it back "
                  "and run this again.".format(case_id, len(moved),
                                               "\n  ".join(moved)))
            return 2

        case = known.get(case_id)
        if case is None:
            print("\nstopping: {} is in the frozen order and not in the "
                  "corpus.".format(case_id))
            return 2

        print("\n  {} ...".format(case_id), flush=True)
        # The frozen copy, for the duration of this case. `run_case` starts a
        # child process that reads the prompt directory this names.
        os.environ["SECURITY_SCAN_PROMPT_DIR"] = str(home(name) / "prompts")
        result = run_case(case, provider=body["protocol"]["provider"],
                          profile=body["protocol"]["profile"],
                          adjudications=rulings,
                          # Its own class: an experiment against a frozen
                          # protocol can be ordered differently from a direct
                          # corpus run, even though both end at the same
                          # `review`. Codex, 2026-09-05.
                          #
                          # And it travels from the caller when there is one:
                          # the same two passes bought as part of the Sonnet
                          # trial are authorised by D-015, not by whatever
                          # orders a bare experiment. A class says *why* the
                          # spending is authorised, and the reason belongs to
                          # whoever had it.
                          spend_class=spend_class)

        # After, before it is written anywhere. The check before the case
        # leaves the case itself unprotected — the reviewer loads its prompts
        # and its files while it runs — and on the last case of a pass there is
        # no next check at all.
        moved = drift(body)
        if moved:
            print("  discarded: {} thing(s) moved while it ran:\n    {}"
                  .format(len(moved), "\n    ".join(moved)))
            print("\nThat review was paid for and is not part of this "
                  "experiment. Put it back and run this again.")
            return 2

        rendered = json.dumps(result, indent=2, ensure_ascii=False) + "\n"
        if describe(result) in ("no verdict", "error") or result.get("incomplete"):
            # Kept, because it was paid for, and kept *apart*, because an
            # accepted file is also what tells the next run to skip the case.
            # Publishing an errored row as an ordinary result turned a
            # transient provider failure into a case that could never be run
            # again and an experiment that stayed incomplete for ever.
            aside = home(name) / "pass-{}-unfinished".format(label)
            publish(aside / "{}.json".format(case_id), rendered)
            print("  {}: {} — kept aside, not accepted. Run this again to "
                  "retry it.".format(case_id, describe(result)), flush=True)
            return 2

        target = home(name) / "pass-{}".format(label) / "{}.json".format(case_id)
        if not publish(target, rendered):
            return 2
        taken.append(case_id)
        print("  {}: {}".format(case_id, describe(result)), flush=True)

    print("\npass {}: {} accepted of {}.".format(
        label, len(accepted(name, label)), len(body["protocol"]["order"])))
    return 0


def describe(result: Dict[str, Any]) -> str:
    if result.get("incomplete"):
        return "did not conclude ({})".format(", ".join(result["incomplete"]))
    if result.get("error"):
        return "error"
    verdict = result.get("pair_success")
    if verdict is True or verdict is False:
        return "pass" if verdict else "fail"
    return "no verdict"


def verdicts(name: str, label: str, frozen: Dict[str, str]) -> Dict[str, Any]:
    """`case_id -> pass/fail`, refusing anything that is not a verdict.

    One file per case by construction, so the duplicate problem the previous
    design had cannot arise: a second result for a case would have to overwrite
    an accepted one, and `publish` refuses to overwrite.
    """
    out: Dict[str, Any] = {}
    for case_id, row in accepted(name, label).items():
        if case_id not in frozen:
            out["(not in the suite) " + case_id] = "stray"
            continue
        if row.get("unreadable"):
            out[case_id] = "unreadable"
        elif row.get("case_digest") != frozen[case_id]:
            out[case_id] = "wrong-version"
        else:
            verdict = row.get("pair_success")
            if verdict is True or verdict is False:
                out[case_id] = "pass" if verdict else "fail"
            elif verdict is None:
                out[case_id] = "unresolved"
            else:
                # `"false"` is a non-empty string and would read as a pass.
                out[case_id] = "not-a-verdict"
    return out


def compare(name: str) -> int:
    body = load(name)
    if body is None:
        # Only when there is no manifest at all. `load` also refuses one frozen
        # over no case, and telling that reader it was never frozen would send
        # them looking for the wrong thing.
        if not (home(name) / "manifest.json").is_file():
            print("It was never frozen, so there is no rule to compare against "
                  "and none may be invented now.", file=sys.stderr)
        return 2

    # Checked here as well as before each case. `run` closes the window up to
    # the moment a case finishes; without this, everything the experiment rests
    # on could be edited afterwards and the comparison would still print "no
    # movement observed".
    moved = drift(body)
    if moved:
        print("Refusing to compare: {} thing(s) have moved since the freeze."
              .format(len(moved)), file=sys.stderr)
        for line in moved:
            print("  {}".format(line), file=sys.stderr)
        print("\nThe results may be sound; this comparison is not. Nothing "
              "here can say whether the change came before or after the "
              "passes.", file=sys.stderr)
        return 2

    frozen = {row["case_id"]: row["case_digest"] for row in body["cases"]}
    a = verdicts(name, "a", frozen)
    b = verdicts(name, "b", frozen)

    usable = {"pass", "fail"}
    agreed, flipped, unusable = [], [], []
    for case_id in sorted(frozen):
        first, second = a.get(case_id), b.get(case_id)
        if first not in usable or second not in usable:
            unusable.append("{} (a={}, b={})".format(
                case_id, first or "absent", second or "absent"))
        elif first == second:
            agreed.append(case_id)
        else:
            flipped.append("{}: {} -> {}".format(case_id, first, second))

    stray = sorted(k for k in list(a) + list(b) if k not in frozen)

    print("experiment {} · pass a against pass b".format(name))
    print("  {} case(s) frozen, {} comparable".format(
        len(frozen), len(agreed) + len(flipped)))
    print("  agreed with itself: {}".format(len(agreed)))
    print("  flipped:            {}".format(len(flipped)))
    for line in flipped:
        print("    {}".format(line))
    if unusable:
        print("\n  no comparable pair: {}".format(len(unusable)))
        for line in unusable:
            print("    {}".format(line))
    if stray:
        print("\n  results the frozen suite did not ask for: {}".format(
            ", ".join(stray)))

    print("\n{}".format(body["protocol"]["not_answerable"]))
    if unusable or stray:
        print("\nIncomplete: a case with no verdict on one side is not evidence "
              "of agreement.")
        return 2
    if flipped:
        # Not a failure. Movement is the finding this experiment was bought to
        # produce, and exiting non-zero on it would make the answer look like a
        # broken run.
        print("\nThe suite moves on its own. Any gate threshold has to sit "
              "above this, and this file cannot say how far above.")
    else:
        print("\nNo movement observed in one paired repetition. That is not "
              "'the suite is stable' — it is one observation, and the cases "
              "known to move were deliberately included.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)

    it = sub.add_parser("freeze")
    it.add_argument("name")
    it.add_argument("--dry-run", action="store_true")
    # Choosing the model stops being a variable typed in front of one command
    # in one shell. The argument wins over the environment — freeze spends
    # nothing, and `run` still refuses before spending when the shell and the
    # manifest disagree — and both the winning value and where it came from are
    # printed and recorded.
    it.add_argument("--model", default=None,
                    help="the reviewing model; overrides SECURITY_SCAN_MODEL")
    it.add_argument("--verify-model", default=None,
                    help="the verifying model; overrides "
                         "SECURITY_SCAN_VERIFY_MODEL. Unset means the "
                         "reviewing model chosen above, not the shell's.")

    check = sub.add_parser("verify")
    check.add_argument("name")

    go = sub.add_parser("run")
    go.add_argument("name")
    go.add_argument("pass_label", choices=PASSES, metavar="PASS")
    go.add_argument("--cases", type=int, metavar="N",
                    help="stop after N cases; run again to continue")

    done = sub.add_parser("compare")
    done.add_argument("name")

    args = parser.parse_args()
    # `requested_now` resolves the models through the reviewer's own config,
    # which validates *every* setting and not only the three recorded here. One
    # bad value anywhere — `SECURITY_SCAN_FAIL_ON=bogus`, a malformed integer —
    # raised out of `drift` and printed a traceback where a refusal belonged.
    #
    # Refused rather than recorded as a marker. A marker would be written by the
    # freeze and computed again by the run, the two would match, and a shell
    # whose configuration does not load would have been called unchanged — the
    # absence read as agreement, arrived at through the fix for it.
    try:
        if args.command == "freeze":
            return freeze(args.name, args.dry_run,
                          args.model, args.verify_model)
        if args.command == "verify":
            return verify(args.name)
        if args.command == "run":
            return run(args.name, args.pass_label, args.cases)
        return compare(args.name)
    except ConfigError as exc:
        print("this shell's configuration does not load, so there is nothing "
              "to freeze or to check against:\n  {}".format(exc),
              file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
