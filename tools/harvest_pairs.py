#!/usr/bin/env python3
"""Build pairs out of real security fixes, instead of writing them.

Every case in `corpus/` so far is my construction, which is the same criticism
that sank the original decoy set: the person who wrote the prompt also chose
which idioms it would be tested on. The pair structure removes the "looks
dangerous" shortcut but not that one.

A published advisory fixes it. GitHub's advisory database names, for a large
number of real vulnerabilities, the exact commit that fixed each — so the
ground truth comes from the maintainers who shipped the fix, and the code is
someone else's.

## The construction

Take the fix commit **F** and its parent **P**. Both members review a diff that
touches exactly the same lines, in opposite directions:

    safe member     baseline = P,  change = F            (the fix being added)
    unsafe member   baseline = F,  change = revert of F  (the fix being removed)

That is a stronger pair than anything hand-written can be. The two diffs are
the same size, in the same files, on the same lines, in real code with real
surroundings. Nothing correlates with the answer except the direction.

It is also the exact shape of the attack worth catching: someone removing a
guard that a maintainer deliberately added.

## Answer keys, and removing them

A fix commit is soaked in the answer. The message says what it fixes, the tests
added alongside are often named after the CVE, and a changelog entry may spell
it out. All of it is scrubbed:

  * commit messages are replaced with a neutral one on both members;
  * files whose path suggests a test or a changelog are dropped from the change
    on both members equally, so the two stay symmetric;
  * **comments are stripped from every file in both members**, because the
    maintainer's explanation of the guard only ever lands on the side that has
    the guard. An audit found the whole corpus decided by a rule that reads no
    code at all — *more comment lines means safe* — scoring 48/48. See
    `strip_comments.py`;
  * cases whose remaining diff still mentions the advisory are rejected rather
    than shipped, because a corpus that leaks is worse than a smaller one.

The manifest records the advisory id, but manifests live outside the built
repository — the agent never sees one.

Usage:
    tools/harvest_pairs.py --ecosystem pip --limit 5
    tools/harvest_pairs.py --ecosystem go --cwe CWE-89 --out corpus-real/
    tools/harvest_pairs.py --advisory GHSA-xxxx-xxxx-xxxx
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).resolve().parent))

from strip_comments import STRIPPED, UNCHANGED, strip_comments_report

# Ecosystem → the `language:` value the corpus uses. Advisories are indexed by
# package ecosystem, and the mapping is not always one to one (npm holds both
# JavaScript and TypeScript), so the language is settled from the changed files
# instead, and this is only the query key.
ECOSYSTEM_LANGUAGE = {
    "pip": "python", "npm": "typescript", "go": "go", "maven": "java",
    "composer": "php", "rubygems": "ruby", "rust": "rust", "nuget": "csharp",
}

# Two-letter code per language for the case id. Taken from a table rather than
# from `language[:2]`, which gave `ru` for both ruby and rust and quietly turned
# the prefix into noise — ids stayed unique because of the advisory suffix, so
# nothing broke and nothing said so either.
LANGUAGE_CODE = {
    "python": "py", "go": "go", "java": "jv", "php": "php", "ruby": "rb",
    "rust": "rs", "typescript": "ts", "javascript": "js", "csharp": "cs",
    "kotlin": "kt", "scala": "sc",
}
assert len(set(LANGUAGE_CODE.values())) == len(LANGUAGE_CODE), "codes must be distinct"

EXTENSION_LANGUAGE = {
    ".py": "python", ".go": "go", ".java": "java", ".php": "php", ".rb": "ruby",
    ".rs": "rust", ".ts": "typescript", ".tsx": "typescript", ".js": "javascript",
    ".jsx": "javascript", ".cs": "csharp", ".kt": "kotlin", ".scala": "scala",
}

# CWE → the agent's own category vocabulary, which is read from
# `prompts/findings.schema.json` rather than restated here. An earlier version
# of this map used names the agent can never emit — `authorization`,
# `path_traversal`, `open_redirect` — so every case built from them scored as a
# miss without ever being given a chance to pass. Only mappings that are
# unambiguous are listed; anything else harvests with an empty expected
# category and is scored on file alone, which the manifest states rather than
# leaving to be guessed.
# Named here so a test can say which file the truth lives in.
SCHEMA_NAME = "prompts/findings.schema.json"

CWE_CATEGORY = {
    "CWE-89": "injection", "CWE-564": "injection", "CWE-943": "injection",
    "CWE-78": "injection", "CWE-77": "injection", "CWE-88": "injection",
    "CWE-94": "injection", "CWE-95": "injection", "CWE-470": "injection",
    "CWE-79": "xss", "CWE-80": "xss", "CWE-116": "xss",
    "CWE-22": "path-traversal", "CWE-23": "path-traversal",
    "CWE-36": "path-traversal", "CWE-59": "path-traversal",
    "CWE-918": "ssrf",
    "CWE-502": "deserialization",
    "CWE-287": "authn-authz", "CWE-306": "authn-authz",
    "CWE-862": "authn-authz", "CWE-863": "authn-authz", "CWE-639": "authn-authz",
    "CWE-284": "authn-authz", "CWE-269": "authn-authz", "CWE-566": "authn-authz",
    "CWE-798": "secrets", "CWE-259": "secrets",
    "CWE-352": "csrf",
    "CWE-601": "open-redirect",
    "CWE-200": "sensitive-data-exposure", "CWE-532": "sensitive-data-exposure",
    "CWE-327": "crypto", "CWE-328": "crypto", "CWE-916": "crypto",
    "CWE-330": "crypto", "CWE-338": "crypto", "CWE-208": "crypto",
    "CWE-367": "race-condition", "CWE-362": "race-condition",
    "CWE-400": "dos", "CWE-770": "dos", "CWE-789": "dos", "CWE-1333": "dos",
    "CWE-295": "crypto", "CWE-297": "crypto", "CWE-322": "crypto",
    "CWE-248": "dos", "CWE-754": "dos", "CWE-755": "dos", "CWE-704": "dos",
    "CWE-125": "dos", "CWE-787": "dos", "CWE-476": "dos", "CWE-681": "dos",
    "CWE-611": "other",
}

# Paths dropped from the change on both members. A test named after the CVE is
# a printed answer key; a changelog entry is the same thing in prose.
NOISE = re.compile(
    r"(^|/)(tests?|spec|specs|__tests__|testdata|fixtures?)(/|$)"
    r"|(^|/)(CHANGELOG|CHANGES|HISTORY|NEWS|SECURITY|RELEASE[-_]NOTES)"
    r"|(_test\.(go|py|rb|js|ts)$)|(^test_)|(/test_)|(\.spec\.[jt]sx?$)|(Test\.java$)",
    re.IGNORECASE)

# Anything left that names the advisory means the scrub was incomplete.
LEAK = re.compile(r"CVE-\d{4}-\d{4,7}|GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}",
                  re.IGNORECASE)

COMMIT_URL = re.compile(r"https://github\.com/([^/]+/[^/]+)/commit/([0-9a-f]{7,40})")

GIT_ENV_BASE = {
    "GIT_AUTHOR_NAME": "Corpus", "GIT_AUTHOR_EMAIL": "corpus@example.invalid",
    "GIT_COMMITTER_NAME": "Corpus", "GIT_COMMITTER_EMAIL": "corpus@example.invalid",
    "GIT_TERMINAL_PROMPT": "0",
}


def git_env(home: Path) -> dict:
    import os
    env = dict(GIT_ENV_BASE)
    env["PATH"] = os.environ.get("PATH", "/usr/bin:/bin")
    env["HOME"] = str(home)
    return env


def git(repo: Path, *args, check=True, env=None) -> str:
    proc = subprocess.run(("git", "-C", str(repo), *args),
                          capture_output=True, text=True, check=False, env=env)
    if check and proc.returncode != 0:
        raise RuntimeError("git {}: {}".format(
            " ".join(args)[:60], proc.stderr.strip()[:200]))
    return proc.stdout


# --------------------------------------------------------------- discovery


def advisories(ecosystem: str, limit: int, cwe: str = "", severity: str = "") -> list:
    """Advisories that name exactly one fix commit.

    More than one commit means the fix is spread across a series, and picking
    one of them gives a pair where the unsafe member is still partly fixed —
    a case whose ground truth is wrong in a way nothing downstream would notice.
    """
    params = ["ecosystem={}".format(ecosystem), "type=reviewed", "per_page=100"]
    if severity:
        params.append("severity={}".format(severity))
    url = "/advisories?" + "&".join(params)

    # `--paginate` was built into a list that was then deleted before the call,
    # so every harvest read one page of a hundred and `--limit 400` quietly
    # meant "up to a hundred". The number asked for and the number searched
    # were different, and nothing said so.
    proc = subprocess.run(("gh", "api", "--paginate", url, "--jq",
                           ".[] | {ghsa: .ghsa_id, cve: .cve_id, summary: .summary, "
                           "severity: .severity, cwes: [.cwes[].cwe_id], "
                           "refs: [.references[]? | select(test(\"/commit/\"))]}"),
                          capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        raise SystemExit("gh api failed: " + proc.stderr.strip()[:300])

    found = []
    for line in proc.stdout.splitlines():
        if not line.strip():
            continue
        item = json.loads(line)
        commits = [m for ref in item["refs"] for m in COMMIT_URL.findall(ref)]
        if len(commits) != 1:
            continue
        if cwe and cwe not in item["cwes"]:
            continue
        item["repo"], item["sha"] = commits[0]
        found.append(item)
        if len(found) >= limit:
            break
    return found


def fetch_commit(repo_slug: str, sha: str, work: Path) -> Path:
    """Clone just enough history to hold the fix and its parent.

    A blobless partial clone with depth 2 is a few megabytes even for a large
    project; a full clone of some of these is a gigabyte.
    """
    repo = work / "repo"
    env = git_env(work)
    subprocess.run(("git", "init", "-q", str(repo)), check=True,
                   capture_output=True, env=env)
    git(repo, "remote", "add", "origin",
        "https://github.com/{}.git".format(repo_slug), env=env)
    proc = subprocess.run(
        ("git", "-C", str(repo), "fetch", "-q", "--depth", "2",
         "--filter=blob:none", "origin", sha),
        capture_output=True, text=True, check=False, env=env)
    if proc.returncode != 0:
        raise RuntimeError("fetch failed: " + proc.stderr.strip()[:160])
    return repo


# ------------------------------------------------------------- construction


REGRESSION = "regression"
SNAPSHOT = "snapshot"

# The third construction, considered and not built — recorded here so it is a
# decision rather than an oversight.
#
# Each of the two above gives something away. `regression` is focused on the
# decisive lines and its unsafe member always *deletes*, so the direction of
# the diff predicts the answer. `snapshot` has both members add, so direction
# carries nothing — and the diff becomes a whole new module, which is finding a
# needle rather than judging a control.
#
# A construction with neither: the baseline holds the decisive function as a
# compiling stub (`panic("not implemented")` and its equivalents), and both
# members replace it — one with the fixed implementation, one with the
# vulnerable one. Additive on both sides, and one function wide.
#
# Not built for two reasons, and the second is the real one:
#
#   1. It needs function-boundary detection and stub synthesis for eight
#      languages, roughly the size of `strip_comments.py`.
#   2. It would not fit the harvested cases anyway. Twenty of forty-eight real
#      fixes touch more than one file, and a stub of five functions across
#      three files is not a diff anyone would open.
#
# What it would buy is a better regression suite. What the project actually
# lacks is evidence from changes nobody built to be reviewed, and no
# construction can supply that. See LIMITATIONS.md.
FOCUSED_ADDITION_NOT_BUILT = True

MAX_CONTEXT_FILES = 25
MAX_CONTEXT_BYTES = 400_000


def changed_files(repo: Path, parent: str, fix: str, env: dict) -> list:
    out = git(repo, "diff", "--name-only", "--diff-filter=M", parent, fix, env=env)
    return [line for line in out.splitlines() if line.strip()]


def context_files(repo: Path, rev: str, keep: list, env: dict) -> list:
    """Unchanged files sitting beside the ones the fix touched.

    Without these, a harvested case is a file in a vacuum: no callers, no
    validators, no configuration, and no way for the agent to check a claim
    about what happens upstream. The whole repository is too much — it turns
    the task from reviewing a change into finding a needle — so the compromise
    is the directories the change is in, bounded so a case stays a case.
    """
    wanted_dirs = {str(Path(path).parent) for path in keep}
    listing = git(repo, "ls-tree", "-r", "--name-only", rev, env=env, check=False)

    siblings = []
    for path in listing.splitlines():
        if not path.strip() or path in keep:
            continue
        if str(Path(path).parent) not in wanted_dirs:
            continue
        if NOISE.search(path):
            continue
        siblings.append(path)

    chosen, total = [], 0
    for path in sorted(siblings, key=len):
        blob = git(repo, "show", "{}:{}".format(rev, path), env=env, check=False)
        if not blob or "\x00" in blob[:1024]:
            continue
        if total + len(blob) > MAX_CONTEXT_BYTES or len(chosen) >= MAX_CONTEXT_FILES:
            break
        chosen.append(path)
        total += len(blob)
    return chosen


def write_source(target: Path, path: str, blob: str, untouched: list) -> None:
    """One file into a member, with its comments already gone.

    Every write goes through here — `change/` and baseline alike, both members
    alike. Doing it on the change alone would leave the same prose one directory
    up, and doing it to one member would be the very asymmetry being removed.

    A file the stripper will not vouch for is written exactly as it came and
    recorded in `untouched`, which the run prints. Silence would be worse: an
    unstripped file is a visible flaw, a mangled one is a wrong answer nobody
    can see.
    """
    text, status = strip_comments_report(blob, Path(path).suffix)
    if status not in (STRIPPED, UNCHANGED):
        untouched.append("{}: {}".format(path, status))
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")


def build_member(
    case_dir: Path, member: str, repo: Path, parent: str, fix: str,
    keep: list, env: dict, context: list = (), construction: str = REGRESSION,
    untouched: Optional[list] = None,
) -> None:
    """Lay a member out as `baseline files` + `change/`.

    The pair runner treats anything under `change/` as the second commit, so
    the two members differ only in what the change does.

    Two constructions, which measure different things and must never be scored
    together:

    **regression** — the fix is added on one side and reverted on the other.
    Exactly symmetric, and exactly the attack worth catching, but the direction
    of the diff is then perfectly predictive of the answer: every unsafe member
    deletes something. A tool with a rule about removed controls scores well
    here without having recognised the weakness at all.

    **snapshot** — both members *add* the implementation from a shared
    baseline, one fixed and one not. The diffs are no longer exact inverses,
    but provenance and surroundings stay matched and direction stops carrying
    the answer. This is the one that measures discrimination.
    """
    baseline_rev, change_rev = (parent, fix) if member == "safe" else (fix, parent)
    root = case_dir / member
    if untouched is None:
        untouched = []
    if root.exists():
        shutil.rmtree(root)
    (root / "change").mkdir(parents=True)

    # Context is taken from one revision for both members. Reading it from each
    # member's own baseline would let an unrelated change elsewhere in the
    # directory differ between them, and then the members differ by something
    # other than the thing under test.
    for path in context:
        blob = git(repo, "show", "{}:{}".format(fix, path), env=env, check=False)
        if not blob:
            continue
        write_source(root / path, path, blob, untouched)

    if construction == SNAPSHOT:
        # Both members add; neither deletes. The file is absent from the
        # baseline, so what the agent reviews is a new implementation arriving.
        source_rev = fix if member == "safe" else parent
        for path in keep:
            blob = git(repo, "show", "{}:{}".format(source_rev, path),
                       env=env, check=False)
            if not blob:
                continue
            write_source(root / "change" / path, path, blob, untouched)
        return

    # Repository-relative paths, kept intact. Flattening to a basename — which
    # this did until it was pointed out — destroys package structure, makes
    # every import in the file false, collides two files that share a name, and
    # leaves the agent unable to follow a caller. The case is a slice of a real
    # project or it is not worth harvesting.
    for path in keep:
        for rev, dest in ((baseline_rev, root), (change_rev, root / "change")):
            blob = git(repo, "show", "{}:{}".format(rev, path), env=env, check=False)
            if not blob:
                continue
            write_source(dest / path, path, blob, untouched)


def leak_check(case_dir: Path) -> list:
    """Anything naming the advisory means the scrub missed something."""
    leaks = []
    for path in sorted(case_dir.rglob("*")):
        if not path.is_file() or path.name == "case.yml":
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for match in LEAK.findall(text):
            leaks.append("{}: {}".format(path.relative_to(case_dir), match))
    return leaks


def language_of(paths: list) -> str:
    counts: dict = {}
    for path in paths:
        lang = EXTENSION_LANGUAGE.get(Path(path).suffix.lower())
        if lang:
            counts[lang] = counts.get(lang, 0) + 1
    return max(counts, key=counts.get) if counts else ""


def category_of(cwes: list) -> str:
    for cwe in cwes:
        if cwe in CWE_CATEGORY:
            return CWE_CATEGORY[cwe]
    return ""


def harvest(item: dict, out: Path, max_files: int, max_lines: int,
            construction: str = REGRESSION) -> dict:
    work = Path(tempfile.mkdtemp(prefix="harvest-")).resolve()
    env = git_env(work)
    verdict = {"ghsa": item["ghsa"], "repo": item["repo"], "sha": item["sha"][:12]}
    try:
        repo = fetch_commit(item["repo"], item["sha"], work)
        parent = git(repo, "rev-parse", item["sha"] + "^", env=env).strip()

        modified = changed_files(repo, parent, item["sha"], env)
        keep = [p for p in modified if not NOISE.search(p)]
        dropped = [p for p in modified if NOISE.search(p)]
        if not keep:
            verdict["skipped"] = "every changed file looks like a test or changelog"
            return verdict
        if len(keep) > max_files:
            verdict["skipped"] = "{} files changed, over the {} limit".format(
                len(keep), max_files)
            return verdict

        stat = git(repo, "diff", "--numstat", parent, item["sha"], "--", *keep, env=env)
        # `--numstat` writes `-\t-\tpath` for a binary file, and `.isdigit()`
        # rejected the dash — so a commit rewriting a forty-megabyte binary
        # scored as a zero-line change and sailed under the limit. The guard
        # was the bug: "cannot be counted" arrived as "nothing changed", which
        # is the same confusion as an incomplete run arriving as a clean one.
        churn, binary = 0, []
        for line in stat.splitlines():
            fields = line.split("\t")
            if len(fields) < 3:
                continue
            added, removed, path = fields[0], fields[1], fields[2]
            if added == "-" or removed == "-":
                binary.append(path)
                continue
            churn += int(added or 0) + int(removed or 0)
        if binary:
            verdict["skipped"] = (
                "the fix touches binary file(s) whose size cannot be counted: "
                "{}".format(", ".join(binary[:3])))
            return verdict
        if churn > max_lines:
            verdict["skipped"] = "{} lines changed, over the {} limit".format(
                churn, max_lines)
            return verdict

        language = language_of(keep)
        if not language:
            verdict["skipped"] = "no recognised source language among " + ", ".join(keep[:3])
            return verdict

        context = context_files(repo, item["sha"], keep, env)

        case_id = "{}-{}{}".format(
            LANGUAGE_CODE.get(language, language[:2]),
            item["ghsa"].lower().replace("ghsa-", ""),
            "" if construction == REGRESSION else "-snap")
        case_dir = out / case_id
        if case_dir.exists():
            shutil.rmtree(case_dir)
        case_dir.mkdir(parents=True)

        untouched: list = []
        for member in ("safe", "unsafe"):
            build_member(case_dir, member, repo, parent, item["sha"], keep, env,
                         context=context, construction=construction,
                         untouched=untouched)

        if construction == SNAPSHOT:
            # A snapshot member with nothing in its baseline cannot be built:
            # `git commit` refuses an empty tree, so the case errors in every
            # harness that makes a baseline commit — and it errored silently
            # through eleven soundness checks, because "both baselines are
            # empty" satisfies "both baselines match".
            #
            # It happens when the fix touched the only file in its directory,
            # leaving no sibling to hold. Nothing to salvage: the construction
            # needs a baseline for both members to add to.
            empty = [m for m in ("safe", "unsafe")
                     if not any(p.is_file() for p in (case_dir / m).glob("*")
                                if p.parent.name != "change")]
            if empty or not context:
                shutil.rmtree(case_dir)
                verdict["skipped"] = (
                    "snapshot needs a baseline and this fix left no unchanged "
                    "sibling in its directory")
                return verdict

        leaks = leak_check(case_dir)
        if leaks:
            # Rejected, not patched. Editing real code to hide the answer makes
            # it no longer real code, which was the whole point of harvesting.
            shutil.rmtree(case_dir)
            verdict["skipped"] = "advisory id survives the scrub: " + leaks[0]
            return verdict

        category = category_of(item["cwes"])
        # Every file the fix touched, not the first one. A fix is not obliged
        # to fit in one file, and recording `keep[0]` made the others count as
        # the wrong place: Winter's CSRF fix normalises a name in
        # `BackendController.php` and rejects the bad ones in `Controller.php`,
        # and the manifest named the file without the check in it.
        #
        # Repository-relative paths, not basenames: two files called `views.py`
        # in different packages are different files, and `Controller.php` alone
        # also matches `BackendController.php`.
        target = list(keep)
        manifest = [
            "case_id: {}".format(case_id),
            "language: {}".format(language),
            "family: {}".format(category or "unclassified"),
            "framework: ''",
            "# Harvested from a published advisory, not written by hand. Ground",
            "# truth is the maintainers' own fix; this file lives outside the",
            "# built repository, so the agent never sees it.",
            "source_advisory: {}".format(item["ghsa"]),
            "source_cve: {}".format(item["cve"] or "none"),
            "source_repo: {}".format(item["repo"]),
            "source_fix_commit: {}".format(item["sha"]),
            "source_cwes: [{}]".format(", ".join(item["cwes"]) or ""),
            "severity_reported: {}".format(item["severity"]),
            "construction: {}".format(construction),
            "# regression: the two members review the same lines in opposite",
            "#   directions — safe adds the maintainers' fix, unsafe reverts it.",
            "#   Exactly symmetric, but every unsafe member deletes something, so",
            "#   direction predicts the answer and a removed-control rule scores",
            "#   well here without recognising anything.",
            "# snapshot: both members add an implementation from a shared",
            "#   baseline, one fixed and one not. Direction carries no answer.",
            "# Never score the two constructions together.",
            "decisive_control: the change the maintainers shipped as the fix",
            "expected_category: {}".format(category),
            "expected_file: [{}]".format(", ".join(repr(p) for p in target)),
            "dropped_from_change: [{}]".format(
                ", ".join(repr(p) for p in dropped[:6])),
            # A null summary is a real advisory shape, and the sibling field
            # two lines up already guarded for it.
            "summary: {!r}".format((item.get("summary") or "")[:200]),
        ]
        (case_dir / "case.yml").write_text("\n".join(manifest) + "\n", encoding="utf-8")

        verdict.update({"case_id": case_id, "language": language,
                        "construction": construction, "context": len(context),
                        "category": category or "(unclassified)",
                        "files": len(keep), "lines": churn,
                        "dropped": len(dropped),
                        "untouched": sorted(set(untouched))})
        return verdict
    except Exception as exc:
        verdict["skipped"] = "{}: {}".format(type(exc).__name__, str(exc)[:120])
        return verdict
    finally:
        shutil.rmtree(work, ignore_errors=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ecosystem", default="pip", choices=sorted(ECOSYSTEM_LANGUAGE))
    parser.add_argument("--cwe", default="", help="e.g. CWE-89")
    parser.add_argument("--severity", default="", choices=["", "low", "medium",
                                                           "high", "critical"])
    parser.add_argument("--limit", type=int, default=5)
    parser.add_argument("--out", default="corpus-real")
    parser.add_argument("--construction", choices=(REGRESSION, SNAPSHOT),
                        default=REGRESSION,
                        help="regression: fix added vs reverted (symmetric, but "
                             "direction predicts the answer). snapshot: both "
                             "members add, one fixed one not.")
    parser.add_argument("--max-files", type=int, default=3,
                        help="reject fixes touching more source files than this")
    parser.add_argument("--max-lines", type=int, default=120,
                        help="reject fixes larger than this many changed lines")
    args = parser.parse_args()

    if not shutil.which("gh"):
        sys.exit("gh is not on PATH; it is how advisories are queried")

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    found = advisories(args.ecosystem, args.limit * 4, args.cwe, args.severity)
    print("{} advisory/advisories with exactly one fix commit\n".format(len(found)))

    built, skipped = [], []
    for item in found:
        if len(built) >= args.limit:
            break
        verdict = harvest(item, out, args.max_files, args.max_lines,
                          args.construction)
        if "skipped" in verdict:
            skipped.append(verdict)
            print("  skip {:<24} {}".format(verdict["ghsa"], verdict["skipped"][:52]))
        else:
            built.append(verdict)
            print("  {:<6} {:<24} {:<14} {} file(s), {} line(s), {} context".format(
                "BUILT", verdict["case_id"], verdict["category"],
                verdict["files"], verdict["lines"], verdict["context"]))

    print("\n{} case(s) built into {}/, {} skipped".format(
        len(built), out, len(skipped)))

    # Said out loud, every time. A file the stripper would not vouch for keeps
    # its comments, and its comments are the thing the audit found decisive.
    kept_comments = [(v["case_id"], note) for v in built for note in v["untouched"]]
    if kept_comments:
        print("\n{} file(s) written with comments intact — the stripper "
              "would not vouch for them:".format(len(kept_comments)))
        for case_id, note in kept_comments:
            print("  {:<24} {}".format(case_id, note))
    if built:
        print("\nRun them with:  tools/pair_corpus.py {}/".format(out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
