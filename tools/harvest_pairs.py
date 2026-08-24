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

# Ecosystem → the `language:` value the corpus uses. Advisories are indexed by
# package ecosystem, and the mapping is not always one to one (npm holds both
# JavaScript and TypeScript), so the language is settled from the changed files
# instead, and this is only the query key.
ECOSYSTEM_LANGUAGE = {
    "pip": "python", "npm": "typescript", "go": "go", "maven": "java",
    "composer": "php", "rubygems": "ruby", "rust": "rust", "nuget": "csharp",
}

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
    "CWE-200": "sensitive-data-exposure", "CWE-532": "sensitive-data-exposure",
    "CWE-327": "crypto", "CWE-328": "crypto", "CWE-916": "crypto",
    "CWE-330": "crypto", "CWE-338": "crypto", "CWE-208": "crypto",
    "CWE-367": "race-condition", "CWE-362": "race-condition",
    "CWE-400": "dos", "CWE-770": "dos", "CWE-789": "dos", "CWE-1333": "dos",
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
    query = ["/advisories", "--paginate", "--jq", "."]
    params = ["ecosystem={}".format(ecosystem), "type=reviewed", "per_page=100"]
    if severity:
        params.append("severity={}".format(severity))
    url = "/advisories?" + "&".join(params)

    proc = subprocess.run(("gh", "api", url, "--jq",
                           ".[] | {ghsa: .ghsa_id, cve: .cve_id, summary: .summary, "
                           "severity: .severity, cwes: [.cwes[].cwe_id], "
                           "refs: [.references[]? | select(test(\"/commit/\"))]}"),
                          capture_output=True, text=True, check=False)
    del query
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


def changed_files(repo: Path, parent: str, fix: str, env: dict) -> list:
    out = git(repo, "diff", "--name-only", "--diff-filter=M", parent, fix, env=env)
    return [line for line in out.splitlines() if line.strip()]


def build_member(
    case_dir: Path, member: str, repo: Path, parent: str, fix: str,
    keep: list, env: dict,
) -> None:
    """Lay a member out as `baseline files` + `change/`.

    The pair runner treats anything under `change/` as the second commit, so
    the two members differ only in which version of the changed files is the
    baseline and which is the change.
    """
    baseline_rev, change_rev = (parent, fix) if member == "safe" else (fix, parent)
    root = case_dir / member
    if root.exists():
        shutil.rmtree(root)
    (root / "change").mkdir(parents=True)

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
            target = dest / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(blob, encoding="utf-8")


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


def harvest(item: dict, out: Path, max_files: int, max_lines: int) -> dict:
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
        churn = sum(int(n) for line in stat.splitlines()
                    for n in line.split()[:2] if n.isdigit())
        if churn > max_lines:
            verdict["skipped"] = "{} lines changed, over the {} limit".format(
                churn, max_lines)
            return verdict

        language = language_of(keep)
        if not language:
            verdict["skipped"] = "no recognised source language among " + ", ".join(keep[:3])
            return verdict

        case_id = "{}-{}".format(language[:2], item["ghsa"].lower().replace("ghsa-", ""))
        case_dir = out / case_id
        if case_dir.exists():
            shutil.rmtree(case_dir)
        case_dir.mkdir(parents=True)

        for member in ("safe", "unsafe"):
            build_member(case_dir, member, repo, parent, item["sha"], keep, env)

        leaks = leak_check(case_dir)
        if leaks:
            # Rejected, not patched. Editing real code to hide the answer makes
            # it no longer real code, which was the whole point of harvesting.
            shutil.rmtree(case_dir)
            verdict["skipped"] = "advisory id survives the scrub: " + leaks[0]
            return verdict

        category = category_of(item["cwes"])
        # The repository-relative path, not a basename: two files called
        # `views.py` in different packages are different files, and scoring
        # on the basename would credit a finding in the wrong one.
        target = keep[0]
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
            "# The two members review the same lines in opposite directions:",
            "# safe adds the maintainers' fix, unsafe removes it.",
            "decisive_control: the change the maintainers shipped as the fix",
            "expected_category: {}".format(category),
            "expected_file: {}".format(target),
            "dropped_from_change: [{}]".format(
                ", ".join(repr(p) for p in dropped[:6])),
            "summary: {!r}".format(item["summary"][:200]),
        ]
        (case_dir / "case.yml").write_text("\n".join(manifest) + "\n", encoding="utf-8")

        verdict.update({"case_id": case_id, "language": language,
                        "category": category or "(unclassified)",
                        "files": len(keep), "lines": churn,
                        "dropped": len(dropped)})
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
        verdict = harvest(item, out, args.max_files, args.max_lines)
        if "skipped" in verdict:
            skipped.append(verdict)
            print("  skip {:<24} {}".format(verdict["ghsa"], verdict["skipped"][:52]))
        else:
            built.append(verdict)
            print("  {:<10} {:<22} {:<14} {} file(s), {} line(s)".format(
                "BUILT", verdict["case_id"], verdict["category"],
                verdict["files"], verdict["lines"]))

    print("\n{} case(s) built into {}/, {} skipped".format(
        len(built), out, len(skipped)))
    if built:
        print("\nRun them with:  tools/pair_corpus.py {}/".format(out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
