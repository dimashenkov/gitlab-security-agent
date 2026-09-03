#!/usr/bin/env python3
"""Select ordinary changes for the second rule of D-013, and record why each was taken.

The paired corpus asks two questions: does the reviewer find a weakness when
there is one, and does it stay quiet on the *patched* version of a file that was
once vulnerable. Neither is the question a team asks before putting the tool in
its pipeline. That question is: **when nothing was ever wrong, does it stay
quiet?** A rename, an extracted function, a new test, a reworded log line — code
that was never a weakness and never had a fix. D-013 makes it a hard gate: of
100 mechanically selected ordinary changes, up to 9 noisy passes and it holds,
21 or more and the tool is not fit for a pipeline.

This program builds the **sampling frame** for that gate. It does not decide
whether a change is ordinary — a human does, twice, afterwards. Everything here
is mechanical, declared before the sample was seen, and recorded per candidate
including every rejection.

## What the caller has to produce, because this program has no network

There is deliberately no API client, no token and no fetch in this file. A
selection whose inputs arrive over the wire cannot be replayed a month later,
and a credential in a sampling tool is a credential in every log it writes.

Two supported ways to hand it candidates:

1.  **`harvest`, from local clones.** Clone the repositories yourself, then::

        git clone --filter=blob:none https://github.com/OWNER/NAME clones/NAME
        tools/ordinary_corpus.py harvest --clones clones \\
            --since 2026-01-01 --until 2026-06-01 --out candidates.json

    `harvest` shells out to `git` in each clone. That is local disk, not the
    network, and it is the only reason `subprocess` appears here.

2.  **A candidates file you built some other way** — `gh api`, a GitLab export,
    a spreadsheet — as long as it holds the record shape `harvest` writes. See
    `REQUIRED_FIELDS` below; a record missing any of them is *refused*, never
    assumed to have passed the check it cannot answer.

Then::

    tools/ordinary_corpus.py select --candidates candidates.json \\
        --since 2026-01-01 --until 2026-06-01 --target 30 --out manifest.json
    tools/ordinary_corpus.py check --manifest manifest.json --candidates candidates.json
    tools/ordinary_corpus.py template --manifest manifest.json --out adjudications.yml

## What this program refuses to decide

* **Whether a change is safe.** No rule here reads "this looks fine". The
  exclusions remove changes that *touch* a security-relevant area; what is left
  is a candidate for human adjudication, not a verdict.
* **Whether an upstream security label existed.** `git` carries no labels. A
  record whose `labels_source` is not authoritative is selected with
  `label_evidence: "unavailable"` recorded on it, and the adjudication template
  carries a field the human must fill in. "The tool saw no label" and "there was
  no label" are different sentences and this file never merges them.
* **Whether the sample is large enough to answer anything.** 30 is step 2 of
  D-013's order; the gate needs 100.

## Three answers, not two

Every candidate lands in exactly one disposition:

    taken         eligible and drawn into the sample
    not_selected  eligible, but the per-repository cap or the target was full
    excluded      a rule fired on evidence present in the record
    undecidable   the record did not let a rule be evaluated at all

`undecidable` exists because a missing field is not a passed check. They are
counted separately, never folded into `excluded`, and a candidate can never
become `taken` by having said nothing.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

# The ceilings are imported, not copied. A number typed in twice is a number
# that goes stale in one of the two places, and the harm here is specific: a
# change selected as "the reviewer sees this whole" that the reviewer in fact
# reads truncated, scored as an ordinary pass over half a diff.
from security_agent.tools import MAX_DIFF_CHARS  # noqa: E402
from security_agent.workspace import Workspace  # noqa: E402

# ---------------------------------------------------------------------------
# THE RULES, DECLARED BEFORE THE SAMPLE WAS SEEN
#
# Everything from here to the end of this block is a constant. It is here, at
# the top and in one piece, so a reader can satisfy themselves that no rule was
# widened or narrowed after somebody looked at which changes it let through.
# `select` writes a digest of this whole block into the manifest, and `check`
# recomputes it: a rule edited after the freeze is visible, not arguable.
# ---------------------------------------------------------------------------

# The order is a constant, not a flag. If an operator could pass `--seed`, they
# could re-roll until they liked the sample, and the sample's whole claim is
# that nobody chose it. Changing this string is a visible edit to a versioned
# file that changes the digest and every case id at once.
ORDER_SEED = "ordinary-corpus-v1"

# D-013: "not more than 10 of 100 from one repository". Held as a fraction so
# the shape survives the step from 30 to 100 without a second number to keep in
# sync with the first.
REPO_CAP_FRACTION = 0.10

# D-013: "at least 10 public repositories". Checked against the *selected* set,
# not the pool — a pool of 40 repositories that happens to yield 30 changes
# from 4 of them is not what the decision asked for.
MIN_REPOS = 10

# Not in D-013, and argued for in the report: a noise number measured on 30
# Python changes says nothing about how loud the reviewer is on PHP, and the
# gate is meant to decide whether the tool is tolerable in *a* pipeline. Five
# of the nine languages the corpus covers is the floor. Failing it is a refusal
# with a named remedy (widen the pool), not a silent short sample.
MIN_LANGUAGES = 5

# Which file extension counts as which language. The *set* of languages comes
# from `corpus-real/*/case.yml` at run time — the reviewer's claimed coverage is
# what that corpus exercises, and hard-coding a second list here is how the two
# drift. This map only says how to recognise each of them on disk, and a corpus
# language with no entry here is a refusal, not a language quietly dropped.
LANGUAGE_EXTENSIONS: Dict[str, Tuple[str, ...]] = {
    "python": (".py", ".pyi"),
    "go": (".go",),
    "php": (".php", ".phtml", ".inc"),
    "typescript": (".ts", ".tsx"),
    "javascript": (".js", ".jsx", ".mjs", ".cjs"),
    "rust": (".rs",),
    "ruby": (".rb", ".rake"),
    "csharp": (".cs",),
    "java": (".java",),
}

# The vocabulary of the eleven areas D-013's brief names: authentication,
# authorization, parsing, permissions, crypto, secrets, deserialization,
# request handling, filesystem paths, CI privileges, input validation.
#
# Matched as whole *words*, after splitting paths and changed lines on
# non-alphanumerics and on camelCase boundaries. Substring matching was tried
# and rejected in the same hour: "file" matches `profile`, "auth" matches
# `author`, and a sampling frame that throws away every commit by an author is
# not a sampling frame. Word matching costs the compounds, so the compounds are
# listed explicitly (`filepath`, `apikey`, `realpath`).
#
# This net is wide on purpose and it is wide in the safe direction: a false
# exclusion costs one candidate out of a pool that can be enlarged, while a
# false inclusion puts a security-relevant change into a corpus whose whole
# claim is that none of them are.
SENSITIVE_TERMS: Tuple[str, ...] = (
    # authentication
    "auth", "authn", "authenticate", "authenticated", "authentication",
    "login", "logout", "signin", "signup", "session", "sessions",
    "password", "passwords", "passwd", "credential", "credentials",
    "oauth", "openid", "jwt", "saml", "ldap", "kerberos", "sso", "mfa",
    "otp", "totp", "2fa",
    # authorization and permissions
    "authz", "authorize", "authorized", "authorization", "permission",
    "permissions", "perm", "perms", "privilege", "privileges", "privileged",
    "rbac", "acl", "acls", "role", "roles", "policy", "policies", "grant",
    "grants", "scope", "scopes", "chmod", "chown", "umask", "setuid",
    "setgid", "sudo", "root", "impersonate", "tenant", "tenancy",
    # crypto
    "crypt", "crypto", "cryptography", "encrypt", "encrypted", "encryption",
    "decrypt", "decryption", "cipher", "ciphers", "hmac", "md5", "sha1",
    "sha256", "rsa", "ecdsa", "aes", "tls", "ssl", "mtls", "x509", "pem",
    "certificate", "certificates", "cert", "certs", "keystore", "truststore",
    "signature", "signatures", "nonce", "salt", "pbkdf2", "bcrypt", "scrypt",
    "argon2", "randomness", "entropy", "csprng", "secrets", "secret",
    "token", "tokens", "apikey", "keyring", "vault", "dotenv",
    # parsing, deserialization, encoding
    "parse", "parser", "parsers", "parsing", "parsed", "lexer", "tokenizer",
    "grammar", "unmarshal", "unmarshall", "marshal", "deserialize",
    "deserialization", "deserializer", "unserialize", "pickle", "cpickle",
    "unpickle", "decode", "decoder", "decoding", "encode", "encoder",
    "encoding", "yaml", "xml", "xxe", "dtd", "protobuf", "objectinputstream",
    "binaryformatter",
    # request handling
    "request", "requests", "response", "responses", "http", "https",
    "router", "route", "routes", "routing", "handler", "handlers",
    "middleware", "controller", "controllers", "endpoint", "endpoints",
    "servlet", "wsgi", "asgi", "cors", "csrf", "xsrf", "xss", "cookie",
    "cookies", "header", "headers", "url", "urls", "uri", "querystring",
    "redirect", "redirects", "proxy", "webhook", "upload", "uploads",
    "download", "multipart", "graphql", "grpc", "websocket", "csp",
    # filesystem paths
    "path", "paths", "filepath", "filepaths", "realpath", "abspath",
    "basename", "dirname", "symlink", "symlinks", "hardlink", "tempfile",
    "tmpfile", "mkdtemp", "mkdir", "rmdir", "chdir", "chroot", "traversal",
    "glob", "walkdir", "filename", "filenames", "openfile",
    # CI privileges and execution
    "ci", "cd", "pipeline", "pipelines", "workflow", "workflows", "runner",
    "runners", "dockerfile", "docker", "entrypoint", "jenkinsfile",
    "exec", "execve", "popen", "subprocess", "shell", "bash", "eval",
    "system", "spawn", "command", "commands",
    # input validation and injection
    "validate", "validates", "validated", "validation", "validator",
    "sanitize", "sanitise", "sanitizer", "sanitized", "escape", "escaped",
    "escaping", "unescape", "allowlist", "denylist", "whitelist",
    "blacklist", "normalize", "normalise", "injection", "inject", "sqli",
    "sql", "query", "queries", "prepared", "quoting", "quote",
    "vulnerability", "vulnerable", "exploit", "attacker", "untrusted",
    "malicious", "overflow", "ssrf", "rce", "lfi", "rfi", "idor",
)

# Paths whose *location* carries privilege regardless of what words are in
# them. Matched as substrings of the lowercased path, because these are exact
# filenames and directory prefixes rather than vocabulary.
SENSITIVE_PATH_MARKERS: Tuple[str, ...] = (
    ".github/workflows/", ".gitlab-ci.yml", ".gitlab/ci/", "jenkinsfile",
    "dockerfile", "docker-compose", ".circleci/", "azure-pipelines",
    ".env", "id_rsa", ".pem", ".key", ".crt", ".p12", ".jks",
    "security.md", "securitypolicy",
)

# A commit that says it is a security fix. Matched against subject, body,
# trailers and labels. `CVE-`/`GHSA-` are the identifiers; the rest is the
# shape an embargoed or coordinated fix takes when it lands.
SECURITY_SIGNAL_PATTERNS: Tuple[str, ...] = (
    r"\bcve-\d{4}-\d{4,}\b",
    r"\bghsa-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}\b",
    r"\boss-fuzz\b", r"\bosv-\d", r"\bsnyk-\b", r"\bhackerone\b",
    r"\bbug\s*bounty\b", r"\bembargo", r"\bcoordinated disclosure\b",
    r"\bresponsible disclosure\b", r"\bsecurity (fix|patch|issue|advisory|release)\b",
    r"\bsecurity[- ]sensitive\b", r"\bhardening\b", r"\bcwe-\d+\b",
    r"\bfix(es|ed)? (a |the )?(security |auth |crypto )?(vuln|vulnerability|exploit)",
)

# Labels that mean the same thing when a record carries authoritative labels.
SECURITY_LABELS: Tuple[str, ...] = (
    "security", "vulnerability", "cve", "advisory", "security-fix",
    "security fix", "sec", "appsec", "product-security", "s:security",
)

# Where labels are believed from. A record harvested from git alone carries no
# label channel at all, and `"git"` is *not* in this tuple for that reason: the
# absence of a label in a source that cannot report labels is not the absence
# of a label.
AUTHORITATIVE_LABEL_SOURCES: Tuple[str, ...] = (
    "github-api", "gitlab-api", "manual-review",
)

# Dependency manifests and locks. Excluded whole for the first corpus, per the
# brief: a bumped dependency is a change whose security relevance lives outside
# the diff, in the upstream release notes, which no reviewer here reads.
DEPENDENCY_FILES: Tuple[str, ...] = (
    "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "requirements.txt", "requirements-dev.txt", "poetry.lock",
    "pyproject.toml", "pipfile", "pipfile.lock", "setup.cfg",
    "go.mod", "go.sum", "cargo.toml", "cargo.lock", "gemfile",
    "gemfile.lock", "composer.json", "composer.lock", "pom.xml",
    "build.gradle", "build.gradle.kts", "gradle.lockfile",
    "packages.lock.json", "paket.lock", "mix.lock", "renovate.json",
    ".nvmrc", ".python-version", "dependabot.yml",
)
DEPENDENCY_SUBJECT_PATTERNS: Tuple[str, ...] = (
    r"\bbump\b", r"\bupgrade[sd]?\b", r"\bupdate[sd]? (the )?dep",
    r"\bdependabot\b", r"\brenovate\b", r"\bpin\b .*\bversion\b",
)

DOC_EXTENSIONS: Tuple[str, ...] = (
    ".md", ".markdown", ".rst", ".txt", ".adoc", ".asciidoc", ".rdoc",
    ".org", ".po", ".pot", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
)
DOC_PATH_MARKERS: Tuple[str, ...] = (
    "docs/", "doc/", "documentation/", "changelog", "authors", "contributors",
    "license", "notice", "readme", ".github/issue_template",
    ".github/pull_request_template",
)
GENERATED_PATH_MARKERS: Tuple[str, ...] = (
    "vendor/", "node_modules/", "third_party/", "dist/", "build/",
    "generated/", "gen/", ".min.js", ".min.css", "_pb2.py", "_pb2_grpc.py",
    ".pb.go", ".pb.cc", ".pb.h", ".generated.", "autogen", "__snapshots__/",
    ".snap", "swagger.json", "openapi.json",
)

# Applied top to bottom, first match decides the disposition. The order is
# itself a declared rule: `record_incomplete` is first because nothing below it
# can be evaluated over a record that is not there, and `diff_truncated` is
# second because no content rule can be believed over half a diff.
RULE_ORDER: Tuple[str, ...] = (
    "record_incomplete",
    "diff_truncated",
    "not_single_parent",
    "outside_interval",
    "security_signal",
    "sensitive_path",
    "sensitive_change",
    "dependency_update",
    "docs_or_generated_only",
    "no_supported_source",
    "diff_over_ceiling",
)

# Which rules mean "could not check" rather than "checked and excluded".
UNDECIDABLE_RULES: Tuple[str, ...] = (
    "record_incomplete", "conflicting_records",
)

REQUIRED_FIELDS: Dict[str, str] = {
    "repo": "str",
    "commit": "str",
    "parents": "int",
    "subject": "str",
    "body": "str",
    "labels": "list",
    "labels_source": "str",
    "files": "list",
    "committed_date": "str",
    "diff_text": "str",
    "diff_truncated": "bool",
}

# End of the declared block. `rules_digest` covers it.
# ---------------------------------------------------------------------------

WORD_SPLIT = re.compile(r"[^0-9a-zA-Z]+")
CAMEL_BOUNDARY = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")


class InputError(Exception):
    """The input cannot be read as a candidate set. Never a guess."""


# ---------------------------------------------------------------------------
# Small shared helpers
# ---------------------------------------------------------------------------

def words(text: str) -> set:
    """The word set of a path or a line, split on punctuation and camelCase.

    `profile` must not match `file` and `author` must not match `auth`; those
    two substring hits alone removed most of a trial pool. Splitting
    `parseRequest` into `parse` and `request` is the other half — a matcher
    that only sees snake_case is blind to every Go and Java identifier.
    """
    return set(WORD_SPLIT.split(CAMEL_BOUNDARY.sub(" ", text).lower())) - {""}


def changed_lines(diff: str) -> List[str]:
    """Only the lines the author added or removed.

    Context lines are excluded deliberately. A hunk of three added lines can sit
    inside forty lines of context that mention `request` twice, and matching
    over the whole hunk excludes the change for words its author never touched.
    The `+++`/`---` file headers are excluded for the same reason: they repeat
    the path, which the path rule already reads.
    """
    out = []
    for line in diff.splitlines():
        if line.startswith(("+++", "---")):
            continue
        if line.startswith(("+", "-")):
            out.append(line[1:])
    return out


def digest_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


def digest_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()[:16]


def canonical(record: Dict[str, Any]) -> str:
    return json.dumps(record, sort_keys=True, ensure_ascii=False)


def order_hash(repo: str, commit: str) -> str:
    """Position in the sample, from the seed and the identity of the change.

    Not the date: dates let whoever chose the interval choose the sample. Not
    `random.shuffle`: that orders the list it is handed, so a differently
    ordered input would give a different sample from the same candidates.
    """
    material = "{}\x00{}\x00{}".format(ORDER_SEED, repo, commit)
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def rules_digest() -> str:
    """A digest over the declared block, so a later edit to it is visible.

    Covers the constants themselves rather than the file, because the file also
    holds argument parsing and printing, and a changed help string is not a
    changed rule. `generator_digest` covers the whole file for the reader who
    wants the stronger statement.
    """
    parts = [
        ORDER_SEED, repr(REPO_CAP_FRACTION), repr(MIN_REPOS),
        repr(MIN_LANGUAGES), repr(sorted(LANGUAGE_EXTENSIONS.items())),
        repr(SENSITIVE_TERMS), repr(SENSITIVE_PATH_MARKERS),
        repr(SECURITY_SIGNAL_PATTERNS), repr(SECURITY_LABELS),
        repr(AUTHORITATIVE_LABEL_SOURCES), repr(DEPENDENCY_FILES),
        repr(DEPENDENCY_SUBJECT_PATTERNS), repr(DOC_EXTENSIONS),
        repr(DOC_PATH_MARKERS), repr(GENERATED_PATH_MARKERS),
        repr(RULE_ORDER), repr(UNDECIDABLE_RULES), repr(REQUIRED_FIELDS),
    ]
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()[:16]


def diff_ceilings() -> Dict[str, Any]:
    """The reviewer's real ceilings, imported from the reviewer.

    Two of them, and the smaller binds. `Workspace.MAX_DIFF_BYTES` is where git
    stops being read; `tools.MAX_DIFF_CHARS` is where the diff is trimmed before
    the model sees anything. A change under the first and over the second is one
    the reviewer reads in part — and a review of half a change scored as an
    ordinary pass is the exact reading this corpus must not produce.
    """
    return {
        "max_diff_bytes": Workspace.MAX_DIFF_BYTES,
        "max_diff_chars": MAX_DIFF_CHARS,
        "source": ("security_agent.workspace.Workspace.MAX_DIFF_BYTES and "
                   "security_agent.tools.MAX_DIFF_CHARS, imported not copied"),
    }


def corpus_languages(corpus: Path) -> Dict[str, str]:
    """Which languages the reviewer is exercised on, and each one's id prefix.

    Read from `corpus-real/*/case.yml` rather than listed here. The claim being
    tested is "the reviewer supports these languages", and the only evidence for
    it in this repository is the corpus that exercises them; a second list in
    this file would be a claim about a claim.
    """
    found: Dict[str, str] = {}
    for case in sorted(corpus.glob("*/case.yml")):
        body = yaml.safe_load(case.read_text(encoding="utf-8")) or {}
        language = body.get("language")
        if not isinstance(language, str) or not language:
            continue
        prefix = case.parent.name.split("-", 1)[0]
        found.setdefault(language, prefix)
    if not found:
        raise InputError(
            "no case under {} names a language, so there is no statement of "
            "what the reviewer covers to select against".format(corpus))
    missing = sorted(set(found) - set(LANGUAGE_EXTENSIONS))
    if missing:
        raise InputError(
            "the corpus covers {} and LANGUAGE_EXTENSIONS has no entry for "
            "them. Selecting now would silently drop every change in those "
            "languages and report a spread it never measured.".format(
                ", ".join(missing)))
    return found


def parse_day(text: str, field: str) -> datetime:
    """A YYYY-MM-DD boundary, at midnight UTC.

    A bare date is accepted and a datetime is not, so the interval cannot
    quietly depend on the operator's timezone: two people running the same
    command in Sofia and in California must select the same 30 changes.
    """
    try:
        # `%z` appended and supplied, rather than a naive parse patched up
        # afterwards: a bare `strptime` returns a datetime with no zone, and a
        # naive datetime compared against an aware one raises at the point of
        # comparison rather than here, where the message can say what to fix.
        day = datetime.strptime(text + "+0000", "%Y-%m-%d%z")
    except ValueError as exc:
        raise InputError("--{} must be YYYY-MM-DD, got {!r} ({})".format(
            field, text, exc)) from exc
    return day


def parse_commit_date(text: str) -> Optional[datetime]:
    """The committer date, or None when it cannot be read as one.

    None is a third answer here too: `committed_date` present but unparseable
    is not a date inside the interval, and the caller turns it into a refusal
    rather than into a pass.
    """
    try:
        moment = datetime.fromisoformat(text)
    except (TypeError, ValueError):
        return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc)


# ---------------------------------------------------------------------------
# The rules
# ---------------------------------------------------------------------------

def missing_fields(record: Dict[str, Any]) -> List[str]:
    """Which required fields are absent or the wrong type, named individually.

    Type is checked, not only presence. `labels: "security"` is a string that
    `in` happily searches, so a record could carry a security label as a bare
    string and every membership test would look at its characters instead. A
    record that is shaped wrongly is a record that cannot be checked.
    """
    bad = []
    for name, kind in sorted(REQUIRED_FIELDS.items()):
        value = record.get(name)
        if name not in record:
            bad.append("{} (absent)".format(name))
        elif kind == "str" and not isinstance(value, str):
            bad.append("{} (not a string)".format(name))
        elif kind == "int" and (isinstance(value, bool) or not isinstance(value, int)):
            bad.append("{} (not an integer)".format(name))
        elif kind == "bool" and not isinstance(value, bool):
            # `bool(record.get("diff_truncated"))` would read the string
            # "false" as True and an absent field as False. Both readings are
            # wrong in a direction nobody checks, so neither is allowed.
            bad.append("{} (not a boolean)".format(name))
        elif kind == "list" and not isinstance(value, list):
            bad.append("{} (not a list)".format(name))
    if not bad:
        if not record["repo"].strip():
            bad.append("repo (empty)")
        if not COMMIT_RE.match(record["commit"].strip().lower()):
            bad.append("commit (not a 40-character hex sha)")
        if not record["files"]:
            bad.append("files (empty; a change with no file is not a change)")
        if any(not isinstance(p, str) or not p.strip() for p in record["files"]):
            bad.append("files (holds something that is not a path)")
        if any(not isinstance(lb, str) for lb in record["labels"]):
            bad.append("labels (holds something that is not a label)")
        if parse_commit_date(record["committed_date"]) is None:
            bad.append("committed_date (not an ISO 8601 timestamp)")
    return bad


def rule_diff_truncated(record: Dict[str, Any], ctx: Dict[str, Any]) -> Optional[str]:
    if record["diff_truncated"]:
        return ("the diff was not read whole at harvest, so no rule below "
                "could be evaluated over its content")
    return None


def rule_not_single_parent(record: Dict[str, Any], ctx: Dict[str, Any]) -> Optional[str]:
    parents = record["parents"]
    if parents != 1:
        return ("{} parent(s); a merge has no single diff of its own and a "
                "root commit is not a change to anything".format(parents))
    return None


def rule_outside_interval(record: Dict[str, Any], ctx: Dict[str, Any]) -> Optional[str]:
    moment = parse_commit_date(record["committed_date"])
    # `moment` cannot be None here: `record_incomplete` already refused an
    # unparseable date, and this rule is only reached past it.
    if moment < ctx["since"] or moment >= ctx["until"]:
        return "committed {}, outside [{}, {})".format(
            moment.date().isoformat(), ctx["since"].date().isoformat(),
            ctx["until"].date().isoformat())
    return None


def rule_security_signal(record: Dict[str, Any], ctx: Dict[str, Any]) -> Optional[str]:
    text = "\n".join([record["subject"], record["body"]] + record["labels"]).lower()
    for pattern in SECURITY_SIGNAL_PATTERNS:
        found = re.search(pattern, text)
        if found:
            return "message matches {!r} at {!r}".format(pattern, found.group(0))
    if record["labels_source"] in AUTHORITATIVE_LABEL_SOURCES:
        marked = sorted({lb for lb in (x.lower() for x in record["labels"])
                         if lb in SECURITY_LABELS})
        if marked:
            return "labelled {}".format(", ".join(marked))
    return None


def rule_sensitive_path(record: Dict[str, Any], ctx: Dict[str, Any]) -> Optional[str]:
    for path in record["files"]:
        low = path.lower()
        for marker in SENSITIVE_PATH_MARKERS:
            if marker in low:
                return "{} matches the privileged location {!r}".format(path, marker)
        hit = sorted(words(path) & set(SENSITIVE_TERMS))
        if hit:
            return "{} carries {}".format(path, ", ".join(hit))
    return None


def rule_sensitive_change(record: Dict[str, Any], ctx: Dict[str, Any]) -> Optional[str]:
    seen = set()
    for line in changed_lines(record["diff_text"]):
        seen |= words(line) & set(SENSITIVE_TERMS)
        if len(seen) >= 4:
            break
    if seen:
        return "added or removed lines carry {}".format(", ".join(sorted(seen)))
    return None


def rule_dependency_update(record: Dict[str, Any], ctx: Dict[str, Any]) -> Optional[str]:
    for path in record["files"]:
        base = path.rsplit("/", 1)[-1].lower()
        if base in DEPENDENCY_FILES:
            return "touches the dependency manifest {}".format(path)
    subject = record["subject"].lower()
    for pattern in DEPENDENCY_SUBJECT_PATTERNS:
        if re.search(pattern, subject):
            return "subject matches {!r}".format(pattern)
    return None


def _is_doc(path: str) -> bool:
    low = path.lower()
    return (low.endswith(DOC_EXTENSIONS)
            or any(marker in low for marker in DOC_PATH_MARKERS))


def _is_generated(path: str) -> bool:
    low = path.lower()
    return any(marker in low for marker in GENERATED_PATH_MARKERS)


def rule_docs_or_generated_only(record: Dict[str, Any],
                                ctx: Dict[str, Any]) -> Optional[str]:
    if all(_is_doc(p) or _is_generated(p) for p in record["files"]):
        return ("every path is documentation or generated output; there is no "
                "hand-written source for the reviewer to be quiet about")
    return None


def languages_of(record: Dict[str, Any], supported: Dict[str, str]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for path in record["files"]:
        if _is_generated(path):
            continue
        low = path.lower()
        for language in supported:
            if low.endswith(LANGUAGE_EXTENSIONS[language]):
                counts[language] = counts.get(language, 0) + 1
                break
    return counts


def rule_no_supported_source(record: Dict[str, Any],
                             ctx: Dict[str, Any]) -> Optional[str]:
    if not languages_of(record, ctx["supported"]):
        return ("no changed file is hand-written source in {}".format(
            ", ".join(sorted(ctx["supported"]))))
    return None


def rule_diff_over_ceiling(record: Dict[str, Any], ctx: Dict[str, Any]) -> Optional[str]:
    diff = record["diff_text"]
    chars, size = len(diff), len(diff.encode("utf-8"))
    if chars > ctx["ceilings"]["max_diff_chars"]:
        return "{} characters, over the {} the reviewer shows the model".format(
            chars, ctx["ceilings"]["max_diff_chars"])
    if size > ctx["ceilings"]["max_diff_bytes"]:
        return "{} bytes, over the {} the reviewer reads from git".format(
            size, ctx["ceilings"]["max_diff_bytes"])
    return None


RULES = {
    "diff_truncated": rule_diff_truncated,
    "not_single_parent": rule_not_single_parent,
    "outside_interval": rule_outside_interval,
    "security_signal": rule_security_signal,
    "sensitive_path": rule_sensitive_path,
    "sensitive_change": rule_sensitive_change,
    "dependency_update": rule_dependency_update,
    "docs_or_generated_only": rule_docs_or_generated_only,
    "no_supported_source": rule_no_supported_source,
    "diff_over_ceiling": rule_diff_over_ceiling,
}


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------

def evaluate(record: Dict[str, Any], ctx: Dict[str, Any]) -> Dict[str, Any]:
    """One candidate, judged against every rule, with all of them recorded.

    The first firing rule decides the disposition, because the order is
    declared. All of them are kept because "excluded by `sensitive_path`" and
    "excluded by `sensitive_path`, and also a dependency bump, and also over the
    ceiling" are different pictures of the pool, and only the second one tells
    the operator which rule to argue with when the pool comes out too thin.
    """
    repo = record.get("repo") if isinstance(record.get("repo"), str) else ""
    commit = record.get("commit") if isinstance(record.get("commit"), str) else ""
    row: Dict[str, Any] = {
        "repo": repo,
        "commit": commit,
        "order_hash": order_hash(repo, commit) if repo and commit else None,
        "subject": record.get("subject") if isinstance(record.get("subject"), str) else "",
    }

    bad = missing_fields(record)
    if bad:
        row.update({
            "disposition": "undecidable",
            "rule": "record_incomplete",
            "reason": "cannot be checked: " + "; ".join(bad),
            "rules_fired": ["record_incomplete"],
        })
        return row

    fired = []
    for name in RULE_ORDER:
        if name == "record_incomplete":
            continue
        reason = RULES[name](record, ctx)
        if reason is not None:
            fired.append({"rule": name, "reason": reason})

    counts = languages_of(record, ctx["supported"])
    row.update({
        "committed_date": record["committed_date"],
        "files": len(record["files"]),
        "diff_chars": len(record["diff_text"]),
        "diff_bytes": len(record["diff_text"].encode("utf-8")),
        "languages_touched": sorted(counts),
        # Ties broken alphabetically rather than by file order, so the same
        # change keeps the same case id whichever way the files were listed.
        "language": (sorted(counts, key=lambda k: (-counts[k], k))[0]
                     if counts else None),
        # Recorded on every candidate, taken or not. "git reports no labels"
        # and "the project attached no security label" are different facts and
        # the adjudicator is told which one this is.
        "label_evidence": ("authoritative"
                           if record["labels_source"] in AUTHORITATIVE_LABEL_SOURCES
                           else "unavailable"),
        "labels_source": record["labels_source"],
        "rules_fired": [f["rule"] for f in fired],
        "rules_detail": fired,
    })

    if fired:
        row["disposition"] = "excluded"
        row["rule"] = fired[0]["rule"]
        row["reason"] = fired[0]["reason"]
    else:
        row["disposition"] = "eligible"
        row["rule"] = None
        row["reason"] = None
        row["case_id"] = "ord-{}-{}".format(
            ctx["supported"][row["language"]], row["order_hash"][:8])
    return row


def group_duplicates(records: Sequence[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]],
                                                                 List[Dict[str, Any]]]:
    """Collapse identical repeats; refuse to choose between contradictory ones.

    Two records for one commit are not a harmless repeat. If they are byte-equal
    the second carries nothing, and dropping it by position would make the
    sample depend on input order. If they differ, one of them is wrong and this
    program has no way to tell which — so both are refused as `undecidable`
    rather than resolved by whichever the caller happened to list first.
    """
    groups: Dict[Any, List[Dict[str, Any]]] = {}
    for index, record in enumerate(records):
        repo, commit = record.get("repo"), record.get("commit")
        key = ((repo.strip(), commit.strip().lower())
               if isinstance(repo, str) and isinstance(commit, str)
               else ("\x00unidentified", index))
        groups.setdefault(key, []).append(record)

    unique, conflicts = [], []
    for key in sorted(groups, key=lambda k: (str(k[0]), str(k[1]))):
        members = groups[key]
        forms = sorted({canonical(m) for m in members})
        if len(forms) == 1:
            copy = dict(members[0])
            if len(members) > 1:
                copy["_duplicate_copies"] = len(members)
            unique.append(copy)
            continue
        for form in forms:
            member = json.loads(form)
            conflicts.append({
                "repo": key[0] if isinstance(key[0], str) else "",
                "commit": str(key[1]),
                "order_hash": None,
                "subject": member.get("subject") if isinstance(
                    member.get("subject"), str) else "",
                "disposition": "undecidable",
                "rule": "conflicting_records",
                "reason": ("{} records name this commit and they do not "
                           "agree; which one is true is not decidable "
                           "here".format(len(members))),
                "rules_fired": ["conflicting_records"],
            })
    return unique, conflicts


def select(records: Sequence[Dict[str, Any]], ctx: Dict[str, Any],
           target: int) -> Dict[str, Any]:
    """Evaluate everything, order by hash, draw under the per-repository cap."""
    unique, conflicts = group_duplicates(records)
    rows = [evaluate(r, ctx) for r in unique] + conflicts

    eligible = [r for r in rows if r["disposition"] == "eligible"]
    # Hash first, then repo and commit. The tie-break is not decoration: two
    # commits sharing a 64-hex prefix will not happen, but a sort with no total
    # order is a sort whose output depends on the input order, which is the one
    # property this function exists to remove.
    eligible.sort(key=lambda r: (r["order_hash"], r["repo"], r["commit"]))

    cap = max(1, math.ceil(target * REPO_CAP_FRACTION))
    per_repo: Dict[str, int] = {}
    selected = []
    for row in eligible:
        if len(selected) >= target:
            row["disposition"] = "not_selected"
            row["reason"] = "the sample was already full at {}".format(target)
            continue
        if per_repo.get(row["repo"], 0) >= cap:
            row["disposition"] = "not_selected"
            row["reason"] = ("{} had already contributed {}, the cap for a "
                             "sample of {}".format(row["repo"], cap, target))
            continue
        per_repo[row["repo"]] = per_repo.get(row["repo"], 0) + 1
        row["disposition"] = "taken"
        selected.append(row)

    ids = [r["case_id"] for r in selected]
    if len(set(ids)) != len(ids):
        raise InputError(
            "two selected changes were given the same case id: {}. A sample "
            "whose members cannot be told apart cannot be adjudicated.".format(
                sorted({i for i in ids if ids.count(i) > 1})))

    rows.sort(key=lambda r: (r["order_hash"] or "", r["repo"], r["commit"]))
    languages = sorted({r["language"] for r in selected})
    repos = sorted({r["repo"] for r in selected})
    counts = {name: sum(1 for r in rows if r["disposition"] == name)
              for name in ("taken", "not_selected", "excluded", "undecidable")}
    by_rule: Dict[str, int] = {}
    for row in rows:
        if row["disposition"] in ("excluded", "undecidable"):
            by_rule[row["rule"]] = by_rule.get(row["rule"], 0) + 1

    checks = [
        {"name": "sample_filled", "required": target,
         "observed": len(selected), "met": len(selected) == target,
         "remedy": "widen the date interval or add repositories to the pool"},
        {"name": "distinct_repositories", "required": MIN_REPOS,
         "observed": len(repos), "met": len(repos) >= MIN_REPOS,
         "remedy": "add repositories; D-013 asks for at least ten"},
        {"name": "distinct_languages", "required": MIN_LANGUAGES,
         "observed": len(languages), "met": len(languages) >= MIN_LANGUAGES,
         "remedy": ("add repositories in the languages the corpus covers that "
                    "the sample does not")},
    ]

    return {
        "rows": rows,
        "selected": selected,
        "counts": counts,
        "excluded_by_rule": dict(sorted(by_rule.items())),
        "per_repo": dict(sorted(per_repo.items())),
        "languages": {lang: sum(1 for r in selected if r["language"] == lang)
                      for lang in languages},
        "label_evidence_unavailable": sum(
            1 for r in selected if r.get("label_evidence") == "unavailable"),
        "per_repo_cap": cap,
        "checks": checks,
        "complete": all(c["met"] for c in checks),
    }


# ---------------------------------------------------------------------------
# Manifest
# ---------------------------------------------------------------------------

def build_manifest(name: str, outcome: Dict[str, Any], ctx: Dict[str, Any],
                   target: int, source: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "corpus": name,
        # Not "changes that were never vulnerable". Nothing here establishes
        # that, and the tool's own protocol says so: the rules remove changes
        # that *touch* a sensitive area, and whether what is left is ordinary
        # is the one question two people answer by hand afterwards. An artifact
        # that states the conclusion its own process has not reached yet is the
        # defect this repository is built to catch, printed on the cover.
        "purpose": ("The sampling frame for D-013's second rule: changes drawn "
                    "mechanically, before any result was seen, for two people "
                    "to adjudicate as ordinary or not. Selection is not a "
                    "finding that a change is safe."),
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "generator": {
            "tool": "tools/ordinary_corpus.py",
            "generator_digest": digest_file(Path(__file__).resolve()),
            "rules_digest": rules_digest(),
        },
        "rules": {
            "order_seed": ORDER_SEED,
            "target": target,
            "per_repo_cap": outcome["per_repo_cap"],
            "per_repo_cap_fraction": REPO_CAP_FRACTION,
            "min_repositories": MIN_REPOS,
            "min_languages": MIN_LANGUAGES,
            "interval": {
                "since": ctx["since"].date().isoformat(),
                "until": ctx["until"].date().isoformat(),
                "boundaries": "since inclusive, until exclusive, committer date, UTC",
            },
            "exclusion_order": list(RULE_ORDER),
            "undecidable_rules": list(UNDECIDABLE_RULES),
            "ceilings": ctx["ceilings"],
            "supported_languages": {
                "languages": dict(sorted(ctx["supported"].items())),
                "source": "corpus-real/*/case.yml, read at selection time",
            },
        },
        "protocol": {
            "primary_endpoint": (
                "of the selected changes, how many produce at least one "
                "adjudicated unfounded finding presented as actionable."),
            "thresholds_at_100": {
                "pass_at_or_below": 9, "fail_at_or_above": 21,
                "between": "undecided, which is not a pass",
                "also_required": "at least 90% finish under the limits",
            },
            "adjudication": (
                "two independent humans per change, verdict one of ordinary / "
                "not_ordinary / unclear. `unclear` enters neither numerator "
                "nor denominator, per D-013."),
            "not_answerable": (
                "whether any selected change is in fact free of a weakness. "
                "The rules below remove changes that touch a security-relevant "
                "area; they do not certify what is left. That is the human "
                "step, and this manifest is its input, not its result."),
            "label_channel": (
                "candidates marked label_evidence 'unavailable' came from a "
                "source that cannot report labels at all. The absence of a "
                "security label in such a record is not evidence there was "
                "none, and the adjudication template makes a human say so."),
            "after_the_result": (
                "D-013: once the result is seen, no adjustment — not to the "
                "prompt, the verifier, the model, the schema, the scorer, or "
                "these eligibility rules."),
        },
        "input": source,
        "counts": outcome["counts"],
        "excluded_by_rule": outcome["excluded_by_rule"],
        "coverage": {
            "repositories": outcome["per_repo"],
            "languages": outcome["languages"],
            "label_evidence_unavailable": outcome["label_evidence_unavailable"],
            "checks": outcome["checks"],
        },
        "complete": outcome["complete"],
        "selected": [{"case_id": r["case_id"], "repo": r["repo"],
                      "commit": r["commit"], "language": r["language"],
                      "order_hash": r["order_hash"],
                      "label_evidence": r["label_evidence"],
                      "diff_bytes": r["diff_bytes"],
                      "subject": r["subject"]} for r in outcome["selected"]],
        "candidates": outcome["rows"],
    }


def publish(target: Path, text: str) -> bool:
    """Write beside the target and rename, or leave nothing behind.

    Lifted from `experiment.py` on purpose, including the link-then-unlink: a
    manifest quietly overwritten by a second run is the failure that leaves the
    comparison looking perfectly ordinary.
    """
    temporary = target.with_name("{}.writing.{}".format(target.name, os.getpid()))
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        temporary.write_text(text, encoding="utf-8")
        os.link(temporary, target)
        temporary.unlink()
        return True
    except OSError as exc:
        temporary.unlink(missing_ok=True)
        print("could not write {}: {}".format(target, exc), file=sys.stderr)
        return False


def load_candidates(path: Path) -> List[Dict[str, Any]]:
    """The candidate list, or a refusal. Never a partial read.

    A file holding one record instead of a list, or a list with a string in it,
    is refused rather than filtered. `[good_record, "oops"]` filtered down to
    one record is a pool the operator thinks has two things in it.
    """
    try:
        body = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise InputError("{}: cannot be read as JSON ({})".format(path, exc)) from exc
    if isinstance(body, dict) and isinstance(body.get("candidates"), list):
        body = body["candidates"]
    if not isinstance(body, list):
        raise InputError(
            "{}: holds {}, and a candidate set is a list of records (or an "
            "object with a `candidates` list)".format(path, type(body).__name__))
    for index, item in enumerate(body):
        if not isinstance(item, dict):
            raise InputError(
                "{}: entry {} is {}, not a record. A pool with something "
                "unreadable in it is not a pool of a known size.".format(
                    path, index, type(item).__name__))
    return body


def context(since: str, until: str, corpus: Path) -> Dict[str, Any]:
    start, end = parse_day(since, "since"), parse_day(until, "until")
    if start >= end:
        raise InputError("--since {} is not before --until {}".format(since, until))
    return {
        "since": start,
        "until": end,
        "supported": corpus_languages(corpus),
        "ceilings": diff_ceilings(),
    }


# ---------------------------------------------------------------------------
# harvest — local clones only, no network
# ---------------------------------------------------------------------------

def git(clone: Path, *args: str) -> str:
    done = subprocess.run(["git", "-C", str(clone), *args],
                          capture_output=True, text=True, check=False)
    if done.returncode != 0:
        raise InputError("git {} failed in {}: {}".format(
            " ".join(args), clone, done.stderr.strip()))
    return done.stdout


def repo_name(clone: Path) -> Tuple[str, str]:
    """A stable identity for the repository, and where it came from.

    The remote URL rather than the directory name: the directory is whatever
    the operator typed, and two people cloning the same project into differently
    named directories would produce two different sets of 30 changes from the
    same commits.
    """
    try:
        url = git(clone, "config", "--get", "remote.origin.url").strip()
    except InputError:
        url = ""
    if not url:
        return clone.name, "directory-name"
    url = re.sub(r"^\w+://", "", url)
    url = re.sub(r"^[^/@]+@", "", url).replace(":", "/", 1)
    return re.sub(r"\.git$", "", url).strip("/"), "remote.origin.url"


def harvest_clone(clone: Path, since: str, until: str,
                  read_limit: int) -> List[Dict[str, Any]]:
    name, source = repo_name(clone)
    shas = git(clone, "log", "--since={}".format(since), "--until={}".format(until),
               "--pretty=format:%H").split()
    out = []
    for sha in shas:
        head = git(clone, "show", "--no-patch", "--pretty=format:%P%x00%cI%x00%s%x00%b",
                   sha)
        parents, date, subject, body = [*head.split("\x00", 3), "", "", "", ""][:4]
        files = [p for p in git(clone, "show", "--pretty=format:", "--name-only", sha
                                ).splitlines() if p.strip()]
        diff = git(clone, "show", "--pretty=format:", "--unified=3", sha)
        truncated = len(diff.encode("utf-8")) > read_limit
        if truncated:
            # Kept short rather than kept whole. The content rules will not be
            # believed over it anyway — `diff_truncated` fires before them — and
            # a manifest carrying megabytes of a diff nobody will read is a
            # manifest nobody opens.
            diff = diff[:1000]
        out.append({
            "repo": name,
            "repo_name_source": source,
            "commit": sha,
            "parents": len(parents.split()) if parents.strip() else 0,
            "committed_date": date,
            "subject": subject,
            "body": body,
            # Empty, and honestly labelled. git has no label channel; saying
            # `"labels_source": "git"` here is what stops the selector from
            # reading this empty list as "the project attached no security
            # label to this change".
            "labels": [],
            "labels_source": "git",
            "files": files,
            "diff_text": diff,
            "diff_truncated": truncated,
        })
    return out


def cmd_harvest(args: argparse.Namespace) -> int:
    clones = sorted(p for p in Path(args.clones).iterdir()
                    if (p / ".git").exists() or (p / "HEAD").exists())
    if not clones:
        print("no git clone under {}".format(args.clones), file=sys.stderr)
        return 2
    limit = 2 * Workspace.MAX_DIFF_BYTES
    records: List[Dict[str, Any]] = []
    for index, clone in enumerate(clones, 1):
        print("  [{}/{}] {}".format(index, len(clones), clone.name), flush=True)
        got = harvest_clone(clone, args.since, args.until, limit)
        print("        {} commit(s)".format(len(got)), flush=True)
        records.extend(got)
    text = json.dumps(records, indent=2, ensure_ascii=False) + "\n"
    if not publish(Path(args.out), text):
        return 2
    print("{} candidate(s) from {} repositor(ies) written to {}".format(
        len(records), len(clones), args.out))
    print("No rule has been applied yet. Run `select` next.")
    return 0


# ---------------------------------------------------------------------------
# select / check / template
# ---------------------------------------------------------------------------

def report(manifest: Dict[str, Any]) -> None:
    counts = manifest["counts"]
    print("  taken {taken} · eligible but not drawn {not_selected} · "
          "excluded {excluded} · undecidable {undecidable}".format(**counts))
    if manifest["excluded_by_rule"]:
        print("  rules that fired first:")
        for rule, n in sorted(manifest["excluded_by_rule"].items(),
                              key=lambda kv: (-kv[1], kv[0])):
            print("    {:<24} {}".format(rule, n))
    coverage = manifest["coverage"]
    print("  languages: {}".format(", ".join(
        "{} {}".format(k, v) for k, v in sorted(coverage["languages"].items()))
        or "none"))
    print("  repositories: {}".format(len(coverage["repositories"])))
    if coverage["label_evidence_unavailable"]:
        print("  {} selected change(s) came from a source with no label "
              "channel — a human must confirm no upstream security label"
              .format(coverage["label_evidence_unavailable"]))
    for check in coverage["checks"]:
        if not check["met"]:
            print("  NOT MET · {}: {} of {} — {}".format(
                check["name"], check["observed"], check["required"],
                check["remedy"]), file=sys.stderr)


def cmd_select(args: argparse.Namespace) -> int:
    ctx = context(args.since, args.until, Path(args.corpus))
    path = Path(args.candidates)
    records = load_candidates(path)
    print("{} candidate(s) read from {}".format(len(records), path), flush=True)
    outcome = select(records, ctx, args.target)
    manifest = build_manifest(args.name, outcome, ctx, args.target, {
        "file": str(path),
        "digest": digest_file(path),
        "records": len(records),
    })
    report(manifest)
    if not publish(Path(args.out), json.dumps(manifest, indent=2,
                                              ensure_ascii=False) + "\n"):
        return 2
    print("Written to {}.".format(args.out))
    if not manifest["complete"]:
        # Written and then refused. The manifest is the diagnosis — which rule
        # ate the pool, which language is missing — and withholding it would
        # leave the operator with an exit code and no way to act on it. But the
        # exit code is 2: a short sample is not a sample.
        print("\nThis is not a usable sample. Exit 2 — see NOT MET above.",
              file=sys.stderr)
        return 2
    print("Next: `template` for the adjudication skeleton. Two humans, "
          "independently, before any review is bought.")
    return 0


# Fields that legitimately differ between the freeze and a later check.
# `created_at` is when the document was written; `generator_digest` is checked
# separately above, with its own message, because an edit to the tool that
# leaves the declared rules alone is a different fact from an edit to a rule.
CHECK_IGNORES = ("created_at", "generator.generator_digest")


def _differences(was, now, path="") -> List[str]:
    """Every field where the stored document and the re-derived one disagree.

    Named individually and by path. "The manifest differs" tells an operator
    nothing about which edit to look for, and the edits this is guarding
    against — a rewritten `counts`, a `label_evidence` flipped from
    `unavailable` to `authoritative`, an emptied `excluded_by_rule` — are all
    single fields buried in a large document.
    """
    if path in CHECK_IGNORES:
        return []
    out: List[str] = []
    if isinstance(was, dict) and isinstance(now, dict):
        for key in sorted(set(was) | set(now)):
            here = "{}.{}".format(path, key) if path else key
            if key not in was:
                out.append("{}: absent from the manifest, the rules give {!r}"
                           .format(here, now[key]))
            elif key not in now:
                out.append("{}: the manifest says {!r}, the rules give nothing"
                           .format(here, was[key]))
            else:
                out.extend(_differences(was[key], now[key], here))
        return out
    if isinstance(was, list) and isinstance(now, list):
        if len(was) != len(now):
            return ["{}: {} entries in the manifest, {} from the rules".format(
                path or "selected", len(was), len(now))]
        for i, (a, b) in enumerate(zip(was, now)):
            out.extend(_differences(a, b, "{}[{}]".format(path, i)))
        return out
    if was != now:
        out.append("{}: the manifest says {!r}, the rules give {!r}".format(
            path or "the document", was, now))
    return out


def cmd_check(args: argparse.Namespace) -> int:
    """Re-derive the selection and prove the manifest is what the rules give.

    Three separate claims, each with its own failure: the input has not moved,
    the rules have not moved, and the same rules over the same input still give
    the same 30. A tool that only re-ran the selection would pass happily over
    an edited rule block, which is the exact edit this is guarding.

    **The whole manifest is compared, not the list of case ids.** The first
    version compared ids alone and printed "Reproduced" over a manifest whose
    counts said `taken: 7` beside thirty rows, whose `coverage.repositories`
    named one repository, whose `excluded` rows had been relabelled
    `not_selected` with the rejection table emptied, and — worst — whose
    `label_evidence` had been flipped from `unavailable` to `authoritative` on
    every row. `cmd_template` copies that field straight through, so the flip
    tells the adjudicator the label channel was not blind and they skip the one
    check the manifest's own text says they must make by hand.

    A check that verifies less than it announces is worse than no check: it
    converts "nobody looked" into "somebody looked and it was fine".
    """
    manifest = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
    problems = []

    now_rules, now_gen = rules_digest(), digest_file(Path(__file__).resolve())
    if manifest["generator"]["rules_digest"] != now_rules:
        problems.append("the declared rules have been edited since the freeze "
                        "({} -> {})".format(manifest["generator"]["rules_digest"],
                                            now_rules))
    if manifest["generator"]["generator_digest"] != now_gen:
        problems.append("the tool's source has changed since the freeze "
                        "({} -> {}); harmless if the rules digest above "
                        "holds".format(manifest["generator"]["generator_digest"],
                                       now_gen))

    path = Path(args.candidates)
    if digest_file(path) != manifest["input"]["digest"]:
        problems.append("{} is not the file this manifest was built from"
                        .format(path))

    interval = manifest["rules"]["interval"]
    ctx = context(interval["since"], interval["until"], Path(args.corpus))
    outcome = select(load_candidates(path), ctx, manifest["rules"]["target"])
    again = [r["case_id"] for r in outcome["selected"]]
    before = [r["case_id"] for r in manifest["selected"]]
    if again != before:
        problems.append("the selection no longer reproduces: {} then, {} now"
                        .format(len(before), len(again)))
    else:
        # Rebuild the whole document and compare it, rather than picking fields
        # to check. Picking is how the first version came to verify the case
        # ids and nothing else, and a list of fields to compare drifts from the
        # list of fields written the moment somebody adds one.
        rebuilt = build_manifest(manifest.get("corpus", ""), outcome, ctx,
                                 manifest["rules"]["target"],
                                 manifest.get("input", {}))
        problems.extend(_differences(manifest, rebuilt))

    for line in problems:
        print("  " + line, file=sys.stderr)
    if problems:
        print("Not reproduced.", file=sys.stderr)
        return 2
    print("Reproduced: {} change(s), same rules, same input.".format(len(before)))
    return 0


def cmd_template(args: argparse.Namespace) -> int:
    """The skeleton the two adjudicators fill in, with every verdict null.

    `null`, not `false` and not an empty string. An unfilled verdict must be
    impossible to count: whatever tallies these has to refuse a null, and a
    default of `false` would silently mean "not noisy" for every change nobody
    ever looked at.
    """
    manifest = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
    cases = {}
    for entry in manifest["selected"]:
        cases[entry["case_id"]] = {
            "repo": entry["repo"],
            "commit": entry["commit"],
            "language": entry["language"],
            "subject": entry["subject"],
            # Two independent verdicts, not one. D-013 step 2 says doubly
            # adjudicated, and a single field would make the second reader's
            # job "agree or disagree with what is already written".
            "verdict_a": None,
            "verdict_b": None,
            "verdict_values": "ordinary | not_ordinary | unclear",
            # Only meaningful where the manifest says the label channel was
            # blind, but present on every case so nobody has to notice which.
            "label_evidence": entry["label_evidence"],
            "upstream_security_label_checked_by_hand": None,
            "note_a": "",
            "note_b": "",
        }
    body = {
        "corpus": manifest["corpus"],
        "manifest": str(args.manifest),
        "generator_digest": manifest["generator"]["generator_digest"],
        "rules_digest": manifest["generator"]["rules_digest"],
        "instructions": (
            "Two people fill verdict_a and verdict_b without seeing each "
            "other's. `unclear` is a real answer and enters neither numerator "
            "nor denominator. Where label_evidence is 'unavailable', check the "
            "upstream issue or PR for a security label before answering, and "
            "record that you did. No review is run until every verdict is "
            "filled: a change adjudicated after its result is seen is a change "
            "adjudicated by the result."),
        "cases": cases,
    }
    text = yaml.safe_dump(body, sort_keys=False, allow_unicode=True)
    if not publish(Path(args.out), text):
        return 2
    print("{} case(s) written to {}. Every verdict is null on purpose."
          .format(len(cases), args.out))
    return 0


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)

    h = sub.add_parser("harvest", help="build candidate records from local clones")
    h.add_argument("--clones", required=True, help="directory of git clones")
    h.add_argument("--since", required=True, help="YYYY-MM-DD, inclusive")
    h.add_argument("--until", required=True, help="YYYY-MM-DD, exclusive")
    h.add_argument("--out", required=True)
    h.set_defaults(func=cmd_harvest)

    s = sub.add_parser("select", help="apply the declared rules and draw the sample")
    s.add_argument("--candidates", required=True)
    s.add_argument("--since", required=True, help="YYYY-MM-DD, inclusive")
    s.add_argument("--until", required=True, help="YYYY-MM-DD, exclusive")
    s.add_argument("--target", type=int, default=30)
    s.add_argument("--name", default="ordinary-v1")
    s.add_argument("--corpus", default=str(ROOT / "corpus-real"))
    s.add_argument("--out", required=True)
    s.set_defaults(func=cmd_select)

    c = sub.add_parser("check", help="prove the manifest reproduces from its input")
    c.add_argument("--manifest", required=True)
    c.add_argument("--candidates", required=True)
    c.add_argument("--corpus", default=str(ROOT / "corpus-real"))
    c.set_defaults(func=cmd_check)

    t = sub.add_parser("template", help="write the adjudication skeleton")
    t.add_argument("--manifest", required=True)
    t.add_argument("--out", required=True)
    t.set_defaults(func=cmd_template)

    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except InputError as exc:
        # Exit 2, never 1. "I could not build a sample" and "the sample says
        # something" are different answers, and this repository spends the
        # distinction everywhere else.
        print(str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
