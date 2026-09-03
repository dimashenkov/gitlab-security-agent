"""Hostile audit of `tools/ordinary_corpus.py`.

Every test here asserts the CORRECT behaviour and is marked `xfail(strict=True)`.
A test that starts passing means the defect it names has been fixed and the mark
must come off. A test that starts *failing to xfail* means the defect is back in
a different shape.

Nothing here spends money: no `claude`, no network, no clone. `harvest` is
exercised against a git repository built in `tmp_path`.
"""

from __future__ import annotations

import json
import subprocess
import sys
from collections import Counter
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import ordinary_corpus as oc  # noqa: E402

PLAIN_DIFF = (
    "diff --git a/pkg/greet.go b/pkg/greet.go\n"
    "--- a/pkg/greet.go\n"
    "+++ b/pkg/greet.go\n"
    "@@ -1,3 +1,3 @@\n"
    " package pkg\n"
    "-func Greet(n string) string { return \"hi \" + n }\n"
    "+func Greet(who string) string { return \"hello \" + who }\n"
)

LANGUAGE_FILES = ("pkg/greet.go", "pkg/greet.py", "pkg/greet.php",
                  "pkg/greet.ts", "pkg/greet.rs", "pkg/greet.rb")


def record(repo: str, commit: str, **over):
    body = {
        "repo": repo,
        "commit": commit,
        "parents": 1,
        "committed_date": "2026-03-04T10:00:00+00:00",
        "subject": "rename the greeting argument",
        "body": "",
        "labels": [],
        "labels_source": "git",
        "files": ["pkg/greet.go"],
        "diff_text": PLAIN_DIFF,
        "diff_truncated": False,
    }
    body.update(over)
    return body


def sha(seed: str) -> str:
    import hashlib
    return hashlib.sha256(seed.encode()).hexdigest()[:40]


@pytest.fixture
def corpus(tmp_path):
    root = tmp_path / "corpus-real"
    for prefix, language in (("py", "python"), ("go", "go"), ("php", "php"),
                             ("ts", "typescript"), ("rs", "rust"),
                             ("rb", "ruby"), ("cs", "csharp"),
                             ("jv", "java"), ("js", "javascript")):
        directory = root / "{}-aaaa-bbbb-cccc".format(prefix)
        directory.mkdir(parents=True)
        (directory / "case.yml").write_text(
            yaml.safe_dump({"case_id": directory.name, "language": language}),
            encoding="utf-8")
    return root


@pytest.fixture
def ctx(corpus):
    return oc.context("2026-01-01", "2026-07-01", corpus)


def pool(n_repos=12, per_repo=4):
    out = []
    for r in range(n_repos):
        filename = LANGUAGE_FILES[r % len(LANGUAGE_FILES)]
        for c in range(per_repo):
            out.append(record("host/repo{:02d}".format(r),
                              sha("{}:{}".format(r, c)), files=[filename]))
    return out


def write_pool(tmp_path, records):
    path = tmp_path / "candidates.json"
    path.write_text(json.dumps(records, indent=2), encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# 1. The per-repository cap counts spellings, not repositories.
#
# `group_duplicates` (ordinary_corpus.py:773) normalises the identity with
# `repo.strip()` / `commit.strip().lower()`. `evaluate` (:698) and the cap in
# `select` (:827,:832) use the raw string. So one repository written twelve
# slightly different ways is twelve repositories to the cap and to the
# `distinct_repositories` check, and the sample can be drawn entirely from one
# project while the manifest reports `complete: true`.
# ---------------------------------------------------------------------------

@pytest.mark.xfail(strict=True, reason=(
    "select() keys the per-repository cap and the distinct_repositories check "
    "on the raw `repo` string, while group_duplicates already strips it; one "
    "project spelled with trailing spaces fills the whole sample"))
def test_the_repo_cap_counts_repositories_not_spellings(ctx):
    records = []
    for spelling in range(12):
        name = "host/only" + " " * spelling
        for c in range(3):
            records.append(record(name, sha("{}:{}".format(spelling, c)),
                                  files=[LANGUAGE_FILES[spelling % 6]]))
    outcome = oc.select(records, ctx, 30)
    assert len(outcome["selected"]) == 30
    drawn = Counter(r["repo"].strip() for r in outcome["selected"])
    assert max(drawn.values()) <= outcome["per_repo_cap"], (
        "one repository contributed {} of {} changes under a cap of {}; the "
        "run reports complete={} and {} distinct repositories".format(
            max(drawn.values()), len(outcome["selected"]),
            outcome["per_repo_cap"], outcome["complete"],
            len(outcome["per_repo"])))


@pytest.mark.xfail(strict=True, reason=(
    "order_hash() is computed over the raw repo/commit strings, so upcasing a "
    "sha the record's own validator already lowercases re-rolls that "
    "candidate's position in the sample"))
def test_upcasing_a_sha_does_not_move_a_candidate_in_the_order(ctx):
    lower = record("host/x", sha("a"))
    upper = record("host/x", sha("a").upper())
    # missing_fields() accepts both: it validates commit.strip().lower().
    assert oc.missing_fields(lower) == [] and oc.missing_fields(upper) == []
    a = oc.select([lower], ctx, 30)["rows"][0]
    b = oc.select([upper], ctx, 30)["rows"][0]
    assert a["case_id"] == b["case_id"], (
        "the same commit got two case ids: {} and {}".format(
            a["case_id"], b["case_id"]))


# ---------------------------------------------------------------------------
# 2. `check` compares case ids and nothing else.
#
# cmd_check (:1208-1212) builds `again`/`before` from `case_id` only. Every
# other field of the manifest — the headline counts, the coverage block, the
# `complete` verdict, `label_evidence` on each selected row, and the whole
# `candidates` audit table — is never compared with what the rules produce.
# ---------------------------------------------------------------------------

def _select_manifest(tmp_path, corpus, records=None):
    path = write_pool(tmp_path, records if records is not None else pool())
    out = tmp_path / "manifest.json"
    assert oc.main(["select", "--candidates", str(path), "--since", "2026-01-01",
                    "--until", "2026-07-01", "--corpus", str(corpus),
                    "--out", str(out)]) == 0
    return path, out


# Fixed 2026-09-03: `cmd_check` rebuilds the whole manifest and compares it
# field by field, so the three tests below assert real behaviour rather than a
# wish. They were written as strict xfails and turned red the moment the defect
# went — which is what the marker is for.
def test_check_refuses_a_manifest_whose_counts_do_not_match_its_rows(
        tmp_path, corpus):
    path, out = _select_manifest(tmp_path, corpus)
    body = json.loads(out.read_text(encoding="utf-8"))
    assert len(body["selected"]) == 30
    # Counts and coverage that flatly contradict the 30 rows below them.
    body["counts"] = {"taken": 7, "not_selected": 0, "excluded": 0,
                      "undecidable": 0}
    body["coverage"]["repositories"] = {"host/repo00": 30}
    body["coverage"]["languages"] = {"go": 30}
    body["coverage"]["label_evidence_unavailable"] = 0
    out.write_text(json.dumps(body), encoding="utf-8")
    assert oc.main(["check", "--manifest", str(out), "--candidates", str(path),
                    "--corpus", str(corpus)]) == 2


def test_check_refuses_a_manifest_with_edited_label_evidence(tmp_path, corpus):
    path, out = _select_manifest(tmp_path, corpus)
    body = json.loads(out.read_text(encoding="utf-8"))
    assert all(r["label_evidence"] == "unavailable" for r in body["selected"])
    for row in body["selected"]:
        row["label_evidence"] = "authoritative"
    out.write_text(json.dumps(body), encoding="utf-8")
    assert oc.main(["check", "--manifest", str(out), "--candidates", str(path),
                    "--corpus", str(corpus)]) == 2


def test_check_refuses_a_manifest_whose_rejection_table_was_rewritten(
        tmp_path, corpus):
    records = pool() + [record("host/x", sha("bad"), files=["pkg/authz.go"])]
    path, out = _select_manifest(tmp_path, corpus, records)
    body = json.loads(out.read_text(encoding="utf-8"))
    hit = [r for r in body["candidates"] if r["disposition"] == "excluded"]
    assert hit, "fixture no longer produces an excluded candidate"
    for row in hit:
        row["disposition"] = "not_selected"
        row["rule"] = None
        row["reason"] = "the sample was already full at 30"
    body["excluded_by_rule"] = {}
    out.write_text(json.dumps(body), encoding="utf-8")
    assert oc.main(["check", "--manifest", str(out), "--candidates", str(path),
                    "--corpus", str(corpus)]) == 2


# ---------------------------------------------------------------------------
# 3. A diff with no added or removed lines passes every content rule.
#
# `files: []` is refused at :534 ("a change with no file is not a change").
# There is no matching guard on `diff_text`: rule_sensitive_change (:596) walks
# an empty list of changed lines, finds nothing, and reports nothing found.
# ---------------------------------------------------------------------------

@pytest.mark.xfail(strict=True, reason=(
    "an empty diff_text with diff_truncated false is read as 'the content "
    "rules were checked and passed'; missing_fields guards `files` being "
    "empty but not `diff_text`"))
def test_an_empty_diff_is_not_a_checked_diff(ctx):
    row = oc.select([record("host/x", sha("blank"), diff_text="",
                            files=["pkg/greet.py"])], ctx, 30)["rows"][0]
    assert row["disposition"] != "taken", (
        "a record with no diff content at all was drawn into the sample as "
        "an ordinary change")


@pytest.mark.xfail(strict=True, reason=(
    "a rename carries its sensitive origin only in `rename from`, which is "
    "neither in `files` (rule_sensitive_path) nor an added/removed line "
    "(rule_sensitive_change), so moving auth/token.py is 'ordinary'"))
def test_a_rename_out_of_a_sensitive_path_is_not_read_as_ordinary(ctx):
    renamed = record(
        "host/x", sha("rename"),
        subject="move the helper into pkg",
        files=["pkg/greet.py"],
        diff_text=("diff --git a/auth/token.py b/pkg/greet.py\n"
                   "similarity index 100%\n"
                   "rename from auth/token.py\n"
                   "rename to pkg/greet.py\n"))
    row = oc.select([renamed], ctx, 30)["rows"][0]
    assert row["disposition"] != "taken", (
        "a file renamed out of auth/ was selected as an ordinary change; the "
        "old path was never looked at")


# ---------------------------------------------------------------------------
# 4. changed_lines() drops the content of any line that itself starts with
#    `+` or `-`.
#
# changed_lines (:366-371) skips every diff line beginning `+++` or `---` to
# drop the file headers. A *removed* source line whose own text starts with
# `--` (a SQL/Lua/Haskell comment, a C-style `--i` decrement) becomes `---…`
# and is skipped with them; an *added* line starting `++` becomes `+++…`.
# ---------------------------------------------------------------------------

@pytest.mark.xfail(strict=True, reason=(
    "changed_lines() drops any removed line whose own content starts with "
    "'--' along with the '---' file header, so removing a line about a "
    "password is invisible to rule_sensitive_change"))
def test_a_removed_line_starting_with_two_dashes_is_still_read(ctx):
    hidden = record("host/x", sha("dashes"), files=["pkg/greet.js"],
                    subject="tidy the counter", diff_text=(
                        "diff --git a/pkg/greet.js b/pkg/greet.js\n"
                        "--- a/pkg/greet.js\n"
                        "+++ b/pkg/greet.js\n"
                        "@@ -1,4 +1,3 @@\n"
                        " function greet(n) {\n"
                        "---i; // stop checking the session password here\n"
                        "   return n;\n"
                        " }\n"))
    row = oc.select([hidden], ctx, 30)["rows"][0]
    assert row["rule"] == "sensitive_change", (
        "the removed line carried 'session' and 'password' and the change was "
        "recorded as {}".format(row["disposition"]))


@pytest.mark.xfail(strict=True, reason=(
    "the same hole on the added side: an added line whose content starts "
    "with '++' becomes '+++…' and is dropped with the file header"))
def test_an_added_line_starting_with_two_pluses_is_still_read(ctx):
    hidden = record("host/x", sha("pluses"), files=["pkg/greet.cs"],
                    subject="tidy the counter", diff_text=(
                        "diff --git a/pkg/greet.cs b/pkg/greet.cs\n"
                        "--- a/pkg/greet.cs\n"
                        "+++ b/pkg/greet.cs\n"
                        "@@ -1,3 +1,4 @@\n"
                        " void Greet() {\n"
                        "+++retries; // skip the certificate check\n"
                        " }\n"))
    row = oc.select([hidden], ctx, 30)["rows"][0]
    assert row["rule"] == "sensitive_change", (
        "the added line carried 'certificate' and the change was recorded as "
        "{}".format(row["disposition"]))


# ---------------------------------------------------------------------------
# 5. A contradictory duplicate silently removes a candidate from the sample.
#
# group_duplicates (:788-802) turns both copies into `undecidable` and the run
# continues. Adding one record with a single field changed is therefore a way
# to drop any change the operator dislikes and promote the next one — and the
# run still reports `complete: true`, and `check` reproduces it exactly.
# ---------------------------------------------------------------------------

@pytest.mark.xfail(strict=True, reason=(
    "conflicting_records is recorded but no coverage check reads it, so a "
    "poisoned input still produces `complete: true`; one extra record with a "
    "changed subject removes any candidate from the sample"))
def test_conflicting_records_make_the_sample_incomplete(ctx):
    records = pool(n_repos=12, per_repo=4)
    victim = oc.select(records, ctx, 30)["selected"][0]
    poisoned = records + [record(victim["repo"], victim["commit"],
                                 subject="something else entirely",
                                 files=["pkg/greet.go"])]
    outcome = oc.select(poisoned, ctx, 30)
    assert victim["case_id"] not in {r["case_id"] for r in outcome["selected"]}
    assert any(r["rule"] == "conflicting_records" for r in outcome["rows"])
    assert outcome["complete"] is False, (
        "a candidate was removed from the sample by an unresolvable "
        "contradiction and the manifest still calls the sample usable")


# ---------------------------------------------------------------------------
# 6. `harvest` asks git for an interval in the operator's local time zone.
# ---------------------------------------------------------------------------

def build_clone(root: Path, when: str) -> Path:
    """A clone whose commits carry a fixed *committer* date.

    `git commit --date` sets the author date only, and both `git log --since`
    and the `%cI` the harvester records read the committer date — so the date
    has to go in through the environment or the fixture measures nothing.
    """
    import os

    clone = root / "clone"
    (clone / "pkg").mkdir(parents=True)
    env = dict(os.environ, GIT_COMMITTER_DATE=when, GIT_AUTHOR_DATE=when,
               GIT_COMMITTER_NAME="T", GIT_AUTHOR_NAME="T",
               GIT_COMMITTER_EMAIL="t@example.invalid",
               GIT_AUTHOR_EMAIL="t@example.invalid")

    def run(*args):
        subprocess.run(["git", "-C", str(clone), *args], check=True,
                       capture_output=True, text=True, env=env)

    subprocess.run(["git", "init", "-q", str(clone)], check=True,
                   capture_output=True, text=True, env=env)
    run("config", "user.email", "t@example.invalid")
    run("config", "user.name", "T")
    run("config", "commit.gpgsign", "false")
    run("remote", "add", "origin", "git@github.com:owner/name.git")
    for step, text in enumerate(("package pkg\n", "package pkg\n\nvar N = 1\n")):
        (clone / "pkg" / "greet.go").write_text(text, encoding="utf-8")
        run("add", "-A")
        run("commit", "-q", "-m", "step {}".format(step))
    return clone


def _harvest(tmp_path, clones_root, tz):
    out = tmp_path / "candidates-{}.json".format(tz.replace("/", "_"))
    env_tz = tz
    import os
    old = os.environ.get("TZ")
    os.environ["TZ"] = env_tz
    try:
        assert oc.main(["harvest", "--clones", str(clones_root),
                        "--since", "2026-01-01", "--until", "2026-07-01",
                        "--out", str(out)]) == 0
    finally:
        if old is None:
            os.environ.pop("TZ", None)
        else:
            os.environ["TZ"] = old
    return json.loads(out.read_text(encoding="utf-8"))


@pytest.mark.xfail(strict=True, reason=(
    "harvest hands --since/--until straight to `git log`, whose approxidate "
    "fills the unspecified time of day from the operator's *current clock* "
    "and the unspecified zone from their locale, while select applies the "
    "same bare date at midnight UTC; the first several hours of the interval "
    "never reach the pool. (Would xpass only if run inside the first second "
    "of a UTC day.)"))
def test_harvest_reads_the_interval_from_midnight_utc(tmp_path):
    clones = tmp_path / "clones"
    clones.mkdir()
    # Midnight UTC on the first day: `since` is inclusive per the manifest's
    # own declared boundaries, and parse_day() puts it exactly here.
    build_clone(clones, "2026-01-01T00:00:00+00:00")
    got = _harvest(tmp_path, clones, "UTC")
    assert len(got) == 2, (
        "harvest dropped commits that select's own interval calls inside it; "
        "`git log --since=2026-01-01` resolved to the current time of day on "
        "that date, not to midnight")


# The time-zone half of the same defect is real but was NOT isolated into a
# deterministic test and is therefore not claimed as a finding: `git log
# --since=2026-01-01 00:00` was observed to include the commit under TZ=UTC and
# exclude it under TZ=America/Los_Angeles, but with a bare date the zone effect
# is entangled with the clock effect above and a test on it would xpass or
# xfail depending on the hour it ran.
