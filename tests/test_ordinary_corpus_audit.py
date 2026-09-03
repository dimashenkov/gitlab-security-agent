"""Hostile audit of `tools/ordinary_corpus.py`.

Every test here asserts the CORRECT behaviour.

The eleven from the audit were written first as `xfail(strict=True)` over a
defect that was live at the time, so each turned red the moment its defect went
— that is what the strict marker is for, and it is why those assertions are not
a description of the code. Every marker has come off: each of the eleven is
fixed, and each test guards against its specific failure returning.

The others were added alongside the fixes and were never xfails: the floor
tests, which fail if a fix went too far, the freeze tests, and the last one in
the file, which was not on the audit list at all — it came out of running the
fixed `harvest` end to end and names a defect the interval fix had been hiding.

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
# `group_duplicates` normalised the identity with `repo.strip()` /
# `commit.strip().lower()`; `evaluate` and the cap in `select` used the raw
# string. So one repository written twelve slightly different ways was twelve
# repositories to the cap and to the `distinct_repositories` check, and the
# sample could be drawn almost entirely from one project while the manifest
# reported `complete: true`.
#
# Fixed 2026-09-03: `identity()` is the single normalisation and every call
# site goes through it, `evaluate` stores the normalised pair on the row, and
# the cap keys on that.
#
# The pool below carries twelve *genuine* repositories beside the twelve
# spellings. The first version of this test offered the spellings alone and
# asserted a full sample of thirty — which only holds while the defect is
# present, because one repository under a cap of three can contribute three.
# A fixture that cannot be satisfied by correct behaviour proves nothing, so
# the sample is filled from elsewhere and the spelled project is held to the
# cap like any other.
# ---------------------------------------------------------------------------

def test_the_repo_cap_counts_repositories_not_spellings(ctx):
    records = list(pool(n_repos=12, per_repo=4))
    for spelling in range(12):
        name = "host/only" + " " * spelling
        for c in range(3):
            records.append(record(name, sha("only:{}:{}".format(spelling, c)),
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
    # And it is one repository in the manifest's coverage table too, not
    # twelve: `distinct_repositories` is checked against these keys.
    assert [k for k in outcome["per_repo"] if k.strip() == "host/only"] \
        in ([], ["host/only"])


class TestWhatTheFreezeActuallyRestsOn:
    """`generator_digest` is the freeze check. `rules_digest` is a label.

    A digest over the rule *code* was built for the gap between them and
    dropped after four review rounds; the comment above `rules_digest` in
    `tools/ordinary_corpus.py` records why. Each round found the last one
    incomplete, and the honest verdict was that it added no safety at all: a
    hash of the whole file already moves on every edit to a rule, a helper or a
    constant, and `cmd_check` already refuses on it. The behavioural digest
    could only have classified a change that was already blocking.

    These tests assert what is true, which is less than what was claimed.
    """

    def test_the_digest_is_the_same_twice(self):
        assert oc.rules_digest() == oc.rules_digest()

    def test_a_changed_constant_moves_it(self, monkeypatch):
        before = oc.rules_digest()

        monkeypatch.setattr(oc, "REPO_CAP_FRACTION", 0.5)

        assert oc.rules_digest() != before

    def test_a_reordered_rule_moves_it(self, monkeypatch):
        """`RULE_ORDER` is the declared name and order, and the order decides
        which rule's reason is reported when several fire."""
        before = oc.rules_digest()

        monkeypatch.setattr(
            oc, "RULE_ORDER", tuple(reversed(oc.RULE_ORDER)))

        assert oc.rules_digest() != before

    def test_an_alias_in_the_runtime_table_does_not_move_it(self, monkeypatch):
        """`sorted(RULES)` was added beside `RULE_ORDER` and duplicated it
        badly: sorted, it could not see a reordering, and it moved for a key
        added to the runtime table — reporting "the declared rules have been
        edited" over a change to nothing declared."""
        before = oc.rules_digest()

        monkeypatch.setitem(oc.RULES, "an_alias", oc.RULES["sensitive_path"])

        assert oc.rules_digest() == before

    def test_a_gutted_rule_body_does_NOT_move_it(self, monkeypatch):
        """Stated as a test rather than left to a docstring, because this is
        the gap somebody will otherwise rediscover and try to close again.

        Replacing a rule with one that excludes nothing leaves this digest
        exactly where it was. `generator_digest` is what catches that edit,
        and `cmd_check` treats a mismatch in it as a problem in its own right —
        not, as it once said, as "harmless if the rules digest holds".
        """
        before = oc.rules_digest()

        def excludes_nothing(record, ctx):
            return None

        monkeypatch.setitem(oc.RULES, "sensitive_path", excludes_nothing)

        assert oc.rules_digest() == before

    def test_the_manifest_records_a_hash_of_the_whole_generator_file(
            self, tmp_path, corpus):
        """The one that actually holds the freeze — read out of the manifest,
        not recomputed from `digest_file`.

        The first version of this test asserted `digest_file(source)` equals
        sha256 of the file, which is a test that `digest_file` is sha256. It
        would have passed just as well if `build_manifest` had stopped putting
        the generator's hash in the document at all.
        """
        import hashlib

        _path, out = _select_manifest(tmp_path, corpus)
        body = json.loads(out.read_text(encoding="utf-8"))
        source = Path(oc.__file__).resolve()

        assert body["generator"]["generator_digest"] == \
            hashlib.sha256(source.read_bytes()).hexdigest()[:16]

    def test_check_reports_a_changed_generator_digest_as_the_problem(
            self, tmp_path, corpus, capsys):
        path, out = _select_manifest(tmp_path, corpus)

        # First: the untouched manifest checks clean. Without this, the
        # refusal below could be any other validation failure and the test
        # would pass while the generator digest went unread.
        assert oc.main(["check", "--manifest", str(out), "--candidates",
                        str(path), "--corpus", str(corpus)]) == 0
        capsys.readouterr()

        body = json.loads(out.read_text(encoding="utf-8"))
        body["generator"]["generator_digest"] = "0" * 16
        out.write_text(json.dumps(body), encoding="utf-8")

        code = oc.main(["check", "--manifest", str(out), "--candidates",
                        str(path), "--corpus", str(corpus)])
        reported = capsys.readouterr()

        assert code == 2
        message = reported.out + reported.err
        assert "the tool's source has changed" in message, message
        # And it must not tell the operator to wave it through.
        assert "harmless" not in message


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
# 2. `check` compared case ids and nothing else. Fixed 2026-09-03.
#
# `cmd_check` built `again`/`before` from `case_id` only, so every other field
# of the manifest — the headline counts, the coverage block, the `complete`
# verdict, `label_evidence` on each selected row, and the whole `candidates`
# audit table — went uncompared, and "Reproduced" was printed over a document
# that contradicted itself. It now rebuilds the whole manifest and compares it
# field by field.
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
# `files: []` is refused ("a change with no file is not a change"). There was
# no matching guard on `diff_text`: rule_sensitive_change walked an empty list
# of changed lines, found nothing, and reported nothing found.
#
# Fixed 2026-09-03: `missing_fields` requires a non-empty `diff_text`, so the
# record is `undecidable` with a named remedy rather than silently taken.
# ---------------------------------------------------------------------------

def test_an_empty_diff_is_not_a_checked_diff(ctx):
    row = oc.select([record("host/x", sha("blank"), diff_text="",
                            files=["pkg/greet.py"])], ctx, 30)["rows"][0]
    assert row["disposition"] != "taken", (
        "a record with no diff content at all was drawn into the sample as "
        "an ordinary change")


# Fixed 2026-09-03: `moved_paths()` reads `rename from`/`rename to`/`copy
# from`/`copy to` out of the diff, and `rule_sensitive_path` checks both ends
# of a move alongside the paths in `files`.
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
# changed_lines skipped every diff line beginning `+++` or `---` to drop the
# file headers. A *removed* source line whose own text starts with `--` (a
# SQL/Lua/Haskell comment, a C-style `--i` decrement) becomes `---…` and was
# skipped with them; an *added* line starting `++` becomes `+++…`.
#
# Fixed 2026-09-03: the headers are found by position, not by prefix — a file
# header can only stand before the first `@@` of its file, and changed_lines
# now reads only hunk bodies.
# ---------------------------------------------------------------------------

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
# group_duplicates turns both copies into `undecidable` and the run continued.
# Adding one record with a single field changed was therefore a way to drop any
# change the operator dislikes and promote the next one — and the run still
# reported `complete: true`, and `check` reproduced it exactly, because both
# derive from the same poisoned input.
#
# Fixed 2026-09-03: `no_contradicted_commits` is a coverage check with a named
# remedy, and the commits in question are listed in the manifest.
# ---------------------------------------------------------------------------

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


# Fixed 2026-09-03: `git_instant()` turns the boundary into an explicit instant
# with an explicit zone, built from the same `parse_day` `select` uses, so git
# has no unspecified field left to fill from the operator's clock or locale.
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


# ---------------------------------------------------------------------------
# 7. A UTC committer date came back from harvest unreadable.
#
# Found 2026-09-03 while verifying the fix above end to end, not from the
# audit list. `harvest` writes git's `%cI`, and git prints `...T00:00:00Z` —
# not `+00:00` — whenever the committer's zone is UTC. `parse_commit_date`
# used `datetime.fromisoformat`, which rejects `Z` before Python 3.11 (3.9.6
# here), so every such record was `record_incomplete` and the pool was 84
# candidates with 0 eligible.
#
# The two defects hid each other: the pool that triggers this one is exactly
# the pool the old bare-date `--since` was dropping, so it could not show up
# until the interval was fixed. The existing suite missed it because its
# fixture lets the committer date default to the machine's local zone, which
# on this machine is not UTC and so never produces a `Z`.
# ---------------------------------------------------------------------------

def test_a_utc_committer_date_from_git_is_read_not_refused(tmp_path, ctx):
    clones = tmp_path / "clones"
    clones.mkdir()
    build_clone(clones, "2026-03-04T10:00:00+00:00")
    out = tmp_path / "candidates.json"
    assert oc.main(["harvest", "--clones", str(clones), "--since", "2026-01-01",
                    "--until", "2026-07-01", "--out", str(out)]) == 0
    records = json.loads(out.read_text(encoding="utf-8"))
    assert len(records) == 2
    # This is what git actually writes, and the shape the defect choked on.
    assert all(r["committed_date"].endswith("Z") for r in records), (
        "the fixture no longer produces the UTC spelling this test is about")
    assert all(oc.missing_fields(r) == [] for r in records), (
        "harvest wrote a committed_date its own selector cannot read: {}".format(
            [oc.missing_fields(r) for r in records]))
    rows = oc.select(records, ctx, 30)["rows"]
    assert not any(r["rule"] == "record_incomplete" for r in rows)


# The time-zone half of the same defect is real but was NOT isolated into a
# deterministic test and is therefore not claimed as a finding: `git log
# --since=2026-01-01 00:00` was observed to include the commit under TZ=UTC and
# exclude it under TZ=America/Los_Angeles, but with a bare date the zone effect
# is entangled with the clock effect above and a test on it would xpass or
# xfail depending on the hour it ran.
