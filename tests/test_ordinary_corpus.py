"""The sampling frame for D-013's second rule.

Every test here is written against a way the selection could be wrong *and look
right*: a sample that quietly depends on the order of its input, a repository
that dominates it, an exclusion that vanished instead of being recorded, and a
record with a field missing that was treated as a record that passed the check.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import ordinary_corpus as oc

# A diff carrying none of the sensitive vocabulary. Kept deliberately dull: any
# word in here that reaches SENSITIVE_TERMS would make every test in the file
# pass for the wrong reason.
PLAIN_DIFF = (
    "diff --git a/pkg/greet.go b/pkg/greet.go\n"
    "--- a/pkg/greet.go\n"
    "+++ b/pkg/greet.go\n"
    "@@ -1,3 +1,3 @@\n"
    " package pkg\n"
    "-func Greet(n string) string { return \"hi \" + n }\n"
    "+func Greet(who string) string { return \"hello \" + who }\n"
)


def record(repo: str, commit: str, **over):
    """One complete, eligible candidate. Tests spoil exactly one thing."""
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
    """A stand-in `corpus-real`, naming the languages the reviewer covers.

    The real one is read at selection time on purpose; the tests point at a
    small one so a new case landing in `corpus-real` cannot flip a test.
    """
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
    """A pool wide enough to satisfy the coverage checks."""
    languages = [("go", "pkg/greet.go"), ("python", "pkg/greet.py"),
                 ("php", "pkg/greet.php"), ("typescript", "pkg/greet.ts"),
                 ("rust", "pkg/greet.rs"), ("ruby", "pkg/greet.rb")]
    out = []
    for r in range(n_repos):
        _, filename = languages[r % len(languages)]
        for c in range(per_repo):
            out.append(record("host/repo{:02d}".format(r),
                              sha("{}:{}".format(r, c)),
                              files=[filename]))
    return out


# --------------------------------------------------------------------------
# Reproducibility
# --------------------------------------------------------------------------

def test_same_input_gives_the_same_selection(ctx):
    records = pool()
    first = oc.select(records, ctx, 30)
    second = oc.select(records, ctx, 30)
    assert [r["case_id"] for r in first["selected"]] == \
           [r["case_id"] for r in second["selected"]]
    assert first["complete"] and len(first["selected"]) == 30


def test_reordered_input_gives_the_same_selection(ctx):
    """The sample must not be a function of the order the caller listed.

    `random.Random(seed).shuffle(candidates)` would pass the test above and fail
    this one: it orders the list it is handed, so appending one repository's
    commits to the front of the file would change which thirty are drawn.
    """
    records = pool()
    forward = oc.select(records, ctx, 30)
    backward = oc.select(list(reversed(records)), ctx, 30)
    assert [r["case_id"] for r in forward["selected"]] == \
           [r["case_id"] for r in backward["selected"]]
    # The whole candidate table too, not only the drawn set: a manifest whose
    # rows move with the input order cannot be diffed between two runs.
    assert [(r["repo"], r["commit"], r["disposition"])
            for r in forward["rows"]] == \
           [(r["repo"], r["commit"], r["disposition"]) for r in backward["rows"]]


def test_selection_does_not_depend_on_the_date(ctx):
    """Same commits, different commit dates inside the interval, same sample."""
    base = pool()
    moved = [dict(r, committed_date="2026-0{}-01T00:00:00+00:00".format(
        (i % 6) + 1)) for i, r in enumerate(base)]
    assert [r["case_id"] for r in oc.select(base, ctx, 30)["selected"]] == \
           [r["case_id"] for r in oc.select(moved, ctx, 30)["selected"]]


# --------------------------------------------------------------------------
# The cap
# --------------------------------------------------------------------------

def test_no_repository_exceeds_the_cap(ctx):
    outcome = oc.select(pool(n_repos=12, per_repo=10), ctx, 30)
    assert outcome["per_repo_cap"] == 3
    assert max(outcome["per_repo"].values()) == 3
    assert len(outcome["selected"]) == 30


def test_cap_scales_with_the_target(ctx):
    """D-013 says at most 10 of 100. Held as a fraction so 30 and 100 agree."""
    assert oc.select(pool(n_repos=20, per_repo=10), ctx, 100)["per_repo_cap"] == 10


def test_a_single_repository_cannot_fill_the_sample(ctx):
    """One project offering hundreds of commits must not become the corpus."""
    outcome = oc.select(pool(n_repos=1, per_repo=200), ctx, 30)
    assert len(outcome["selected"]) == 3
    assert outcome["complete"] is False
    failed = {c["name"] for c in outcome["checks"] if not c["met"]}
    assert {"sample_filled", "distinct_repositories"} <= failed


def test_capped_candidates_are_recorded_not_dropped(ctx):
    outcome = oc.select(pool(n_repos=12, per_repo=10), ctx, 30)
    left = [r for r in outcome["rows"] if r["disposition"] == "not_selected"]
    assert left, "eligible-but-not-drawn candidates vanished from the table"
    assert all(r["reason"] for r in left)
    assert len(outcome["rows"]) == 120


# --------------------------------------------------------------------------
# Exclusions are recorded, not dropped
# --------------------------------------------------------------------------

EXCLUDED = [
    ("security_signal",
     {"subject": "fix CVE-2026-11111 in the greeter"}),
    ("security_signal",
     {"labels": ["security"], "labels_source": "github-api"}),
    ("sensitive_path",
     {"files": ["pkg/auth/greet.go"]}),
    ("sensitive_change",
     {"diff_text": PLAIN_DIFF.replace("hello ", "hello token ")}),
    ("dependency_update",
     {"files": ["go.mod"]}),
    ("docs_or_generated_only",
     {"files": ["docs/greet.md"]}),
    ("no_supported_source",
     {"files": ["pkg/greet.erl"]}),
    ("not_single_parent",
     {"parents": 2}),
    ("outside_interval",
     {"committed_date": "2025-03-04T10:00:00+00:00"}),
    ("diff_truncated",
     {"diff_truncated": True}),
]


@pytest.mark.parametrize(("rule", "spoil"), EXCLUDED, ids=[r for r, _ in EXCLUDED])
def test_each_exclusion_is_recorded_with_its_rule(ctx, rule, spoil):
    """An excluded candidate leaves a row naming the rule and giving a reason.

    A sample whose rejects are not on the record cannot be audited: nobody can
    tell a pool that had nothing in it from a rule that ate everything.
    """
    outcome = oc.select([record("host/x", sha("only"), **spoil)], ctx, 30)
    assert len(outcome["rows"]) == 1
    row = outcome["rows"][0]
    assert row["disposition"] == "excluded"
    assert row["rule"] == rule
    assert row["reason"]
    assert outcome["selected"] == []
    assert outcome["excluded_by_rule"] == {rule: 1}


def test_an_excluded_candidate_is_never_taken(ctx):
    """It has to be absent from `selected`, not merely annotated in the table."""
    records = [*pool(), record("host/x", sha("bad"), files=["pkg/authz.go"])]
    outcome = oc.select(records, ctx, 30)
    assert sha("bad") not in {r["commit"] for r in outcome["selected"]}


def test_the_diff_ceiling_comes_from_the_reviewer(ctx):
    """Not a number typed here. A copied ceiling is a ceiling that goes stale.

    The binding one is the character cap the reviewer trims to before the model
    sees anything: a change under the byte ceiling and over it is reviewed in
    part, and an ordinary pass over half a diff proves nothing.
    """
    from security_agent.tools import MAX_DIFF_CHARS
    from security_agent.workspace import Workspace

    assert ctx["ceilings"]["max_diff_chars"] == MAX_DIFF_CHARS
    assert ctx["ceilings"]["max_diff_bytes"] == Workspace.MAX_DIFF_BYTES

    # `x{i}` was the first filler and it produced the identifier `x509` at
    # i=509, so the change was excluded as sensitive before its size was ever
    # looked at. A fixture that trips a different rule tests a different rule.
    filler = "\n".join("+    value{} := {}".format(i, i)
                       for i in range(MAX_DIFF_CHARS // 16 + 400))
    big = record("host/x", sha("big"), diff_text=PLAIN_DIFF + filler)
    assert len(big["diff_text"]) > MAX_DIFF_CHARS
    row = oc.select([big], ctx, 30)["rows"][0]
    assert row["rule"] == "diff_over_ceiling"


def test_word_matching_does_not_fire_on_innocent_substrings(ctx):
    """`author` is not `auth` and `profile` is not `file`.

    Substring matching was the first implementation and it removed every commit
    whose path held the word `author`. A frame that throws away most of the pool
    for a spelling accident is not mechanical selection, it is a filter nobody
    can defend.
    """
    innocent = record("host/x", sha("innocent"),
                      files=["pkg/author/profile.go"],
                      subject="tidy the author profile helper")
    assert oc.select([innocent], ctx, 30)["rows"][0]["disposition"] == "taken"


def test_camel_case_identifiers_are_split(ctx):
    """`parseRequest` must be seen. Snake-case-only matching is blind to Go."""
    camel = record("host/x", sha("camel"),
                   diff_text=PLAIN_DIFF + "\n+  v := parseRequest(b)\n")
    row = oc.select([camel], ctx, 30)["rows"][0]
    assert row["rule"] == "sensitive_change"


def test_context_lines_do_not_exclude_a_change(ctx):
    """Only added and removed lines are read.

    Matching over whole hunks excluded a two-line rename because forty lines of
    untouched context around it mentioned `request`.
    """
    with_context = record("host/x", sha("ctx"), diff_text=(
        "diff --git a/pkg/greet.go b/pkg/greet.go\n"
        "--- a/pkg/greet.go\n"
        "+++ b/pkg/greet.go\n"
        "@@ -1,5 +1,5 @@\n"
        " func handle(request string) string {\n"   # context, untouched
        "-  n := 1\n"
        "+  count := 1\n"
        " }\n"))
    assert oc.select([with_context], ctx, 30)["rows"][0]["disposition"] == "taken"


# --------------------------------------------------------------------------
# Absence is not agreement
# --------------------------------------------------------------------------

@pytest.mark.parametrize("field", sorted(oc.REQUIRED_FIELDS))
def test_a_missing_field_is_refused_not_assumed_eligible(ctx, field):
    """The record cannot answer the rule, so the rule did not pass.

    This is the repository's recurring defect in its newest place: a candidate
    with no `labels` key sailing through the security-label check because the
    check read an absent field as an empty one.
    """
    broken = record("host/x", sha("broken"))
    del broken[field]
    outcome = oc.select([broken], ctx, 30)
    row = outcome["rows"][0]
    assert row["disposition"] == "undecidable"
    assert row["rule"] == "record_incomplete"
    assert field in row["reason"]
    assert outcome["selected"] == []


@pytest.mark.parametrize(("field", "value"), [
    ("labels", "security"),          # a string `in` searches character by character
    ("diff_truncated", "false"),     # bool("false") is True
    ("parents", True),               # bool is an int in Python; 1 parent it is not
    ("files", []),                   # a change with no file is not a change
    ("committed_date", "last tuesday"),
    ("commit", "abc123"),            # a short sha is two different commits later
])
def test_a_malformed_field_is_refused(ctx, field, value):
    broken = record("host/x", sha("broken"))
    broken[field] = value
    row = oc.select([broken], ctx, 30)["rows"][0]
    assert row["disposition"] == "undecidable"
    assert row["rule"] == "record_incomplete"


def test_undecidable_is_counted_apart_from_excluded(ctx):
    """Three answers, not two. Folding them loses the difference that matters:
    one pool shrank because the rules worked, the other because the input is
    unusable, and only the second is the operator's to fix."""
    broken = record("host/z", sha("c"))
    del broken["body"]
    counts = oc.select([record("host/x", sha("a"), files=["pkg/auth.go"]),
                        broken], ctx, 30)["counts"]
    assert counts["excluded"] == 1
    assert counts["undecidable"] == 1
    assert counts["taken"] == 0


def test_labels_from_git_are_not_evidence_of_no_label(ctx):
    """An empty list from a source with no label channel is not a clean bill."""
    row = oc.select([record("host/x", sha("nolabels"))], ctx, 30)["rows"][0]
    assert row["label_evidence"] == "unavailable"
    row = oc.select([record("host/x", sha("labelled"),
                            labels_source="github-api")], ctx, 30)["rows"][0]
    assert row["label_evidence"] == "authoritative"


def test_a_security_label_only_excludes_when_the_source_can_report_labels(ctx):
    """The rule fires on evidence, and only where evidence exists."""
    taken = oc.select([record("host/x", sha("s"), labels=["security"],
                              labels_source="git")], ctx, 30)["rows"][0]
    assert taken["disposition"] == "taken"
    assert taken["label_evidence"] == "unavailable"


def test_contradictory_records_for_one_commit_are_refused(ctx):
    """Two records, one commit, different content. Which is true is not
    decidable here, so neither is believed and neither is silently preferred
    by being listed first."""
    a = record("host/x", sha("dup"))
    b = record("host/x", sha("dup"), subject="something else entirely")
    rows = oc.select([a, b], ctx, 30)["rows"]
    assert all(r["rule"] == "conflicting_records" for r in rows)
    assert all(r["disposition"] == "undecidable" for r in rows)


def test_identical_repeats_collapse_to_one(ctx):
    a = record("host/x", sha("dup"))
    outcome = oc.select([a, dict(a)], ctx, 30)
    assert len(outcome["rows"]) == 1
    assert outcome["rows"][0]["disposition"] == "taken"


# --------------------------------------------------------------------------
# Coverage checks refuse rather than return a thin sample
# --------------------------------------------------------------------------

def test_a_thin_language_spread_is_a_refusal(ctx):
    """30 changes in two languages says nothing about the other seven, and the
    gate it feeds is about whether the tool is bearable in a pipeline."""
    records = [record("host/repo{:02d}".format(r), sha("{}:{}".format(r, c)),
                      files=["pkg/greet.go" if r % 2 else "pkg/greet.py"])
               for r in range(12) for c in range(4)]
    outcome = oc.select(records, ctx, 30)
    assert len(outcome["selected"]) == 30
    assert outcome["complete"] is False
    assert [c["met"] for c in outcome["checks"] if
            c["name"] == "distinct_languages"] == [False]


def test_a_language_the_corpus_covers_with_no_extension_map_is_refused(tmp_path):
    """A corpus language this file cannot recognise would be dropped in
    silence, and the manifest would report a spread it never measured."""
    root = tmp_path / "corpus-real"
    directory = root / "el-aaaa-bbbb-cccc"
    directory.mkdir(parents=True)
    (directory / "case.yml").write_text(
        yaml.safe_dump({"language": "erlang"}), encoding="utf-8")
    with pytest.raises(oc.InputError) as caught:
        oc.context("2026-01-01", "2026-07-01", root)
    assert "erlang" in str(caught.value)


def test_supported_languages_are_read_from_the_corpus(corpus):
    got = oc.corpus_languages(corpus)
    assert got["python"] == "py" and got["java"] == "jv"
    assert set(got) == set(oc.LANGUAGE_EXTENSIONS)


# --------------------------------------------------------------------------
# The manifest and the commands
# --------------------------------------------------------------------------

def write_pool(tmp_path, records):
    path = tmp_path / "candidates.json"
    path.write_text(json.dumps(records, indent=2), encoding="utf-8")
    return path


def test_select_writes_a_manifest_carrying_rules_seed_and_every_candidate(
        tmp_path, corpus):
    path = write_pool(tmp_path, pool())
    out = tmp_path / "manifest.json"
    code = oc.main(["select", "--candidates", str(path), "--since", "2026-01-01",
                    "--until", "2026-07-01", "--target", "30",
                    "--corpus", str(corpus), "--out", str(out)])
    assert code == 0
    body = json.loads(out.read_text(encoding="utf-8"))
    assert body["rules"]["order_seed"] == oc.ORDER_SEED
    assert body["rules"]["exclusion_order"] == list(oc.RULE_ORDER)
    assert body["rules"]["ceilings"]["max_diff_chars"]
    assert len(body["selected"]) == 30
    assert len(body["candidates"]) == 48
    assert body["input"]["digest"] == oc.digest_file(path)
    assert body["generator"]["rules_digest"] == oc.rules_digest()
    assert body["complete"] is True


def test_an_incomplete_sample_exits_two_and_still_writes_the_diagnosis(
        tmp_path, corpus):
    path = write_pool(tmp_path, pool(n_repos=2, per_repo=4))
    out = tmp_path / "manifest.json"
    code = oc.main(["select", "--candidates", str(path), "--since", "2026-01-01",
                    "--until", "2026-07-01", "--corpus", str(corpus),
                    "--out", str(out)])
    assert code == 2
    body = json.loads(out.read_text(encoding="utf-8"))
    assert body["complete"] is False
    assert any(not c["met"] for c in body["coverage"]["checks"])


def test_check_reproduces_and_then_refuses_a_changed_input(tmp_path, corpus):
    path = write_pool(tmp_path, pool())
    out = tmp_path / "manifest.json"
    assert oc.main(["select", "--candidates", str(path), "--since", "2026-01-01",
                    "--until", "2026-07-01", "--corpus", str(corpus),
                    "--out", str(out)]) == 0
    assert oc.main(["check", "--manifest", str(out), "--candidates", str(path),
                    "--corpus", str(corpus)]) == 0
    path.write_text(json.dumps(pool(n_repos=13), indent=2), encoding="utf-8")
    assert oc.main(["check", "--manifest", str(out), "--candidates", str(path),
                    "--corpus", str(corpus)]) == 2


def test_check_refuses_a_manifest_built_under_different_rules(tmp_path, corpus):
    """The guard against widening a rule after seeing which changes it let
    through. Re-running the selection alone would pass happily."""
    path = write_pool(tmp_path, pool())
    out = tmp_path / "manifest.json"
    assert oc.main(["select", "--candidates", str(path), "--since", "2026-01-01",
                    "--until", "2026-07-01", "--corpus", str(corpus),
                    "--out", str(out)]) == 0
    body = json.loads(out.read_text(encoding="utf-8"))
    body["generator"]["rules_digest"] = "0" * 16
    out.write_text(json.dumps(body), encoding="utf-8")
    assert oc.main(["check", "--manifest", str(out), "--candidates", str(path),
                    "--corpus", str(corpus)]) == 2


def test_template_leaves_every_verdict_null(tmp_path, corpus):
    """Not False and not "". Whatever counts these must be unable to read an
    unfilled verdict as "not noisy"."""
    path = write_pool(tmp_path, pool())
    manifest = tmp_path / "manifest.json"
    assert oc.main(["select", "--candidates", str(path), "--since", "2026-01-01",
                    "--until", "2026-07-01", "--corpus", str(corpus),
                    "--out", str(manifest)]) == 0
    adjudications = tmp_path / "adjudications.yml"
    assert oc.main(["template", "--manifest", str(manifest),
                    "--out", str(adjudications)]) == 0
    body = yaml.safe_load(adjudications.read_text(encoding="utf-8"))
    assert len(body["cases"]) == 30
    for case in body["cases"].values():
        # One verdict since 2026-09-04. D-013 asked for two people ruling
        # independently, so the changes they disagreed about could be counted;
        # the owner decided there is no second person, and the assistant cannot
        # be it — the findings under adjudication are its own output. What that
        # costs is written into D-013 beside the thresholds.
        assert case["verdict"] is None
        assert "verdict_a" not in case and "verdict_b" not in case
        # And it says who ruled. `corpus-real/adjudications.yml` was taken for
        # hand judgement for a day and was not.
        assert case["adjudicated_by"] == "human"
        assert case["upstream_security_label_checked_by_hand"] is None


def test_case_ids_are_stable_and_carry_the_language(ctx):
    outcome = oc.select(pool(), ctx, 30)
    for row in outcome["selected"]:
        prefix = ctx["supported"][row["language"]]
        assert row["case_id"] == "ord-{}-{}".format(prefix, row["order_hash"][:8])
    assert len({r["case_id"] for r in outcome["selected"]}) == 30


def test_a_candidate_file_with_a_non_record_in_it_is_refused(tmp_path):
    """Filtering it out would leave the operator with a pool of an unknown
    size, believing it knew the size."""
    path = tmp_path / "candidates.json"
    path.write_text(json.dumps([record("host/x", sha("a")), "oops"]),
                    encoding="utf-8")
    with pytest.raises(oc.InputError):
        oc.load_candidates(path)


def test_an_inverted_interval_is_refused(corpus):
    with pytest.raises(oc.InputError):
        oc.context("2026-07-01", "2026-01-01", corpus)


def test_a_timestamp_without_a_zone_is_read_as_utc_not_as_local(ctx):
    """Two operators in different time zones must select the same changes."""
    early = record("host/x", sha("edge"), committed_date="2026-01-01T00:30:00")
    assert oc.select([early], ctx, 30)["rows"][0]["disposition"] == "taken"
    before = record("host/x", sha("edge2"), committed_date="2025-12-31T23:30:00")
    assert oc.select([before], ctx, 30)["rows"][0]["rule"] == "outside_interval"


# --------------------------------------------------------------------------
# harvest — a real local clone, no network
# --------------------------------------------------------------------------

def build_clone(tmp_path):
    """A two-commit git repository on disk, with a remote url and no network."""
    import subprocess

    clone = tmp_path / "clone"
    (clone / "pkg").mkdir(parents=True)

    def run(*args):
        subprocess.run(["git", "-C", str(clone), *args], check=True,
                       capture_output=True, text=True)

    subprocess.run(["git", "init", "-q", str(clone)], check=True,
                   capture_output=True, text=True)
    run("config", "user.email", "t@example.invalid")
    run("config", "user.name", "T")
    run("config", "commit.gpgsign", "false")
    # The identity the selector uses. Without it, two people cloning the same
    # project into differently named directories would draw different samples
    # from the same commits.
    run("remote", "add", "origin", "git@github.com:owner/name.git")
    for step, text in enumerate(("package pkg\n", "package pkg\n\nvar N = 1\n")):
        (clone / "pkg" / "greet.go").write_text(text, encoding="utf-8")
        run("add", "-A")
        run("-c", "user.email=t@example.invalid",
            "commit", "-q", "-m", "step {}".format(step),
            "--date", "2026-03-0{}T10:00:00+00:00".format(step + 1))
    return clone


def test_harvest_writes_records_the_selector_accepts(tmp_path, corpus):
    """The two halves must actually fit together.

    A harvester that omits one required field produces a pool where every
    candidate is `undecidable`, and the operator sees "0 taken" with no hint
    that the two programs disagree about the record shape.
    """
    clones = tmp_path / "clones"
    clones.mkdir()
    build_clone(clones)
    out = tmp_path / "candidates.json"
    assert oc.main(["harvest", "--clones", str(clones), "--since", "2026-01-01",
                    "--until", "2027-01-01", "--out", str(out)]) == 0
    records = json.loads(out.read_text(encoding="utf-8"))
    assert len(records) == 2
    assert {r["repo"] for r in records} == {"github.com/owner/name"}
    assert all(oc.missing_fields(r) == [] for r in records)

    ctx_ = oc.context("2026-01-01", "2027-01-01", corpus)
    rows = oc.select(records, ctx_, 30)["rows"]
    # The first commit is a root commit: no parent, so no diff of its own.
    assert {r["rule"] for r in rows} == {None, "not_single_parent"}


def test_harvest_labels_git_as_a_source_with_no_label_channel(tmp_path):
    """The empty list git produces must not read as "no security label"."""
    clones = tmp_path / "clones"
    clones.mkdir()
    build_clone(clones)
    out = tmp_path / "candidates.json"
    assert oc.main(["harvest", "--clones", str(clones), "--since", "2026-01-01",
                    "--until", "2027-01-01", "--out", str(out)]) == 0
    records = json.loads(out.read_text(encoding="utf-8"))
    assert all(r["labels_source"] == "git" for r in records)
    assert "git" not in oc.AUTHORITATIVE_LABEL_SOURCES
