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


SENSITIVE_DIFF = (
    "diff --git a/pkg/greet{e} b/pkg/greet{e}\n"
    "--- a/pkg/greet{e}\n"
    "+++ b/pkg/greet{e}\n"
    "@@ -1,3 +1,3 @@\n"
    " unchanged\n"
    "-    old = parse(request)\n"
    "+    new = parse(request)\n"
)


def pool(n_repos=12, per_repo=4):
    """A pool wide enough to satisfy the coverage checks, in both strata.

    Half the changes touch a security-adjacent area and half do not. Since
    2026-09-04 `sensitive_path` and `sensitive_change` label rather than
    exclude, and the sample is drawn to a quota from each stratum — so a pool
    of only quiet changes fills half the sample and no more. A fixture that
    cannot be satisfied by correct behaviour proves nothing.
    """
    languages = [("go", "pkg/greet.go"), ("python", "pkg/greet.py"),
                 ("php", "pkg/greet.php"), ("typescript", "pkg/greet.ts"),
                 ("rust", "pkg/greet.rs"), ("ruby", "pkg/greet.rb")]
    out = []
    for r in range(n_repos):
        _, filename = languages[r % len(languages)]
        extension = filename[filename.rindex("."):]
        for c in range(per_repo):
            # Alternating, so every repository contributes to both strata and
            # the per-repository cap is exercised across them rather than
            # within one.
            sensitive = (c % 2 == 1)
            out.append(record(
                "host/repo{:02d}".format(r), sha("{}:{}".format(r, c)),
                files=[filename],
                diff_text=(SENSITIVE_DIFF.format(e=extension) if sensitive
                           else PLAIN_DIFF)))
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

# `sensitive_path` and `sensitive_change` are NOT here since 2026-09-04. They
# stopped excluding and became strata: they label a candidate rather than
# removing it, and their own behaviour is tested in
# `TestTheSensitiveRulesLabelRatherThanExclude` below.
EXCLUDED = [
    ("security_signal",
     {"subject": "fix CVE-2026-11111 in the greeter"}),
    ("security_signal",
     {"labels": ["security"], "labels_source": "github-api"}),
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


class TestTheSensitiveRulesLabelRatherThanExclude:
    """They used to exclude, and that made the whole measurement wrong.

    On a real pool of 2129 candidates they accounted for 1334 of the 2003
    exclusions — every ordinary change whose path or changed lines mention
    parsing, request handling, filesystem paths or input validation. Those are
    the changes most likely to make a security reviewer say something, so
    removing them meant the rate answered "how often does it alarm on ordinary
    changes *that survive this filter*" and not "how often does it alarm in a
    pipeline". It measured the rules as much as the reviewer.

    They now label. Codex named the defect and the repair on 2026-09-04.
    """

    def test_a_sensitive_path_is_kept_and_labelled(self, ctx):
        row = oc.evaluate(
            record("host/x", sha("p"), files=["pkg/auth/greet.go"]), ctx)

        assert row["disposition"] == "eligible"
        assert row["stratum"] == "sensitive"
        assert row["stratum_rules"] == ["sensitive_path"]

    def test_a_sensitive_change_is_kept_and_labelled(self, ctx):
        row = oc.evaluate(
            record("host/x", sha("c"),
                   diff_text=PLAIN_DIFF.replace("hello ", "hello token ")),
            ctx)

        assert row["disposition"] == "eligible"
        assert row["stratum"] == "sensitive"
        assert row["stratum_rules"] == ["sensitive_change"]

    def test_both_rules_firing_is_one_stratum_and_two_pieces_of_evidence(self, ctx):
        row = oc.evaluate(
            record("host/x", sha("b"), files=["pkg/auth/greet.go"],
                   diff_text=PLAIN_DIFF.replace("hello ", "hello token ")),
            ctx)

        assert row["stratum"] == "sensitive"
        assert sorted(row["stratum_rules"]) == ["sensitive_change",
                                                "sensitive_path"]

    def test_neither_is_the_quiet_stratum(self, ctx):
        row = oc.evaluate(record("host/x", sha("q")), ctx)

        assert row["stratum"] == "quiet"
        assert row["stratum_rules"] == []

    def test_a_sensitive_change_that_a_real_rule_excludes_is_still_excluded(
            self, ctx):
        """Labelling does not rescue anything. A dependency bump in an auth
        path is still a dependency bump."""
        row = oc.evaluate(
            record("host/x", sha("d"), files=["pkg/auth/go.mod"]), ctx)

        assert row["disposition"] == "excluded"
        assert row["rule"] == "dependency_update"
        assert row["stratum"] == "sensitive"

    def test_the_quotas_are_equal_and_drawn_from_both(self, ctx):
        outcome = oc.select(pool(), ctx, 30)
        strata = outcome["strata"]

        assert strata["quota"] == {"sensitive": 15, "quiet": 15}
        assert strata["drawn"] == {"sensitive": 15, "quiet": 15}

    def test_an_odd_target_does_not_lose_a_case(self, ctx):
        """0.5 and 0.5 of 31 round to two halves that do not add up. A quota
        that silently differs from the target is a sample whose size nobody
        stated."""
        outcome = oc.select(pool(), ctx, 31)

        assert sum(outcome["strata"]["quota"].values()) == 31

    def test_the_repository_cap_is_global_and_not_per_stratum(self, ctx):
        """A cap applied inside each stratum lets one project contribute its
        cap twice — twenty of a hundred where D-013 allows ten."""
        outcome = oc.select(pool(), ctx, 30)
        cap = outcome["per_repo_cap"]

        assert max(outcome["per_repo"].values()) <= cap

    def test_the_cap_does_not_starve_a_stratum_the_pool_could_fill(self, ctx):
        """Codex's counterexample, exactly. Target 2, cap 1.

        Repository A holds a sensitive change and a quiet one; repository B
        holds a sensitive one. A's sensitive change sorts first.

        Greedy — in either of the two versions written before this — takes
        A-sensitive, refuses A-quiet at the cap, and reports 1 and 0. The
        allocation B-sensitive plus A-quiet fills both, and the shortfall was
        then blamed on a pool that had enough in it.

        The rows are searched for by hash so the fixture holds whatever the
        seed does, rather than asserting an order that a changed seed silently
        breaks — the previous version of this test claimed the quiet rows sat
        after the sensitive ones and they did not.
        """
        def rows_for(tag, sensitive):
            return record(
                "host/{}".format("A" if tag.startswith("a") else "B"),
                sha(tag), files=["pkg/greet.py"],
                diff_text=(SENSITIVE_DIFF.format(e=".py") if sensitive
                           else PLAIN_DIFF))

        # Both inequalities. `A-sensitive < B-sensitive` alone is not the
        # arrangement: greedy also has to reach A's sensitive row before A's
        # quiet one, or it takes the quiet one first and succeeds by accident.
        # With one condition the search could pick a trio that proves nothing.
        def key(row):
            return oc.order_hash(row["repo"], row["commit"])

        for n in range(500):
            a_sensitive = rows_for("a-sensitive-{}".format(n), True)
            a_quiet = rows_for("a-quiet-{}".format(n), False)
            b_sensitive = rows_for("b-sensitive-{}".format(n), True)
            if (key(a_sensitive) < key(b_sensitive)
                    and key(a_sensitive) < key(a_quiet)):
                break
        else:
            pytest.skip("no arrangement found; the seed must have changed")

        assert key(a_sensitive) < key(b_sensitive)
        assert key(a_sensitive) < key(a_quiet)

        outcome = oc.select([a_sensitive, a_quiet, b_sensitive], ctx, 2)

        assert outcome["strata"]["drawn"] == {"sensitive": 1, "quiet": 1}, (
            "greedy takes A's sensitive row, refuses A's quiet one at the cap "
            "and reports {} — while B-sensitive plus A-quiet fills both"
            .format(outcome["strata"]["drawn"]))
        assert max(outcome["per_repo"].values()) <= outcome["per_repo_cap"]

    def test_the_allocator_beats_greedy_on_a_pool_where_greedy_falls_short(
            self, ctx):
        """A pool the allocator fills and the old greedy draw does not.

        The first version of this test asserted only that the quotas filled at
        target 30 — and greedy filled that fixture too, so the test passed
        without exercising the thing it was named for. Codex simulated it.

        Both algorithms are run here, on the same rows: greedy as it was, one
        pass down the global hash order, and the allocator. The test is the
        difference between them, so it cannot pass by accident.
        """
        quota = {"sensitive": 3, "quiet": 3}
        cap = 1

        def greedy(eligible):
            """One pass down the hash order, first come first served."""
            used, drawn = {}, {"sensitive": 0, "quiet": 0}
            for row in eligible:
                s = row["stratum"]
                if drawn[s] >= quota[s] or used.get(row["repo"], 0) >= cap:
                    continue
                used[row["repo"]] = used.get(row["repo"], 0) + 1
                drawn[s] += 1
            return drawn

        # Built to the shape that defeats greedy, at three times the size of
        # the two-row counterexample: three repositories holding a sensitive
        # change *and* a quiet one, three holding only a sensitive one, and
        # every A-sensitive row sorting before every B-sensitive row and before
        # its own quiet sibling.
        #
        # Greedy then fills its sensitive quota entirely from the A
        # repositories, and every quiet row is behind a spent cap: 3 and 0. The
        # allocator re-routes the sensitive rows to B and takes the quiet ones:
        # 3 and 3.
        #
        # The shas are searched for rather than typed, because the order comes
        # out of the hash and a fixture that asserted an order would break
        # silently if `ORDER_SEED` ever changed.
        def key(row):
            return oc.order_hash(row["repo"], row["commit"])

        def find(repo, sensitive, before=None):
            for n in range(4000):
                row = record(
                    repo, sha("{}:{}:{}".format(repo, sensitive, n)),
                    files=["pkg/greet.py"],
                    diff_text=(SENSITIVE_DIFF.format(e=".py") if sensitive
                               else PLAIN_DIFF))
                if before is None or key(row) > before:
                    return row
            return None

        records, ceiling = [], "0" * 16
        for name in ("A0", "A1", "A2"):          # sensitive first, then quiet
            s = find("host/{}".format(name), True, ceiling)
            q = find("host/{}".format(name), False, key(s))
            if s is None or q is None:
                pytest.skip("no arrangement found; the seed must have changed")
            records += [s, q]
            ceiling = max(ceiling, key(s))
        for name in ("B0", "B1", "B2"):          # sensitive, all sorting later
            s = find("host/{}".format(name), True, ceiling)
            if s is None:
                pytest.skip("no arrangement found; the seed must have changed")
            records.append(s)

        rows = [oc.evaluate(r, ctx) for r in records]
        eligible = sorted((r for r in rows if r["disposition"] == "eligible"),
                          key=lambda r: (r["order_hash"], r["repo"], r["commit"]))
        by_stratum = {
            "sensitive": [r for r in eligible if r["stratum"] == "sensitive"],
            "quiet": [r for r in eligible if r["stratum"] == "quiet"],
        }
        greedy_drawn = greedy(eligible)
        taken = oc._allocate(by_stratum, quota, cap)
        allocated = {"sensitive": 0, "quiet": 0}
        used = {}
        for row in eligible:
            if id(row) in taken:
                allocated[row["stratum"]] += 1
                used[row["repo"]] = used.get(row["repo"], 0) + 1

        assert greedy_drawn != quota, (
            "the fixture no longer distinguishes the two algorithms: greedy "
            "also filled {}".format(greedy_drawn))
        assert allocated == quota, (
            "the allocator did not fill a pool it could: {}".format(allocated))
        assert max(used.values()) <= cap

    def test_two_repositories_sharing_a_sha_are_two_rows(self, ctx):
        """A change's identity is repository *and* commit.

        The flow's row nodes were named after the stratum and the sha, so two
        repositories holding the same sha — legitimate, and it happens — fused
        into one node: capacities added up and only the last row survived the
        lookup, so the allocator returned fewer rows than the flow carried.
        Codex reproduced it. The names are ranks now.
        """
        # Four repositories, because the cap at a target of four is one apiece.
        # Two of them hold the *same* sha, which is the collision.
        shared = sha("shared-commit")
        rows = [record("host/one", shared, files=["pkg/greet.py"]),
                record("host/two", shared, files=["pkg/greet.go"]),
                record("host/three", sha("s1"), files=["pkg/greet.php"],
                       diff_text=SENSITIVE_DIFF.format(e=".php")),
                record("host/four", sha("s2"), files=["pkg/greet.rs"],
                       diff_text=SENSITIVE_DIFF.format(e=".rs"))]

        outcome = oc.select(rows, ctx, 4)

        assert outcome["strata"]["drawn"] == {"sensitive": 2, "quiet": 2}, (
            "the two rows sharing a sha collapsed into one: {}".format(
                outcome["strata"]["drawn"]))
        assert len(outcome["selected"]) == 4

    def test_the_draw_follows_the_hash_order_and_not_the_sha(self, ctx):
        """The search visits neighbours in sorted order, and the node names
        used to contain the sha — so sorting sorted by sha, not by
        `order_hash`, which is what the draw is supposed to depend on. Between
        two maximum flows a changed sha could move the sample."""
        rows = pool()
        first = oc.select([dict(r) for r in rows], ctx, 30)

        # Same rows, same hashes, presented in a different order.
        shuffled = [dict(r) for r in rows[7:]] + [dict(r) for r in rows[:7]]
        second = oc.select(shuffled, ctx, 30)

        assert ([r["case_id"] for r in first["selected"]]
                == [r["case_id"] for r in second["selected"]])

    def test_a_pool_that_genuinely_cannot_fill_says_so(self, ctx):
        """The floor. An allocator that always claims success would pass every
        test above and hide a short sample."""
        only_quiet = [record("host/repo{:02d}".format(r), sha("q{}".format(r)),
                             files=["pkg/greet.py"])
                      for r in range(12)]

        outcome = oc.select(only_quiet, ctx, 30)

        assert outcome["strata"]["drawn"]["sensitive"] == 0
        assert outcome["complete"] is False
        assert [c["met"] for c in outcome["checks"]
                if c["name"] == "sensitive_quota_filled"] == [False]

    def test_the_draw_is_still_a_function_of_the_hash_and_nothing_else(self, ctx):
        """The round-robin must not have made the sample depend on input
        order — that is the one property this whole file exists for."""
        records = pool()
        forwards = oc.select(list(records), ctx, 30)
        backwards = oc.select(list(reversed(records)), ctx, 30)

        assert ([r["case_id"] for r in forwards["selected"]]
                == [r["case_id"] for r in backwards["selected"]])

    def test_the_frame_share_is_recorded_for_weighting(self, ctx):
        """The sample is 50/50 by design and the population is not, so a
        pipeline-representative figure needs the frame proportions. An
        unweighted average over the hundred is a prevalence for a population
        that does not exist."""
        strata = oc.select(pool(), ctx, 30)["strata"]

        assert set(strata["frame_share"]) == {"sensitive", "quiet"}
        assert abs(sum(strata["frame_share"].values()) - 1.0) < 0.01

    def test_the_two_by_two_is_recorded_rather_than_first_firings(self, ctx):
        """"737 path, 597 change" hides how many are both — and on the real
        pool 395 of 701 were. First-firing counts cannot say whether two strata
        were the right number."""
        cells = oc.select(pool(), ctx, 30)["strata"]["rule_overlap"]

        assert set(cells) == {"neither", "path only", "change only", "both"}
        assert sum(cells.values()) > 0


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
    # A dependency bump: a real exclusion. This used to use a sensitive path,
    # which since 2026-09-04 is a stratum label and not an exclusion at all —
    # the candidate is meant to be taken now, so the fixture was testing
    # nothing.
    records = [*pool(), record("host/x", sha("bad"), files=["go.mod"])]
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
    """`parseRequest` must be seen. Snake-case-only matching is blind to Go.

    Asserted on the stratum since 2026-09-04: the rule labels rather than
    excludes, so the candidate is eligible and sits in the sensitive stratum.
    What is being tested is unchanged — whether the word was seen at all.
    """
    camel = record("host/x", sha("camel"),
                   diff_text=PLAIN_DIFF + "\n+  v := parseRequest(b)\n")
    row = oc.select([camel], ctx, 30)["rows"][0]
    assert row["stratum"] == "sensitive"
    assert row["stratum_rules"] == ["sensitive_change"]


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
    # `go.mod`, not an auth path: the sensitive rules label rather than exclude
    # since 2026-09-04, so the old fixture produced a *taken* candidate and the
    # excluded count it asserted was never going to arrive.
    counts = oc.select([record("host/x", sha("a"), files=["go.mod"]),
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
    # Both strata, so the sample can actually fill: the point of this test is
    # the language spread, and a fixture that also starves a quota would fail
    # for a second reason and prove neither.
    records = [
        record("host/repo{:02d}".format(r), sha("{}:{}".format(r, c)),
               files=["pkg/greet.go" if r % 2 else "pkg/greet.py"],
               diff_text=(SENSITIVE_DIFF.format(e=".go" if r % 2 else ".py")
                          if c % 2 else PLAIN_DIFF))
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


SHA = "a" * 40


@pytest.mark.parametrize("repo, commit", [
    ("github.com/O/A", SHA.upper()),
    ("  github.com/o/a  ", "  " + SHA + "  "),
])
def test_the_identity_fold_covers_case_and_whitespace(repo, commit):
    assert oc.identity(repo, commit) == ("github.com/o/a", SHA)


@pytest.mark.parametrize("repo, commit, expected", [
    ("github.com/o/a.git", SHA, ("github.com/o/a.git", SHA)),
    ("https://github.com/o/a", SHA, ("https://github.com/o/a", SHA)),
    ("git@github.com:o/a", SHA, ("git@github.com:o/a", SHA)),
    ("github.com/o/a", SHA[:7], ("github.com/o/a", SHA[:7])),
])
def test_the_identity_fold_covers_nothing_else(repo, commit, expected):
    """A known limitation, pinned so it cannot vanish either way.

    `identity` folds case and surrounding whitespace and nothing more, so one
    change written any of these ways is a different identity — and the
    generations ledger, which reads disjointness through this function, would
    pass a repeat spelled differently as unseen.

    The assertion is the exact tuple, not merely "not the canonical one". An
    implementation folding all four onto some other shared value would satisfy
    `!=` while contradicting the very claim this test records. Codex,
    2026-09-05.

    This test is not asking for the narrow behaviour. It states it, so that
    widening the fold is a deliberate change with this test failing in front of
    it. Widening re-orders `order_hash` for any affected spelling, and whether
    that re-samples anything was measured rather than assumed: of the 3056
    records in the pool behind `ordinary-v1`, **none** carries a `.git`
    suffix, a URL, an ssh remote or a sha that is not forty lower-case hex
    characters. Three repository strings differ only in case, which the fold
    already handles — the `AutoMapper/AutoMapper` fold that once cost two of
    thirty. So the limitation is a hazard for a pool built differently, not a
    live one, and widening today would move nothing.
    """
    assert oc.identity(repo, commit) == expected


def test_a_change_with_no_usable_identity_is_none_not_a_guess():
    """Callers must not invent one; `None` is the third answer."""
    assert oc.identity(None, SHA) is None
    assert oc.identity("github.com/o/a", None) is None


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
