"""Harvesting pairs from published advisories.

The value of a harvested case rests on two properties, and both are easy to
break without noticing:

  * **Symmetry.** The two members must review the same lines in opposite
    directions. If they drift — a file kept in one and not the other, a
    different baseline — then something other than the fix distinguishes them,
    and whatever the corpus then measures is not what it claims.
  * **No answer key.** A fix commit is soaked in the answer: the message names
    the CVE, the tests added alongside are often named after it. A case that
    ships with the answer inside scores the agent's ability to read a label.

The network-touching part is not tested here; these cover the logic that
decides what gets built and what gets thrown away.
"""

from __future__ import annotations

import filecmp
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from harvest_pairs import (
    CWE_CATEGORY,
    LEAK,
    NOISE,
    SCHEMA_NAME,
    build_member,
    category_of,
    git_env,
    language_of,
    leak_check,
)

# ------------------------------------------------------- what gets dropped


@pytest.mark.parametrize("path", [
    "tests/test_parser.py",
    "test/foo_test.go",
    "spec/models/user_spec.rb",
    "src/__tests__/login.spec.ts",
    "CHANGELOG.md",
    "docs/SECURITY.md",
    "RELEASE-NOTES.rst",
    "src/main/java/AuthTest.java",
])
def test_answer_key_paths_are_dropped_from_the_change(path):
    assert NOISE.search(path), path


@pytest.mark.parametrize("path", [
    "src/parser.py",
    "internal/exec/runner.go",
    "app/models/user.rb",
    "lib/contest.py",          # contains "test" but is not a test
    "src/latest_version.ts",
])
def test_ordinary_source_files_are_kept(path):
    assert not NOISE.search(path), path


# ------------------------------------------------------------- leak checks


@pytest.mark.parametrize("text", [
    "# fixes CVE-2023-41040",
    "See GHSA-wvpp-8hx9-p66j for details",
    "cve-2024-1234 regression",
])
def test_an_advisory_id_anywhere_is_a_leak(text):
    assert LEAK.search(text)


def test_ordinary_code_is_not_flagged_as_a_leak():
    assert not LEAK.search("def resolve(path):\n    return path.resolve()\n")


def test_leak_check_walks_the_whole_case(tmp_path):
    (tmp_path / "safe").mkdir()
    (tmp_path / "safe" / "a.py").write_text("x = 1\n")
    (tmp_path / "safe" / "b.py").write_text("# guard for CVE-2021-9999\n")
    leaks = leak_check(tmp_path)
    assert len(leaks) == 1
    assert "b.py" in leaks[0]


def test_the_manifest_is_exempt_because_it_never_enters_the_repo(tmp_path):
    """It records the advisory on purpose; the agent is never shown it."""
    (tmp_path / "case.yml").write_text("source_cve: CVE-2020-1234\n")
    assert leak_check(tmp_path) == []


# ----------------------------------------------------------- classification


def test_the_language_comes_from_the_files_not_the_ecosystem():
    """npm holds both; guessing from the ecosystem mislabels half of it."""
    assert language_of(["src/app.ts", "src/util.ts", "README.md"]) == "typescript"
    assert language_of(["main.go"]) == "go"
    assert language_of(["README.md"]) == ""


def test_an_unmapped_cwe_yields_no_expected_category():
    """Better an honest blank than a category invented to fill the field."""
    assert category_of(["CWE-1188"]) == ""
    assert category_of(["CWE-89"]) == "injection"
    assert category_of(["CWE-1188", "CWE-918"]) == "ssrf"


def test_every_mapped_category_is_one_the_agent_can_report():
    """A category the agent never emits scores every such case as a miss.

    Read from the schema, not from a set typed here. The version of this test
    that typed the set passed while the map contained `authorization`,
    `path_traversal` and `open_redirect` — none of which the agent can emit —
    because it was written from the same wrong belief as the code it checked.
    A test that shares the code's premise tests nothing.
    """
    from security_agent.vocabulary import categories

    unknown = set(CWE_CATEGORY.values()) - set(categories())
    assert not unknown, "not in {}: {}".format(SCHEMA_NAME, sorted(unknown))


def test_every_case_in_every_corpus_scores_against_a_real_category():
    """The check that would have caught it in the corpus rather than the map."""
    from security_agent.vocabulary import categories

    valid = set(categories())
    offenders = []
    for manifest in sorted(Path(__file__).resolve().parents[1].glob("corpus*/*/case.yml")):
        spec = yaml.safe_load(manifest.read_text(encoding="utf-8")) or {}
        wanted = (spec.get("expected_category") or "").strip()
        # Blank is allowed and means "score on file alone", which is the honest
        # answer for a weakness the vocabulary has no name for.
        if wanted and wanted not in valid:
            offenders.append("{}: {}".format(manifest.parent.name, wanted))
    assert not offenders, offenders


# ---------------------------------------------------------------- symmetry


def test_the_two_members_are_exact_inverses(tmp_path):
    """The property the whole construction rests on.

    Built from a real two-commit repository rather than from stubs, because the
    failure this guards against is a `git show` returning the wrong revision,
    which stubs would not reproduce.
    """
    repo = tmp_path / "src"
    repo.mkdir()
    env = git_env(tmp_path)
    subprocess.run(("git", "init", "-q", "-b", "main", str(repo)),
                   check=True, capture_output=True, env=env)

    target = repo / "handler.py"
    target.write_text("def run(cmd):\n    os.system(cmd)\n")
    subprocess.run(("git", "-C", str(repo), "add", "-A"),
                   check=True, capture_output=True, env=env)
    subprocess.run(("git", "-C", str(repo), "commit", "-qm", "before"),
                   check=True, capture_output=True, env=env)
    parent = subprocess.run(("git", "-C", str(repo), "rev-parse", "HEAD"),
                            check=True, capture_output=True, text=True,
                            env=env).stdout.strip()

    target.write_text("def run(cmd):\n    subprocess.run(shlex.split(cmd))\n")
    subprocess.run(("git", "-C", str(repo), "add", "-A"),
                   check=True, capture_output=True, env=env)
    subprocess.run(("git", "-C", str(repo), "commit", "-qm", "after"),
                   check=True, capture_output=True, env=env)
    fix = subprocess.run(("git", "-C", str(repo), "rev-parse", "HEAD"),
                         check=True, capture_output=True, text=True,
                         env=env).stdout.strip()

    case = tmp_path / "case"
    case.mkdir()
    for member in ("safe", "unsafe"):
        build_member(case, member, repo, parent, fix, ["handler.py"], env)

    assert filecmp.cmp(case / "safe" / "handler.py",
                       case / "unsafe" / "change" / "handler.py", shallow=False)
    assert filecmp.cmp(case / "safe" / "change" / "handler.py",
                       case / "unsafe" / "handler.py", shallow=False)
    assert "os.system" in (case / "safe" / "handler.py").read_text()
    assert "shlex.split" in (case / "safe" / "change" / "handler.py").read_text()
