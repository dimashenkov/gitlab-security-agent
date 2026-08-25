"""The corpus check, which is the cheapest thing in this project and was absent.

Every defect it looks for was found by hand, after a paid run had already been
scored against it — seven cases judged on category names the schema does not
contain, twenty manifests naming one file where the fix touched several. None
of those cost anything to detect. They cost money because nothing looked.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from check_corpus import check_case

VOCABULARY = {"injection", "xss", "csrf", "dos", "other"}


def build(tmp_path, manifest: str, safe: dict, unsafe: dict) -> Path:
    case = tmp_path / "a-case"
    case.mkdir(parents=True)
    (case / "case.yml").write_text(manifest)
    for member, files in (("safe", safe), ("unsafe", unsafe)):
        for name, body in files.items():
            path = case / member / "change" / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(body)
    return case


MANIFEST = ("expected_category: injection\n"
            "expected_file: ['app/views.py']\n")


def test_a_well_formed_case_has_nothing_to_say(tmp_path):
    case = build(tmp_path, MANIFEST,
                 {"app/views.py": "safe code\n"},
                 {"app/views.py": "unsafe code\n"})
    assert check_case(case, VOCABULARY) == []


def test_a_category_the_agent_cannot_emit_is_caught(tmp_path):
    """The original: `authorization`, `path_traversal` and `open_redirect` do
    not exist in the schema, so seven cases were guaranteed misses and read as
    failures of the reviewer."""
    case = build(tmp_path, "expected_category: open_redirect\n"
                           "expected_file: ['app/views.py']\n",
                 {"app/views.py": "a\n"}, {"app/views.py": "b\n"})
    problems = check_case(case, VOCABULARY)
    assert any("not in the schema" in p for p in problems), problems


def test_a_file_the_fix_touches_but_the_manifest_omits_is_caught(tmp_path):
    """Twenty of forty-eight. Winter's fix normalises a name in one file and
    rejects the bad ones in another; the manifest named the first."""
    case = build(tmp_path, MANIFEST,
                 {"app/views.py": "a\n", "app/forms.py": "guard added\n"},
                 {"app/views.py": "b\n", "app/forms.py": "no guard\n"})
    problems = check_case(case, VOCABULARY)
    assert any("app/forms.py" in p and "does not list" in p for p in problems), problems


def test_a_file_identical_in_both_members_need_not_be_listed(tmp_path):
    """It is the same code on both sides, so it cannot be the decisive control.

    `go-sql-decoy-01` adds a `routes.go` that puts the middleware genuinely on
    the call path. Both members need it and neither is about it. Requiring it
    in `expected_file` would widen the target to a file where a finding would
    be neither expected nor wrong.
    """
    case = build(tmp_path, MANIFEST,
                 {"app/views.py": "a\n", "app/routes.py": "same\n"},
                 {"app/views.py": "b\n", "app/routes.py": "same\n"})
    assert check_case(case, VOCABULARY) == []


def test_a_file_that_differs_must_still_be_listed(tmp_path):
    """The exemption is for identical files only. One byte apart and it is a
    place the decisive control could be hiding."""
    case = build(tmp_path, MANIFEST,
                 {"app/views.py": "a\n", "app/routes.py": "guarded\n"},
                 {"app/views.py": "b\n", "app/routes.py": "unguarded\n"})
    problems = check_case(case, VOCABULARY)
    assert any("app/routes.py" in p for p in problems), problems


def test_a_target_path_that_matches_nothing_is_caught(tmp_path):
    """It scores every run as a miss, silently and forever."""
    case = build(tmp_path, "expected_category: injection\n"
                           "expected_file: ['app/nowhere.py']\n",
                 {"app/views.py": "a\n"}, {"app/views.py": "b\n"})
    problems = check_case(case, VOCABULARY)
    assert any("no member changes" in p for p in problems), problems


def test_identical_members_are_caught(tmp_path):
    """Two identical members measure nothing, and a harvest that dropped the
    decisive file produces exactly that."""
    case = build(tmp_path, MANIFEST,
                 {"app/views.py": "same\n"}, {"app/views.py": "same\n"})
    problems = check_case(case, VOCABULARY)
    assert any("byte-identical" in p for p in problems), problems


@pytest.mark.parametrize("identifier", ["CVE-2023-41040", "GHSA-p2ch-c2c3-4xm5"])
def test_an_advisory_named_in_the_code_is_caught(tmp_path, identifier):
    """The case is answerable without reading anything."""
    case = build(tmp_path, MANIFEST,
                 {"app/views.py": "# fixes {}\nsafe\n".format(identifier)},
                 {"app/views.py": "unsafe\n"})
    problems = check_case(case, VOCABULARY)
    assert any("names the advisory" in p for p in problems), problems


def test_an_empty_category_is_a_problem_not_a_default(tmp_path):
    """It matches any category, so the case is looser than the table implies —
    and it was silently doing that in three cases."""
    case = build(tmp_path, "expected_category:\n"
                           "expected_file: ['app/views.py']\n",
                 {"app/views.py": "a\n"}, {"app/views.py": "b\n"})
    problems = check_case(case, VOCABULARY)
    assert any("no expected_category" in p for p in problems), problems


def test_several_categories_are_allowed_and_each_is_checked(tmp_path):
    """Keystone's negative-`take` bypass is defensibly `dos` and defensibly
    `other`; picking one would be guessing which word the model reaches for."""
    case = build(tmp_path, "expected_category: ['dos', 'other']\n"
                           "expected_file: ['app/views.py']\n",
                 {"app/views.py": "a\n"}, {"app/views.py": "b\n"})
    assert check_case(case, VOCABULARY) == []

    case = build(tmp_path / "second", "expected_category: ['dos', 'invented']\n"
                                      "expected_file: ['app/views.py']\n",
                 {"app/views.py": "a\n"}, {"app/views.py": "b\n"})
    problems = check_case(case, VOCABULARY)
    assert any("invented" in p for p in problems), problems


def test_a_missing_member_stops_the_rest_of_the_checks(tmp_path):
    """Reporting nine consequences of one missing directory buries the cause."""
    case = tmp_path / "half-a-case"
    case.mkdir()
    (case / "case.yml").write_text(MANIFEST)
    (case / "safe" / "change").mkdir(parents=True)
    problems = check_case(case, VOCABULARY)
    assert problems == ["no unsafe/ directory"]


def test_the_real_corpus_passes():
    """The check is only worth having if the corpus it guards is clean now."""
    root = Path(__file__).resolve().parents[1]
    manifests = sorted((root / "corpus").rglob("case.yml"))
    assert manifests, "the hand-written corpus went missing"

    from security_agent.vocabulary import categories

    vocabulary = set(categories())
    broken = {m.parent.name: check_case(m.parent, vocabulary)
              for m in manifests if check_case(m.parent, vocabulary)}
    assert not broken, broken
