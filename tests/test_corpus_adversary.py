"""A corpus must not be scoreable without reading the code.

This is here because an audit found that

    the member with more comment lines is the safe one, tiebreak on more bytes

picked correctly **48 times out of 48** on the harvested corpus. The cases come
from real security fixes, and a fix commit carries the maintainer's explanation
of the fix — so harvesting put that prose on the safe side and nowhere else.

Nothing in the review pipeline could have shown this. The agent would have
scored well, the number would have been believed, and what was really being
measured was whether the safe member had more comments. A corpus that leaks is
worse than a small one, because a small one is visibly small.

So the adversary runs in CI. If a rule that reads no code beats chance by much,
the corpus is not measuring what it says.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from corpus_adversary import (
    byte_count,
    comment_lines,
    evaluate,
    import_lines,
    judge,
    worst,
)

ROOT = Path(__file__).resolve().parents[1]

# 0.65 rather than 0.5: with a few dozen cases, a run of coin flips reaches the
# high fifties often enough that a tighter gate would fail on noise. It is set
# to catch a systematic cue, not to prove there is none.
THRESHOLD = 0.65
MIN_FIRES = 6


def write_case(root: Path, name: str, safe: str, unsafe: str, suffix=".py") -> Path:
    case = root / name
    for member, text in (("safe", safe), ("unsafe", unsafe)):
        target = case / member / "change" / ("code" + suffix)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
    (case / "case.yml").write_text("case_id: {}\n".format(name), encoding="utf-8")
    return case


# ------------------------------------------------------------------- corpora


@pytest.mark.parametrize("corpus", ["corpus", "corpus-real"])
def test_no_code_blind_rule_can_score_the_corpus(corpus):
    root = ROOT / corpus
    if not root.is_dir():
        pytest.skip("{} is not present".format(corpus))

    scores = evaluate([root])
    name, accuracy, row = worst(scores, MIN_FIRES)
    if not name:
        pytest.skip("no rule fired often enough to judge {}".format(corpus))

    assert abs(accuracy - 0.5) <= THRESHOLD - 0.5, (
        "{}: the rule {!r} reads no code and is right {:.0f}% of the time over "
        "{} case(s). The corpus is measuring that rule, not the reviewer."
        .format(corpus, name, 100 * accuracy, row["fired"])
    )


@pytest.mark.parametrize("corpus", ["corpus", "corpus-real"])
def test_the_two_members_carry_the_same_amount_of_prose(corpus):
    """The specific asymmetry the audit found, checked case by case.

    Aggregate accuracy can sit at chance while individual cases leak badly in
    both directions, so the per-case check is not redundant.
    """
    root = ROOT / corpus
    if not root.is_dir():
        pytest.skip("{} is not present".format(corpus))

    offenders = []
    for manifest in sorted(root.rglob("case.yml")):
        case = manifest.parent
        safe, unsafe = comment_lines(case / "safe"), comment_lines(case / "unsafe")
        if safe != unsafe:
            offenders.append("{}: safe {} comment line(s), unsafe {}".format(
                case.name, safe, unsafe))
    assert not offenders, offenders


# --------------------------------------------------------------------- rules


def test_a_rule_abstains_when_the_two_members_tie(tmp_path):
    """Counted as evidence, a tie would drag every rule towards 50%."""
    case = write_case(tmp_path, "tied", "x = 1\n", "x = 2\n")
    assert judge(case, byte_count) == ""


def test_a_rule_names_the_member_it_believes_is_safe(tmp_path):
    case = write_case(tmp_path, "skewed", "x = 1\ny = 2\nz = 3\n", "x = 1\n")
    assert judge(case, byte_count) == "safe"
    assert judge(case, comment_lines) == ""


def test_a_rule_that_picks_the_unsafe_member_leaks_just_as_much(tmp_path):
    """Distance from chance, not raw accuracy.

    A rule reliably picking the *unsafe* member is the same leak read backwards,
    and ranking on accuracy alone would score it 0% and call it harmless.
    """
    for index in range(8):
        write_case(tmp_path, "case{}".format(index), "x = 1\n", "x = 1\ny = 2\n")
    _, accuracy, row = worst(evaluate([tmp_path]), MIN_FIRES)
    assert row["fired"] == 8
    assert accuracy == 0.0
    assert abs(accuracy - 0.5) > THRESHOLD - 0.5


def test_the_audit_s_own_rule_is_reproduced(tmp_path):
    """Comment count first, bytes as a tiebreak — the one that scored 48/48."""
    for index in range(8):
        write_case(tmp_path, "case{}".format(index),
                   "# explains the fix\nx = 1\n", "x = 1\n")
    scores = evaluate([tmp_path])
    assert scores["comments, then bytes"]["fired"] == 8
    assert scores["comments, then bytes"]["correct"] == 8


def test_a_shebang_is_not_counted_as_prose(tmp_path):
    case = write_case(tmp_path, "shebang", "#!/usr/bin/env python\nx = 1\n", "x = 1\n")
    assert comment_lines(case / "safe") == 0


def test_comment_markers_are_per_language(tmp_path):
    case = write_case(tmp_path, "go", "// a note\nx := 1\n", "x := 1\n", suffix=".go")
    assert comment_lines(case / "safe") == 1
    assert comment_lines(case / "unsafe") == 0


def test_imports_are_counted_across_languages(tmp_path):
    case = write_case(tmp_path, "imports",
                      "import json\nfrom hmac import compare_digest\nx = 1\n",
                      "import pickle\nx = 1\n")
    assert import_lines(case / "safe") == 2
    assert import_lines(case / "unsafe") == 1


def test_only_the_change_is_examined(tmp_path):
    """Baseline files are shared context; counting them measures the repository."""
    case = write_case(tmp_path, "baseline", "x = 1\n", "x = 1\n")
    (case / "safe" / "context.py").write_text("# " + "prose\n# " * 40, encoding="utf-8")
    assert comment_lines(case / "safe") == 0
