"""The drawing in `docs/` makes claims about `cli.py`. These fail when it lies.

`docs/flow.html` and `docs/flow.en.html` draw one review, step by step. Three
fixes on 2026-09-03 reordered that review — the output directory is now checked
above the skip, the prompt guard runs even when the label switches the review
off, and suppression is applied *before* verification so that only the kept
candidates are ever bought a verifier. Every one of those changes made the
picture wrong, and nothing failed. A rule that is documented and unchecked is
the defect this repository keeps finding in itself.

The check is aimed at the *relationship* between the drawing and the code, not
at the drawing's words:

* every step box cites `module.py · function`, and that function must exist in
  that module — a rename in `src/` breaks the citation;
* the citations, read top to bottom by their `y`, must appear in the same order
  as those functions are called inside `cli.py::_run`, read by `ast` — so
  moving a call in the code without moving its box fails here;
* the two pages must draw identical geometry, and the English page must carry
  no Cyrillic;
* every label must still fit inside the box that holds it.

What it cannot catch is written at the bottom of this file.
"""

import ast
import html
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"
PACKAGE = ROOT / "src" / "security_agent"
PAGES = (DOCS / "flow.html", DOCS / "flow.en.html")

# `report.py · write_artifacts`, `cli.py · _prompt_risk`, and so on. The
# separator is the same middle dot the drawing uses everywhere else, so a box
# that merely mentions a file name in prose ("report.md") does not match.
CITATION = re.compile(r"([a-z_][a-z_0-9]*)\.py · ([A-Za-z_][A-Za-z_0-9]*)")
TEXT = re.compile(r'<text class="([a-z]+)"[^>]*x="([\d.]+)" y="([\d.]+)"[^>]*>'
                  r"([^<]*)</text>")
RECT = re.compile(r'<rect class="([^"]+)" x="([\d.]+)" y="([\d.]+)" '
                  r'width="([\d.]+)" height="([\d.]+)"')
PATH = re.compile(r'<path[^>]*\sd="([^"]+)"')
CYRILLIC = re.compile(r"[Ѐ-ӿԀ-ԯ]")

# Advance per character, measured against the fonts the page asks for. The
# drawing has no text wrapping: a label that is too long runs out of its box.
CHAR_WIDTH = {"t": 8.4, "tm": 8.4, "s": 6.7, "sd": 6.6, "et": 6.7, "pt": 6.7,
              "lt": 6.4}

# Boxes that legitimately contain other boxes, and so cannot be measured
# against the labels that fall inside them.
CONTAINERS = {"pen"}

# Citations that must be present. Without this, the ordering test could be
# satisfied by deleting every inconvenient box: an empty sequence is in order.
# These five are the steps the ordering exists to pin down.
REQUIRED = {
    ("report", "preflight_output_dir"),
    ("cli", "_prompt_risk"),
    ("suppress", "apply"),
    ("verify", "verify_candidates"),
    ("gate", "decide"),
}


# --------------------------------------------------------------- the drawing


def _svg(page: Path) -> str:
    body = page.read_text(encoding="utf-8")
    return body[body.index("<svg"):body.index("</svg>")]


def _labels(page: Path):
    """(class, x, y, text) for every label, in document order."""
    return [(m.group(1), float(m.group(2)), float(m.group(3)),
             html.unescape(m.group(4)))
            for m in TEXT.finditer(_svg(page))]


def _rects(page: Path):
    return [(m.group(1), float(m.group(2)), float(m.group(3)),
             float(m.group(4)), float(m.group(5)))
            for m in RECT.finditer(_svg(page))]


def _cited(page: Path):
    """Every `module.py · function` the drawing claims, top to bottom."""
    found = []
    for _cls, x, y, label in _labels(page):
        match = CITATION.search(label)
        if match:
            found.append((y, x, match.group(1), match.group(2)))
    found.sort()
    return [(module, name) for _y, _x, module, name in found]


def _geometry(page: Path):
    svg = _svg(page)
    return (
        [("rect", *r) for r in _rects(page)]
        + [("text", c, x, y) for c, x, y, _ in _labels(page)]
        + [("path", d) for d in PATH.findall(svg)]
    )


# ------------------------------------------------------------------ the code


def _defined_names(module: str):
    """Everything `module.py` defines, methods included."""
    tree = ast.parse((PACKAGE / (module + ".py")).read_text(encoding="utf-8"))
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(node.name)
    return names


def _run_call_order():
    """(module, function) in the order `cli.py::_run` first calls them.

    Import aliases are resolved, because `_run` imports `load` as `load_rules`
    and `apply` as `apply_suppressions` — a citation that named the local alias
    would point at a function no module defines.
    """
    source = (PACKAGE / "cli.py").read_text(encoding="utf-8")
    tree = ast.parse(source)

    aliases = {}

    def read_imports(nodes):
        """Imports in *these* statements, not in everything under them.

        `ast.walk(tree)` picked up the imports inside every function in
        `cli.py`, so an unrelated one importing the same alias — several
        functions here import `apply_suppressions` locally — would overwrite
        the meaning `_run` gives it, and this test would fail with neither
        `_run` nor the diagram having changed.
        """
        for node in nodes:
            if isinstance(node, ast.ImportFrom) and node.module:
                for name in node.names:
                    aliases[name.asname or name.name] = (
                        node.module.lstrip("."), name.name)

    read_imports(tree.body)
    run = next(node for node in tree.body
               if isinstance(node, ast.FunctionDef) and node.name == "_run")
    read_imports(run.body)

    local = {node.name for node in tree.body
             if isinstance(node, (ast.FunctionDef, ast.ClassDef))}

    calls = []
    for node in ast.walk(run):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            called = node.func.id
            where = (node.lineno, node.col_offset)
            if called in aliases:
                calls.append((where, aliases[called]))
            elif called in local:
                calls.append((where, ("cli", called)))
    calls.sort()

    first = {}
    for where, pair in calls:
        first.setdefault(pair, where)
    return [pair for pair, _ in sorted(first.items(), key=lambda kv: kv[1])]


# ----------------------------------------------------------------- the tests


@pytest.mark.parametrize("page", PAGES, ids=lambda p: p.name)
def test_every_cited_function_exists(page):
    """A citation is a claim about `src/`; a rename must break it."""
    missing = []
    for module, name in _cited(page):
        source = PACKAGE / (module + ".py")
        if not source.is_file():
            missing.append("{}.py does not exist".format(module))
        elif name not in _defined_names(module):
            missing.append("{}.py defines no {}".format(module, name))
    assert not missing, "{} cites code that is not there: {}".format(
        page.name, missing)


@pytest.mark.parametrize("page", PAGES, ids=lambda p: p.name)
def test_the_required_steps_are_drawn(page):
    """The ordering test below is vacuous on a diagram with nothing in it."""
    absent = REQUIRED - set(_cited(page))
    assert not absent, "{} no longer draws {}".format(page.name, sorted(absent))


@pytest.mark.parametrize("page", PAGES, ids=lambda p: p.name)
def test_the_drawn_order_is_the_order_run_calls_them(page):
    """Top-to-bottom in the picture == first-call order in `cli.py::_run`.

    This is the check that was missing this morning. Suppression was drawn
    below verification while `_run` had already been changed to apply the rules
    first, and nothing anywhere said so.

    A citation `_run` never calls — `tools.py · _handle_report_finding`, which
    the model reaches through the tool dispatcher — is checked for existence
    above and sits out of the ordering; it has no position to compare against.
    """
    code_order = _run_call_order()
    ranked = {pair: i for i, pair in enumerate(code_order)}

    drawn = [pair for pair in _cited(page) if pair in ranked]
    assert len(drawn) >= 10, (
        "only {} of the drawn steps can be located in _run; the ordering check "
        "has stopped covering the flow".format(len(drawn)))

    positions = [ranked[pair] for pair in drawn]
    assert positions == sorted(positions), (
        "{} draws the steps in an order _run does not follow.\n"
        "  drawn: {}\n  _run:  {}".format(
            page.name,
            [".".join(p) for p in drawn],
            [".".join(p) for p in code_order if p in set(drawn)]))


@pytest.mark.parametrize("page", PAGES, ids=lambda p: p.name)
def test_no_step_is_drawn_twice_in_the_column(page):
    """One citation, one box. Two would make the order above ambiguous."""
    drawn = _cited(page)
    duplicates = {pair for pair in drawn if drawn.count(pair) > 1}
    assert not duplicates, "{} cites {} more than once".format(
        page.name, sorted(duplicates))


def test_both_pages_draw_the_same_picture():
    """Same rects, same text anchors, same wires — only the words differ.

    A change made to one page and not the other is the failure this catches;
    it has happened, in both directions.
    """
    left, right = (_geometry(page) for page in PAGES)
    assert left == right, "the two pages have drifted apart"


def test_the_english_page_is_english():
    """Except the link that names the other language."""
    body = html.unescape(PAGES[1].read_text(encoding="utf-8"))
    strays = [line.strip() for line in body.splitlines()
              if CYRILLIC.search(line) and 'class="lang"' not in line]
    assert not strays, strays


@pytest.mark.parametrize("page", PAGES, ids=lambda p: p.name)
def test_labels_fit_the_boxes_that_hold_them(page):
    """SVG text does not wrap; a long translation runs out of its box.

    A label outside every box is measured against the canvas instead — the
    captions beside the amber bracket live there, and were checked against
    nothing until a box-less label was noticed overflowing.
    """
    rects = [r for r in _rects(page) if r[0] not in CONTAINERS]
    canvas = float(re.search(r'viewBox="0 0 ([\d.]+)', _svg(page)).group(1))

    spills = []
    for cls, x, y, label in _labels(page):
        end = x + len(label) * CHAR_WIDTH.get(cls, 7.0)
        for _rcls, rx, ry, rw, rh in rects:
            if rx <= x <= rx + rw and ry <= y <= ry + rh:
                if (rx + rw) - end < 6:
                    spills.append((round((rx + rw) - end), label))
                break
        else:
            if canvas - end < 6:
                spills.append((round(canvas - end), label))
    assert not spills, "{}: labels that do not fit: {}".format(page.name, spills)


@pytest.mark.parametrize("page", PAGES, ids=lambda p: p.name)
def test_the_boxes_do_not_overlap(page):
    """Two boxes on the same pixels means one of them was moved by hand."""
    rects = [r for r in _rects(page) if r[0] not in CONTAINERS]
    clashes = []
    for i, (acls, ax, ay, aw, ah) in enumerate(rects):
        for bcls, bx, by, bw, bh in rects[i + 1:]:
            if (ax < bx + bw and bx < ax + aw
                    and ay < by + bh and by < ay + ah):
                clashes.append((acls, ay, bcls, by))
    assert not clashes, "{}: overlapping boxes {}".format(page.name, clashes)


def test_the_page_is_self_contained():
    """No CDN, no remote font, no image the reader has to be online for."""
    for page in PAGES:
        body = page.read_text(encoding="utf-8")
        remote = re.findall(r'(?:src|href)="(https?:|//)[^"]*"', body)
        assert not remote, "{} loads something from off the page".format(page.name)


# What this file cannot catch, said out loud rather than left to be discovered:
#
# * Wording. Every sentence under a citation is prose, and prose can say the
#   opposite of what the function does with the test still green.
# * Steps the drawing simply leaves out. Nothing here notices a call added to
#   `_run` that no box mentions — only a call that moved.
# * Where the arrows go. The wires are compared between the two pages, never
#   against a control-flow graph, so an exit drawn from the wrong box passes.
# * The paths through `_run` that are not the API provider's: `_review_with_cli`
#   and `verify_cli` do the same work through the local CLI and are not drawn.
# * Order inside a called function. `_prompt_risk` resolving its own baseline,
#   or `decide` reading the outcome, is below the resolution of the picture.
