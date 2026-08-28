"""Comments come out; nothing else does.

An audit found `corpus-real/` decided by a rule that reads no code: *the member
whose `change/` has more comment lines is the safe one*. It scored 48/48,
because the cases are harvested from real security fixes and the maintainer's
explanation of the guard only exists on the side that has the guard. Some were
literal answer keys — a safe-only `(CWE-639 / CWE-862)`, eleven safe-only
`// SECURITY:` markers.

The fix strips comments from both members. Which makes the stripper itself the
risk: a stripper that mistakes the `//` inside `"http://x"` for a comment turns
a real vulnerability into a file that no longer compiles, or — worse, because
it is invisible — into one that compiles and no longer contains the bug. So the
tests are ordered the way the risk is:

  1. string literals survive, in every language;
  2. comments and docstrings do not;
  3. directives the compiler reads do;
  4. the line count never moves;
  5. and the real corpus carries the same amount of prose on both sides, which
     is the property the audit found violated.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from strip_comments import (
    STRIPPED,
    UNCHANGED,
    UNSUPPORTED,
    comment_lines,
    strip_comments,
    strip_comments_report,
)

ROOT = Path(__file__).resolve().parents[1]

# The nine the harvester can produce. Named here so that adding a language to
# EXTENSION_LANGUAGE without a scanner fails a test rather than passing quietly.
LANGUAGES = ["python", "go", "java", "php", "ruby", "rust", "typescript",
             "javascript", "csharp"]

SUFFIX = {"python": ".py", "go": ".go", "java": ".java", "php": ".php",
          "ruby": ".rb", "rust": ".rs", "typescript": ".ts",
          "javascript": ".js", "csharp": ".cs"}


# ------------------------------------------------------- 1. strings survive

# The half of the job that matters. Each source contains a comment marker
# inside a string literal, and a real comment after it: the string must come
# through byte for byte, the comment must not come through at all.
INSIDE_A_STRING = {
    "python": ('url = "http://host/#frag"  # explains the guard\n',
               'url = "http://host/#frag"\n'),
    "go": ('url := "http://host/#frag" // explains the guard\n',
           'url := "http://host/#frag"\n'),
    "java": ('String u = "http://host/#frag"; // explains the guard\n',
             'String u = "http://host/#frag";\n'),
    "php": ('<?php\n$u = \'http://host/#frag\'; // explains the guard\n',
            '<?php\n$u = \'http://host/#frag\';\n'),
    "ruby": ('u = "http://host/#frag" # explains the guard\n',
             'u = "http://host/#frag"\n'),
    "rust": ('let u = "http://host/#frag"; // explains the guard\n',
             'let u = "http://host/#frag";\n'),
    "typescript": ('const u = "http://host/#frag"; // explains the guard\n',
                   'const u = "http://host/#frag";\n'),
    "javascript": ("const u = 'http://host/#frag'; // explains the guard\n",
                   "const u = 'http://host/#frag';\n"),
    "csharp": ('var u = "http://host/#frag"; // explains the guard\n',
               'var u = "http://host/#frag";\n'),
}


@pytest.mark.parametrize("language", LANGUAGES)
def test_a_comment_marker_inside_a_string_is_not_a_comment(language):
    source, expected = INSIDE_A_STRING[language]
    assert strip_comments(source, SUFFIX[language]) == expected


# The literals each language gets wrong in its own way. Every one of these must
# come out of the stripper exactly as it went in.
UNTOUCHABLE = [
    (".py", 'p = r"C:\\x"\nq = f"{a}#{b}"\ns = """a # b"""\n'),
    (".py", "s = '''triple ' quoted # not a comment'''\n"),
    (".go", 'raw := `line one // not a comment\nline two`\nr := \'/\'\n'),
    (".java", 'String s = """\n  a // b\n  """;\nchar c = \'/\';\n'),
    (".php", "<?php\n$h = <<<SQL\nselect 1 -- // not a comment\nSQL;\n"),
    (".php", "<?php\n$n = <<<'RAW'\n# not a comment\nRAW;\n"),
    (".rb", "s = %w[a#b c#d]\nt = <<~TEXT\n  # not a comment\nTEXT\n"),
    (".rb", 'r = /a#b/ =~ x\nc = ?#\ni = "a #{h["k#v"]} b"\n'),
    (".rs", 'let r = r#"a // b"#;\nlet c = \'/\';\nlet s = "a /* b */ c";\n'),
    (".rs", "fn f<'a>(x: &'a str) -> &'a str { x }\n"),
    (".ts", "const t = `a ${b} // not a comment`;\nconst r = /a\\/\\/b/;\n"),
    (".js", "const d = a / b / c;\nconst s = 'it\\'s // fine';\n"),
    (".cs", 'var v = @"C:\\path // not a comment";\nvar i = $"{a}/{b}";\n'),
]


@pytest.mark.parametrize("suffix,source", UNTOUCHABLE)
def test_literals_are_never_rewritten(suffix, source):
    assert strip_comments(source, suffix) == source


# ------------------------------------------------------ 2. comments do not

WHOLE_LINE = {
    "python": ("# explains the guard\nx = 1\n", "\nx = 1\n"),
    "go": ("// explains the guard\nx := 1\n", "\nx := 1\n"),
    "java": ("// explains the guard\nint x = 1;\n", "\nint x = 1;\n"),
    "php": ("<?php\n# explains the guard\n$x = 1;\n", "<?php\n\n$x = 1;\n"),
    "ruby": ("# explains the guard\nx = 1\n", "\nx = 1\n"),
    "rust": ("// explains the guard\nlet x = 1;\n", "\nlet x = 1;\n"),
    "typescript": ("// explains the guard\nconst x = 1;\n", "\nconst x = 1;\n"),
    "javascript": ("// explains the guard\nconst x = 1;\n", "\nconst x = 1;\n"),
    "csharp": ("// explains the guard\nvar x = 1;\n", "\nvar x = 1;\n"),
}


@pytest.mark.parametrize("language", LANGUAGES)
def test_a_whole_line_comment_becomes_a_blank_line(language):
    source, expected = WHOLE_LINE[language]
    result = strip_comments(source, SUFFIX[language])
    assert result == expected
    assert "explains" not in result


TRAILING = {
    "python": ("call(user_id)  # only the owner may read this\n", "call(user_id)\n"),
    "go": ("call(userID) // only the owner may read this\n", "call(userID)\n"),
    "java": ("call(userId); // only the owner may read this\n", "call(userId);\n"),
    "php": ("<?php\ncall($id); # only the owner may read this\n", "<?php\ncall($id);\n"),
    "ruby": ("call(user_id) # only the owner may read this\n", "call(user_id)\n"),
    "rust": ("call(user_id); // only the owner may read this\n", "call(user_id);\n"),
    "typescript": ("call(userId); // only the owner may read\n", "call(userId);\n"),
    "javascript": ("call(userId); // only the owner may read\n", "call(userId);\n"),
    "csharp": ("Call(userId); // only the owner may read\n", "Call(userId);\n"),
}


@pytest.mark.parametrize("language", LANGUAGES)
def test_a_trailing_comment_goes_and_its_code_stays(language):
    """The code line survives whole, with no trailing whitespace left behind."""
    source, expected = TRAILING[language]
    assert strip_comments(source, SUFFIX[language]) == expected


# Docstrings for the two languages that have them, doc comments for the rest.
# Same prose, same problem: `/** Validates the tenant id */` is an answer key
# written in a different syntax.
DOCSTRING = {
    "python": ('def f(x):\n    """Reject any id the caller does not own."""\n'
               "    return x\n",
               "def f(x):\n    ''\n    return x\n"),
    "ruby": ("=begin\nReject any id the caller does not own.\n=end\ndef f(x)\n"
             "  x\nend\n",
             "\n\n\ndef f(x)\n  x\nend\n"),
    "go": ("// Check reports whether the caller owns it.\nfunc Check() {}\n",
           "\nfunc Check() {}\n"),
    "java": ("/** Reject any id the caller does not own. */\nvoid f() {}\n",
             "\nvoid f() {}\n"),
    "php": ("<?php\n/** Reject any id the caller does not own. */\nfunction f() {}\n",
            "<?php\n\nfunction f() {}\n"),
    "rust": ("/// Reject any id the caller does not own.\nfn f() {}\n",
             "\nfn f() {}\n"),
    "typescript": ("/** Reject any id the caller does not own. */\nfunction f() {}\n",
                   "\nfunction f() {}\n"),
    "javascript": ("/** Reject any id the caller does not own. */\nfunction f() {}\n",
                   "\nfunction f() {}\n"),
    "csharp": ("/// <summary>Reject any id the caller does not own.</summary>\n"
               "void F() {}\n",
               "\nvoid F() {}\n"),
}


@pytest.mark.parametrize("language", LANGUAGES)
def test_a_docstring_or_doc_comment_is_prose_and_goes(language):
    source, expected = DOCSTRING[language]
    result = strip_comments(source, SUFFIX[language])
    assert result == expected
    assert "Reject any id" not in result


def test_a_module_docstring_leaves_a_string_behind_not_a_pass():
    """`pass` here would make the future import a syntax error.

    A future statement may be preceded by the module docstring and nothing
    else, so the placeholder has to stay a string expression. Found by
    compiling the result rather than by reading it.
    """
    source = '"""What this module is for."""\nfrom __future__ import annotations\n'
    result = strip_comments(source, ".py")
    assert result == "''\nfrom __future__ import annotations\n"
    compile(result, "<test>", "exec")


def test_a_docstring_is_the_only_statement_and_the_suite_still_parses():
    source = 'class C:\n    """Only this."""\n'
    result = strip_comments(source, ".py")
    compile(result, "<test>", "exec")
    assert "Only this" not in result


def test_a_string_in_an_expression_is_not_a_docstring():
    source = 'x = ("a"\n     "b")\n'
    assert strip_comments(source, ".py") == source


# ------------------------------------------------------- 3. directives stay

# Removing one of these changes the program, which outranks removing prose.
DIRECTIVES = [
    (".py", "#!/usr/bin/env python3\nx = 1\n"),
    (".py", "# -*- coding: utf-8 -*-\nx = 1\n"),
    (".py", "import os  # noqa: F401\n"),
    (".py", "x = []  # type: list\n"),
    (".py", "if x:  # pragma: no cover\n    pass\n"),
    (".go", "//go:build linux\n\npackage main\n"),
    (".go", "// +build linux\n\npackage main\n"),
    (".go", "//go:embed static\nvar f embed.FS\n"),
    (".ts", "// @ts-expect-error deliberately wrong\nconst x = f();\n"),
    (".ts", "/* eslint-disable no-eval */\nconst x = 1;\n"),
    (".ts", '/// <reference types="node" />\nconst x = 1;\n'),
    (".js", "// eslint-disable-next-line no-param-reassign\nx = 1;\n"),
    (".rs", "#[derive(Debug)]\nstruct S;\n"),
    (".rs", '#[cfg(feature = "tls")]\nfn f() {}\n'),
    (".php", "<?php\n#[Attribute]\nclass A {}\n"),
]


@pytest.mark.parametrize("suffix,source", DIRECTIVES)
def test_a_directive_the_compiler_reads_is_kept(suffix, source):
    assert strip_comments(source, suffix) == source


def test_a_prose_comment_that_merely_contains_a_directive_word_still_goes():
    """`global ` is how eslint spells a directive and how English spells a word.

    The first version matched the needle anywhere in the comment and kept
    `// Apply global SSH key if configured` — a prose comment surviving on one
    member and not the other is the asymmetry this whole file exists to remove.
    """
    source = "// Apply global SSH key if configured\nconst x = 1;\n"
    assert strip_comments(source, ".ts") == "\nconst x = 1;\n"


def test_php_output_outside_the_tags_is_not_code_and_is_left_alone():
    source = "<div>see http://x // not a comment</div>\n<?php\n// gone\n$x = 1;\n"
    assert strip_comments(source, ".php") == (
        "<div>see http://x // not a comment</div>\n<?php\n\n$x = 1;\n")


# ----------------------------------------------------- 4. line count is fixed

ALL_SOURCES = (
    [(SUFFIX[lang], src) for lang, (src, _) in INSIDE_A_STRING.items()]
    + [(SUFFIX[lang], src) for lang, (src, _) in WHOLE_LINE.items()]
    + [(SUFFIX[lang], src) for lang, (src, _) in TRAILING.items()]
    + [(SUFFIX[lang], src) for lang, (src, _) in DOCSTRING.items()]
    + UNTOUCHABLE + DIRECTIVES
)


@pytest.mark.parametrize("suffix,source", ALL_SOURCES)
def test_the_line_count_never_moves(suffix, source):
    """A blank line, not a deleted one.

    Line numbers stay meaningful — and, the reason it is not negotiable, a
    length delta between the two members would be a new free signal of exactly
    the kind the comments were.
    """
    result = strip_comments(source, suffix)
    assert result.count("\n") == source.count("\n")
    assert len(result.splitlines()) == len(source.splitlines())


@pytest.mark.parametrize("suffix,source", ALL_SOURCES)
def test_stripping_twice_is_stripping_once(suffix, source):
    once = strip_comments(source, suffix)
    assert strip_comments(once, suffix) == once


@pytest.mark.parametrize("suffix,source", ALL_SOURCES)
def test_no_supported_language_is_quietly_skipped(suffix, source):
    _, status = strip_comments_report(source, suffix)
    assert status in (STRIPPED, UNCHANGED), status


# ------------------------------------------------- what is refused, out loud


@pytest.mark.parametrize("suffix", sorted(UNSUPPORTED))
def test_a_language_without_a_scanner_says_so_and_changes_nothing(suffix):
    source = "// a comment\ncode\n"
    result, status = strip_comments_report(source, suffix)
    assert result == source
    assert status.startswith("unsupported"), status


def test_a_file_the_scanner_cannot_finish_is_written_through_untouched():
    """Giving up is a result. Guessing is not."""
    source = "/* opened and never closed\nint x = 1;\n"
    result, status = strip_comments_report(source, ".java")
    assert result == source
    assert status.startswith("unsafe"), status


def test_jsx_is_refused_rather_than_guessed_at():
    """`<p>a // b</p>` has a `//` that is neither a string nor code."""
    source = "const a = <Panel>\n  see http://x // here\n</Panel>;\n"
    result, status = strip_comments_report(source, ".tsx")
    assert result == source
    assert status.startswith("unsupported"), status


def test_python_that_stops_parsing_is_reverted_rather_than_shipped():
    """The one language where the result can be checked for free."""
    from strip_comments import _python_regressed

    assert _python_regressed("x = 1\n", "x = 1\n") == ""
    assert _python_regressed("def f():\n    'doc'\n", "def f():\n") != ""


# --------------------------------------------- ruby literals in argument slots


SAVON = (
    "    def define_class_operation(operation)\n"
    "      class_operation_module.module_eval %{\n"
    "        def #{operation_method_name(operation)}(locals = {})\n"
    "          client.call #{operation.inspect}, locals\n"
    "        end\n"
    "      }, __FILE__, __LINE__ - 4\n"
    "    end\n"
)


def test_a_percent_literal_after_a_method_name_is_a_string_not_a_modulo():
    """The corpus case this destroyed.

    `value_next` was decided by a hardcoded list of method names, and a list of
    names is only ever right about the names on it. `module_eval` was not on
    it, so the `%` read as a modulo, the scanner stayed outside the string, and
    the `#{...}` inside it was taken for a comment and deleted — leaving `def`
    with no name and `client.call` with no arguments.

    That is the whole weakness of `rb-mx5j-mp4f-g8jg`: Savon evaluating a WSDL
    operation name as Ruby source. The review reported nothing because there
    was nothing left to report, and the miss was scored against the reviewer.
    """
    result, status = strip_comments_report(SAVON, ".rb")

    assert "#{operation_method_name(operation)}" in result
    assert "#{operation.inspect}" in result
    assert status == UNCHANGED, status


@pytest.mark.parametrize("opener", ["#{name}", "#@ivar", "#$global"])
def test_an_interpolation_read_as_a_comment_refuses_the_file(opener):
    """The guard that catches the next scanner gap, whatever opens it.

    A Ruby comment never begins with an interpolation. Reaching one outside a
    string means the scanner is in the wrong place, and deleting the span would
    delete code — so the file is written through untouched and the harvester
    reports it. Without this the failure above was silent and vouched for.

    All three openers, because Ruby interpolates `#@ivar` and `#$global`
    without braces and a guard that knows one form guards against one bug. It
    earns its keep on its own: over the ruby shipped with this machine it
    catches three files the scanner would otherwise have deleted code from.
    """
    from strip_comments import Untouched, _scan_ruby

    with pytest.raises(Untouched):
        _scan_ruby("x = %z{ " + opener + " }\n")


def test_a_heredoc_after_a_method_name_is_a_heredoc():
    """The same defect as the percent literal, through a different opener, and
    the reason the guard above is not written against `#{` alone.

    `module_eval <<RUBY` is how Ruby metaprogramming reads a body from a
    heredoc. Deciding it is a left shift puts the scanner outside the body, and
    every line of that body then reads as a comment.
    """
    result, status = strip_comments_report(
        "module_eval <<RUBY\n#@generated_source\nRUBY\n", ".rb")
    assert "#@generated_source" in result
    assert status == UNCHANGED, status


def test_a_left_shift_after_a_method_name_is_still_a_left_shift():
    """The floor under the rule above: spacing decides, so a spaced `<<` is an
    operator and the comment after it goes."""
    result, status = strip_comments_report("x = a << b # note\n", ".rb")
    assert "note" not in result
    assert status == STRIPPED, status


def test_a_scanner_returning_overlapping_spans_is_reported_not_raised():
    """Giving up is a result; crashing is not — and this was the one give-up
    path that crashed.

    Overlapping spans mean a scanner is wrong, which is precisely when the
    caller needs a status rather than a traceback: the harvester lists every
    file it could not vouch for, and an exception is not on that list.
    """
    import strip_comments

    original = strip_comments._SCANNERS["ruby"]
    strip_comments._SCANNERS["ruby"] = lambda text: [(0, 5, ""), (2, 7, "")]
    try:
        result, status = strip_comments_report("abcdefghij\n", ".rb")
    finally:
        strip_comments._SCANNERS["ruby"] = original

    assert result == "abcdefghij\n"
    assert status.startswith("unsafe"), status


@pytest.mark.parametrize("source,keep", [
    # A spaced operator stays an operator, both ways round.
    ("x = a % b\ny = \"#{keep}\"\n", "#{keep}"),
    ("x = fmt % [a, b]\ny = \"#{keep}\"\n", "#{keep}"),
    ("x = a / b\ny = \"#{keep}\"\n", "#{keep}"),
    # Glued to a method name it opens a literal, whatever the name.
    ("mod.module_eval %{hi #{name}}\n", "#{name}"),
    ("anything_at_all %{hi #{name}}\n", "#{name}"),
    ("text.sanitize /[a-z]#{x}/\ny = \"#{keep}\"\n", "#{keep}"),
])
def test_the_ruby_rule_is_the_spacing_not_a_list_of_names(source, keep):
    result, _ = strip_comments_report(source, ".rb")
    assert keep in result


def test_a_comment_after_a_method_name_still_goes():
    """The permissive direction has a floor: a `#` that is a comment is one."""
    result, status = strip_comments_report("foo bar  # note\n", ".rb")
    assert "note" not in result
    assert status == STRIPPED, status


# ------------------------------------------------ the chain, not the links


def test_the_harvester_writes_stripped_files_in_both_members(tmp_path):
    """A stripper nobody calls strips nothing.

    Built from a real two-commit repository rather than from stubs, because
    what is being checked is that `build_member` routes every write — the
    change, the baseline, both members — through the stripper. A unit test of
    `strip_comments` cannot fail when that wiring is missing.
    """
    from harvest_pairs import build_member, git_env

    repo = tmp_path / "src"
    repo.mkdir()
    env = git_env(tmp_path)

    def run(*args):
        subprocess.run(("git", "-C", str(repo), *args), check=True,
                       capture_output=True, env=env)

    subprocess.run(("git", "init", "-q", "-b", "main", str(repo)),
                   check=True, capture_output=True, env=env)
    target = repo / "handler.py"
    target.write_text("def run(cmd):\n    os.system(cmd)\n")
    run("add", "-A")
    run("commit", "-qm", "before")
    parent = subprocess.run(("git", "-C", str(repo), "rev-parse", "HEAD"),
                            check=True, capture_output=True, text=True,
                            env=env).stdout.strip()

    # The shape the audit found: the maintainer explains the guard, and the
    # explanation exists only on the side that has the guard.
    target.write_text(
        '"""Command execution helpers."""\n'
        "def run(cmd):\n"
        "    # SECURITY: shell metacharacters reach the shell otherwise\n"
        "    subprocess.run(shlex.split(cmd))  # no shell\n")
    run("add", "-A")
    run("commit", "-qm", "after")
    fix = subprocess.run(("git", "-C", str(repo), "rev-parse", "HEAD"),
                         check=True, capture_output=True, text=True,
                         env=env).stdout.strip()

    case = tmp_path / "case"
    case.mkdir()
    for member in ("safe", "unsafe"):
        build_member(case, member, repo, parent, fix, ["handler.py"], env)

    written = sorted(p for p in case.rglob("*.py") if p.is_file())
    assert len(written) == 4, written
    for path in written:
        text = path.read_text(encoding="utf-8")
        assert "SECURITY" not in text, path
        assert "Command execution helpers" not in text, path
        assert comment_lines(text) == 0, path

    # And the code itself is still there, in the right member, on the right side.
    assert "shlex.split" in (case / "safe" / "change" / "handler.py").read_text()
    assert "os.system" in (case / "unsafe" / "change" / "handler.py").read_text()


def test_a_file_the_harvester_cannot_strip_is_recorded_not_hidden(tmp_path):
    """An unstripped file is a visible flaw; a silent one is a wrong answer."""
    from harvest_pairs import write_source

    notes: list = []
    source = "const a = <Panel>\n  // kept\n</Panel>;\n"
    write_source(tmp_path / "ui.tsx", "ui.tsx", source, notes)
    assert (tmp_path / "ui.tsx").read_text(encoding="utf-8") == source
    assert len(notes) == 1 and "ui.tsx" in notes[0], notes

    notes.clear()
    write_source(tmp_path / "ok.py", "ok.py", "# gone\nx = 1\n", notes)
    assert (tmp_path / "ok.py").read_text(encoding="utf-8") == "\nx = 1\n"
    assert notes == []


# --------------------------------------------------- 5. the corpus property


def _change_prose(member: Path) -> int:
    return sum(comment_lines(path.read_text(encoding="utf-8", errors="replace"))
               for path in sorted((member / "change").rglob("*"))
               if path.is_file())


@pytest.mark.parametrize("corpus", ["corpus-real"])
def test_both_members_of_every_harvested_case_carry_the_same_prose(corpus):
    """The property the audit found violated, checked against the real corpus.

    Not "few comments" — *equal* comments. A case where one side explains
    itself and the other does not is scoreable without reading a line of it,
    and no amount of downstream measurement would ever have said so.
    """
    root = ROOT / corpus
    if not root.is_dir():
        pytest.skip("{} is not present".format(corpus))

    offenders = []
    for manifest in sorted(root.glob("*/case.yml")):
        case = manifest.parent
        safe, unsafe = _change_prose(case / "safe"), _change_prose(case / "unsafe")
        if safe != unsafe:
            offenders.append("{}: safe {} comment line(s), unsafe {}".format(
                case.name, safe, unsafe))
    assert not offenders, offenders
