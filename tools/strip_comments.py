#!/usr/bin/env python3
"""Remove prose comments from harvested source, on both members equally.

An audit of `corpus-real/` found the whole corpus gameable by a rule that reads
no code at all: *the member whose `change/` carries more comment lines is the
safe one*. It scored 48/48. The cause is structural, not accidental — the cases
are harvested from real security fixes, so the maintainer's explanation of the
guard lands only on the side that has the guard. Some were literal answer keys:
a safe-only `(CWE-639 / CWE-862)`, eleven safe-only `// SECURITY:` markers.

Deleting the comments from the safe side would be tampering with the evidence.
Deleting them from *both* sides is the only symmetric answer, so that is what
this does: every file written into a case, in either member, in `change/` and
in the baseline alike, arrives with its comments already gone.

## The rule that outranks the others

**Never change what the code does.** A stripper that mistakes the `//` inside
`"https://x"` for a comment has destroyed the case — the file no longer
compiles, or worse, still compiles and no longer contains the vulnerability the
manifest claims. So every scanner here tracks string literals, and every one of
them may give up: `Untouched` propagates out as a status, the file is written
exactly as it came, and the harvester prints which file and why. A case with
one unstripped file is a case with a flaw someone can see. A case with a
silently mangled file is a wrong answer nobody can see.

## What is kept

Comments the compiler reads are not prose, and removing them changes the
program: `//go:embed`, `// +build`, `# type:`, `# noqa`, `/* eslint-disable */`,
`// @ts-ignore`, shebangs, encoding declarations. Rust's `#[...]` and PHP 8's
`#[...]` are attributes rather than comments and are never candidates at all —
the PHP scanner in particular has to tell `#[Attribute]` from `# comment`.

## Line count is preserved

A stripped line becomes an empty line rather than disappearing. Two reasons:
line numbers in a manifest or a finding stay meaningful, and — the reason that
matters here — a length delta between the two members would be exactly the same
kind of free signal the comments were.
"""

from __future__ import annotations

import re
import tokenize
from io import StringIO
from typing import List, Optional, Tuple

# A span of text to remove: (start, end, replacement). The replacement is
# almost always empty; Python docstrings are the exception, because a suite
# whose only statement was the docstring needs *something* left behind.
Span = Tuple[int, int, str]

# Suffix → the scanner to use. Mirrors EXTENSION_LANGUAGE in harvest_pairs.py,
# plus the two extras the harvested corpus actually contains: Ruby signature
# files and Vue single-file components.
SUFFIX_LANGUAGE = {
    ".py": "python", ".pyi": "python",
    ".go": "go",
    ".java": "java",
    ".php": "php", ".phtml": "php", ".inc": "php",
    ".rb": "ruby", ".rbs": "ruby", ".rake": "ruby",
    ".rs": "rust",
    ".ts": "typescript", ".mts": "typescript", ".cts": "typescript",
    ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".cs": "csharp",
    ".vue": "vue",
}

# Deliberately not handled, and said out loud rather than half-attempted:
#
#   .tsx/.jsx  JSX text is not a string literal and not code — `<p>a // b</p>`
#              has a `//` that is neither. A scanner that gets this wrong eats
#              the rest of the line. Plain .ts/.js files that turn out to
#              contain JSX are refused by the same check, at scan time.
#   .kt/.scala in EXTENSION_LANGUAGE, out of scope here; Scala's string
#              interpolation and Kotlin's nested templates each need their own
#              scanner and neither language appears in the harvested corpus.
UNSUPPORTED = {
    ".tsx": "JSX text is not a string literal; a wrong guess eats a line of code",
    ".jsx": "JSX text is not a string literal; a wrong guess eats a line of code",
    ".kt": "no scanner written for Kotlin string templates",
    ".scala": "no scanner written for Scala interpolation",
}

STRIPPED = "stripped"
UNCHANGED = "unchanged"          # supported, but there was nothing to remove


class Untouched(Exception):
    """The scanner is not sure, so the file is written exactly as it came."""


# --------------------------------------------------------------- public API


def strip_comments(text: str, suffix: str) -> str:
    """Comments removed, line count unchanged. Unsure means unchanged."""
    return strip_comments_report(text, suffix)[0]


def strip_comments_report(text: str, suffix: str) -> Tuple[str, str]:
    """`(text, status)`. Status is `stripped`, `unchanged`, or why not."""
    suffix = suffix.lower()
    if suffix in UNSUPPORTED:
        return text, "unsupported {}: {}".format(suffix, UNSUPPORTED[suffix])
    scanner = _SCANNERS.get(SUFFIX_LANGUAGE.get(suffix, ""))
    if scanner is None:
        return text, "unsupported {}: no scanner".format(suffix or "(no suffix)")
    try:
        spans = scanner(text)
    except Untouched as exc:
        return text, "unsafe {}: {}".format(suffix, exc)
    except RecursionError:
        return text, "unsafe {}: nesting too deep to scan".format(suffix)
    if not spans:
        return text, UNCHANGED
    out = _apply(text, spans)
    if out.count("\n") != text.count("\n"):  # belt and braces; must never fire
        return text, "unsafe {}: line count changed".format(suffix)
    if SUFFIX_LANGUAGE[suffix] == "python":
        broke = _python_regressed(text, out)
        if broke:
            return text, "unsafe {}: {}".format(suffix, broke)
    return out, STRIPPED


def comment_lines(text: str) -> int:
    """The audit's own measure: lines that *look* like a comment.

    Deliberately dumb and language-blind, because the adversary it models is
    dumb and language-blind. Used by the corpus symmetry test, so it must not
    share an implementation with the stripper — a check written from the same
    premise as the code it checks tests nothing.

    Dumb, but not wrong. A `#` counts only when a space follows it, which is
    how prose is written and is not how `#[Attribute]`, `#if`, `#region`,
    `#ECEBEF` or a CSS `#id {` are written. A leading `*` counts only as `* `
    or `*/`, which is how a block comment continues, and not as `**kwargs`,
    `*deref` or the `*,` of a keyword-only signature. A leading `--` is dropped
    altogether: in this corpus it is a CSS custom property far more often than
    it is a comment.
    """
    return sum(1 for line in text.splitlines() if _LOOKS_LIKE_COMMENT.match(line))


_LOOKS_LIKE_COMMENT = re.compile(
    r"""^\s*(\#[ \t#]|//|/\*|\*([ \t/]|$)|<!--|\"\"\"|'''|=begin\b)""")


# ------------------------------------------------------------- the renderer


def _apply(text: str, spans: List[Span]) -> str:
    """Blank the spans, keeping every newline that was inside them."""
    spans = sorted(spans)
    pieces: List[str] = []
    pos = 0
    for start, end, replacement in spans:
        if start < pos:                       # overlapping spans: a scanner bug
            raise Untouched("overlapping spans at {}".format(start))
        pieces.append(text[pos:start])
        pieces.append(replacement)
        pieces.append("\n" * text.count("\n", start, end))
        pos = end
    pieces.append(text[pos:])

    # Line k of the output is line k of the input, which is the whole point of
    # emitting the newlines above, and is what lets these two sets be computed
    # against the original text.
    blanked, tidy = set(), set()
    for start, end, _ in spans:
        first = text.count("\n", 0, start)
        last = text.count("\n", 0, end)
        blanked.update(range(first, last + 1))
        # Only a span that runs to the end of its line may take the trailing
        # whitespace with it. A block comment ending mid-line leaves whatever
        # follows alone, up to and including significant trailing spaces inside
        # a string literal that starts on that line.
        if end >= len(text) or text[end] == "\n":
            tidy.add(last)

    lines = "".join(pieces).split("\n")
    for k in blanked:
        if k < len(lines) and (k in tidy or not lines[k].strip()):
            lines[k] = lines[k].rstrip()
    return "\n".join(lines)


def _python_regressed(before: str, after: str) -> str:
    """Python is the one language where the result can be checked for free."""
    try:
        compile(before, "<before>", "exec")
    except (SyntaxError, ValueError):
        return ""                      # it did not parse before either
    try:
        compile(after, "<after>", "exec")
    except (SyntaxError, ValueError) as exc:
        return "stripping broke the parse ({})".format(str(exc)[:60])
    return ""


# ------------------------------------------------------------ small helpers


def _quoted(text: str, i: int, quote: str, *, newline_ok: bool = False) -> int:
    """`text[i]` opens the string. Returns the index just past its close."""
    n = len(text)
    j = i + 1
    while j < n:
        c = text[j]
        if c == "\\":
            j += 2
            continue
        if c == "\n" and not newline_ok:
            raise Untouched("newline inside a {} string".format(quote))
        if c == quote:
            return j + 1
        j += 1
    raise Untouched("unterminated {} string".format(quote))


def _line_end(text: str, i: int) -> int:
    j = text.find("\n", i)
    return len(text) if j < 0 else j


def _block_end(text: str, i: int, opener: str = "/*", closer: str = "*/") -> int:
    j = text.find(closer, i + len(opener))
    if j < 0:
        raise Untouched("unterminated block comment")
    return j + len(closer)


def _at_line_start(text: str, i: int) -> bool:
    return i == 0 or text[i - 1] == "\n"


def _keeps(comment: str, needles: Tuple[str, ...]) -> bool:
    """Is this comment a directive rather than prose?

    Anchored at the head of the comment body, not searched anywhere inside it.
    The unanchored version of this kept `// Apply global SSH key if configured`
    because `global ` is how eslint's `/* global foo */` is spelled — a prose
    comment surviving on one member and not the other is the exact asymmetry
    the whole exercise is here to remove.
    """
    body = comment.lstrip("/*!#").lstrip().lower()
    return body.startswith(needles)


# ------------------------------------------------------------------ python


# `type:` and friends are read by tooling; a `noqa` or a `pragma: no cover`
# changes what a build reports. A shebang decides which interpreter runs.
_PY_DIRECTIVE = re.compile(
    r"^#\s*(type:|noqa|pragma|pylint:|mypy:|pyright:|pytype:|flake8:|ruff:"
    r"|isort:|fmt:|yapf|black|nosec|nosemgrep|coding[:=]|-\*-|codespell)",
    re.IGNORECASE)


def _scan_python(text: str) -> List[Span]:
    """Uses the real tokenizer, so string literals cost nothing to get right.

    Docstrings go too. They are replaced by `''` rather than deleted: `def f():`
    whose body was only a docstring must keep a statement, and a *string*
    statement specifically — `pass` in the first position of a module would make
    a following `from __future__ import ...` a syntax error.
    """
    try:
        tokens = list(tokenize.generate_tokens(StringIO(text).readline))
    except (tokenize.TokenError, IndentationError, SyntaxError) as exc:
        raise Untouched("tokenizer: {}".format(str(exc)[:60])) from None

    starts = _line_offsets(text)

    def offset(pos: Tuple[int, int]) -> int:
        row, col = pos
        return starts[row - 1] + col

    ignorable = {tokenize.COMMENT, tokenize.NL}
    opens_statement = {tokenize.NEWLINE, tokenize.INDENT, tokenize.DEDENT,
                       tokenize.ENCODING, tokenize.NL}

    spans: List[Span] = []
    previous = tokenize.NEWLINE          # the file itself opens a statement
    for index, token in enumerate(tokens):
        if token.type == tokenize.COMMENT:
            if not _PY_DIRECTIVE.match(token.string.strip()) and not (
                    token.start[0] == 1 and token.string.startswith("#!")):
                spans.append((offset(token.start), offset(token.end), ""))
            continue
        if token.type == tokenize.NL:
            continue
        if token.type == tokenize.STRING and previous in opens_statement:
            following = tokenize.NEWLINE
            for nxt in tokens[index + 1:]:
                if nxt.type not in ignorable:
                    following = nxt.type
                    break
            prefix = token.string[:3].lower()
            # An f-string statement can call something. Nothing else here can.
            if following in (tokenize.NEWLINE, tokenize.ENDMARKER) and "f" not in prefix:
                spans.append((offset(token.start), offset(token.end), "''"))
        previous = token.type
    return spans


def _line_offsets(text: str) -> List[int]:
    starts, pos = [0], 0
    while True:
        pos = text.find("\n", pos)
        if pos < 0:
            break
        pos += 1
        starts.append(pos)
    return starts


# ---------------------------------------------------------------------- go


# `//go:` is read by the compiler and by go:generate; `// +build` is the old
# build-constraint syntax and still honoured. Dropping either changes the build.
_GO_KEEP = ("//go:", "//line ", "//export ", "//nolint", "//sys ", "//extern ")


def _scan_go(text: str) -> List[Span]:
    spans: List[Span] = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c == "/" and text.startswith("//", i):
            end = _line_end(text, i)
            comment = text[i:end]
            if not (comment.startswith(_GO_KEEP)
                    or comment.replace(" ", "").startswith("//+build")):
                spans.append((i, end, ""))
            i = end
        elif c == "/" and text.startswith("/*", i):
            end = _block_end(text, i)
            spans.append((i, end, ""))
            i = end
        elif c == "`":
            j = text.find("`", i + 1)
            if j < 0:
                raise Untouched("unterminated raw string")
            i = j + 1
        elif c in "\"'":
            i = _quoted(text, i, c)
        else:
            i += 1
    return spans


# -------------------------------------------------------------------- java


def _scan_java(text: str) -> List[Span]:
    spans: List[Span] = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if text.startswith("//", i):
            end = _line_end(text, i)
            spans.append((i, end, ""))
            i = end
        elif text.startswith("/*", i):
            end = _block_end(text, i)
            spans.append((i, end, ""))
            i = end
        elif text.startswith('"""', i):
            j = text.find('"""', i + 3)
            while j > 0 and text[j - 1] == "\\":
                j = text.find('"""', j + 1)
            if j < 0:
                raise Untouched("unterminated text block")
            i = j + 3
        elif c in "\"'":
            i = _quoted(text, i, c)
        else:
            i += 1
    return spans


# -------------------------------------------------------------------- rust


# A char literal, as opposed to a lifetime: `'a'`, `'\n'`, `'\u{1f600}'`. A
# `'a` with no closing quote is a lifetime and must be walked past rather than
# scanned as the opening of a string.
_RUST_CHAR_RE = re.compile(r"'(?:\\(?:x[0-9a-fA-F]{2}|u\{[0-9a-fA-F_]{1,6}\}"
                           r"|[nrt0\\'\"])|[^\\'\n])'")
_RUST_RAW = re.compile(r"(?:b|c)?r(#*)\"")


def _scan_rust(text: str) -> List[Span]:
    spans: List[Span] = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if text.startswith("//", i):
            end = _line_end(text, i)
            spans.append((i, end, ""))          # `///` and `//!` included
            i = end
        elif text.startswith("/*", i):
            depth, j = 1, i + 2                 # Rust block comments nest
            while j < n and depth:
                if text.startswith("/*", j):
                    depth += 1
                    j += 2
                elif text.startswith("*/", j):
                    depth -= 1
                    j += 2
                else:
                    j += 1
            if depth:
                raise Untouched("unterminated block comment")
            spans.append((i, j, ""))
            i = j
        elif c in "rbc" and _RUST_RAW.match(text, i):
            match = _RUST_RAW.match(text, i)
            closer = '"' + match.group(1)
            j = text.find(closer, match.end())
            if j < 0:
                raise Untouched("unterminated raw string")
            i = j + len(closer)
        elif c == '"':
            i = _quoted(text, i, '"', newline_ok=True)
        elif c == "'":
            match = _RUST_CHAR_RE.match(text, i)
            i = match.end() if match else i + 1  # otherwise a lifetime
        else:
            i += 1
    return spans


# ------------------------------------------------------------- javascript


# Read by a compiler or a linter, so not prose: TypeScript's triple-slash
# references and `@ts-` pragmas, eslint's inline configuration, source maps.
_JS_KEEP = ("<reference", "@ts-", "eslint", "prettier-ignore", "istanbul ",
            "c8 ignore", "@jsx", "@flow", "sourcemappingurl", "jshint",
            "globals ", "global ", "webpack", "@vite-ignore", "@__pure__",
            "v8 ignore", "biome-ignore", "deno-lint")
# `@license` and `@preserve` are deliberately absent: a licence header is prose,
# and keeping it would leave prose behind for no compiler's benefit.

_JS_REGEX_KEYWORDS = {
    "return", "typeof", "instanceof", "in", "of", "new", "delete", "void",
    "throw", "case", "do", "else", "yield", "await",
}

# One `<Tag ...>` or `</Tag>` at the head of a line is enough: JSX text is not
# a string, so `//` in it is not a comment and not code either.
_JSX = re.compile(r"^[ \t]*(?:return\s*\(\s*)?</?[A-Z][\w.]*[\s/>]"
                  r"|^[ \t]*</[a-z][\w.-]*>", re.MULTILINE)


def _scan_javascript(text: str) -> List[Span]:
    if _JSX.search(text):
        raise Untouched("file contains JSX")
    return _scan_js_region(text, 0, len(text))


def _scan_js_region(text: str, start: int, stop: int) -> List[Span]:
    spans: List[Span] = []
    i = start
    kind = "start"          # what the previous significant token was
    word = ""
    while i < stop:
        c = text[i]
        if c in " \t\r\n":
            i += 1
            continue
        if text.startswith("//", i):
            end = min(_line_end(text, i), stop)
            if not _keeps(text[i:end], _JS_KEEP):
                spans.append((i, end, ""))
            i = end
            continue
        if text.startswith("/*", i):
            end = _block_end(text, i)
            if end > stop:
                raise Untouched("block comment crosses the region")
            if not _keeps(text[i:end], _JS_KEEP):
                spans.append((i, end, ""))
            i = end
            continue
        if c == "/" and (kind in ("start", "op")
                         or (kind == "word" and word in _JS_REGEX_KEYWORDS)):
            end = _js_regex_end(text, i, stop)
            if end is None:                     # it was division after all
                i += 1
                kind, word = "op", ""
                continue
            i = end
            kind, word = "value", ""
            continue
        if c in "\"'":
            i = _quoted(text, i, c)
            kind, word = "value", ""
            continue
        if c == "`":
            i = _js_template_end(text, i, stop)
            kind, word = "value", ""
            continue
        if c.isalnum() or c in "_$":
            j = i
            while j < stop and (text[j].isalnum() or text[j] in "_$"):
                j += 1
            word, kind = text[i:j], "word"
            i = j
            continue
        kind = "value" if c in ")]}" else "op"
        word = ""
        i += 1
    return spans


def _js_regex_end(text: str, i: int, stop: int) -> Optional[int]:
    """End of a regex literal, or None if this `/` was a division sign.

    A regex literal cannot contain a raw newline, so "did not close on this
    line" is a reliable way to undo a wrong guess instead of eating the file.
    """
    j, klass = i + 1, False
    while j < stop:
        c = text[j]
        if c == "\\":
            j += 2
            continue
        if c == "\n":
            return None
        if c == "[":
            klass = True
        elif c == "]":
            klass = False
        elif c == "/" and not klass:
            j += 1
            while j < stop and text[j].isalpha():
                j += 1
            return j
        j += 1
    return None


def _js_template_end(text: str, i: int, stop: int) -> int:
    j = i + 1
    while j < stop:
        c = text[j]
        if c == "\\":
            j += 2
            continue
        if c == "`":
            return j + 1
        if text.startswith("${", j):
            j = _js_template_expr(text, j + 1, stop)
            continue
        j += 1
    raise Untouched("unterminated template literal")


def _js_template_expr(text: str, i: int, stop: int) -> int:
    """`text[i]` is the `{` of a `${...}`; returns the index past its `}`."""
    depth, j = 0, i
    while j < stop:
        c = text[j]
        if c in "\"'":
            j = _quoted(text, j, c)
            continue
        if c == "`":
            j = _js_template_end(text, j, stop)
            continue
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return j + 1
        j += 1
    raise Untouched("unterminated template substitution")


# ------------------------------------------------------------------ csharp


_CS_RAW = re.compile(r'"{3,}')


def _scan_csharp(text: str) -> List[Span]:
    spans: List[Span] = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if text.startswith("//", i):
            end = _line_end(text, i)
            spans.append((i, end, ""))          # `///` doc comments included
            i = end
        elif text.startswith("/*", i):
            end = _block_end(text, i)
            spans.append((i, end, ""))
            i = end
        elif c in "@$" and _cs_prefixed(text, i):
            i = _cs_prefixed_end(text, i)
        elif _CS_RAW.match(text, i):
            fence = _CS_RAW.match(text, i).group(0)
            j = text.find(fence, i + len(fence))
            if j < 0:
                raise Untouched("unterminated raw string")
            i = j + len(fence)
        elif c == '"':
            i = _quoted(text, i, '"')
        elif c == "'":
            i = _quoted(text, i, "'")
        else:
            i += 1
    return spans


def _cs_prefixed(text: str, i: int) -> bool:
    prefix = text[i:i + 2]
    return prefix in ('@"', '$"') or text[i:i + 3] in ('$@"', '@$"')


def _cs_prefixed_end(text: str, i: int) -> int:
    """`@"..."`, `$"..."` and the two combinations of them."""
    prefix = ""
    while text[i] in "@$":
        prefix += text[i]
        i += 1
    verbatim = "@" in prefix
    j, n = i + 1, len(text)
    while j < n:
        c = text[j]
        if verbatim:
            if c == '"':
                if text[j:j + 2] == '""':       # a doubled quote, not the end
                    j += 2
                    continue
                return j + 1
            j += 1
            continue
        if c == "\\":
            j += 2
            continue
        if c == "\n":
            raise Untouched("newline in an interpolated string")
        if c == '"':
            return j + 1
        j += 1
    raise Untouched("unterminated string")


# --------------------------------------------------------------------- php


_PHP_OPEN = re.compile(r"<\?(?:php\b|=)?", re.IGNORECASE)
_PHP_HEREDOC = re.compile(r"<<<[ \t]*(?:([A-Za-z_]\w*)|\"([A-Za-z_]\w*)\""
                          r"|'([A-Za-z_]\w*)')\r?\n")


def _scan_php(text: str) -> List[Span]:
    """Outside `<?php` the file is literal output — nothing there is a comment.

    `#` opens a comment, except `#[`, which since PHP 8 opens an attribute and
    is read by the runtime.
    """
    spans: List[Span] = []
    i, n = 0, len(text)
    in_php = False
    while i < n:
        if not in_php:
            match = _PHP_OPEN.search(text, i)
            if not match:
                break
            i = match.end()
            in_php = True
            continue
        c = text[i]
        if text.startswith("?>", i):
            in_php = False
            i += 2
        elif text.startswith("//", i) or (c == "#" and not text.startswith("#[", i)):
            end = min(_line_end(text, i), _php_close(text, i))
            spans.append((i, end, ""))
            i = end
        elif text.startswith("/*", i):
            end = _block_end(text, i)
            spans.append((i, end, ""))
            i = end
        elif text.startswith("<<<", i):
            match = _PHP_HEREDOC.match(text, i)
            if not match:
                raise Untouched("unrecognised heredoc opener")
            label = match.group(1) or match.group(2) or match.group(3)
            closer = re.compile(r"^[ \t]*" + re.escape(label) + r"\b", re.MULTILINE)
            found = closer.search(text, match.end())
            if not found:
                raise Untouched("unterminated heredoc {}".format(label))
            i = found.end()
        elif c in "\"'`":
            i = _quoted(text, i, c, newline_ok=(c != "'"))
        else:
            i += 1
    return spans


def _php_close(text: str, i: int) -> int:
    """A `?>` ends a one-line comment as surely as a newline does."""
    j = text.find("?>", i)
    return len(text) if j < 0 else j


# -------------------------------------------------------------------- ruby


_RB_HEREDOC = re.compile(r"<<([~-])?(?:([A-Za-z_]\w*)|\"([^\"\n]+)\"|'([^'\n]+)')")
_RB_PERCENT = re.compile(r"%([qQwWiIrsx]?)([^\sA-Za-z0-9])")
_RB_PAIRS = {"(": ")", "[": "]", "{": "}", "<": ">"}
# Words after which a `/`, `%` or `?` opens a literal rather than continuing an
# expression. `end` is deliberately absent: `end / 2` is a division.
_RB_OPENERS = {
    "and", "or", "not", "if", "elsif", "unless", "while", "until", "when",
    "case", "then", "do", "return", "yield", "in", "begin", "ensure", "rescue",
    "else", "raise", "puts", "print", "match", "split", "gsub", "sub", "scan",
    "grep", "select", "reject", "assert", "expect", "next", "break",
}


def _scan_ruby(text: str) -> List[Span]:
    """The one with no borrowed tokenizer, so the one that gives up most.

    Heredocs, `%w[]` literals, regex literals and `?c` char literals all hinge
    on whether the parser is expecting an operator or a value, which is tracked
    here as `value_next`. Anything that does not resolve raises and the file is
    written through untouched.
    """
    spans: List[Span] = []
    i, n = 0, len(text)
    value_next = True
    pending: List[Tuple[bool, str]] = []
    while i < n:
        c = text[i]
        if c == "\n":
            i += 1
            if pending:
                i = _rb_heredoc_bodies(text, i, pending)
                pending = []
            value_next = True
            continue
        if c in " \t\r":
            i += 1
            continue
        if c == "#":
            end = _line_end(text, i)
            spans.append((i, end, ""))
            i = end
            continue
        if _at_line_start(text, i) and text.startswith("=begin", i):
            match = re.compile(r"^=end.*$", re.MULTILINE).search(text, i)
            if not match:
                raise Untouched("=begin with no =end")
            spans.append((i, match.end(), ""))
            i = match.end()
            continue
        if c in "\"'`":
            i = _rb_string(text, i, c)
            value_next = False
            continue
        if text.startswith("<<", i):
            opened = _rb_heredoc_open(text, i, value_next)
            if opened:
                i, marker = opened
                pending.append(marker)
                value_next = False
                continue
        if c == "/" and value_next:
            end = _rb_regex_end(text, i)
            if end is None:
                i += 1
                value_next = True
                continue
            i = end
            value_next = False
            continue
        if c == "%" and value_next:
            match = _RB_PERCENT.match(text, i)
            if match:
                i = _rb_percent_end(text, match)
                value_next = False
                continue
        if c == "?" and value_next and i + 1 < n and not text[i + 1].isspace():
            match = re.compile(r"\?(?:\\\w+|\S)(?![\w])").match(text, i)
            if match:
                i = match.end()
                value_next = False
                continue
        if c == ":" and i + 1 < n and text[i + 1] in "\"'":
            i = _rb_string(text, i + 1, text[i + 1])   # a quoted symbol
            value_next = False
            continue
        if c == "$" and i + 1 < n and not (text[i + 1].isalnum() or text[i + 1] == "_"):
            i += 2                                     # $', $" and friends
            value_next = False
            continue
        if c.isalnum() or c in "_@:":
            j = i
            while j < n and (text[j].isalnum() or text[j] in "_@:?!"):
                j += 1
            word = text[i:j].lstrip("@:")
            value_next = word in _RB_OPENERS
            i = j
            continue
        value_next = c not in ")]}"
        i += 1
    return spans


def _rb_string(text: str, i: int, quote: str) -> int:
    """Single quotes are literal; double quotes and backticks interpolate."""
    if quote == "'":
        return _quoted(text, i, "'", newline_ok=True)
    n = len(text)
    j = i + 1
    while j < n:
        c = text[j]
        if c == "\\":
            j += 2
            continue
        if c == quote:
            return j + 1
        if text.startswith("#{", j):
            j = _rb_interpolation(text, j + 1)
            continue
        j += 1
    raise Untouched("unterminated {} string".format(quote))


def _rb_interpolation(text: str, i: int) -> int:
    depth, j, n = 0, i, len(text)
    while j < n:
        c = text[j]
        if c in "\"'`":
            j = _rb_string(text, j, c)
            continue
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return j + 1
        j += 1
    raise Untouched("unterminated interpolation")


def _rb_heredoc_open(text: str, i: int, value_next: bool):
    match = _RB_HEREDOC.match(text, i)
    if not match:
        return None
    squiggly, bare = match.group(1), match.group(2)
    label = match.group(2) or match.group(3) or match.group(4)
    # `a <<B` is a left shift unless the label is shouted or the form is
    # squiggly/quoted. Ruby itself uses much the same rule of thumb.
    if bare and not squiggly and not (value_next and bare.isupper()):
        return None
    return match.end(), (squiggly is not None, label)


def _rb_heredoc_bodies(text: str, i: int, pending: List[Tuple[bool, str]]) -> int:
    for indented, label in pending:
        pattern = r"^[ \t]*" + re.escape(label) + r"[ \t]*$" if indented \
            else r"^" + re.escape(label) + r"[ \t]*$"
        match = re.compile(pattern, re.MULTILINE).search(text, i)
        if not match:
            raise Untouched("unterminated heredoc {}".format(label))
        i = match.end()
        if i < len(text) and text[i] == "\n":
            i += 1
    return i


def _rb_regex_end(text: str, i: int) -> Optional[int]:
    j, klass, n = i + 1, False, len(text)
    while j < n:
        c = text[j]
        if c == "\\":
            j += 2
            continue
        if c == "\n":
            return None                    # do not let a division eat the file
        if c == "[":
            klass = True
        elif c == "]":
            klass = False
        elif c == "/" and not klass:
            j += 1
            while j < n and text[j] in "imxounse":
                j += 1
            return j
        j += 1
    return None


def _rb_percent_end(text: str, match) -> int:
    opener = match.group(2)
    closer = _RB_PAIRS.get(opener, opener)
    nests = opener in _RB_PAIRS
    depth, j, n = 1, match.end(), len(text)
    while j < n:
        c = text[j]
        if c == "\\":
            j += 2
            continue
        if nests and c == opener:
            depth += 1
        elif c == closer:
            depth -= 1
            if depth == 0:
                return j + 1
        j += 1
    raise Untouched("unterminated %{} literal".format(opener))


# --------------------------------------------------------------------- vue


_VUE_BLOCK = re.compile(r"<(script|style)\b[^>]*>", re.IGNORECASE)
_VUE_HTML_COMMENT = re.compile(r"<!--.*?-->", re.DOTALL)


def _scan_vue(text: str) -> List[Span]:
    """A single-file component is three languages in one file.

    The `<template>` is markup, where the comment is `<!-- -->`; `<script>` is
    JavaScript or TypeScript; `<style>` is CSS, where it is `/* */`. Each is
    scanned as itself, and nothing outside a known block is touched.
    """
    spans: List[Span] = []
    regions: List[Tuple[int, int]] = []
    i = 0
    while True:
        match = _VUE_BLOCK.search(text, i)
        if not match:
            break
        kind = match.group(1).lower()
        closer = re.compile(r"</{}\s*>".format(kind), re.IGNORECASE)
        found = closer.search(text, match.end())
        if not found:
            raise Untouched("unclosed <{}>".format(kind))
        start, stop = match.end(), found.start()
        regions.append((match.start(), found.end()))
        if kind == "script":
            body = text[start:stop]
            if _JSX.search(body):
                raise Untouched("<script> contains JSX")
            spans.extend(_scan_js_region(text, start, stop))
        else:
            spans.extend(_scan_style(text, start, stop))
        i = found.end()

    for match in _VUE_HTML_COMMENT.finditer(text):
        if not any(start <= match.start() < stop for start, stop in regions):
            spans.append((match.start(), match.end(), ""))
    return spans


def _scan_style(text: str, start: int, stop: int) -> List[Span]:
    """CSS `/* */`, plus the SCSS `//` that Vue components are full of.

    A `//` counts only at the head of a line or straight after `;`, `{` or `}`.
    Anywhere else in a stylesheet the likeliest `//` by far is the one in
    `url(https://…)`, and CSS has no string state worth tracking to tell them
    apart.
    """
    spans: List[Span] = []
    i = start
    while i < stop:
        if text.startswith("/*", i):
            end = _block_end(text, i)
            if end > stop:
                raise Untouched("style comment crosses the block")
            spans.append((i, end, ""))
            i = end
            continue
        if text.startswith("//", i):
            before = text[:i].rstrip(" \t")
            if before.endswith(("\n", ";", "{", "}")) or not before:
                end = min(_line_end(text, i), stop)
                spans.append((i, end, ""))
                i = end
                continue
        i += 1
    return spans


_SCANNERS = {
    "python": _scan_python,
    "go": _scan_go,
    "java": _scan_java,
    "php": _scan_php,
    "ruby": _scan_ruby,
    "rust": _scan_rust,
    "typescript": _scan_javascript,
    "javascript": _scan_javascript,
    "csharp": _scan_csharp,
    "vue": _scan_vue,
}
