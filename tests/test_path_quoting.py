"""One accented character in a file name, and the gate stopped working.

Git quotes any path containing a byte above 0x7f, and that default is on. The
changed-file list escaped it by using the NUL-separated form, where quoting is
disabled — but the changed-line map is built from a *plain* diff, so
`src/café.py` arrived as the literal string

    "b/src/caf\\303\\251.py"

and was stored under a key nothing could look up. `attribution()` then found
the file in neither the additions nor the deletions and returned "", which is
how a weakness that was *already there* is recorded. `in_changed_lines` went
false, and the gate skips a pre-existing finding by default.

So: put the vulnerable code in a file with an accent in its name, and a
confirmed critical finding stops blocking the merge. No injection, no model
cooperation, one character in a path.

Two of the controls above it fell with it. The removed-control rule keys off
`attributed_by == "deleted"`, so deleting a guard in such a file no longer
blocked regardless of severity; and both prompts were told, in as many words,
that the code "already existed" — so the model reasoned from a false premise
too.

The fix is `core.quotePath=false` in the git environment, rather than a decoder
at the one call site: the next thing parsed out of a textual diff will not
remember to ask.
"""

from __future__ import annotations

import subprocess

import pytest

from security_agent.workspace import Workspace

# Latin-1 supplement, a different Latin script, Cyrillic, and CJK — each one
# only needs a byte above 0x7f to trigger the quoting.
#
# These four are **test data, not prose**, and the repository's English-only
# rule exempts them by name: the test proves git quoting survives a path with
# bytes above 0x7f, and a name spelled in ASCII proves nothing. A sweep once
# swapped the Cyrillic one for Greek to satisfy the rule — which kept the
# non-ASCII the rule permits and lost the specific string the test was written
# against, for no gain. Do not translate, transliterate, or substitute another
# alphabet for any of them.
AWKWARD = (
    # Bytes above 0x7f — the case `core.quotePath=false` covers.
    "café.py", "naïve.go", "плащане.py", "決済.rb",
    # And the case it does not. Git's documentation: double-quote, backslash
    # and control characters are escaped *regardless of the setting*. All three
    # are legal in a path on Linux, and each one was still arriving quoted
    # after the first fix — found by this agent reviewing that fix.
    "report\\v2.py", 'quote".py', "tab\there.py",
)


@pytest.fixture
def repo(tmp_path):
    """A base commit and a change, across names git would quote."""
    root = tmp_path / "repo"
    (root / "src").mkdir(parents=True)

    def git(*args):
        subprocess.run(["git", "-C", str(root), *args], check=True,
                       capture_output=True)

    subprocess.run(["git", "init", "-q", str(root)], check=True, capture_output=True)
    git("config", "user.email", "t@example.com")
    git("config", "user.name", "T")
    for name in (*AWKWARD, "plain.py"):
        (root / "src" / name).write_text("VALUE = 1\n", encoding="utf-8")
    git("add", "-A")
    git("commit", "-qm", "base")
    base = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"],
                          capture_output=True, text=True, check=True).stdout.strip()

    for name in (*AWKWARD, "plain.py"):
        (root / "src" / name).write_text(
            'VALUE = db.execute("SELECT " + user_id)\n', encoding="utf-8")
    git("add", "-A")
    git("commit", "-qm", "change")
    return Workspace(root=root, diff_base=base, diff_head="HEAD")


def test_the_two_views_of_one_change_name_the_same_files(repo):
    """The assertion that fails on the unfixed code.

    `changed_files` uses the NUL-separated form, where git does not quote;
    `changed_line_map` parses a plain diff, where by default it does. The two
    disagreeing is the whole defect, and neither one alone reveals it.
    """
    changed = sorted(path for path, _ in repo.changed_files())
    attributed = sorted(repo.changed_line_map().files())

    assert changed == attributed


@pytest.mark.parametrize("name", AWKWARD)
def test_a_quoted_name_never_reaches_a_caller(repo, name):
    """Named per script so a failure says which one, and so a fix that handles
    Latin-1 and not Cyrillic cannot pass."""
    keys = repo.changed_line_map().files()

    assert "src/" + name in keys
    assert not any(key.startswith('"') for key in keys)


@pytest.mark.parametrize("name", AWKWARD)
def test_a_change_in_such_a_file_is_attributed_to_the_change(repo, name):
    """The step that decided the gate. `""` means "already there", and a
    pre-existing finding does not block by default — so this returning empty
    was a confirmed critical passing the merge."""
    from security_agent.evidence import attribution

    where = attribution("src/" + name, 1, 1, repo.changed_line_map())

    assert where == "added"


def test_an_ordinary_name_was_never_affected(repo):
    """The control. Every ASCII path worked, which is why this survived: a
    repository of ASCII names shows nothing at all."""
    from security_agent.evidence import attribution

    assert attribution("src/plain.py", 1, 1, repo.changed_line_map()) == "added"


def test_the_setting_is_pinned_in_the_environment_we_build(repo):
    """Pinned rather than inherited. The git environment deliberately reads no
    user or system config, so a machine where somebody set `core.quotePath` is
    not what makes this work — and a machine where nobody did is not what makes
    it fail."""
    from security_agent.workspace import _git_env

    env = _git_env()
    count = int(env["GIT_CONFIG_COUNT"])
    pairs = {env["GIT_CONFIG_KEY_{}".format(i)]: env["GIT_CONFIG_VALUE_{}".format(i)]
             for i in range(count)}

    assert pairs["core.quotePath"] == "false"
    # And the entry that was already there is still counted.
    assert pairs["safe.directory"] == "*"


# ------------------------------------------------- the half a setting cannot fix


@pytest.mark.parametrize("raw,expected", [
    ('"b/src/caf\\303\\251.py"', "b/src/café.py"),
    ('"b/src/report\\\\v2.py"', "b/src/report\\v2.py"),
    ('"b/src/quote\\".py"', 'b/src/quote".py'),
    ('"b/src/tab\\there.py"', "b/src/tab\there.py"),
    ("b/src/plain.py", "b/src/plain.py"),          # unquoted, untouched
])
def test_a_quoted_path_is_decoded(raw, expected):
    """Octal bytes and the three escapes git always emits, whatever the config.

    The decoder is what makes the fix complete. `core.quotePath=false` closed
    one third of the hole and read as though it had closed all of it, which is
    the more dangerous of the two states.
    """
    from security_agent.evidence import unquote_path

    assert unquote_path(raw) == expected


@pytest.mark.parametrize("malformed", [
    '"b/src/trailing\\"',        # a backslash with nothing after it
    '"b/src/bad\\9.py"',         # not an escape git emits, not octal
    '"b/src/short\\7"',          # an octal run cut off
])
def test_a_malformed_quoted_path_is_returned_as_it_arrived(malformed):
    """Never repaired by guessing. A reconstructed path is a path the change
    may not contain, and this map decides whether a finding blocks."""
    from security_agent.evidence import unquote_path

    assert unquote_path(malformed) == malformed


@pytest.mark.parametrize("out_of_range", [
    '"b/src/x\\400.py"',         # three octal digits, and not a byte
    '"b/src/x\\777.py"',
])
def test_an_octal_escape_above_a_byte_does_not_raise(out_of_range):
    """It raised `ValueError: byte must be in range(0, 256)`.

    `\\400` passes the three-octal-digits test and `bytearray.append` then
    rejects it, so the exception left a path decoder and travelled up through
    `changed_lines` — which is called once for the whole change. The cost is
    not one mis-keyed file: the changed-line map is never built, so *every*
    finding in the change loses its attribution at once.

    Git cannot emit one, which is why this had never been seen. Every other
    branch here already treats "not an escape git would emit" as malformed and
    returns the string; this one crashed instead.
    """
    from security_agent.evidence import unquote_path

    assert unquote_path(out_of_range) == out_of_range


def test_a_path_that_is_not_utf8_survives_as_a_key():
    """A byte sequence that is not UTF-8 is still a real path. Mangling it into
    replacement characters would produce a key matching nothing — which is the
    failure the decoder exists to end, arriving by another route."""
    from security_agent.evidence import unquote_path

    decoded = unquote_path('"b/src/\\377.py"')

    assert decoded.startswith("b/src/")
    assert decoded.endswith(".py")
    assert not decoded.startswith('"')


# ------------------------------------- the same failure, without any quoting


# Git does not quote a space: it is not a control character, not a backslash and
# not a double quote. What it does instead is terminate the path with a single
# TAB, so the space cannot be read as the end of the name. `.strip()` removed
# that tab *and* whatever real whitespace the name ended with — so `handler.py `
# was filed under `handler.py`, a key nothing looks up, and every finding in it
# came out "already there". Same gate, same silence, no accented character
# anywhere near it.
SPACED = ("handler.py ", "two words.py")


@pytest.fixture
def spaced_repo(tmp_path):
    root = tmp_path / "spaced"
    (root / "src").mkdir(parents=True)
    for name in SPACED:
        try:
            (root / "src" / name).write_text("VALUE = 1\n", encoding="utf-8")
        except OSError as exc:
            pytest.skip("this filesystem refuses the name {!r}: {}".format(name, exc))

    def git(*args):
        subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True)

    subprocess.run(["git", "init", "-q", str(root)], check=True, capture_output=True)
    git("config", "user.email", "t@example.com")
    git("config", "user.name", "T")
    git("add", "-A")
    git("commit", "-qm", "base")
    base = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"],
                          capture_output=True, text=True, check=True).stdout.strip()
    for name in SPACED:
        (root / "src" / name).write_text(
            'VALUE = db.execute("SELECT " + user_id)\n', encoding="utf-8")
    git("add", "-A")
    git("commit", "-qm", "change")
    return Workspace(root=root, diff_base=base, diff_head="HEAD")


def test_the_two_views_agree_on_a_name_with_whitespace(spaced_repo):
    """The same assertion as the quoted case, and it failed for the other
    reason: one view reads the NUL form and keeps every byte, the other parsed
    the header and threw the trailing one away."""
    changed = sorted(path for path, _ in spaced_repo.changed_files())
    attributed = sorted(spaced_repo.changed_line_map().files())

    assert changed == attributed


@pytest.mark.parametrize("name", SPACED)
def test_a_change_in_a_name_with_whitespace_is_attributed(spaced_repo, name):
    """`""` means "already there", and a pre-existing finding does not block."""
    from security_agent.evidence import attribution

    assert attribution("src/" + name, 1, 1, spaced_repo.changed_line_map()) == "added"


@pytest.mark.parametrize("header,expected", [
    # What git actually writes, taken from its output: one tab terminator when
    # the name contains a space, and none when it does not.
    ("+++ b/src/handler.py \t", "src/handler.py "),
    ("+++ b/src/two words.py\t", "src/two words.py"),
    ("+++ b/src/plain.py", "src/plain.py"),
    # Quoted *and* terminated: the prefix is inside the quotes, the tab is not.
    ('+++ "b/src/caf\\303\\251 x.py"\t', "src/café x.py"),
    ('+++ "b/src/tab\\there.py"', "src/tab\there.py"),
    ("+++ /dev/null", "/dev/null"),
])
def test_a_header_names_the_file_exactly(header, expected):
    """One tab comes off, and nothing else. A name that ends in a tab is
    quoted by git — tab is a control character — so removing exactly one
    terminator can never eat a real one."""
    from security_agent.evidence import _header_path

    assert _header_path(header) == expected


# --------------------------------------- the boundary the decoder sits behind


def test_git_output_is_decoded_reversibly():
    """`errors="replace"` destroyed the bytes before either parser saw them.

    A file name is a sequence of bytes on Linux and need not be UTF-8. Decoding
    git's stdout with `replace` turned any such byte into `U+FFFD` at the
    subprocess boundary, so the two views of one change could not agree on a
    key however carefully each was written — and the decoder added one layer
    up was working on characters that had already been thrown away.

    Asserted on the source rather than through a file, because the filesystem
    this runs on may refuse to hold such a name at all. The chain test below
    does it properly where it can.
    """
    import inspect

    from security_agent.workspace import Workspace

    body = inspect.getsource(Workspace.git)

    assert 'decode("utf-8", "surrogateescape")' in body, \
        "stdout must decode reversibly, or a non-UTF-8 path stops being a key"
    assert 'decode("utf-8", "replace")' in body, \
        "stderr is a message for a person; a hostile name must not break it"


def test_a_name_that_is_not_utf8_keys_both_views_the_same(tmp_path):
    """The chain, where the filesystem allows it.

    Skipped rather than silently weakened on a filesystem that enforces UTF-8
    — macOS and Windows both do. A test that cannot run where it is run, and
    says nothing about that, is how this project has twice shipped a control
    with a green test above it.
    """
    import os
    import subprocess as sp

    root = tmp_path / "repo"
    (root / "src").mkdir(parents=True)
    hostile = os.fsdecode(b"src/bad\xff.py")
    try:
        (root / hostile).write_bytes(b"VALUE = 1\n")
    except OSError as exc:
        pytest.skip("this filesystem refuses a non-UTF-8 name: {}".format(exc))

    def git(*args):
        sp.run(["git", "-C", str(root), *args], check=True, capture_output=True)

    sp.run(["git", "init", "-q", str(root)], check=True, capture_output=True)
    git("config", "user.email", "t@example.com")
    git("config", "user.name", "T")
    (root / "src" / "plain.py").write_text("VALUE = 1\n")
    git("add", "-A")
    git("commit", "-qm", "base")
    base = sp.run(["git", "-C", str(root), "rev-parse", "HEAD"],
                  capture_output=True, text=True, check=True).stdout.strip()
    (root / hostile).write_bytes(b'VALUE = db.execute("SELECT " + x)\n')
    (root / "src" / "plain.py").write_text('VALUE = db.execute("SELECT " + x)\n')
    git("add", "-A")
    git("commit", "-qm", "change")

    ws = Workspace(root=root, diff_base=base, diff_head="HEAD")

    assert sorted(p for p, _ in ws.changed_files()) == \
        sorted(ws.changed_line_map().files())
