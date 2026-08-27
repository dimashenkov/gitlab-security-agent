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
AWKWARD = ("café.py", "naïve.go", "плащане.py", "決済.rb")


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
