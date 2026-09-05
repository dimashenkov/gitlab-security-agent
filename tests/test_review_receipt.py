"""The review gate, against the failure it was built for.

Twice on 2026-09-03: stage everything, review the staged diff, keep editing,
commit. The reviewer saw a diff that was not the one that landed. Every test
here is a form of that, plus the forms that would make the gate unusable if it
got them wrong.
"""
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

# Derived from this file's own location, not typed out. A hard-coded path
# tested a copy that happened to be identical, and would silently have tested
# yesterday's on the day they diverged. The two lived side by side in a
# scratchpad while this was being written; they are in the repository now, so
# the derivation goes up one level and into `tools/` — still derived, and the
# assertion below is what makes a wrong move fail at collection rather than
# test a file that is not there.
TOOL = Path(__file__).resolve().parents[1] / "tools" / "review_receipt.py"
assert TOOL.is_file(), TOOL
failures = []
ran = []


def sh(*args, cwd):
    return subprocess.run(args, cwd=str(cwd), capture_output=True, text=True,
                          check=False)


def tool(*args, cwd):
    p = subprocess.run([sys.executable, str(TOOL), *args], cwd=str(cwd),
                       capture_output=True, text=True, check=False)
    return p.returncode, (p.stdout + p.stderr)


def check(name, ok, detail=""):
    # A list rather than a counter, because `global` on an int is a lint the
    # repository's own hook refuses, and because the names are worth having
    # when the count is wrong.
    ran.append(name)
    print("  {:<3} {}{}".format("ok" if ok else "BAD", name,
                                "" if ok else "\n        " + detail[:200]))
    if not ok:
        failures.append("{}: {}".format(name, detail[:200]))


def fresh():
    root = Path(tempfile.mkdtemp(prefix="gate-"))
    sh("git", "init", "-q", ".", cwd=root)
    sh("git", "config", "user.email", "t@example.com", cwd=root)
    sh("git", "config", "user.name", "T", cwd=root)
    (root / "a.py").write_text("VALUE = 1\n", encoding="utf-8")
    sh("git", "add", "-A", cwd=root)
    sh("git", "commit", "-qm", "base", cwd=root)
    return root


print("=== the failure it exists for ===")

root = fresh()
(root / "a.py").write_text("VALUE = 2\n", encoding="utf-8")
sh("git", "add", "-A", cwd=root)
code, out = tool("write", "--ruling", "ready", "--complete", cwd=root)
check("a review of what is staged is recorded", code == 0, out)

code, out = tool("check", cwd=root)
check("the gate passes on the reviewed tree", code == 0, out)

# The exact thing that happened twice: keep editing after the review.
(root / "a.py").write_text("VALUE = 3\n", encoding="utf-8")
sh("git", "add", "-A", cwd=root)
code, out = tool("check", cwd=root)
check("editing after the review is refused",
      code == 1 and "not what was reviewed" in out, out)

# And a new file staged after the review — the other half of `git add -A`.
code, _ = tool("write", "--ruling", "ready", "--complete", cwd=root)
(root / "b.py").write_text("OTHER = 1\n", encoding="utf-8")
sh("git", "add", "-A", cwd=root)
code, out = tool("check", cwd=root)
check("a file staged after the review is refused", code == 1, out)

print()
print("=== the states that must not read as approval ===")

root = fresh()
(root / "a.py").write_text("VALUE = 2\n", encoding="utf-8")
sh("git", "add", "-A", cwd=root)
code, out = tool("check", cwd=root)
check("no receipt at all is a refusal", code == 1 and "no review" in out, out)

(root / ".git" / "review-receipt.json").write_text("{not json",
                                                   encoding="utf-8")
code, out = tool("check", cwd=root)
check("an unreadable receipt is a refusal, not an absent one",
      code == 1 and "cannot be read" in out, out)

tool("write", "--ruling", "blocked", "--reason", "found a defect", cwd=root)
code, out = tool("check", cwd=root)
check("a `blocked` ruling refuses", code == 1 and "blocked" in out, out)

# Through the tool, not by editing the receipt on disk. Editing it was how the
# real defect stayed hidden: `--complete` defaulted to `None` and the check
# refused only a literal `False`, so the ordinary `write --ruling ready`
# produced an approved receipt that asserted nothing about what the reviewer
# had been given. The test that was meant to catch it hand-wrote the `False`.
tool("write", "--ruling", "ready", cwd=root)
code, out = tool("check", cwd=root)
check("a `ready` that does not claim the whole change refuses",
      code == 1 and "whole change" in out, out)

tool("write", "--ruling", "ready", "--complete", cwd=root)
code, out = tool("check", cwd=root)
check("and the same review claiming it passes", code == 0, out)

receipt = root / ".git" / "review-receipt.json"
for broken, name in (("[]", "a receipt that is a list"),
                     ('"ready"', "a receipt that is a string"),
                     ('{"ruling": "ready"}', "a receipt with no tree"),
                     ('{"tree": 5, "parents": [], "ruling": "ready"}',
                      "a receipt whose tree is not a string")):
    receipt.write_text(broken, encoding="utf-8")
    code, out = tool("check", cwd=root)
    check("{} is refused, not crashed through".format(name),
          code == 1 and "REFUSED" in out, out)

receipt.write_text(json.dumps({
    "tree": "0" * 40, "parents": [], "ruling": "bypass"}), encoding="utf-8")
code, out = tool("check", cwd=root)
check("a hand-written bypass with no reason is refused",
      code == 1 and "no reason" in out, out)

print()
print("=== the parents, which an amend changes ===")

root = fresh()
(root / "a.py").write_text("VALUE = 2\n", encoding="utf-8")
sh("git", "add", "-A", cwd=root)
tool("write", "--ruling", "ready", "--complete", cwd=root)
sh("git", "commit", "-qm", "second", cwd=root)
(root / "a.py").write_text("VALUE = 3\n", encoding="utf-8")
sh("git", "add", "-A", cwd=root)
code, out = tool("check", cwd=root)
check("a receipt does not carry over to the next commit",
      code == 1, out)

root = fresh()
(root / "a.py").write_text("VALUE = 2\n", encoding="utf-8")
sh("git", "add", "-A", cwd=root)
tool("write", "--ruling", "ready", "--complete", cwd=root)
sh("git", "commit", "-qm", "second", cwd=root)
tool("write", "--ruling", "ready", "--complete", "--amend", cwd=root)

# `check` with NO flag, because that is what a `pre-commit` hook can do: git
# tells it nothing about `--amend`. Passing the flag from the test made this
# pass while the real hook would have refused a properly reviewed amend.
code, out = tool("check", cwd=root)
check("an amend reviewed as an amend passes the hook as the hook runs it",
      code == 0, out)

# And the parents alone must carry it. Same tree, wrong kind of commit.
receipt = root / ".git" / "review-receipt.json"
body = json.loads(receipt.read_text(encoding="utf-8"))
body["amend"] = False
receipt.write_text(json.dumps(body), encoding="utf-8")
code, out = tool("check", cwd=root)
check("an amend receipt relabelled as an ordinary commit is refused on parents",
      code == 1 and "parents" in out, out)

print()
print("=== the bypass, which has to exist and has to be loud ===")

root = fresh()
(root / "a.py").write_text("VALUE = 2\n", encoding="utf-8")
sh("git", "add", "-A", cwd=root)
code, out = tool("write", "--ruling", "bypass", cwd=root)
check("a bypass with no reason is refused",
      code == 2 and "needs a reason" in out, out)

code, out = tool("write", "--ruling", "bypass", "--reason",
                 "the reviewer is down", cwd=root)
check("a bypass with a reason is written", code == 0, out)
code, out = tool("check", cwd=root)
check("a bypass passes and says so",
      code == 0 and "BYPASS" in out and "reviewer is down" in out, out)

print()
print("=== the first commit in a repository ===")

root = Path(tempfile.mkdtemp(prefix="gate-empty-"))
sh("git", "init", "-q", ".", cwd=root)
sh("git", "config", "user.email", "t@example.com", cwd=root)
sh("git", "config", "user.name", "T", cwd=root)
(root / "a.py").write_text("VALUE = 1\n", encoding="utf-8")
sh("git", "add", "-A", cwd=root)
code, out = tool("write", "--ruling", "ready", "--complete", cwd=root)
check("a repository with no HEAD yet is handled", code == 0, out)
code, out = tool("check", cwd=root)
check("and its gate passes", code == 0, out)

print()
print("=== the message, which is the other half of the failure ===")


def with_message(root, text):
    path = root / "msg.txt"
    path.write_text(text, encoding="utf-8")
    return path


root = fresh()
(root / "a.py").write_text("VALUE = 2\n", encoding="utf-8")
sh("git", "add", "-A", cwd=root)
msg = with_message(root, "Raise the value\n\nBecause it was too low.\n")
tool("write", "--ruling", "ready", "--complete", "--message-file", str(msg), cwd=root)

code, out = tool("check-message", str(msg), cwd=root)
check("the reviewed message passes", code == 0, out)

other = with_message(root, "Raise the value\n\nSomething else entirely.\n")
code, out = tool("check-message", str(other), cwd=root)
check("a different message is refused",
      code == 1 and "not the one that was reviewed" in out, out)

# A comment line ADDED after the review is refused, and this test asserted the
# opposite until it was measured. `git commit -F` cleans whitespace only, so a
# `#` line survives into the stored commit — a gate that ignored it would let an
# unreviewed line land, which is the bypass Codex named. Normalisation now goes
# through `git stripspace`, git's own code, rather than an imitation of it.
commented = with_message(
    root, "Raise the value\n\nBecause it was too low.\n"
          "# a line added after the review\n")
code, out = tool("check-message", str(commented), cwd=root)
check("a comment line added after the review is refused",
      code == 1 and "not the one that was reviewed" in out, out)

trailing = with_message(
    root, "Raise the value\n\nBecause it was too low.\n\n\n")
code, out = tool("check-message", str(trailing), cwd=root)
check("trailing blank lines do not change the answer", code == 0, out)

# A review recorded without a message proves nothing about the message.
root = fresh()
(root / "a.py").write_text("VALUE = 2\n", encoding="utf-8")
sh("git", "add", "-A", cwd=root)
tool("write", "--ruling", "ready", "--complete", cwd=root)
msg = with_message(root, "anything at all\n")
code, out = tool("check-message", str(msg), cwd=root)
check("a review with no message on record refuses the message check",
      code == 1 and "without a commit message" in out, out)

code, out = tool("check-message", str(root / "not-there.txt"), cwd=root)
check("a message file that cannot be read is refused, not waved through",
      code == 1 and "could not be read" in out, out)

print()
print("=== the stale receipt, which parents alone do not catch ===")

# Two amends in a row. After the first, the prospective parents are the same
# and the tree can be unchanged — so the receipt for the first amend matched
# the second. `reviewed_head` is what separates them.
root = fresh()
(root / "a.py").write_text("VALUE = 2\n", encoding="utf-8")
sh("git", "add", "-A", cwd=root)
tool("write", "--ruling", "ready", "--complete", cwd=root)
sh("git", "commit", "-qm", "second", cwd=root)

tool("write", "--ruling", "ready", "--complete", "--amend", cwd=root)
code, out = tool("check", cwd=root)
check("the first amend passes", code == 0, out)
sh("git", "commit", "-q", "--amend", "-m", "second, reworded", cwd=root)

code, out = tool("check", cwd=root)
check("a SECOND amend on the same tree is refused",
      code == 1 and "HEAD has moved" in out, out)

# And a receipt written before this feature existed says nothing about HEAD.
receipt = root / ".git" / "review-receipt.json"
tool("write", "--ruling", "ready", "--complete", "--amend", cwd=root)
body = json.loads(receipt.read_text(encoding="utf-8"))
del body["reviewed_head"]
receipt.write_text(json.dumps(body), encoding="utf-8")
code, out = tool("check", cwd=root)
check("a receipt that does not say where HEAD was is refused",
      code == 1 and "where HEAD was" in out, out)

print()
print("=== the receipt's own field types ===")

root = fresh()
(root / "a.py").write_text("VALUE = 2\n", encoding="utf-8")
sh("git", "add", "-A", cwd=root)
tool("write", "--ruling", "ready", "--complete", cwd=root)
receipt = root / ".git" / "review-receipt.json"
good = json.loads(receipt.read_text(encoding="utf-8"))

for field, value, name in (
        ("amend", "yes", "a string `amend` does not switch the mode on"),
        ("parents", [5], "a parent that is not an object id"),
        ("reason", 7, "a numeric reason"),
        ("reviewed_head", 3, "a numeric reviewed_head")):
    body = dict(good)
    body[field] = value
    receipt.write_text(json.dumps(body), encoding="utf-8")
    code, out = tool("check", cwd=root)
    check("{} is refused".format(name), code == 1 and "REFUSED" in out, out)

# A bypass with a numeric reason used to crash `.strip()` in check-message.
body = dict(good)
body.update({"ruling": "bypass", "reason": ""})
receipt.write_text(json.dumps(body), encoding="utf-8")
msg = root / "m.txt"
msg.write_text("anything\n", encoding="utf-8")
code, out = tool("check-message", str(msg), cwd=root)
check("check-message refuses a bypass with no reason too",
      code == 1 and "no reason" in out, out)

print()
print("=== the message, in bytes ===")

# `errors="replace"` mapped every undecodable byte onto one replacement
# character, so two different messages digested the same — in the half of the
# gate built to stop exactly that. Git allows a non-UTF-8 commit encoding, so
# this is reachable.
root = fresh()
(root / "a.py").write_text("VALUE = 2\n", encoding="utf-8")
sh("git", "add", "-A", cwd=root)

one = root / "one.txt"
two = root / "two.txt"
one.write_bytes(b"Title\n\nBody \xff\n")
two.write_bytes(b"Title\n\nBody \xfe\n")
tool("write", "--ruling", "ready", "--complete", "--message-file", str(one),
     cwd=root)
code, out = tool("check-message", str(one), cwd=root)
check("a non-UTF-8 message matches itself", code == 0, out)
code, out = tool("check-message", str(two), cwd=root)
check("two different undecodable bytes do not share one approval",
      code == 1, out)

# And an undecodable byte must not collide with a real U+FFFD either.
three = root / "three.txt"
three.write_bytes("Title\n\nBody �\n".encode("utf-8"))
code, out = tool("check-message", str(three), cwd=root)
check("an undecodable byte does not match a real replacement character",
      code == 1, out)

print()
print("=== the cleanup mode git is actually configured with ===")

root = fresh()
(root / "a.py").write_text("VALUE = 2\n", encoding="utf-8")
sh("git", "add", "-A", cwd=root)
sh("git", "config", "commit.cleanup", "verbatim", cwd=root)
a = root / "a.txt"
b = root / "b.txt"
a.write_bytes(b"Title\n\nBody\n")
b.write_bytes(b"Title\n\nBody   \n\n\n")
tool("write", "--ruling", "ready", "--complete", "--message-file", str(a),
     cwd=root)
code, out = tool("check-message", str(a), cwd=root)
check("under verbatim the reviewed message still matches itself",
      code == 0, out)
code, out = tool("check-message", str(b), cwd=root)
check("under verbatim, whitespace git would keep is not normalised away",
      code == 1, out)

print()
print("=== the window between the two hooks ===")

# `pre-commit` checks the tree; git then obtains the message and runs
# `prepare-commit-msg`. Anything staged in that window was never reviewed, and
# `check-message` used to let it through on a matching message alone — the
# original failure class one hook later. Codex, 2026-09-05.
root = fresh()
(root / "a.py").write_text("VALUE = 2\n", encoding="utf-8")
sh("git", "add", "-A", cwd=root)
msg = with_message(root, "Raise the value\n\nBecause it was too low.\n")
tool("write", "--ruling", "ready", "--complete", "--message-file", str(msg),
     cwd=root)
code, out = tool("check", cwd=root)
check("pre-commit passes on the reviewed tree", code == 0, out)

# What `prepare-commit-msg` could do, or another shell, between the two.
(root / "sneaked.py").write_text("BACKDOOR = True\n", encoding="utf-8")
sh("git", "add", "-A", cwd=root)
code, out = tool("check-message", str(msg), cwd=root)
check("content staged after pre-commit is refused at commit-msg",
      code == 1 and "not what was reviewed" in out, out)
check("and it says why the check happens twice",
      "between `pre-commit` and `commit-msg`" in out, out)

# A bypass excuses the review, not the question of which content is committed.
root = fresh()
(root / "a.py").write_text("VALUE = 2\n", encoding="utf-8")
sh("git", "add", "-A", cwd=root)
tool("write", "--ruling", "bypass", "--reason", "urgent", cwd=root)
(root / "sneaked.py").write_text("BACKDOOR = True\n", encoding="utf-8")
sh("git", "add", "-A", cwd=root)
code, out = tool("check-message", str(with_message(root, "Anything\n")),
                 cwd=root)
check("a bypass does not excuse content staged after it",
      code == 1 and "not what was reviewed" in out, out)

print()
print("=== installing, and whether git actually runs it ===")

# The gate passed every case for two days while installed nowhere, so the last
# thing it asserts is that a real `git commit` goes through it. Codex,
# 2026-09-05: neither core.hooksPath nor an executable hook existed, so normal
# commits bypassed both checks entirely.
root = fresh()
code, out = tool("install", cwd=root)
check("install reports what it wrote", code == 0 and "pre-commit" in out, out)
for name in ("pre-commit", "commit-msg"):
    path = root / ".git" / "hooks" / name
    check("{} exists and is executable".format(name),
          path.is_file() and os.access(str(path), os.X_OK), str(path))

# The hook calls the repository's own copy, so a repository that has none is a
# hook pointing at nothing. It must say so rather than dying on a traceback.
done = sh("git", "commit", "--allow-empty", "-m", "x", cwd=root)
check("a hook whose tool is missing refuses, and says what to do",
      done.returncode != 0
      and "the review gate is installed" in (done.stdout + done.stderr)
      and "remove the gate" in (done.stdout + done.stderr),
      (done.stdout + done.stderr)[:250])

# Give the temp repository the layout the hook expects, which is the layout the
# real one has. Copying the tool rather than pointing at this checkout: a hook
# reaching outside its own repository would keep working after the tool moved,
# and would then be testing a copy nobody edits.
(root / "tools").mkdir()
(root / "tools" / "review_receipt.py").write_bytes(TOOL.read_bytes())

(root / "a.py").write_text("VALUE = 2\n", encoding="utf-8")
sh("git", "add", "-A", cwd=root)
done = sh("git", "commit", "-m", "no receipt for this", cwd=root)
check("a real commit with no receipt is refused",
      done.returncode != 0 and "no review on record" in (
          done.stdout + done.stderr),
      (done.stdout + done.stderr)[:200])

msg = with_message(root, "Raise the value\n\nBecause it was too low.\n")
tool("write", "--ruling", "ready", "--complete", "--message-file", str(msg),
     cwd=root)
done = sh("git", "commit", "-F", str(msg), cwd=root)
check("a real commit with a receipt goes through",
      done.returncode == 0, (done.stdout + done.stderr)[:200])

# What the hook is for, end to end: reviewed, then something else staged.
(root / "b.py").write_text("VALUE = 3\n", encoding="utf-8")
sh("git", "add", "-A", cwd=root)
msg2 = with_message(root, "Second\n\nBody.\n")
tool("write", "--ruling", "ready", "--complete", "--message-file", str(msg2),
     cwd=root)
(root / "c.py").write_text("SNEAKED = True\n", encoding="utf-8")
sh("git", "add", "-A", cwd=root)
done = sh("git", "commit", "-F", str(msg2), cwd=root)
check("a real commit staged after the review is refused",
      done.returncode != 0 and "not what was reviewed" in (
          done.stdout + done.stderr),
      (done.stdout + done.stderr)[:200])

# A hook somebody else put there is a control; replacing it silently would
# remove one to install one.
root = fresh()
(root / ".git" / "hooks" / "pre-commit").write_text(
    "#!/bin/sh\necho somebody else\n", encoding="utf-8")
code, out = tool("install", cwd=root)
check("a foreign hook is refused rather than overwritten",
      code == 1 and "did not write it" in out, out)
check("and the refusal says how to proceed", "--force" in out, out)
code, out = tool("install", "--force", cwd=root)
check("--force replaces it", code == 0, out)

code, out = tool("uninstall", cwd=root)
check("uninstall removes what it wrote", code == 0 and "removed" in out, out)
check("and the hooks are gone",
      not (root / ".git" / "hooks" / "pre-commit").exists(), out)
code, out = tool("uninstall", cwd=root)
check("uninstalling twice says so rather than failing",
      code == 0 and "was not installed" in out, out)

root = fresh()
(root / ".git" / "hooks" / "commit-msg").write_text(
    "#!/bin/sh\nexit 0\n", encoding="utf-8")
code, out = tool("uninstall", cwd=root)
check("uninstall refuses to delete a hook it did not write",
      code == 1 and "somebody else" in out, out)

# Ownership from a marker line meant a hook this tool wrote and somebody then
# edited was still "ours": install discarded the edit, uninstall deleted it,
# and a foreign hook that merely copied the line inherited both.
root = fresh()
tool("install", cwd=root)
hook = root / ".git" / "hooks" / "pre-commit"
hook.write_text(hook.read_text(encoding="utf-8") + "\n# my own line\n",
                encoding="utf-8")
code, out = tool("install", cwd=root)
check("an edited hook is not silently overwritten",
      code == 1 and "edited since" in out, out)
code, out = tool("uninstall", cwd=root)
check("and it is not silently deleted either",
      code == 1 and "edited since" in out, out)
check("the edit is still there", "my own line" in hook.read_text(
    encoding="utf-8"), "")

root = fresh()
(root / ".git" / "hooks" / "pre-commit").write_text(
    "#!/bin/sh\n# installed by tools/review_receipt.py\necho not really\n",
    encoding="utf-8")
code, out = tool("install", cwd=root)
check("a foreign hook carrying the marker line does not inherit ownership",
      code == 1, out)

# `write_text` follows a symlink, so a hook path pointing elsewhere had this
# writing and chmodding a file outside the hooks directory.
root = fresh()
outside = root / "not-a-hook.txt"
outside.write_text("do not touch\n", encoding="utf-8")
(root / ".git" / "hooks" / "pre-commit").symlink_to(outside)
code, out = tool("install", cwd=root)
check("a symlinked hook is refused rather than written through",
      code == 1 and "did not write it" in out, out)
check("and the file it pointed at is untouched",
      outside.read_text(encoding="utf-8") == "do not touch\n", "")
code, out = tool("install", "--force", cwd=root)
check("even --force writes the hook, not the target",
      code == 0 and outside.read_text(encoding="utf-8") == "do not touch\n",
      out)
check("and the hook is a real file now",
      not (root / ".git" / "hooks" / "pre-commit").is_symlink(), "")

# The case the symlink branch exists for. Reading through the link, a symlink
# pointing at a file holding the expected text looks like this tool's own hook,
# and install would proceed without a word — replacing a link somebody made on
# purpose. It is somebody else's arrangement whatever it points at.
root = fresh()
tool("install", cwd=root)
real = root / ".git" / "hooks" / "pre-commit"
elsewhere = root / "kept-hook.sh"
elsewhere.write_text(real.read_text(encoding="utf-8"), encoding="utf-8")
real.unlink()
real.symlink_to(elsewhere)
code, out = tool("install", cwd=root)
check("a symlink is refused even when it points at the expected text",
      code == 1 and "did not write it" in out, out)
code, out = tool("uninstall", cwd=root)
check("and uninstall refuses it too rather than unlinking silently",
      code == 1, out)
check("the file it pointed at survives", elsewhere.is_file(), "")

# Judging while removing left the gate half installed: pre-commit gone,
# commit-msg still there, and the refusal read as though nothing had happened.
# A half-installed gate is worse than either finished state. Codex, 2026-09-05.
root = fresh()
tool("install", cwd=root)
edited = root / ".git" / "hooks" / "commit-msg"
edited.write_text(edited.read_text(encoding="utf-8") + "\n# mine\n",
                  encoding="utf-8")
code, out = tool("uninstall", cwd=root)
check("a mixed state removes nothing rather than half of it",
      code == 1 and "Nothing was removed" in out, out)
check("the hook it would have removed first is still there",
      (root / ".git" / "hooks" / "pre-commit").is_file(), "")
check("and so is the edited one", edited.is_file(), "")

print()
print("=== check-push, deleted ===")

root = fresh()
code, out = tool("check-push", cwd=root)
check("it refuses rather than reporting on the wrong object",
      code == 2 and "removed" in out, out)

print()


# --------------------------------------------------------------------------
# The cases above run at import, which is how they were written as a script.
# Under pytest that made the file report "no tests ran" — a green line over
# forty-two cases nobody executed, which is the shape this repository exists to
# catch. The two entry points below make the same cases answer to both runners,
# and neither can pass while a case fails.
# --------------------------------------------------------------------------

EXPECTED_CASES = 74


def test_every_case_behaves():
    assert failures == [], "\n".join(failures)


def test_the_cases_that_ran_are_the_cases_there_are():
    """A file that stops executing halfway would otherwise pass on silence.

    `failures == []` is satisfied by running nothing at all, so the count is
    asserted beside it. Raising the number here without adding a case fails;
    adding a case without raising it fails too.
    """
    assert len(ran) == EXPECTED_CASES, (
        "{} case(s) ran, {} expected — a case was added, removed, or the file "
        "stopped part way".format(len(ran), EXPECTED_CASES))


def test_no_two_cases_share_a_name():
    """Two cases under one name is one case reported twice.

    The count would still be right, and the failing one could be read as the
    passing one.
    """
    duplicates = sorted({n for n in ran if ran.count(n) > 1})
    assert duplicates == [], duplicates


if __name__ == "__main__":
    if failures:
        print("{} FAILURE(S): {}".format(len(failures), failures))
        sys.exit(1)
    print("all {} cases behave".format(len(ran)))
