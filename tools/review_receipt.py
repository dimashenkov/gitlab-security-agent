#!/usr/bin/env python3
"""The review gate: record that a review happened, and refuse a commit without one.

    tools/review_receipt.py write   --ruling ready   # after Codex has ruled
    tools/review_receipt.py check                    # what pre-commit runs
    tools/review_receipt.py show                     # what is on record

Development tooling. It imports nothing from `src/`, runs no review, corpus or
measurement machinery, and writes nothing any product code reads. Nothing in
`src/` or in CI depends on it.

## Why this exists

`CLAUDE.md`: "The unit is the commit. Nothing is recorded that Codex has not
seen." That rule was executed by the assistant remembering it, and on
2026-09-03 it failed twice in the same way: stage everything, run Codex on the
staged diff, keep editing, commit. Codex reviewed a diff that was not the diff
that landed, and both commit messages described behaviour the committed code did
not have. Codex caught the second one itself.

## What the receipt is keyed on, and why not the diff

Not a digest of `git diff --cached`. Its text depends on diff configuration,
on text conversion filters, and on how binary files are represented — a key that
moves for reasons that are not changes.

Git's own identities instead:

    tree      `git write-tree` — the exact content that would be committed
    parents   what HEAD is now, or the parents of HEAD for an amend
    message   a digest of the message, when one is on record

The tree changes the instant any staged file changes, which is exactly the
failure this exists for. The parents matter because an amend has different ones
from an ordinary commit, and a receipt that ignored them would carry over.

## What it deliberately is not

**It is not proof that a review happened.** The receipt is written by whoever
runs this command. Against an author who wants to skip the review it is
theatre — they can write the receipt, pass `--no-verify`, or commit from another
shell. It is aimed at the adversary this project actually has: the assistant
forgetting the order of the steps.

**So the bypass is honest rather than impossible.** `--bypass` with a reason
writes the reason into the receipt and lets the commit through. A gate with no
way out is a gate somebody deletes, and then nothing is checked at all.

**It records what the review was given.** `--diff-bytes` and `--complete` say
how large the change was and whether the reviewer was shown all of it. A
`ready` ruling over a change that was delivered in part is the same defect this
product has in its own gate, one level up.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

RULINGS = ("ready", "blocked", "bypass")


def git(*args, cwd=None):
    """`(stdout, None)` or `(None, why)`. Never a bare string: a failed read
    and an empty answer must not look the same to the caller."""
    try:
        proc = subprocess.run(("git", *args), cwd=cwd, capture_output=True,
                              text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return None, "{}: {}".format(type(exc).__name__, exc)
    if proc.returncode != 0:
        return None, (proc.stderr or "").strip()[:300]
    return proc.stdout.strip(), None


def repo_root():
    out, why = git("rev-parse", "--show-toplevel")
    return (Path(out), None) if out else (None, why)


def receipt_path(root: Path):
    """Where the receipt lives, asked of git rather than assumed.

    `root/.git` is a *file* in a linked worktree, not a directory, so building
    the path by hand wrote nothing and read nothing there — a gate that
    silently does not exist in half the places somebody works.

    Under the git directory either way, never in the working tree: a receipt
    inside the tree changes the tree it attests to, so writing it would
    invalidate itself.
    """
    out, why = git("rev-parse", "--git-path", "review-receipt.json", cwd=root)
    if out is None:
        return None, why
    path = Path(out)
    return (path if path.is_absolute() else root / path), None


def prospective(root: Path, amend: bool = False):
    """The identity of the commit that would be made right now.

    `(identity, None)` or `(None, why)`. The tree comes from `git write-tree`,
    which writes the index out as a real tree object — the same object the
    commit would point at. It changes the moment any staged file changes.
    """
    tree, why = git("write-tree", cwd=root)
    if tree is None:
        return None, "could not write the index out as a tree: {}".format(why)

    head, _ = git("rev-parse", "HEAD", cwd=root)
    if head is None:
        parents = []                      # the first commit in a repository
    elif amend:
        out, why = git("rev-list", "--parents", "-n", "1", "HEAD", cwd=root)
        if out is None:
            return None, "could not read HEAD's parents: {}".format(why)
        parents = out.split()[1:]
    else:
        parents = [head]
    return {"tree": tree, "parents": parents}, None


def digest(data) -> str:
    """Over bytes. A `str` is encoded here rather than at each call site, so
    nobody has to remember which of the two they are holding."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()[:16]


def normalise_message(raw: bytes, cwd=None):
    """The message through git's own normaliser, not an imitation of it.

    `(normalised bytes, None)` or `(None, why)`.

    The first version wrote this by hand: drop `#` lines, trim trailing blanks.
    Measured 2026-09-03 and it was wrong in both directions.

    * `git commit -F` cleans **whitespace only**, so a `#` line *survives* into
      the commit — while the hand-written version removed it. A message with an
      added comment digested the same as one without, and the added line
      landed unreviewed. Precisely the bypass this exists to stop.
    * `core.commentChar` is configurable. With `;` set, git strips `;` lines and
      keeps `#`; the hand-written version did the opposite.

    `git stripspace` is git's own implementation and reads the repository's
    configuration. Without `--strip-comments`, it is the whitespace cleanup
    that `-F` applies — which is what `commit-msg` was measured to receive.

    Measured against what `commit-msg` is actually handed: `git stripspace`
    agrees in all ten message shapes tried — comments, trailing blanks, no
    final newline, CRLF, leading blanks, internal double blanks, trailing
    spaces, a trailer, a fenced `#` — and under `commit.cleanup` of
    `whitespace` and `strip`.

    Under `verbatim` it does not: git hands the hook the untouched text, so
    normalising would compare something git never produces. There, the raw
    text is compared instead.

    **The limit, stated rather than implied.** A commit made through an editor
    with the default cleanup gets git's comment block appended, and the final
    cleanup strips it *after* `commit-msg` has run. So a match here proves the
    message the hook saw is the message that was reviewed; a later cleanup can
    only remove text, never add it. For the failure this gate exists for — a
    message *claiming* behaviour the code does not have — removal-only is
    enough. It is not a proof that the stored bytes are identical. And
    `--cleanup` passed on the command line is invisible to a hook, so only the
    configured mode can be seen.

    **Bytes throughout, never decoded text.** Decoding with `errors="replace"`
    turned every undecodable byte into one replacement character, so `b"\\xff"`
    and `b"\\xfe"` digested the same — and both collided with a message that
    genuinely contained U+FFFD. Two different commit messages sharing one
    approval, in the half of the gate built to stop exactly that. Git allows a
    non-UTF-8 commit encoding, so this is reachable and not theoretical.
    """
    mode, _ = git("config", "--get", "commit.cleanup", cwd=cwd)
    if (mode or "").strip() == "verbatim":
        # Git hands the hook the untouched text here, so normalising would
        # compare something git never produces — and would map two messages the
        # hook really does receive as different onto one digest.
        return raw, None
    try:
        proc = subprocess.run(("git", "stripspace"), input=raw, cwd=cwd,
                              capture_output=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return None, "{}: {}".format(type(exc).__name__, exc)
    if proc.returncode != 0:
        return None, (proc.stderr or b"").decode("utf-8", "replace")[:200]
    return proc.stdout, None


def load(root: Path):
    """`(receipt, None)`, `(None, None)` for absent, `(None, why)` for broken.

    Three answers, not two. Absent means nobody reviewed; broken means nobody
    can tell — and a caller that folded them together would let a corrupt file
    read as a missing one, which is the softer of the two messages.
    """
    path, why = receipt_path(root)
    if path is None:
        return None, "could not work out where the receipt lives: {}".format(why)
    # `exists()` and not `is_file()`: a directory here is a broken state, not
    # an absent receipt, and the two must not read the same.
    if path.exists() and not path.is_file():
        return None, "{} is not a file".format(path)
    if not path.exists():
        return None, None
    try:
        body = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return None, "the receipt could not be read: {}".format(exc)
    # The receipt is the trust boundary: everything below reads fields off it,
    # and `[]` or `"ready"` would crash on `.get`. A crash inside a git hook
    # fails closed, which looks like a refusal and is not one — it is an
    # uncontrolled "could not check" wearing a refusal's clothes.
    if not isinstance(body, dict):
        return None, "the receipt is a {}, not an object".format(
            type(body).__name__)
    for field, kind in (("tree", str), ("parents", list), ("ruling", str)):
        if not isinstance(body.get(field), kind):
            return None, "the receipt has no usable `{}`".format(field)
    if any(not isinstance(p, str) for p in body["parents"]):
        return None, "the receipt's `parents` holds something that is not an "\
                     "object id"
    # `amend` decides which parents are compared. A truthy string would have
    # switched the mode on silently, so it is required to be a boolean when it
    # is there at all.
    if "amend" in body and not isinstance(body["amend"], bool):
        return None, "the receipt's `amend` is a {}, not a boolean".format(
            type(body["amend"]).__name__)
    for field in ("reason", "message_digest", "reviewed_head"):
        if body.get(field) is not None and not isinstance(body[field], str):
            return None, "the receipt's `{}` is a {}, not text".format(
                field, type(body[field]).__name__)
    return body, None


def cmd_write(args) -> int:
    root, why = repo_root()
    if root is None:
        print("not a git repository: {}".format(why), file=sys.stderr)
        return 2

    identity, why = prospective(root, amend=args.amend)
    if identity is None:
        print(why, file=sys.stderr)
        return 2

    if args.ruling == "bypass" and not (args.reason or "").strip():
        print("a bypass needs a reason. It is recorded in the receipt and "
              "reported again at push, which is the whole point of allowing "
              "one at all.", file=sys.stderr)
        return 2

    message_digest = None
    if args.message_file:
        try:
            # `errors="replace"`: git allows a non-UTF-8 commit encoding, and
            # an undecodable byte must not become an uncaught exception — that
            # is an uncontrolled "could not check", which this file refuses
            # everywhere else. Both sides decode the same way, so a message
            # that round-trips through the replacement character still
            # compares equal to itself and differs from anything else.
            raw = Path(args.message_file).read_bytes()
        except OSError as exc:
            print("the message file could not be read: {}".format(exc),
                  file=sys.stderr)
            return 2
        normalised, why = normalise_message(raw, cwd=str(root))
        if normalised is None:
            print("git could not normalise the message ({}), so nothing here "
                  "would establish which message was reviewed.".format(why),
                  file=sys.stderr)
            return 2
        message_digest = digest(normalised)

    head_now, _ = git("rev-parse", "HEAD", cwd=root)

    receipt = {
        "version": 1,
        "tree": identity["tree"],
        "parents": identity["parents"],
        # Normalised on both sides, by git. Writing the raw digest and
        # comparing a normalised one made every message check refuse, including
        # of the very message that had just been reviewed — a gate that refuses
        # everything is removed within the hour, and it would take the working
        # half with it.
        "message_digest": message_digest,
        # The commit HEAD was on when the review happened. Without it an amend
        # receipt survived a *second* amend: after the first, the prospective
        # parents are the same, so an unchanged tree matched a stale receipt.
        # A metadata-only amend then passed on a review of the amend before it.
        "reviewed_head": head_now,
        "ruling": args.ruling,
        # Recorded, because `pre-commit` cannot find out on its own — git tells
        # a hook nothing about `--amend`.
        "amend": bool(args.amend),
        "reviewer": args.reviewer,
        "reason": (args.reason or "").strip() or None,
        # What the reviewer was actually given. A `ready` over a change
        # delivered in part is this product's own defect, one level up.
        "diff_bytes": args.diff_bytes,
        "delivered_whole": args.complete,
        "written_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    path, why = receipt_path(root)
    if path is None:
        print("could not work out where to write the receipt: {}".format(why),
              file=sys.stderr)
        return 2
    # A unique temporary name, not a fixed `.tmp`: two writers on the fixed one
    # replace each other's bytes and the loser then reports on a receipt it did
    # not write. `os.replace` is atomic on one filesystem, so a half-written
    # file is never what the gate reads.
    handle, tmp_name = tempfile.mkstemp(dir=str(path.parent),
                                        prefix=path.name + ".", suffix=".tmp")
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as out:
            out.write(json.dumps(receipt, indent=2) + "\n")
            out.flush()
            os.fsync(out.fileno())
        os.replace(tmp_name, path)
    except OSError as exc:
        Path(tmp_name).unlink(missing_ok=True)
        print("the receipt could not be written: {}".format(exc),
              file=sys.stderr)
        return 2
    print("receipt written: {} {} parents={} tree={}".format(
        args.ruling, args.reviewer, len(receipt["parents"]),
        receipt["tree"][:12]))
    return 0


def identity_problems(root, receipt, amend_flag=False):
    """Everything the receipt must still match, or the reasons it does not.

    Extracted so that **both** hooks run it. `pre-commit` ran it and
    `commit-msg` did not, and git does real work between the two: it obtains
    and edits the message, and it runs `prepare-commit-msg`. Anything in that
    window — another shell, or `prepare-commit-msg` itself — can stage a change
    the reviewer never saw, and the message half would then wave through
    exactly the content half this gate exists to stop. The original failure
    class, moved one hook later. Codex, 2026-09-05.
    """
    # An amend is not announced to `pre-commit`: git passes it no argument and
    # sets no variable that says so. Taking `--amend` from the caller made the
    # tests pass and the hook wrong — a properly reviewed amend would have been
    # refused by the real gate. So the receipt says which kind of commit it was
    # written for, and this compares against that. A receipt written for an
    # amend still cannot pass as an ordinary commit, because its parents differ.
    amend = amend_flag or bool(receipt.get("amend"))
    identity, why = prospective(root, amend=amend)
    if identity is None:
        return ["{}\n    Could not work out what would be committed, so the "
                "receipt could not be matched against it.".format(why)]

    problems = []
    if receipt.get("tree") != identity["tree"]:
        problems.append(
            "the staged content is not what was reviewed\n"
            "      reviewed: {}\n"
            "      staged:   {}\n"
            "    Something was edited or staged after the review. This is the "
            "exact failure this gate exists for.".format(
                str(receipt.get("tree"))[:16], identity["tree"][:16]))
    if list(receipt.get("parents") or []) != identity["parents"]:
        problems.append(
            "the commit would sit on different parents than the review did\n"
            "      reviewed: {}\n"
            "      now:      {}".format(
                receipt.get("parents"), identity["parents"]))
    if receipt.get("ruling") == "blocked":
        problems.append("the reviewer ruled `blocked`" + (
            ": " + receipt["reason"] if receipt.get("reason") else ""))
    if receipt.get("ruling") not in RULINGS:
        problems.append("the receipt carries no ruling this gate recognises: "
                        "{!r}".format(receipt.get("ruling")))
    if receipt.get("ruling") == "ready" and receipt.get("delivered_whole") is not True:
        # `is not True`, not `is False`. The flag defaulted to `None` and this
        # test read only the literal `False`, so the ordinary command —
        # `write --ruling ready` — produced an approved receipt that asserted
        # nothing about what the reviewer had actually been given. Absence read
        # as agreement, in the gate built to stop exactly that.
        problems.append(
            "the receipt does not say the reviewer was shown the whole "
            "change ({}). Pass `--complete` when the review saw all of it; "
            "a ruling over part of a change is a ruling about a different "
            "change.".format(
                "recorded: {!r}".format(receipt.get("delivered_whole"))
                if "delivered_whole" in receipt else "the field is absent"))
    if receipt.get("ruling") == "bypass" and not str(
            receipt.get("reason") or "").strip():
        # Checked here as well as at write. The receipt is the trust boundary,
        # and a hand-written one skips every check the writer performs.
        # `str(...)`: a numeric reason crashed `.strip()`, which fails closed
        # but as the uncontrolled kind of refusal this file refuses to make.
        problems.append("the receipt claims a bypass and gives no reason")

    # Where HEAD was when the review happened. Without this an amend receipt
    # survived a *second* amend: after the first, the prospective parents are
    # identical, so an unchanged tree still matched. A metadata-only amend then
    # passed on the review of the amend before it.
    head_now, why_head = git("rev-parse", "HEAD", cwd=root)
    reviewed_head = receipt.get("reviewed_head")
    if "reviewed_head" not in receipt:
        problems.append(
            "the receipt does not say where HEAD was when it was written, so "
            "nothing establishes that it is not left over from an earlier "
            "commit on the same tree")
    elif reviewed_head != head_now:
        problems.append(
            "HEAD has moved since the review\n"
            "      reviewed at: {}\n"
            "      now:         {}\n"
            "    The receipt is left over from a commit that has already "
            "been made.".format(
                str(reviewed_head)[:16] if reviewed_head else "(no commits)",
                (head_now or "(no commits)")[:16]))

    return problems


def load_or_refuse(root):
    """`(receipt, None)` or `(None, exit_code)`, having said why."""
    receipt, why = load(root)
    if why:
        print("REFUSED: {}\n  A receipt that cannot be read is not a receipt."
              .format(why), file=sys.stderr)
        return None, 1
    if receipt is None:
        print("REFUSED: no review on record for this commit.\n"
              "  Put the change in front of the reviewer, then:\n"
              "    tools/review_receipt.py write --ruling ready\n"
              "  Or, if this genuinely has to go in unreviewed:\n"
              "    tools/review_receipt.py write --ruling bypass "
              "--reason '...'", file=sys.stderr)
        return None, 1
    return receipt, None


def cmd_check(args) -> int:
    root, why = repo_root()
    if root is None:
        print("not a git repository: {}".format(why), file=sys.stderr)
        return 2

    receipt, code = load_or_refuse(root)
    if receipt is None:
        return code

    problems = identity_problems(root, receipt, args.amend)
    if problems:
        print("REFUSED:", file=sys.stderr)
        for p in problems:
            print("    " + p, file=sys.stderr)
        return 1

    if receipt.get("ruling") == "bypass":
        # Allowed, and never quiet. `check-push` was deleted on Codex's ruling
        # — a check reporting on the wrong object is worse than none — so this
        # is the one place it is announced, and the sentence used to promise a
        # second announcement that no longer exists.
        print("BYPASS: committing without a review — {}".format(
            receipt.get("reason")))
        return 0

    print("reviewed: {} by {} at {}".format(
        receipt.get("ruling"), receipt.get("reviewer"),
        receipt.get("written_at")))
    return 0


def cmd_check_message(args) -> int:
    """What `commit-msg` runs: is this the message the reviewer was shown?

    The other half of the failure. Twice on 2026-09-03 the commit message
    described behaviour the committed code did not have — and `check` above
    catches only the content half. A gate that proves the reviewed *code* went
    in, and says nothing about the reviewed *message*, is a gate that reads as
    more than it is.

    Git strips comment lines and trailing whitespace before it writes the
    message into the commit, so the digest is taken over the stripped form on
    both sides. Comparing the raw file would fail for a comment the author
    never sees.
    """
    root, why = repo_root()
    if root is None:
        print("not a git repository: {}".format(why), file=sys.stderr)
        return 2

    receipt, code = load_or_refuse(root)
    if receipt is None:
        return code

    # The whole identity again, not only the message. `pre-commit` checked the
    # tree and then git obtained the message and ran `prepare-commit-msg`;
    # anything staged in that window was never reviewed, and this hook used to
    # let it through on the strength of a matching message. Run for a bypass
    # receipt too: a bypass excuses the review, not the question of which
    # content is being committed. Codex, 2026-09-05.
    problems = identity_problems(root, receipt)
    if problems:
        print("REFUSED:", file=sys.stderr)
        for p in problems:
            print("    " + p, file=sys.stderr)
        print("    Checked again here because the content can change between "
              "`pre-commit` and `commit-msg`.", file=sys.stderr)
        return 1

    if receipt.get("ruling") == "bypass":
        # A bypass still has to be a real one. Returning success on the word
        # alone let a hand-written receipt skip the reason check that `check`
        # performs — the receipt is the trust boundary and every reader of it
        # has to say so.
        if not str(receipt.get("reason") or "").strip():
            print("REFUSED: the receipt claims a bypass and gives no reason.",
                  file=sys.stderr)
            return 1
        return 0

    try:
        raw = Path(args.message_file).read_bytes()
    except OSError as exc:
        print("REFUSED: the commit message could not be read ({}). Unread is "
              "not the same as unchanged.".format(exc), file=sys.stderr)
        return 1

    recorded = receipt.get("message_digest")
    if recorded is None:
        print("REFUSED: the review was recorded without a commit message, so "
              "nothing here establishes that the reviewer saw the message "
              "that is about to be committed.\n"
              "  Write the message first, then review, then:\n"
              "    tools/review_receipt.py write --ruling ready "
              "--message-file <file>", file=sys.stderr)
        return 1

    normalised, why = normalise_message(raw, cwd=str(root))
    if normalised is None:
        print("REFUSED: git could not normalise the commit message ({}), so "
              "it could not be compared with the reviewed one.".format(why),
              file=sys.stderr)
        return 1

    if digest(normalised) != recorded:
        print("REFUSED: the commit message is not the one that was reviewed.\n"
              "  Both of the failures this gate exists for had a message "
              "describing behaviour the code did not have.", file=sys.stderr)
        return 1
    return 0


def cmd_check_push(args) -> int:
    """Deleted 2026-09-03, and kept as a note so it is not rebuilt.

    It read the receipt's `ruling` and never looked at the refs being pushed,
    so it could miss bypassed history entirely and attribute a bypass to
    whatever HEAD happened to be. Its two tests passed because they exercised
    that same wrong thing.

    Codex: delete it. A check that reports on the wrong object is worse than no
    check, because its silence is read as coverage. A real `pre-push` would
    take the pushed ranges from stdin and want a receipt per commit — which
    this receipt, covering one prospective commit, is not.
    """
    print("check-push was removed; see the note in the source.",
          file=sys.stderr)
    return 2


def cmd_show(args) -> int:
    root, why = repo_root()
    if root is None:
        print("not a git repository: {}".format(why), file=sys.stderr)
        return 2
    receipt, why = load(root)
    if why:
        print(why, file=sys.stderr)
        return 2
    if receipt is None:
        print("no receipt on record.")
        return 0
    print(json.dumps(receipt, indent=2))
    identity, _ = prospective(root)
    if identity:
        print()
        print("staged tree now: {}  {}".format(
            identity["tree"][:16],
            "matches" if identity["tree"] == receipt.get("tree")
            else "DIFFERENT from the reviewed one"))
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)

    write = sub.add_parser("write", help="record a review of what is staged")
    write.add_argument("--ruling", choices=RULINGS, required=True)
    write.add_argument("--reviewer", default="codex")
    write.add_argument("--reason", default="")
    write.add_argument("--message-file",
                       help="the commit message the reviewer was shown")
    write.add_argument("--diff-bytes", type=int, default=None)
    write.add_argument("--complete", action="store_true", default=None,
                       help="the reviewer was shown the whole change")
    write.add_argument("--amend", action="store_true")
    write.set_defaults(func=cmd_write)

    check = sub.add_parser("check", help="what pre-commit runs")
    check.add_argument("--amend", action="store_true")
    check.set_defaults(func=cmd_check)

    msg = sub.add_parser("check-message", help="what commit-msg runs")
    msg.add_argument("message_file")
    msg.set_defaults(func=cmd_check_message)

    push = sub.add_parser("check-push", help="what pre-push runs")
    push.set_defaults(func=cmd_check_push)

    show = sub.add_parser("show", help="what is on record")
    show.set_defaults(func=cmd_show)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
