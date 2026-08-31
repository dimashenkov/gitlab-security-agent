"""Sandboxed, read-only access to the repository under review.

Every tool goes through this class. The agent is reading code that an untrusted
contributor may have authored, so the boundary has to hold against a repository
that is actively trying to escape it: a symlink pointing at ``/`` , a path
argument of ``../../etc/shadow``, a ``.gitattributes`` that invokes an external
diff driver. Two rules follow from that, and they are enforced here rather than
in each tool:

* Paths are resolved and then checked for containment under the repo root,
  after symlink resolution — never by string prefix on the unresolved path.
* Git runs with ``--no-ext-diff`` and no shell, so nothing in the repository can
  choose what process gets executed.
"""

from __future__ import annotations

import fnmatch
import logging
import subprocess
import time
from pathlib import Path
from typing import List, Optional, Sequence, Tuple

log = logging.getLogger(__name__)


class WorkspaceError(Exception):
    """A tool argument was rejected, or git could not answer the question."""


# Ceilings that keep one tool call from filling the context window. Tools report
# when they trim, so the agent knows to narrow its request rather than assuming
# it saw everything.
MAX_READ_BYTES = 300_000
MAX_OUTPUT_CHARS = 60_000
# A hard stop on how many matches are read at all, independent of how
# many are shown. The pattern is chosen by the model.
MAX_SEARCH_HITS = 20_000
GIT_TIMEOUT_SECONDS = 120


class Workspace:
    def __init__(
        self,
        root: Path,
        excludes: Sequence[str] = (),
        diff_base: str = "",
        diff_head: str = "HEAD",
        scope: Sequence[str] = (),
        diff_ceiling: int = 0,
        default_context_lines: int = 12,
    ) -> None:
        self.root = root.resolve()
        if not (self.root / ".git").exists():
            raise WorkspaceError("{} is not a git repository".format(self.root))
        self.excludes = tuple(excludes)
        # Narrows the change under review. Never narrows what can be read — see
        # `Config.scope`, and `changed_line_map`, which deliberately ignores it.
        self.scope = tuple(s for s in scope if s and s.strip())
        self.diff_base = diff_base
        self.diff_head = diff_head
        # How much context a diff carries when the model does not ask for a
        # number. It used to be a constant in `tools.py`, so
        # `SECURITY_SCAN_CONTEXT_LINES` was read from the environment, stored on
        # the config, and never consulted — a documented control that changed
        # nothing. Negative is refused rather than clamped: it can only come
        # from a typo, and silently reading it as 0 would answer a question
        # nobody asked. Zero itself is allowed and means hunks with no context.
        if default_context_lines < 0:
            raise WorkspaceError(
                "context lines cannot be negative, got {}".format(
                    default_context_lines))
        self.default_context_lines = default_context_lines
        self._tracked: Optional[List[str]] = None
        # Set when a diff was cut off at the ceiling. Recorded rather than only
        # said in prose: a sentence in the model's context is guidance, and an
        # attacker can write the same sentence. This is the accounting, and it
        # reaches the artifact so a report cannot claim coverage the run did not
        # have.
        self.diff_truncated = False
        # Zero means "use the class default". Held rather than defaulted at the
        # call site so `diff_ceiling` has one answer.
        self._diff_ceiling = max(0, int(diff_ceiling))
        self._changed_lines: Optional[dict] = None

    # ---------------------------------------------------------------- paths

    def resolve(self, relative: str) -> Path:
        """Map a repo-relative path from the model onto a real, contained file."""
        if not relative or not relative.strip():
            raise WorkspaceError("path must not be empty")
        candidate = relative.strip()
        if candidate.startswith("/"):
            # Treat an absolute-looking path as repo-relative rather than
            # rejecting it; the model often writes "/src/app.py" for "src/app.py".
            candidate = candidate.lstrip("/")

        target = (self.root / candidate).resolve()
        if target != self.root and self.root not in target.parents:
            raise WorkspaceError(
                "path {!r} resolves outside the repository; only paths inside the "
                "repository can be read".format(relative)
            )
        return target

    def repo_path(self, relative: str) -> str:
        """Normalise a path from the model for addressing the git tree.

        Deliberately does not touch the filesystem. `resolve()` exists to keep
        *filesystem* reads inside the checkout, and it does that by following
        symlinks — correct for reading a file, wrong for naming a blob. A
        symlink committed to the repository is a legitimate object with content
        of its own, and resolving it would reject it for pointing outside the
        tree, which is exactly the thing we want to be able to look at.

        Traversal is rejected lexically instead: no component may be `..`, and
        the result never escapes the root because it never leaves the string.
        """
        if not relative or not relative.strip():
            raise WorkspaceError("path must not be empty")
        candidate = relative.strip().lstrip("/")
        parts = []
        for part in candidate.split("/"):
            if part in ("", "."):
                continue
            if part == "..":
                raise WorkspaceError(
                    "path {!r} points outside the repository".format(relative))
            parts.append(part)
        if not parts:
            raise WorkspaceError("path must not be empty")
        return "/".join(parts)

    def relative(self, path: Path) -> str:
        try:
            return str(path.relative_to(self.root))
        except ValueError:
            return str(path)

    def is_excluded(self, path: str) -> bool:
        """Match a repo-relative path against the exclude globs.

        Patterns are tested against ``path`` and ``/path`` so a directory
        pattern like ``*/vendor/*`` matches a top-level ``vendor/`` as well as a
        nested one.
        """
        candidates = (path, "/" + path)
        name = path.rsplit("/", 1)[-1]
        for pattern in self.excludes:
            if any(fnmatch.fnmatch(c, pattern) for c in candidates):
                return True
            if "/" not in pattern and fnmatch.fnmatch(name, pattern):
                return True
        return False

    def in_scope(self, path: str) -> bool:
        """Is this changed file one the run is answerable for?

        An empty scope means every changed file, which is the only safe default
        for a gate. A pattern matches as a glob, and a bare directory name
        matches everything under it — `--path src/auth` is what a person means
        when they say "just look at the auth code", and requiring them to write
        `src/auth/*` for that would be a trap rather than a feature.
        """
        if not self.scope:
            return True
        candidates = (path, "/" + path)
        for raw in self.scope:
            pattern = raw.strip().strip("/")
            if not pattern:
                continue
            if any(fnmatch.fnmatch(c, pattern) for c in candidates):
                return True
            if path == pattern or path.startswith(pattern + "/"):
                return True
        return False

    def out_of_scope(self, paths: Sequence[str]) -> List[str]:
        """Changed files this run is not answerable for. For the report.

        A scoped review that reports "no findings" without saying what it did
        not look at is the same sentence as a full review that found nothing,
        and they mean opposite things.
        """
        return [p for p in paths if not self.in_scope(p)]

    # ------------------------------------------------------------------ git

    def git(self, *args: str, check: bool = True) -> str:
        """Run git and return its output, with the two streams decoded differently.

        **stdout with `surrogateescape`.** A file name is a sequence of bytes on
        Linux and need not be UTF-8. Decoding with `errors="replace"` turned any
        such byte into `U+FFFD` here, *before* either path parser saw it — so
        the two views of one change, one reading the NUL form and one parsing a
        textual diff, could not agree on a key however carefully each was
        written. `surrogateescape` is reversible: the bytes survive, both sides
        decode them the same way, and a path that is not text is still an
        identity.

        This was found by a code review of the fix for the *previous* version of
        the same failure, which was a git setting. The setting was necessary and
        was two layers away from sufficient.

        **stderr with `replace`.** It is a message for a person, never a key, and
        a hostile file name inside an error must not be able to make the
        reporting of that error fail.
        """
        try:
            proc = subprocess.run(
                ("git", "--no-pager", "-C", str(self.root), "--no-optional-locks", *args),
                capture_output=True,
                check=False,
                timeout=GIT_TIMEOUT_SECONDS,
                env=_git_env(),
            )
        except subprocess.TimeoutExpired:
            raise WorkspaceError("git {} timed out".format(" ".join(args))) from None
        if check and proc.returncode != 0:
            raise WorkspaceError(
                "git {} failed: {}".format(
                    " ".join(args),
                    proc.stderr.decode("utf-8", "replace").strip() or "no output")
            )
        return proc.stdout.decode("utf-8", "surrogateescape")

    def rev_exists(self, rev: str) -> bool:
        if not rev:
            return False
        proc = subprocess.run(
            ("git", "-C", str(self.root), "rev-parse", "--verify", "--quiet", rev + "^{commit}"),
            capture_output=True,
            text=True,
            check=False,
            env=_git_env(),
        )
        if proc.returncode != 0 and proc.stderr.strip():
            # A missing revision exits non-zero *silently* under --quiet, so
            # anything on stderr means git refused for some other reason —
            # ownership, a corrupt object, a broken environment. Reporting that
            # as "revision not found" sent a whole CI debugging session chasing
            # GIT_DEPTH when the real message was "dubious ownership".
            log.warning("git rev-parse %s: %s", rev, proc.stderr.strip().splitlines()[0])
        return proc.returncode == 0

    def tracked_files(self) -> List[str]:
        if self._tracked is None:
            listing = self.git("ls-files", "-z")
            self._tracked = sorted(
                p for p in listing.split("\0") if p and not self.is_excluded(p)
            )
        return self._tracked

    def changed_files(self) -> List[Tuple[str, str]]:
        """(path, change type) for the range under review, excludes applied."""
        if not self.diff_base:
            return []
        raw = self.git(
            "diff", "--no-color", "--no-ext-diff", "-M", "--name-status", "-z",
            "--diff-filter=ACMRT", self.diff_base, self.diff_head,
        )
        out: List[Tuple[str, str]] = []
        for path, code in _parse_name_status(raw):
            if not self.is_excluded(path) and self.in_scope(path):
                out.append((path, _STATUS_NAMES.get(code, code)))
        return out

    def raw_changed_paths(self) -> List[str]:
        """Every path this change touched, with neither filter applied.

        The excludes say what the model may read and the scope says what the
        review is answerable for. Both are the wrong lens for a question about
        what the *change* did — and two such questions exist: does this change
        edit its own suppression file, and does it edit the prompts it is judged
        by. Answering either through a filtered list hands a committed exclude
        pattern the power to switch the guard off.

        Rename detection is off for the same reason it is off in
        `change_touches`: with `-M` a rename reports only its new path, so a
        change that moved a guarded file *away* reads as having left it alone.
        """
        if not self.diff_base:
            return []
        raw = self.git(
            "diff", "--no-color", "--no-ext-diff", "--no-renames",
            "--name-status", "-z", self.diff_base, self.diff_head,
        )
        return [path for path, _ in _parse_name_status(raw)]

    def change_touches(self, relative: str) -> bool:
        """Does the change under review edit this exact file?

        Asks git, and applies neither the excludes nor the scope. Both of those
        say what this *review* is answerable for; this question is about what
        the *change* did, and the one caller is the guard that stops a merge
        request from suppressing its own findings. A file hidden from the review
        by an exclude pattern is still a file the change edited, and letting an
        exclusion decide whether that guard fires would hand the exclusion the
        power to switch the guard off.

        Deleted paths count, and so does a rename in either direction. Removing
        the rules, or moving them somewhere the review will not read them, is an
        edit to the rules. `-M` is deliberately **not** passed for that reason:
        with rename detection on, `_parse_name_status` reports only the new path
        of a rename, so a change that renamed the suppression file away read as
        having left it alone.

        Three failures found by this agent reviewing this function, on the first
        real run of the CLI runner. This one, the `check=False` below, and the
        case comparison — all three fail *open* on a security control, which is
        the direction that does not announce itself.
        """
        if not self.diff_base:
            return False
        wanted = self.repo_path(relative)
        # `check=True`, unlike the first version. A non-zero git exit returned
        # an empty string, `any()` over nothing is False, and the guard reported
        # "the change did not touch its own suppression file" — a fail-open on
        # the one control that stops a merge request approving itself, arriving
        # silently. Its sibling `changed_files` has always raised here. If git
        # cannot answer, the run fails with exit 2 rather than guessing.
        raw = self.git(
            "diff", "--no-color", "--no-ext-diff", "--no-renames",
            "--name-status", "-z", self.diff_base, self.diff_head,
        )
        paths = [path for path, _ in _parse_name_status(raw)]
        if any(path == wanted for path in paths):
            return True

        # A last comparison, folded, for a case-insensitive filesystem. macOS
        # and Windows runners open `.Security-Agent-Ignore.yml` when asked for
        # `.security-agent-ignore.yml`, so the rules would load and the guard
        # would miss. Deliberately only in this direction: a fold that decided
        # two genuinely different files were the same would over-fire the
        # guard, which costs an argument, while under-firing costs the gate.
        folded = wanted.lower()
        return any(path.lower() == folded for path in paths)

    def all_changed_files(self) -> List[Tuple[str, str]]:
        """Every changed file, scope ignored. What the report needs to be honest.

        `changed_files` is what the reviewer works from; this is what says how
        much of the change that was.
        """
        saved, self.scope = self.scope, ()
        try:
            return self.changed_files()
        finally:
            self.scope = saved

    def every_changed_file(self) -> List[Tuple[str, str]]:
        """Every changed file, with neither the excludes nor the scope applied.

        `changed_files` applies both, so when it comes back empty the caller
        cannot tell which of the two emptied it — and the report told every
        reader it was their exclude patterns, including the reader whose
        `--path` did it. This is the unfiltered list the two predicates are
        then asked about one at a time.

        Same diff filter as `changed_files`, and deliberately unlike
        `raw_changed_paths`: the question here is what *could* have been
        reviewed, so a deleted file is correctly absent rather than counted as
        something a rule hid.
        """
        saved_excludes, saved_scope = self.excludes, self.scope
        self.excludes, self.scope = (), ()
        try:
            return self.changed_files()
        finally:
            self.excludes, self.scope = saved_excludes, saved_scope

    def diff(self, path: str = "", context_lines: Optional[int] = None) -> str:
        if not self.diff_base:
            raise WorkspaceError(
                "no diff base is available for this run (not a merge request "
                "pipeline). Use the file-reading tools instead."
            )
        args = [
            "diff", "--no-color", "--no-ext-diff", "-M",
            "--unified={}".format(max(0, min(
                self.default_context_lines if context_lines is None
                else context_lines, 100))),
            self.diff_base, self.diff_head,
        ]
        if path:
            args += ["--", self.repo_path(path)]
        elif self.scope:
            # The resolved file list rather than the patterns themselves. A git
            # pathspec has its own magic prefixes and its own glob rules, and a
            # scope that meant one thing to `in_scope` and another to git would
            # put a file in the diff that the coverage accounting says was never
            # in the change.
            in_scope = [p for p, _ in self.changed_files()]
            if not in_scope:
                return ""
            args += ["--", *(self.repo_path(p) for p in in_scope)]
        return self._bounded(args)

    # How much of a diff is read before the pipe is closed.
    #
    # Derived from what the only consumer asks for, not chosen for feeling
    # roomy. `get_diff` trims to 120,000 characters before the model sees
    # anything, so reading megabytes past that is work with no review value.
    # This is that ceiling with room for the worst case of multi-byte encoding,
    # the diff's own headers, and one read of overshoot.
    #
    # A genuine change can exceed it, and when one does the run says the diff
    # was partial rather than implying the change was abnormal.
    MAX_DIFF_BYTES = 512 * 1024

    @property
    def diff_ceiling(self) -> int:
        """The ceiling actually in force, which an operator can raise.

        The gate tells a reader of a truncated review that they may raise this;
        that sentence was false when it was written, because the number was a
        constant with no configuration surface. A remedy nobody can perform is
        worse than none — it moves the blame to a reader who cannot act.
        """
        return self._diff_ceiling or self.MAX_DIFF_BYTES

    def _bounded(self, args: List[str]) -> str:
        """Read git's output up to a ceiling, then stop reading.

        `subprocess.run(capture_output=True)` reads the whole pipe into memory
        before returning, and the size of a diff is chosen by whoever opened the
        merge request. Four repetitive files of half a gigabyte each compress to
        almost nothing in the repository and expand to about two gigabytes here:
        an out-of-memory kill on a shared runner, comfortably inside the git
        timeout.

        That is the one failure that defeats the exit-2 contract. A SIGKILL is
        not an exception — `main`'s `except` never runs, no artifact is written,
        no comment is posted, and the previous run's green note stays on the
        merge request describing code that is no longer there.

        `search()` was hardened against exactly this and `diff()` was not, which
        is the whole finding: the reasoning was written down one function away
        and did not travel.
        """
        deadline = time.monotonic() + GIT_TIMEOUT_SECONDS
        try:
            proc = subprocess.Popen(
                ("git", "--no-pager", "-C", str(self.root),
                 "--no-optional-locks", *args),
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                env=_git_env(),
            )
        except OSError as exc:
            raise WorkspaceError("git {} failed: {}".format(
                " ".join(args), exc)) from None

        chunks: List[bytes] = []
        size = 0
        truncated = False
        try:
            while True:
                if time.monotonic() > deadline:
                    truncated = True
                    break
                chunk = proc.stdout.read(65_536)
                if not chunk:
                    break
                chunks.append(chunk)
                size += len(chunk)
                if size >= self.diff_ceiling:
                    truncated = True
                    break
        finally:
            # Killed rather than drained: draining is what an unbounded read
            # does, and the point of stopping was not to hold the rest.
            if truncated:
                proc.kill()
            proc.stdout.close()
            proc.wait()

        body = b"".join(chunks).decode("utf-8", "surrogateescape")
        if truncated:
            self.diff_truncated = True
            # Said in the output the model reads, because a diff that stops
            # halfway through a file looks exactly like a file that ends there.
            body = body.rsplit("\n", 1)[0] + (
                "\n… this diff was cut off at {} bytes. What follows it was not "
                "read, and a change this large has not been fully reviewed."
                .format(self.diff_ceiling))
        return body

    def changed_line_map(self):
        """Lines this change is answerable for, per file, computed once.

        Used to tell a weakness this change introduced from one that was already
        there. Empty outside a merge request, where the distinction is moot.

        **Scope is deliberately ignored here.** This map answers "did the change
        touch this line", which is a fact about the change and not about what
        this run was asked to look at. Narrowing it would make a finding in an
        out-of-scope file look pre-existing, and pre-existing findings are gated
        more softly — so a scope flag, whose whole purpose is to look at less,
        would quietly make the gate more permissive about what it did look at.
        """
        if self._changed_lines is None:
            from .evidence import changed_lines  # local import: avoids a cycle

            if not self.diff_base:
                from .evidence import ChangedLines

                self._changed_lines = ChangedLines()
            else:
                raw = self.git(
                    "diff", "--no-color", "--no-ext-diff", "-M", "--unified=0",
                    self.diff_base, self.diff_head, check=False,
                )
                self._changed_lines = changed_lines(raw)
        return self._changed_lines

    # ----------------------------------------------------------------- read

    def blob_text(self, path: str) -> str:
        """The file's contents **at the revision under review**, not from disk.

        Reading the working tree looks equivalent and is not. The checkout is
        material an untrusted contributor controls, and what sits at a path on
        disk need not be what the commit says is there: a symlink, a file
        written by an earlier job step, a `.gitattributes` filter, or anything
        else that touched the directory between checkout and review. A finding
        must describe the code that is actually proposed for merge, and the only
        authority on that is the object database.

        `git show <rev>:<path>` resolves through the tree of that commit, so a
        symlink is returned as its own content — a link — rather than followed
        to whatever it points at.
        """
        rel = self.repo_path(path)
        rev = self.diff_head or "HEAD"

        size = self._blob_size(rev, rel)
        if size is None:
            raise WorkspaceError(
                "{} is not a tracked file at the revision under review".format(rel))
        if size > MAX_READ_BYTES:
            raise WorkspaceError(
                "{} is {} KB, over the {} KB read limit. Pass start_line and "
                "end_line to read a window of it.".format(
                    rel, size // 1024, MAX_READ_BYTES // 1024))

        try:
            proc = subprocess.run(
                ("git", "--no-pager", "-C", str(self.root), "show",
                 "{}:{}".format(rev, rel)),
                capture_output=True, check=False, timeout=GIT_TIMEOUT_SECONDS,
                env=_git_env(),
            )
        except subprocess.TimeoutExpired:
            raise WorkspaceError("reading {} timed out".format(rel)) from None
        if proc.returncode != 0:
            raise WorkspaceError("cannot read {} at {}: {}".format(
                rel, _abbrev(rev), proc.stderr.decode("utf-8", "replace").strip()))

        try:
            return proc.stdout.decode("utf-8")
        except UnicodeDecodeError:
            raise WorkspaceError("{} is not UTF-8 text (binary file)".format(rel)) from None

    def _blob_size(self, rev: str, rel: str) -> Optional[int]:
        """Size of the blob at that revision, or None when the path is not one.

        The type is checked first because `cat-file -s` answers for a tree as
        happily as for a blob, so without it a directory reads as a file of some
        size and the failure surfaces much later and less clearly.

        Size is checked before reading so an enormous file is refused rather
        than pulled into memory first.
        """
        kind = subprocess.run(
            ("git", "-C", str(self.root), "cat-file", "-t", "{}:{}".format(rev, rel)),
            capture_output=True, text=True, check=False, env=_git_env(),
        )
        if kind.returncode != 0 or kind.stdout.strip() != "blob":
            return None

        proc = subprocess.run(
            ("git", "-C", str(self.root), "cat-file", "-s", "{}:{}".format(rev, rel)),
            capture_output=True, text=True, check=False, env=_git_env(),
        )
        if proc.returncode != 0:
            return None
        try:
            return int(proc.stdout.strip())
        except ValueError:
            return None

    # `raw_text` is the name the rest of the agent uses; it now means "the blob
    # at the reviewed revision" everywhere.
    raw_text = blob_text

    def read_file(self, path: str, start_line: int = 1, end_line: int = 0) -> Tuple[str, bool]:
        """Return line-numbered text and whether it was trimmed."""
        rel = self.repo_path(path)
        text = self.blob_text(path)

        lines = text.splitlines()
        total = len(lines)
        start = max(1, start_line)
        stop = total if end_line <= 0 else min(total, end_line)
        if start > total:
            raise WorkspaceError(
                "{} has {} lines; start_line {} is past the end".format(rel, total, start))

        selected = lines[start - 1 : stop]
        body = "\n".join(
            "{:>6} | {}".format(n, line) for n, line in enumerate(selected, start=start)
        )
        trimmed = False
        if len(body) > MAX_OUTPUT_CHARS:
            body = body[:MAX_OUTPUT_CHARS]
            trimmed = True
        header = "{} (lines {}-{} of {})".format(rel, start, stop, total)
        return "{}\n{}".format(header, body), trimmed

    def list_directory(self, path: str = "", depth: int = 1) -> str:
        """List tracked entries under a directory, depth-limited."""
        target = self.resolve(path) if path.strip(" /") else self.root
        rel_root = self.relative(target)
        prefix = "" if target == self.root else rel_root.rstrip("/") + "/"

        if prefix and not any(p.startswith(prefix) for p in self.tracked_files()):
            if not target.exists():
                raise WorkspaceError("{} does not exist".format(rel_root))
            raise WorkspaceError("{} contains no tracked files".format(rel_root))

        depth = max(1, min(depth, 6))
        dirs = set()
        files = []
        for tracked in self.tracked_files():
            if prefix and not tracked.startswith(prefix):
                continue
            remainder = tracked[len(prefix) :]
            parts = remainder.split("/")
            if len(parts) <= depth:
                files.append(remainder)
            else:
                dirs.add("/".join(parts[:depth]) + "/")

        entries = sorted(dirs) + sorted(files)
        body = "\n".join(entries) if entries else "(no tracked files)"
        if len(body) > MAX_OUTPUT_CHARS:
            shown = body[:MAX_OUTPUT_CHARS].rsplit("\n", 1)[0]
            body = shown + "\n… list trimmed; narrow the path or reduce depth"
        return "{} ({} entries)\n{}".format(prefix or ".", len(entries), body)

    def search(
        self,
        pattern: str,
        path_glob: str = "",
        max_results: int = 80,
        case_sensitive: bool = False,
        context_lines: int = 0,
    ) -> Tuple[str, int]:
        """Regex search over tracked files via ``git grep``.

        Returns (rendered results, match count). ``git grep`` is used rather
        than a shell pipeline so the pattern is passed as an argv element and is
        never interpreted by a shell.
        """
        if not pattern.strip():
            raise WorkspaceError("pattern must not be empty")
        max_results = max(1, min(max_results, 300))
        args = ["grep", "--no-color", "-n", "-E", "-I"]
        if not case_sensitive:
            args.append("-i")
        if context_lines > 0:
            args.append("-C{}".format(min(context_lines, 10)))
        args += ["-e", pattern]
        if path_glob:
            args += ["--", ":(glob)" + path_glob.lstrip("/")]

        # Read as it arrives and stop at the ceiling, rather than collecting
        # everything and trimming afterwards. `capture_output=True` buffers the
        # whole of stdout first, and the size of that is chosen by the pattern
        # — which the model picks, and which repository prose can push toward
        # something broad. A result large enough to exhaust memory ends in a
        # SIGKILL, and a killed process cannot write "the review did not
        # complete": it is the one failure that defeats the exit-2 contract,
        # because `except Exception` never runs.
        hits, truncated = self._grep_stream(args)
        total = len(hits)
        if total == 0:
            return "no matches for {!r}".format(pattern), 0

        shown = hits[:max_results]
        body = "\n".join(shown)
        if len(body) > MAX_OUTPUT_CHARS:
            body = body[:MAX_OUTPUT_CHARS].rsplit("\n", 1)[0] + "\n… output trimmed"
        note = ""
        if truncated:
            # "At least", never a total. Counting the rest means reading the
            # rest, which is the thing being avoided — and a fabricated total
            # is worse than an honest floor.
            note = ("\n… stopped after {} match(es); there are more. Narrow the "
                    "pattern or set path_glob.".format(total))
        elif total > len(shown):
            note = "\n… {} more match(es) not shown; narrow the pattern or set path_glob".format(
                total - len(shown)
            )
        head = "at least {}".format(total) if truncated else str(total)
        return "{} match(es) for {!r}:\n{}{}".format(head, pattern, body, note), total

    def _grep_stream(self, args):
        """Run `git grep` and stop reading at the ceiling.

        Returns (kept lines, whether more were left unread). Excluded paths are
        filtered as the lines arrive, so an excluded directory cannot fill the
        budget with output that would have been discarded anyway.
        """
        deadline = time.monotonic() + GIT_TIMEOUT_SECONDS
        proc = subprocess.Popen(
            ("git", "--no-pager", "-C", str(self.root), *args),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, errors="replace", env=_git_env(),
        )
        hits, size, truncated = [], 0, False
        try:
            for raw in proc.stdout:
                if time.monotonic() > deadline:
                    truncated = True
                    break
                line = raw.rstrip("\n")
                if not line or self.is_excluded(line.split(":", 1)[0]):
                    continue
                hits.append(line)
                size += len(line) + 1
                # Twice the rendered ceiling: enough that `max_results` and the
                # character trim still have something to choose from, bounded
                # enough that the process cannot be killed for holding it.
                if size > MAX_OUTPUT_CHARS * 2 or len(hits) > MAX_SEARCH_HITS:
                    truncated = True
                    break
        finally:
            if truncated:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
            # stderr is read after stdout is done with, and capped for the same
            # reason: an error message is not a channel worth trusting either.
            stderr = (proc.stderr.read(4_000) if proc.stderr else "") or ""
            proc.stdout.close()
            if proc.stderr:
                proc.stderr.close()
            code = proc.wait()

        if truncated:
            return hits, True
        # git grep exits 1 for "no matches", which is a valid answer.
        if code not in (0, 1):
            raise WorkspaceError(
                "search failed: {}".format(stderr.strip() or "invalid pattern"))
        return hits, False


def _abbrev(rev: str) -> str:
    """Shorten a SHA for a message, but never a branch name."""
    if len(rev) > 12 and all(c in "0123456789abcdef" for c in rev.lower()):
        return rev[:12]
    return rev


def _git_env() -> dict:
    """A minimal environment for git subprocesses.

    Config files are pinned to nothing on purpose. ``--no-ext-diff`` stops an
    ``external diff`` driver from running, but only if the config defining it is
    never read, and a repository can ship a ``.gitconfig`` that gets picked up
    when ``HOME`` points into the tree. So ``HOME`` goes somewhere that does not
    exist and both config files are routed to ``/dev/null``.

    That leaves one problem, and it is the reason for the ``safe.directory``
    entry below. A CI runner clones the repository as one user and this process
    runs as another, so git refuses it with "detected dubious ownership" — which
    is a sensible default for a shared machine and pointless here, where the
    checkout is the very thing we were asked to read. The usual fix is
    ``safe.directory`` in *system* config, but that file is exactly what the
    hardening above stops git from reading. Injecting the setting through
    ``GIT_CONFIG_COUNT`` keeps both properties: no config file is trusted, and
    the ownership check is still waived.
    """
    return {
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "HOME": "/nonexistent",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_SYSTEM": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_COUNT": "2",
        "GIT_CONFIG_KEY_0": "safe.directory",
        "GIT_CONFIG_VALUE_0": "*",
        # Git quotes any path holding a byte over 0x7f, and this defaults to on.
        # `src/café.py` comes out of a plain diff as `"b/src/caf\303\251.py"` —
        # a string no caller can look up. The changed-line map is built from a
        # plain diff, so an accented character in a file name put every finding
        # in that file under a key nothing matched: attribution came back empty,
        # `in_changed_lines` was false, and the gate skips a finding it believes
        # was already there. One character in a path, and a confirmed critical
        # stopped blocking.
        #
        # Set here rather than at the one call site because the same quoting
        # would silently mis-key anything else parsed from a textual diff, and
        # the next such parser will not remember to ask.
        "GIT_CONFIG_KEY_1": "core.quotePath",
        "GIT_CONFIG_VALUE_1": "false",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_OPTIONAL_LOCKS": "0",
        "LC_ALL": "C.UTF-8",
    }


_STATUS_NAMES = {
    "A": "added",
    "C": "copied",
    "M": "modified",
    "R": "renamed",
    "T": "type changed",
}


def _parse_name_status(raw: str):
    """Parse ``git diff --name-status -z`` output.

    The NUL-separated form emits ``status\\0path\\0`` for most changes, but
    renames and copies emit ``status\\0old\\0new\\0`` — three fields — so the
    stream has to be walked rather than chunked in pairs.
    """
    fields = [f for f in raw.split("\0") if f != ""]
    i = 0
    while i < len(fields):
        code = fields[i][:1]
        if code in ("R", "C"):
            if i + 2 >= len(fields):
                break
            yield fields[i + 2], code  # report against the new path
            i += 3
        else:
            if i + 1 >= len(fields):
                break
            yield fields[i + 1], code
            i += 2
