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
GIT_TIMEOUT_SECONDS = 120


class Workspace:
    def __init__(
        self,
        root: Path,
        excludes: Sequence[str] = (),
        diff_base: str = "",
        diff_head: str = "HEAD",
    ) -> None:
        self.root = root.resolve()
        if not (self.root / ".git").exists():
            raise WorkspaceError("{} is not a git repository".format(self.root))
        self.excludes = tuple(excludes)
        self.diff_base = diff_base
        self.diff_head = diff_head
        self._tracked: Optional[List[str]] = None
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

    # ------------------------------------------------------------------ git

    def git(self, *args: str, check: bool = True) -> str:
        try:
            proc = subprocess.run(
                ("git", "--no-pager", "-C", str(self.root), "--no-optional-locks", *args),
                capture_output=True,
                check=False,
                text=True,
                errors="replace",
                timeout=GIT_TIMEOUT_SECONDS,
                env=_git_env(),
            )
        except subprocess.TimeoutExpired:
            raise WorkspaceError("git {} timed out".format(" ".join(args))) from None
        if check and proc.returncode != 0:
            raise WorkspaceError(
                "git {} failed: {}".format(" ".join(args), proc.stderr.strip() or "no output")
            )
        return proc.stdout

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
            if not self.is_excluded(path):
                out.append((path, _STATUS_NAMES.get(code, code)))
        return out

    def diff(self, path: str = "", context_lines: int = 12) -> str:
        if not self.diff_base:
            raise WorkspaceError(
                "no diff base is available for this run (not a merge request "
                "pipeline). Use the file-reading tools instead."
            )
        args = [
            "diff", "--no-color", "--no-ext-diff", "-M",
            "--unified={}".format(max(0, min(context_lines, 100))),
            self.diff_base, self.diff_head,
        ]
        if path:
            resolved = self.relative(self.resolve(path))
            args += ["--", resolved]
        return self.git(*args, check=False)

    def changed_line_map(self):
        """Lines this change is answerable for, per file, computed once.

        Used to tell a weakness this change introduced from one that was already
        there. Empty outside a merge request, where the distinction is moot.
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

    def raw_text(self, path: str) -> str:
        """File contents with no line numbering, for evidence matching."""
        target = self.resolve(path)
        if not target.is_file():
            raise WorkspaceError("{} is not a file in this checkout".format(self.relative(target)))
        if target.stat().st_size > MAX_READ_BYTES:
            raise WorkspaceError(
                "{} is too large to load ({} KB)".format(
                    self.relative(target), target.stat().st_size // 1024)
            )
        try:
            return target.read_text(encoding="utf-8")
        except UnicodeDecodeError as exc:
            raise WorkspaceError(
                "{} is not UTF-8 text".format(self.relative(target))) from exc
        except OSError as exc:
            raise WorkspaceError(
                "cannot read {}: {}".format(self.relative(target), exc)) from exc

    def read_file(self, path: str, start_line: int = 1, end_line: int = 0) -> Tuple[str, bool]:
        """Return line-numbered text and whether it was trimmed."""
        target = self.resolve(path)
        rel = self.relative(target)
        if target.is_dir():
            raise WorkspaceError("{} is a directory; use list_directory".format(rel))
        if not target.exists():
            raise WorkspaceError(
                "{} does not exist at the revision checked out in this job".format(rel)
            )
        size = target.stat().st_size
        if size > MAX_READ_BYTES:
            raise WorkspaceError(
                "{} is {} KB, over the {} KB read limit. Pass start_line and "
                "end_line to read a window of it.".format(
                    rel, size // 1024, MAX_READ_BYTES // 1024
                )
            )
        try:
            text = target.read_text(encoding="utf-8")
        except UnicodeDecodeError as exc:
            raise WorkspaceError(
                "{} is not UTF-8 text (binary file)".format(rel)) from exc
        except OSError as exc:
            raise WorkspaceError("cannot read {}: {}".format(rel, exc)) from exc

        lines = text.splitlines()
        total = len(lines)
        start = max(1, start_line)
        stop = total if end_line <= 0 else min(total, end_line)
        if start > total:
            raise WorkspaceError(
                "{} has {} lines; start_line {} is past the end".format(rel, total, start)
            )

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

        try:
            proc = subprocess.run(
                ("git", "--no-pager", "-C", str(self.root), *args),
                capture_output=True,
                check=False,
                text=True,
                errors="replace",
                timeout=GIT_TIMEOUT_SECONDS,
                env=_git_env(),
            )
        except subprocess.TimeoutExpired:
            raise WorkspaceError(
                "search for {!r} timed out; use a more specific pattern".format(pattern)
            ) from None
        # git grep exits 1 for "no matches", which is a valid answer, not a failure.
        if proc.returncode not in (0, 1):
            raise WorkspaceError(
                "search failed: {}".format(proc.stderr.strip() or "invalid pattern")
            )

        hits = [
            line for line in proc.stdout.splitlines()
            if line and not self.is_excluded(line.split(":", 1)[0])
        ]
        total = len(hits)
        if total == 0:
            return "no matches for {!r}".format(pattern), 0

        shown = hits[:max_results]
        body = "\n".join(shown)
        if len(body) > MAX_OUTPUT_CHARS:
            body = body[:MAX_OUTPUT_CHARS].rsplit("\n", 1)[0] + "\n… output trimmed"
        note = ""
        if total > len(shown):
            note = "\n… {} more match(es) not shown; narrow the pattern or set path_glob".format(
                total - len(shown)
            )
        return "{} match(es) for {!r}:\n{}{}".format(total, pattern, body, note), total


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
        "GIT_CONFIG_COUNT": "1",
        "GIT_CONFIG_KEY_0": "safe.directory",
        "GIT_CONFIG_VALUE_0": "*",
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
