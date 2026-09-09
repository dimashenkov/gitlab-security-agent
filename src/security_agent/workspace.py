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

import codecs
import fnmatch
import logging
import os
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Sequence, Tuple

# One definition of what a line is. `read_file` numbering blobs one way
# and the citation check numbering them another is how a finding comes to
# cite a line the reader never saw.
from .evidence import lines_of

log = logging.getLogger(__name__)


class WorkspaceError(Exception):
    """A tool argument was rejected, or git could not answer the question."""


class FileNotAtRevision(WorkspaceError):
    """No blob at that path in that tree.

    Deleted by the change, renamed, or a path the model invented — this says
    only that the tree does not have it. Which of the three it is comes from
    `changed_objects`, never from the absence itself.
    """


class FileTooLarge(WorkspaceError):
    """The blob is there, and larger than the ceiling in force.

    Separate from `FileNotAtRevision` because the callers act on the two
    oppositely, and until 2026-09-07 they could not tell them apart. The
    citation check caught an undifferentiated `WorkspaceError` around
    `raw_text` and took every failure as evidence the file had been deleted,
    so a file that merely exceeded the ceiling entered the deletion branch,
    was refused there for a second and unrelated reason, and reached the
    artifact as `unknown-path` with the detail *"is not a file this change
    deleted; read it with read_file"* — advising the tool that had refused it
    first. Measured on a built repository, not reasoned about.

    Carries the size and the ceiling, so a caller can say which limit was hit
    rather than repeating a number it assumed.
    """

    def __init__(self, message: str, *, size: int = 0, ceiling: int = 0):
        super().__init__(message)
        self.size = size
        self.ceiling = ceiling


# Ceilings that keep one tool call from filling the context window. Tools report
# when they trim, so the agent knows to narrow its request rather than assuming
# it saw everything.
MAX_READ_BYTES = 300_000
MAX_OUTPUT_CHARS = 60_000
# **What local code may hold, which is a different question.** `MAX_READ_BYTES`
# is a ceiling on what is *emitted to the model*, and that is what the comment
# above it means. Two readers of a blob emit none of it: the generated-file
# classifier looks for a banner, and the citation check matches a quoted
# snippet against the file. Both were refused by the context ceiling anyway —
# so a 658 KB generated file was never labelled generated, and a real weakness
# in a large file could be seen in the diff and not reported, because the
# citation check could not open the file to confirm the quote.
#
# Kept a ceiling rather than removed: the size is chosen by whoever wrote the
# merge request. It is checked before the read, so an enormous blob is refused
# rather than loaded and then discovered.
MAX_LOCAL_SCAN_BYTES = 8_000_000
# The head a generated-file banner can be in. Generators write it on the first
# line; this is that with room for a licence header above it.
MAX_HEAD_BYTES = 8_000
# A hard stop on how many matches are read at all, independent of how
# many are shown. The pattern is chosen by the model.
MAX_SEARCH_HITS = 20_000
GIT_TIMEOUT_SECONDS = 120


def _decoded(chunk: bytes, rel: str) -> str:
    """UTF-8 or a refusal, never mojibake.

    Decoding with `errors="replace"` would let a binary blob through as a wall
    of replacement characters, which reads to a model as a file it has seen.
    The whole-file reader refused those; the streaming window has to refuse
    them the same way or the two readers disagree about what is text.

    Strict is safe here because every chunk handed in ends at a newline or is
    the final one, so a multi-byte character is never split across the
    boundary.
    """
    try:
        return chunk.decode("utf-8")
    except UnicodeDecodeError:
        raise WorkspaceError(
            "{} is not UTF-8 text (binary file)".format(rel)) from None


# How much of one `git grep` record's text is kept. The rest is drained without
# being stored, so a minified line of several megabytes costs this much memory
# and not its own length. Bytes, because that is what git counts and what comes
# off the pipe.
MAX_RECORD_BYTES = 8_000
# What is rendered from it once the window around the match is cut. The same
# number as `evidence.MAX_EXCERPT_LINE_CHARS`, for the same reason: past this a
# line is minified or generated and nobody reads the rest of it.
MAX_RECORD_CHARS = 2_000
# Fixed-size reads. Iterating a binary pipe yields *lines*, so one record with
# no newline in it is accumulated whole before the loop body ever runs, and a
# ceiling below that would bound what is stored rather than what is read.
GREP_CHUNK_BYTES = 65_536
# A path is bounded by the filesystem and a line number is short, so the two
# framing fields arrive within this. Reading past it without finding them means
# the stream is not what this parser is for, and guessing is worse than stopping.
MAX_FRAMING_BYTES = 65_536
# The column field is digits then NUL. Looking this far past the second NUL
# decides match-versus-context without scanning to the newline, which on a
# minified line is megabytes away.
MAX_COLUMN_DIGITS = 20

# The bare `--` git writes between context blocks. An object rather than a
# string so it cannot be confused with a record whose text happens to be `--`.
HUNK_SEPARATOR = object()

# Why a bounded read stopped. Two causes, and they take opposite remedies:
# raising `SECURITY_SCAN_DIFF_CEILING_BYTES` repairs the first and makes the
# second worse. They shared one boolean until 2026-09-08, so the note the model
# reads named the setting for both.
CUT_BY_CEILING = "byte_ceiling"
CUT_BY_DEADLINE = "deadline"


@dataclass(frozen=True)
class ClippedLine:
    """A read that was cut *inside* one line, and which line it was.

    Recorded because the remedy differs and only one of the two cuts has one.
    A read that dropped later lines is answered by asking for a narrower
    window. A single line longer than the output ceiling is not: the reader is
    already looking at the narrowest window that exists, and `start_line=N,
    end_line=N` returns the identical bytes. Measured on 2026-09-07 — a
    140,009-character line delivered 2,000 characters and advised a narrower
    window, so a reviewer following the advice loops on the same answer for
    ever and the rest of that line is unreachable through this tool at any
    argument.

    The shape is the one `_trim_diff` arrived at for the same class of defect:
    a message that names a remedy has to be able to tell which situation it is
    in, and a boolean cannot.
    """

    # The line the body stops inside, 1-based, as the reader sees it.
    number: int
    # How long that line actually is, so the reader knows the size of what is
    # missing rather than only that something is.
    chars: int
    # Whether the window selected lines after this one. They were not
    # delivered, and unlike the clipped line itself they *are* reachable — a
    # window starting after it returns them.
    more_after: bool


class GrepRecord:
    """One line git matched or gave as context, fields still in bytes.

    Bytes, because the decisions taken on it are taken in git's units. The
    column is a **byte** offset into the line — measured on 2026-09-07, a match
    at character 22 of a Cyrillic line is reported at byte 35 — so a window cut
    around it is cut in bytes and decoded afterwards. Decoding first and
    slicing by that number lands in a different word, which is this project's
    recurring defect arriving inside the fix for another one.
    """

    __slots__ = ("path", "line", "column", "text", "offset", "dropped_after")

    def __init__(self, path, line, column, text, offset, dropped_after):
        self.path = path        # bytes, still carrying any `REV:` prefix
        self.line = line        # bytes, ASCII digits
        self.column = column    # bytes or None — a context line has no match
        self.text = text        # bytes, at most MAX_RECORD_BYTES of them
        # Where `text` starts within the line. Non-zero when the retained
        # window was taken around a match far along a minified line, and the
        # reason the retained slice is not simply the head: keeping the first
        # 8,000 bytes of a line whose match is at byte 72,000 discards the
        # match before anything downstream can see it.
        self.offset = offset
        self.dropped_after = dropped_after  # was there more after `text`


def _trimmed_decode(chunk: bytes, cut_before: bool = False,
                    cut_after: bool = False) -> str:
    """Decode a byte window, forgiving only the edges that were actually cut.

    A window cut in bytes can begin or end inside a multi-byte character; those
    two are artefacts of the cut. Anything else — including a bad byte at the
    start or end of a *whole* line — is what the file holds, and it raises, so
    a search never presents a repaired line as the line.

    **Written three times, and each version excused a different thing.**

    The first dropped up to four trailing bytes and retried, guarded by "the
    error is within four of the end". Measured exhaustively: `b"abc\xffdef"`
    decoded to `"abc"`, silently — once enough trailing bytes are dropped every
    interior error is within four of the new end, so the guard excused all of
    them.

    The second used an incremental decoder with `final=False`, which fixed the
    interior and left both edges unconditionally forgiving: `b"\x80abc"` gave
    `"abc"` and `b"abc\xe2\x82"` gave `"abc"` on a *complete* record, where
    neither edge had been cut and both are corruption. Codex, 2026-09-07, on
    the gate for the second version.

    So the caller says which edges it cut. That is knowable — the parser
    records it — and inferring it from the bytes is what produced both of the
    earlier defects.
    """
    lead = 0
    if cut_before:
        # A UTF-8 character is at most four bytes, so at most three
        # continuation bytes can precede the first whole one.
        while lead < len(chunk) and lead < 3 and (chunk[lead] & 0xC0) == 0x80:
            lead += 1
    body = chunk[lead:]
    decoder = codecs.getincrementaldecoder("utf-8")()
    try:
        # `final=False` keeps an incomplete trailing sequence in the decoder's
        # own buffer rather than reporting it, and it is never flushed — that
        # is the cut tail being dropped. With `final=True` the same incomplete
        # tail is the error it is.
        return decoder.decode(body, not cut_after)
    except UnicodeDecodeError:
        raise WorkspaceError("a matched line is not UTF-8 text") from None


def _window_around(record, decode) -> str:
    """The part of a line worth showing, rendered from the retained window.

    **The window has to contain what was searched for.** A prefix clip does
    not: on a minified line whose match is at character 200,000, the first two
    thousand characters are a record that no longer demonstrates why it
    matched — worse than a truncated line, which is at least honestly the start
    of one. Codex refused the prefix design on exactly that, 2026-09-07.

    The cut itself happens in the parser, which knows the column before it
    reads the text and so can drain what it will not show. This renders what
    survived and says which side was left out.

    `--column` gives the *start* of git's first match on the line, in bytes,
    1-based. Only the start: an ERE's matched extent is not bounded by the
    length of its source (`x.*y`), so what is guaranteed is that the window
    holds the match start and a bounded run of what follows — not the whole
    match, and not any later match on the same line. Saying otherwise would be
    a claim nothing checks, which is the thing this tool hunts.
    """
    if not record.text:
        return ""
    dropped_before = record.offset > 0
    dropped_after = record.dropped_after
    # Which edges the *parser* cut, which is the only thing the decoder may
    # forgive. A complete record has neither, and a bad byte at either end of
    # one is corruption in the file rather than an artefact of a window.
    shown = decode(record.text, dropped_before, dropped_after)
    if len(shown) > MAX_RECORD_CHARS:
        # **Centred on the match, not taken from the head.** The parser keeps a
        # byte window around the column; cutting that window's *first* two
        # thousand characters throws the match away again, one layer down,
        # because the match sits a quarter of the way into the window by
        # design. The same defect as the prefix clip, in the renderer.
        at = 0
        if record.column is not None and record.column.isdigit():
            into = max(0, int(record.column) - 1 - record.offset)
            # **Not a cut edge.** The prefix ends at git's match start, which
            # is a character boundary in the file — nothing cut it, so an
            # incomplete sequence immediately before the match is corruption
            # and must raise rather than be trimmed away. Only the leading edge
            # is one the parser made. Codex, second gate round, 2026-09-07.
            at = len(decode(record.text[:into], dropped_before, False)) \
                if into else 0
        begin = max(0, at - MAX_RECORD_CHARS // 4)
        finish = begin + MAX_RECORD_CHARS
        dropped_before = dropped_before or begin > 0
        dropped_after = dropped_after or finish < len(shown)
        shown = shown[begin:finish]
    prefix = "… " if dropped_before else ""
    suffix = " …" if dropped_after else ""
    return prefix + shown + suffix


def _grep_records(stream, should_stop=None):
    """`git grep -z --column` output, one bounded record at a time.

    A record is `path NUL line NUL [column NUL] text`, ending at a newline. The
    column is there on a matched line and absent on a context line, so the
    shape *varies* and the framer cannot count to two. It is still decidable:
    text can never contain a NUL, and the column is a short run of digits, so a
    NUL within `MAX_COLUMN_DIGITS` of the second one marks a match record.
    Checked against real output for four awkward paths — one holding a newline,
    one holding a colon and digits, one ending in digits — rather than reasoned
    about.

    Bounded three ways, and each one is something that went wrong:

    * **fixed-size reads**, because iterating a binary pipe yields lines and a
      record with no newline would arrive whole before the ceiling was ever
      consulted;
    * **at most `MAX_RECORD_BYTES` of text retained**, the remainder drained;
    * **`should_stop()` consulted while draining**, so a deadline is checked
      during a long record and not only between records.

    The framing state lives in the fields already captured, not in the buffer,
    so dropping the buffer mid-drain cannot lose the record being drained.
    """
    read = getattr(stream, "read1", None) or stream.read
    buffer = b""
    ended = False

    def more():
        """Pull one chunk. False at the end of the stream."""
        nonlocal buffer, ended
        if ended:
            return False
        chunk = read(GREP_CHUNK_BYTES)
        if not chunk:
            ended = True
            return False
        buffer += chunk
        return True

    def fill_to(size):
        while len(buffer) < size and more():
            pass

    while True:
        if should_stop is not None and should_stop():
            return

        fill_to(3)
        if buffer.startswith(b"--\n"):
            buffer = buffer[3:]
            yield HUNK_SEPARATOR
            continue

        first = buffer.find(b"\0")
        while first < 0 and len(buffer) <= MAX_FRAMING_BYTES and more():
            first = buffer.find(b"\0")
        if first < 0:
            break
        second = buffer.find(b"\0", first + 1)
        while second < 0 and len(buffer) <= MAX_FRAMING_BYTES and more():
            second = buffer.find(b"\0", first + 1)
        if second < 0:
            break

        path = buffer[:first]
        line = buffer[first + 1:second]

        fill_to(second + 2 + MAX_COLUMN_DIGITS)
        ahead = buffer[second + 1:second + 2 + MAX_COLUMN_DIGITS]
        cut = ahead.find(b"\0")
        if cut > 0 and ahead[:cut].isdigit():
            column = ahead[:cut]
            start = second + 1 + cut + 1
        else:
            column = None
            start = second + 1

        # Everything before `start` has been captured into `path`, `line` and
        # `column`, so the buffer may now be consumed freely.
        #
        # **The retained window is taken around the match, not from the head.**
        # `--column` is known before the text is read, which is what makes this
        # possible: on a minified line whose match is at byte 72,000, keeping
        # the first 8,000 bytes throws the match away before any renderer can
        # look at it, and the answer becomes a record that does not show why it
        # matched. Measured with a Cyrillic bundle, not reasoned about.
        buffer = buffer[start:]
        want_from = 0
        if column is not None:
            want_from = max(0, int(column) - 1 - MAX_RECORD_BYTES // 4)
        want_to = want_from + MAX_RECORD_BYTES
        text = b""
        seen = 0
        dropped_after = False
        while True:
            newline = buffer.find(b"\n")
            available = buffer if newline < 0 else buffer[:newline]
            begin = max(0, want_from - seen)
            finish = max(0, want_to - seen)
            if begin < len(available):
                text += available[begin:finish]
            seen += len(available)
            if seen > want_to:
                dropped_after = True
            if newline >= 0:
                buffer = buffer[newline + 1:]
                break
            buffer = b""
            if should_stop is not None and should_stop():
                return
            if not more():
                break
        yield GrepRecord(path, line, column, text, want_from, dropped_after)


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
        # Asked of git once per workspace, not once per process: see
        # `_empty_tree` for why the object id is not a constant.
        self.__empty_tree: Optional[str] = None
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
        # The same fact about the *last* `diff()` call rather than about the run.
        # Both are needed and they are not the same: the run-level flag is a
        # hole in the review and must stay set once anything was cut, while a
        # caller asking "was *this* body whole" gets a wrong answer from a flag
        # an earlier single-file diff turned on. That confusion would have
        # reported a genuinely complete diff as never delivered.
        self.last_diff_truncated = False
        # Set by `search`: whether the scan that produced the last count
        # stopped early, so the count is a floor rather than an answer.
        self.last_search_truncated = False
        # Set by `_bounded`: `""`, `CUT_BY_CEILING` or `CUT_BY_DEADLINE`. Two
        # different things stop a read and they have opposite remedies —
        # raising the byte ceiling repairs the first and makes the second worse,
        # by letting more output accumulate before the clock kills it anyway.
        # `last_diff_truncated` answered "was it cut" and the caller filled in
        # the cause, which is how the model was told to raise a setting that
        # could not help it. Codex, tenth gate round, 2026-09-08.
        self.last_diff_cause = ""
        # How many paths the last diff was restricted to; 0 is the whole
        # change. Set in `diff()`, read where the note has to know whether
        # narrowing is still open to the reader.
        self.last_diff_paths = 0
        # Set by `_render_window`: `None`, or the one line a read was cut
        # *inside*. Two cuts share the `trimmed` flag and only one of them has
        # the remedy the flag's message names. Dropping later lines is answered
        # by asking for a narrower window; a single line longer than the output
        # ceiling is not, because the line is already the narrowest window
        # there is and returns the identical bytes. So which cut happened
        # travels beside the flag, in the same idiom as the two above.
        self.last_read_clip: Optional[ClippedLine] = None
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

    def hidden_by_rules(self) -> Tuple[List[str], List[str]]:
        """(hidden by an exclude rule, left out by `--path`), deletions too.

        `changed_files` and `changed_objects` both apply the two filters as
        they read, so a path a rule covers is gone before anything can record
        that a rule covered it. `out_of_scope` was filled from
        `all_changed_files`, which is `--diff-filter=ACMRT` — so a *deletion*
        a rule hid appeared in no field of `Coverage` at all, and
        `Coverage.excluded` was declared, serialised and never assigned by
        anybody. Measured and recorded on 2026-09-09, built the same day.

        The argument for recording it is the one `out_of_scope`'s own
        docstring already makes: a scoped review that reports "no findings"
        without saying what it did not look at is the same sentence as a full
        review that found nothing. An operator who excludes `vendor/` has said
        not to *review* it; nothing in that says the artifact should be unable
        to mention that a file there was deleted.

        Order matters and matches `changed_files`: `is_excluded` is asked
        first, so a path that is both excluded and out of scope is reported
        once, as excluded. Two lists that overlap would be counted twice by
        anybody who added them.
        """
        saved_excludes, saved_scope = self.excludes, self.scope
        self.excludes, self.scope = (), ()
        try:
            every = [obj.path for obj in self.changed_objects()]
        except WorkspaceError:
            # A line in a report, not a gate. A git invocation that fails here
            # must not take down a review that has already been done — the
            # same rule `inventory_notes` follows.
            return [], []
        finally:
            self.excludes, self.scope = saved_excludes, saved_scope
        excluded = [path for path in every if self.is_excluded(path)]
        out_of_scope = [path for path in every
                        if not self.is_excluded(path)
                        and not self.in_scope(path)]
        return excluded, out_of_scope

    def refuse_untrusted_attributes(self) -> None:
        """Refuse to run when an attributes file outranks the pinned source.

        `--attr-source` pins where git reads the *tree's* `.gitattributes`, and
        that closes the route a merge request can reach: a `*.py -diff` line
        committed beside the weakness made every changed file look binary, so
        the diff the model read was `Binary files … differ`, `search` returned
        zero, and the finding was filed pre-existing and never verified.

        `$GIT_DIR/info/attributes` is not in the tree and `--attr-source` does
        not cover it. Git consults it with higher precedence than the tree, so
        one line there reproduces the whole effect. Named by Codex on
        2026-09-07 as the part that was not closed, and built 2026-09-09.

        It is **not** reachable through a merge request — nothing a contributor
        pushes lands in `$GIT_DIR` — so this is not a hole in the product's
        threat model. It is a statement about the runner: the job wants a fresh
        git directory, and if it has not got one, this review cannot say what
        it read. Refusing is the honest answer and it exits 2, "the check did
        not run", rather than 0.

        **Only the attributes that can do it.** The first version refused any
        file with a non-blank line in it, so a comment, or an ordinary
        `export-ignore`, exited 2 on a repository nothing was wrong with.
        Codex, 2026-09-09: immediately reachable in a legitimate developer or
        CI checkout. That is the gate-that-fires-on-nothing this file's own
        comments warn about, written two paragraphs under one of them — and a
        gate that fires on nothing is deleted rather than obeyed, which costs
        the real route as well.

        So the line has to set an attribute that changes what git calls
        diffable: `diff` in any spelling, `text`, or the `binary` macro, which
        expands to `-diff -text`. Comments, blanks and everything else pass.

        Empty is allowed for the same reason. A zero-byte file sets no
        attribute at all.
        """
        # **Asked of git, not assembled.** `--absolute-git-dir` in a linked
        # worktree is that worktree's own administrative directory, while git
        # resolves shared paths like `info/attributes` through the *common*
        # directory — so a harmful file there still reached git while this
        # guard read a path that does not exist and returned quietly. Codex,
        # 2026-09-09. `--git-path` answers where git will actually look, which
        # is the only question this check is asking.
        try:
            located = self.git("rev-parse", "--path-format=absolute",
                               "--git-path", "info/attributes").strip()
        except WorkspaceError:
            # Not a repository, or git cannot answer. That is somebody else's
            # error to report, and reporting it here as "untrusted attributes"
            # would send the reader looking for a file that does not exist.
            return
        if not located:
            return
        path = Path(located)
        try:
            body = path.read_text(encoding="utf-8", errors="replace")
        except FileNotFoundError:
            return
        except OSError as exc:
            raise WorkspaceError(
                "{} exists and could not be read ({}). It outranks the pinned "
                "attribute source, so what git will call binary cannot be "
                "established, and neither can what this review read."
                .format(path, exc)) from exc
        setting = _first_diff_attribute(body)
        if setting is None:
            return
        raise WorkspaceError(
            "{} sets a diff attribute for this repository — {!r} — and it "
            "outranks the pinned attribute source. Such a line can make every "
            "changed file look binary: the diff becomes 'Binary files … "
            "differ', searches return nothing, and findings are filed as "
            "pre-existing without being verified. Nothing a merge request can "
            "push reaches this file — it is the runner's own state. Give the "
            "job a fresh git directory, or remove that line, and run again."
            .format(path, setting))

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

    def _argv(self, *args: str) -> tuple:
        """The command line every git invocation in this class is built from.

        **One builder, because three of them were built by hand and only one
        carried the pin.** `--attr-source` was added to `git()` and
        `_bounded` and `_grep_stream` construct their own `Popen` — so the
        primary diff the model reads and every `search` still let an in-tree
        `.gitattributes` decide what git would show. The attribution map was
        protected and the material was not. Codex, on the gate for that repair,
        2026-09-07.

        `hash-object`, `cat-file`, `show` and `rev-parse` do not consult
        attributes, so they are not built here — pinning them would be
        decoration, and a builder used for everything hides which calls the pin
        is load-bearing for.
        """
        return ("git", "--no-pager", "-C", str(self.root),
                "--no-optional-locks", "--attr-source", self._empty_tree(),
                *args)

    def _empty_tree(self) -> str:
        """The object id of the empty tree, asked of git rather than written out.

        **The reviewed material must not describe itself to the tools that read
        it.** One line of `.gitattributes` saying `*.py -diff` makes
        `git diff --numstat` print `-` for both counts; the file is then
        classified binary and drops out of the changed-line map, while the map
        stays non-empty because `.gitattributes` is in it. `tools.py` reads the
        empty attribution as "this line was already there", the finding is
        filed pre-existing, and the gate skips it. Measured end to end on
        2026-09-07: exit 1 becomes exit 0, with the verdict line saying "none
        at or above the high threshold" about a `critical`, and the finding is
        never verified because `_worth_verifying` skips pre-existing ones.

        `--no-ext-diff` and the pinned `GIT_CONFIG_*` already stop the
        neighbouring route: an external diff driver has to be *defined* in
        configuration, and no configuration is trusted. `-diff` is built in and
        needs no configuration at all, which is how it walked through a guard
        written against the same idea.

        Measured rather than assumed, because three plausible switches do not
        work: `--text` is applied after the attribute, and the global
        `core.attributesFile` does not override an in-tree one. `--attr-source`
        does, and git has had it since 2.40 for exactly this purpose. Its cost
        was measured too — content detection is untouched, an ordinary change
        is byte-identical, and what is lost is a project's own `binary`
        markings, which are about diff readability rather than about safety.

        Asked of git instead of hardcoding `4b825dc...`: that constant is the
        SHA-1 empty tree, and a SHA-256 repository has a different one.
        """
        # **Per instance, keyed on this repository.** The first version cached
        # it on the class, which is the same object id everywhere right up
        # until it is not: a SHA-256 repository's empty tree is
        # `6ef19b41...` where SHA-1's is `4b825dc6...`, so a process holding
        # both would hand one the other's. Measured: git answers
        # `fatal: bad --attr-source` and exits 128, so it is a loud failure
        # rather than a silent one — but a cache keyed on nothing is a defect
        # waiting for the day the failure stops being loud.
        if self.__empty_tree is None:
            # **Every failure here becomes a `WorkspaceError`.** This runs on
            # the first git call of a workspace's life, and it runs inside
            # `_argv` — so a raw `OSError` or `TimeoutExpired` would escape
            # from `_bounded` and `_grep_stream`, which give a `WorkspaceError`
            # for every other way git can fail. A caller that handles one and
            # not the other is a caller that crashes on the day git is missing
            # rather than reporting that it could not check. Codex, on the
            # second gate round for this change, 2026-09-07.
            try:
                done = subprocess.run(
                    ("git", "-C", str(self.root), "hash-object", "-t", "tree",
                     os.devnull),
                    capture_output=True, check=False,
                    timeout=GIT_TIMEOUT_SECONDS, env=_git_env())
            except subprocess.TimeoutExpired:
                raise WorkspaceError(
                    "git timed out naming its own empty tree, so the attribute "
                    "source cannot be pinned and the review would run with the "
                    "reviewed repository deciding what is readable") from None
            except OSError as exc:
                raise WorkspaceError(
                    "git could not be run to name its own empty tree ({}), so "
                    "the attribute source cannot be pinned and the review would "
                    "run with the reviewed repository deciding what is "
                    "readable".format(exc)) from None
            if done.returncode != 0:
                raise WorkspaceError(
                    "git cannot name its own empty tree, so the attribute "
                    "source cannot be pinned and the review would run with "
                    "the reviewed repository deciding what is readable: "
                    + done.stderr.decode("utf-8", "replace").strip())
            self.__empty_tree = done.stdout.decode("ascii").strip()
        return self.__empty_tree

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
                self._argv(*args),
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

    def blob_bytes(self, revision: str, path: str) -> Optional[bytes]:
        """What `path` held at `revision`, or `None` where it held nothing.

        Bytes, not text. The caller comparing prompt content needs to know
        whether two files are the same, and decoding first — however carefully
        — turns that into a question about the decoding. `None` for a path that
        did not exist there, which is an answer and not a failure: a file the
        change *added* is as much its choice as one it edited.
        """
        if not revision:
            return None
        # **The one blob reader left without a ceiling.** Codex, 2026-09-07, on
        # the gate for this change: it bypasses `_blob_at` and reads whatever
        # is there. Comparing a prompt file against its baseline is a small
        # read for a file we ship — but the revision and the tree are the
        # change's, and "the file we expect there is small" is an assumption
        # about material the change controls, which is the one kind this
        # project does not make.
        #
        # `FileTooLarge` rather than `None`: `None` means the path held
        # nothing, the caller treats that as a legitimate answer, and a file
        # too large to compare is not a file that was not there.
        size = self._blob_size(revision, path)
        if size is None:
            return None
        if size > MAX_LOCAL_SCAN_BYTES:
            raise FileTooLarge(
                "{} at {} is {} KB, over the {} KB limit for this read".format(
                    path, _abbrev(revision), size // 1024,
                    MAX_LOCAL_SCAN_BYTES // 1024),
                size=size, ceiling=MAX_LOCAL_SCAN_BYTES)
        proc = subprocess.run(
            ("git", "--no-pager", "-C", str(self.root), "--no-optional-locks",
             "show", "{}:{}".format(revision, path)),
            capture_output=True, check=False, timeout=GIT_TIMEOUT_SECONDS,
            env=_git_env(),
        )
        return proc.stdout if proc.returncode == 0 else None

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

    def changed_objects(self) -> List["ChangedObject"]:
        """Everything this change did, with enough detail to judge coverage.

        Two git commands rather than one, because neither answers alone:
        `--name-status` says what happened to each path and `--numstat` says how
        much text moved and whether the file is binary. They are joined on the
        path, which is the same path in both because both are given `-M` and
        both report a rename against its new name.

        No `--diff-filter`. `changed_files()` has one, deliberately — it is the
        list of files a reviewer is asked to open, and a deleted file cannot be
        opened. This list answers a different question: what did the change do.
        A deletion belongs in it, because the removed lines of a deleted guard
        are in the diff and are exactly what a security review is for.

        The excludes and the scope are applied, as they are in `changed_files`:
        this is still the run's own view of its work, and a file the operator
        excluded is not a hole in the review.
        """
        if not self.diff_base:
            return []
        raw = self.git(
            "diff", "--no-color", "--no-ext-diff", "-M", "--raw", "-z",
            self.diff_base, self.diff_head,
        )
        numstat_raw = self.git(
            "diff", "--no-color", "--no-ext-diff", "-M", "--numstat", "-z",
            self.diff_base, self.diff_head,
        )
        counts = {path: (added, removed, binary)
                  for path, added, removed, binary in _parse_numstat(numstat_raw)}

        out: List[ChangedObject] = []
        for path, old_path, code, old_mode, new_mode in _parse_raw(raw):
            if self.is_excluded(path) or not self.in_scope(path):
                continue
            added, removed, binary = counts.get(path, (0, 0, False))
            out.append(ChangedObject(
                path=path,
                status=_STATUS_NAMES.get(code, code),
                added=added,
                removed=removed,
                binary=binary,
                old_path=old_path,
                old_mode=old_mode,
                new_mode=new_mode,
            ))
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

    def reached_through_a_link(self, relative: str) -> Optional[str]:
        """The first symlink between the root and `relative`, or `None`.

        `change_touches` asks **git** whether a path was edited, and git never
        follows a link — it reports the link's own blob. The loaders ask the
        **filesystem**, which does follow it. So a file committed as a symlink
        is guarded under one name and read from another, and the guard that
        stops a change from suppressing its own findings goes quiet while the
        change supplies the rules through the destination.

        Two merge requests and no knowledge of the finding: commit
        `.security-agent-ignore.yml` as a link to `docs/notes.yml`, which reads
        as tidying; then put the weakness and the entry excusing it into
        `docs/notes.yml`. Git reports only `docs/notes.yml`, the guard sees its
        own name untouched, and the rule applies to the change that wrote it.
        Verified on a real repository before this existed.

        Lexical, on the path as named, and every component: resolving first
        would follow the link that is the whole question.
        """
        try:
            named = self.repo_path(relative)
        except WorkspaceError:
            return None
        walked = self.root
        for part in named.split("/"):
            walked = walked / part
            if walked.is_symlink():
                return str(walked.relative_to(self.root))
        return None

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

        **Deletions included, and the reason the old sentence gave for leaving
        them out was backwards.** It said a deleted file is "correctly absent
        rather than counted as something a rule hid" — but when a rule *does*
        hide one, that is exactly what it is. Measured 2026-09-09: a merge
        request whose only change was `git rm vendor/guard.php` — a path in
        `DEFAULT_EXCLUDES`, so no operator configuration involved — emptied
        `changed_files` and `changed_objects` both, and this list was empty
        too, so the caller could name neither filter and reported "This change
        adds or modifies no file, so there was nothing to review." over a
        removed guard. The same file *modified* correctly said every file was
        excluded. The deletion was reported strictly worse than the
        modification, which is the asymmetry the gate's own deletion hole had.

        The status is carried through, so the caller can say what was removed
        rather than only that something was.
        """
        saved_excludes, saved_scope = self.excludes, self.scope
        self.excludes, self.scope = (), ()
        try:
            seen = self.changed_files()
            known = {path for path, _ in seen}
            # From `changed_objects` and not `raw_changed_paths`. The latter
            # runs `--no-renames`, so a rename reports its old path as a `D` —
            # and this list would then claim a moved file was deleted. Nothing
            # reads it that way today, because a rename leaves `changed_files`
            # non-empty and this list's only caller runs when that is empty;
            # but a list that says a false thing is one the next caller
            # believes. `changed_objects` is `-M`-aware, and with the two
            # filters cleared above it sees everything.
            #
            # A rename's *source* counts too, and Codex found that on
            # 2026-09-09: `app/guard.py -> vendor/guard.py` reported only the
            # new path, so a guard moved behind an exclude rule was described
            # less clearly than one deleted outright — the same asymmetry, one
            # step along. The old path is carried as `moved_from` rather than
            # `deleted`, because it is a different fact and the caller counts
            # them separately.
            gone = []
            for obj in self.changed_objects():
                if obj.status == "deleted" and obj.path not in known:
                    gone.append((obj.path, "deleted"))
                elif obj.old_path and obj.old_path not in known:
                    gone.append((obj.old_path, "moved_from"))
            return seen + gone
        finally:
            self.excludes, self.scope = saved_excludes, saved_scope

    def diff(self, path: str = "", context_lines: Optional[int] = None) -> str:
        if not self.diff_base:
            raise WorkspaceError(
                "no diff base is available for this run (not a merge request "
                "pipeline). Use the file-reading tools instead."
            )
        # Cleared before the work, not after it. It says "the last call", and a
        # call that raised is still the last one — leaving the previous answer
        # standing would make a stale True or False survive a failure.
        self.last_diff_truncated = False
        self.last_diff_cause = ""
        # How many paths this diff was restricted to; 0 means the whole change.
        # **The tool argument is not the answer to that.** A run started with
        # `--path huge.py` sets `Workspace.scope`, so a plain `get_diff {}` is
        # already one file — and the note told it to ask for one file at a
        # time, which is what it had done. Counting the resolved paths rather
        # than testing the argument also keeps a scope covering a directory or
        # several `--path` values from being read as one file, which narrowing
        # would still help. Codex, thirteenth gate round, 2026-09-08.
        self.last_diff_paths = 0
        args = [
            "diff", "--no-color", "--no-ext-diff", "-M",
            "--unified={}".format(max(0, min(
                self.default_context_lines if context_lines is None
                else context_lines, 100))),
            self.diff_base, self.diff_head,
        ]
        if path:
            args += ["--", self.repo_path(path)]
            self.last_diff_paths = 1
        elif self.scope:
            # The resolved file list rather than the patterns themselves. A git
            # pathspec has its own magic prefixes and its own glob rules, and a
            # scope that meant one thing to `in_scope` and another to git would
            # put a file in the diff that the coverage accounting says was never
            # in the change.
            #
            # **From the objects, not from the openable list.** Codex,
            # 2026-09-06, adjudicating the deletion-only repair in `cli.py`:
            # `changed_files` filters deletions out, so a scoped run over a
            # change made of deletions built its pathspec from an empty list
            # and returned an empty diff — the removed lines gone from the one
            # place that carries them. The scope is still applied, by
            # `changed_objects`, which is where a deleted path lives.
            in_scope = [obj.path for obj in self.changed_objects()]
            if not in_scope:
                return ""
            args += ["--", *(self.repo_path(p) for p in in_scope)]
            self.last_diff_paths = len(in_scope)
        body, cause = self._bounded(args)
        # The boolean is kept beside the cause rather than replaced by it: the
        # gate, the session document and several tests read it under the old
        # meaning, and "was it cut" is still the question most of them ask.
        self.last_diff_truncated = bool(cause)
        return body

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
        """The byte ceiling actually in force, which an operator can raise.

        The gate names this to a reader of a truncated review; that sentence
        was false when it was written, because the number was a constant with
        no configuration surface. A remedy nobody can perform is worse than
        none — it moves the blame to a reader who cannot act.

        It is named **conditionally** now, because raising this is not enough
        on its own: `tools.MAX_DIFF_CHARS` bounds what the model is shown,
        independently of this and with no setting behind it, and is the smaller
        of the two by default. A change cut by that limit stays cut at any
        value here. Measured 2026-09-08; see `LIMITATIONS.md`.
        """
        return self._diff_ceiling or self.MAX_DIFF_BYTES

    def _bounded(self, args: List[str]) -> Tuple[str, bool]:
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

        **A failed git is not an empty diff.** stderr goes to `/dev/null` and the
        exit status used to go unread, so a bad revision, a broken index or a
        pathspec git would not accept all came back as `""` — indistinguishable
        from a change with nothing in it. That distinction was cosmetic until
        `whole_diff` started reading an empty body as "the reviewer was shown
        everything there is"; then it became a way for a crash to be recorded as
        complete coverage. A non-zero status is raised, except after a
        deliberate kill, where a non-zero status is what killing produced.
        """
        # **The command line before the clock.** `_argv` resolves the pinned
        # attribute source, which runs git on the first call of a workspace's
        # life — so building it after the deadline was set spent part of this
        # read's budget on work the budget was not meant to cover. Instant in
        # practice and wrong in shape, which is the kind that stops being
        # instant on somebody else's filesystem.
        argv = self._argv(*args)
        deadline = time.monotonic() + GIT_TIMEOUT_SECONDS
        try:
            proc = subprocess.Popen(
                argv,
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                env=_git_env(),
            )
        except OSError as exc:
            raise WorkspaceError("git {} failed: {}".format(
                " ".join(args), exc)) from None

        chunks: List[bytes] = []
        size = 0
        # **Which of the two, not merely that one of them.** The deadline and
        # the byte ceiling both stop this loop and their remedies point in
        # opposite directions; a caller handed one boolean has to guess, and
        # the one that guessed told the model to raise the ceiling after a
        # clock cut. Codex, tenth gate round, 2026-09-08.
        cause = ""
        try:
            # Never more than the ceiling in one read. The first version asked
            # for 64k regardless and then compared, so a 300-byte diff under a
            # 50-byte ceiling arrived whole and was called truncated — the
            # ceiling was a suggestion and the flag was about the suggestion
            # rather than about the output.
            while size < self.diff_ceiling:
                if time.monotonic() > deadline:
                    cause = CUT_BY_DEADLINE
                    break
                chunk = proc.stdout.read(min(65_536, self.diff_ceiling - size))
                if not chunk:
                    break
                chunks.append(chunk)
                size += len(chunk)
            else:
                # The ceiling was reached exactly, which is not the same as
                # being cut by it: a diff whose last byte lands on the limit is
                # whole, and calling that truncated told the reviewer it had
                # seen part of a change it had seen all of. One more read
                # settles it — nothing means end of output, a byte means there
                # was more. The byte is discarded rather than kept: keeping it
                # put the body one over the ceiling the whole function exists
                # to hold, and it belongs to the part being declared missing.
                #
                # Like every other read here, this one blocks. The deadline is
                # checked between reads and does not bound one, which was true
                # of the loop before this probe existed; what bounds a git that
                # never answers is git's own exit, not this timer.
                if proc.stdout.read(1):
                    cause = CUT_BY_CEILING
        finally:
            # Killed rather than drained: draining is what an unbounded read
            # does, and the point of stopping was not to hold the rest.
            if cause:
                proc.kill()
            proc.stdout.close()
            status = proc.wait()

        if not cause and status != 0:
            raise WorkspaceError(
                "git {} exited {}; no diff was produced".format(
                    " ".join(args[:6]), status))

        body = b"".join(chunks).decode("utf-8", "surrogateescape")
        if cause:
            self.diff_truncated = True
            # Said in the output the model reads, because a diff that stops
            # halfway through a file looks exactly like a file that ends there.
            #
            # And it names the cause it actually had. "Cut off at N bytes" over
            # a deadline cut is a wrong number *and* a wrong story: the reader
            # concludes the change is too big when git was simply too slow, and
            # the remedy that follows from that reading makes things worse.
            body = body.rsplit("\n", 1)[0] + (
                "\n… this diff was cut off at {} bytes. What follows it was not "
                "read, and a change this large has not been fully reviewed."
                .format(self.diff_ceiling)
                if cause == CUT_BY_CEILING else
                "\n… reading this diff hit the {}-second git deadline and "
                "stopped. What follows it was not read; the change may be any "
                "size, and this one was not fully reviewed."
                .format(GIT_TIMEOUT_SECONDS))
        self.last_diff_cause = cause
        return body, cause

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
                # `check=True`. It was False, and `git` returns whatever it
                # managed to write whatever its exit code — so a diff killed
                # after one file's hunks, or refused outright, produced a
                # *structurally valid* partial map. Every file git never got to
                # is then absent from it, findings there are reported as
                # pre-existing, and pre-existing does not block. The hunk
                # accounting in `changed_lines` cannot see this: output that
                # stops cleanly between files is well-formed.
                #
                # `git diff A B` exits non-zero only on a real failure here —
                # `--exit-code`, which makes a difference exit 1, is not passed.
                # So a failure raises, `cli` catches it, and the run ends at
                # exit 2: the check did not run, which is a different answer
                # from "the change is clean".
                raw = self.git(
                    "diff", "--no-color", "--no-ext-diff", "-M", "--unified=0",
                    self.diff_base, self.diff_head,
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
        return self._blob_at(self.diff_head or "HEAD", self.repo_path(path),
                             MAX_READ_BYTES)

    def _blob_at(self, rev: str, rel: str, ceiling: int) -> str:
        """One blob, at one revision, under one named ceiling.

        **Every** whole-blob read goes through here, and each caller names the
        revision it means and the ceiling that belongs to its purpose. Before
        2026-09-07 the readers fetched their own: `blob_text` checked the size
        first and `removed_text`, written later for the deletion repair, ran
        `git show` straight into `capture_output=True` with no check at all.
        Measured on a built repository — the same 4,999,982-byte content was
        refused at 292 KB when it was live and returned whole when the change
        had deleted it. The attacker chooses both the deletion and the size,
        and a merge request removing a large vendored blob looks ordinary.

        The structural point is that the fix is not a second size check. A
        ceiling added here applies at head and at base alike, and a future
        reader cannot acquire a revision without also acquiring a limit.
        """
        size = self._blob_size(rev, rel)
        if size is None:
            raise FileNotAtRevision(
                "{} is not a tracked file at {}".format(rel, _abbrev(rev)))
        if size > ceiling:
            raise FileTooLarge(
                "{} is {} KB, over the {} KB limit for this read".format(
                    rel, size // 1024, ceiling // 1024),
                size=size, ceiling=ceiling)

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

    def _window_at(self, rev: str, rel: str, start: int, stop: int,
                   size: Optional[int] = None):
        """The lines in ``[start, stop]`` of a blob, without holding the blob.

        Streams `git show` and keeps only the requested lines, so the memory
        cost is the window and not the file. Returns
        ``(lines, total, complete)``: ``total`` is the line count when the
        stream was read to the end, and ``complete`` says whether it was — a
        scan stopped at `MAX_LOCAL_SCAN_BYTES` knows the file has *at least*
        that many lines and must not print the number as if it were the answer.

        The size is not used as a *ceiling*. That is the difference between
        this and `_blob_at`: a window into a file too large to hold is exactly
        the case this exists for, and refusing on size would restore the defect
        it was written to remove. It is looked up for existence only —
        `_render_window` passes the value it already has so the probe is not
        run twice.

        **Existence is settled here rather than by each caller**, because it
        was settled by each caller and they disagreed. A failing `git show`
        raised the base class, so a windowed read of a *deleted* file never
        reached the fallback that reads the base — the whole-file path had the
        taxonomy and the windowed path did not, and `head_text` had neither.
        Codex, 2026-09-07.
        """
        if size is None:
            size = self._blob_size(rev, rel)
        if size is None:
            raise FileNotAtRevision(
                "{} is not a tracked file at {}".format(rel, _abbrev(rev)))
        proc = subprocess.Popen(
            ("git", "--no-pager", "-C", str(self.root), "show",
             "{}:{}".format(rev, rel)),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=_git_env(),
        )
        kept = []
        number = 0
        scanned = 0
        complete = True
        drained = False
        pending = b""
        try:
            while True:
                chunk = proc.stdout.read(65_536)
                if not chunk:
                    break
                scanned += len(chunk)
                pending += chunk
                # Split on the last newline so a multi-byte character never
                # straddles a chunk boundary and decodes as two replacements.
                cut = pending.rfind(b"\n")
                if cut < 0:
                    if scanned > MAX_LOCAL_SCAN_BYTES:
                        complete = False
                        break
                    continue
                ready, pending = pending[: cut + 1], pending[cut + 1 :]
                for line in lines_of(_decoded(ready, rel)):
                    number += 1
                    if start <= number <= stop:
                        kept.append((number, line))
                if scanned > MAX_LOCAL_SCAN_BYTES:
                    complete = False
                    break
            if complete and pending:
                # A final line with no trailing newline is a line.
                for line in lines_of(_decoded(pending, rel)):
                    number += 1
                    if start <= number <= stop:
                        kept.append((number, line))
            drained = True
        finally:
            # Killed unless the pipe was read to the end — and `drained` says
            # that, where `complete` does not. A binary file raises out of the
            # decode with `complete` still True, and waiting on a git that is
            # still writing into a pipe nobody is reading is a deadlock, not a
            # tidy-up.
            if not drained:
                proc.kill()
            proc.stdout.close()
            stderr = proc.stderr.read()
            proc.stderr.close()
            status = proc.wait()

        # A scan cut short at the ceiling kills git, so a non-zero status is
        # expected there and says nothing. Only a completed read can report a
        # failure, and it must: `git show` on a path that is not in the tree
        # exits non-zero having printed nothing, which is indistinguishable
        # from an empty file if the status is ignored.
        if complete and status != 0:
            raise WorkspaceError("cannot read {} at {}: {}".format(
                rel, _abbrev(rev), stderr.decode("utf-8", "replace").strip()))
        return kept, (number if complete else None), complete

    @staticmethod
    def _decode_record(chunk: bytes, cut_before: bool = False,
                       cut_after: bool = False) -> str:
        return _trimmed_decode(chunk, cut_before, cut_after)

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
        # **"The path is not there" and "git refused" were one value, and the
        # consequence fell on the model.** Both became `None`, `_blob_at` turned
        # that into `FileNotAtRevision`, and a real `critical` was rejected as
        # `unknown-path` with the reviewer told "do not report this finding
        # again" — over a git failure. The terminal prints one hard-coded
        # reason for every rejection, so the only trace in the job log blamed
        # the model. Found 2026-09-09.
        #
        # Measured rather than assumed, because the two are distinguishable and
        # only in stderr:
        #
        #     HEAD:nope.py       rc=128  fatal: path 'nope.py' does not exist
        #     HEAD:untracked.py  rc=128  fatal: path '…' exists on disk, but
        #                                not in 'HEAD'
        #     nosuchrev:app.py   rc=128  fatal: invalid object name
        #     HEAD:app.py        rc=0    blob
        #
        # The first two are answers about the file — it is not in the revision,
        # which is exactly what this method is asked. The third is this tool
        # failing to look, and it exits 2 rather than accusing anybody.
        #
        # The second was found by the suite one minute after the first version
        # of this went in: it refused an untracked file as a git failure, which
        # would turn "you are reading the disk, not the revision" — a real and
        # deliberate refusal — into "the check did not run".
        #
        # Checked against a shallow clone, because every GitLab runner makes
        # one: a real blob answers, a path that never existed answers `None`,
        # and a revision the clone does not carry refuses — which is right, and
        # is the whole distinction. That last case is guarded upstream anyway;
        # `_resolve_range` raises on a base outside the clone before any
        # citation is checked.
        if kind.returncode != 0:
            reason = kind.stderr or ""
            if "does not exist" in reason or "but not in" in reason:
                return None
            raise WorkspaceError(
                "git could not say what {!r} is at {}: {}".format(
                    rel, rev, (kind.stderr or "").strip() or "no message"))
        if kind.stdout.strip() != "blob":
            return None

        proc = subprocess.run(
            ("git", "-C", str(self.root), "cat-file", "-s", "{}:{}".format(rev, rel)),
            capture_output=True, text=True, check=False, env=_git_env(),
        )
        if proc.returncode != 0:
            # It was a blob one call ago. Anything failing now is the tool, not
            # the file — the object cannot have stopped existing in between,
            # and reporting it as absent would blame the change for a broken
            # repository.
            raise WorkspaceError(
                "git could not size {!r} at {}, having just called it a blob: "
                "{}".format(rel, rev,
                            (proc.stderr or "").strip() or "no message"))
        try:
            return int(proc.stdout.strip())
        except ValueError:
            return None

    def raw_text(self, path: str) -> str:
        """The blob at the reviewed revision, for local code that emits none of it.

        Was an alias of `blob_text` and is no longer, because the two answer
        different questions. `blob_text` serves `read_file` and is bounded by
        what may be *shown to the model*; this serves the citation check, which
        matches a quoted snippet against the file and emits nothing — and was
        being refused by a context ceiling it never spends. The consequence was
        measured: a weakness in a 658 KB file could be seen in the diff and not
        reported, because the check could not open the file to confirm the
        quote, and the artifact recorded the drop as `unknown-path`.

        Still bounded — by `MAX_LOCAL_SCAN_BYTES`, which is about memory rather
        than about context, and is checked before the read.
        """
        return self._blob_at(self.diff_head or "HEAD", self.repo_path(path),
                             MAX_LOCAL_SCAN_BYTES)

    def head_text(self, path: str, limit: int = MAX_HEAD_BYTES) -> str:
        """The first lines of a blob, for a reader that only needs the top.

        The generated-file classifier looks for a banner, which generators put
        on the first line. It reached the file through `blob_text`, so every
        file over the context ceiling raised, `tools.py` swallowed that into
        `head = ""`, and `classify("")` answered None — the classifier went
        blind on exactly the file class it exists for, since the generated
        files are the large ones. Measured: `classify` on the real head of a
        658 KB protobuf returns "Go generator banner"; on the empty string it
        returns nothing, and nothing is what it was being given.
        """
        rev = self.diff_head or "HEAD"
        rel = self.repo_path(path)
        lines, _total, _complete = self._window_at(rev, rel, 1, 200)
        return "\n".join(text for _n, text in lines)[:limit]

    def removed_text(self, path: str) -> str:
        """The content of a file **this change deleted**, at the base.

        `raw_text` reads the reviewed revision, where a deleted file is not —
        so a finding quoting the authorisation check that was removed failed
        citation validation as `unknown-path` and was dropped. The diff could
        inspire the finding and nothing could record it. Codex named this on
        the gate pass for the deletion repair, 2026-09-06.

        Narrow on purpose. It refuses any path this change did not delete, so
        it cannot become a general way of reading the base revision — the
        reason `blob_text` gives for reading the reviewed commit rather than
        the working tree applies just as much to reading whatever the parent
        happened to contain.
        """
        rel = self._deleted_path(path)
        # **A ceiling this had none of.** Written for the deletion repair, it
        # ran `git show` straight into `capture_output=True`, so the size check
        # that guards every live-file read was absent on the one path an
        # attacker chooses the size of. Measured on 2026-09-07: the same
        # 4,999,982-byte content was refused at 292 KB while it was live and
        # returned whole once the change deleted it.
        return self._blob_at(self.diff_base, rel, MAX_LOCAL_SCAN_BYTES)

    def _deleted_path(self, path: str) -> str:
        """The repo path, having established this change actually deleted it.

        Narrow on purpose. Reading the base is refused for any path this change
        did not delete, so it cannot become a general way of reading whatever
        the parent happened to contain — the reason `blob_text` gives for
        reading the reviewed commit rather than the working tree applies just
        as much there.
        """
        rel = self.repo_path(path)
        deleted = {obj.path for obj in self.changed_objects()
                   if obj.status == "deleted"}
        if rel not in deleted:
            raise WorkspaceError(
                "{} is not a file this change deleted; read it with read_file"
                .format(rel))
        if not self.diff_base:
            raise WorkspaceError(
                "there is no base revision to read {} from".format(rel))
        return rel

    def read_file(self, path: str, start_line: int = 1, end_line: int = 0) -> Tuple[str, bool]:
        """Return line-numbered text and whether it was trimmed."""
        return self._render_window(
            self.diff_head or "HEAD", self.repo_path(path), start_line, end_line)

    def read_removed_file(self, path: str, start_line: int = 1,
                          end_line: int = 0) -> Tuple[str, bool]:
        """The same window, at the base, for a file this change deleted."""
        return self._render_window(
            self.diff_base, self._deleted_path(path), start_line, end_line,
            at_base=True)

    def _render_window(self, rev: str, rel: str, start_line: int, end_line: int,
                       at_base: bool = False) -> Tuple[str, bool]:
        """A window of a file, line-numbered, whatever the file's size.

        **The window is why this exists.** Until 2026-09-07 `read_file` fetched
        the whole blob and sliced it, so the ceiling on the whole file was also
        a ceiling on any part of it: a `start_line`/`end_line` read of a large
        file was refused with the identical message, which for a while
        suggested passing `start_line` and `end_line`. A weakness introduced by
        a small diff to a large file could not be quoted at all.

        A read with no window still refuses above `MAX_READ_BYTES`, because
        that is what would be emitted — and the refusal now names a remedy that
        works, which the previous one deliberately did not, there having been
        none.
        """
        # Cleared first, so the record describes *this* read. A flag left set
        # by an earlier call is read as a statement about the current one, and
        # the message it produces would name a line the reader never asked for.
        # The `read_file` handler falls back to `read_removed_file` on absence,
        # which lands here a second time — so this has to be reset on entry and
        # not only on the paths that raise.
        self.last_read_clip = None
        # **Existence is settled before anything is streamed, on every path.**
        # It used to be settled only for a whole-file read, and the windowed
        # one inferred it: a failing `git show` raised a bare `WorkspaceError`,
        # so `read_file` with a window on a *deleted* file never reached the
        # fallback that reads the base — the taxonomy the whole-file path
        # exposes and the one the windowed path exposed were different, and the
        # deletion repair only covered the first. Codex, 2026-09-07.
        size = self._blob_size(rev, rel)
        if size is None:
            raise FileNotAtRevision(
                "{} is not a tracked file at {}".format(rel, _abbrev(rev)))
        want_whole = end_line <= 0 and start_line <= 1
        if want_whole and size > MAX_READ_BYTES:
            raise FileTooLarge(
                "{} is {} KB, over the {} KB limit for reading a whole "
                "file. Pass start_line and end_line to read part of it."
                .format(rel, size // 1024, MAX_READ_BYTES // 1024),
                size=size, ceiling=MAX_READ_BYTES)

        start = max(1, start_line)
        stop = end_line if end_line > 0 else (1 << 62)
        if stop < start:
            raise WorkspaceError(
                "end_line {} is before start_line {}".format(end_line, start))
        selected, total, complete = self._window_at(rev, rel, start, stop,
                                                    size=size)
        if total == 0:
            # An empty file, and not a missing one — two distinct states in
            # git, which this collapsed into the absence exception. A tracked
            # empty file then fell through to the deleted-file fallback and was
            # refused there as a path nothing deleted, so the reviewer was told
            # two untrue things about a file that is simply blank.
            return "{}{} (0 lines)".format(
                rel, " at the base revision" if at_base else ""), False
        if not selected:
            # Not an empty answer: `start_line` past the end is a question with
            # no lines behind it, and returning nothing would read as "those
            # lines are blank".
            if complete:
                raise WorkspaceError(
                    "{} has {} lines; start_line {} is past the end".format(
                        rel, total, start))
            raise WorkspaceError(
                "{} was read up to the {} KB scan limit without reaching line "
                "{}; how many lines it has is not established".format(
                    rel, MAX_LOCAL_SCAN_BYTES // 1024, start))

        # **Whole lines, and a header built from what survived.** The body was
        # cut mid-character and the header still named the range that had been
        # asked for, so a three-line window of 30,000-character lines answered
        # `lines 1-3` with line 3 absent — a claim about what was delivered
        # that nothing checked, which is the shape this tool exists to hunt.
        # Codex, 2026-09-07.
        #
        # The first line is kept whatever its length: dropping it would answer
        # a different question from the one asked, and a reader who sees one
        # clipped line knows more than one who sees none.
        rendered = ["{:>6} | {}".format(n, line) for n, line in selected]
        trimmed = False
        kept_lines = []
        used = 0
        for index, text in enumerate(rendered):
            cost = len(text) + (1 if kept_lines else 0)
            if kept_lines and used + cost > MAX_OUTPUT_CHARS:
                trimmed = True
                break
            kept_lines.append(text)
            used += cost
        if len(kept_lines) == 1 and len(kept_lines[0]) > MAX_OUTPUT_CHARS:
            kept_lines[0] = kept_lines[0][:MAX_OUTPUT_CHARS]
            trimmed = True
            # **Which cut this was.** The caller's message names a remedy, and
            # for this cut the remedy it used to name is the same call again:
            # one line is already the narrowest window, so `start_line=N,
            # end_line=N` returns these identical bytes. The line's real length
            # comes from `selected`, which holds it whole — `kept_lines` has
            # just been clipped and the number taken from it would be the
            # ceiling, not the size of what is missing.
            self.last_read_clip = ClippedLine(
                number=selected[0][0], chars=len(selected[0][1]),
                more_after=len(selected) > 1)
        selected = selected[: len(kept_lines)]
        body = "\n".join(kept_lines)
        # "of at least N" when the scan stopped at the ceiling. The exact count
        # is not known then, and printing one would be a guess dressed as a
        # measurement.
        counted = ("{}".format(total) if complete
                   else "at least {}".format(selected[-1][0]))
        header = "{}{} (lines {}-{} of {})".format(
            rel, " at the base revision" if at_base else "",
            selected[0][0], selected[-1][0], counted)
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
        # **Cleared on the way in, not only on the way out, and before the
        # argument checks.** `search` returns early for "no matches", and a
        # flag written only at the successful exit keeps the previous search's
        # answer — so a clean no-match search following a stopped one reported
        # "at least 0 match(es)". A stale qualifier is the same defect as a
        # missing one: the line says something about a search that did not
        # happen.
        #
        # Placing it after the argument checks left an empty pattern — which
        # raises before any search occurs — carrying the previous one's
        # qualifier: the same defect, two lines lower. Found by writing the
        # test for the fix rather than by reading it.
        self.last_search_truncated = False
        # **What the caller may record as read, taken from the records rather
        # than from the rendered answer.** `tools._paths_in_search` scanned the
        # body for `path:digits:`, and the body of a no-match answer begins
        # with the pattern echoed back — so
        # `search_code(pattern="zzzznotpresent:1:")` matched nothing anywhere
        # and recorded an exposure for a "file" named
        # `no matches for 'zzzznotpresent`. Measured 2026-09-07, repaired
        # 2026-09-09.
        #
        # The cost is not a wrong list. `exposures` is the record of what
        # reached the reviewer, and `gate._reviewed_nothing` is exactly
        # `not outcome.exposures` — so a run whose only tool call was a
        # no-match search with a colon-and-digits pattern looked like a run
        # that had read something, and walked past the branch that refuses a
        # review which opened nothing.
        #
        # Cleared here for the same reason `last_search_truncated` is: this
        # method returns early in three places, and a value written only at the
        # successful exit is the previous search's answer.
        self.last_search_paths: Tuple[str, ...] = ()
        if not pattern.strip():
            raise WorkspaceError("pattern must not be empty")
        max_results = max(1, min(max_results, 300))
        # `-z` puts a NUL between the path, the line number and the text.
        # Without it the parser has to guess where a path ends, and a path may
        # contain both separators git uses: `app/case-12-data.py:7:match` was
        # read as `app/case-12-data`, so an excluded file with a
        # line-number-shaped name came back. Codex, 2026-09-07 — and measured
        # against real `git grep` output rather than assumed.
        # `--column` gives the byte offset of the first match on each matched
        # line, which is what lets the parser keep the region *around* the match
        # instead of the head of the line. Without it, a minified line whose
        # match sits at byte 72,000 comes back as its first 8,000 bytes — a
        # record that no longer shows why it matched. It adds a field to match
        # lines and none to context lines, so the record shape varies; see
        # `_grep_records`.
        args = ["grep", "--no-color", "-n", "--column", "-E", "-I", "-z"]
        if not case_sensitive:
            args.append("-i")
        if context_lines > 0:
            args.append("-C{}".format(min(context_lines, 10)))
        args += ["-e", pattern]
        # **The revision under review, as every other reader uses.** `blob_text`
        # says in its own docstring why the working tree must not be trusted —
        # the checkout is material an untrusted contributor controls — and this
        # ran `git grep` with no revision, which searches exactly that. Built
        # as a real tree on 2026-09-06: a commit with no `require_admin` beside
        # a working tree that has one gave "absent" from `read_file` and one
        # match from here, so a verifier could refute a finding on a control
        # that is not in the change. No attacker needed: a later commit on the
        # branch, an earlier CI step, a checkout that is simply ahead.
        #
        # `blob_text` resolves the same way, so the two cannot disagree.
        rev = self.diff_head or "HEAD"
        args.append(rev)
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
        records, truncated = self._grep_stream(args, rev, context_lines > 0)
        # **Matched lines, not rendered lines.** With `-C` git returns the lines
        # around a match as well, and counting them made one hit with two lines
        # of context on each side into "5 match(es) for 'NEEDLE'" — a number the
        # model plans with, over a file containing one. Codex, third gate round,
        # 2026-09-07, and measured on a built repository rather than reasoned
        # about. The defect is older than this change: `total = len(hits)` has
        # counted context since context was added.
        total = sum(1 for _, matched, _path in records if matched)
        # Every record's file, matched or context: a context line is in the
        # conversation exactly as a matched one is, and `exposures` records
        # what reached the reviewer rather than what interested it. Order
        # preserved, duplicates dropped, so the list reads as the answer does.
        if total == 0:
            # `truncated` before the count. A search that ran out of time
            # before keeping a single line kept zero lines, and the zero branch
            # never looked — so "the reviewer asked whether this pattern occurs
            # anywhere" was answered "it does not", over a search that was
            # stopped. The truncation notice further down is reachable only
            # when something was found, which is the case where it matters
            # least.
            #
            # Zero *matches* rather than zero records, and the two differ only
            # under `-C`. Without context every record is a match by
            # construction, so this is the same branch it always was; with
            # context, git emits no context line except around a match, and the
            # exclude check drops a whole file at a time, so a surviving record
            # implies a surviving match. What is not claimed is that the
            # deadline is the only way to reach this — it is the only one
            # reachable today, and the message names it, which is a narrower
            # statement than the code can prove.
            if truncated:
                # The phrase this refusal replaces must not appear in it. A
                # model skimming a tool error for a summary can take the words
                # out of the sentence that denies them, and the whole point is
                # that those two words were never true here.
                raise WorkspaceError(
                    "the search for {!r} was stopped at the {}s limit before "
                    "reading any of the repository. Nothing was established "
                    "about this pattern in either direction. Narrow it with "
                    "path_glob or a more specific pattern and ask again."
                    .format(pattern, GIT_TIMEOUT_SECONDS))
            return "no matches for {!r}".format(pattern), 0

        # **`max_results` limits matches, and the cut lands before a match, not
        # inside a block.** Slicing the rendered lines let the leading context
        # of the first hit fill the whole allowance: `max_results=1` over a file
        # with two lines of context returned `f.py:1:aaa` under the heading
        # "5 match(es)" — every line shown was one that did not match, and the
        # line that did was the one dropped. Cutting at the record *after* the
        # last match allowed keeps every shown match together with the context
        # git gave it. What it does *not* claim is that no unmatched line
        # survives its match: the leading context of the first withheld match
        # is still shown, and that is a real line at a real number which the
        # caller asked for by passing `context_lines`. The claim being made is
        # narrower and is the one that was false — the matches shown, the
        # heading and the note account for each other exactly.
        #
        # **Both ceilings are applied here, at record boundaries.** The
        # character ceiling used to be a `body[:60_000]` cut taken *after* this
        # selection, and a cut in the joined string lands wherever it lands: on
        # two blocks of `context_lines=10` it could end inside the second one,
        # before its matching line — leaving context on screen for a match that
        # was never shown, while the heading counted that match and no note
        # mentioned it, because `kept` had been settled before the string was
        # cut. Codex, fourth gate round, 2026-09-07. A ceiling enforced in a
        # different unit from the thing it is protecting is the same shape as
        # the byte-offset-into-a-decoded-string defect above.
        end = len(records)
        kept = 0
        used = 0
        for position, (line, matched, _path) in enumerate(records):
            if used + len(line) + 1 > MAX_OUTPUT_CHARS or (
                    matched and kept == max_results):
                end = position
                break
            used += len(line) + 1
            if matched:
                kept += 1
        shown = records[:end]
        # `kept` is now, by construction, the number of matches in `shown` —
        # which is what the note below subtracts from. The two used to be
        # computed at different times over different things, and that is the
        # whole of the defect.
        body = "\n".join(line for line, _matched, _path in shown)
        # **The paths of the lines actually shown**, set here rather than
        # over every record read: `max_results` and the character ceiling
        # both cut, and a file whose only lines were dropped never reached
        # the reviewer. `exposures` records what reached it.
        self.last_search_paths = tuple(
            dict.fromkeys(path for _line, _matched, path in shown))
        # **Three different facts, and a search can be all three at once.**
        # These were mutually exclusive branches, with `truncated` first, and
        # that hid the one the reader most needs: measured on this repository,
        # `search(".", max_results=5)` answered "at least 1471 match(es)",
        # printed five lines, and said only "the scan stopped here" — nothing
        # accounted for the 1,466 matches it had actually reached and was
        # withholding. "The scan stopped" is about what was *not read*; "N more
        # not shown" is about what was read and not printed. One does not imply
        # the other and neither substitutes for it. Codex, sixth gate round,
        # 2026-09-07.
        notes = []
        if total > kept:
            # `total - kept`, not `total - len(shown)`: `shown` holds context
            # lines too, so subtracting its length reported fewer withheld
            # matches than there are and could reach zero while matches were
            # being withheld — the note then vanished entirely.
            notes.append(
                "… {} more match(es) not shown; narrow the pattern or set "
                "path_glob".format(total - kept))
        elif end < len(records):
            # **Every match counted is shown, and lines are still missing.**
            # The ceiling can land on a context record that follows the last
            # match — every match accounted for, `total == kept`, and neither
            # note above fires, while lines the caller asked for by passing
            # `context_lines` were dropped in silence. Codex, fifth gate round,
            # 2026-09-07: an answer that claims an exact result must not also
            # be quietly short of what was requested. It says what was left out
            # rather than pretending nothing was.
            notes.append(
                "… the size limit was reached; every match is shown but some "
                "of the surrounding context is not. Ask for fewer "
                "context_lines to see it.")
        if truncated:
            # "At least", never a total. Counting the rest means reading the
            # rest, which is the thing being avoided — and a fabricated total
            # is worse than an honest floor.
            # **"Stopped" is what is known; "there are more" is not.** The
            # ceiling is crossed by the record that crosses it, and that record
            # may be the last one git had — the scan then ends complete while
            # the note claims another match exists. Codex, 2026-09-07, on the
            # gate for the record-bounding change. A one-record lookahead would
            # settle it and costs a read; saying only what was established
            # costs nothing and is the answer the rest of this file gives.
            notes.append(
                "… the scan stopped here, so this is what was reached and not "
                "necessarily all there is. Narrow the pattern or set path_glob "
                "to see the rest.")
        note = ("\n" + "\n".join(notes)) if notes else ""
        # A floor, for the same reason: the scan stopped, so the count is what
        # it reached. It is not "at least N and there is an N+1" — it is "N,
        # and nothing establishes whether there are more".
        head = "at least {}".format(total) if truncated else str(total)
        # **The count leaves through a channel that cannot qualify it.** The
        # body says "at least N" and the tool summary printed "N match(es)"
        # from the same search — two statements about one result, disagreeing,
        # and the artifact keeps the second. Recorded the way
        # `last_diff_truncated` records the same fact for `diff`, because
        # widening the return type would touch every caller to carry one bit.
        self.last_search_truncated = truncated
        return "{} match(es) for {!r}:\n{}{}".format(head, pattern, body, note), total

    @staticmethod
    def _without_revision(line: str, rev: str) -> str:
        """A `git grep REV` line with its revision prefix removed.

        Matched against the revision the search actually passed rather than by
        counting separators: a path may contain either of them, and a line that
        merely begins with something prefix-shaped is not one. Passed in rather
        than re-read from the workspace, so the stripping cannot disagree with
        the search that produced the line.

        Only the colon form reaches here now: with `-z` the path is a NUL-
        terminated field, so `REV:path` is the whole of it whether the line is
        a match or context. Before `-z` the two spellings differed —
        `REV:path:line:text` against `REV-path-line-text` — and a version that
        knew only the colon left the revision on every context line, which then
        failed the exclude check and was shown to the model as a path
        `read_file` refuses. Codex found that on the gate pass, 2026-09-07, and
        refused the heuristic that replaced it as well.
        """
        prefix = rev + ":"
        return line[len(prefix):] if line.startswith(prefix) else line

    def _grep_stream(self, args, rev="", with_context=False):
        """Run `git grep` and stop reading at the ceiling.

        Returns (kept records, whether more were left unread). A record is
        `(rendered line, whether that line matched, the file it came from)`.
        The path is carried rather than parsed back out of the rendered
        line: `tools._paths_in_search` did that, and the body of a no-match
        answer echoes the pattern, so a search for `zzzz:1:` recorded a file
        that does not exist as having been read. Excluded paths are
        filtered as the lines arrive, so an excluded directory cannot fill the
        budget with output that would have been discarded anyway.

        **The second field is why this returns pairs.** With `-C` git emits the
        lines *around* a match as well, and they arrived here indistinguishable
        from the match — so the caller counted them, and one hit with two lines
        of context on each side was reported as five matches. `--column` is
        present on a matched line and absent on a context line, which is the
        same fact the framer already reads, so the distinction costs nothing.

        `with_context` is false for the default search, where git emits no
        context at all and every record is a match by construction. That is not
        a shortcut: a record whose column was cut off by the end of the stream
        is deliberately given no column, and without this it would be demoted to
        context and lost from the count on the one path where nothing is
        ambiguous.
        """
        # Built before the clock starts, for the reason given in `_bounded`.
        argv = self._argv(*args)
        deadline = time.monotonic() + GIT_TIMEOUT_SECONDS
        proc = subprocess.Popen(
            argv,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            # **Binary.** The column git reports is a byte offset into the
            # line, so the window around it is cut in bytes and decoded after —
            # a text stream would have decoded first and made that number point
            # into a different word. Decoding is `_grep_stream`'s job now, per
            # field, because a path and a matched line want opposite treatment:
            # the path reversibly, the text strictly.
            env=_git_env(),
        )
        hits, size, truncated = [], 0, False
        # Set only when the record loop reaches the end of the generator. Every
        # other way out — a ceiling, the deadline, an exception from the strict
        # decoder — leaves it false, and each of those leaves git writing.
        drained = False
        try:
            # **Records, not lines.** With `-z` the path is a NUL-terminated
            # field, and a path may legally contain a newline — measured on
            # 2026-09-07: `app/od\nd.py` arrives as two `readline` results, so
            # iterating the stream by line split one record into two malformed
            # ones and handed the exclude check a path that was never there.
            # A record is `REV:path NUL number NUL text` and ends at the first
            # newline *after* the second NUL. Codex named it on the gate pass
            # for `-z` itself, which fixed the delimiter and left the framing.
            # **A generator that stops is indistinguishable from a stream that
            # ended.** `_grep_records` returns when the deadline passes, and a
            # `for` loop reads that as the end of the output — so a search
            # killed by its own timeout came back as a search that found
            # nothing, which is the defect `test_search_stopped_at_the_deadline`
            # was written for and which this rewrite reintroduced. The callback
            # records that it fired rather than only answering.
            def past_deadline():
                nonlocal truncated
                if time.monotonic() > deadline:
                    truncated = True
                return truncated

            for record in _grep_records(proc.stdout, should_stop=past_deadline):
                if past_deadline():
                    break
                # The hunk separator git writes between context blocks. It
                # carries no path, so it cannot be excluded and it must not be
                # counted: a search whose every real line was excluded would
                # otherwise report a nonzero result made of nothing but these.
                if record is HUNK_SEPARATOR:
                    continue

                # **The revision prefix comes off before anything reads the
                # path.** `git grep REV` prefixes every record with `REV:`, and
                # three things downstream take that field as the path: this
                # exclude check, `_paths_in_search` recording exposures, and the
                # model, which is shown the path and can only open it through
                # `read_file` — which takes repository paths.
                #
                # Decoded here and not in the parser. A path is whatever bytes
                # the filesystem holds, so `surrogateescape` keeps it reversible
                # rather than replacing what it cannot read; the text is decoded
                # strictly, because a replacement character in a quoted line is
                # a character the file does not contain.
                path = self._without_revision(
                    record.path.decode("utf-8", "surrogateescape"), rev)
                if not path or self.is_excluded(path):
                    continue
                if not record.line.isdigit():
                    continue
                number = record.line.decode("ascii")
                text = _window_around(record, self._decode_record)
                hits.append(("{}:{}:{}".format(path, number, text),
                             record.column is not None or not with_context,
                             path))
                size += len(path) + len(number) + len(text) + 3
                # Twice the rendered ceiling: enough that `max_results` and the
                # character trim still have something to choose from, bounded
                # enough that the process cannot be killed for holding it.
                #
                # Reachable only by *many* records now. One 320,000-character
                # minified line used to trip it on its own, after the only match
                # in the repository — so `truncated` was set while the count was
                # exact, and both its consumers then lied: the head became
                # `at least 1` and the note said "there are more" when there
                # were none, while the summary line printed `1 match(es)` from
                # the same search. Codex, on the gate for this, 2026-09-07.
                if size > MAX_OUTPUT_CHARS * 2 or len(hits) > MAX_SEARCH_HITS:
                    truncated = True
                    break
            else:
                # The `for` ran to the end of the generator. Only here is it
                # established that nobody is still waiting to write into a pipe
                # this loop has stopped reading.
                drained = True
        finally:
            # **Terminate whenever this loop stopped early, not only when a
            # ceiling stopped it.** `_window_around` decodes strictly and
            # *raises* — that is deliberate, a quoted line must be the line —
            # and the raise leaves this function through `finally` with
            # `truncated` false. git was then still writing: it blocked on a
            # full stdout pipe nobody would drain again, `proc.stderr.read`
            # blocked waiting for a process that could not exit, and the search
            # never returned at all. Measured on 2026-09-07, not argued: a file
            # with one bad byte on its first matched line and 6,000 matches
            # after it hung with no output past "searching…". A security gate
            # that never returns is worse than one that answers wrongly, and
            # the deadline does not help — nothing consults it from in here.
            # Codex, fifth gate round.
            #
            # `truncated or not drained`, because the two are not the same
            # thing in either direction: the deadline fires *inside* the
            # generator, which then returns, and the loop ends normally with
            # `truncated` already true and git still running.
            if truncated or not drained:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
            # stderr is read after stdout is done with, and capped for the same
            # reason: an error message is not a channel worth trusting either.
            raw_stderr = (proc.stderr.read(4_000) if proc.stderr else b"") or b""
            stderr = raw_stderr.decode("utf-8", "replace")
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
    "D": "deleted",
    "M": "modified",
    "R": "renamed",
    "T": "type changed",
}


def unreadable_source_paths(ws: "Workspace") -> List[str]:
    """Changed paths that are source and that nobody could be shown.

    Kept apart from `inventory_notes`'s `unreadable`, which is every object
    with no reviewable text — a rename, a mode change, a submodule pointer, a
    real image. Those are disclosed and block nothing. This is the third
    state: a `.js` or a `.py` git calls binary because of one NUL byte, where
    "no findings" would be said about a file the review never saw.

    Swallowed to an empty list on the same terms as its neighbour: a git
    invocation that fails must not take down a review already done.
    """
    try:
        objects = ws.changed_objects()
    except WorkspaceError:
        return []
    return [obj.path for obj in objects if obj.unreadable_source]


def inventory_notes(ws: "Workspace") -> Tuple[List[Tuple[str, str]], List[str]]:
    """What the report needs from the inventory: the unreadable, and the deleted.

    One function rather than the same two comprehensions on both runners: the
    two coverage blocks have drifted apart before, and the report reads
    whichever one filled it.

    The deleted list is here because `changed_files()` filters deletions out —
    correctly, since it is the list of files a reviewer is asked to open — and
    a deleted file therefore appeared in no part of the report at all. A deleted
    security control is one of the things this product exists to catch.

    Failures are swallowed to empty lists on purpose. These are lines in a
    report, not a gate; a git invocation that fails here must not take down a
    review that has already been done.
    """
    try:
        objects = ws.changed_objects()
    except WorkspaceError:
        return [], []
    unreadable = [(obj.path, obj.why_unreadable())
                  for obj in objects if not obj.has_reviewable_text]
    deleted = [obj.path for obj in objects if obj.status == "deleted"]
    return unreadable, deleted


def _parse_numstat(raw: str):
    """Parse ``git diff --numstat -z`` into (path, added, removed, binary).

    Two shapes in the NUL-separated form. An ordinary entry is one field,
    ``added\\tremoved\\tpath``. A rename or copy puts nothing after the second
    tab and follows with two more fields: ``added\\tremoved\\t``, ``old``,
    ``new`` — so the stream is walked rather than split into lines.

    Binary files report ``-`` for both counts rather than a number. Coercing
    that to zero would say a binary file changed nothing, which is the sentence
    a reader would then use to skip it; it is reported as binary instead, and
    what "nothing to read here" means is decided by the caller rather than by a
    silent zero.
    """
    fields = [f for f in raw.split("\0") if f != ""]
    i = 0
    while i < len(fields):
        # Split twice and no more. A tab is a legal character in a path on
        # Linux and `-z` does not quote it, so an unlimited split cuts such a
        # name in half and files the change under a path nothing looks up.
        parts = fields[i].split("\t", 2)
        if len(parts) < 3:
            i += 1
            continue
        added_raw, removed_raw, path = parts[0], parts[1], parts[2]
        if not path:
            # A rename or copy: the two paths are the next two fields.
            if i + 2 >= len(fields):
                break
            path = fields[i + 2]  # the new name, as everywhere else here
            i += 3
        else:
            i += 1
        binary = added_raw == "-" or removed_raw == "-"
        added = 0 if binary else int(added_raw or 0)
        removed = 0 if binary else int(removed_raw or 0)
        yield path, added, removed, binary


# Git's own mode words, kept as themselves. A number here is more honest than a
# name: `100755` is what git wrote and what a reader can look up, and inventing
# "executable" would hide the difference between a mode change and a type one.
MODE_SUBMODULE = "160000"
MODE_SYMLINK = "120000"
MODE_ABSENT = "000000"


# The attributes that decide whether git shows a file's contents. `binary` is
# a macro for `-diff -text`, and `diff` may be set, unset, unspecified or
# pointed at a driver — every spelling of it changes what a review can read.
# Nothing else in an attributes file can, which is why the list is short and
# why refusing on anything outside it was a gate that fired on nothing.
_DIFF_ATTRIBUTES = frozenset({"diff", "text"})

# `binary` is git's own macro and expands to `-diff -text` — but **only when it
# is set**. `-binary`, `!binary` and `binary=anything` do not invoke the macro
# and hide nothing, and the first version of this reduced every token to its
# name before testing it, so all three exited 2 on a checkout nothing was wrong
# with. Codex, 2026-09-09. The macro is therefore matched as the bare word.
_BINARY_MACRO = "binary"


def _first_diff_attribute(body: str) -> Optional[str]:
    """The first line of an attributes file that changes what git will show.

    `None` when no line does. Comments and blanks are skipped, the leading
    pattern is dropped, and each remaining token is reduced to its attribute
    name: `-diff`, `!diff` and `diff=driver` are all `diff`.

    Written 2026-09-09 after the first version of `refuse_untrusted_attributes`
    refused any non-blank file at all — so a comment, or an ordinary
    `* export-ignore`, exited 2 on a repository nothing was wrong with.

    Eleven shapes were measured against git itself and none is missed: a plain
    `-diff`, a macro defined and used in the same file, tabs, trailing space, a
    comment before a harmful line, and the harmless ones that used to be
    refused.

    **The macro shape is measured and the pin closes it.** A `[attr]` macro
    defined in the *tree's* `.gitattributes` and only *used* here — `*.py
    hidden` — puts no dangerous token in this file, so this predicate lets it
    through, and that is correct: run through `Workspace.diff`, which pins
    `--attr-source` to the empty tree, the macro is undefined and the diff
    comes back readable. The same macro **defined and used in this file** does
    hide it, and is refused, because the definition carries `-diff`.

    Established on the second attempt. The first harness ran a hand-rolled
    `git diff --attr-source` with `check=False` and read only stdout, so a git
    that refused the flag returned an empty string and "the diff is hidden" was
    true for every case including the control — a measurement with no control
    is what let a claim of a gap be made and then withdrawn. The second uses
    the product's own reader and a case where nothing is set anywhere.
    """
    for line in (body or "").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        tokens = stripped.split()[1:]
        for token in tokens:
            if token == _BINARY_MACRO:
                return stripped
            name = token.lstrip("-!").split("=", 1)[0]
            if name in _DIFF_ATTRIBUTES:
                return stripped
    return None


def _parse_raw(raw: str):
    """Parse ``git diff --raw -z -M`` into (path, old_path, code, old_mode, new_mode).

    Chosen over `--name-status` because it is the only form that carries the
    modes, and the modes are what tell a mode-only change from a rename that
    edited nothing, a symlink from a regular file, and a submodule bump from
    either. All three look like an ordinary modification without them, and all
    three have no source line for a reviewer to read.

    One entry is ``:<old mode> <new mode> <old sha> <new sha> <status>`` in the
    first field, then the path — or, for a rename, the old path and the new one
    as two further fields.

    The `C` branch is kept and will not fire. Copy detection needs `-C`, which
    is deliberately not asked for: it is expensive on large changes, and every
    caller here passes `-M` alone, so a copied file arrives as an addition.
    Written down because the branch reads like support for something that is
    not switched on, and the next person to see `C` here should know it means
    "if a caller ever asks for copies" rather than "copies are found".
    """
    fields = [f for f in raw.split("\0") if f != ""]
    i = 0
    while i < len(fields):
        meta = fields[i]
        if not meta.startswith(":"):
            i += 1
            continue
        parts = meta[1:].split()
        if len(parts) < 5:
            i += 1
            continue
        old_mode, new_mode, code = parts[0], parts[1], parts[4]
        if code[:1] in ("R", "C"):
            if i + 2 >= len(fields):
                break
            yield fields[i + 2], fields[i + 1], code[:1], old_mode, new_mode
            i += 3
        else:
            if i + 1 >= len(fields):
                break
            yield fields[i + 1], "", code[:1], old_mode, new_mode
            i += 2


@dataclass(frozen=True)
class ChangedObject:
    """One thing this change did, and whether a reviewer could read it.

    The inventory `changed_files()` returns cannot answer the question a
    completeness rule has to ask. It applies `--diff-filter=ACMRT`, so a pure
    deletion is not in it at all — and the removed lines of a deleted guard are
    exactly the change a security review exists to catch. It also cannot tell a
    file whose text is in the diff from one whose text can never be: a binary
    blob, a mode-only change and a pure rename appear as ordinary modifications
    and carry no readable line.

    A rule built on that list would fail healthy reviews for the second reason
    and miss deletions for the first. This is the list it should have been.
    """

    path: str
    status: str
    added: int = 0
    removed: int = 0
    binary: bool = False
    old_path: str = ""
    old_mode: str = ""
    new_mode: str = ""

    @property
    def submodule(self) -> bool:
        return MODE_SUBMODULE in (self.old_mode, self.new_mode)

    @property
    def symlink(self) -> bool:
        return MODE_SYMLINK in (self.old_mode, self.new_mode)

    # There was an `executable` property here, added on 2026-09-09 because
    # the ruling named executable files and removed the same day because the
    # rule it fed was replaced. It asked whether either endpoint's mode ended
    # in `755`, and `looks_like_source` used it to promote a name neither
    # table knew. With the default now "source unless it is a recognised
    # asset", `bin/server` is source without being asked about its mode, and
    # the property answered nothing that changed an outcome. It is gone rather
    # than kept unused: a property whose docstring explains a decision it no
    # longer takes part in is the shape this repository keeps being caught by.

    @property
    def mode_changed(self) -> bool:
        """The permissions moved, whatever else did.

        Its own fact rather than a shrug about a zero-line diff: a script that
        becomes executable is a security-relevant change with no source line in
        it, and a rule that only knows "nothing to read" would file it beside a
        rename and forget it.
        """
        return bool(self.old_mode and self.new_mode
                    and self.old_mode != self.new_mode
                    and MODE_ABSENT not in (self.old_mode, self.new_mode))

    @property
    def has_reviewable_text(self) -> bool:
        """Would a diff of this object put any source line in front of anyone?

        False for a binary blob, for a submodule pointer, for a change of mode
        alone, and for a rename that moved a file without editing it. Not
        "unimportant" — a rename of a security-critical file is worth knowing
        about, and a script gaining the executable bit certainly is; both are in
        this list for that reason. It is that *reading* them is not a thing
        anyone can do, so a rule that demanded evidence of reading would be
        demanding the impossible, and a gate that cannot be satisfied gets
        deleted rather than obeyed.
        """
        if self.binary or self.submodule:
            return False
        return bool(self.added or self.removed)

    # Paths whose content is source whatever git says about it. Git decides
    # `binary` from the bytes — a NUL in the first 8000 — so one such byte in
    # a comment turns a JavaScript file into "Binary files … differ", and a
    # reviewer is shown nothing while the gate counts the file as accounted
    # for. Codex, 2026-09-09, ruling on that: three states, not two.
    #
    # By extension and by name, because that is what a person calls source.
    # The list is deliberately not exhaustive and does not need to be: a
    # source path this does not name behaves as it did before, and one it
    # does name can no longer be hidden by a byte.
    SOURCE_SUFFIXES = frozenset({
        ".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".go", ".rb",
        ".php", ".java", ".kt", ".scala", ".cs", ".c", ".h", ".cc", ".cpp",
        ".hpp", ".rs", ".swift", ".m", ".mm", ".sh", ".bash", ".zsh", ".pl",
        ".pm", ".ex", ".exs", ".erl", ".lua", ".r", ".sql", ".graphql",
        ".proto", ".tf", ".yml", ".yaml", ".json", ".toml", ".ini", ".cfg",
        ".env", ".conf", ".gradle", ".cmake", ".mk", ".bzl",
    })
    SOURCE_NAMES = frozenset({
        "Dockerfile", "Makefile", "Jenkinsfile", "Gemfile", "Rakefile",
        "Procfile", "CMakeLists.txt", "BUILD", "WORKSPACE",
    })

    # **The list that decides, and it is the list of what is *not* source.**
    #
    # The first two attempts named source instead, and Codex refused both on
    # the same ground: *"The comment that the list 'does not need to be'
    # exhaustive is false for a completeness check: every omission restores
    # the exact bypass the check was introduced to prevent."* `Login.vue` with
    # one NUL byte was invisible, and so were `.svelte`, `.dart`, `.clj`,
    # `.sol` and every extension nobody had thought of yet — a silent "no
    # findings" over source no reviewer received, which is the failure this
    # product exists to prevent.
    #
    # Naming the assets instead makes the omissions fall the other way: a
    # format missing from this list is *reported* rather than hidden, and a
    # report naming one file too many is a visible, forgivable false alarm
    # with a documented move behind it. An omission in the other list was
    # silent and permanent.
    #
    # What belongs here is anything **no reviewer could read at any setting**:
    # rendered content, compressed archives, compiled output, binary data
    # formats. That is the ruling's "disclosed non-source change" — a PNG
    # blocks nothing not because images are safe, but because there is no text
    # being kept from anybody.
    #
    # `.jar` and `.war` are here and Codex named them questionable. They are
    # compiled deployables and a swapped one is a supply-chain change — and no
    # reviewer can read one either way, so calling it withheld source would
    # fail every dependency update forever. `LIMITATIONS.md` carries that as a
    # case seen and left, not overlooked.
    #
    # **`.bin` and `.dat` were here and were taken out.** Codex, 2026-09-09:
    # *"filename suffixes do not prove that a file is compiled output"* —
    # `scripts/bootstrap.bin` at mode `100755` is as likely to be a shell
    # script, and this table said it was an asset. Every other entry names a
    # format; those two name nothing, so they belong on the default side
    # where an unrecognised name is accounted for rather than excused.
    #
    # The list is checked for the false-alarm direction as well, because
    # inverting the default made every omission here a merge that comes out
    # incomplete. `.avif` and `.heic` were missing on the first pass and would
    # have blocked an ordinary image replacement — Codex found them, and the
    # packaging, translation and model-weight rows went in from the same
    # question asked of the whole table.
    ASSET_SUFFIXES = frozenset({
        # rendered and drawn
        ".png", ".jpg", ".jpeg", ".jfif", ".gif", ".webp", ".avif", ".heic",
        ".heif", ".bmp", ".ico", ".tiff", ".tif", ".svg", ".pdf", ".psd",
        ".ai", ".sketch", ".eps",
        # played
        ".mp3", ".mp4", ".wav", ".ogg", ".webm", ".mov", ".avi", ".flac",
        ".m4a", ".m4v", ".mkv", ".aac", ".wma",
        # typeset
        ".woff", ".woff2", ".ttf", ".ttc", ".otf", ".eot",
        # compressed
        ".zip", ".gz", ".tgz", ".bz2", ".xz", ".7z", ".rar", ".tar",
        ".zst", ".lz4", ".br",
        # compiled or linked output, and the debug files beside it
        ".jar", ".war", ".ear", ".exe", ".dll", ".so", ".dylib", ".a", ".o",
        ".obj", ".lib", ".class", ".pyc", ".pyo", ".wasm", ".elf", ".node",
        ".ko", ".pdb", ".map", ".dsym",
        # packaged for installation
        ".apk", ".ipa", ".aab", ".whl", ".egg", ".deb", ".rpm", ".msi",
        ".nupkg", ".gem",
        # compiled translations
        ".mo", ".qm",
        # data a person reads through a program
        ".csv", ".tsv", ".parquet", ".avro", ".orc", ".arrow", ".npy",
        ".npz", ".pkl", ".db", ".sqlite", ".sqlite3", ".mdb",
        ".xlsx", ".xls", ".docx", ".doc", ".pptx", ".ppt", ".rtf", ".odt",
        # model weights
        ".h5", ".onnx", ".pt", ".pth", ".safetensors", ".pb", ".tflite",
        # images of machines
        ".iso", ".dmg", ".img", ".vmdk", ".qcow2",
    })

    @property
    def looks_like_source(self) -> bool:
        """Whether this path is source, whatever git made of its bytes.

        The third state. A PNG that git calls binary is an
        *intentionally non-source object* and blocks nothing; a `.js` that git
        calls binary is **source nobody could read**, and a review that says
        "no findings" over it is saying it about a file it never saw.

        **The default is source, and only `ASSET_SUFFIXES` gets out of it.**
        Two earlier versions asked the opposite question — is this name on a
        list of source extensions — and Codex refused both: *"every omission
        restores the exact bypass the check was introduced to prevent."*
        `Login.vue` with one NUL byte was invisible, and so was every language
        nobody had added yet. A completeness check cannot be built on a list
        of what it knows about, because the thing it exists to catch is what
        nobody thought of.

        Asked in this order, and the order is the whole design: a recognised
        asset is not source whatever else is true of it, and everything else
        is. `SOURCE_SUFFIXES` and `SOURCE_NAMES` survive as a fast, readable
        statement of the common case; removing them would not change one
        answer, and they are checked first so that a name in both — there are
        none today — resolves as source.
        """
        name = self.path.rsplit("/", 1)[-1]
        if name in self.SOURCE_NAMES:
            return True
        # `dot > 0` and not `dot >= 0`, because a leading dot is a hidden file
        # and not an extension — `.gitignore` is not a `.gitignore` file. The
        # consequence Codex found is that a name which is *only* a dotted
        # suffix never matched: `config.env` was recognised and the canonical
        # `.env` was not. So the whole name is tried as well.
        if name.lower() in self.SOURCE_SUFFIXES:
            return True
        dot = name.rfind(".")
        suffix = name[dot:].lower() if dot > 0 else ""
        if suffix in self.SOURCE_SUFFIXES:
            return True
        return suffix not in self.ASSET_SUFFIXES

    @property
    def unreadable_source(self) -> bool:
        """Source this run could not be shown. Coverage is partial when true.

        Not `has_reviewable_text`'s complement: a rename with no edit, a mode
        change and a submodule pointer are all unreadable and none of them is
        source hidden from a reviewer. This is the one that makes a review
        incomplete.
        """
        # A symlink is excluded for the same reason as a submodule, and it
        # became reachable when the default flipped to "source": a symlink's
        # whole content is one target path, and git prints it. It is
        # *disclosed*, and this state is for what was withheld. `bin/link`
        # otherwise came out withheld source on a name no table knew.
        #
        # `_is_only_a_pointer` and not `submodule or symlink`, because those
        # two ask whether *either* endpoint is one. Git's type change
        # `120000 -> 100755` has a symlink on one side and a real executable
        # on the other, and excluding it would lose the file the machine now
        # runs — the defect Codex found in the previous version of this rule,
        # arriving again one property along.
        return bool(self.binary and not self._is_only_a_pointer()
                    and self.looks_like_source)

    def _is_only_a_pointer(self) -> bool:
        """Was this a submodule or a symlink on every side it existed?

        Both are records of *where something else is*, and git prints them
        whole: two commit ids, or one target path. Neither is source withheld
        from a reviewer. But a change with a pointer on one side and a real
        file on the other is a real file arriving or leaving, and the file is
        what this question is about.
        """
        pointers = (MODE_SUBMODULE, MODE_SYMLINK)
        present = [mode for mode in (self.old_mode, self.new_mode)
                   if mode and mode != MODE_ABSENT]
        return bool(present) and all(mode in pointers for mode in present)

    def why_unreadable(self) -> str:
        """Why no source line of this object can be put in front of a reviewer.

        Empty when there is text to read. A sentence rather than a code,
        because it is written into the report for a person: "3 files could not
        be read" invites the question this answers, and a reader who cannot get
        the answer assumes the worst or, worse, assumes nothing.
        """
        if self.has_reviewable_text:
            return ""
        if self.submodule:
            return "submodule pointer"
        if self.binary:
            return "binary"
        if self.mode_changed:
            return "mode {} → {}".format(self.old_mode, self.new_mode)
        if self.old_path:
            return "moved from {}, unchanged".format(self.old_path)
        return "no lines changed"


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
