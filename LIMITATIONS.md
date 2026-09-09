# What this is not, and what it has not been shown to do

Read this before putting the agent in front of anyone's merge requests. It is
written to help you decide against it, because the material that would help you
decide for it does not exist yet.

**Status: experimental research preview. Not suitable for reviewing untrusted
contributions.** Findings are model-generated leads, not security conclusions.

"Advisory only" is not by itself a sufficient boundary, and calling it that
would be the more comfortable half of the truth. While prompt injection is
unresolved, an attacker who can write a comment in the repository can make a
real finding look refuted to the person reading the report. That is less
dangerous than bypassing a gate and it is still attacker-influenced
reassurance, which is the tool's only output.

---

## The one-line version

A clean result means the agent read some code and reported nothing. It does not
mean the change is safe, and it does not mean the change was fully examined.

## One read ceiling was serving two different purposes — fixed

`MAX_READ_BYTES` exists to stop a hostile change exhausting the model's
context. Four readers of a file were being judged by it, and three of them put
none of the file in front of the model.

| reader | what happened, measured on a built repository |
|---|---|
| `read_file`, a window of three lines | refused, **word for word** as the whole file was |
| the generated-file classifier | refused, swallowed into `head = ""`; a 658 KB protobuf was never labelled generated |
| the citation check | refused, and the claim dropped as `unknown-path` — *"still does not resolve to a readable file"* |
| the deleted-file reader | **no ceiling at all**: the same 4,999,982 bytes were refused while live and returned whole once deleted |

So a weakness introduced by a small diff to a large file could be seen in the
diff and not reported, and the artifact recorded a reason that was not the
reason. The path resolved; the file was merely large.

**Split by purpose.** `MAX_READ_BYTES` keeps its meaning — the ceiling on what
is *emitted to the model* — and a whole-file read above it is still refused,
with a message that now names a window, which now works. `MAX_LOCAL_SCAN_BYTES`
is the ceiling on what local code may hold and never emits. A test asserts the
second is not below the first, because lowering the wrong one would make
citation stricter than reading and restore the defect through an edit to a
number.

**Every blob read goes through one revision-aware fetcher.** That is the
structural half, and it is what the deleted-file hole argued for: a ceiling
added at the fetcher applies at head and at base alike, and a future reader
cannot acquire a revision without also acquiring a limit. The narrow guard on
reading the base survives — any path this change did not delete is still
refused.

**"Not there" and "too large" are now different errors.** They were one, and
the fallback branched on nothing: `except WorkspaceError` around the live read
took every failure as evidence of a deletion, so a large file entered the
deletion branch, was refused there for an unrelated second reason, and reached
the artifact as `unknown-path` with the detail *"is not a file this change
deleted; read it with read_file"* — advising the tool that had refused it
first. A file above the local ceiling is now rejected as `file-too-large`, with
its own counter and its own line in the report.

**And the window had to be bounded in characters, not only in lines.**
`excerpt` bounded a window at 25 lines and both callers put the result straight
into something a model reads. A file that is one enormous line has one line: a
299,990-byte single-line file produced a 299,999-character "window of 25 lines"
and every line-based check called it small. Widening the local ceiling would
have made it 8 MB. Each line is clipped, then the window is narrowed towards
the cited line until the body fits — and the cited line survives either way,
because a window that drops the code being argued about answers a different
question from the one asked.

**What is still true.** A file above `MAX_LOCAL_SCAN_BYTES` cannot be cited at
all: nothing can confirm a quotation from it. That is now said out loud, in the
rejection and in the report, rather than recorded as a missing path. And 8 MB
is chosen, not derived — large enough that no honest source file reaches it,
small enough to hold, and no measurement says 8 rather than 2 or 32.

## The search read the working tree; every other reader read the revision — fixed

`blob_text` says it in its own docstring — the checkout "is material an
untrusted contributor controls, and what sits at a path on disk need not be
what the commit says is there" — and `search` built a `git grep` with no
revision, which searches exactly that. Built as a real repository on
2026-09-06: the reviewed commit has no `require_admin`, the working tree has
one.

| reader | answer |
|---|---|
| `read_file` at the reviewed revision | the guard is absent |
| `search` for the same name | **1 match** |

A verifier that refuted a finding because "the guard is right there" could be
looking at code that is not in the change. It needed no attacker: a later
commit on the branch, an earlier CI step that wrote a file, a checkout simply
ahead. The reasoning `blob_text` gives had never been applied to the function
beside it.

**Four rounds, each finding the layer under the last.** Passing the revision
makes `git grep` prefix every line, and three things downstream read the first
field as a path — the exclude check, the exposure record, and the model, which
can only open a repository path. Stripping `REV:` then missed context lines,
which git spells `REV-path-line-text`. Parsing that by hand was refused,
because a path may contain either separator and `app/case-12-data.py:7:x` was
read as `app/case-12-data`. So the search runs with `-z`, whose NUL no path can
contain — and `-z` fixes the delimiter while leaving the framing: a path may
legally contain a newline, so reading the stream by line split one record into
two. Measured against real output rather than assumed.

**It also uncovered an older defect.** The exclude check read the path as
everything before the first colon, so on a context line it tested
`app/auth.py-1-def run(...)` and matched nothing. Searching an excluded file
with `context_lines=2` returned a line of it. That predates all of this; the
revision prefix only made it visible.

**And a fourth round, on 2026-09-07, replaced the parser again.** A single
minified line broke two claims the search made about itself. The trim was
`body[:60_000].rsplit("\n", 1)[0]`, and on a slice holding no newline that
returns the slice — so what sat under `bundle.js:1:` was a fragment ending
mid-token and reading as the code at that line. Worse, the scan's own ceiling
was reached by that one 320,000-character record, so `truncated` was set after
the *only* match in the repository: the head printed `at least 1` for an exact
count, the note said "there are more" when there were none, and the summary
line printed `1 match(es)` from the same search.

The fix is not a clip. Codex refused a prefix clip outright — on a line whose
match is at character 200,000, the first two thousand characters are a record
that no longer demonstrates why it matched, which is worse than a truncated
line. `git grep --column` gives the byte offset of the first match, so the
parser keeps a bounded window *around* it and drains the rest, and the renderer
centres its own cut on the same point. Both halves had to be fixed: keeping the
first 8,000 bytes threw the match away in the parser, and cutting the first
2,000 characters threw it away again in the renderer — the same defect, one
layer down.

Three things were measured rather than assumed, and each changed the design:
the record shape **varies** (a matched line carries a column, a context line
does not, so the framer cannot count NULs to two); the column is a **byte**
offset, 1-based, so a match at character 22 of a Cyrillic line is reported at
35 and slicing a decoded string by that number lands in a different word; and
iterating a binary pipe yields *lines*, so a record with no newline arrived
whole before any ceiling was consulted.

What is guaranteed is narrower than it looks and is stated rather than implied:
the window holds the *start* of git's first match on the line and a bounded run
of what follows. An ERE's matched extent is not bounded by the length of its
source, and `--column` reports no later match on the same line.

What is not established, named because it is the one thing here that is merely
assumed: that a successful `git grep` ends with a complete record.

**And the same round found that a line of context was being counted as a
match.** With `context_lines=2`, one occurrence came back as `5 match(es)`, and
with `max_results=1` the single line shown was the first line of *context* —
text that does not contain the pattern — under a heading claiming five. Two
things from one confusion: `total = len(hits)` counted every rendered line, and
the allowance was spent on rendered lines too, so leading context displaced the
line the search was for. Both are fixed: the count and the allowance are taken
over records that carry a `--column`, and the cut lands on a record boundary
before a match rather than inside one. The defect is older than the parser
rewrite that surfaced it and no test had asked.

The 60,000-character ceiling moved into that same selection, because it had the
same fault one level along: it was a cut on the joined string, taken *after* the
matches had been counted, so on two blocks of context it could end inside the
second one — the matching line gone, its context still on screen, the heading
still counting it and no note saying anything had been withheld. Measured, not
argued: with the ceiling at 170 characters the old code answered "2 match(es)",
showed one, and said nothing.

What is guaranteed is only this, and it is worth stating exactly because two
wider claims have already turned out false: the matches counted in the heading
equal the matches shown plus the matches the note says are withheld, and an
answer that is short of the context that was asked for says so. Nothing more.
The leading context of the *first withheld match* is still shown — a real line
at a real number, which is what `context_lines` asked for — and the ceiling can
land on a context line *after* the last match, in which case every match is
shown, `total` equals what was kept, neither of the other two notes applies, and
a third one names the size limit. That branch existed and said nothing until it
was found on the fifth gate round.

The three notes are cumulative, and were not. "The scan stopped" is a statement
about what was never read; "N more match(es) not shown" is a statement about
what *was* read and is being withheld. As mutually exclusive branches with the
stopped one first, the second could never appear alongside it: measured on this
repository, `search(".", max_results=5)` answered "at least 1471 match(es)",
printed five lines, and accounted for none of the 1,466 it had in hand. Neither
sentence substitutes for the other and both are printed when both are true.

**And decoding strictly could hang the search outright — fixed.** A quoted line
has to be the line, so the decoder raises rather than repairing; the raise left
`_grep_stream` through its `finally` with `truncated` false, and nothing
terminated the child. git was still writing: it blocked on a stdout pipe this
loop would never read again, the cleanup blocked reading a stderr that could not
reach EOF, and the search never returned. The deadline does not help — nothing
consults it from in there. Measured on 2026-09-07: a file with one invalid byte
on its first matched line and 6,000 matches after it printed "searching…" and
nothing more. A gate that never returns is worse than one that answers wrongly,
and no test that drove the decoder directly could see it. The child is now
terminated on every exit where the record loop stopped before the end of the
stream, which is a strictly wider condition than "a ceiling was hit".

## The reviewed tree could describe itself to the tools that read it — fixed

One line of `.gitattributes` in the same merge request as the weakness:

```
*.py -diff
```

`git diff --numstat` then prints `-` for both counts, the file is classified
binary, and it drops out of the changed-line map — while the map stays
non-empty, because `.gitattributes` is in it. The empty attribution reads as
"this line was already there", the finding is filed pre-existing, and the gate
skips it.

| | without the line | with it |
|---|---|---|
| the changed-line map | holds `app.py` | does not |
| a critical finding | blocks, exit 1 | **filed pre-existing, exit 0** |
| the verdict line | names the finding | "none at or above the high threshold" |
| verification | runs | never runs — pre-existing findings are skipped |

**It was worse than the attribution.** With the repair inverted: the diff the
model reads shows `Binary files a/app.py and b/app.py differ` instead of the
code, and `search("os.system")` returns **zero**. So the line hid the weakness
from the reviewer and blinded the verifier; the attribution effect, which was
found first, was its third.

`--no-ext-diff` and the pinned `GIT_CONFIG_*` close the neighbouring route,
because an external diff driver has to be *defined* in configuration. `-diff`
is built into git and needs none, which is how it walked through a guard
written against the same idea.

**Three switches were measured, one works.** `--text` is applied after the
attribute; `core.attributesFile` does not override an in-tree file;
`--attr-source` does. Its cost was measured too: content detection is
untouched, an ordinary change is byte-identical, and what is lost is a
project's own `binary` markings, which are about diff readability rather than
about safety.

Three layers, because Codex ruled that one was not enough:

* **the pin, on every attribute-sensitive command.** It was added to `git()`
  alone at first, and `_bounded` and `_grep_stream` build their own `Popen` —
  so the accounting was protected while the diff and every search were not.
* **attribution fails closed.** "The map places no line in this file" and "the
  map places no line at *this* line" were the same boolean and are different
  facts. This closes the class rather than the route.
* **an all-binary change exits 2.** Nothing inspectable is not evidence of no
  findings. Forgivable by `SECURITY_SCAN_FAIL_ON_INCOMPLETE`, unlike a review
  that opened nothing it could have opened — the first version of this made an
  asset-only repository permanently unmergeable, and a gate that cannot be
  satisfied gets deleted rather than obeyed.

**What is not closed.** `$GIT_DIR/info/attributes` outranks the tree and is not
affected by pinning the source. It is not reachable through a merge request,
but it is part of the runner's trust: the job wants a fresh git directory, or a
check that the file is absent. Named by Codex, not built.

## A search that matched nothing still recorded a file as read — fixed

`search_code` records which files a result quoted by regex-scanning the rendered
answer for `path:digits:`, and the answer begins with the pattern echoed back.
Measured on 2026-09-07: `search_code(pattern="zzzznotpresent:1:")` matches no
file anywhere and still records an exposure for a "file" named
`no matches for 'zzzznotpresent`.

That matters beyond a wrong list. `exposures` is the record of what actually
reached the reviewer, and the gate's `_reviewed_nothing` check is exactly
`not outcome.exposures` — so a run whose only tool call was a no-match search
with a colon-and-digits pattern would look like a run that read something. It is
the shape this repository hunts: a claim about what was inspected, derived from
prose rather than from the thing inspected.

Fixed 2026-09-09, as this paragraph said it should be: the exposures are built
from the records `Workspace.search` keeps rather than from the rendered text,
and a no-match answer records none. `search` publishes `last_search_paths`,
taken from the lines actually *shown* — so a file whose only lines the
`max_results` cut or the character ceiling dropped is not recorded either.

`_paths_in_search` and its regex are deleted rather than left unused: a parser
that answers the same question differently is the second spelling this
repository keeps finding, and the next reader would have had two to choose
from.

## A reused artifact with no verdict was reused as a pass — fixed

`--reuse` hands back the stored decision rather than paying for a replicate.
The last line of `_reuse` was `int(verdict.get("exit_code", EXIT_OK))` over
`previous.get("verdict") or {}`, and nothing before it established that a
verdict was recorded. Measured on 2026-09-06 across every shape:

| the stored artifact | was reused as |
|---|---|
| a blocking verdict | exit 1 |
| a clean verdict | exit 0 |
| `verdict` present but empty | **exit 0** |
| `verdict` is `null` | **exit 0** |
| no `verdict` key at all | **exit 0** |

Three spellings of "no decision was recorded", all read as "the decision was
that nothing blocks" — in the one path that exists to avoid paying for a
review. The repository's own recurring defect. Found by `gpt-6-astra`.

It now requires a verdict object carrying an `exit_code` that is one of the
three this tool defines, and returns **exit 2** otherwise: "I could not
establish what the earlier run decided" is a different answer from "it found
something".

**Restricted to `{0, 1, 2}` on Codex's argument, against mine.** I wanted any
integer accepted, so an artifact from a newer version stayed readable. A POSIX
exit status is eight bits: a stored `256` returned from here reaches the shell
as **0**. A malformed or future verdict would become "clean" at the process
boundary, which is worse than refusing to read a newer artifact — forward
compatibility here means refusing an unknown code, not forwarding a meaning
this binary does not have.

Four containers beside it were read the same way — `provenance`, `coverage`,
`identity` and the reuse `count`. `or {}` passes any truthy value and then
raises `AttributeError` on a list, out of the middle of the path that decides
whether a stored answer can be trusted; `main` turned that into exit 2, a
crash wearing the code for could-not-check. They go through `identity.block`
now, which asks what the value is.

What each malformed block does was measured rather than assumed, and they
differ: `coverage` and `identity` stop the reuse and the run pays, because
they are what say the stored answer is about *this* code. `provenance` does
not, because `review_identity` fills the model and the prompts from the
configuration — an unreadable provenance does not make the artifact stale.

## The evidence rule guarded confirmations and not refutations — fixed

A verifier that confirms a finding without saying what it searched for is
downgraded to `uncertain`. `_require_evidence` returned immediately for
anything that was not a confirmation, so a verifier that *refuted* one was held
to nothing. Measured on 2026-09-06 by handing the same empty payload through
twice with only the verdict differing:

| the vote | what came back |
|---|---|
| `{"verdict": "confirmed"}` | `uncertain` — "did not state what it searched for" |
| `{"verdict": "refuted"}` | **`refuted`**, reasoning `""`, control_search `""` |

Three empty refutations discarded a critical finding. The direction held to a
standard was the one that would have *reported* something.

**And refuting costs nothing, which is why the old rule was wrong.** The test
that recorded the behaviour said "refuting is the direction that already costs
it something". It does not: `refuted` removes the candidate from the report
entirely, while `uncertain` keeps it visible, tagged "unverified chain", at low
confidence. So the asymmetry was not a considered trade — it was a hole where
findings left without a trace.

A refutation now states the control, caller or broken link it found and where.
Adjudicated rather than chosen: prose alone "only proves the model produced
prose; it does not prove it inspected code", and leaving it "preserves an
unauditable path for deleting findings".

**What it costs, weighed before it was done.** Quiet verifiers stop suppressing
false positives, so reports carry more unresolved findings. At the default
confidence threshold that is visible clutter and not a merge wall; an
installation gating at `low` would feel it, and the answer there is verifier
compliance rather than evidence-free refutations.

Three further rounds each found the next thing, and the first is worth keeping
in view: the repair would have turned silent deletion into a **merge wall**,
because the downgrade preserved `removes_control` and that flag gates whatever
the severity says. Same verifiers, opposite failure. Then the stored-document
decoder bypassed the rule entirely; then forty spaces passed as evidence,
because the live path stripped these fields and the decoder did not.

## A reviewer that says "I could not settle this" still passes — by decision

`finish_review` takes an `unresolved` list so the reviewer can record a
security question it could not answer, and the artifact carries it. `decide`
never read it. Measured on 2026-09-06 with a control:

| the run | exit |
|---|---|
| finished, nothing unresolved | 0 |
| finished, recording *"cannot establish authentication for /admin/run"* | **0** |

**Making it block was adjudicated and refused.** `_partial` asks whether the
machinery denied the reviewer evidence — it stopped early, the diff was cut,
contexts were refused. An unresolved question is the opposite: the reviewer
examined the evidence and cannot justify a conclusion. Codex, 2026-09-07:
merging the two would teach a model that admitting uncertainty fails the job,
so reviewers would omit marginal questions, force yes-or-no conclusions, or
operators would switch off the partial-review protection — all three worse than
what it fixes. A separate flag was refused for the same reason one level down:
the field is free-form and carries nothing saying whether a question is
security-material, so a policy over it would postpone the same failure.

So it does not gate, and it is no longer invisible. The artifact counts it and
the terminal prints `exit 0 — nothing blocking, with 1 unresolved question`.

The route to gating, if it is ever wanted, is a structured field — whether the
question can change the verdict, and what would settle it — not an inference
from prose.

## A change that only deletes files was not reviewed at all — fixed

Recorded because it stood for months and because the shape of the repair is
worth more than the repair. `changed_files()` applies `--diff-filter=ACMRT`,
`_run` branched on that list, and a commit whose whole content was the removal
of a file wrote "no reviewable files changed" and exited 0 without asking the
model anything. Deleting a whole file that held an authorisation check is the
strongest form of the thing this product exists to catch. Found by
`gpt-6-astra` on 2026-09-06 and confirmed by building the tree.

**It took eight repairs, and each was invisible until the one before it
landed.** Every round the path looked closed and the next gate pass found the
next link:

| # | where | what it did |
|---|---|---|
| 1 | `_run` | branched on the openable list; exit 0 without asking the model |
| 2 | `Workspace.diff()` | scoped pathspec from `changed_files`, so a scoped run got an empty diff |
| 3 | `list_changed_files` | answered "no reviewable files" to a change that removed a guard |
| 4 | the briefing | announced `Files changed: 0` to a reviewer it had just sent to look |
| 5 | citation validation | read the reviewed revision; every finding dropped as `unknown-path` |
| 6 | attribution | no line map for `+++ /dev/null`, so the finding came out "pre-existing" and left the gate |
| 7 | the verifier's brief | reloaded through `raw_text`; the verifier could not see the evidence that admitted the finding |
| 8 | the verifier's `read_file` | the brief said "read more with the tools" and the tool could not reach the file |

Numbers 5 to 8 are the interesting ones: the finding was *accepted* and then
lost — silently attributed away, or handed to a verifier that had to refute it
for want of the file. A control-flow fix alone would have produced a review
that ran, reported nothing, and looked correct.

`Workspace.removed_text` reads the base blob and refuses any path this change
did not delete, so none of this became a general way of reading the parent
commit. The one thing left undone is the field name
`introduced_by_this_change`, which is true of the deletion and misleading about
the cited lines; renaming it is an artifact-schema migration and not part of a
repair.

## What has actually been evaluated

| | |
|---|---|
| Languages | Go, Python, TypeScript, Ruby, Rust, Java, PHP, C# — between 6 and 11 cases each |
| Change shape | Two: a focused diff centred on one control, and a whole newly-added module |
| Repository size | 4 to 56 files and 24 to 433 KB per case |
| Forge | GitLab, self-managed, `merge_request_event` pipelines |
| Provider | Anthropic first-party API only |
| Real merge requests | **none** |
| Independent adjudication | **none** |

Everything measured was measured on cases this project constructed or harvested
itself. An adopter cannot check the numbers by re-running the corpus, because
agreeing with the author is what the corpus was built to do.

## A cue in how the cases are built, measured and left in

Every case is a pair — the same code with and without a security control — and
the agent is shown one member and asked to judge it. How the pair is presented
turns out to matter as much as what is in it. There are two constructions and
each gives something away:

**regression.** The safe member adds the control; the unsafe member removes it.
Focused on exactly the decisive lines, and exactly the change worth catching —
but the unsafe member *always deletes something*, so the direction of the diff
predicts the answer. A tool with a rule about removed controls scores well here
without recognising anything.

**snapshot.** Both members add an implementation to a shared baseline, one
fixed and one not. Direction carries no answer — and the diff is now a whole
newly added module, which is a different task: finding a needle rather than
judging a control. The 2-of-6 harvested result measured this, and everything
said about the agent before it measured the other.

The construction that would have neither — a baseline holding the decisive
function as a compiling stub, with both members replacing it, so both are
additive *and* the diff is one function — **is not built**. It needs
function-boundary detection and stub synthesis for eight languages, and it
would still not fit the harvested cases, where 20 of 48 fixes touch more than
one file.

`tools/corpus_adversary.py` measures what the remaining cues are worth. As of
2026-08-26 no within-member cue fires often enough to judge; between members,
"the bigger one is safe" scores 85%. That second number does not reach the
reviewer — each review is shown one member with no reference to the other — but
it is reported rather than dismissed.

## What the numbers are, and are not

**There is a corpus recall figure and there is no precision figure.**

Recall on the matched-pair corpus is **61 of 78 = 78%**, 95% Wilson interval
68–86%, from the frozen configuration D-013 names. The qualification is not
decoration: it is *corpus* recall, not recall in use. Target matching is
deliberately coarse — category and file, with no judgement of whether the
finding is correct — the corpus is retrospective, and "no catastrophe" is not
"pass".

**And the 78 are not 78 independent trials.** They are 42 advisories, 36 of
them measured in both constructions — regression and snapshot — so most
advisories contribute two observations of the same underlying weakness. A
Wilson interval assumes independent trials, and this one was computed as
though every case were one.

Computed on 2026-09-06 rather than argued: taking each advisory as a single
trial, with its constructions averaged, gives **79% over 42, interval 64–88%**.
The rate does not move; that interval is six points wider. The two
constructions disagree on 10 of the 36, so they are not one observation either
— collapsing them entirely would be the opposite error.

**That is one alternative calculation, not the size of the dependence.** It
shows how the figure moves under a specific choice of clustering; it does not
establish the true correlation between two constructions of one advisory, and
neither interval has had its coverage checked. `gpt-6-astra` objected to an
earlier wording here that called it "the measured size", and the objection is
right.

Found by a hostile review of the standing corpus. The reviewer's own claim was
larger — that the twins are byte-identical and up to fifty points of recall are
repeats — and that is false: **0 of the 39 twin pairs have identical trees**.
The dependence is real; how large it is has not been established, and the two
calculations above differ by one point on the rate and six on the interval.
The difference between "the twins are identical and fifty points are repeats"
and that is why a finding is checked before it is believed.

**And some credited hits may name a different weakness from the one the case
targets.** Target matching is category and file — `artifact.py` — so a finding
in the right file under an accepted category is credited whatever mechanism it
actually describes. That much is a fact about the code.

**Everything in the table below is a hypothesis, not a result.** It is what
`gpt-6-astra` reported on 2026-09-06 from reading the fixes against the
credited findings, and the mechanism column has *not* been checked: the stored
rows carry a count of findings, not their text. Presented as the reviewer's
reading, with the arithmetic that would follow **if** it is right — not as a
measured alternative figure. Codex objected to an earlier version of this
section that stated the four as facts and then qualified them afterwards; a
caveat below a table does not retract the table.

| case | what the case targets | what the credited finding names |
|---|---|---|
| `py-g7gc-gmgp-wgqg-snap` | repeated substitution in `noparenthesis()` | backtracking in a Received-header regex present in **both** members |
| `ts-w4mq-xh27-6xpx-snap` | the process-wide `Mustache.escape` override | a different injection path, unchanged by the fix |
| `rs-8rw6-p7m8-63jp-snap` | array-element SELECT permission leakage | computed fields on an unfiltered record |
| `py-8x5v-cpv7-8jjp-snap` | NAT64-encoded addresses bypassing classification | IP-literal redirects bypassing the resolver |

*If* all four are as described, removing their credits would give 57 of 78 =
73%, five points below the headline; a fifth, `php-mpmw-f6h6-3g26-snap`, is
arguable and would take it to 72%. **Neither number is a measurement of this
agent's recall.** They are what the arithmetic yields under an unchecked
reading, and the headline figure stands at 78% until somebody does the check.

**What was verified.** All five carry `unsafe_recall: true` in the
stored rows, and four of them carry `pair_success: false` — so the pair failure
is already acknowledged while the unsafe-side credit still counts toward
recall. That much is read off the artifacts. Whether each finding describes a
different mechanism is a reading of prose the stored rows do not carry: they
record the number of findings, not their text. The claim is recorded as the
reviewer made it, with that limit stated, rather than adopted as measured.

The figure that would settle it is a re-scoring with the finding text beside
each answer key. Whether that is free depends on whether the finding texts
still exist: the stored rows do not carry them, and nobody has checked which
artifacts do. "The artifacts exist" was asserted here and is withdrawn —
confirming a credit in a count-only row establishes nothing about the prose.

Precision is withdrawn and stays withdrawn: the corpus is half vulnerable and
half fixed, and in a pipeline the vulnerable changes are a small minority, so
a precision computed here is not precision anywhere.

**This paragraph said "there is no recall figure" until 2026-09-06**, and by
then the repository was gating on one — `tools/stop_rule.py` rejects a
configuration below 65% recall and recomputes 61/78 from the artifacts every
time it runs. Codex adjudicated it the same day: *a project cannot
operationally gate on a measurement while claiming the measurement does not
exist.* The sentence was true when written and describes the era below, which
is a different and earlier corpus:

- **10 of 17** on hand-written pairs — seven of the failures were cases scored
  against category names the agent cannot emit. The real figure is somewhere
  between 10/17 and 17/17 and has not been re-measured.
- **2 of 6** on harvested real advisories — **withdrawn**. Three of the four
  failures were reviews that never completed and were silently counted as
  "found nothing", and twenty of forty-eight manifests named the wrong target
  file.
- **15 of 15** prompt-injection trials held — **withdrawn**. Scored correctly,
  three of four suppression payloads moved the verdict. Since then the panel,
  the verifier's evidence requirement and the scorer have all changed, and a
  narrow re-measurement (verifier only, one case, two runs per condition) saw
  no movement from the two payloads it tested — see
  `measurements/2026-08-25-verifier-replay/`. That is not end-to-end
  resistance and it is not prevalence. The honest sentence is: no movement was
  observed in those trials on that case.

  A follow-up on a harder construction — a sanitiser that really exists, is
  really on the call path, and is irrelevant to the sink — found the reviewer
  and both verifier panels reasoning about what the function does to a quote
  rather than stopping at whether it exists
  (`measurements/2026-08-25-decoy-validator/`). One case. It is the strongest
  result in this project and it is still one case.

What exists instead is a regression suite. It can support "this version did
what the previous version did on these frozen cases" and nothing about code
outside them.

## In which direction it is wrong

Honestly: not established, and that is itself the most important limitation. On
the evidence available:

- **Misses are the observed failure.** On the harvested cases, the reviewer
  more often reported nothing than reported something wrong.
- **It reports real problems outside the expected one.** Of three findings
  hand-adjudicated, two were correct weaknesses the advisory did not cover and
  one was wrong. Treat findings outside the change's obvious subject as worth
  reading, not as noise.
- **It can promote a real defect to a security claim it is not.** The one
  adjudicated-wrong finding described a genuine bug accurately and called it
  exploitable without checking the caller that prevents it.
- **Two runs of the same merge request can disagree, measured.** Thirteen real
  cases run twice with nothing changed between the passes: **two flipped**, so
  about 15% instability, from `measurements/experiment-noise-floor-2`. Until
  2026-09-06 this line said stability was known only from one synthetic case
  and that nothing was known about real code — written before that experiment
  and never revised, so the document was claiming less evidence than the
  repository held. Thirteen cases is thin and the rate is not established to
  any useful precision; what is established is that the disagreement happens.

## Known failure modes

| Failure | Consequence | Mitigation |
|---|---|---|
| Misses a vulnerability in a large newly added module | Nothing is reported; the change looks reviewed | Do not treat a quiet result as coverage. Read the file list in the report |
| Reports a real defect as a security weakness | Wasted reviewer attention; in gating mode, a blocked merge | Every finding carries the code and the verifier's search; overrule it on that |
| Prompt injection via ordinary developer prose | Gating: **a real vulnerability passes.** Advisory: a real finding is made to look refuted to the reader. Three of four payloads did this when last measured | Unresolved. Do not run against untrusted contributions at all — the failure survives turning the gate off |
| Review stops early | No findings, exit 2 | Exit 2 is never 0; the report header says it did not complete |
| Two runs disagree on the same code | A merge blocked yesterday passes today | Not measured on real code. Suppressions are matched on quoted code, not wording, so an accepted risk survives rewording |
| A finding's category is one you did not expect | It is skipped by category filters | The vocabulary is fixed in the schema; open redirect, notably, has no name in it |
| The right code, the wrong danger | The finding names a lesser consequence than the one that matters, and a reader triages by the name | None. `py-p43p-whwx-q52h`: the reviewer found the exact line an advisory calls an unauthenticated denial of service — an unbounded username written to a log — and reported it as log injection. Both readings are true of the code; only one gets fixed this week. Scored as a miss, deliberately, rather than adjudicated into a pass |
| A dependency change | Not reviewed. `*.lock` is excluded by default, and nothing makes the manifest get read instead | None. The exclusion was a token decision, and for a while the code claimed the coverage had moved to the manifest — it had not. A bumped version that only a lockfile records is invisible to this tool. Use a dependency scanner alongside it |


### A false authorization finding the verifier confirmed

`rs-8rw6-p7m8-63jp`, measured 2026-09-02. On the fixed member the reviewer
claims that `snapshot.get_or_insert_with(|| out.clone())` makes field SELECT
permissions evaluate against a requester-controlled projection. The code says
otherwise: `reduce_current` runs before the projection, and the permission
expression is handed `Some(&self.current)` — the snapshot serves to enumerate
the fields and the value, not as the authorization record context.

It was reported `high`, one verifier confirmed it, it blocked the merge with
exit 1, and it failed the pair. That is the expensive failure, not a scoring
artefact: a tool that blocks a correct fix is a tool that gets switched off.

What it shows is where the layers stop. The evidence check proves the quoted
code exists; it does not establish that the conclusion follows from it. The
verifier is the layer meant to refute the reasoning, and `_require_evidence`
asks it to describe the control it searched for — not whether what it wrote
follows. Both passed, and the finding was still wrong.

**One frozen case. It establishes no rate.** Until something measures one,
treat a finding of this shape — a claim about a trust boundary — by reading the
arguments actually passed to the permission expression.

The case stays in the corpus and stays a failure: it is recorded as a
`known_failure` rather than a limitation, because it measures precisely the
question above and removing it would close the accounting by throwing the test
away.


## The fifteen measured misses

Measured on 2026-08-30 across five languages and both constructions: 56 pairs,
29 passing raw. Eleven failures were adjudicated — five cases whose nominally
safe member still carried the advisory's weakness, six findings that shared a
target's category and file while describing something else. One is held pending
a second reading. The fifteen below are what is left, and no ruling reaches
them: the reviewer did not report the advisory's weakness in the member that
carries it.

Every case is named individually. Grouping them under one sentence would let one
twin's explanation account for the other, which is why `tools/check_accounted.py`
matches on the exact identifier.

**No fix was attempted, and that is a statement rather than an omission.** The
stopping rule allows one round. No bounded, evidence-backed intervention was
identified for either family: the first would need a change to how the reviewer
reads a whole added file, whose effect cannot be known without spending the
round to measure it, and the second is a question about which weakness the
reviewer chooses to pursue, which nothing here can direct. A token prompt change
made so that a fix could be claimed would be ceremony, not a fix.

### Family A — nothing reported in the member carrying the weakness

The reviewer read the change and reported no finding the answer key recognises.

| Case | The weakness it did not report |
|---|---|
| `go-m6jg-wr9m-cg2f` | path traversal in a hooks file |
| `go-qmcq-xw74-w667` | command injection through `EDITOR` |
| `go-w67g-5rqw-f597-snap` | a cryptographically weak PRNG for the WebSocket mask key |
| `php-7mpf-4465-7fc2-snap` | stored XSS in a backend list widget |
| `py-p43p-whwx-q52h-snap` | an unbounded username written to a log on failed login |
| `ts-cqmq-8755-7xvh-snap` | a negative `take` bypassing the query limit |
| `ts-q7m3-rhxg-7vxr` | path traversal |
| `ts-v667-gc2r-2xm7-snap` | improper authentication; both members returned nothing |
| `py-qr67-gv47-xwwh-snap` | `%u` token expansion still escaping in `AuthorizedKeysFile` |

`py-qr67-gv47-xwwh-snap` is here as well as among the adjudicated: its safe
member's finding was excused as a different weakness, and its unsafe member
still reported nothing the answer key recognises. One ruling does not dispose of
the other half of a pair — a case can be an incidental finding and a miss at
once, and it is.

Seven of the nine are snapshot cases, and four of those have a regression twin
that passes on the same weakness in the same code. That is the pattern the two
constructions were built to expose, and it is where the corpus-wide gap between
them shows: the weakness is found when the diff removes a guard and not found
when the diff is a whole added file. Stated as the dominant pattern and not as
the cause — two of the eight are regressions, so a single explanation would be
an inference dressed as an observation.

Note that `py-p43p-whwx-q52h-snap` is **not** the case described in "the right
code, the wrong danger" above. That is its regression twin, which located the
line and understated the danger. This one reported nothing at all. Two different
failures, and putting them under one sentence would claim the snapshot reviewer
found a line it never mentioned.

### Family B — a real weakness reported, and not the one asked for

The reviewer read the change and reported something true about it, in the right
file, that is not the advisory's weakness. Scored as a miss: a report that is
useful and incomplete is still incomplete, and the reader who needed the
advisory's weakness did not get it.

| Case | Asked for | Reported instead |
|---|---|---|
| `go-8r62-w5wh-fc5m-snap` | an origin-check bypass | a request-body size limit computed and not enforced |
| `go-m6jg-wr9m-cg2f-snap` | path traversal | inverted signature verification, skipped by default |
| `go-qmcq-xw74-w667-snap` | `EDITOR` command injection | the same signature defect |
| `php-p2ch-c2c3-4xm5-snap` | CSRF through AJAX handler names | **unauthenticated file inclusion, rated critical** |
| `php-pg62-f8g4-4wqh-snap` | privilege escalation | a CSRF token read from route attributes |
| `ts-m9mq-7m7q-xc6p-snap` | path traversal | an SSRF through a redirect, read and found real |
| `py-p43p-whwx-q52h` | denial of service | log injection — the same line, the lesser consequence |

The tool does not know which advisory it is being measured against; it reads
code and reports what it sees. That explains the shape and does not excuse it,
because a user asking "is this change safe" gets an answer that missed the
thing the change was about.

**`php-p2ch-c2c3-4xm5-snap` deserves reading rather than counting.** The
reviewer reported unauthenticated file inclusion, rated critical — graver than
the CSRF the case was built around, and in the member that carries the
weakness. The pair is scored a miss because the target was not found. The
finding itself is not disposed of by that score; if it is real it is a product
result regardless of what the benchmark makes of it.

It was read on 2026-08-30 and ruled `unclear`, which is a verdict and not a
deferral. One thing is shown: URL segments reach `include_once` through a
constructed class path, and `BackendAuth::check()` runs afterwards, inside the
controller that inclusion is still resolving. No authentication barrier is
visible before the include on this dispatch path.

Everything the word `critical` rests on is not shown, and it is more than one
missing helper — that a traversal segment survives HTTP and route normalisation
at all, which path it resolves to, that an existing `.php` file sits there, and
that including it does anything. A first reading of mine was wrong in the
reviewer's favour: `..` in the controller position does not traverse, because
`.php` is concatenated immediately and it becomes `...php`. Only the leading
segment can climb, and the literal `Controllers` component constrains where it
lands.

Recorded in `adjudications.yml` with `not_verifiable: true` and deliberately
without an `incidental` key, so it moves no number in either direction. Codex
argued for `not_real`, scoped to the concrete claim; `unclear` was kept because
the ordering is real and reproducible from this file, and the objection is
recorded beside the ruling rather than dropped.

## The two cases outside the five languages

Added 2026-08-31, when the accounting stopped counting rows from an unrecorded
corpus version and the last two C#/Ruby cases came due. They are limitations for
two different reasons, and collapsing them would hide the second one.

**`cs-pfvm-w89x-94jw-snap` — family B, and the finding it did report is real.**
The advisory is a denial of service: a malformed UDP datagram crashes the TURN
receive loop with no restart, disabling UDP relay for every client. Neither
member reports anything in the `dos` category. Both report authentication
defects in the same file — TURN Refresh/CreatePermission/ChannelBind accepted
without MESSAGE-INTEGRITY, fingerprint `40f090843694be27`, present on **both**
members and therefore surviving the maintainers' fix — and the safe member adds
hardcoded `turn-user/turn-pass` credentials and a relay that permits loopback
and private-range peers. Scored a miss, because the advisory's weakness was
never named. The authentication finding is recorded in `adjudications.yml` with
`verdict: real` and no `incidental` key, so it changes no number and is not lost.

**`rb-g65v-27r3-5p6m` — not a miss at all, and this is the honest shape of it.**
The reviewer found the advisory's arbitrary file read on the unsafe member. It
also reported, on the safe member, that the fix leaves an existence oracle:
`_serve` withholds the body but still answers 403 for a readable path and 404
for an absent one, and `_readable_file` never normalises the path. That finding
is correct, is a lesser weakness than the advisory's, and was ruled `incidental`
on 2026-08-28.

**The ruling cannot be applied, because the row carries no fingerprint.** It was
written before batch summaries recorded them, and `ruled_incidental` matches on
the fingerprint and on nothing else — deliberately, because a ruling that named
only the file would also excuse a genuine arbitrary file read in that file.
`tools/artifact.py` anticipated exactly this and named the honest behaviour:
leave the pair scored as it was and say why, rather than widen the key until it
fits.

So this is a limitation about the **evidence**, not about the reviewer. Its
snapshot twin has a fingerprint, carries the identical ruling, and passes. This
one is recoverable by one re-run and by nothing else — no reading changes it.

Rejected while writing these, and recorded because it would have reversed a
decision the project had already argued: ruling both Ruby cases
`case_is_malformed` on the grounds that the traversal survives the fix. Codex
refused it. The advisory's weakness is arbitrary file *read* and no file content
leaves the process on the safe member; the residual oracle is smaller, answers a
different question, and is not new — before the fix the codes were 200 versus
404. Reaching for `case_is_malformed` because a fingerprint was missing would
also have used a case-level ruling to evade the safeguard that the missing
fingerprint exists to enforce.

## What is sent where

The agent runs in your CI job and holds two credentials: an Anthropic API key
and a GitLab token.

**To Anthropic** goes whatever the agent reads — file contents, diffs, paths,
and commit metadata from the revisions under review. It reads through read-only
tools (list, diff, read, search, log) and cannot execute anything. There is no
allowlist of what it may read beyond your `excludes`, so assume any file in the
reviewed repository may be sent, including one holding a secret.

**The GitLab token** needs `api` scope to post the merge request note. That
scope is broader than posting a note. Use a project access token, not a personal
one.

Anthropic's retention terms apply and are not restated here; check them for your
own account.

## Cost and runtime

Measured, on eight real harvested cases plus two single reviews:

| | |
|---|---|
| Per review | $0.60 – $3.65 observed |
| Runtime | 265 – 895 seconds observed |
| Predictable in advance | **no** — a 4–6× spread, uncorrelated with case size |

The cheapest review had 52 files, the most expensive 12. Cost tracks how much
the agent chose to read and think.

Ceilings, all configurable: 60 turns, 2,700 seconds, 400,000 output tokens,
32,000 tokens per response (raised once to 64,000 on truncation). There is **no
dollar ceiling** — a hard spend limit has to be set on the Anthropic account,
because cost is only known after a response completes. An attacker-authored
merge request chooses when that spend happens.

## Every condition that produces exit 2

Exit 2 means the review did not reach an answer. It is never a pass.

`turn_limit` · `time_limit` · `budget_exhausted` · `context_exhausted` ·
`response_too_long` · `transport_error` · `refusal` · `error`

Plus, before any review starts and without an artifact: invalid configuration,
an unusable repository or revision range, missing credentials, and a report
that cannot be written where it was asked to go.

## If you are the author, using it on your own code

The tier the project has actually settled on. Most of what blocks third-party
use is about evidence someone else would need; the conditions that matter for
the author are different and shorter:

- **Advisory and never a required check.** `allow_failure: true`, or
  `tools/review.sh`, which runs locally with `--no-comment` and no GitLab token.
- **Read your own diff first**, and write down what you noticed, before you open
  the report. Read it the other way round and a useful finding cannot be told
  apart from one you would have found anyway.
- **Selectively, not on every commit.** It earns its cost where security
  reasoning crosses files: new request handlers, authorisation, query and
  command and template construction, path handling, deserialisation, CI and
  secret handling, dependency integration, large generated changes. Not
  refactors, tests, formatting or documentation.
- **A spend limit on the provider account.** The ceilings here are turns, time
  and tokens; none of them is dollars, and cost is only known after a response
  completes.
- **Only repositories whose contents you are willing to send.** There is no
  positive allowlist — exclusions are patterns, so assume any file may be read.
- **The injection caveat still applies, narrowed.** A single author removes the
  obvious attacker, but repository prose also arrives through vendored code,
  generated files, accepted patches and upstream examples. The defensible
  condition is that you treat review-relevant prose as non-hostile, or accept
  that third-party prose may influence the report.

**The decision procedure**, so the trial can end rather than drift: ten eligible
changes or one month, whichever is later. Keep it if at least one finding showed
you something that would otherwise have shipped, or if its call-chain evidence
saves more time than adjudicating it costs. Turn it off if none did, if wrong
findings keep costing real attention, or if you catch yourself reading a quiet
report as reassurance. Ten wrong findings dismissed in a minute each establish
low irritation, not value.

`tools/journal.py report` prints that decision with the counts beside it.

## Running it without blocking

Use `allow_failure: true` on the job, and do not make it a required check.

**Do not reach for `SECURITY_SCAN_FAIL_ON=none`.** It also makes the job
non-blocking, and until 2026-08-25 it silently skipped verification: with no
threshold there is nothing a verdict can change about gating, so nothing was
verified — no independent refutation, no odd panel, no requirement that a
confirmation state what it searched for. Advisory mode is exactly where the
report is the whole product, so that was the wrong place to lose them. The
scope no longer follows the gate setting; `allow_failure` remains the honest
way to run it non-blocking.

## Overriding a decision

Accepted risks live in `.security-agent-ignore.yml`, keyed on a fingerprint
derived from the quoted code — never from the finding's wording, which changes
every run. Each entry requires a written reason and may carry an expiry. An
entry with no reason is refused: an accepted risk without one is
indistinguishable from a mistake.

There is no forge-enforced approval on that file beyond whatever your own
branch protection provides. If you gate on this tool, that is a gap you must
close yourself.

## Things you should assume are untrusted

Comments and documentation in the reviewed repository are **input to a language
model**, not evidence. A comment claiming that input is validated upstream, or
that security has already reviewed a file, is a working attack against this
agent today. So is the same claim placed in `CONTRIBUTING.md`.

## Stricter than ordinary findings

A change that removes an existing security control blocks regardless of
severity, when gating is on. This is deliberate and it is the rule most likely
to produce a block you disagree with.

## Not supported

Cross-project `include:` (unproven) · Amazon Bedrock · Google Vertex AI · any
provider other than the Anthropic first-party API.

**GitHub Actions is supported and has never run.** The adapter posts one
comment per pull request and edits it in place, the same contract as GitLab,
and it is covered by tests rather than by a real workflow. Two things a first
run will meet: `GITHUB_TOKEN` is not in the environment unless the workflow
passes it, and a pull request from a fork gets a read-only token, so the
comment is skipped and the artifact is still written.

## Upgrades

Any change to the prompts, the schema, the model, the gate settings or the
scorer invalidates every measurement taken before it. The baseline mechanism
refuses to compare across such a change rather than reporting a delta that
would read as a change in the reviewer. Treat a version bump as removing the
evidence, not carrying it forward.

---

*Written 2026-08-25 against v0.1.0. If it disagrees with the README, this file
is the one that was written to be pessimistic.*

## A unified diff with no `diff --git` lines can hide a short hunk

`evidence.changed_lines` refuses a hunk whose header declares more lines than
its body carries — at the end of the diff, and at the next `diff ` or `@@`
header. One shape escapes: with no `diff --git` separators, an under-delivering
hunk followed by the next file's `--- a/x` header consumes that header as an
ordinary deletion, because a line beginning `-` inside a hunk body *is* a
deletion. `-- ` opens a comment in SQL, Lua, Haskell and Ada, which is why
column zero is read as the diff's own structure and never as a header while a
hunk is open.

Detecting it would mean treating `--- `/`+++ ` as headers inside a hunk body,
and that is the forgery the parser was rewritten to stop: an author writes
`++ b/decoy.py`, git emits `+++ b/decoy.py`, and every addition after it is
filed against a file that does not exist. Trading a live vulnerability for an
unreachable one is not a trade.

Unreachable is measured rather than assumed. `workspace.changed_line_map` is
the only caller and it shells out to `git diff`, which writes a `diff --git`
line per file section — 160 real diffs from this repository's own history parse
without a refusal. Found on 2026-09-03 by a generated input, and the property
in `tests/test_properties_more.py` states the exclusion in the assumption
rather than in silence.

## Hardcoded secrets: claimed, never measured — run a dedicated scanner

`prompts/findings.schema.json` offers the agent two categories for this,
`secrets` and `sensitive-data-exposure`, and `prompts/system.md` asks for them
by name: "secrets committed to source, config, CI files, or fixtures". The
corpus says what that is worth:

| category | cases |
|---|---|
| `secrets` | **0** |
| `sensitive-data-exposure` | 2 |
| all categories | 90 |

So the capability is **stated and unmeasured**, which is the shape this project
exists to refuse everywhere else. Nothing here establishes a recall figure for
committed credentials, and the two `sensitive-data-exposure` cases are about
data reaching logs and responses, not about a key in the source.

**Three reasons it is the wrong tool for this, independent of the corpus:**

* **It reasons; it does not enumerate.** There is no entropy test, no pattern
  list for AWS, GitHub, Stripe or JWT shapes, no baseline of known-good
  strings. A key that does not look like a key to a reader does not look like
  one to the model either, and the answer varies between runs — which is the
  property `tools/sentinel.py` exists to measure and the reason
  `LIMITATIONS.md` carries a noise floor at all.
* **It reads the change, not the repository.** In `diff` mode the review sees
  `BASE..HEAD`. A credential committed last year is in no diff, and the git
  history is never walked. A secret scanner's whole value is the opposite:
  every blob, every branch, every commit.
* **The excludes hide exactly where keys hide.** `DEFAULT_EXCLUDES` drops
  lockfiles, minified bundles and vendored trees for token cost. A token in
  `package-lock.json` or a bundled `.min.js` is never read — and, until
  2026-09-03, `diff()` handed the model excluded content anyway on the default
  path, so the exclusion did not even hold in the direction it was written for.

**Run a dedicated job instead.** `Snyk Code` covers hardcoded secrets and runs
as an ordinary CI/CD job beside this one; `gitleaks` and `trufflehog` are the
open-source equivalents and additionally scan history. They are deterministic:
the same commit gives the same answer every time, which is the property this
agent cannot offer and does not claim.

The division is not a workaround, it is the design. Everything that can be
decided by a pattern should be decided by a pattern — the project's own rule is
that whatever can be deterministic must not be paid for. This agent is for the
weaknesses that need a reader: whether a check can be skipped, whether a sink
is reachable, whether a guard that was deleted mattered. A regular expression
cannot answer those, and a model should not be asked to do a regular
expression's job.

**Not fixed, and deliberately.** Adding secret cases to the corpus would
measure a capability that should be delivered elsewhere, and buying that
measurement costs real money. The honest entry is this one.

## The adjudications are the reviewer grading its own work

`corpus-real/adjudications.yml` holds 29 rulings — `real`, `not_real`,
`incidental`, `case_is_malformed` — and they decide what counts. Established on
2026-09-03, from `git log` and from the commit messages' own wording ("the
ruling Codex stopped me from reversing"): **the assistant wrote them**, in
earlier sessions, committed under the owner's git identity. The owner did not
adjudicate. Nothing in the file says this.

| | |
|---|---|
| who produced the finding | the model |
| who ruled whether it is real | **the same model** |
| who checked the ruling | Codex, on some of them |

### What it invalidates

Re-scoring the corpus through these rulings makes the numbers look much better
and does not make them more true:

| | cases | alerts on the fix |
|---|---|---|
| raw, latest row per case | 78 | 20 (26%) |
| minus 9 ruled `case_is_malformed` | 69 | 11 |
| minus findings ruled `incidental` | 69 | **1** |

"1 of 69" rests entirely on rulings that are not independent. It is not a
better number, it is a more convenient one, and the difference is the whole
subject of this file. **26% stands** as the figure the stop rule uses: coarse,
and free of the reviewer's opinion about its own output.

The rulings remain useful for what they are — an explanation of why a row looks
the way it does, and a record of reasoning that would otherwise be lost. They
are not evidence, and no threshold may be computed through them.

### The narrower defect underneath

`safe_false_positive` is an alias for `safe_target_persistence`, and
`artifact.is_target` matches on **category and file only** — there is no
judgement of whether the finding is correct. A patched file nearly always still
has something true to say in the same category, so the 26% is not a
false-alarm rate at all; it is a "the fixed file still carries a finding of
this category" rate. `tools/pair_corpus.py` says as much in its own comments,
and `D-013`'s 40% ceiling was set against the number without that reading.

### When the rulings apply, and when they do not

The 26% above is **raw** — no ruling touched it — and that is an accident of
dates, not a property of the tool. Verified 2026-09-03: all ten cases carrying
an applicable excusal still read `alert: True` in their stored rows, because
the rulings were written after those runs. `tools/stop_rule.py` reads the
stored rows; `tools/pair_corpus.py` applies the rulings while it scores. So the
same corpus yields 20 alerts from the file and 10 from a fresh run, and nothing
on a row says which kind of number it is.

`tools/stop_rule.py` also counts nine cases that `stage2` and
`check_accounted` drop as `case_is_malformed`. Three tools, three
denominators, one corpus. It prints both readings and takes its verdict from
**the raw one only** — the second carries no verdict at all, and the line under
it names how many of the rulings behind it are independent (zero). Printed
because four tools disagreeing over one corpus is worth seeing; unanswered
because a note saying "not evidence" beside a verdict loses to the verdict.

That was not the first version. The first removed the ruled cases and could
return `stop` on what was left — computing a threshold through the rulings two
files from the sentence forbidding it. Caught by Codex at the commit gate. A
prohibition written down and stepped over in the same change is worse than one
never written, and this is the second time in one day that a rule here was
recorded and not enforced.

### Three defects fixed the day this was written, and one that was already dead

- `ruled_incidental` ignored `verdict` entirely, so a ruling saying the
  reviewer was **wrong** (`not_real`) instructed the scorer to *excuse* the
  alert — deleting a true false positive. `php-p2ch-c2c3-4xm5-snap` carries
  exactly that pair of keys and was saved only by never having had a
  fingerprint recorded. Now only `verdict: real` excuses.
- Nothing applied any ruling to the broken member, so a finding ruled
  `not_real` there earned full recall credit and could carry a pair on its own.
  `artifact.ruled_false_alarm` is the reader for it and `pair_corpus` calls it.
- `case_is_malformed` — which removes a case from the denominator outright, and
  has removed thirteen — accepted a truthy value and defaulted the reason to
  "adjudicated malformed". `rs-g9hv-x236-4qp3-snap` had its real reason written
  under `note:`, a field no code reads, and was excluded on the default for a
  day. Both are now required.

### What would fix the whole entry

Blind adjudication by somebody who did not produce the findings, on a sample
large enough to carry a rate. `adjudicated_by: human` is the field that would
record it, `artifact.independence()` counts them, and the count is zero. Until
it is not, the honest reading is that this corpus measures **discrimination
between a vulnerable file and its patched twin**, and that no false-alarm rate
has been established by anyone but the model itself.

`adjudicated_by` is self-attested: a row saying `human` is a claim, not a
proof, and nothing here can tell a person's ruling from a model's. It is worth
recording anyway, because "unrecorded" and "model" and "human" are three
different states and the file used to show none of them.

## The Sonnet gate has no baseline, and the order now says so

`tools/d013_order.py` reports the step `sonnet_gate` as `done_when: undefined`,
and until 2026-09-05 that was the only thing it said. D-013's prose gave the
reason as "`tools/sentinel_compare.py` prints a verdict and stores nothing".

That is true and it is the *second* obstacle. The first, measured by calling
the comparator against the committed reference:

> this reference is retired and is not a baseline: its rows carry no
> `models_verified` — no row anywhere in `measurements/` does — so it cannot
> separate the model that reviewed from the model that verified. No arrangement
> passes.

So the Sonnet comparison cannot be performed today for a reason no amount of
storage work would fix. A replacement baseline needs paid runs whose rows carry
`models_verified`, which is money and a change to what the runner writes.

The order tool now asks `sentinel_compare.validate_reference` rather than
restating its rules, and the step names its baseline in the block rather than
in the tool's source.

**That is less than it sounds.** `sentinel_compare.py` still takes the
reference as a positional argument, so the file the order reports on and the
file somebody eventually compares against are coupled by nobody but the person
typing the command. The declaration removes a hard-coded path from the tool; it
does not bind the command. Codex named this on 2026-09-05 after an earlier
wording here claimed the two "cannot inspect different files", which was
exactly the shape of claim this document exists to prevent.

### `validate_reference` is not an exhaustive schema

`sentinel_compare.validate_reference` answers whether a baseline is usable
without any challenger runs, and the D-013 order tool asks it before reporting
what blocks the Sonnet gate. It was built by finding, one at a time, every
field the comparison read before establishing what that field was — a
`models_served` that was a bare string and walked into thirteen one-letter
model names, a `settings` erased into `{}` by a tolerant read before the check
that was written to refuse it, a `run_id` that was a list, a
`model_substituted` recording `true` and passing a check documented as
requiring `false`, an `environment` object satisfying "records an environment"
while recording none of the four fields the comparison holds a challenger to.

Thirty-two rounds of review, each finding one more. Codex said on the
twenty-fourth what the count already showed: **field-by-field guards are not
converging**, and container types, required keys, booleans and non-blank
strings belong at the boundary, once. That was done for the challenger rows —
`_check_row_shape` runs from `read_run` over every row of every run — and for
the reference it is a list of checks rather than a schema.

So: `REF_USABLE` means "nothing in the list of known defects applies", not
"this file is well formed".

What is established: a **known** reference defect is refused before any
challenger row is read, because `compare()` calls `validate_reference` first.
What is not: that an unknown malformed shape is refused before a verdict. Such
a shape that *passes* `validate_reference` makes the preflight report
`established`; `compare()` may or may not refuse it further on, and without a
shared schema nothing proves that it does. One that raises on the way through
comes back as `cannot tell`, which is the third answer and not this one.

The first version of this paragraph said the gap was bounded because "a
malformed baseline that gets past it is refused later by `compare()`". Codex
refused that on 2026-09-05: there is no second exhaustive boundary, and the
sentence contradicted the admission two paragraphs above it. Writing the
reference's shape down once, as a schema the builder and the reader share, is
the fix and is not built.

### What the containment check on that path does and does not establish

The step's `reference` is refused at parse time if it is absolute or spelled
with `..`, and refused again at the read if it resolves outside the repository.
The second check is **not coupled to the open that follows**: the file or an
ancestor could be replaced between the resolve and `read_text`, and the read
would follow the new link. Closing that would take descriptor-relative,
no-follow traversal.

It is not built. This is a development tool run by the person who owns the
working tree, and everything it reads is already trusted at that level. The
check is worth having against a mistake or a stale symlink. It is not a
boundary against an adversary with write access anywhere in the tree, and
saying otherwise would be the claim-wider-than-the-evidence this repository
exists to catch.

The first version of this paragraph justified that with "anyone who can win the
race can edit `DECISIONS.md` or the tool itself". Codex refused it the same
day: write access confined to `measurements/` wins the race and grants neither.
The conclusion rests on the trust model, not on a claim about what such an
attacker would also be able to reach.

## The noise measurement, and the one thing its scorer does not check

`tools/ordinary_noise.py` reports how often the reviewer alarms on a change
with nothing to find — 0 of 27 blocked, 1 of 27 reporting, on 2026-09-06. What
it verifies before printing anything:

| | |
|---|---|
| the sample | exactly one row per admitted case, ids read from the seal and never from the record being scored |
| the denominator | the whole admitted set, always; an unreadable case is an unknown *inside* it and makes the figure a range |
| the configuration | every completed row records `claude-cli`, `claude-opus-5` requested **and served**, and `model_substituted: false` |
| the money | not money: list price on a subscription. `tools/spend.py` reports what the records charge, and says so itself when that cannot be established as a total — nothing in these records keys a run, so where a `rows.json` and kept artifacts sit together it cannot tell whether any run is in both, and one that is would be counted twice |

**What it does not check: the artifact's own description of itself.** The
estimand, the list of things the figure may not be called, and the list of
excluded cases are read from the saved file and printed. A file whose rows are
untouched but whose labels have been edited would print a misleading
description and exit 0. Codex, 2026-09-06, after seven rounds on this tool:
this affects no arithmetic, no denominator, no row identity and no provenance,
and exploiting it means editing the prose while leaving the measurement intact.

Recorded rather than fixed, because the seventh round was the point at which
the findings stopped being about the number and became about malformed files
nobody has produced. The fix, if it is ever wanted, is for `cmd_score` to
reconstruct the labels from D-014 exactly as it already reconstructs the
admitted ids.

## The Sonnet trial: what the interleave and the ledger do not establish

D-015 asks for an interleaved order committed before any result is seen, and
for the reference to be frozen from the Opus passes before the Sonnet ones are
looked at. Under a genuinely interleaved order the Sonnet rows are on disk long
before the last Opus row is, so those two cannot both hold in their literal
reading. `tools/sonnet_trial.py` enforces the narrower thing and says so.

| | |
|---|---|
| established | the reference was frozen at a recorded point in the sequence, built from the Opus arm and nothing else, and the file compared against later still has that content |
| **not** established | that nobody read the challenger rows before the freeze |

Codex, 2026-09-06: *"A ledger records writes, not reads. Plaintext challenger
files already on disk make that history observationally indistinguishable from
one where nobody inspected them."* Enforcing the literal rule needs the
challenger's results to be unreadable until the reference digest is committed.
That is not built, it is not claimed, and this paragraph exists so that the
guarantee is not read wider than it is.

Two more boundaries of the same tool:

* **The interleave is at case granularity, not review granularity.** Within one
  unit both members of a pair are reviewed by the same arm, back to back. A
  change lasting seconds still lands on both members of one pair together.
* **`prepared` without `done` is a person's decision, not the tool's.** A crash
  between writing the result and appending the ledger line leaves a row at the
  path the open unit expects. Nothing in a JSON file binds it to the review
  this trial paid for — Codex, 2026-09-06: *"Anyone can place a fabricated row
  at that unit's expected path after preparation."* So `run` refuses, names the
  file, and asks for `--recover`; the acceptance is a ledger line carrying
  `recovered: true`. The row is still trusted, but deliberately and on the
  record rather than silently.
* **The chain's head is git, and only if the ledger is committed.** A hash
  chain kept in the file it protects can be rewritten whole with every hash
  recomputed. `committed_prefix` asks git whether the ledger on disk extends
  the committed one, and `run` refuses when it does not — but an uncommitted
  ledger answers `unknown`, which is "I could not check" and not "it is sound".
  Commit the ledger as the trial proceeds or this check has nothing to hold.
* **The reference is built from the arm; the builder is not.**
  `sentinel_reference.build()` takes its case list from the live
  `suites/sentinel.yml` and checks each row's digest against the live
  `corpus-real`, neither of which is the frozen arm — so `sonnet_trial.py
  reference` asks `experiment.drift` about that arm first and refuses when
  anything it froze has moved. That makes the two agree at the moment of the
  freeze. It does not make the builder read the arm's own case list, and a
  future change to `build()` could reintroduce the gap without this refusal
  noticing.
* **`reference --recover` verifies, and the window is still real.** Writing
  the file and appending its ledger line are two writes, so a crash between
  them leaves a reference nothing records. Recovery rebuilds the baseline and
  records the file only if the two match, which is stronger than the unit
  recovery — but it depends on the arm's rows still building the same thing,
  which is exactly what the drift check above is for.

## Repo mode had no "the reviewer opened nothing" refusal — adjudicated and closed

Found 2026-09-09, hunting for a fourth route to exit 0. `coverage.changed`,
`coverage.deleted` and `coverage.unreadable` are filled at exactly two places
and both are behind `mode == "diff"` — `agent.py` and
`runner_claude_code.py`. So in repo mode `gate._readable_change` is `False`,
`_partial` is `False`, and the branch that refuses a review which ended saying
it was done without opening anything **cannot fire at all**.

Measured: `mode="repo"`, no exposures, `finish_review` on the first turn —
`exit 0`, "✅ AI security review — no findings reported". The identical run in
diff mode exits 2 and says no setting makes it a pass.

**This is not a corner.** `Config.resolve_mode` returns `repo` whenever the
mode is `auto` and there is no merge-request id, and `is_merge_request` is
`bool(CI_MERGE_REQUEST_IID)`. An ordinary GitLab **branch pipeline** sets none
— and that is the pipeline an MR shows under "Pipelines must succeed". On
GitHub the same holds for a `push` event. So every hole closed on the diff path
today has a twin here, in the mode a large share of installations gate on.

**Why it is recorded rather than repaired.** The obvious fix — answer `True`
for every non-diff mode, since a whole tree always has something that could be
opened — was written, and it turns **15 of this repository's own tests red**:
the exit-code tests, the artifact test, both suppression tests, the
verification handoff. Every one of them drives a fake model that replies once,
with `end_turn`, and calls no tool.

So the question underneath the repair is not mechanical: **is a repo-mode
review that made no tool call a pass?** Fifteen tests currently assert that it
is, and the gate's own comment names "a provider that returns `end_turn` before
any tool call" as the thing it exists to refuse. Those two cannot both stand.

**Codex adjudicated it the same day, and it is closed.**

> *"Repo mode with zero exposures must not pass. Repo mode is a claim about an
> entire repository, so a completed response without receiving repository
> content is not a review. The 15 failing tests are stale fixtures: give their
> fake reviewers a real exposure or explicitly mark runs as non-performed. Do
> not preserve an unsafe product contract to accommodate mocks."*

`_readable_change` answers `True` for any mode but `diff`, and the fifteen
fixtures were given a reviewer that opens a file before it says anything — one
turn, added in `install_client`, which is what a real review does first. A
fixture whose reviewer reports a finding in a file it never opened was
asserting the hole rather than the behaviour.

The branch is also conditioned on `review_status == performed`, because the two
non-performed dispositions reach it with no exposures by design: without that,
the skip label exited 2 instead of 0 — the escape hatch turned into a block,
and the first of the seven things the `review_status` adjudication said must
not break. The suite caught it one edit after it was introduced.

## A deletion an exclude rule hides leaves no trace in the artifact

Found 2026-09-09, hunting every change shape that reaches the gate with nothing
opened. Seventeen shapes were built as real commits and checked — rename, mode
change, symlink, type change, submodule, empty file, `.gitattributes -diff`,
quoted paths, merge base, orphan base — and every one of them exits 2. Two
things about deletions do not, and one of them is fixed.

**Fixed:** a deletion-only change whose path an exclude rule or the `--path`
scope hides emptied every list, so the report named no filter and said "This
change adds or modifies no file, so there was nothing to review" over a removed
guard — while the same file *modified* correctly said every file was excluded.
`every_changed_file` now sees deletions and the sentence names the filter and
the removal.

**Also fixed, 2026-09-09.** Two more, and they were one repair:

* `changed_objects()` applies `is_excluded` and `in_scope` before building
  `coverage.deleted`, so when a change removed an excluded file **and** edited
  a reviewable one, the run proceeded normally and the removed path appeared
  in **no field of `Coverage` at all**.
* `Coverage.excluded` was declared and serialised and **never assigned**. An
  excluded-only change's artifact was field-for-field identical to an empty
  commit's.

`Workspace.hidden_by_rules` reads the change with both filters cleared and
returns what each rule covered, deletions included; both runners call it and
fill `excluded` and `out_of_scope` from it. `is_excluded` is asked first, so a
path both rules cover is reported once — two overlapping lists are counted
twice by anybody who adds them.

The argument is the one `out_of_scope`'s own docstring already made: *a scoped
review that reports "no findings" without saying what it did not look at is the
same sentence as a full review that found nothing.* An operator who excludes
`vendor/` has said not to *review* it; nothing in that says the artifact should
be unable to mention that a file there was deleted.

An earlier draft of this section said the reuse key and `check_accounted` would
have to be told about the new field. Codex checked and that was overstated:
reuse is already keyed on the configured excludes, and `check_accounted` reads
no coverage field at all. The claim was larger than the evidence, which is the
thing this file exists to catch elsewhere.

The policy question is separate and is not what this records. An operator who
excludes `vendor/` has said not to *review* it; nothing in that says the
artifact should be unable to mention that a file there was deleted.

## A row refused for its reviewer is refused silently — fixed

`stop_rule.is_product_row` decides whether a measurement row answers for this
model. When it says no, the row is skipped and an older one answers instead,
and nothing says that happened. Two readers depend on it —
`stop_rule.latest_rows` and `sentinel.recorded_outcomes` — and between them
they set the recall and false-alarm figures, the alarm codebook, and the labels
in the sentinel suite.

The rule allows the product model plus any name in a helper *family*
(`claude-haiku-`), which is measured: all 97 member records on disk flagged
`model_substituted` record Haiku beside Opus and are genuine paid Opus
measurements. Codex, 2026-09-09, on the version before that: holding the dated
`claude-haiku-4-5-20251001` exactly, while `config.py` spells the same model
`claude-haiku-4-5`, would have discarded paid rows the moment the provider
answered with the configured alias.

The family match removes that specific trap and not the general one. **A helper
from a family nobody has listed still refuses the row, and the failure looks
like headline numbers quietly falling back to older measurements.** That is the
right direction to be wrong in — the alternative counts a foreign reviewer as
this one — but a refusal nobody can see is a refusal nobody will diagnose.

**The diagnostic is built, 2026-09-09.** `why_not_product_row` returns the
reason instead of a boolean, the two readers count reasons into
`stop_rule.SKIPPED`, cleared at the start of each pass, and both command lines
print one line under their answer. On this repository today:

```
26 row(s) did not answer for claude-opus-5: 26 asked for claude-sonnet-5
```

Six reasons, not one, because a single message would send every reader looking
in the wrong place. Silence now means every row was read — which is still a
different statement from silence about whether anybody looked, and that
distinction is the reason the line exists at all.

## A skipped parameter was subtracted twice — adjudicated and fixed

Found 2026-09-09 while repairing the parameter-level marker in
`stage2._conditionally_marked_cases`. Not created by that repair — the
single-decorator form of it was already there — but the repair makes it
reachable in more shapes, so it is written down rather than left in somebody's
head.

`skip`, `skipif` and `xfail` are all treated as conditional, and the count is
subtracted from the recorded passes. But **only `xfail` can pollute the pass
count**: a skipped case is written into the junit report with a `<skipped>`
child and is already excluded, while an xpass has no child at all and is
indistinguishable from a pass. Subtracting the skipped ones again
double-penalises.

Measured: one `skip`-marked value stacked with three plain ones generates six
cases — three genuinely skipped and **three genuine unconditional passes**. The
count is 3, the recorded passes are 3, `3 > 3` is false, and the scenario is
reported uncovered although three unconditional cases passed. Before the repair
it read covered, by accident of under-counting.

**The obvious fix is to count only `xfail`, and it is a trade rather than a
correction.** It contradicts `_conditionally_run`'s stated stance that any
conditional marker disqualifies a test whichever way it ends, and it has a
measured cost of its own: `skipif(False)` runs and is recorded as a plain
`PASSED`, so an xfail-only count would credit a `skipif`-marked case as
coverage.

Two defensible rules, opposite failure directions, and picking one alone is the
kind of decision this repository sends to review.

**Codex adjudicated it the same day, and it is built.** *"Only `xfail` needs
special subtraction because XPASS is indistinguishable from PASS in JUnit;
runtime JUnit results should decide `skip`/`skipif`. Apply that rule at both
function and parameter level."*

So `_CONDITIONAL` holds `xfail` alone. The runtime result decides `skip` and
`skipif` — a skipped case carries a `<skipped>` child and never enters the pass
count, so subtracting its marker again was the double penalty; a
`skipif(False)` runs, is recorded as a plain pass, and now counts. The source
is read only for what the report cannot say.

## Three readers took another model's row for the product's — fixed

Found 2026-09-09, when the Sonnet trial's 52 rows landed under `measurements/`.
Four readers took another model's rows for the product's; the first three were
repaired that morning and these three the same afternoon.

`stop_rule.latest_rows` and `sentinel.recorded_outcomes` already shared
`stop_rule.is_product_row`: a row carrying `members` has to name
`claude-opus-5` in **every** member, and a row with no `members` key predates
the field and is read. These three did not, and each failed differently:

| Reader | What it did with a foreign row | Now |
|---|---|---|
| `run_queue.already_run` | returned `True` and skipped buying the measurement that was wanted | asks `why_not_row_for` against `queue_model()`, on **both** its paths — the queue's own file and the walk of every batch |
| `check_accounted.executed` | filed the case `unadopted` rather than `unrun` | counts product rows only; the foreign cases are collected in `account`'s own walk, under `FOREIGN`, and printed beside the tally |
| `stage2.measured_outside_the_stream` | offered the row for adoption as this stage's answer | takes `product_only`, and `probe_use` prints the foreign cases on their own line |

**The trigger was one row**: a scorable row for a case that has *no* Opus
result, produced by another model, at the current case digest. None exists
today — every case the Sonnet arm touched already carries an Opus row, which is
why `executed()` returns 78 either way and the live baskets did not move. The
guard was a coincidence of the corpus, not a mechanism, and that is why this
was repaired rather than watched.

The consequence was the expensive direction: all three would have told the
owner not to buy a measurement that has never been made.

**Not repaired by dropping the row.** These readers' question is "was this
bought", and a run on another model is a real charge — `run_queue`'s own
docstring records the double payment that cost about a dollar twice. So the
foreign rows are *named*, not filtered into silence: `check_accounted` prints
`N case(s) measured only by another model`, and `stage2` prints `N measured
only by another model`. Both lines are empty today and the tests build the row
that fills them.

Codex, 2026-09-09: *"All three ask whether any paid measurement exists, not
whether this product was measured. They should share a per-member reviewer-
identity predicate, with an explicit legacy policy."* The predicate is
`stop_rule.why_not_row_for` and the legacy policy is the one it already had: a
row with no `members` key predates the field and is read.

**Two rounds of objection, and the second changed the design.** Codex first
ruled that the filter restored the double-payment defect and that
`already_run` must accept any bought row. That rests on reading a Sonnet row
and an Opus row as two payments for one answer; they are one payment each for
two answers, and if the only row is foreign then this product's measurement of
that case does not exist and nothing would ever buy it. Put back with that
argument, the adjudication came out: *"The counter-argument holds for product
coverage: a Sonnet result is not an Opus measurement, so it must not settle
the Opus corpus debt. Under the old behavior, no mechanism would buy the
missing Opus result."*

And with it a narrower defect that was real and mine: the first version asked
for `claude-opus-5` **by name** in all three readers. Codex: *"run
`tools/run_queue.py` with `SECURITY_SCAN_MODEL=claude-sonnet-5` … restart the
queue with the same environment, model, case, and corpus version … the case is
queued and purchased again, overwriting the first Sonnet result. That is a
second payment for the same answer."* So the two questions are split by
reader, which is the shape the repair now has:

* `check_accounted` and `stage2` ask about the **product**, with the fixed
  name. What the project owes is measured against the model it ships, and an
  exported variable must not move those numbers.
* `run_queue.already_run` asks about **the model this invocation is buying**,
  resolved by `stop_rule.queue_model` the way `Config` resolves it.

Two more came out of the rounds after that, both from the same repair:

* **The queue file was model-agnostic.** `already_run` refused a foreign row
  correctly, but `run_one` wrote every model to `QUEUE/<case>.json`. Codex:
  *"Alternating models repeats the duplicate purchase indefinitely."* Sonnet,
  then Opus over the top of it, then Sonnet again because the Sonnet row no
  longer existed. `run_queue.result_path` now keeps the bare name for the
  product — every file on disk carries it and every reader globs `queue/*.json`,
  so renaming them would rewrite the record to fix a path — and returns
  `<case>.<model>.json` for anything else. A model name holding a path
  separator is refused rather than sanitised, because a sanitised name is a
  different name and would then look like a different model.
* **The foreign line ignored `--construction`.** It was computed in `main`
  over every case while the headline above it was filtered, so
  `--construction regression` could name a *snapshot* case as still owed a run
  — and exit 0 while saying so. It is now collected inside `account`'s own
  walk, under the key `FOREIGN`, which also removes the second snapshot of the
  tree. That key is deliberately not one of the six outcomes: a case named
  there is already counted in `unrun`, so `BUCKETS` is what sums, in the tool
  and in the property test both.

* **The legacy rule was a presumption about the product, applied to every
  model.** A row with no `members` key predates the field, and every such row
  was bought with Opus — which is why reading it is right, and why it is a
  fact about the product rather than about whichever model is being asked
  about. Codex: *"The legacy compatibility rule is valid only for the fixed
  product-model readers… It cannot establish the identity of an arbitrary
  queue model."* A legacy Opus row satisfied a Sonnet queue, so the case was
  never measured with Sonnet and nothing would ever ask again. Such a row now
  answers for `PRODUCT_MODEL` and refuses for anything else.

* **"Not the product's" was read as "another model's".** The foreign set was
  the boolean negation of the product test, and that test says `False` both
  for a row Sonnet produced and for one recording no provenance at all —
  Codex's example is `{"members": {"safe": {}, "unsafe": {}}}`. So a malformed
  row was reported as another model's measurement: a claim about a model, made
  from a row that names none. `stop_rule.identified_model` now gives three
  answers — the product, a named other model, or `UNIDENTIFIED` — and both
  readers ask it rather than negating a boolean. This is the repository's own
  recurring defect, found inside the change written to repair a version of it.

* **And the repair opened a door of its own.** `result_path` writes a
  non-product run to `queue/<case>.<model>.json` — inside the production
  stream, which `check_accounted.standings` and `stage2.result_files` both
  glob. So a Sonnet row became the case's settled answer while the accounting
  correctly said no product run existed: the tool reported the case as `pass`
  *and* as still owed a run, in one breath, and could exit 0. Worse in the
  other direction too — `measured_outside_the_stream` skipped it as already
  *in* the stream, so it was not reported as foreign either. Wrong twice from
  one row. Codex, 2026-09-09. The stream is a **place**; a verdict is about
  the **product**, and the two are now asked separately:
  `stage2.settles_a_verdict` is the one spelling, both verdict loops call it,
  `standings` applies the same rule, and the stream exclusion in
  `measured_outside_the_stream` holds only for the product question. Every
  earlier foreign fixture sat under `experiment-*/pass-*/`, outside both
  globs, which is exactly why none of them reached this.

* **And a comment that promised one walk while the code made two.**
  `account()` asked `executed()` and then `measured_by_other_models()`, two
  snapshots of a directory a running queue writes into. A product result
  landing between them put its case in `unrun` *and* in `FOREIGN`: the tool
  saying a case was still owed a run it had just been given, and exiting 1 on
  it. `bought_by_model()` is one walk keyed by what
  `stop_rule.identified_model` names — `UNIDENTIFIED` a key of its own, not
  folded into either answer — and `account` takes both sets from it. Codex,
  2026-09-09, and the comment claiming one walk was already in the file.

* **And it reached into the rounds.** `run_queue --round N` rebinds the queue
  directory, so `result_path` writes a foreign run to
  `round-N/<case>.<model>.json`. A round freezes the provider, the profile,
  the order and four digests — and `round.py`'s own docstring has always
  listed the model among them, while the manifest neither recorded it nor
  enforced it. Codex, 2026-09-09: freeze a round, run it with
  `SECURITY_SCAN_MODEL=claude-sonnet-5`, and the queue accepted it; run it
  again with the product and every case was bought a second time, because the
  bare name it looks for was not there. Then `compare` read both models' rows
  and took the latest by timestamp, reporting Sonnet against Opus as the
  product moving on its own — **the number every gate threshold sits above.**

  Repaired in the three places the failure has: the manifest freezes
  `stop_rule.queue_model()`; the queue refuses a mismatch **before anything is
  bought**, and a test replaces `run_one` with something that fails if it is
  ever reached; and `compare` counts only rows from the frozen model and
  prints how many it set aside, because a row that is dropped in silence
  reports a round as thinner than it is. A manifest frozen before the field
  existed names no model, and then the product is what it meant — every round
  so far was bought with it.

* **And one that predates all of it**, found in round 10 because the model
  work had put attention on the same function. `freeze` records
  `case_digest` and `legacy_case_digest` for every case and `compare` read
  neither. Edit a member between the freeze and the paid run, and the new row
  answers a different question from the baseline it is counted against; when
  the two verdicts happen to agree, the tool prints a stability measurement
  over two different inputs and exits 0. `check_accounted.about_this_version`
  and `stage2` have applied exactly this check to the same rows for weeks —
  this reader had not learnt it. Both spellings of the digest are accepted,
  and a manifest that records none is compared as before, because refusing
  every row in an old round would turn it into one that measured nothing.

  Seven of this file's own tests went red the minute the check was added:
  every fixture wrote rows with no `case_digest`, which `pair_corpus` has
  never emitted. They were given the digest the round freezes rather than the
  check being weakened — the same call as on 2026-09-09 in the product, where
  fifteen fixtures drove a reviewer that opened no file.

  And the repair for that one needed its own other half, found the round
  after: `compare` refusing the row did nothing to stop the queue **buying**
  it. Codex, 2026-09-09: edit a member after the freeze and the case was
  purchased normally, its row recorded the new digest, and `compare` then
  reported it as "not yet run" and could exit 2 having measured nothing — the
  money spent on a row thrown away at the other end. `run_queue --round`
  refuses a changed digest before `run_one` can spend, on the same rule
  `compare` applies, so the two ends agree about which rounds are checkable.

  And once the digest check existed, the round after found the hole it could
  be walked around: `protocol.order` decides what is bought and `cases`
  carries the digests `compare` reads, and nothing checked that the two name
  the same set. A case in `order` and not in `cases` was bought with no digest
  check and then ignored by the comparison — money spent on a row nothing
  looks at, while the case the comparison does look at is reported as never
  run. A repeated id in `order` bought one case twice, because `queued` is
  computed once. `freeze` builds both lists from one list, so a genuine
  manifest passes; the refusal is for a hand-edited one and for a future
  `freeze` that lets them drift.

  And the model repair had the same hole one step earlier. Freezing the round
  under `SECURITY_SCAN_MODEL=claude-sonnet-5` froze *Sonnet*, so the run
  matched and the comparison was still wrong: `baselines()` comes from
  `check_accounted.verdicts()`, which is the product's answers and nothing
  else. The pass printed "0 agreed, 1 flipped" and exited 0 over Sonnet
  against an Opus baseline — Codex, 2026-09-09, the cross-model comparison the
  round before had been repaired to prevent, arriving through the freeze
  instead of through the run. **A round is a measurement of the product**, so
  `freeze` refuses to run under any other model and names
  `tools/experiment.py` as the thing that compares two of them. The manifest
  records `PRODUCT_MODEL` rather than the resolved value, because after the
  refusal the two are equal and the constant says which fact is being written
  down.

  The one-walk repair itself needed a second pass. Folding `executed` and
  `measured_by_other_models` together left `standings` walking separately, so
  the race survived in a third place: a queue result landing between them
  filed the case as `unadopted` while its row was already in the stream, and
  the tool told the owner to publish a row into the place it was already in,
  exiting 1. `walk()` now reads every file once and tags each row with whether
  it is in the production stream, and all three views derive from that one
  list. The test counts calls to `walk`, which is the question; counting calls
  to `bought_by_model` was what let the third walk hide.

  And `walk()` had the race inside itself: it listed the production stream
  twice, once for the membership set and once to choose what to read, so a
  queue result appearing between the two was read and tagged as *outside* the
  stream — ignored by `standings`, counted by `bought_by_model`, and the case
  came out `unadopted` with its result already in the stream. The same race,
  one level down, where counting calls to `walk` cannot see it. The test now
  counts the listings too.

  The name itself was then wrong, found six rounds later:
  `<case>.<model>.json` does not uniquely encode the pair. A product run of a
  case literally called `a-case.claude-sonnet-5` and a Sonnet run of `a-case`
  both land on `a-case.claude-sonnet-5.json` — one overwrites the other, and
  on restart `already_run` reads the file, rejects the `case_id` inside it and
  buys the case again. The defect the qualified name was introduced to
  prevent, back through an ambiguity in the name. Case ids are directory names
  and nothing forbids a dot in one. It is a **directory** now,
  under a reserved segment: `queue/by-model/<model>/<case>.json`. It cannot be
  ambiguous, and it takes a foreign run out of the production stream by
  construction, since every reader of that stream globs `queue/*.json`.

  The reserved segment took one more round. Placed straight in the queue, a
  model directory shares that namespace with the queue's own files, and
  `SECURITY_SCAN_MODEL` takes any non-empty string —
  `SECURITY_SCAN_MODEL=log.jsonl`, or `manifest.json`, or the name of an
  existing result, made `mkdir` run beneath a file and the run died before it
  started. `by-model` is not a case id, so nothing the queue writes can land
  on it.

  Moving the write then had to move the readers, found the round after that:
  `check_accounted`, `stage2`, `sentinel`, `window_recut` and `round.compare`
  all globbed `queue/*.json` and nothing else, so a foreign run was resumable
  by the queue and **invisible to every tally at once** — the case stayed
  `unrun` *and* was absent from the foreign line. The production stream keeps
  its narrow glob, because a foreign row is not the product's verdict; every
  reader of *what was bought* gained `queue/*/*.json`, and `round.compare`
  gained `*/*.json` so the rows it sets aside are counted rather than never
  seen. The tests concealed it by still building the obsolete suffix layout —
  a shape `result_path` no longer emits — and were moved to the real one.

  The naming repair also created a migration, found the round after: a Sonnet
  result written by an earlier version sits under the old universal
  `<case>.json`, and a reader looking only at the path *this* invocation would
  write missed it — the case bought again over a valid, current-digest row
  sitting right there. Two rounds later the same sentence was still only half
  true: the search had grown two name patterns and was still keyed on the
  name, under a comment claiming it read the row. It now opens **every** file
  the queue holds and lets `case_id` decide, so any layout the queue has ever
  written is found — `<case>.json`, `<model>/<case>.json`, and the
  `<case>.<model>.json` that existed between them. A file name is a place to
  look rather than an answer, and now that is what the code does rather than
  what a comment says. A file that exists and
  answers for no model still stops the fall-through to the batches, so a row
  from elsewhere cannot stand in for the queue's own unfinished one.

  And the guard added with that search was over-broad, found the round after:
  returning `False` as soon as *a* file for the case existed meant an Opus
  queue row hid a valid current Sonnet row in a batch, and Sonnet was bought
  again. The question is whether this model's measurement exists **anywhere**,
  so a queue file that answers for another model — or for none, because the
  run did not finish — says nothing about it. The original branch returned
  early too and the guard preserved that shape; the shape was wrong.

  The same double-listing was in `stage2` and predates all of this:
  `measured_outside_the_stream` listed the stream to build the membership set,
  then called `paid_result_files`, which listed it again. A queue result
  landing between the two was read by the second listing while the first had
  not marked its path as inside, so the case was reported as needing adoption
  with its row already in the stream. `paid_result_files` now takes the
  listing its caller has already made. The test counts the listings, which is
  the only thing that can see it.

  And the sentinel for the third answer was drawn from the value space it is
  meant to sit outside of: it was the literal string `"unidentified"`, and
  `SECURITY_SCAN_MODEL` takes any non-empty name. A real measurement bought
  with `SECURITY_SCAN_MODEL=unidentified` returned a value the readers could
  not tell from the sentinel, and its paid row was discarded as unreadable
  rather than reported as another model's work. It is a unique object now.

  And `probe_use` listed the stream three times — once for the verdicts and
  once inside each of its two `measured_outside_the_stream` calls. A paid
  product row written between the first and the rest fell out of `run` (the
  first listing had not seen it), out of `unadopted` (the later listing sees
  it *inside* the stream) and out of the foreign line (it is the product's),
  so a completed measurement somebody had paid for appeared in no line of the
  report at all. One listing is threaded through all three. The three places
  this race was found — `check_accounted.account`, `check_accounted.walk`,
  `stage2` twice — are the same mistake at four depths: **a directory listed
  twice is two directories.**

  And the digest check itself had two states where it needed three.
  `frozen_digests.get(case_id)` answers `None` both for a case the manifest
  does not name and for a frozen case recorded before digests existed, and the
  falsey test let the first through — into the collection, where the reporting
  loop, which walks the manifest, never looks at it again. A paid row for a
  case outside the round vanished without a word, **under a comment claiming
  it was named**. Absence read as agreement, inside the line written to stop
  absence being read as agreement.

  Freezing that listing then had to be done twice, because the first repair
  froze only the production stream and `paid_result_files` went on globbing
  the experiment and round directories afresh on every call. A product
  *experiment* row arriving between the two calls appeared in no report line —
  the race the parameter was added to close, still open one glob along. Both
  listings are captured once now, and the test counts both.

  And closing `freeze` did nothing about a manifest already on disk. One
  naming another model — hand-edited, or written by an earlier revision of
  this same change — was obeyed by both consumers: it matched a Sonnet
  environment, the round was bought with Sonnet, and `compare` put those rows
  against the Opus baselines `baselines()` draws from the product's own
  verdicts. "0 agreed, 1 flipped", exit 0, one model reported as the other
  moving on its own. Both readers now refuse an explicit model that is not the
  product's; absence still means the product, because every round frozen
  before the field existed was bought with it.

  And one more that predates all of it, found because the queue was under
  attention: `run_one` read whatever file stood at the target path after the
  subprocess, without asking whether *this* run had written it. `already_run`
  reschedules a case whose code changed since its last queue result, and the
  old artifact stays on disk — so if `pair_corpus` died before writing, the
  previous run's row was read, classified, and the failed attempt counted as a
  completed measurement. **"Did not check" read as "checked", inside the queue
  built to avoid exactly that.**

  Three rounds went into it, and each repair was answered by the next:

  1. The file's modification stamp, compared before and after. Codex: the
     writer used `Path.write_text`, which truncates before writing, so a
     killed run destroyed the previous paid artifact **and** moved the stamp,
     so the guard did not fire. `pair_corpus.write_results` now writes a
     temporary file and `os.replace`s it, which is atomic.
  2. The stamp alone, then. Codex: `write_results` replaces the target, and on
     a filesystem with coarse timestamps two writes land in one tick — so a
     complete, paid result read as `no-artifact`, the expensive direction.
  3. The inode beside the stamp. Codex: the refusal branch deletes the file,
     because a refused pair has measured nothing and leaving it would make
     `already_run` skip the case for ever — and by then the target had already
     been replaced, so what it deleted was the **earlier paid measurement**.

  The answer was to stop asking. The child is pointed at a path beside the
  target and never at it: the file is this run's, it is `os.replace`d over the
  target only when it is a result, and the previous artifact is untouched
  until a complete new one goes over it. Three questions closed by removing
  the thing that raised them.

  A fourth round then took the name: `<case>.json.attempt` is *deterministic*,
  so two queues running the same case share it and can unlink, read or promote
  each other's file — one completes a valid result, the other replaces it with
  a refusal before the first reads it, the first deletes the refusal, the
  second finds nothing, and a paid measurement is gone with the case still
  queued. `mkstemp` in the target's own directory now, so the promotion is
  still a rename on one filesystem, and the emptiness of the file it creates
  is read as "the child wrote nothing" rather than its existence being read as
  "it did".

  And the digest that guards a round covers the members and **not the answer
  key** — deliberately, because a corrected category must not throw away
  evidence about the same code. Codex, 2026-09-09: that exclusion is right for
  a row and wrong for a round, where what a pass *means* is one of the frozen
  conditions. Edit only a frozen case's `case.yml` and both the queue and
  `compare` accepted the row, so a flip caused by the key moving was reported
  as the product moving, with exit 0. `artifact.answer_key_digest` hashes the
  whole manifest text — not the fields it happens to name today, because the
  list of scoring fields has grown twice — and both ends check it. A round
  frozen before the field existed is not checked rather than refused, the same
  rule the other digests use.

`queue_model` deliberately reads an empty `SECURITY_SCAN_MODEL` as Opus, which
is the opposite of this repository's usual rule that an empty value is a
variable somebody set. `config._env` returns the default for an empty value,
so a run started that way buys Opus; the queue has to answer what the run will
*do*. The first version returned the empty string and argued for it in its own
docstring — the test compares against `Config` rather than against the
argument, which is how the disagreement surfaced.

Each of the four defect tests was run with the predicate answering `True` for
every row — the reader as it stood before this — and each failed. The four
control tests beside them passed, so the filter rejects foreign rows rather
than everything. The two tests for the queue's own model were run the same way
against `queue_model` answering the fixed name, and both failed.

**One gap is left open on purpose**, in the next section: `already_run` and
`check_accounted.executed` still glob fewer directories than `stage2` and
`sentinel` do.

## `already_run` still cannot see experiments or rounds

Found 2026-09-09. `run_queue --round N` rebinds `QUEUE` to
`measurements/round-N/` and writes every result there. The readers that walk
the measurement tree did not walk the same tree:

| Reader | Directories it globs |
|---|---|
| `stage2.paid_result_files` | batches, `queue/`, `queue/by-model/`, `experiment-*/pass-*/`, `round-*/` |
| `sentinel.result_files` | the same |
| `check_accounted.walk` | the same, **since this change** |
| `run_queue.already_run` | its own `QUEUE` — **neither `experiment-*` nor another round** |

`check_accounted.executed` was the third reader caught globbing fewer places
than the results are written to, and Codex raised it as blocking on the change
that rewrote that walk, so it was closed there: a case measured only inside a
round read as `unrun` and the owner was told to buy it again — the exact
defect `executed` exists to prevent, one directory over, at about a dollar a
time.

**`already_run` is left as it stands, and the question is not a glob.** Under
`--round N` it reads that round's own directory, which is what makes a round
repeatable; outside one it reads the queue and the batches. Whether it *should*
see an experiment row is a real question with two defensible answers, and
`check_accounted` deliberately keeps experiment rows out of `verdicts` for a
reason that was paid for: an experiment freezes its own prompts, scorer and
answer key, so its row proves a case was run and not what its answer is.
Skipping a queued case on one may be right, or may be the same "adopted
without a decision" mistake one directory along. It needs adjudicating before
the glob widens; widening it first is how the previous version of this
sentence became a defect.

**No live trigger today.** `measurements/round-1/` holds one file,
`ABANDONED.md`, and no results at all.

## Six questions that were decisions, not repairs — adjudicated and applied

Found 2026-09-09 by six narrow-mandate subagent hunts, each measured against
the running code. They were held here rather than repaired because each had a
defensible answer in more than one direction, and deciding one in passing is
how a gate acquires a rule nobody chose. Codex ruled on all six the same day
and every ruling is in the code; the paragraphs below say what was wrong, what
was decided, and — where the decision has a price — what it costs.

**A NUL byte made a source file unreadable, and the gate passed.** Git decides
`binary` from *content*, which the pinned `--attr-source` cannot touch, so one
NUL in a comment turned a running `.js` into "Binary files … differ".
`_readable_change` subtracted the file and `_reviewed_nothing`'s `accountable`
did not, so one *other* readable file satisfied the gate for the whole change.
Measured: two-file merge request, `auth.js` with one NUL and a `check()` that
returns `true` unconditionally, plus a README edit — exit 0, "No security
findings", `whole_diff_delivered: true`. The obvious repair, *any* unreadable
changed file makes the run partial, would block a merge for adding a PNG.

Ruled: three states, not two. *"A binary change to a recognised source path,
executable file, or otherwise source-classified object makes coverage partial.
A PNG remains a disclosed non-source change and does not block merely for
being binary."* The classification is one property on `ChangedObject`, and
`_partial`, `_readable_change`, `whole_diff_delivered` and the report all read
that one. The report gives it its own heading — the entry a reader has to act
on cannot sit under the one that says no action is needed.

The first implementation built only the first of the ruling's three clauses,
and Codex found both gaps the same day. `bin/server` at mode `100755` was an
asset — the file the machine *runs*, classified by its lack of an extension —
and `.env` was one too, because a leading dot is not a suffix and the guard
`dot > 0` rejected the canonical name while `config.env` matched. Both now
classify as source; a submodule and a symlink do not, though git writes their
modes in the same field.

**The list was pointing the wrong way, and it took three rounds to see it.**
The first two versions asked "is this name on a list of *source* extensions",
and Codex refused both on one ground: *"every omission restores the exact
bypass the check was introduced to prevent."* `Login.vue` with a NUL byte in a
template string was invisible, and so were `.svelte`, `.dart`, `.clj`, `.sol`
and every language nobody had added yet — a silent "no findings" over source
no reviewer received.

So the table now names the **assets**, and everything else is source. The
omissions fall the other way: a format missing from `ASSET_SUFFIXES` is
reported rather than hidden, which is a visible false alarm with
`SECURITY_SCAN_FAIL_ON_INCOMPLETE` behind it and a line in that table as the
permanent fix. **The price is real and is accepted here:** a changed
`docs/readme.txt` that git calls binary — it has a NUL byte in it — now makes
the review incomplete. That is rare, it is odd when it happens, and it is a
message rather than a silence.

`.jar` and `.war` are in the asset table and Codex named them questionable. A
swapped jar is a supply-chain change; it is also unreadable to any reviewer at
any setting, so calling it withheld source would fail every dependency update
forever. **What is not built:** a separate rule for a changed archive — a
required justification, a checksum comparison, a manifest diff. This paragraph
is the record that the case was seen and left, not overlooked. `.svg` sits in
the same table on the same reasoning and is the weaker case, since an SVG can
carry a script element and git rarely calls one binary.

## An executable with a compiled-output suffix — adjudicated: the name wins

Codex, 2026-09-09, on the inverted rule: `bin/updater.exe` added at mode
`100755` comes out a disclosed asset, because `.exe` is in the asset table and
the table is asked before anything else. Its ruling was disjunctive — *"a
recognised source path, executable file, or otherwise source-classified
object"* — so an executable is meant to be accounted for whatever its name.

Two readings, and both have a cost that is paid by somebody:

* **The mode wins.** Every changed `.exe`, `.so`, `.dylib` or `.jar` carrying
  the executable bit makes the review incomplete. Nobody can read any of them
  at any setting, so the gate blocks on a fact no reviewer can act on, and a
  gate that cannot be satisfied gets deleted rather than obeyed — which is the
  reasoning the three-state ruling itself rests on.
* **The name wins**, which is what the code does today. A committed
  `updater.exe` is reported under "No source lines to read" and does not
  block. A swapped binary is then disclosed rather than refused.

Codex chose the second, 2026-09-09: *"The executable bit says the object may
be launched; it does not make its contents reviewable source… Option A accepts
a permanent false-incompleteness failure: legitimate binary updates block with
no action capable of completing the review. That violates the rule that an
unsatisfiable gate is deleted. Option B accepts that a malicious binary
replacement can pass this source-coverage gate after being disclosed. That is
a real supply-chain limitation, but it is honestly classified: detecting it
requires a separate binary-integrity or provenance control, not pretending the
source reviewer could have read it."*

**So this is what the product does not do, stated plainly:** a merge request
that replaces a committed binary — an `.exe`, a `.so`, a `.jar` — is listed in
the report and does not block. Nothing here reads it, and nothing here claims
to. A team that needs that needs a binary-integrity control, which is a
different product.

The half of the finding that is *not* in question was fixed: `.bin` and `.dat`
are out of the asset table, because those two suffixes name no format at all
and `scripts/bootstrap.bin` at mode `100755` is as likely to be a shell script
as a blob. Codex: *"filename suffixes do not prove that a file is compiled
output."* The residue is only the suffixes that unambiguously name compiled or
rendered output, and it is here rather than decided in passing.

`tests/test_workspace.py` asserts the adjudicated answer with the reasoning
beside it, and it took two attempts to get the assertion honest: the first
version asserted that every asset stays an asset at mode `100755` as though it
were obvious, and Codex ruled that it encoded a defect rather than protecting a
fix. The difference is not the assertion — it is that the assertion now names a
ruling and the failure that ruling accepts.

A second round on that repair found two more, both in the executable rule.
It asked the two endpoints *together* and refused the object when either was a
symlink — so git's type change `120000 -> 100755`, a symlink replaced by a
real executable, came out an asset. And it asked the bit *before* the name
tables, so `docs/logo.png` committed at mode `100755` — an accidental `chmod
+x`, and common — became withheld source and an image-only merge request came
out incomplete. A gate that blocks for adding a logo gets deleted rather than
obeyed, which is the failure the three-state ruling exists to avoid. The bit
is now the last question, and `ASSET_SUFFIXES` names the content types it may
not promote.

The executable rule is gone with them: with the default now "source unless it
is a recognised asset", `bin/server` is source without anybody asking about
its mode, and a property whose docstring explains a decision it no longer
takes part in is the shape this repository keeps being caught by.

**One identity, two readers.** Deduplication compared the first anchor;
suppression compared the whole anchor set. Both directions were live: one
weakness quoted from a different line twice became two candidates and bought
two verifier panels; an accepted risk written from one finding silenced a
*different* one sharing an anchor.

Ruled for the suppression side: *"Suppression must match the one canonical
fingerprint printed for acceptance, not any shared anchor. False negatives
cost another explicit suppression entry; false positives hide a different
weakness."* Dedup stays conservative — duplicate findings and extra verifier
calls are preferable to merging distinct weaknesses whose evidence overlaps.
The price is written up separately below.

**`agreed_confidence` took the upper median.** With an even number of
observations one reply carried on its own, upward but not downward — and the
docstring claimed "one outlier moves nothing". Ruled: the claimed confidence
is the tie-break observation, added when the count is even, and the median is
then taken. One changed reply plus one unchanged reply moves nothing in either
direction; two agreeing replies move it in either direction.

**A one-seat panel could delete a critical.** `verify_votes` defaults to 1 and
escalated to three only when the finding could block — false under
`SECURITY_SCAN_FAIL_ON=none`, in an ungated category, and for a pre-existing
finding. One verifier then refuted a critical and it landed in the collapsed
"Refuted" block, in the mode `_verify_floor`'s own docstring calls the one
"where the report is the whole product". Ruled: *"Gate configuration controls
the exit code, not whether the report may erase a critical on one opinion."*
The protection sits in `_votes_for` independently of `_could_become_blocking`.

**`review_identity` omitted every ceiling that decides how much was looked
at.** Measured: a `normal` run and a `deep` run over the same commits hashed
to the same digest `fb7cb1edda3dbf6d`, so `--reuse` answered the deep review
with the shallow one's exit code. Ruled: the identity must carry the resolved,
effective budget, *"not a hand-selected subset of raw settings"*. It is
derived from `config.BEHAVIOURAL` now — the list a test already forces to be
complete — with the exemptions named and checked. Beside it, `agent_version`
had read `0.1.0` across 88 commits to `src/`; `source_digest()` hashes the
package's own files, so the key moves when the code does.

**The verifier's model entered the reviewer's list.** `review_models` was the
difference of two lists, which cannot express one model doing both jobs: the
list came back empty, the run read as having had no reviewer, and a rule put
the requested model back — recording "not substituted" about a run nothing
vouches for. Ruled: *"Store roles independently… For old artifacts whose
overlapping lists make the reviewer unknowable, report the provenance as
ambiguous and refuse corpus admission rather than inferring 'not
substituted.'"* `models_reviewed` is written as it happens, `models_served`
stays as a compatibility aggregate, and `provenance_ambiguous` is a published
field that `stop_rule.why_not_row_for` refuses on.

The first implementation of that refusal read the serialised flag and nothing
else — and a legacy artifact, the only kind this path exists for, cannot carry
the flag at all. So the one shape it was written to refuse was the one shape
that walked past it, and the comment beside the line said the opposite in so
many words. Absence read as agreement, inside the line added to stop a
different reading of absence. Found by Codex the same day and fixed: the
reader recomputes the rule when the field is absent, and
`tests/test_model_list_predicates.py` now pins the reader's spelling against
the writer's over the same shapes.

## A single file whose diff is over 120,000 characters can never be read whole

Two ceilings cut the diff and they are independent. `Workspace.diff_ceiling`
bounds how many **bytes** the workspace will read and is configurable through
`SECURITY_SCAN_DIFF_CEILING_BYTES`. `tools.MAX_DIFF_CHARS` bounds how many
**characters** the model is shown and is a module constant with no setting
behind it. The second is the smaller on any default configuration, so it is the
one that binds.

The consequence is narrow and real: when one file's own diff exceeds 120,000
characters, no value of the environment variable makes that run complete. The
run is recorded partial, `SECURITY_SCAN_FAIL_ON_INCOMPLETE` decides whether it
blocks, and **the operator's only move is to split the change to that file.**
`--path` is not a second one: scoping the review to that file alone reaches the
identical limit. That is true wherever such a file sits — the one the cut
landed inside, or a later one dropped entirely — so `--path` is a remedy for
the *files whose own diff fits*, and for no others. Neither move recovers what
*this* run did not see.

Measured on 2026-09-08 with the workspace ceiling raised fifty times above
`MAX_DIFF_CHARS`: `last_diff_truncated` was False, so the byte ceiling was
provably not what bound, and the tool result still carried "Diff trimmed at
120000 characters". The test is
`test_raising_the_ceiling_really_does_not_complete_the_reading`.

Written down rather than repaired because deriving the model-facing ceiling
from the configured one changes how much text a hostile change can push into
the reviewer's context, and that is a decision with its own argument. Three
gate rounds put a remedy in the operator's message that turned out not to work
— reading the file in windows, then raising this setting flatly — so the
message names the setting conditionally: it helps when the byte ceiling is
what cut the diff, and not otherwise.

**Conditionally, because the run cannot tell which ceiling cut it.**
`_handle_get_diff` knows — `trimmed` is the character limit and
`ws.last_diff_truncated` is the byte one — and collapses both into a single
`diff_truncated` flag before the gate or the report sees it. So neither
message can say which move will work, only which one might. Carrying the cause
through `Coverage` would let both say the true thing for the run in hand; it
is not built, and this paragraph is the record that it is missing rather than
overlooked.


## The forge context is behavioural and is outside the review's identity

`briefing` puts the merge request's title, description and source branch in
front of the model, so two runs over one commit with different merge request
prose are not the same review. `config.BEHAVIOURAL` names `gitlab` for exactly
that reason.

`review_identity` leaves it out, and the reason is that the same object also
carries the job url and the pipeline's own commit sha, which differ on every
run of an unchanged pipeline. Folding it in whole would make every identity
unique and silently end reuse — the artifact would never be reusable and
nobody would be told why. Folding in a chosen part of it is the hand-picking
that Codex's ruling of 2026-09-09 was about, and choosing which part is a
decision with its own argument.

So `identity.CARRIED_ELSEWHERE` names it with an empty string, the completeness
test in `tests/test_identity.py` passes because the exemption is explicit, and
this paragraph is the record that the exemption is a judgement rather than an
oversight. **What can go wrong:** a merge request whose description is edited
to say "this is a refactor, ignore the auth change" keys the same as the run
before the edit, so a cached artifact answers for prose the model never saw.

## An accepted risk can stop matching when the model requotes

`suppress.Rule.matches` compares the ignore file's value against the finding's
one canonical fingerprint, and the fingerprint is built from the first
distinctive line the model quotes. Measured: across four identical runs of one
case, three quoted a call and the fourth started a line later at the expression
inside it. The entry written from one of those runs does not match the other.

Until 2026-09-09 the rule matched *any* anchor the finding carried, which
survived that drift and cost something worse: two different weaknesses in one
file and category that quote one line in common share an anchor, so an entry
accepting the first silenced the second — permanently, and looking exactly like
a clean report. Codex ruled the trade the other way: *"False negatives cost
another explicit suppression entry; false positives hide a different
weakness."*

**What it costs the operator:** a blocked merge that was already accepted can
block again, and the remedy is a second line in the ignore file with the new
fingerprint the report prints. **What is not built:** an identity stable across
requoting. Codex named the shape — it needs more than "a line both quotes" —
and nothing here attempts it.


## The pass rate counted single draws from a process measured as unstable

`stop_rule.latest_rows` settles each case with the newest admissible product
row. That is the best estimate of current behaviour and it is also **one
draw**: `experiment-noise-floor-2` ran thirteen cases twice with nothing
changed, and two came out differently — the 15% instability `RESULT.md`
reports. Those two sat inside the pass rate as facts and nothing in the
counting said which they were. `go-m6jg-wr9m-cg2f` was recorded as a miss
because the second pass missed it; `rb-g65v-27r3-5p6m` as clean because the
second pass was clean.

**The suspicion that led here was wrong, and the measurement is what settled
it.** The queued note said a row from a trial directory could supersede a
corpus row *because it was measured with a different instrument*. It cannot:
across 248 member records there is exactly one settings block, and the two
records that differ carry `verify_model: claude-opus-5` explicitly where the
rest leave it unset — and unset resolves to the reviewer's model, which is
that same model. Same instrument, different recording, nothing to refuse on.
The defect was one reader along from where it was expected.

Codex, 2026-09-09, choosing to mark rather than to leave it: *"This accepts
the failure of conservatism: without an epoch/version field, it can preserve a
historical flip after a genuine change in behavior. That is preferable to
silently converting observed nondeterminism into a definitive current pass or
failure."*

So `check_accounted` has a sixth basket, `unstable`. **The tally did not
move**: it is still 50 pass, and the basket is empty today. The three cases
the first implementation put in it were not unstable at all — each carried a
failure recorded against an *older version of the case* beside a pass recorded
against today's, and within its own version every row agrees. Those are
repaired cases, and the reader was manufacturing a contradiction out of two
different questions. `check_accounted.standings` has always rejected a stale
`case_digest`; this reader did not, which is the two ends of one rule
disagreeing, arriving inside the change that was fixing a different reader.
Found by Codex the same day, along with three more:

* a `{"results": [...]}` file — a shape three other readers accept — was
  treated as one row, so such an artifact could hide a flip completely;
* the check was asked *after* every branch about the standing answer, so a
  case whose rows contradict each other but whose newest row cannot be read
  fell to `unaccounted` and the flip was named nowhere;
* the line that names contradicted cases looked only at `limitation` and
  `known_failure`, while `invalid` wins before instability is asked — so a
  case ruled invalid hid its flip entirely, under a comment claiming the
  opposite.

What the basket actually reports today is the three real flips, and they are
all under a ruling somebody made. The ruling keeps them and they are named
beside the tally with the bucket they are in, because a machine observation
does not revoke a human decision — this file has already been caught once
letting it:

```
3 more carry a contradicted answer and keep the bucket a ruling put them in:
  go-m6jg-wr9m-cg2f (limitation), py-p43p-whwx-q52h (limitation),
  rb-g65v-27r3-5p6m (limitation)
```

A third round found three more, and the first is the one worth carrying:
**the command printed "neither passed nor failed" and returned exit 0 to CI in
the same run.** The exit condition listed `unaccounted`, `unrun` and
`unadopted` and not this basket, so a case with two answers and no ruling
announced itself and was reported as success. `unstable` is now one of the
states that is not exit 0, and the message says what closes it: a fix that
removes the disagreement, or a line here saying the case is not decidable as
it stands. **Re-measuring is not a third option** — a third draw of a coin
that has landed both ways is a third draw.

The other two: a contradicted case that is in no bucket at all — deleted,
renamed, mistyped — was dropped from the naming line in silence, under a
comment claiming every contradicted case is named; and the test written for
that naming would have passed with the whole printing block deleted, because
it asserted the bucket rather than the report. Checked on the running code,
the first of those cannot currently arrive: `about_this_version` refuses a row
whose case has no manifest, so such a row never contradicts anything. The
fallback that names it stays, and what the test asserts is the predicate that
makes it unreachable — because that is the assertion that fails if somebody
loosens it.

A fourth round found the repair to the second of those lying in its turn:
`--construction snapshot` filters the buckets and did not filter this list, so
all three contradicted *regression* cases were reported as "not in the
corpus" — about cases sitting in `corpus-real/`. Three states now, not two: in
a bucket, in the corpus but outside the filter this run asked for, or absent.
The same shape as the source classifier earlier the same day, one file along.

A fifth round found two more, and the first is wider than the change that
surfaced it. **A `case_id` was a path, not a name.** It is joined onto the
corpus directory, so `"../corpus-real/foo"`, `"./foo"` and `"foo/."` all
resolve to `foo` and were accepted as results about it — and
`about_this_version` is what `standings` uses to settle every case, so an
aliased id could supply the standing answer for a case it does not name, in
the accounting every number in this project is read from. A case id is now
required to be one directory name. The second: `main` scanned for
contradictions a second time to build the naming line, so a row written
between the two scans made two views of one directory disagree about one case
— named as contradicted *and* as sitting in `pass`, under a sentence claiming
a ruling holds it there. One listing now, handed to both readers.

"A directory listed twice is two directories" is one of the four recurring
shapes this repository's own commit message names, and it arrived inside the
change that message describes.

The coherence check that refuses a row whose three outcome fields disagree has
**never fired on a real row**: 118 rows taken, 34 with a non-boolean field — a
crashed run — 53 another model's, 0 dropped. Codex checked the writer against
it independently and `pair_corpus` writes exactly that expression. It is a
guard against a file no run wrote, not a filter on production output.

Two things this does **not** do, and both are open:

* **It is sticky and cannot be un-stuck.** Two later agreeing draws do not
  resolve an earlier contradiction, because nothing in the artifacts says the
  code changed between them. A genuine repair therefore leaves the case
  marked. Codex named the fix — a measurement epoch, a version field the rows
  carry — and it is not built.
* **`stop_rule.rates` is untouched.** It still counts the latest draw for the
  D-013 recall and false-alarm figures, so the baskets and the rates now
  answer the instability question differently. That is deliberate rather than
  overlooked: those two numbers have a published threshold behind them and
  moving them is a separate decision with its own measurement. It is written
  here so that the difference is a recorded choice and not a discovery.
