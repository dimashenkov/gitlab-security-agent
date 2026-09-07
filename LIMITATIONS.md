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

## A file over 292 KB cannot be read at all

`blob_text` refuses a blob over `MAX_READ_BYTES`, and the ceiling is on the
whole blob rather than on any window of it, so `read_file` cannot reach a large
file either way. Measured on 2026-09-06 against a 302,057-byte file whose
change was two lines:

| the attempt | the answer |
|---|---|
| the whole file | refused |
| a window of three lines | **the same refusal, word for word** |

A weakness introduced by a small diff in a large existing file therefore cannot
be quoted, and a finding whose citation cannot be validated is not recorded.
The diff itself carries the new lines, so nothing is truncated and no context
is refused: the gate sees an ordinary, complete review with no findings. That
is the limitation, and it stands — windowed reading is not built.

**The message is fixed; the limitation is not.** It used to say *"Pass
start_line and end_line to read a window of it"*, which is the remedy that does
not work — the window hits the same ceiling and gets the same message,
repeating the suggestion that had just failed. It now states the limit and
names no remedy at all, and a test holds it to that.

The correction had the defect twice before it stopped. The first replacement
pointed at `get_diff`, which exists only in a diff review: `diff()` refuses
without a `diff_base`, the MCP server does not offer the tool in that mode, and
the diff has ceilings of its own. Codex found the same class of error inside
the fix for that class of error, one gate pass later. So the test checks for
five words rather than one phrase — `get_diff`, `start_line`, `end_line`,
`instead`, `try` — because the next person to add a helpful suggestion should
meet the question rather than the wording.

## The search reads the working tree; every other reader reads the revision

`blob_text` says it in its own docstring — the checkout "is material an
untrusted contributor controls, and what sits at a path on disk need not be
what the commit says is there" — and `read_file` goes through it. `search`
builds a `git grep` with no revision, which searches the working tree.

Built as a real repository on 2026-09-06: the reviewed commit has no
`require_admin`, the working tree has one.

| reader | answer |
|---|---|
| `read_file` at the reviewed revision | the guard is absent |
| `search` for the same name | **1 match** |

A verifier that refutes a finding because "the guard is right there" can be
looking at code that is not in the change. It needs no attacker: a later
commit on the branch, an earlier CI step that wrote a file, a checkout that is
simply ahead. The reasoning `blob_text` gives for not reading the working tree
applies to `search` word for word and was not applied to it.

Found by `gpt-6-astra` and confirmed by building the tree. Not fixed: `git grep`
takes a revision, so the edit is small, but it changes what every search
returns and that wants a measurement rather than a patch at the end of a
session.

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

## A reviewer that says "I could not settle this" passes

`finish_review` takes an `unresolved` list, the field exists so the reviewer
can record a security question it could not answer, and the artifact carries
it. `decide` never reads it. Measured on 2026-09-06 against `gate.decide`, with
a control:

| the run | exit |
|---|---|
| finished, nothing unresolved | 0 |
| finished, recording *"cannot establish authentication for /admin/run"* | **0** |

So the sentence a careful reviewer writes when it knows it has not finished
thinking changes nothing about the decision. `_partial` asks three questions —
did the model stop early, was the diff truncated, were contexts refused — and
"did the reviewer leave a security question open" is not among them.

The first two attempts at this check both printed the same exit code for the
run *and* its control, which proves nothing; the code was coming from
`_reviewed_nothing`, because the synthetic outcome recorded no exposures. The
finding stands only because the third attempt made the control exit 0.

Found by `gpt-6-astra` on a hostile pass over the standing product. Not fixed:
whether an open question should block, warn, or only be printed is a policy
choice, and the gate has one flag for partial reviews already.

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
