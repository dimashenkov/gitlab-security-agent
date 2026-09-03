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

There is no recall figure and no precision figure. Both were measured, both
turned out to be measuring something else, and both were withdrawn:

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
- **Stability is measured on one synthetic case**, four identical runs
  agreeing. Nothing is known about run-to-run agreement on real code. Assume
  two runs of the same merge request can disagree.

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
