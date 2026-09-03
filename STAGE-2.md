# Stage 2 — the agent, checked against known advisories

**The goal is not a new feature. The goal is for the agent to be run often over
code with known weaknesses, and for the discrepancy to be fixed.**

The obstacle was the price: every run costs money over the API, and the rule of
this project is that a cosmetic change does not justify a run. So reviews waited
for an occasion, and there was no occasion. Stage 2 removes that obstacle — a
second runner through `claude -p`, which runs under the login this CLI already
has — and what that costs is a property of the login, which the run asks about
and records instead of assuming. CI stays untouched on the API.

Codex, round 21, verbatim: *build the thin dogfood runner, not the full
second-provider feature. Preserve the explicit `claude-cli` identity, keep CI
untouched, use zero-verifier probes only as leads, and require real use before
investing in polish.*

Thin means: not a second provider with equal rights, but a way for the author to
run his own tool. That is why there is an explicit `claude-cli` identity in the
artifact, why CI is not touched, and why polish comes **after** use, not before
it.

**Change on 2026-08-27, point 8.** Originally the stage was measured with twenty
reviews of changes in this repository, adjudicated by hand. The question that
answered is "was it useful to you" — and only the author of the code can answer
that. The code here is mine, so both the question and the answer are mine, and
they mean nothing. That is why `journal/` is not a measure of anything in this
stage, and the work is measured against twenty-four pairs from published
advisories, whose truth is the fix by the maintainers themselves. See point 8.

---

## Points

Every point says what it is and when it is done. "Done" is something that is
checked with a command, not with judgement.

### 1. Budget — `budget.py`

One `RunBudget` for the whole review: wall clock, number of tool calls, number of
verifier sessions. Verifier capacity is **reserved** before the session starts
rather than counted after it — verifiers run concurrently, and counting after
completion lets three of them see room for one more and start together.

An exhausted budget is exit 2 with a sentence saying that this is not a statement
about the code.

Profiles: `probe` (6 turns, 0 verifiers, 5 min, never conclusive), `normal`
(20 turns, 3 verifiers, 20 min), `deep` (40 turns, 3 verifiers, 30 min).

Two refusals from the original specification, confirmed by Codex:

- **`max_verifiers: 2` is forbidden in the constructor.** Two do not make a
  majority; exactly that configuration gave three blocks and one pass in four
  identical runs. A profile that quietly sets two undoes a measured fix while
  looking like a budget choice.
- **`probe` has zero verifiers, not one.** One verifier produces an object shaped
  like a verdict behind which stands a single unchecked opinion. Zero is more
  honest: whatever `probe` finds is a lead, not a finding.

*Done when:* `pytest tests/test_budget.py` is green and covers the refusal of an
even panel, the reservation before the start, and exit 2 on exhaustion.

**State: the code is written, the tests are missing.**

### 2. Splitting the result into three

```
canonical_result     ← compared byte by byte between the runners
provider_telemetry   ← checked against a schema, the values are not compared
raw_artifact         ← not compared
```

Today the artifact is one object and the telemetry is mixed in with the decision.
Without that split the conformance test (point 5) would have to carry a list of
exceptions scattered through the checks — and a scattered exception is the way a
discrepancy passes unnoticed.

Into `canonical_result` goes everything that can change the decision: tool
results and the classification of errors, call counting, the behaviour when
reserving verifier capacity, acceptance or rejection of a citation, normalized
paths, schema validation, normalization of severity and confidence, derived
severity, fingerprints, the ordering of the candidates, vote aggregation,
confirmed/refuted/disputed, blocking fingerprints, warnings and conclusions in
the report, the presence of an artifact on every terminal path, and the rule that
an unfinished run cannot look clean.

Into `provider_telemetry` — provider, requested and served model, raw stop
status, session identifier, time and duration, tokens and cost (including "not
reported"), number of turns by the provider's own count, cache, diagnostics
underneath the canonical stop reason.

**How it was decided (different from the first sketch):** the artifact is **not**
restructured. `findings.json` stays as it is — six tools read it and every old
artifact would have become unreadable. Instead `canonical.py` is a pure function
that splits it in two at comparison time. The list of exceptions lives in one
place, not scattered through the test — exactly Codex's warning.

The direction of the failure is deliberate: **a field nobody has classified gets
compared.** `TELEMETRY_PATHS` is a list of what is allowed to differ, not of what
is forbidden. A new field tomorrow falls into the compared half, the test fails,
and somebody looks. The opposite — falling into the ignored half — does nothing,
and that is exactly the case that is not discovered afterwards.

*Done when:* `tests/test_canonical.py` is green over an artifact produced by a
real run, not by a dictionary written out by hand.

**State: done.** 9 telemetry paths, 21 tests.

### 3. `ClaudeCodeRunner`

`claude -p` as a subprocess, `--output-format json`. The tools are supplied
through an MCP bridge to the existing `dispatch()` — the same code the API path
uses, with no second implementation. Checked on this machine (CLI 2.1.231):
`--print`, `--output-format json`, `--mcp-config`, `--strict-mcp-config`,
`--allowedTools`, `--disallowedTools`, `--permission-mode`, `--system-prompt`,
`--no-session-persistence`, `--exclude-dynamic-system-prompt-sections`.

**`--max-turns` does not exist.** So the turn ceiling is not enforced through the
CLI but through what we count ourselves: the wall clock (we kill the process) and
the number of tool calls (our `dispatch` refuses past the ceiling, which at the
same time tells the model to wrap up). Codex: turns are in any case less portable
than time and calls.

**Where the seam runs.** `claude -p` carries a loop of its own, while our loop
holds the turn ceiling, the clock, the retry on a truncated response, and the
list of allowed stop reasons. The runner does not insert itself into it — it
**replaces** `run()`.

That is tolerable for one reason: everything that decides anything accumulates in
`Session` through `dispatch()`, because every capability is a tool. The message
history is not where the decision lives — the tool journal is. If the MCP bridge
calls the **same** `dispatch()`, `Session` fills up identically, whoever drove
the loop. The runner supplies only a stop reason, a summary, turns and spend —
that is, exactly the telemetry from point 2.

**Three things before the runner gets written** (Codex, round 22):

1. **`finish_review`** — an explicit protocol for the end, instead of "the CLI
   exited with 0". ✅ Done. See below — it fixes something in the current path
   as well.
2. **A journal of canonical events**, not a replay of the raw calls. The child
   accumulates events, the parent reduces them through the same `Session` logic.
3. **The phases must carry ownership of the budget mechanically**, not by
   agreement. Today I claim that they do not overlap: the child counts the calls
   during the review, the parent holds the clock and reserves verifier sessions,
   which start after the review ends. A claim that is not enforced is a claim
   that one day stops being true.

**The turn ceiling becomes `int | None`.** The CLI cannot enforce it, so for this
runner it is `None` and is reported as "not enforced by this runner". A profile
that promises 20 turns to a runner that does not count them is lying.

**The summary from the CLI is presentation, not state.** It is recorded with
provenance `claude_cli.result` and never creates, removes or changes a finding.
The canonical summary comes through `finish_review`.

**The verifiers go through the CLI locally as well.** Otherwise every successful
local review still sends a bill over the API — exactly what this stage removes.
The verifier needs no MCP: a replaced system prompt, zero tools, a hard timeout.

**The parts that already stand:**

- `mcp_server.py` — the bridge. Every call goes through the same `dispatch()`.
  Descriptor 1 is taken at the file-descriptor level, not only `sys.stdout`: a
  subprocess that inherited it would have put `git`'s output in the middle of a
  JSON-RPC frame. The production entry point **refuses to start** if it cannot
  take it.
- `session_document.py` — the finished session, written atomically by the child
  and checked by the parent. What is derived is recomputed, not trusted.
- `crash_journal.py` — what is left of a killed run. It never turns into state
  that gets judged upon. Exclusive creation of the file and a run id on every
  record: a second run over the same path would have presented findings from
  yesterday's run as today's progress.
- `rendering.py` — the two escaping rules in one place, because two different
  things now render text for the model.

*Done when:* a run over a fixed diff produces the same `canonical_result` as the
API path over the same diff.

### 3a. `finish_review` — the review says that it is finished

Done, and it is worth a section of its own, because it fixes something in the
*current* path.

Until now the summary was whatever happened to be in the last response — a
sentence written to be read, arriving over a channel with no schema and no
minimum. Now it is a tool argument and is recorded exactly as it was passed.

More importantly: the review now **declares** that it has finished. Over the
Messages API the difference is small (`end_turn` means the model decided to
stop), but a provider that drives its own loop exits with 0 both when the review
is finished and when something gave up. The two must never look the same.

Plus `unresolved` — the questions the review did not manage to close, one per
line. A named gap is worth more than the finding above it; an unnamed gap is
indistinguishable from a clean review.

**It is recorded, it does not block.** A run that stops without a signature has
still completed — turning that into a failure today would fail runs that are
fine. The number is read off the batches over the corpus, and then it is
tightened.

### 3b. `submit_verdict` — the verifier votes instead of stopping

The same thing on a smaller scale. A review that stops is not a review that
finished; a verifier that stops is not a verifier that voted.

Over the Messages API the second case is nearly safe — a response constrained by
a schema is a guarantee, not a hope. A provider with a loop of its own gives no
such guarantee, and "the process exited" would have read as "the panel voted".

Both channels stay open — removing the constrained response would weaken the path
that works today. The vote records which channel it came through: an argument
that was passed and a response the transport happened to validate are not the
same event.

The schema of the verdict is supplied from outside, it is not written out again
in the tool layer. Two definitions of a verdict is exactly the drift this project
has already caught twice.

**And one correction of Codex itself.** It ruled that the verifier through the
CLI needs no tools. Here the verifiers **do** have tools and read the code before
they vote; the prompt asks for `control_search` — what they searched for and
where — and a verdict that cannot say what it searched for drops to `uncertain`,
and `uncertain` is below the threshold. A verifier without tools would not have
voted worse: it would have voted `uncertain` for everything and every finding
would have blocked. `Profile` already refuses such a configuration by name.

### 4. Closing off the tools — two layers

One layer is not enough.

- **Layer 1:** through `--mcp-config` only our tools are exposed, and
  `--strict-mcp-config` switches off every other MCP configuration on the
  machine.
- **Layer 2:** a permission mode that refuses everything not enumerated — Bash,
  Write and Edit are not merely not granted, they are refused.
- **Plus:** switching off the ambient Claude Code configuration — `CLAUDE.md`,
  skills, plugins, hooks, settings.

The last one is the reason, not a convenience. Codex: *this runner does not share
your prompt contract — it quietly adds a second instruction channel controlled by
the repository.* `CLAUDE.md` in the reviewed repo is a file the author of the
change can edit. The whole project rests on the rule that the contents of the
repository are data, not instructions; a runner that reads `CLAUDE.md` breaks it
before the prompt has even started.

**How it was decided — stronger than planned.** The CLI skips the trust dialog in
non-interactive mode. That means it must not be run **inside** the reviewed
repository at all: there `.claude/settings.json`, `CLAUDE.md`, hooks and plugins
are files the author of the change can edit, and they become a second instruction
channel underneath our prompt contract.

That is why the CLI runs in an **empty temporary directory and is never given a
path to the tree.** The repository is read only by the MCP server — a different
process. This is not a setting that can be got wrong; this is the absence of a
path.

The remaining layers stand: `--strict-mcp-config` (every other MCP configuration
is ignored), `--allowedTools` with our prefix only, `--disallowedTools` naming
every built-in tool one by one, `--system-prompt`, which **replaces** (rather
than appends), and `--no-session-persistence`.

*Done when:* a test proves that the CLI is not given a path to the tree and that
a request for Bash is refused.

### 5. Conformance test — 13 failure scenarios

The two runners must give the same `canonical_result` on the same input. Codex:
the most valuable fixtures are the failures, not the successes.

| # | Scenario |
|---|---|
| 1 | ordinary success |
| 2 | corrupted terminal JSON |
| 3 | missing terminal result |
| 4 | unknown status |
| 5 | authentication failure / rate limit / exhausted quota |
| 6 | killed on the wall clock while the model is thinking |
| 7 | killed on the wall clock while a tool is running |
| 8 | exhausted budget for calls |
| 9 | exhausted budget for verifier sessions |
| 10 | a request for a forbidden tool |
| 11 | a partial finding, then termination |
| 12 | a successful end with invalid data for a finding |
| 13 | the process is killed without leaving an artifact |

*Done when:* 13 of 13 pass with both runners, and `canonical_result` is
byte-identical in all 13.

### 6. Choice of runner, with no silent fallback to the API

`--provider claude-cli | anthropic-api`. There is no `auto` — a mode whose job is
to decide which of two accounts to charge is a decision about money taken instead
of the user. If `claude-cli` is unauthenticated, rate-limited, exhausted or
crashes, the run **fails**. It does not switch over.

*Done when:* a test proves that a failure of the CLI gives exit 2 and zero API
calls.

### 7. Scope — `--changed-only` and `--path`

Without this every local run is a review of the whole repository and "run it
often" is impossible. `--changed-only` against the branch you started from is the
case that will be used every day.

**Two flags, not the three of the first sketch.** `--path` accepts an exact path
just as easily as a pattern, so a separate `--file` would have been a second
spelling of the same thing. A flag added in order to close a checkbox is how a
measure stops measuring.

**It narrows what is reviewed, never what is read.** The whole design rests on
following the code outside the hunk — the check that makes the change safe, and
the caller that makes it attackable, are almost never in the diff. A scope that
fenced in the reading too would have turned every hidden control into a false
alarm: the tool would become less reliable the more precisely it was aimed.

**And it does not soften the threshold.** The map of changed lines deliberately
ignores the scope. It answers "did the change touch this line" — a fact about the
change, not about what we asked to look at. If it narrowed along with the scope,
a finding outside the scope would look pre-existing, and pre-existing ones are
let through more leniently — that is, a flag for "look at less" would make the
threshold more forgiving towards what it did look at.

A narrowed review has a **different identity** and carries a warning in the
report. "No findings" from a review of one file and "no findings" from a review
of the change are the same sentence and opposite claims.

**State: done.** 13 tests.

*Done when:* the time of `tools/review.sh --changed-only` has been measured from
a real run, not from judgement — that is, at point 8.

### 8. Qualification against pairs of advisories

**Not "the measure". A name that says what it is** — Codex asked for exactly
that, because the previous name promised more than the thing does.

As it was: twenty reviews of real changes in this repository, every finding
adjudicated by a person. The question it answered is "was it useful to you" — and
only the author of the code can answer that. The code here I wrote myself, so the
question is mine, not his, and the answer means nothing.

The decision of 2026-08-27: **this is not worked on for now.** The project is
measured only against other people's repositories, whose problems are already
known.

`corpus-real/`: **43 advisories**, drawn from published advisories, and the truth
is **the fix by the maintainers themselves**.

The counting is per advisory, not per directory. One advisory gives a
`regression` case and usually a `-snap` twin, and `tools/harvest_pairs.py` says
of the two constructions "never score the two constructions together" — that is,
a table that adds them together counts most rows twice. Hence: 43 `regression` +
39 `snapshot` = 82 directories in `corpus-real/`, plus 23 written by hand in
`corpus/` = 105.

```
python3 tools/check_corpus.py corpus/ corpus-real/
# 105 case(s) checked, 0 with problems.

python3 -c "
import yaml,pathlib,collections
c=collections.Counter()
for m in sorted(pathlib.Path('corpus-real').glob('*/case.yml')):
    c[(yaml.safe_load(m.read_text()) or {}).get('construction')]+=1
print(sorted(c.items()))"
# [('regression', 43), ('snapshot', 39)]
```

Four `regression` cases have no `-snap` twin: `go-qqff-5854-px68`,
`php-gvrw-qqp5-jgc5`, `php-hq84-x37p-j6q5`, `ts-q7m3-rhxg-7vxr`. That is where
the difference 43 against 39 comes from.

Not all of them can measure anything — the ones adjudicated unusable have a
"safe" member that still carries the weakness the case is about, and a pair with
such a member distinguishes nothing in either direction. The denominator is
computed, not copied out: `tools/stage2.py` reads `adjudications.yml` and
subtracts the adjudicated ones. Adjudicated unusable are four:
`cs-q939-rpr3-3284`, `py-2cp2-2r3c-7p7r`, `py-6x92-6vx4-5fwr` and
`py-2cp2-2r3c-7p7r-snap`. Hence the denominator of point 8 is **40 regression
(+38 snapshot)**, and not 43 and 39.

**Change on 2026-08-28: further harvesting goes into four languages.** The cases
were spread two to four per language. At such a count any "per language" number
can only be 0%, 33%, 67% or 100%, that is, the table the batches print measures
nothing: one batch gave "php 0%, ruby 0%" out of one case each.

That is why the new cases go into **`javascript/typescript`, `python`, `php` and
`go`**, each of which is already at **eight advisories**:

```
python3 -c "
import yaml,pathlib,collections
c=collections.Counter()
for m in sorted(pathlib.Path('corpus-real').glob('*/case.yml')):
    b=yaml.safe_load(m.read_text()) or {}
    if b.get('construction')=='regression': c[b.get('language')]+=1
print(sorted(c.items()))"
# [('csharp', 3), ('go', 8), ('java', 2), ('javascript', 1), ('php', 8),
#  ('python', 8), ('ruby', 3), ('rust', 3), ('typescript', 7)]
```

Care when re-reading that number: `javascript/typescript` is **one basket in the
plan, but two values of `language:` in the manifests** — 7 typescript plus 1
javascript makes 8. Every table has to say which of the two counts it uses,
otherwise the reader will count something else.

**The corpus is not four-language and is not claimed to be.** Outside the four
there remain **11 advisories in four languages** — `csharp` 3, `java` 2, `ruby`
3, `rust` 3. They stay: they are already built, some of them carry paid results,
and they go on being scored. Deleting them would throw away evidence. The
decision is **where further harvesting goes**, not what the corpus contains.

**A discrepancy that is recorded rather than smoothed over.** The denominator of
point 8 is 40 — every measurable `regression` pair, in whatever language — and
not the 32 of the four baskets. After subtracting the unusable ones the four
baskets give 30 (`python` loses two), and the other four languages give 10.
30 + 10 = 40. The two numbers do not contradict each other, but they describe
different things: **the target of point 8 is "every measurable pair", while the
four languages are a rule for harvesting.** The code is the one that is right
about the denominator, and it is not touched in order to match a plan. The plan
is the one that should have said which of the two counts it is giving — now it
says so.

A note on the same line: the comment in `tools/stage2.py` above `probe_use` still
speaks of "all 47" and "the 24 regression cases". Those are stale numbers in a
comment, not in a computation — the computation is made from the corpus and is
correct. It has been left untouched deliberately; fixing a comment is a change in
`tools/`.

Two cases dropped out because the answer travelled inside the reviewed change:
`py-mv8m-v9v6-5f94` and its twin — the fix touches `.rst`, which
`strip_comments.py` does not read, so the maintainer's prose about the fix went
into the change; and `js-w93q-cq9w-58p7` already at harvest time, for the same
reason with JSX. Replacements have been harvested for both. That is why
`javascript` is 1: the only remaining case with `language: javascript`.

The choice of the four was by yield of advisories per ecosystem, counted in
GitHub's database. That counting was done **outside** this repository and no
artifact here records it, which is why no number for it is quoted: nothing in the
tree recomputes it, and a number nobody can derive for themselves is a claim, not
a measurement. What is checkable is the result, and that is the table above.

`go` is among the four because of its **shape**, not its volume: the other three
are web languages with almost the same weakness profile, while the go cases in
the corpus are `dos` from a nil panic and from resource exhaustion. Without it
one style of code is measured, not a tool.

`javascript` and `typescript` count as one language. The language is determined
by the file extension — a property of the file, not of the review — a mixed repo
is the norm, and the agent compiles nothing: it reads with `read_file` and
`search_code`, which know nothing about types. And nobody would act differently
because of "it is weaker on `.js`".

**The price, said straight away:** `README.md` and `LIMITATIONS.md` can no longer
claim "language independent". It has been measured on nine values of `language:`,
four baskets of which have been harvested up to eight advisories, while the rest
come from earlier work — and that is what can be quoted.
Every case is a **pair** over the same lines: the dangerous version and the fixed
one. The pair passes only if the dangerous one is blocked **and** the fixed one
is not — stricter than "did it find something", because a tool that blocks
everything fails exactly as much as one that blocks nothing.

**What it measures:** discrimination over these frozen pairs; regression against
an earlier version at the same identity and settings; and whether the tool
catches the member marked dangerous without blocking its paired fix.

**What it does not measure**, and is not presented as measuring:

- usefulness to a person;
- precision or recall over ordinary changes;
- frequency-weighted behaviour;
- stability between repeated runs;
- behaviour over unfamiliar families of weakness or somebody else's structure;
- that the "safe" member has no other weakness — Hydra and SurrealDB were exactly
  that;
- anything whatsoever about a new repository.

**And most important of all: all of them out of all of them is a threshold for
acceptance, not a score for quality.** The moment a failure changes a prompt or
code and the same pairs are run again, the corpus becomes a regression suite for
development. One and the same thing cannot also be an independent evaluation.
That is why the number is not quoted as proof of anything outside the cases
themselves — and it is written as a fraction with a computed denominator, never
as a nailed-down count, because every adjudication of an unusable case moves it.

**The check for leakage runs before every run.** Once the corpus turned out to be
solvable without reading code — counting comments gave 48 out of 48. Today: 70
cases, 0 problems, and no cue inside a single member fires often enough to be
judged by. The cues visible when the two are compared give 100% — and this is
**not dismissed** with the argument that the review sees one member. A cue tied
to "safe versus dangerous" is present in the member itself too: an added check, a
changed API, the shape of a patch. It is not proof of leakage, but it weakens the
claim that success necessarily comes from following the meaning.

The adjudicated exceptions (`adjudications.yml`) are part of the frozen identity
of the corpus, not a note off to the side.

*Done when:* both members of every case that can measure anything have been run
through `--provider claude-cli` against its current version, the results are in
`measurements/`, and the decision has been preserved — the dangerous one blocks,
the safe one passes. The count is computed by `tools/stage2.py` and is not
written down here: every new adjudication of an unusable case moves it, and a
number in a plan that the code does not compute is a number that goes stale
quietly.

### 9. The fixes

Every failure gets either a commit or a line in `LIMITATIONS.md` with the reason
why it is not being fixed. There is no third position — and "the model simply did
not catch it" is a reason that gets written down, not passed over in silence.

*Done when:* the number of failures equals the number of fixes plus the number of
recorded limitations.

---

## How we track it

```
tools/stage2.py
```

It prints the table below by reading the state out of the repository — tests,
artifacts, journal — and not out of checkboxes in this file. The numbers come
from measurement, not from expectation; a file with checkboxes is a place where
judgement is made into fact.

| # | Parameter | Measure | Target |
|---|---|---|---|
| 1 | tests for the budget | pytest | green |
| 2 | canonical split | absence of telemetry in `canonical_result` | 0 fields |
| 3a | `finish_review` | tool, prompt, loop | all three |
| 3b | `submit_verdict` | tool, prompt, loop | all three |
| 3 | `ClaudeCodeRunner` | conformance over a fixed diff | matches |
| 4 | closing off the tools | a test for `CLAUDE.md` and for Bash | 2/2 |
| 5 | conformance scenarios | number passing with both runners | every one named |
| 6 | no silent fallback | a test for a failure of the CLI | exit 2, 0 API calls |
| 7 | scope | `--changed-only` and `--path`, with a test | 2/2 flags, tested |
| 8 | pairs of advisories | `tools/stage2.py` over `measurements/` | every measurable pair, the decision preserved |
| 9 | fixes | confirmed = fixed + recorded | equality |
| — | the whole suite | pytest | all green |
| — | local spend | the login from the artifacts in `measurements/` | a run on the subscription, not assumed |

The stage is done when all thirteen rows are at their target. Not earlier and not
by judgement.

The rows are thirteen because `tools/stage2.py` has thirteen checks:
`python3 tools/stage2.py` prints them all. Three rows were corrected on
2026-08-28, after a line-by-line reconciliation with `CHECKS` in the code:

- **3a and 3b were missing entirely.** The tracker measures them, the plan did
  not mention them — that is, the table looked complete while two of the checks
  were not in it.
- **7 said "time of `--changed-only` < 5 min".** `probe_scope` does not measure
  time: it looks at whether `--changed-only` and `--path` are present and whether
  `tests/test_scope.py` passes.
- **local spend said "$0.00".** `probe_spend` explicitly does not claim that —
  its docstring says the old version used to check `cost_usd` for truthiness, so
  a missing number passed for zero. Now "done" means a run whose login the CLI
  reported as a subscription.

---

## What stage 2 deliberately does not do

- **It does not make `claude-cli` an equal provider.** CI stays on the API. The
  thin runner is for the author, not for the users.
- **It does not polish.** Codex was explicit: use comes before polish. Whatever
  the pairs of advisories show is what gets polished — not what looks unfinished
  in advance.
- **It does not touch the prompts for cosmetics.** A reworded sentence cannot
  change a result, and it cancels comparability with everything measured so far.
- **It does not produce a number for recall or precision.** Both are withdrawn
  and stay withdrawn; `LIMITATIONS.md` says why.
