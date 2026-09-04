# The decisions, and why

`AUDIT.md` says what was broken. `LIMITATIONS.md` — what cannot be done. Here is
**why we chose it this way**: the part nobody remembers afterwards and
rediscovers at the wrong price.

## How an entry is written

Every entry goes through Codex before it lands. Not for approval — for
objection, and the objection is recorded. "Codex reviewed it" is not a record;
what is recorded is what it said.

The fields are not decoration. The first version of this file was rejected
outright because it had no `State` and no `Checked against` — and without them a
stale entry looks like a live rule. Codex put it this way: *without these states
the file becomes worse than missing memory — it becomes confidently stale
memory.*

    ID              D-001, never reused
    State           active | proposed | superseded | withdrawn
    Scope           which part of the system
    Decided         what
    Rejected        what not, and why not
    Reason          why
    Enforced by     a symbol or a test that makes it true
    Evidence        an artifact or a command the reader runs
    Checked against commit
    Objection       what Codex said
    Revisited when

An entry in state `proposed` is not a decision and stands apart, at the bottom.

---

## D-001 · The exit code distinguishes three things, not two

| | |
|---|---|
| **State** | active |
| **Known hole** | `AUDIT.md` blocking 9 — see Objection |
| **Scope** | `src/security_agent/gate.py`, the exit code of the process |
| **Checked against** | `b19b7bf` |

**Decided.** `0` = checked and clean. `1` = a blocking finding. `2` = it never
got to an answer.

**Rejected.** A binary "pass / fail", the way linters do it. It has nowhere to
put an interrupted run, and interrupted runs are about a fifth of what has been
measured.

**Reason.** "I could not check" and "it is clean" look identical from outside. A
crash carrying the code for "vulnerabilities found" sends a person hunting for
something that does not exist; a crash carrying `0` sends them to look for
nothing at all.

**Enforced by.** `gate.decide`; `gate._reviewed_nothing` for the run that nothing
reached. `tests/test_gate.py`.

**Evidence.** `python3 -m pytest tests/test_gate.py -q`. Six separate defects,
each one leading to `exit 0` over unreviewed code, listed in `AUDIT.md`.

**Objection (Codex, 2026-08-29).** The entry claims more than the code enforces.
The path through the Messages API accepts `end_turn` as a finished review
without the reviewer having signed off — that is, "it never got to an answer" is
not detected in that case. The hole is `AUDIT.md` blocking 9 and it is left open
deliberately: closing it needs the share of reviews that sign off, and that is
collected from the coming batches.

**Revisited when** `finished_explicitly` has been recorded for at least twenty
finished reviews. The deciding number is the share that did **not** sign off:
under 5% — we tighten, and `end_turn` without `finish_review` becomes an
incomplete run; over 20% — tightening would fail reviews that are fine, and the
prompt is changed instead. Between the two: measure more.

---

## D-002 · A finding's identity is never tied to prose

| | |
|---|---|
| **State** | active |
| **Scope** | `tools/artifact.py`, comparison between runs |
| **Checked against** | `b19b7bf` |

**Decided.** `identity(finding)` is `(category, file)`. `blocking_identities`
adds an **ordinal**, which carries a count and nothing more — that two findings
in one file are two and not one.

**Rejected.** A fingerprint of the title: it gave five different values for one
finding across five runs and broke risk acceptance — the accepted risk vanished
on the next run, because the model had reworded the sentence. Also rejected: the
lexicographically smallest quoted line — it depends on how much of the construct
the model decided to quote. And `(category, file)` on its own is rejected for
the blocking ones — it merges two different findings in one file into one.

**Reason.** The key has to depend on code that has been checked to exist, not on
the way it was described.

**Enforced by.** `tools/artifact.py:identity`, `blocking_identities`;
`tests/test_injection_corpus.py::test_two_blocking_findings_in_one_file_stay_two`
and `::test_the_ordinal_says_how_many_and_never_which_one`.

**Evidence.** `python3 -m pytest tests/test_injection_corpus.py -q`. Checked by
sabotage against both rejected implementations: with `(category, file)` two
tests fail, with the smallest anchor — two others.

**Objection (Codex, 2026-08-29).** The first version of this entry was
misleading: it said the identity is a triple everywhere. It is not — `identity`
is a pair, and the ordinal exists only in `blocking_identities`. Fixed.

**Revisited when** a finer anchor appears that survives the check: two runs of
one case give it one key, and two different findings in one file — different
ones. Measured with `tools/stability.py` over at least ten cases.

---

## D-003 · The corpus is pairs, not examples

| | |
|---|---|
| **State** | active |
| **Scope** | `corpus-real/`, `tools/pair_corpus.py` |
| **Checked against** | `b19b7bf` |

**Decided.** Every case is a real fix of a vulnerability, out of which we make
two members: with the fix and without it. Each member is reviewed separately,
without knowing about the other. What is scored is whether the two answers
differ.

**Rejected.** Hand-written examples with decoys. An audit showed that such a
corpus is solved by a rule that does not read code at all: "more comment lines
means safe" gave 48 out of 48.

**Reason.** On the unsafe member alone, "it found something" means nothing — it
may be finding something everywhere. The check is whether it will stay silent
about the fixed one.

**Enforced by.** `tools/corpus_adversary.py` (rules inside a member are caught);
`tools/check_corpus.py` (a case with an uncleaned file in the changed part is
not accepted).

**Evidence.** `python3 tools/corpus_adversary.py corpus/ corpus-real/` — today
not one rule inside a member fires often enough to judge.
`python3 tools/check_corpus.py corpus/ corpus-real/` — 105 cases, 0 problems.

**Objection (Codex, 2026-08-29).** The 48 out of 48 is historical and is not
reproduced by today's corpus — that corpus has been replaced. The number is the
reason for the decision, not the current state, and the entry has to say so. It
says so.

**Revisited when** a rule between members reaches 6 firings and over 65% correct
— the thresholds `tools/corpus_adversary.py` already uses for the rules inside a
member. Today "more imports" is 24 firings and 96%, but it is between members,
and the reviewer never sees both.

---

## D-004 · Two constructions, never added into one number

| | |
|---|---|
| **State** | active |
| **Scope** | scoring, `tools/stage2.py` |
| **Checked against** | `b19b7bf` |

**Decided.** `regression` (the fix has been removed) and `snapshot` (the code
from before the fix) are counted separately and are never summed.

**Rejected.** One combined percentage. It hides that the two do not measure the
same thing.

**Reason.** In a regression the unsafe member is code that something has been
taken out of — and that on its own is a hint, independent of the content.

**Enforced by.** `tools/harvest_pairs.py` says it in the code; `probe_use` in
`tools/stage2.py` shows the snapshots separately, down to the fraction.

**Evidence, and it refuted my expectation.** I assumed snapshot would be easier,
because there is no trace of a removal. go gave **2 out of 6** on regression
(`measurements/cli-batch-5-go.json`) and **1 out of 7** on snapshot
(`measurements/cli-batch-10-go-snap.json`). The opposite of what was predicted.

**Objection (Codex, 2026-08-29).** The recorded refutation is useful only if it
is read as an observation about one language and not as an established fact:
n=13 pairs in one language does not establish which construction is harder.
Accepted — which is why it is recorded as "it refuted my expectation" and not as
"snapshot is harder".

**Revisited when** all four languages have both constructions measured.

---

## D-005 · The proof of a review is `exposures`

| | |
|---|---|
| **State** | active |
| **Scope** | `gate.py`, `identity.py`, `report.py` |
| **Checked against** | `b19b7bf` |

**Decided.** `exposures` — `(path, channel)` for every file whose bytes reached
the model — is the only record that anything was reviewed. A run with an empty
list is not reused from the cache.

**Rejected.** A count of the calls: it proves activity, not that anything
analysable was seen. A reported finding: it proves the quote exists — a fact
about the quote.

**Reason.** A run stopped by a label or by an empty change finishes "clean" and
looks like a review. `complete` does not tell them apart, because a skip also
finishes.

**Enforced by.** `identity.reusable`; `terminal._banner` (`NOT REVIEWED` instead
of a green `PASSED`); `report.build_json` writes the list into the artifact.

**Evidence.**
`python3 -m pytest tests/test_identity.py::test_an_artifact_from_a_run_that_examined_nothing_is_never_reused tests/test_terminal.py -q`

**Objection (Codex, 2026-08-29).** The entry claimed more than is enforced:
`gate._reviewed_nothing` stops `exit 0` only when the run is **also incomplete**.
A run that finished and opened nothing — the one skipped by label — still exits
with `0`, by choice: the tool did what it was told. What is protected is the
cache and the screen, not the exit code.

**Revisited when** a skip mode is added that claims to have checked something —
today's two (label, empty change) do not claim it. Or if a run finishes with an
empty `exposures` on a non-empty change and without a skip: that is a broken MCP
server, which today would exit with `0`.

---

## D-006 · What is missing is recorded as missing, not as zero

| | |
|---|---|
| **State** | active |
| **Scope** | `models.Usage`, `tools/pair_corpus.py` |
| **Checked against** | `b19b7bf` |

**Decided.** `Usage` has three states — reported, incomplete, nothing reported —
derived from recorded events. The CLI's block is read **only if it carries all
four fields**; otherwise it is an absence, not a part.

**Rejected.** A boolean flag `reported` that the writer sets: "a check satisfied
by the shape and not by the thing" — the defect this project produces most
often. Also rejected: partial reading — the two ordinary counters without the
two for the cache understate the cost by **95%** in a real run (12k against 200k
tokens), and the understated figure reads as measured.

**Reason.** All 38 saved runs recorded five zeros, because the field was being
parsed and nobody was reading it. The project could not say what its own batch
had cost — out of its own artifacts.

**Enforced by.** `models.Usage.from_provider`, `reported`, `recorded`,
`complete`; `pair_corpus.cost_summary`.

**Evidence.** A cross-check in `measurements/cli-batch-5-go.json`: our figure
`0.528108` against `provenance.reported_cost_usd` `0.529055` for
`go-qqff-5854-px68/safe` — a 0.2% difference. Run it with:

    python3 -c "import json; b=json.load(open('measurements/cli-batch-5-go.json')); \
    m=[r for r in b if r['case_id']=='go-qqff-5854-px68'][0]['members']['safe']; \
    print(m['cost'], m['provenance']['reported_cost_usd'])"

**Objection (Codex, 2026-08-29).** The names of the four fields were read out of
the CLI's local records — data the reader of this file does not have. That is
why the evidence above is the cross-check, which reproduces from the repository,
and not the investigation. Separately: the terminal object is another document
from the same program, and that it agrees is an inference, not an observation —
which is why the reading is "all four or nothing", so that an error yields an
absence and not a number.

**Revisited when** the verifier also starts reporting its spend — today it is a
second call that returns nothing, and because of it the pair often cannot be
priced.

---

## D-007 · The refusal is measured, not predicted

| | |
|---|---|
| **State** | active |
| **Scope** | `tools/run_queue.py`, `tools/session_ledger.py` |
| **Checked against** | 3201bab |

**Decided.** The queue runs until it is refused. The refusal is recorded, the
reset hour is read out of the message itself, we sleep, we carry on. No cap and
no estimate of the remaining quota.

**Rejected.** A cap on the number of runs in a window, in three different
versions: by batch size, by notional cost, and by number of agent turns. Each
one was a number measuring something else. Also rejected: the alarm at 25 turns
— a threshold with no supported condition is noise with authority.

**Reason.** The remaining quota is not visible: there is no subcommand, nothing
is kept under `~/.claude`, and `--debug api` logs the requests, not the
responses — all three checked. The refusal, though, is observable and costs
little: the five that were measured were refused at the handshake, 12.5 seconds
and zero tokens, against 225 seconds for a finished run. A cap at a limit of
around 28 throws away a whole window to save that much.

**What exactly one refusal establishes, because this was got wrong twice.** A
refusal measures the limit **in this window, under this mixed load**. It does not
measure a constant, because it is not known that there is one: three windows
gave 25·34·26 turns, and moving their boundary made them 32·38·43 — all three
rose together, which means the number depends on the choice of where the window
ends. Weaker than "a sample of one number" and stronger than "it only bounds
it". A **cap does not follow** from it after a few windows.

**Enforced by.** `tools/run_queue.py:classify` — five states, and only a
validated refusal leads to sleeping; `raw_rows` — one row per call, the four
token counts separately, nothing summed; `tools/session_ledger.py` for the turns
of the conversation itself, which runs in another process.

**Evidence.** `python3 -m pytest tests/test_run_queue.py -q`. The conversation's
coverage is checked, not assumed: `python3
tools/session_ledger.py --since 2026-08-29 --count` gives 339 turns from this
session with a lag of about 97 seconds.

**Objection (Codex, 2026-08-29).** Eleven things in the plan are still a
snapshot presented as a rule. The most substantial: "a refusal is cheap" holds
for five handshakes and is recorded as a field so that it gets re-measured; "two
refusals answer the question of whether the window slides" — they do not, they
narrow the hypotheses, which is why point 5 records the outcome and not a
conclusion; and `unknown` does not mean "the wording has changed" — it may be a
timeout, a truncated document, a parsing defect or a local crash, which is the
reason it stops instead of guessing.

**Known and unresolved.** Nothing executes while the machine is asleep. The fix
from 2026-08-30 removes the oversleeping (`time.sleep` counts by a clock that
stops together with the machine — the queue slept 5h45 instead of 3h), but it
cannot make a sleeping computer execute code. A nightly run finishes at the hour
the lid is raised, unless something keeps the machine awake: `caffeinate -dimsu`
keeps it, an open lid on mains keeps it, a closed lid keeps nothing at all,
whatever is asked of `caffeinate`.

**Revisited when** five windows have been recorded with the raw rows from the
three sources, or when a way to see the quota appears.

**Computed and rejected, so that it is not computed again.**
`--provider anthropic-api` does not go through the CLI at all — the SDK through
`ANTHROPIC_API_KEY`, and the key is stripped from the child of
`src/security_agent/runner_claude_code.py` precisely so that the two paths are
demonstrably isolated. So there is no session window there and the remainder is
visible in the headers. The price for the rest of the corpus: **$53 at the
median, $167 at the upper end** (76 reviews × $0.703 and × $2.195, from
`provenance.reported_cost_usd`), plus the reruns. Rejected: the subscription is
paid for and reruns under it cost nothing. Recorded so that it is not
recalculated.

---

## D-008 · The end is "no failure without an outcome", not a number

| | |
|---|---|
| **State** | active |
| **Scope** | point 9 of the plan, `tools/check_accounted.py` |
| **Checked against** | 8a92d09 |

**Decided.** Measuring ends when every case has a row. Four outcomes and no
fifth: it passes, it was fixed and re-measured, it was recorded in
`LIMITATIONS.md`, or it was adjudicated invalid. The sum has to be the number of
cases. The report that says the work is done reads like this: *34 cases: 20
pass, 8 fixed and re-measured, 4 recorded as limitations, 2 adjudicated
invalid.*

**Amended 2026-09-01.** The outcome "fixed and re-measured" does not exist in the
code: `tools/check_accounted.py` has the buckets `pass`, `limitation`,
`invalid`, `not run` and `unaccounted`, and a fixed case falls into `pass`. The
decision stands as recorded; the mismatch is described in D-010 and in the
docstring of the tool itself, instead of inventing a bucket that nothing can
fill.

**Rejected.** A threshold on the fraction — "we stop at 80%". It does not say
what to do with the remaining 20% and leaves failures without a row, which is
the state that led to seventeen unaccounted failures while the fraction looked
healthy.

**Reason, and why it terminates by construction.** Two of the four outcomes take
the case out **for good**: a limitation is not re-measured, an invalid case is
not scored. So the pool can only grow if a fix breaks something else. If every
round takes out more than it puts back, the sequence ends. If it does not take
anything out — that in itself is a signal that the fixes are not working, and
grounds to stop rather than to carry on.

**The three brakes, fixed in advance.**

First, **the number of rounds is one**. A second — only after the variance has
been measured and the improvement falls outside its interval. Today the variance
on real code has not been measured at all (`LIMITATIONS.md` says so), so a
difference of two cases is indistinguishable from noise, and chasing rounds is
chasing noise. A third round — no, not without a new reason recorded **before**
the measuring.

Second, **a case is fixed at most once**. If the failure comes back after the
fix, the case is no longer a candidate for fixing — it becomes a row in
`LIMITATIONS.md`. This is the rule that literally makes the cycle finite: no
case can go round more than twice.

Third, **a clock, not a result**. If the pool is not empty after the agreed
number of windows, the rest is recorded as limitations and it stops. Time is the
constraint that does not negotiate with the number.

**Enforced by.** `tools/check_accounted.py` — it lists the four buckets, exits
with 1 while there is a case without a row, and names every one of them.

**Evidence.** `python3 tools/check_accounted.py`. Today: 82 cases, 31 pass, 1
limitation, 6 invalid, 12 not run, **32 with no explanation**.

**Objection (the owner, 2026-08-30).** My first formulation was a process, not a
stopping condition — "read the failures, fix, measure again" has no end. The end
is a state of the record, not a step in it, and the three brakes above are his,
not mine.

**Revisited when** the "no explanation" bucket is empty, or when the agreed
number of windows runs out — whichever comes first.

---

## D-009 · Variance is not measured without a fix to compare against

| | |
|---|---|
| **State** | active |
| **Scope** | measuring at the start of the next round (D-010), `tools/measure_variance.py` |
| **Checked against** | 9ae7061 |

**Decided.** The cycle stops after the first round. The variance is **not**
measured now.

**Rejected.** The design I proposed: four cases by three runs, 24 reviews, one
window. Rejected for three reasons, each of which is enough on its own. At three
runs a case is either 3-0 or 2-1 — the only resolving power is "it never
flipped" against "it flipped once", which is a coin dressed up as a measurement.
The choice of the four cases is mine, which makes them readable and for exactly
that reason not a sample. And comparing against the old result mixes the
variance with a change in the model between the two runs.

**Reason, and it is more general than the design.** The number the rule wants is
whether "+3 cases" is outside the noise. For that you need the distribution of
the difference **over the whole corpus** — at least one full rerun of the 56
pairs under frozen conditions, preferably two, interleaved in time. That is
several windows. Four convenient cases give a number that sounds like a
threshold and is not one.

And more simply: there is nothing to compare. Zero fixes were made, because no
bounded intervention with a predictable effect was found. Variance measured
without a fix is a number with nowhere to go.

**Enforced by.** `tools/check_accounted.py` — the round is closed when there is
no case without a row; today, across the five languages, there is none. Nothing
requires a second round.

**Evidence.** `python3 tools/check_accounted.py` — 40 pass, 16 limitations, 12
invalid, and the remaining five are outside the five languages.

**Objection (Codex, 2026-08-30).** Votes for stopping: *"The proposed window
creates a number, but not the number your rule wants."* It also gave a second
admissible path — six cases by two runs, called "a search for instability", not
a measurement of the noise: it may reveal a serious problem, but it cannot
establish a threshold. Not chosen, because there is no fix that would justify
it.

**The shape, if a fix ever appears.** Do not compare against today's result.
Freeze the corpus, the scorer, the adjudications and the model; interleave runs
with the old and the new prompt in random order; compare the same cases; keep a
control group with no change; judge by the direction of the flips, not by the
two totals.

**Revisited when** a concrete fix appears that somebody is willing to spend
several windows on.

---

# Proposals

They are not decisions. They stand here so that they are not rediscovered, and
they move up only when they become a measurement.

## P-003 · The user should see what the agent costs him

| | |
|---|---|
| **State** | proposed |
| **Grounds** | the owner's request, 2026-08-31 |
| **Scope** | `journal/`, the report in the merge request, `tools/journal.py` |

**Proposed.** That the review says what it cost, and that this is summed over
time, so that a person can see the spend for a month, for a repository or for a
particular change.

**What we already have.** Every run records the usage in the artifact, and
`journal/` keeps it locally. So the raw material is there and is not being
collected from scratch. What is missing is the assembling and the showing.

**What has to be decided, and it matters more than the code.** The distinction
this project has already paid to learn: `total_cost_usd` under a subscription is
a **notional** price at the API's list rates, not a bill. Three wrong rules about
the weekly limit were built on exactly that conflation. The number has to carry
who paid — otherwise we are showing the user dollars nobody took off him.

**Where it came from.** From the telemetry of `usestrix/strix`. It sends them
`llm_cost`, the input and output words, the number of requests, the duration and
whether the run was through a key or through a subscription.

The note that comes with the borrowing: **their README does not list the cost
and the words.** The "what we track" section says only "which model and whether
it is a key or a subscription". The gap between the description and the code is
exactly the defect this project hunts for in its own files, and it is a reason
to take the idea but not its form.

**For us the form is local.** A security tool that reads someone else's private
code and then phones out is one that many organisations will not allow at all.
`journal/` already records the same thing on the user's own machine; the
difference is who sees it. Sending anything out is not proposed.

**Objection (Codex).** Not looked at yet. It enters the round when it is put up
for work, not while it sits here.

**Becomes a decision when** somebody asks for the report and it is settled what
exactly it shows — notional cost, time, or both with a label saying who pays
them.

## P-002 · How many alarms it raises on code with nothing in it

| | |
|---|---|
| **State** | proposed |
| **Grounds** | a missing measurement, not an observation |
| **Scope** | a new corpus of ordinary changes; `pair_corpus.py` will not do as it is |

**Proposed.** To measure how often the agent raises an alarm on **ordinary**
changes — a rename, a new button, a fixed test — in which there is no known
vulnerability.

**Why it does not exist.** Today false alarms are measured only on the "safe"
member of a pair. That is the same file with the patch applied, that is, code
that was dangerous one line ago. Real merge requests do not look like that.

**Why it matters.** This is the number that decides whether the tool stays
switched on. A tool that finds 6 out of 10 and stays quiet on clean code is
useful. A tool that finds 9 out of 10 and shouts at every third innocent merge
request gets switched off within a week — and then it finds 0 out of 10.

**What is measured, and this is corrected after the objection.** Not "findings
per change". The headline number is **the share of changes that got at least one
blocking finding which, on reading, turns out to be unfounded**. It is reported
grouped by repository — the average repository and the noisiest one — because
the independent unit is the repository, not the change. One noisy repository can
produce every alarm and a single total hides it. "Findings per change" and the
distribution by severity stay as secondary.

**Three traps.**

Silence is not automatically right. Some of the ordinary changes really do
contain an unnoticed weakness; a finding there is a result, not a false alarm.

The reading of the findings is itself accountable and has to be guarded as such:
a rubric declared **before** the reading, with four outcomes — true and
actionable, true but out of scope, a guess with nothing behind it, and false.
Otherwise the borderline cases will be judged with the knowledge of which answer
is wanted.

The selection is declared before the collecting and is mechanical. If I pick
them, I will pick changes that look clean.

**Objection (Codex, 2026-08-31).** Five things, two of them corrections of
errors in the proposal itself.

*Error one, mine:* I claimed the number depends on `SECURITY_SCAN_FAIL_ON`. That
setting changes **what blocks**, not what the agent reports. It is frozen for the
blocking number and is irrelevant to the raw count of findings. Frozen along
with it: the model, the prompt, the diff cap and the rule for an unfinished
review.

*Error two, mine:* "30–40 unrelated changes" buy a bigger denominator and cannot
estimate precisely the thing we need — the concentration. Fewer repositories, a
few mechanically chosen changes in each, plus reruns of a small subgroup.

*And three limitations that go into the report rather than being passed over:*
public merged changes carry survivorship bias — mature open source, accepted,
publicly reviewable — and they miss private code, rejected changes and
repositories full of generated files. The result is announced as "over this
sample of public repositories", never as expected noise in production. One run
per change mixes the noise with the instability, which is why the subgroup is
repeated. And the old `measurements/` cannot answer it: their safe members were
selected around known security fixes.

*On the order:* "line it up, but do not fund it before the stability. Stability
is a precondition for interpreting the noise from a single run. After it, this
should come ahead of a new broad measurement of finding, unless that answers a
specific question that is holding up a release: finding without an estimate of
the cost of acceptance optimises a tool whose tolerable operating point is
unknown."

**Becomes a decision when** the stability has been measured, the selection rule
has been declared and somebody is willing to spend the window.

## P-001 · The adjudication is not one question, but three

| | |
|---|---|
| **State** | proposed |
| **Grounds** | n=1 |
| **Scope** | `corpus-real/adjudications.yml`, scoring |

**Proposed.** That one adjudication answer three separate things: is the finding
true, is it the point of the case, and does it separate the two members.

**Observation.** `py-p43p-whwx-q52h`: the advisory is a denial of service through
unbounded recording of a user name (CWE-400). The agent described the right line
and named it `injection` — "unescaped" instead of "unbounded". The key expects
`dos`, so it was counted as a miss.

**Why we do not count it as found.** The reader acts on the **name**. "Log
injection" gets deferred; "anybody can bring the server down without logging in"
gets fixed today. A finding that described the mechanism correctly and the
consequence wrongly has misled the reader.

**Objection (Codex, 2026-08-29).** Both are true at the same time, and that is
why the fraction is not the place to settle it: the finding localises the
mechanism correctly and misses the consequence. The proposed form — reporting
two numbers, "mechanism found" and "consequence named" — keeps both instead of
choosing. And: it does not create an inconsistency with the adjudication of the
side finding in `ts-m9mq`, because "true" and "the point" are different
questions.

**Becomes a decision when** there are at least five cases in which the mechanism
matches and the consequence does not — today there is one.


## D-010 · Re-measuring is the start of the next round, not the end of this one

| | |
|---|---|
| **State** | active |
| **Scope** | the diagram of the cycle, `CLAUDE.md`, the reports |
| **Decided by** | the owner, 2026-09-01 |
| **Checked against** | `610721a` |

**Decided.** The cycle has three stations — measuring, labelling, a fix or a row
in `LIMITATIONS.md` — and an arrow back to the measuring. "Re-measuring" is not a
fourth station: it *is* measuring, with a narrower scope, and the next round
begins with it.

**Rejected.** The four-step drawing from 2026-08-30, which ended with
"re-measure → we stop". It counts the same work twice and draws a straight line
with a stop where there is a circle.

**What it changes.** The counting, and in a direction that makes the reports
intelligible. Under the old drawing round 1 was "stopped at the third of four
steps" — unfinished. Under the new one round 1 is **finished**: it has been
through all three stations. The next round has not started, because its first
station is measuring, and that has not been run (D-009).

**Reason.** The number of rounds is the number the owner reads in order to know
where we are. A drawing in which one and the same action is now an end, now a
beginning, gives two different numbers for one and the same state — and that is
exactly what happened: "zero turns" and "one round" in one and the same
conversation, about one and the same thing.

**Enforced by.** Nothing in the code — this is a decision about the drawing and
the counting, not about behaviour. The only place that enforces it is
`CLAUDE.md`, which is read verbatim every session, and
`tools/check_decisions.py`, which keeps this entry complete. Recorded
explicitly, because a decision with no enforcer is exactly what the owner
criticised the same day: a rule that sits somewhere and does nothing.

**Evidence.** `python3 tools/check_accounted.py` — it prints the state from
which the position of the marker is determined. That the old drawing gives two
numbers for one state is visible in the conversation of 2026-09-01 itself: "zero
turns" and "one round" for round 1, depending on which drawing is read.

The exit from the round stays the one from D-008: we stop when every case has a
row, and not on a fraction.

**The boundary, explicitly.** The fix is station 3 of round N. The measuring that
confirms it is station 1 of round N+1 — and only after it does the case get the
outcome "fixed". "The round finished" does not mean "the fix is accounted for":
between the two stands one paid measurement that has not been made yet.

**Objection (Codex, 2026-09-01).** The decision is defensible on the substance,
but the diff was not internally consistent: D-009 still pointed at "step 4 of the
cycle", and the boundary between the rounds stayed ambiguous — "the round
finished after the fix" can be read as "the fix is accounted for before the
check". Both are fixed above. Codex also checked that the old four-step drawing
has not been left anywhere else in the repository.

**Revisited when** a second round actually begins and the boundary turns out not
to be where this entry puts it — that is, if the confirming measurement of a fix
has to run together with the fix, rather than as the next station.

**And one thing this entry leaves visibly unresolved.** D-008 and the docstring
of `tools/check_accounted.py` describe five outcomes, one of which is `fixed` —
there is no such bucket in the code. A successfully re-measured fix falls into
`pass` and out of the tray it is indistinguishable from a case that never
failed. It is not D-010's mistake and it is not fixed here: so far the fixes are
zero, so the bucket would be empty in every case, and inventing it with no
record of which case was fixed would be a number with no basis. Recorded so that
the report is not read as saying something it does not say.


## D-011 · We do not change the model provider over price

| | |
|---|---|
| **State** | active |
| **Scope** | the providers in `src/security_agent/config.py`, `runner_claude_code.py` |
| **Decided by** | the owner, 2026-09-01 |
| **Checked against** | `eb727e1` |

**Decided.** The agent stays on Claude through the subscription (`claude-cli`).
No OpenAI model is brought in — neither through the API nor as a `codex-cli`
provider.

**Rejected.** Both forms of the proposal: OpenAI through an API key, which
breaks the decision of 2026-08-30 anyway; and `codex exec` as a second provider,
which would go through the already-paid ChatGPT subscription.

**Reason.** The number that would be saved is not being paid. At published rates
the comparable model (GPT-5.6 Sol, $4/$20) is 20% below Opus 5 ($5/$25) — over
yesterday's run that is $25.58 → $20.46, that is **$5.12 notional**, against $0
actually paid, because we work through a subscription. The cheaper model in the
same table is not theirs at all: Sonnet 5 is $2/$10, two and a half times below
Opus and twice below Sol.

**Enforced by.** Nothing in the code — this is a decision not to build. The only
thing that enforces it is this entry and the absence of a second provider in
`config.py`.

**Evidence.** `measurements/experiment-noise-floor-2/` — 52 reviews, $25.58
notional, `provider: claude-cli`, `auth_method: claude.ai`, separately $0 paid.

**Objection (Codex, 2026-09-01).** It objects to the migration and names three
things beyond the price. First, the most serious: with Claude the runner
demonstrably strips every built-in tool and leaves only our four; `codex exec
--sandbox read-only` means "the tools are restricted", not "there are no tools",
so its own shell could bypass `read_file` and `get_diff` — and with them the
accounting of what was read. Second, of the runner's 1281 lines, 550–650 are
Claude-specific, and that is the riskier half. Third, every measured number
falls away: 82 cases and 38 passing hold for this provider and this model, and
re-measuring is $40 at the low end. Verbatim: *"A migration for these $5 of
notional savings is economically unjustified. A reasonable motive would be
demonstrably better quality, more available capacity on the subscription or a
strategic need for a second provider. Not one of them has been established
yet."*

**Revisited when** one of the three appears: the weekly quota stops collecting
the work into one subscription; measured better quality on another model; or a
need for a second provider for a reason other than price.

**Separate, and still open.** A cheaper *model* with the same provider is not
rejected by this entry. Sonnet 5 is two and a half times below Opus 5, the change
is one variable (`SECURITY_SCAN_MODEL`) and it asks for not one line of new code.
Its price is a measuring one, not an engineering one: nothing measured under
Opus holds for Sonnet, so the question is answered by running the same cases
under both models.


## D-012 · A fifth outcome: a failure that stays in the set

| | |
|---|---|
| **State** | active |
| **Scope** | `tools/check_accounted.py`, `corpus-real/adjudications.yml` |
| **Decided by** | Codex, 2026-09-02; my recommendation was overturned |
| **Checked against** | `75bf0e5` |

**Decided.** A fifth is added to D-008's four outcomes: `known_failure` — a case
whose failure is understood and recorded, and which **stays** in the set for
subsequent measurements. It is marked with `known_failure: true` in
`adjudications.yml`, alongside a row in `LIMITATIONS.md` that says what the
failure is.

**Rejected.** My recommendation: a row in `LIMITATIONS.md` and that is all.
Under D-008 a limitation takes the case out for good, and `rs-8rw6-p7m8-63jp`
measures precisely something valuable — whether a semantically false finding can
survive the verifier and stop a merge. Codex's objection, verbatim: *"this
closes the accounting by losing the most useful future test — administratively
consistent, dishonest as measurement"*.

**Reason.** D-008 merges two independent axes: "does the case have an explained
outcome" and "should it take part in a further measurement". For the four
outcomes the answers always coincided. Here they do not: the outcome is
explained, and the case has to be measured again. A bucket that cannot express
this forces the honest answer into an unsuitable place — and that is the very
thing this rule was added to prevent.

**Enforced by.** `check_accounted.known_failures()`; the branch stands
**before** `limitations`, because such a case is named in both files and the
reverse order would file it as taken out.
`tests/test_check_accounted.py::TestAFailureThatStaysInTheSet`.

**Evidence.** `python3 tools/check_accounted.py` — 82 cases: 48 pass, 1 known
failure, 18 limitations, 13 invalid, 0 not run, 2 not accepted, 0 unaccounted.

**Objection (Codex, 2026-09-02).** None — this is his proposal, and the side that
was overturned is mine. He does, however, also insist on the second point: the
same distinction is missing elsewhere too — fixed cases are merged with the
ordinarily passing ones, which DECISIONS.md already admits. Not fixed here.

**Revisited when** a second case lands in this bucket for a reason different
from this one — then it is checked whether "known failure" has not turned into a
place where unexplained work piles up.

## D-013 · The stop rule: a crude detector of catastrophe, and why not more

| | |
|---|---|
| **State** | active |
| **Scope** | `tools/stop_rule.py`, whether a configuration is abandoned |
| **Checked against** | `1e18a74` |

This entry was written on 2026-09-02 with an em dash where every other heading
uses a middle dot, so `tools/check_decisions.py` did not see it at all — its
body counted as part of D-012, and it had none of the three fields above for a
day. The rule that authorises abandoning the project, invisible to the checker
that exists to keep this file honest. Both halves fixed on 2026-09-03: the
heading here, and `unparsed_headings` in the checker, which now reports a
heading it cannot read instead of passing over it.

**Decided 2026-09-03.** The project had no outcome in which the answer is "this
does not work". Every failure became a fix or a row in `LIMITATIONS.md`, and a
project that cannot fail cannot succeed either.

The first version of this decision had a threshold for **success**. Codex
overturned it and is right: with 78 pairs such a threshold cannot be proved, and
pretending that it can is worse than not having one. What is written here is
what the data carries.

### What we measure, and what has been measured

78 pairs, the last result for each case, out of the artifacts:

```
                     raises alarm   silent
vulnerable version        61          17
fixed                     20          58
```

| measure | value | 95% CI (Wilson) |
|---|---|---|
| recall | 78% | 68–86% |
| alarm on the fix | 26% | 17–36% |

**This is a regression corpus, not proof of acceptability.** `precision`
computed from it is not precision in use: the corpus is 50/50 vulnerable and
fixed, whereas in a real pipeline the vulnerable changes are a minority. The
figure of 75% that an earlier version of this document quoted is withdrawn for
that reason.

### The catastrophic stop

One configuration is frozen — model, prompts, schema, verifier, gate, scorer,
revision. The whole corpus is run, both halves.

**The configuration is rejected if recall falls below 65% or the alarm on the
fix exceeds 40%.**

That is a drop of 13 and of 14 points. They are chosen not because they are good
thresholds, but because they are **the only ones that 78 cases see reliably**.

### What this rule cannot do, declared and not passed over in silence

* **It does not establish success.** There is no "passes" branch. Acceptance
  needs a prospective set, which does not exist.
* **It does not see a drop below 13 points.** For a drop from 78% to 73% its
  power is ≈26% — in three cases out of four a real deterioration goes
  unnoticed.
* **The thresholds were chosen after the numbers had been seen.** That is fitting
  the rule to the result, and it is not repaired by recalculating; it is
  repaired only by new cases.
* **"The alarm on the fix" is not a false-alarm rate** (established 2026-09-03).
  `artifact.is_target` compares only the category and the file — there is no
  judgement of whether the finding is true. The fixed file almost always carries
  something true from the same category, so 40% is a ceiling on "this category
  is still being reported in the fixed file". The threshold stays at 40%,
  because it is comparable between runs and because moving it now would be a
  second fitting after a number has been seen — but it is not quoted as a
  percentage of wrong findings.
* **The number depends on when the verdicts were written, and the row does not
  say which it is.** `stop_rule` reads the recorded rows; `pair_corpus` applies
  the verdicts while it scores. Today the 26% is raw — all ten cases with an
  applicable excuse stand with `alert: True`, because the verdicts were written
  after the runs. The next run gives 10 instead of 20 for the same corpus.
  `stop_rule` prints both denominators, but it judges **by the raw one only**:
  the second is built on verdicts the model wrote for itself, and a verdict must
  not produce a decision to stop. Under the second row it says how many of the
  verdicts are independent — zero.

For the claim "recall is above 70%" ≈200 independent vulnerable cases are
needed; for "I can see a drop of 5 points" — ≈450. Today there are 78. The owner
decided on 2026-09-03 that there are no weeks for building such a set, and that
is the accepted price.

### The second rule: the ordinary changes

It stays as Codex formulated it, because there 100 cases **are enough** for the
boundary that matters — and it is precisely that rule which decides whether
anybody will put up with the tool in their pipeline.

> 100 mechanically selected ordinary changes from at least 10 public
> repositories, no more than 10 from any one, chosen by a reproducible hash,
> before any result whatsoever has been seen. A change is noisy if it produces at
> least one adjudicated unfounded finding presented as actionable.
>
> With 100 changes: **up to 9 noisy — passes; 21 and more — fails; between them —
> undecided.** Separately: at least 90% finished under the limits.
>
> Once the result has been seen, **no tuning whatsoever** — not of the prompt,
> nor of the verifier, the model, the schema, the scorer or the admissibility
> rules.

An ordinary change is one that has never been vulnerable: a rename, a refactor,
a new test. It cannot be proved not to contain a weakness — which is why the
unclear ones are counted separately and enter neither the numerator nor the
denominator.

**One adjudicator, not two. Decided by the owner on 2026-09-04.** The rule as
Codex wrote it asks for two people per change, independently, so that the ones
they disagree about can be counted. There is no second person, and the
assistant cannot be it: the findings under adjudication are the assistant's own
output, and 2026-09-03 established what that produces — see the entry in
`LIMITATIONS.md` on the corpus rulings.

What this costs, stated so the number is not read as more than it is:

* **The rate of disputed changes cannot be measured.** With two adjudicators
  the disagreements are the sample's own error bar. With one there is none, and
  `unclear` carries the whole weight of "this was hard to call".
* **The thresholds keep their arithmetic and lose their footing.** 9 and 21 out
  of 100 were chosen against a boundary somebody would defend in front of a
  team. They still separate a quiet tool from a loud one; they no longer rest
  on two people having agreed where the line is.
* **It is one person's judgement of his own project.** Not a defect — the
  alternative was no measurement at all — but it belongs beside the result
  every time the result is quoted, in the same sentence.

Recorded in the adjudication file itself as `adjudicated_by: human`, and
`artifact.independence()` counts it as independent, because it is: the person
ruling did not produce the findings. That is the property the field was added
for, and it holds here in a way it does not hold for `corpus-real`.

**And with one adjudicator, 9 and 21 stop being evidence.** Codex, 2026-09-04:
one person, with no disagreement rate and no reliability audit, moves cases
between `ordinary`, `unclear` and "unfounded and actionable" — every part of
the endpoint. Calling nine or fewer a *measured* pass is not justified by that.
The cutoffs stay, as **the owner's stated acceptance rule**: the number at
which he is willing to put the tool in a pipeline. They are withdrawn as
evidential thresholds. A blind audit of even a subset, by anyone who did not
produce the findings, would be the smallest thing that changes this back.

### What the frame measures, and what it does not

**Established 2026-09-04, before any review was bought, and it is the reason
the first thirty were not paid for.**

The eligibility rules remove every ordinary change whose path or changed lines
mention parsing, request handling, filesystem paths or input validation. On the
first pool — 2129 candidates from 18 repositories — that was 1334 of the 2003
exclusions. Those are the changes most likely to make a security reviewer say
something. So the number this rule produces is:

> the alarm rate among ordinary changes **that survive the eligibility filter**

and not the alarm rate among ordinary changes in a pipeline. It measures the
rules at least as much as the reviewer. That the survivors are not trivial —
median diff 1232 bytes over two files, real fixes among them — does not repair
it; the missing stratum is exactly the high-trigger one.

The repair, built the same day: **strata, not exclusions.** The two rules label
a candidate and no longer remove it. Every eligible change carries
`stratum: sensitive | quiet` and the evidence that put it there, the sample is
drawn to a quota from each, and the two rates are reported separately and never
pooled. On the same pool this took the eligible count from 118 to 819.

**50 and 50, not 63/37.** Proportional allocation is defensible for a
pipeline-wide prevalence and weakens the quiet stratum exactly where the
comparison lives; Neyman needs variances nobody has. The quotas are justified on
their own ground — comparative precision, and neither stratum swamping the other
— and not derived from the pool's shape. A pipeline-representative figure is
computed afterwards by weighting the two rates with the frame proportions, which
the manifest records. **Never by averaging the hundred**: the sample is equal by
design and the population is not, so the unweighted mean is a prevalence for a
population that does not exist.

The frame proportions, measured on the first pool: 0.856 sensitive, 0.144 quiet.
Not 0.63/0.37 — that figure came from first-firing counts, and the full 2×2 says
otherwise: 118 neither, 26 path only, 280 change only, **395 both**. The two
rules overlap heavily, which is also why first-firing counts are not used to
describe the pool any more.

**The thresholds do not carry across.** "Up to 9 of 50" silently doubles the
tolerated rate, and "both strata must pass" invents a stricter rule nobody
justified. 9% and 21% survive as *rates* and as the owner's acceptance
boundaries.

**Everything from here to the end of this section is a requirement on a scorer
that does not exist.** Nothing computes any of it. This is written in the
future tense on purpose: the first version said "the result carries worst-case
bounds" while no result carried anything, which is the defect this file exists
to catch, committed in the file that catches it. Codex found it twice, in two
places, and once more in the generated template.

The scorer, when there is one, **must**:

* report each stratum separately, with its denominator, its `unclear` count and
  a Wilson interval, and say `undecided` when the data cannot separate the two
  boundaries;
* treat `unclear` as informative missingness rather than noise — difficult and
  borderline changes concentrate there — and mark a stratum **invalid** if
  fewer than 90% of its cases receive an `ordinary` or `not_ordinary` verdict;
* carry worst-case bounds: every unclear case counted noisy, then counted
  quiet. If those bounds straddle both boundaries the answer is undecided by
  construction;
* compute a pipeline-representative figure by weighting the two rates with
  `coverage.strata.frame_share`, and never by averaging the hundred.

`tools/ordinary_corpus.py` draws the sample and records what the sample is. It
scores nothing, and its manifest says so under `required_of_the_scorer`.

**Three kinds of rule, named apart**, because they are different claims:
*population* (a merge, a dependency bump, docs, a security fix — not the kind of
change this is about), *operability* (truncated, over a ceiling, unsupported
language — what the reviewer can process, and **not** evidence that a change is
anything), and *stratum*. The estimand is conditional on processable,
single-parent, supported changes in the chosen repositories and interval, and
the manifest says so.

Codex, 2026-09-04, on every point above.

**Facts about the frame, recorded so the next attempt does not rediscover
them.** The numbers below were read out of `pool-30repos.json` and
`manifest-100.json` directly, not taken from the report of the subagent that
produced them — Codex asked which of them had been written down on trust, and
the honest first answer was "all of them". Anything still unverified is marked
as such where it appears.

* **The first pool could not reach 100; the second can.** 18 repositories gave
  118 eligible changes, and the 10-per-repository cap capped the draw at 85.
  Measured 2026-09-04 on 29 clones: 3056 candidates, **1361 eligible**, and both
  quotas of 50 fill under the cap — 21 repositories used, 9 languages, four at
  the cap. The binding constraint is the **quiet** stratum, not the sensitive one
  and not the cap: 365 eligible against sensitive's 996. **Which remedy would
  lift a larger target is not established** — more repositories and a wider
  interval could each supply quiet changes, and this measurement says only where
  the present pool is tight.

  Frame proportions on this pool: **0.732 sensitive, 0.268 quiet** — the figure
  the weighting uses. The 0.856/0.144 above is the first pool's and is kept
  because it is what the strata decision was taken on.

  New candidates move the hash-ordered draw, so no earlier thirty is the frozen
  set. The freeze in step 1 is what fixes one.

* **Two rules worth looking at again, noticed while measuring the second pool.**
  `no_supported_source` is the largest non-population exclusion — 248 — and
  `LANGUAGE_EXTENSIONS` has no `.kt`, so `okhttp` is a Kotlin clone contributing
  156 candidates to a frame that cannot read them. And 9 candidates carry
  `record_incomplete`, a rule whose name reads as "cannot be checked"; a subagent
  reports they are empty commits, which would make them a *population* fact
  rather than an operability one — **not verified here**, and the three kinds of
  rule are named apart precisely so that difference does not blur.

  Neither acted on. Changing a rule moves the hash-ordered draw, and the freeze
  in step 1 has not happened yet — so a repair now would be a repair to something
  nobody has fixed in place.
* **One automated security signal, and a manual check on every case.** Every
  candidate comes from a local clone, which carries no upstream label at all, so
  every selected row reads `label_evidence: unavailable` — 100 of 100. Missing
  label evidence is not a filter that let something through; it is a channel that
  was never available, which is why the manifest says the absence of a label in
  such a record is not evidence there was none, and makes a human say so. The one
  automated signal that did fire is `security_signal` on commit text: 17 hits in
  3056.

  At a target of 100 the manifest's demand is therefore **100 manual
  confirmations**, and that is a cost of step 3 nothing in the tooling reduces.
  A change that fixes a vulnerability quietly, with a commit message that does
  not say so, sits in the frame as an ordinary change and would be scored as one.
* **`harvest` reads the default branch.** The population the reviewer actually
  meets is proposed changes, before merge. Nothing here establishes that
  post-merge commits have the same mix or the same propensity to draw a
  finding. Unmeasured, and a limitation of the whole approach rather than of
  this run.

### When the two do not agree

**Every failure is a failure.** The corpus fails → it is not fit for the purpose
it was written for. The ordinary changes fail → it is not fit for a pipeline,
even if the corpus passes. Either one undecided → the overall result is
undecided, not "passes".

### The order

**Rewritten 2026-09-04.** The assistant worked on the second step for an hour
without having read that the first comes first, and changed this rule four times
the same day — which the first step exists to prevent. Nothing was spent, so it
was repairable. Asked to make the order hold in future, Codex refused the
enforcement and named the reason: **the order as written could not be enforced,
because it contradicted itself in four places.** Automating it would have frozen
the contradictions rather than the order.

* "doubly adjudicate" — the decision above records one adjudicator.
* "the 22 alarms" — 20 in the latest rows, 21 counting every row ever written.
  The number did not reproduce.
* "no tuning whatsoever once the result has been seen" in the boxed rule, and a
  conditional tuning step here. Both cannot hold.
* "in parallel" for a step written as the fourth of five, which reads as
  something that waits for the third.

The steps, with what each waits for stated rather than implied by its number:

1. **Freeze** the configuration and this rule. Waits for nothing.
2. **Build and adjudicate 30 ordinary changes**, by hand, **without a single
   model call**. Waits for the freeze. One adjudicator — see above, and see
   what that costs.
3. **Extend to 100** mechanically if fewer than 5 of the 30 are `unclear`, and
   run it. Waits for step 2.
4. **Classify the alarms on the fixed member** — free, and **waiting for
   nothing**. It can be done before, during or after any of the rest.

   **Not done, and the reason is worth keeping.** On 2026-09-04 the assistant
   reported this step complete because all 20 alarming cases carry a ruling in
   `corpus-real/adjudications.yml`. Checked: 21 rulings, and **not one of them
   names a cause.** A ruling says whether the finding is *correct* — `real`,
   `not_real`, `incidental`. Step 5 asks a different question: whether the
   alarms show a broad, independently repeated **cause**. Nothing recorded
   answers it.

   So this step needs a `failure_mode` on each alarm. **That it must come from
   a vocabulary fixed in advance is the assistant's addition, on 2026-09-04, and
   no owner decision stands behind it** — step 4 as written asked for a
   classification, not a precommitted taxonomy. The argument for it: a
   vocabulary drawn up after the cases are read is drawn up to fit them, and
   step 5 then asks whether a cause *repeats*, which a category invented per
   case can always be made to answer either way. The argument against it is
   cost, and the owner may take it. One such field exists already, on a
   `not_real` ruling from 2026-08-24 — `reachability-discipline`, for a finding
   correctly described at the statement level and promoted to a security
   weakness without reading the caller. That is the shape the rest need.

   **How many alarms there are depends on which reading, and both numbers are
   real.** 20 of 78 in the raw rows; 11 of 69 once the 9 cases a ruling calls
   malformed are removed. The 9 leave the smaller denominator through
   `case_is_malformed`, which removes a whole *case*; `incidental` is a
   different thing that excuses one *finding* by its fingerprint. The two are
   not alternatives and a case can carry both — `LIMITATIONS.md` records one
   that does — so "malformed rather than incidental" would be false.

   **Classify all 20, and report the 11 beside them.** *Assistant's reasoning,
   not an owner decision, and open to being overturned:* the 9 are removed for
   being bad cases, which is a fact about the corpus and says nothing about why
   the reviewer alarmed. Dropping them would throw away nine observations of the
   thing this step is trying to see. Reporting only the 20 would hide that a
   third of them sit on cases the corpus itself rejects. Both, apart.

   Recorded because the checker had already decided it silently: it reads every
   raw row with `safe_false_positive: true`, which is the 20, while this prose
   said the choice was open. A block that is not neutral while the text calls it
   open is the same defect as a claim nothing enforces, pointed the other way.

   And the constraint that makes the vocabulary hard is already recorded above:
   every ruling is `adjudicated_by: model`, so nothing here can establish that a
   cause is *independently* repeated. Step 5's condition asks for exactly that
   word.
5. **Tune** only if the ordinary changes are close to the boundary **and** the
   classified alarms show a broad, independently repeated cause. Waits for 3
   and 4.

**Step 5, closed by the owner on 2026-09-04: B, and on changes never scored
before.** How it was reached is kept, because the assistant got it wrong twice
first and the shape of the error recurs.

The boxed rule says "no tuning whatsoever once the result has been seen"; step 5
says tune under two conditions. Both are in this decision and they cannot both
hold. The assistant tried to close it twice the same day, and Codex refused
both. The first attempt declared that step 5 means the *next* configuration may
differ — a new decision dressed as a reading. The second attempt wrote the
question down, but with the first option already deleted: it asked *which kind*
of iteration is allowed, having assumed some kind is. Both times the
reconciliation was the assistant's, and both times it read as if D-013 had made
it.

Put whole, the fork was:

> **A.** The boxed rule governs. Step 5 is deleted — once a result has been
> seen, this configuration is not tuned, and neither is a successor derived from
> what the result showed.
>
> **B.** Step 5 is a deliberate exception to the boxed rule. Tuning is permitted
> when its two conditions hold, and the boxed rule means only that the result
> already obtained is not revised.
>
> **C.** Something between them, which the owner states.
>
> And if B or C: does the next measurement need changes that have never been
> scored, or may the same hundred be re-scored?

**The answer: B, and the next measurement is on changes that have never been
scored.** Chosen by the owner on 2026-09-04. He was asked the fork whole and
answered it; the assistant's recommendation was given first, and named as a
recommendation, and it was the same.

**The two paragraphs below are the assistant's reasoning, accepted by the owner,
not his stated reasons.** He answered "whichever is more correct" and did not
give grounds. The distinction matters: a reader must not later quote a
justification the owner never made.

For B over A: A makes the whole exercise a single shot. Measure once, see that
something is wrong, and there is no permitted way to correct it — the project
stops at its first result whatever the result says. A rule under which a project
cannot improve is not caution, it is an ending.

For *unseen changes*: the hundred that produced a result have been read.
Re-scoring them after a change is the thing the boxed rule exists to prevent —
adjusting until the number is agreeable, which any set can be made to yield if it
is scored enough times.

**The cost, corrected.** The first draft of this paragraph said the pool's 1361
eligible changes carry "roughly thirteen rounds", from 1361 ÷ 100. That is the
wrong arithmetic and Codex caught it: the draw needs **50 quiet** per round and
the pool holds **365** quiet, so the ceiling is ⌊365 ÷ 50⌋ = **7 rounds**, before
the ten-per-repository cap takes any more off. The binding stratum is the one
this same section identifies as binding, and the undifferentiated total ignored
it.

**Seven is a ceiling, not a supply.** Nothing establishes that seven disjoint
rounds can actually be drawn — the per-repository cap and the hash-ordered draw
both cut into it, and neither has been measured across successive generations.
The only claim is that more than seven is impossible from this pool.

**This amends the boxed rule; it does not narrow it.** B is an express exception
to a categorically worded prohibition, and the ban on re-scoring comes from the
owner's separate answer about unseen changes, not from the box. The rule that now
governs is: **a result already obtained is never revised, and the changes behind
it are never scored again.** Calling that what the old rule "keeps" would hide a
replacement inside a clarification — the move this file has caught four times
today.

**What this obliges, and it is not free.** A measurement now has an identity, and
so does the configuration that produced it. Without both recorded there is no way
to tell a fresh draw from a re-reading, and the decision above becomes a claim
nothing enforces — which is the defect this file exists to catch. Each generation
records the digest of its frozen configuration, the case ids it scored, and the
assertion that those ids appear in no earlier generation. A draw overlapping any
earlier generation is refused, not warned about.

**None of that is built, and until it is, no measurement is permitted.** Codex,
2026-09-04: the sentence above reads as a control, `on_overlap: refuse` in the
block reads as a control, and `check_generations` reads no ledger and compares
no ids — it returns "cannot tell", every time. So the tool does not select
between a fresh draw and a re-reading; it denies spending outright, and it is
the only thing standing between the decision and the defect the decision names.

That is the honest position and it is written here so nobody reads the paragraph
above as machinery. The requirement was not weakened to fit what exists: the
consequence of an unbuilt ledger is that the paid step does not run, not that it
runs unchecked.

The Sonnet gate goes after all of this: it measures the measuring machine, and
the project's question is a different one.

The same order, in a form a program can read. The prose above is authoritative;
this block exists so a checker does not have to parse English, and a test
requires the two to change together.

A prerequisite graph alone was not enough, and Codex said why: it made
`extend_to_100` unconditional while the prose guards it, and it had no way to say
"this step is stopped because a decision is missing" as against "this step is
waiting for the one before it". Those are different answers and a checker that
merges them lies. So each step also carries what stops it, and every stop names
its kind:

* `guard` — a condition in the prose, with the field that decides it. It says
  when the step runs. **It does not say what happens when the condition fails**,
  because the prose does not, and inventing an answer here was the second thing
  Codex caught: "extend if fewer than 5" is not the same sentence as "5 or more
  makes this undecided". A checker meeting a failed guard reports the guard
  failed and stops. It does not choose between skip, fail and undecided.
* `blocked_on_owner` — a question in this file that nobody has answered. Not a
  prerequisite: no work clears it, only an answer, and the answer is the owner's
  alone. A step in this state is never *ready* and never *done*.
* `undefined_predicates` — words in the prose no program can evaluate. A step
  carrying any of these can be reported *not started*, never *done*.

```yaml
# d013-order
open_questions:
  - id: guard_failure_of_extend_to_100
    asked_of: owner
    text: >-
      what happens when 5 or more of the 30 are unclear; the prose says only
      when the step runs
answered_questions:
  - id: step5_fork
    answered_by: owner
    answered_on: 2026-09-04
    text: >-
      step 5 is an exception to the boxed rule, and the next measurement is on
      changes that have never been scored
generations:
  disjoint: required
  records: [configuration_digest, case_ids]
  on_overlap: refuse
steps:
  - id: freeze
    requires: []
    requires_no_open_questions: true
    done_when: >-
      a freeze record exists, an owner has acknowledged it, and every digest in
      it still matches what is on disk, including the digest of D-013 itself
  - id: adjudicate_30
    requires: [freeze]
    done_when: >-
      the manifest and the adjudication file cover the same sample, the cases
      carry a verdict of ordinary / not_ordinary / unclear, and every one is
      adjudicated_by human
  - id: extend_to_100
    requires: [adjudicate_30]
    guard: fewer than 5 of the 30 are unclear
    guard_field: unclear_count
    guard_below: 5
    guard_failure_blocked_on: guard_failure_of_extend_to_100
    done_when: >-
      the manifest and the adjudication file cover the same sample, the cases
      carry a verdict of ordinary / not_ordinary / unclear, and every one is
      adjudicated_by human
  - id: classify_alarms
    requires: []
    needs_field: failure_mode
    done_when: every alarm carries a non-empty failure_mode
  - id: tune
    requires: [extend_to_100, classify_alarms]
    undefined_predicates: [close to the boundary, broad, independently repeated]
    next_generation: required
    done_when: undefined
  - id: sonnet_gate
    requires: [extend_to_100, classify_alarms]
    done_when: undefined
```

**The Sonnet gate does not wait for `tune`.** An earlier draft had it wait for
`tune` to be "resolved", which deadlocks: `tune` carries predicates no program
can evaluate, so it can never be reported done, and the gate would wait forever
on a step that cannot finish. Codex found it. Both waited on the owner's answer;
that answer has been given, and neither is blocked on a question any more.

`tune` still cannot be reported *done* — `next_generation: required` means what
follows it is a fresh measurement, and its three predicates remain words no
program evaluates. A checker reports it not started, and says which predicates
stopped it.

**`done_when` says what records that a step finished.** Codex, third round:
`requires` expresses order, and nothing said what makes a step *done*. Without
that, the claim "a checker cannot report false readiness" was itself unenforced —
`sonnet_gate` would have gone ready the moment two flags were asserted, with no
artifact behind either.

A step whose `done_when` is `undefined` is **never reported done and never
satisfies another step's `requires`**; the checker names it and exits 2.

**The first version put `undefined` on five of six, and that was worse than the
hole it filled.** Codex, fourth round: with `freeze` undefined, nothing could
ever satisfy `adjudicate_30`, so the whole order became unreachable — a permanent
prohibition wearing the clothes of "cannot tell", under which even completed
artifacts would stay invisible. Four steps now carry a real condition. Two remain
`undefined`, and honestly: `tune`, whose predicates are words no program
evaluates, and `sonnet_gate`, which has no artifact at all —
`tools/sentinel_compare.py` prints a verdict and stores nothing.

**`requires_no_open_questions` on the freeze, because the freeze digests this
file.** Step 1 waits for no other step, so the tool named it first — and
freezing while D-013 still carries an unanswered question produces a record that
breaks the moment the question is answered, since answering it edits the text
whose digest was frozen. Not a hypothetical: the guard-failure question is open
today, and a freeze taken now would have been invalid by the owner's next
sentence.

The stop is reported as an unanswered question, which is the state it is —
not as a missing prerequisite, and not as a failed guard.

**`adjudicate_30` reports `done` on something self-reported, and that is as far
as it can go.** Step 2 says the thirty are built and adjudicated "without a
single model call". The criterion checks that every case records
`adjudicated_by: human` — which a model-assisted adjudication would also record,
if whoever wrote it said so. Nothing in any artifact can establish that no model
was consulted, and nothing here pretends otherwise: `done` on this step means
*the records claim a human*, not *no model was used*. Codex, 2026-09-04.

The check is kept because the absent case is the one that slips: a case with no
`adjudicated_by` at all is not "adjudicated by a human", and requiring the field
catches that. What it cannot do is catch a false claim, and a reader must not
take an unlocked `spend` as evidence the corpus was built by hand.

**The block does not require a vocabulary, and that is deliberate.** It did for
one round, with `needs_vocabulary_first: true` and an empty `vocabulary:` list,
and Codex struck it out: the precommitted vocabulary is the assistant's addition
with no owner decision behind it, so an empty list made step 4 *impossible*
rather than unfinished — a rule nobody agreed to, enforced by a program, and
flatly against "encoded only once it was decided" two paragraphs down. The
tests asserted the implementation faithfully and the decision not at all.

So the machinery stays and the requirement does not. `vocabulary:` and
`needs_vocabulary_first:` remain fields this tool acts on — a step carrying them
has its values checked against the declared list, and a value outside it is
refused. No step carries them today.

**The question for the owner, and it is cheap:** should the permitted
`failure_mode` values be fixed *before* the 20 alarms are classified? The
argument for: a vocabulary drawn up afterwards is drawn up to fit, and step 5
then asks whether a cause *repeats*, which a category invented per case can be
made to answer either way. The argument against: it is extra work before any
classifying starts. If yes, the list goes in the block — and because the block
sits inside the D-013 text the freeze digests, "fixed beforehand" stops being a
promise and becomes something an artifact settles.

**What the gate on spending asks for, and why it is not the freeze alone.** The
first version let a paid run through the moment a freeze existed, while step 2 —
which D-013 requires to happen "without a single model call" — was still not
done, and a test asserted that behaviour. Spending now requires `adjudicate_30`
done (and through it the freeze), a generations ledger, and that the guard on
`extend_to_100` has not failed. Not `extend_to_100` itself: that step is done
only once a hundred cases are adjudicated, which is after the run it would be
gating, so requiring it would forbid the work rather than order it.

**Three requirements on any checker built from this block**, and they are the
reason the block exists rather than decoration on it:

* **A field it does not understand is a refusal, not a shrug.** The first
  implementation kept `id` and `requires` and silently dropped everything else,
  which would have reported `tune` as ready — exactly the false readiness the
  prose above forbids. An unknown key, or a known key it cannot act on, exits 2.
* **The three stopped states are reported apart**: waiting for a prerequisite,
  stopped by a failed guard, stopped on an unanswered question. Merging any two
  of them answers a question nobody asked.
* **`done_when: undefined` is not "not done".** It is "this cannot be
  determined", which is the third answer this project keeps having to add back.
  It exits 2, not 1.

**Encoded only once it was decided.** Generation identity — which configuration
produced which result, and which changes it had already seen — was deliberately
left out while the fork was open, because inventing a field for it would have
fixed a shape for a decision nobody had made. The owner's answer requires it, so
`generations:` now exists. **No generation record has been written yet**, and a
checker reports that as not started rather than as a missing file it should
create.

**The block declares the property; it does not yet enforce it.** Codex listed
six ways a draw could satisfy every word of it and still be a re-reading, and
each is a separate piece of work:

* whether a `case_id` names the underlying change or a row that can be
  regenerated with a new id — a fresh id on an old change passes as unseen;
* whether two aliases of one commit compare equal;
* what the configuration digest covers: the code only, or the prompts, the model
  and the thresholds too — a digest omitting prompts calls a retuned reviewer
  the same configuration;
* who creates a generation record, and where it is authoritative;
* when overlap is checked, and whether recording, checking and drawing are one
  operation or three;
* which generation belongs to which result.

Named so the gap is visible. None is filled by guessing, and until they are
filled `generations:` is a requirement a checker can read and not one it can
enforce — which is the exact defect this file exists to catch, so it is written
down as a gap rather than left to look like a control.

### The fields the schema asks for

Written on 2026-09-03, when the heading was fixed and the checker saw this entry
for the first time. Not new decisions — the text above already carried them, but
under `###` headings the checker cannot read.

**Rejected.** A threshold for success. The first draft had one; Codex overturned
it and was right — 78 pairs cannot carry it, and a rule that says "passes" would
be quoted as acceptance evidence by every later reader. Also rejected: a single
combined score over both halves, which hides which of the two failed; and
`precision` computed from this corpus, which is 50/50 by construction and says
nothing about a pipeline where the vulnerable changes are a minority.

**Reason.** A project that cannot fail cannot succeed either. Every failure so
far became a fix or a row in `LIMITATIONS.md`, and that is not a record of
quality — it is a record of a project with no way to lose. What this rule buys
is narrow and real: a catastrophe, of at least 13 points, is now something the
artifacts refuse rather than something somebody has to notice.

**Enforced by.** `tools/stop_rule.py` — `RECALL_FLOOR`, `PATCHED_ALERT_CEILING`,
`verdict`, which has `stop` / `no catastrophe` / `cannot say` and no `pass`
branch; `render_without_verdict`, which prints the second denominator without an
answer. `tests/test_stop_rule.py`.

**Evidence.** `python3 tools/stop_rule.py` — today 61/78 recall and 20/78 on the
fixed half, verdict `no catastrophe`, exit 0.
`PYTHONPATH=src python3 -m pytest tests/test_stop_rule.py -q` — 35 tests,
including `TestTheVerdictHasNoPassBranch`, which fails if a `pass` branch is
ever added. (Written as 30 first, from counting the functions and not the
parametrised cases. Codex caught it. Nothing in `check_decisions.py` reads a
number inside an evidence line, so a figure quoted there is a claim like any
other prose — which is why this one is now the output of the command beside
it.)

**Objection (Codex, 2026-09-03).** Five rounds at the commit gate, and the two
that changed this decision: `stop_rule` removed the cases a ruling had dropped
and could return `stop` on the remainder — computing a threshold through
verdicts that `LIMITATIONS.md`, two files away, forbids computing rates through.
It now answers from the raw denominator only. Then the repair for that was worse
than the defect: a broken rulings file turned a valid `stop` into `cannot say`,
hiding a catastrophe behind "the check did not finish". The verdict now stands
whatever happens to the rulings.

**Revisited when** the ordinary-change corpus has been adjudicated — the second
rule above is the one that decides whether anybody will tolerate the tool, and
100 cases are enough for it where 78 are not enough for this one. Also revisited
if any ruling in `corpus-real/adjudications.yml` is ever made by somebody who
did not produce the findings: `artifact.independence()` counts them and the
count is zero, and the 40% ceiling was set against a number nobody independent
has looked at.
