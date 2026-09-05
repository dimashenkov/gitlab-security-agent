# The thirty ordinary changes, adjudicated 2026-09-04

The result of D-013 step 2, and it does not live in D-013. That file is the
protocol being tested; it cannot also be its own results log, and writing this
into it broke the freeze within a minute — the rule the run is measured against
would have become a rule edited after the run. Codex ruled it out on
2026-09-04, and this file is where the ruling put it.

Frozen configuration: `freeze.json`, ten inputs, commit `b67bd18`, acknowledged
by the owner. Sample: `sample-30.seal.json`, thirty changes drawn from 1361
eligible across 21 repositories. Raw record: `grok-adjudication.json`.

## What was done

One `grok -p` per case: a new process, single-turn, no session, order shuffled
from a recorded seed, and the prompt carrying the rubric and the diff and
nothing else — not the stratum, which is the label the sampling rules already
applied, and not the case id, which encodes the language.

| | |
|---|---|
| adjudicator | Grok, `grok-4.6` requested, **`grok-4.6-build` answered** all thirty |
| CLI | `grok 1.0.13 (5e9a58528b76)` |
| calls | 30 processes, **30 distinct session ids**, none retried |
| internal work | one turn each — *operational metadata, not evidence of anything* |
| failures | 0 |
| cost | **$0.1921**, on the owner's SuperGrok subscription |
| wall time | 701 seconds |

## What came back

| Verdict | Count |
|---|---|
| `ordinary` | 27 |
| `not_ordinary` | 3 |
| `unclear` | **0** |
| no verdict | 0 |

## The finding is not the verdicts. It is the three.

The sample was meant to hold *ordinary* changes — D-013's frozen definition is a
change that has never been vulnerable. Three of the thirty are security fixes:

| Case | What it actually is |
|---|---|
| `ord-js-0b2b2df3` · lodash `fromPairs` | prototype pollution: `result[pair[0]] = pair[1]` lets `__proto__` through |
| `ord-php-00d8cc16` · guzzle `SetCookie` | IP cookie domains matched subdomains; a GHSA entry |
| `ord-rb-04af7b02` · rack `Rack::Directory` | unescaped regex interpolation disclosing the filesystem root; a CVE |

**At least ten per cent of this pilot sample is contaminated.** *At least*,
because the other 27 were never audited: further security fixes may sit among
them and nothing here would have found them. And *of this sample*, not of the
frame — that is a different claim needing a different measurement, and it is not
made here.

The reason is already written into D-013 and is now measured rather than
predicted: the only automated security filter reads commit text, and the lodash
commit is titled `refactor(fromPairs): use baseAssignValue for consistent
assignment`, with no security wording anywhere in it. `security_signal` could not
have caught it. Neither could a label channel: all thirty carry
`label_evidence: unavailable`, because they come from local clones.

That the assistant could check these three — from the commit, the changed files
and the advisory — is also the only evidence that Grok read the code rather than
the subject line. A shallow reading would have called the lodash commit
`ordinary`; its title says `refactor`.

## What this does to the number

An alarm the reviewer raises on one of those three is **correct**, and the
metric would have scored it as noise on an ordinary change. So an
ordinary-change false-alarm rate cannot be computed over all thirty.

What to do instead — exclude the three as a population rule, replace them by a
predeclared mechanism, invalidate the sample, or report a different estimand —
is **not decided here**. It is a prospective protocol decision and the owner's
to make; a scorer only implements a rule that has been chosen. Saying it
"belongs to the scorer" would hand policy to machinery that does not exist, and
choosing now would be choosing after seeing the outcome.

## Step 2 is not complete

The frozen protocol required the owner to adjudicate **6 of the 30 blind** —
three per stratum, chosen by hash in advance — with any
`ordinary`/`not_ordinary` disagreement invalidating model-only adjudication.

He declined, on 2026-09-04: *"не искам аз нищо да проверявам, и не смятам, че е
нужно при 3 AI агента."*

Declining does not amend a completed round. So:

* the artifact may truthfully say **thirty third-vendor model verdicts,
  unaudited**;
* **step 2 is not complete under the frozen rule**, and step 3 is not authorised
  merely because the `unclear` guard passes numerically. The audit condition is
  checked before the guard becomes operative;
* the freeze is **not** retaken for this round. A new freeze now would make these
  thirty appear governed by a rule adopted after they were seen.

**Three agents are not three checks of this number.** Codex wrote the rules being
applied. The assistant is the reviewer these verdicts will be used to score.
Grok is the only one that adjudicated — so on the 27 `ordinary` verdicts there
is one vote, not three. A count nobody audited does not become a confirmed count
by naming the parties who were nearby.

The 27 `ordinary` verdicts remain unchecked: **no permitted independent audit
has looked at them.** The owner is available and declined; the assistant cannot
stand in, because the question there is whether something is *absent* and its
own model is the one this key would score.

## A correction to how these were checked

**Written 2026-09-05, after the fact, because the tool that produced these
verdicts checked one thing while claiming another.**

The frozen protocol said "single-turn", and the tool read that as
`num_turns == 1`, refusing any reply that reported more — with the stated
reason that more than one turn meant the context was not fresh. That reason was
the assistant's inference and it is wrong. `num_turns` counts the model's own
steps inside one invocation. It says nothing about whether a previous case
carried over.

Three properties were being conflated, and only two of them bear on
contamination:

| Property | What shows it |
|---|---|
| a fresh invocation | a new process, no `--resume`, no `--session-id` |
| separation between calls | **no identifier reuse was observed** |
| how much internal work | `num_turns`, cost, duration — a resource signal |

The middle row is deliberately weaker than "a fresh provider context". A
distinct id the provider reports is *separation evidence*; it is not proof of
what the provider held on its own side.

What was missing is the one that matters: **reuse of an identifier across
cases** was recorded as a boolean and nothing acted on it. It is a refusal now.
And a runaway turn count is refused as a *resource* failure, under its own
name, never as a stale context.

**What this does to the thirty.** They remain **thirty model adjudications
with recorded separation evidence** — thirty processes, no identifier reuse
observed. They were never thirty independently established judgements, and the
distinction matters when the number is quoted. What does not stand at all is
"one turn each" as evidence of freshness: it says only that those calls
finished cheaply, and it has moved out of the evidence table into operational
metadata.

Recorded as a correction of an ambiguous term in the frozen protocol, not as a
claim that the check always meant this. Codex, 2026-09-05, on being asked
whether the rule was sound.

### Six further checks, and what they do to this result — nothing

The same review found six more ways the tool could accept an answer whose
evidence was absent rather than checked. All six were fixed. Each was then run
against **this** artifact rather than assumed harmless, and the result does not
move:

| The check now made | What this run holds |
|---|---|
| `stopReason` must be `end_turn` | `end_turn` on all thirty |
| the diff must **say** it was captured whole | `diff_truncated: false` on all thirty, explicitly |
| the candidates file must match the seal's digest | unchanged; the seal and the pool are the ones recorded |
| distinctness read over **every attempt**, not only accepted ones | all thirty produced a verdict, so the two populations are the same thirty |
| every call must carry an id for the claim to cover the run | thirty ids present, thirty distinct |
| `--limit 0` must ask nothing rather than everything | not used on this run |

The artifact predates the fields `calls_made`, `sessions_compared`,
`responses_compared` and `every_call_compared`, so it does not carry them.
Recomputed from the cases it does carry: thirty attempts, thirty session ids
and thirty response ids present, distinct on both. The checks tighten the tool
for the next run; they do not revise this one.

## Where the material is

`grok-adjudication.json` holds every verdict with its session id, provider
response id, turn count, served model, cost, prompt digest and rationale. The
44.5 MB candidates file and the manifests are outside this repository, under
`~/PROJECTS/gsa-corpus-archive/`, identified by the digest recorded in the seal.
That is a second path on one machine and **not** an archive; a
failure-isolated copy is still owed.
