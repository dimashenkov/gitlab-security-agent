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
| calls | 30 processes, **30 distinct session ids**, one turn each, none retried |
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

## Where the material is

`grok-adjudication.json` holds every verdict with its session id, provider
response id, turn count, served model, cost, prompt digest and rationale. The
44.5 MB candidates file and the manifests are outside this repository, under
`~/PROJECTS/gsa-corpus-archive/`, identified by the digest recorded in the seal.
That is a second path on one machine and **not** an archive; a
failure-isolated copy is still owed.
