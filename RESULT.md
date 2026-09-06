# What this prototype does, and what it was measured at

One page, and every number in it comes from an artifact on disk rather than
from a recollection. Where a number cannot be given, that is said instead.

The goal was set by the owner on 2026-09-06: *a working prototype against
golden data with an acceptable success rate, then stop.* This is the report
against that goal.

## The short version

| | |
|---|---|
| what it is | an autonomous reviewer that reads a code change, follows the code until it understands it, and reports what it finds |
| measured with | reviewer: `claude-opus-5` **requested and served**, no substitution, on a Claude subscription. Verifier: `claude-opus-5` requested; which model *served* it is **not recorded** — no row anywhere carries `models_verified`, the same gap that retires the Sonnet baseline below |
| golden data | 78 matched pairs — the same code with and without one security-relevant construct |
| finds the weakness | **78%** of vulnerable versions · 95% CI 68–86% |
| alarms on the patched twin | **26%** · 95% CI 17–36% · **not** a false-alarm rate |
| blocks an ordinary change | observed blocks in this 27-case pilot: **0**; 95% upper bound **12%** — not "it never blocks" |
| mentions anything on an ordinary change | **1 of 27** · 4% · 95% CI 1–18% |
| gives the same answer twice | **11 of 13.** Two cases flipped with nothing changed — **15% instability** |
| what the measurement cost | **$0.** $8.02 of API list price on a subscription, charged to nobody |
| Sonnet | **never run.** 0 records anywhere under `measurements/` |

## The golden data, and why it is not gameable

Each case is two versions of one file differing by exactly one thing: a
positional placeholder against string interpolation, `exec.Command` with
separate arguments against `/bin/sh -c`, JSX text interpolation against
`dangerouslySetInnerHTML`. Framework, structure, surrounding code and diff size
are held constant. A pair passes only when the vulnerable member produces the
expected finding **and** the fixed member does not, so flagging everything
fails as surely as flagging nothing.

Most cases are harvested rather than written: `tools/harvest_pairs.py` builds a
pair from the fix commit a published advisory names, so the ground truth is the
maintainers' own and the code is someone else's.

**It was gameable once, and is not now.** An earlier corpus could be scored
48 out of 48 by counting comment lines — the vulnerable member simply had more
of them. `tools/corpus_adversary.py` is the permanent check, and today:

```
Within-member cues — the reviewer reads these, so they are gated on
  more comment lines            0 fires      0 correct        0%
```

No rule the reviewer can see fires at all. Between-member cues remain — the
vulnerable member is usually longer — but no review is ever shown both members,
so nothing can use them.

## What 78% means, and what it does not

61 of 78 vulnerable versions raised an alarm. Three things travel with that
number and are not footnotes:

* **The sample is small.** ±9 points. For the claim *"recall is above 70%"*
  about 200 independent vulnerable cases are needed; for *"I can see a five
  point drop"*, about 450. There are 78, and the owner decided on 2026-09-03
  that there are no weeks for building more.
* **The task is narrow.** It measures discrimination between a vulnerable file
  and its patched twin — not "finds vulnerabilities in code".
* **The thresholds were set after the numbers were seen.** D-013 rejects a
  configuration below 65% recall or above 40% on the fix. Those are the only
  movements 78 cases detect reliably, and choosing them afterwards is fitting a
  rule to a result. It is repaired by new cases, not by recalculating.

## What 26% is not

It is the fraction of **fixed** files where the reviewer reported a finding of
the same category in the same file. There is no judgement of whether that
finding is true, and a patched file almost always still contains the function
under discussion. So it is a ceiling on "this category is still being mentioned
in the fixed file", on the hardest negative that exists — not a false-alarm
rate on ordinary work.

A softer number exists and is not used: filtering through the project's own
adjudications gives 1 of 69 instead of 20 of 78. Those adjudications were
written by the same model whose output they judge. **26% stands** precisely
because it is free of the reviewer's opinion about itself.

## The noise on ordinary changes

The number 26% cannot answer, and the one that decides whether anybody keeps
the tool switched on. Thirty changes were drawn from 1361 eligible across 21
public repositories and sealed; Grok adjudicated all thirty and ruled three of
them **security fixes**, so an alarm on those would be correct and they are
excluded. D-014 fixed that rule *before* the reviewer was run.

Measured over the remaining 27 on 2026-09-06, all 27 completing:

```
  blocked the change                0 of 27      0%   95% CI 0–12%
  reported at least one finding     1 of 27      4%   95% CI 1–18%
```

Two figures, reported apart and never added: **blocked** stops a merge;
**reported** is something a person still has to read. Nothing was blocked. One
change of twenty-seven drew a single finding that did not block.

**Zero of 27 is not zero.** With 27 cases the interval reaches 12%, so the
honest reading is *"the blocking rate is somewhere below about one change in
eight, and this sample saw none"* — not *"it never blocks"*. The same arithmetic
that makes 78% recall uncertain by ±9 points makes this bound wide.

It may be called *the observed reviewer alarm rate on the 27 changes Grok
classified as ordinary in the sealed pilot sample*. It may not be called a
false-alarm rate, a figure over all thirty, an estimate for the 1361-change
frame, or human-audited: the 27 carry one unaudited third-party-model
adjudication, so further security fixes may remain among them.

## The same input, twice

The reviewer is not deterministic, and this is measured rather than assumed.
`measurements/experiment-noise-floor-2/` holds two passes over the same cases,
same code, same prompts, same model:

| | |
|---|---|
| cases run twice | 13 |
| gave a **different** answer | **2** |

`go-m6jg-wr9m-cg2f` found the weakness on the first pass and not the second;
`rb-g65v-27r3-5p6m` did the opposite. Nothing changed between them.

This is why 78% is written as 68–86% and not as a point, why the stop rule
refuses to judge on one run, and why any single review of a real merge request
should be read as one draw rather than as the answer. `tools/stability.py`
repeats one case N times when that question comes up again; 13 cases seeing 2
flips is a thin sample and puts the instability somewhere around 15%, not
exactly there.

## What has not been measured at all

| | |
|---|---|
| **Sonnet, or any cheaper model** | never run. The sentinel baseline is retired — no row anywhere carries `models_verified`, so it cannot separate the model that reviewed from the model that verified |
| a false-positive rate on ordinary code | the 27 above are a pilot, not an estimate for the frame |
| behaviour on untrusted contributions | out of scope, and `LIMITATIONS.md` says why |
| anything a person independently checked | every adjudication in this repository was written by a model |

## Where the numbers live

| Question | Command |
|---|---|
| every case accounted for | `tools/check_accounted.py` |
| the stages | `tools/stage2.py --tests` |
| is the corpus gameable | `tools/corpus_adversary.py corpus-real` |
| does the set move on its own | `tools/measure_variance.py` |
| the noise on ordinary changes | `tools/ordinary_noise.py score --results measurements/ordinary-noise` |
| what it has cost | `tools/spend.py` |

`LIMITATIONS.md` is longer than this file and is written to help you decide
against using it. Read it before you do.
