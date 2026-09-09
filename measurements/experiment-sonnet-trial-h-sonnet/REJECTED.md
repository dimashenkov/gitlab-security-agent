# Rejected. No unit of this is recorded as run, and none may be.

Frozen on 2026-09-08 and superseded within the hour. No `ledger.jsonl` and no
results, so nothing here records a purchase — which is as far as the evidence
goes.

**Why.** Its order gave one arm a block of consecutive units the interleave
was supposed to prevent. The generator shuffled without a balance invariant
and only enforced `a` before `b`, so the longest single-arm run came out at 5,
7, 8 and finally 11 of 52 across four schedules — the last is 21% of the trial
on one arm in a single window, and Codex ruled it unacceptable on 2026-09-08.

`MAX_SAME_ARM_RUN` is built into the generator now and checked again when a
schedule is read, so a hand-edited file cannot walk past it.

**What replaces it:** `experiment-sonnet-trial-i-opus/`,
`experiment-sonnet-trial-i-sonnet/`, schedule `6d8e85f2a36805fe`, driver
digest `29a592a9f41d2b91`, longest same-arm run 3.

Untracked, and left on disk only because this session's guard refuses `rm -r`
and `mv`. Delete the directory; nothing references it.
