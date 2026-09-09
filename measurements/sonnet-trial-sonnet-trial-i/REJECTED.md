# Rejected. No unit of this is recorded as run, and none may be.

Frozen on 2026-09-08 and superseded the same day. No `ledger.jsonl` and no
results, so nothing here records a purchase — which is as far as the evidence
goes.

**Why.** `load_schedule` checked what each unit is and never checked that the
units together are the experiment: a file with one dropped, one repeated, one
renamed, or an empty list passed, and the runner would have finished a shorter
or a different trial and reported it as the committed 52. The repair compares
the units against the Cartesian product of the schedule's own cases, arms and
passes — and it changed `sonnet_trial.py`, which is inside the driver digest.

Codex, thirteenth gate round, 2026-09-08.

**What replaces it:** `experiment-sonnet-trial-j-opus/`,
`experiment-sonnet-trial-j-sonnet/`, schedule `6dc4175a3f494d6c`, driver
digest `27ae262e684514b0`, longest same-arm run 3.

Untracked, and left on disk only because this session's guard refuses `rm -r`
and `mv`. Delete the directory; nothing references it.
