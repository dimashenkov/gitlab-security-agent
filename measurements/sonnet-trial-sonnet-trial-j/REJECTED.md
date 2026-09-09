# Rejected. No unit of this is recorded as run, and none may be.

Frozen on 2026-09-08 and superseded the same day. No `ledger.jsonl` and no
results, so nothing here records a purchase — which is as far as the evidence
goes.

**Why.** `load_schedule` derived the expected set of units from the schedule's
*own* list of cases, so a case removed together with its four units left a
shorter trial that looked complete — every remaining purchase valid in both
manifests, and the run reporting itself finished against the shortened order.
A case named twice in that list passed as well.

The loader reads both arm manifests now and requires the schedule's cases to
be theirs. That changed `sonnet_trial.py`, which is inside the driver digest.

Codex, fourteenth gate round, 2026-09-08.

**What replaces it:** `experiment-sonnet-trial-k-opus/`,
`experiment-sonnet-trial-k-sonnet/`, schedule `e414c1c8199d77ee`, driver
digest `31ad8d86577ae203`, longest same-arm run 3.

Untracked, and left on disk only because this session's guard refuses `rm -r`
and `mv`. Delete the directory; nothing references it.
