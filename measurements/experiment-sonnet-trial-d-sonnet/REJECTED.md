# Rejected. No unit of this is recorded as run, and none may be.

Frozen on 2026-09-08 and superseded the same day. No `ledger.jsonl` and no
results, so nothing here records a purchase — which is as far as the evidence
goes: an absent ledger says no unit was recorded, not that none was bought.

**Why.** Its manifests froze no `driver` digest. `tools/experiment.py` decides
what is bought and what is accepted — it selects the protocol settings, calls
`run_case`, applies the adjudications, judges the result and publishes it — and
it sat outside every digest the freeze took. Nine repairs landed in that file
in one session, each changing what a run does, and `verify` said nothing had
moved after every one of them.

`driver_digest` closes that, and `experiment.drift` refuses a manifest frozen
without it:

```
Refusing: 1 thing(s) moved since the freeze.
  driver: this manifest was frozen before the code that runs an experiment was
  recorded, so nothing here can say whether it has changed
```

Raised on the tenth gate round of the day and confirmed by Codex as larger than
the defect it had been asked about.

**What replaces it:** `experiment-sonnet-trial-e-opus/`,
`experiment-sonnet-trial-e-sonnet/`, schedule digest `890966d409c84c74`,
driver digest `ce2b2030efce1838`.

Untracked, and left on disk only because this session's guard refuses `rm -r`
and `mv`. Delete the directory; nothing references it.
