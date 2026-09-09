# Rejected. This is not a preregistration and nothing may be bought from it.

The sonnet half of the attempt described in
`../experiment-sonnet-trial-b-opus/REJECTED.md`. Frozen on 2026-09-08,
abandoned the same hour. No `ledger.jsonl` and no results, so nothing here
records a purchase — which is as far as the evidence goes; see the sibling
file for why that is not the same as none being made.

**Why.** No `behaviour` field in its `environment` block, so the behavioural
settings were not frozen. `experiment.drift` refuses it.

**What replaces it:** `experiment-sonnet-trial-c-sonnet/`, paired with
`experiment-sonnet-trial-c-opus/` under schedule digest `eb92e3ebcb80a953`.

Untracked, and left on disk only because this session's guard refuses `rm -r`
and `mv`. Delete the directory; nothing references it.
