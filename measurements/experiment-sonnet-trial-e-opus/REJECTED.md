# Rejected. No unit of this is recorded as run, and none may be.

Frozen on 2026-09-08 and superseded within the hour. No `ledger.jsonl` and no
results, so nothing here records a purchase — which is as far as the evidence
goes: an absent ledger says no unit was recorded, not that none was bought.

**Why.** Its `driver` digest covered `experiment.py` and `sonnet_trial.py` and
not `sentinel_reference.py` — which builds the baseline the purchased rows are
compared against. Editing it moved no recorded field, so both arms would have
verified clean while the meaning of the comparison changed underneath them.
The change that found this also changed that file's behaviour, which is the
proof it carries consequential semantics rather than presentation.

Codex, eleventh gate round of the day, 2026-09-08.

**What replaces it:** `experiment-sonnet-trial-f-opus/`,
`experiment-sonnet-trial-f-sonnet/`, schedule digest `607bb1a67d229c28`,
driver digest `31ee6574153990a8`.

Untracked, and left on disk only because this session's guard refuses `rm -r`
and `mv`. Delete the directory; nothing references it.
