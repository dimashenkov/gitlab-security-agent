# Rejected. No unit of this is recorded as run, and none may be.

Frozen on 2026-09-08 and superseded within the hour. No `ledger.jsonl` and no
results, so nothing here records a purchase — which is as far as the evidence
goes: an absent ledger says no unit was recorded, not that none was bought.

**Why.** Its `driver` digest did not cover `sentinel_compare.py`, which
computes the verdict, or `sentinel.py`, which decides which lines of the suite
are cases. Either could change after the rows were bought, giving the same
paid reviews a different answer under a rule nobody recorded — and both arms
would still have verified clean.

I argued for leaving the comparator out, on the grounds that freezing it lets
an edit refuse a comparison of reviews already paid for. Codex answered that on
the twelfth gate round and the answer is better: a refusal there does not lose
the rows, it postpones their adjudication.

**What replaces it:** `experiment-sonnet-trial-g-opus/`,
`experiment-sonnet-trial-g-sonnet/`, schedule `b4faa1f607e0a537`, driver
digest `23edb36c5ebc9a7e`.

Untracked, and left on disk only because this session's guard refuses `rm -r`
and `mv`. Delete the directory; nothing references it.
