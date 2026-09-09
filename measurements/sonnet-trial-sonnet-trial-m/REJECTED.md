# Rejected. No unit of this is recorded as run, and none may be.

Frozen on 2026-09-08 and superseded the same day. No `ledger.jsonl` and no
results, so nothing here records a purchase — which is as far as the evidence
goes.

**Why.** `experiment.load` — the boundary where a manifest file becomes an
object, and the function every other reader goes through first — went straight
to `.get`. A manifest that is `null`, a list, a string or a number raised
`AttributeError` instead of the refusal the contract promises, and no amount of
validation in the callers could close it, because they call the loader first.

Codex, seventeenth gate round, 2026-09-08. The repair changed
`tools/experiment.py`, which is inside the driver digest.

**What replaces it:** `experiment-sonnet-trial-n-opus/`,
`experiment-sonnet-trial-n-sonnet/`, schedule `4135827112c9b231`, driver
digest `08ca615061d3eda8`, longest same-arm run 3.

Untracked, and left on disk only because this session's guard refuses `rm -r`
and `mv`. Delete the directory; nothing references it.
