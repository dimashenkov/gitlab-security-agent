# Rejected. No unit of this is recorded as run, and none may be.

Frozen on 2026-09-08 and superseded the same day. No `ledger.jsonl` and no
results, so nothing here records a purchase — which is as far as the evidence
goes.

**Why.** The loader read the arms' case ids assuming the manifest's whole
shape: `json.loads` establishes that a file is JSON and nothing more. A
manifest that is `null`, or whose `cases` is `null`, or whose rows are bare
strings, produced an `AttributeError` or a `TypeError` out of the function
whose job is to refuse.

Codex named it as a class on the fifteenth gate round, 2026-09-08 — *a
validator that assumes a shape the spending path cannot safely consume* — and
the repair checks the shape through, in `sonnet_trial.py`, which is inside the
driver digest.

**What replaces it:** `experiment-sonnet-trial-l-opus/`,
`experiment-sonnet-trial-l-sonnet/`, schedule `ecd5d7421d62cc90`, driver
digest `e48af1b61b8c38a4`, longest same-arm run 3.

Untracked, and left on disk only because this session's guard refuses `rm -r`
and `mv`. Delete the directory; nothing references it.
