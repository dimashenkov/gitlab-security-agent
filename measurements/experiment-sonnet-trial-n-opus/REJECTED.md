# Rejected. No unit of this is recorded as run, and none may be.

Frozen on 2026-09-08 and superseded the same day. No `ledger.jsonl` and no
results, so nothing here records a purchase — which is as far as the evidence
goes.

**Why.** `experiment.load` checked that a manifest is an object and that its
`cases` is truthy, and left every block *inside* it unchecked: an
`"environment": []` crashed `verify` at `.items()`, a `"cases": [null]`
crashed `protocol_settings` at `.get`. `run`, `compare` and the trial builder
all come through that loader, so a shape escaping there escaped everywhere.

Codex, eighteenth gate round, 2026-09-08, answering as a class rather than as
the next instance. The repair changed both `experiment.py` and
`sonnet_trial.py`, which are inside the driver digest.

**What replaces it:** `experiment-sonnet-trial-o-opus/`,
`experiment-sonnet-trial-o-sonnet/`, schedule `1e4ab424a130fd95`, driver
digest `b77c5bfa54409750`, longest same-arm run 3.

Untracked, and left on disk only because this session's guard refuses `rm -r`
and `mv`. Delete the directory; nothing references it.
