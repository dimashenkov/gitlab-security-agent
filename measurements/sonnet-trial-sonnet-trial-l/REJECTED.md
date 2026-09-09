# Rejected. No unit of this is recorded as run, and none may be.

Frozen on 2026-09-08 and superseded the same day. No `ledger.jsonl` and no
results, so nothing here records a purchase — which is as far as the evidence
goes.

**Why.** The manifest shape was checked where a schedule is *read* and not
where one is *built*: `sonnet_trial.build` kept its own reading of the same
blocks, so `freeze` still crashed on a `cases` that is `null`, a row that is
not an object, an id that is not a string — and `suite` and `environment` were
read the same way. A class closed in one caller and not its neighbour is not
closed.

Codex, sixteenth gate round, 2026-09-08. One validator serves both paths now,
and the duplicate rule that lived in `build` is gone rather than copied.

**What replaces it:** `experiment-sonnet-trial-m-opus/`,
`experiment-sonnet-trial-m-sonnet/`, schedule `c9717acdee32926a`, driver
digest `a4fea7fd57f4c022`, longest same-arm run 3.

Untracked, and left on disk only because this session's guard refuses `rm -r`
and `mv`. Delete the directory; nothing references it.
