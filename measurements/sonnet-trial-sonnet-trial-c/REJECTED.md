# Rejected. No unit of this schedule is recorded as run, and none may be.

Schedule digest `eb92e3ebcb80a953`, frozen on 2026-09-08 over
`experiment-sonnet-trial-c-opus/` and `-c-sonnet/`. No `ledger.jsonl` beside it
and no results in either arm, so no unit is recorded as bought — which is as
far as the evidence goes.

**Why.** Both its arms took the `behaviour` digest from the shell's
configuration rather than the one a review runs under, and under
`anthropic-api/normal` rather than the `claude-cli/normal` this trial actually
buys. `experiment.drift` refuses both arms now, so this schedule cannot be run
even if somebody tries.

**What replaces it:** `../sonnet-trial-sonnet-trial-d/`, digest
`5f483df0211adb37`, over `experiment-sonnet-trial-d-opus/` and `-d-sonnet/`.

Untracked, and left on disk only because this session's guard refuses `rm -r`
and `mv`. Delete the directory; nothing references it.
