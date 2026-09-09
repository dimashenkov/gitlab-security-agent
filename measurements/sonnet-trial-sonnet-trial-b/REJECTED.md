# Rejected. No unit of this schedule is recorded as run, and none may be.

Schedule digest `98096cb149d62e15`, frozen on 2026-09-08 over
`experiment-sonnet-trial-b-opus/` and `-b-sonnet/`. No `ledger.jsonl` beside it
and no results in either arm, so no unit is recorded as bought — which is as
far as the evidence goes: an absent ledger is the absence of a record, not a
witness to everything that did not happen.

**Why.** Both its arms froze the models and nothing about how the run behaves —
no `behaviour` field — so a change to the verifier's vote count or to what
blocks would have moved the instrument while every check reported that nothing
had. `experiment.drift` refuses both arms now, so this schedule cannot be run
even if somebody tries.

**What replaces it:** `../sonnet-trial-sonnet-trial-c/`, digest
`eb92e3ebcb80a953`, over `experiment-sonnet-trial-c-opus/` and `-c-sonnet/`.

Untracked, and left on disk only because this session's guard refuses `rm -r`
and `mv`. Delete the directory; nothing references it.
