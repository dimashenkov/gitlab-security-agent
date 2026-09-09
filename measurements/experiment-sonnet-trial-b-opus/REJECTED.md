# Rejected. This is not a preregistration and nothing may be bought from it.

Frozen on 2026-09-08 and abandoned the same hour. It has no `ledger.jsonl` and
no results, so **nothing here records a purchase** — which is as far as the
evidence goes. An absent ledger establishes that no unit was recorded, not that
none was ever bought; a review paid for and never written down would look
exactly like this. Codex, 2026-09-08.

**Why.** Its `environment` block has no `behaviour` field, so it froze the
models and nothing about how the run behaves — `SECURITY_SCAN_VERIFY_VOTES=5`
would have changed how many verifiers vote on every finding while
`experiment.drift` reported that nothing had moved. `drift` now refuses a
manifest without that field, so this directory is refused by the tool as well
as by this file.

Its sibling `experiment-sonnet-trial-b-sonnet/` and the schedule
`sonnet-trial-sonnet-trial-b/` are the same attempt and are rejected with it.

**What replaces it:** `experiment-sonnet-trial-c-opus/`,
`experiment-sonnet-trial-c-sonnet/`, schedule digest `eb92e3ebcb80a953`.

Untracked, and left on disk only because this session's guard refuses `rm -r`
and `mv`. Delete the directory; nothing references it.
