# Rejected. This is not a preregistration and nothing may be bought from it.

Frozen on 2026-09-08 and abandoned the same day. No `ledger.jsonl` and no
results, so nothing here records a purchase — which is as far as the evidence
goes: an absent ledger says no unit was recorded, not that none was bought.

**Why.** Its `behaviour` digest was taken from the shell's configuration rather
than the one a review runs under, and then from the wrong provider: with no
provider or profile passed, `effective_config` gives `anthropic-api/normal`
while every unit of this trial is bought as `claude-cli/normal`. The freeze
described one instrument and the money would have bought another.

Repairing that moved the digest — `f7f91b3378e77fd2 -> 8262ee46e01fa429` and
again after the provider fix — so `experiment.drift` refuses this arm outright.

Its sibling `experiment-sonnet-trial-c-sonnet/` and the schedule
`sonnet-trial-sonnet-trial-c/` are the same attempt and are rejected with it.

**What replaces it:** `experiment-sonnet-trial-d-opus/`,
`experiment-sonnet-trial-d-sonnet/`, schedule digest `5f483df0211adb37`,
behaviour digest `47a7b8075304472a` in both arms.

Untracked, and left on disk only because this session's guard refuses `rm -r`
and `mv`. Delete the directory; nothing references it.
