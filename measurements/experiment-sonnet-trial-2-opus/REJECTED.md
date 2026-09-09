# Rejected. This is not a preregistration and nothing may be bought from it.

Frozen on 2026-09-08 and abandoned within the minute. No `ledger.jsonl` and no
results, so nothing here records a purchase — which is as far as the evidence
goes: an absent ledger says no unit was recorded, not that none was bought.

**Why.** Its sonnet half was frozen with no `--verify-model`, and an unset
verifier follows the reviewing model — so the two arms would have differed in
the verifier as well as in the reviewer, and a difference between them would
not have been attributable to the model. `sonnet_trial.py freeze` refused the
pair by name:

```
refusing to freeze: the two arms differ in 1 thing(s) besides the model:
  verifier_requested: 'claude-opus-5' in the opus arm,
                      'claude-sonnet-5' in the sonnet arm
```

That refusal is the check working. This directory is the half that was
otherwise fine; it is rejected with its pair rather than reused, because an arm
kept from a refused pair is an arm whose partner nobody can name.

It also predates the `behaviour` field, so `experiment.drift` refuses it too.

**What replaces it:** `experiment-sonnet-trial-c-opus/` and
`experiment-sonnet-trial-c-sonnet/`, schedule digest `eb92e3ebcb80a953`.

Untracked, and left on disk only because this session's guard refuses `rm -r`
and `mv`. Delete the directory; nothing references it.
