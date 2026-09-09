# Rejected. This is not a preregistration and nothing may be bought from it.

The sonnet half of the attempt described in
`../experiment-sonnet-trial-2-opus/REJECTED.md`, and the reason it was refused:
frozen with no `--verify-model`, so the verifier followed the reviewing model
and the two arms would have differed in the verifier as well as in the
reviewer. `sonnet_trial.py freeze` refused the pair.

No `ledger.jsonl` and no results, so nothing here records a purchase — see the
opus half for why that is not the same as none being made. It also predates the
`behaviour` field, so `experiment.drift` refuses it too.

**What replaces it:** `experiment-sonnet-trial-c-sonnet/`, frozen with the
verifier pinned to Opus explicitly, paired under schedule digest
`eb92e3ebcb80a953`.

Untracked, and left on disk only because this session's guard refuses `rm -r`
and `mv`. Delete the directory; nothing references it.
