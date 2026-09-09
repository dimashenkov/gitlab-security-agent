# Rejected. No unit of this is recorded as run, and none may be.

Frozen on 2026-09-08 and superseded the same day. No `ledger.jsonl` and no
results, so nothing here records a purchase — which is as far as the evidence
goes.

**Why.** It was frozen before the last repair landed: `experiment.run` set
`SECURITY_SCAN_PROMPT_DIR` and never put it back, so every purchase left the
process pointing at one arm's frozen prompts. The repair changed
`tools/experiment.py`, which is inside the driver digest, so this pair's
`driver` no longer matches the tree — `17de908cdd3cccb8` against
`8ea050244ec23758`.

**And this is the last of eleven.** Twenty adversarial review rounds ran on
this machinery in one day. The first eight found one operator-facing sentence
wrong in a different clause each time; rounds nine to fourteen found real
defects in the trial's code; rounds fifteen to twenty found one class — a
reader assuming a shape a file need not have — closed one caller, one block,
one field at a time. Every repair invalidated the freeze, because the reviewing
tools are themselves inside the digest.

Grok, asked on 2026-09-08 whether this was converging, read the files and
answered: *"the process became the work. Twenty adversarial rounds today,
fifteen rejected pairs, and not one Sonnet review."* Its ruling was to freeze
once with the last repair inside and **not** open another review round.

**What replaces it:** `experiment-sonnet-trial-q-opus/`,
`experiment-sonnet-trial-q-sonnet/`, schedule `b17fde7133690b93`, driver
digest `8ea050244ec23758`, longest same-arm run 3.

Untracked, and left on disk only because this session's guard refuses `rm -r`
and `mv`. Delete the directory; nothing references it.
