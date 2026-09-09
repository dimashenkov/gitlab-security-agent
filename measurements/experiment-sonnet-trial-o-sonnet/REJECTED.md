# Rejected. No unit of this is recorded as run, and none may be.

Frozen on 2026-09-08 and superseded the same day. No `ledger.jsonl` and no
results, so nothing here records a purchase — which is as far as the evidence
goes.

**Why.** Two repairs landed in the driver after it was frozen:

* `experiment.load` checked that a manifest's blocks are objects and not that
  they hold the fields read out of them — `suite.digest` crashed `drift`,
  `protocol.not_answerable` crashed `compare`, a case row without
  `case_digest` crashed the comparison.
* `sonnet_trial._buy` set `SECURITY_SCAN_MODEL` and
  `SECURITY_SCAN_VERIFY_MODEL` and never put them back, so everything the
  process did afterwards — building the reference, printing the status — read
  an environment one arm had left behind.

Codex named the first on the nineteenth gate round; the second surfaced as a
test that failed only when the trial's tests ran before the experiment's,
which is the same fact seen from outside.

**What replaces it:** `experiment-sonnet-trial-p-opus/`,
`experiment-sonnet-trial-p-sonnet/`, schedule `77d4d9421f584177`, driver
digest `17de908cdd3cccb8`, longest same-arm run 3.

Untracked, and left on disk only because this session's guard refuses `rm -r`
and `mv`. Delete the directory; nothing references it.
