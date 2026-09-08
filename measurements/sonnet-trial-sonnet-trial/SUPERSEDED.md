# This pair is superseded and no unit of it is recorded as run

`ledger.jsonl` does not exist beside this file and neither arm holds a result,
so **nothing here records a purchase**.

Stated that way and no wider. An absent ledger establishes that no unit was
recorded, not that no request ever left this machine — a review bought and
never written down would look exactly like this. The ledger is the record; it
is not a witness to everything that did not happen. Codex made the same
correction about the sibling `REJECTED.md` files, 2026-09-08.

## What it was

| | |
|---|---|
| opus arm | `measurements/experiment-sonnet-trial-opus/`, frozen 2026-09-07T16:49:40Z |
| sonnet arm | `measurements/experiment-sonnet-trial-sonnet/`, frozen 2026-09-07T16:49:41Z |
| schedule | `82650d38ccaf65db`, 52 units over 13 cases |
| reviewer digest in both | `3229463a04c8d589` |
| units recorded | **none** |

## Why it stopped being usable

Commit `26fdf0a` changed eleven files under `src/security_agent`. The reviewer
digest is taken over that whole directory, so it moved:

```
$ tools/experiment.py verify sonnet-trial-opus
Refusing: 1 thing(s) moved since the freeze.
  reviewer: 3229463a04c8d589 -> 5ef584629771f12b
```

That refusal is the freeze working. A pass run against these manifests would
answer a question about an instrument that no longer exists.

## What replaces it

| | |
|---|---|
| opus arm | `measurements/experiment-sonnet-trial-q-opus/` |
| sonnet arm | `measurements/experiment-sonnet-trial-q-sonnet/` |
| schedule | `measurements/sonnet-trial-sonnet-trial-q/`, digest `b17fde7133690b93` |
| behaviour digest, both arms | `47a7b8075304472a` |
| driver digest, both arms | `8ea050244ec23758` |
| protocol, both arms | `claude-cli` / `normal` |

Frozen on the tree after `26fdf0a`, with the reviewing model the only
difference between the arms and the verifier pinned to Opus in both.

Named here rather than left to "the commit that adds them": a reader who
reaches this file has the old pair in front of them and needs the replacement's
name, not an instruction to go and find it. Codex, on the gate for this
record, 2026-09-08.

The replacement also freezes something these manifests do not: the behavioural
settings. These record `verify = on` — whether verification runs — and nothing
about how. Measured on 2026-09-08: with `SECURITY_SCAN_VERIFY_VOTES=5` in the
environment, `experiment.drift` returned `[]` against this pair. A panel of
five and a panel of one are different instruments and the check said neither
had moved.

`experiment.drift` now refuses a manifest with no `behaviour` field outright,
so these two are refused twice over — once for the reviewer digest and once for
having frozen no behaviour at all.

## Kept, not rewritten

These manifests are left exactly as they were written. A frozen experiment that
is edited to look current is worse than a stale one: the whole value of a
freeze is that it says what was true when it was made. This file is the pointer
a reader needs, and it is deliberately beside the schedule rather than inside
either manifest.

Adjudicated by Codex on the round before the first purchase, 2026-09-08:
*"Preserve the old artifacts, but commit an explicit supersession record naming
the old and replacement pairs, their schedule digests, the reviewer change, and
whether any units ran. Do not rewrite old manifests to appear current."*
