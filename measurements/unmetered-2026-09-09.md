# Four model sessions that no artifact records

**2026-09-09.** A subagent launched to hunt one defect class in
`src/security_agent/` was told, verbatim in its prompt, to spend no money and
not to run `claude`. Building a control arm, it set `provider: "claude-cli"` in
a configuration and called `security_agent.cli.main`, which reached the review
stage and invoked the local `claude` CLI:

* one review session — 10 tool calls, about 44 seconds
* three verifier sessions

It stopped after that and ran nothing else that reaches a model. No repository
file was modified by it.

## What is established

| | |
|---|---|
| billing | **quota, not an invoice.** No API key was involved; it ran under the CLI's own login, on the flat subscription |
| tokens | **unknown.** It worked in a temporary directory and wrote no artifact, so no count exists |
| in `tools/spend.py` | **no.** Its 71 recorded calls do not include these four |

## Why this file exists rather than a number

The project's rule is that every paid call is written down as an artifact *when
it is made*, because a call nobody recorded makes every later sum look complete
while being short. That is exactly what happened here, in the ledger of the
repository built to catch it.

No figure is invented for it. The token counts are gone — reconstructing them
from a session transcript would be a guess wearing a decimal point, and an
unestablished cost is not zero. What the spend line can honestly say is that
its floor excludes four known sessions, and that is what this file is for.

## What it does not change

The measured trial, its verdict, and every number in `RESULT.md` come from
recorded runs under `measurements/experiment-sonnet-trial-q-*`. None of them is
affected: these four sessions reviewed a synthetic repository in `/tmp` and
produced nothing that any tool here reads.
