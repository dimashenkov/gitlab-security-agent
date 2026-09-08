# The opus arm of the Sonnet trial

`manifest.json` freezes the **opus** arm — Opus reviewing, Opus verifying. Its
pair is `measurements/experiment-sonnet-trial-sonnet` (Sonnet reviewing, Opus
verifying), and the schedule that interleaves them is
`measurements/sonnet-trial-sonnet-trial/schedule.json`.

All three were frozen against one tree, in that order, and committed together.
That order is not a preference: `experiment.run` calls `drift` per unit and
`environment.reviewer` digests every file under `src/security_agent`, so a
commit landing during a run aborts it with units already bought. Measured on
2026-09-07, when this arm was first frozen while a subagent was still editing
`src/` and `verify` refused within the hour.

## Reading `verify` on each arm

`tools/experiment.py verify sonnet-trial-opus` should report that nothing has
moved.

The challenger arm is checked on the terms it will actually run under, and
this is the command that does it:

```
tools/experiment.py verify sonnet-trial-sonnet \
    --model claude-sonnet-5 --verify-model claude-opus-5
```

Without those two arguments it reports `model_requested` moved, because
`verify` compares the manifest against the shell it is run in and this arm
never runs from a shell: `sonnet_trial._buy` sets both variables from the
schedule for every unit, precisely so the ambient shell cannot decide which
model is bought.

That bare failure used to be described here as expected. It is not a defect,
but calling it acceptable verification was — a check whose failure is routinely
excused has stopped being a check. Codex named it on the gate before the first
purchase, and the arguments exist so the question can be asked properly rather
than waved through.

## Why the verifier is pinned in both arms

An unset `SECURITY_SCAN_VERIFY_MODEL` means *the reviewer's own model*. Leaving
it unset would have made this a Sonnet-review/**Sonnet**-verify trial against
Opus/Opus — two differences, not one, and not the instrument D-015 approved.
Both arms name Opus as the verifier explicitly, and
`sonnet_trial._environment_mismatch` refuses a pair whose environments differ
in anything but the reviewing model.

## What the freeze covers, and what it does not

As of 2026-09-07 the environment block carries every `Config` field classified
as behavioural, the prompt and schema digests, the scorer and reviewer source
digests, the resolved paths of both `git` binaries and of the `claude` CLI, and
the suppression rules' expiry state per case. The child is given its
configuration through `--config-json` rather than inheriting the shell, its
forge context is constructed rather than read from CI variables, and the corpus
commits are built with pinned dates so one case builds to one pair of SHAs.

Two things are named rather than covered:

* **The CLI's version.** Running `claude --version` is blocked in the
  environment this was frozen from, so `review_cli_version` reads
  `unestablished: …` rather than a number. What guards an upgrade instead is
  `review_cli`, which carries the resolved path — the version is in the cask
  path — and the binary's size.
* **`$GIT_DIR/info/attributes`.** It outranks a repository's own
  `.gitattributes` and is not affected by the pinned attribute source. It is
  not reachable through a merge request, but it is part of what the runner is
  trusted for.
