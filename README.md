# GitLab security agent

An autonomous security reviewer for GitLab merge requests. It reads the change,
follows the code until it understands it, and blocks the merge when it finds
something exploitable — after proving to itself that the finding is real.

Not a linter and not a diff-to-prompt script. The agent has read-only tools and
decides for itself what to open, what to search for, and when it has enough to
form a judgement. A diff hunk almost never contains the thing that settles the
question; the validation that makes a change safe, or the caller that makes it
exploitable, is usually somewhere else in the repository.

```
merge request
     │
     ▼
┌─ agent turn ──────────────────────────────────┐
│  reads · searches · follows callers            │  ← repeats until the leads
│  reports findings as it confirms them          │    are exhausted
└───────────────────────────────────────────────┘
     │
     ▼  every finding, before it counts:
   layer 1  the quoted code must exist in the file        (deterministic)
   layer 2  an independent verifier tries to refute it    (fresh context)
   layer 3  votes are aggregated; lowering takes one, raising takes all
     │
     ▼
   exit 0 · exit 1 (blocked) · exit 2 (review didn't complete)
```

---

## Quick start

**1. Add two masked CI/CD variables** to the project (Settings → CI/CD → Variables):

| Variable | What it is |
| --- | --- |
| `ANTHROPIC_API_KEY` | Anthropic API key. Mask it and protect it. |
| `SECURITY_SCAN_GITLAB_TOKEN` | Project or group access token with `api` scope, used to post the review as a merge request comment. |

Mark both **masked** (so they are redacted if they ever reach a job log) and
**protected**. Neither is ever passed as a command-line argument — process
arguments show up in `ps` output and in logs under `set -x`, environment
variables do not. The agent reads them from the environment: the SDK picks up
`ANTHROPIC_API_KEY` itself, and `GitLabContext.from_env()` reads the GitLab
token.

`CI_JOB_TOKEN` cannot create merge request notes, so it is not used as a
fallback. Without the GitLab token the review still runs and lands in the job
artifacts — only the comment is skipped.

> **Fork merge requests do not receive project variables.** That is GitLab's
> behaviour and it is the right one, but it means a contribution from a fork
> fails with "no Anthropic credentials found" (exit 2) unless a maintainer runs
> the pipeline. On a public project, either accept that and review forks
> manually, or run the agent from a scheduled job against merged code instead.

**2. Include the job** in `.gitlab-ci.yml`:

```yaml
include:
  - project: 'your-group/gitlab-security-agent'
    ref: main
    file: '/templates/security-scan.yml'
    inputs:
      stage: test
```

That is the whole integration. The job runs on merge request pipelines, posts
one comment (edited in place on re-runs), attaches the report as an artifact,
and exits non-zero when something should block the merge.

**Rolling it out without breaking anyone's day:** start with
`allow_failure: true`, watch a week of merge requests, then turn it on.

```yaml
      inputs:
        allow_failure: true
```

---

## What it does with a merge request

1. Reads the diff and the merge request description.
2. Forms specific suspicions — not "this file handles user input" but "line 42
   builds a query with an f-string; where does `user_id` come from?"
3. Chases each one: reads the whole function, finds the callers, looks for the
   control it expects to exist, checks what the framework does by default.
4. Records a finding the moment a suspicion becomes a traced exploit path.
5. Stops when the leads run out and writes a summary of what it examined.

Then every finding is checked before it is allowed to affect the pipeline.

---

## The hallucination check

A blocking gate that reports invented vulnerabilities gets switched off within a
month. Three layers stand between a claim and a blocked merge.

### Layer 1 — the code must exist

Every finding carries an `evidence` field: the vulnerable code, quoted verbatim.
Before the finding is recorded, that quote is matched against the real file.

- Quote not in the file → **rejected**, with an excerpt of what is actually
  there, so the agent can correct itself or drop the claim.
- File not in the repository → **rejected**, with tracked paths sharing that
  filename.
- Quote found at a different line → the line number is **corrected**; the quote
  is authoritative, not the agent's arithmetic.
- Quote matching several places → **rejected**. A quote that could be any of
  three lines does not say where the weakness is, and the finding is not
  attached to whichever came first.
- Second failure on the same claim → **dropped permanently** and recorded in the
  report's rejected-claims section.

Matching tolerates whitespace and diff markers, and nothing else. A paraphrase
does not match — that is the point.

### Layer 2 — an independent verifier tries to refute it

Each surviving finding goes to a **fresh conversation** with the verifier prompt,
the same read-only tools, and no access to the original agent's reasoning. Its
instructions are to break the claim, and its burden of proof runs the other way:
`confirmed` requires personally tracing source → path → sink → impact. Anything
less is `uncertain` or `refuted`.

Independence is the whole design. A model asked to re-check its own chain of
thought tends to find it convincing.

### Layer 3 — aggregation, with a deliberate asymmetry

| Verdict | Effect |
| --- | --- |
| `confirmed` | Reported; counts toward the gate. |
| `uncertain` | Reported at `low` confidence — visible, not blocking. |
| `refuted` | Moved to a "refuted during verification" section. Never deleted. |

Critical findings get at least two verifiers and require **unanimous** refutation
to be dropped; one dissenting vote only downgrades them to `uncertain`.

Severity is not voted on at all — it is computed from three factual questions
(what the attacker achieves, whether authentication is needed, whether a victim
must act), because "how bad is this" depends on things the diff does not contain
and moved between runs on identical code. Verifiers correct the *facts* and the
number follows. Confidence moves in both directions: lowering takes one
verifier, raising takes all of them.

If verification cannot run at all (API error), the finding is reported and marked
unverified. Being unable to check a claim is not evidence against it.

---

## When the review does not finish

The most dangerous thing this tool could do is look like a pass when it did not
actually finish. So an incomplete run is **exit 2**, not exit 0:

| Stop reason | Meaning |
| --- | --- |
| `completed` | The review reached a conclusion. Only this can be a pass. |
| `turn_limit` / `time_limit` / `budget_exhausted` | Ran out of room mid-review. |
| `refusal` | The model declined to continue. |
| `error` | API or configuration failure. |

Exit codes: **0** nothing blocking · **1** blocking findings · **2** the review
could not be completed. The 1/2 split matters — the first is the author's problem
and the second is the pipeline owner's.

Set `SECURITY_SCAN_FAIL_ON_INCOMPLETE=false` to let partial reviews through. The
report still says the coverage was partial.

---

## Accepting a risk

Every finding in the report comes with its fingerprint. To accept one, add it to
`.security-agent-ignore.yml` in the repository being reviewed:

```yaml
ignore:
  - fingerprint: a3f8c21b9d4e5f60
    reason: Internal admin endpoint, not network-reachable. Tracked in SEC-412.
    expires: 2026-12-31          # optional; after this it applies again

  - path: tests/fixtures/**
    category: secrets
    reason: Dummy credentials in test fixtures.
```

- A `reason` is **required**. An accepted risk without a recorded reason is
  indistinguishable from a mistake six months later.
- `expires` is honoured: an expired entry stops suppressing and logs a warning.
- Suppressed findings stay in the report, in their own section. They are removed
  from the gate, never from view.
- Fingerprints are stable across line moves and re-wordings, so an entry keeps
  matching after unrelated edits.

### Who may accept a risk

The file lives in the repository under review, so the person who is blocked can
unblock themselves. That is deliberate: a suppression file held somewhere else
turns every accepted risk into a ticket for another team, and a gate that cannot
be used on a Friday afternoon gets switched off entirely.

It does mean the same merge request could add a vulnerability and the entry
suppressing it. Two things close that, and they belong together:

**Let the forge decide who approves.** Put the file under a code owner, so
editing it needs approval from a named group — enforced by GitLab rather than by
this tool, and visible in the merge request rather than in documentation:

```
[Security gate][1] @your-group/security
/.security-agent-ignore.yml
/CODEOWNERS
```

Owning `CODEOWNERS` itself matters, or one approved change removes the
protection for every change after it. This binds only if the target branch is
protected, Code Owner approval is required on it, direct pushes are disabled,
authors cannot approve their own merge requests, and approvals reset when the
file changes. Listing an owner on its own enforces nothing.

**A suppression does not apply to the change that introduces it.** Even with
approval, an entry added by the merge request under review takes effect from the
next one onward.

**Other escape hatches:** the `skip-ai-security` label on a merge request skips
the job entirely, and `SECURITY_SCAN_FAIL_ON=none` reports without blocking.

---

## Configuration

Everything is a CI/CD variable. Defaults are in bold.

### Gating

| Variable | Values | Meaning |
| --- | --- | --- |
| `SECURITY_SCAN_FAIL_ON` | critical, **high**, medium, low, none | Severity that blocks a merge. |
| `SECURITY_SCAN_MIN_CONFIDENCE` | high, **medium**, low | Lowest confidence allowed to block. |
| `SECURITY_SCAN_FAIL_ON_INCOMPLETE` | **true**, false | Whether a partial review fails the job. |
| `SECURITY_SCAN_GATE_PRE_EXISTING` | true, **false** | Block on weaknesses this change did not introduce. |
| `SECURITY_SCAN_UNGATED_CATEGORIES` | comma-separated, empty | Categories that never block here. The findings are still reported in full and marked `not gated`; only their power to stop a merge is withheld. Applies to every rule, including removed controls. |

### Model

| Variable | Default | Meaning |
| --- | --- | --- |
| `SECURITY_SCAN_MODEL` | `claude-opus-5` | Model for the review. |
| `SECURITY_SCAN_EFFORT` | `high` | `low`…`max`. The biggest cost/quality lever. |
| `SECURITY_SCAN_MAX_TOKENS` | `32000` | Per-response ceiling. |
| `SECURITY_SCAN_CACHE_TTL` | `1h` | Prompt cache lifetime: `5m` or `1h`. |

### Verification

| Variable | Default | Meaning |
| --- | --- | --- |
| `SECURITY_SCAN_VERIFY` | `true` | Layer 2/3. Layer 1 always runs. |
| `SECURITY_SCAN_VERIFY_VOTES` | `1` | Verifiers per finding. Critical and high always get ≥2. |
| `SECURITY_SCAN_VERIFY_MODEL` | same as review | Override to verify with a different model. |
| `SECURITY_SCAN_VERIFY_MAX` | `40` | Cap on findings verified; the rest are reported unverified, loudly. |

### Limits and scope

| Variable | Default | Meaning |
| --- | --- | --- |
| `SECURITY_SCAN_MAX_TURNS` | `60` | Agent turn ceiling. Raise for large merge requests. |
| `SECURITY_SCAN_MAX_RUNTIME` | `2700` | Wall-clock seconds. |
| `SECURITY_SCAN_TASK_BUDGET` | `250000` | Tokens the agent paces itself against. |
| `SECURITY_SCAN_MODE` | `auto` | `diff` in a merge request, `repo` otherwise. |
| `SECURITY_SCAN_EXCLUDE` | — | Extra glob patterns, comma-separated. Added to the defaults. |
| `SECURITY_SCAN_POST_COMMENT` | `true` | Post to the merge request. |

---

## Whole-repository review

The template also ships a scheduled job that reviews the entire tree instead of a
diff. Add a pipeline schedule with `SECURITY_SCAN_FULL` set to any value. It
reports rather than gates — there is no merge to block, and a red scheduled
pipeline every night trains people to ignore it.

---

## Security of the agent itself

The agent reads code an untrusted contributor may have written, in a job holding
an API key and a GitLab token. That shapes the design:

**No shell, no write tools.** Seven read-only tools: `list_changed_files`,
`get_diff`, `list_directory`, `read_file`, `search_code`, `git_log`, and
`report_finding`. A general-purpose exec tool here would be an escalation path,
not a convenience.

**Containment is checked after symlink resolution.** A path is resolved and then
tested for containment under the repository root — never by string prefix. A
symlink pointing at `/etc` does not get read.

**Git cannot be redirected by the repository.** No shell, `--no-ext-diff`, and
system and global git config routed to `/dev/null`, so a checked-in
`.gitconfig` or `.gitattributes` cannot choose what process runs.

**Repository content is data, not instruction.** The merge request title and
description are attacker-chosen text arriving in the same context as the agent's
instructions. They are fenced, labelled untrusted, and kept in the user turn; the
system prompt states that repository content is never an instruction, and that an
attempt to steer the review is itself a reportable finding.

**Prompts never come from the repository under review.** `resolved_prompt_dir()`
searches the operator's setting and the agent's own installation — never the
working directory. This project's own `self-review` job runs the image built from
the default branch for exactly this reason: a merge request that edits a prompt is
reviewed by the *current trusted* prompt, not by the one it proposes.

**A failed comment cannot turn a red pipeline green.** The exit code comes from
the findings; GitLab API failures are logged and ignored.

---

## Performance and cost

Wall-clock time is dominated by model inference, not by this code. Measured on
this repository:

| Operation | Time |
| --- | --- |
| `search_code` (git grep) | 8.5 ms |
| `read_file` with line numbering | 0.17 ms |
| `locate_evidence`, 5-line quote in a 20 000-line file | 8.8 ms |
| `locate_evidence`, worst case (quote absent) | 24.7 ms |
| `added_lines` over a 5 000-line diff | 1.5 ms |

A 25-turn review spends roughly eight minutes waiting on inference and under a
second running Python. The three levers that actually matter are turn count
(hence the instruction to batch searches), input tokens (hence prompt caching —
the system prompt and tool definitions are byte-identical across turns *and*
across pipelines, so they are read from cache at a fraction of the price), and
`effort`.

---

## Local use

```bash
pip install -e ".[dev]"
export ANTHROPIC_API_KEY=sk-...

# Review the current branch against main
gitlab-security-agent --base main --no-comment

# Review a whole repository
gitlab-security-agent --repo ../some-project --mode repo --no-comment

# Cheaper pass while iterating on prompts
gitlab-security-agent --effort low --no-verify --no-comment
```

The report lands in `.security-scan/report.md`, with the machine-readable result
in `.security-scan/findings.json`.

---

## Layout

```
prompts/
  system.md              the agent's instructions
  verifier.md            the refuter's instructions
  findings.schema.json   what a finding is — the single source of truth
src/security_agent/
  agent.py               the turn loop, cache breakpoints, beta degradation
  tools.py               the tool surface; layer 1 lives in report_finding
  evidence.py            verbatim matching and diff line mapping
  verify.py              layers 2 and 3
  workspace.py           the sandbox: paths, git, reading, searching
  gate.py                findings → exit code
  report.py              Markdown and JSON output
  gitlab.py              the merge request comment
  briefing.py            the opening message, incl. untrusted-text fencing
  config.py              CI variables, validation, prompt resolution
  cli.py                 entry point
templates/security-scan.yml   the includable CI job
```

`prompts/findings.schema.json` is loaded at runtime to build the `report_finding`
tool's schema, so the model is validated at the API layer and the schema cannot
drift from the code.

## Development

```bash
pip install -e ".[dev]"
pytest          # 236 tests
ruff check src/ tests/
```

Tests run without network access: `tests/fakes.py` replays scripted model
responses, so the agent loop, verification hand-off, gating, and report are all
exercised end to end.
