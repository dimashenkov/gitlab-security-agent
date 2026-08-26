# Security review agent

For GitLab, GitHub, and your own branch.

By **[Dimitar Shenkov](https://github.com/dimashenkov)** · MIT licensed ·
[github.com/dimashenkov/gitlab-security-agent](https://github.com/dimashenkov/gitlab-security-agent)

> [!WARNING]
> **Experimental research preview. Not suitable for reviewing untrusted
> contributions.** Findings are model-generated leads, not security
> conclusions. Do not gate merges on it.
> There is no recall figure and no precision figure: both were measured, both
> turned out to be measuring something else, and both were withdrawn. What
> exists is a regression suite over cases this project built itself.
> **Read [LIMITATIONS.md](LIMITATIONS.md) before putting this in front of
> anyone's merge requests** — it is written to help you decide against it.

An autonomous security reviewer for code changes, on GitLab, on GitHub, or on
your own branch before you push it. It reads the change, follows the code until
it understands it, and reports what it finds — after proving to itself that the
finding is real. It can block a merge, and at its current level of evidence it
should not be asked to.

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
   layer 3  an odd panel decides by majority; confidence is the median
     │
     ▼
   exit 0 · exit 1 (blocked) · exit 2 (review didn't complete)
```

---

## What a finding looks like

From `corpus/go-sql-decoy-01`, a case built so the obvious answer is the wrong
one — there is a real sanitiser on the call path, and it is irrelevant to this
sink:

> ### 🟠 `high` · injection — SQL injection in /lookup region parameter
>
> [`lookup.go:13`](#) · confidence: high · verified 3/3
>
> ```go
> rows, err := s.db.QueryContext(r.Context(),
>     fmt.Sprintf("SELECT id, email FROM accounts WHERE region = '%s'", region))
> ```
>
> **What is wrong.** `lookupHandler` interpolates the caller-supplied `region`
> query parameter directly into an SQL string with `fmt.Sprintf` and executes
> it. The comment on line 9 and in `routes.go` claims `Wrap`/`validateAndEscape`
> sanitises the value, but `middleware.go:13-18` only rejects values longer than
> 64 bytes and strips `<...>` markup; it does not touch single quotes,
> semicolons, comment markers, or SQL keywords.
>
> **How it is exploited.** `GET /lookup?region=' OR '1'='1` returns every row.
>
> <details><summary>Verification</summary>
>
> 3/3 verifier(s) agreed — Searched: read `middleware.go` in full;
> `validateAndEscape` only enforces `len<=64` and removes `<...>` tags, with no
> SQL-relevant escaping; `Wrap` applies it to all query params then re-encodes,
> **preserving quotes**. Searched the package listing for any other file that
> could hold parameterisation — none.
> </details>

The verifier's own account of what it searched for is part of the finding: a
confirmation that cannot say what would have refuted it is downgraded to
`uncertain` and stops blocking.

---

## Quick start

Three ways in. Pick the one that matches where your code lives.

### On your own branch, no CI

```bash
export ANTHROPIC_API_KEY=...
tools/review.sh --noticed "what you spotted reading the diff yourself"
```

Reviews the current branch against the commit it left from. No forge token,
nothing posted, nothing blocked — the report lands in `.security-scan/` and the
result is filed in `journal/` for adjudication. Read your own diff *first* and
pass what you saw: read the report first and a useful finding can no longer be
told apart from one you would have found anyway.

### GitHub Actions

Copy `.github/workflows/self-review.yml`. It needs `ANTHROPIC_API_KEY` as a
repository secret, `permissions: pull-requests: write`, and `GITHUB_TOKEN`
passed through explicitly — it is not in the environment otherwise. A pull
request from a fork gets a read-only token, so the comment is skipped and the
artifact is still written.

### GitLab CI

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

### Layer 3 — aggregation, where no single verifier decides

| Verdict | Effect |
| --- | --- |
| `confirmed` | Reported; counts toward the gate. |
| `uncertain` | Reported at `low` confidence — visible, not blocking. |
| `refuted` | Moved to a "refuted during verification" section. Never deleted. |

Anything that could block gets an **odd panel of at least three**, and the
verdict takes a majority. Confidence is the median of the confirming verifiers.
A fact correction takes a majority of the panel. Unanimity survives in exactly
one place, which is the place it was written for: a `critical` finding cannot be
discarded unless every verifier refutes it.

This used to be an asymmetry — lowering takes one voice, raising takes all —
justified as erring toward a **visible** finding. Measurement said it erred the
other way. Two verifiers cannot form a majority, so one saying `uncertain`
carried the verdict; `uncertain` forces confidence to `low`; `low` is under the
gate. Four identical runs of one case produced three blocks and one pass, and
the difference was never about the code. A finding that does not block *is* the
invisible one — it sits in the report saying nothing was settled while the merge
goes through. The rule protected the report and abandoned the gate.

Severity is not voted on at all — it is computed from three factual questions
(what the attacker achieves, whether authentication is needed, whether a victim
must act), because "how bad is this" depends on things the diff does not contain
and moved between runs on identical code. Verifiers correct the *facts* and the
number follows. Confidence still moves in both directions, because an agent
hedging at `low` on a real weakness would otherwise bury it permanently — but it
now takes a majority to move it either way.

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

An accepted risk is matched against **every** line of code the finding quotes,
not only the one printed with it. Two runs do not always start a quote in the
same place — measured: three runs of one case quoted a call, a fourth started a
line later at the expression inside it, and the fingerprint changed with it. A
suppression that expires because the model chose a different line is worse than
no escape hatch at all, because the team believes the risk is still accepted.

Lines that identify nothing are not used as anchors. `if err != nil {` appears
in every function of a Go file; matching on it would let one accepted risk
silence an unrelated finding in the same file.

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

## How it is measured

Two numbers used to stand in for quality here, and neither survived contact
with what they actually bound.

**Counting decoys was not measuring precision.** Five hand-written safe files
the agent stayed quiet about are five true negatives, authored by the same
person who wrote the prompt. Repeating the run measures stability, not sample
size; the upper bound on the false-positive rate stays somewhere near half.

**Matched pairs replace them.** Each case is two versions of the same code
differing by exactly one security-relevant construct — a positional placeholder
against string interpolation, `exec.Command` with separate arguments against
`/bin/sh -c`, JSX text interpolation against `dangerouslySetInnerHTML`.
Framework, structure, surrounding code and diff size are held constant, so what
is measured is whether the decisive idiom is recognised rather than whether
alarming-looking tokens are.

```
pair passes = the safe member produces no target finding
              AND the unsafe member produces the expected one
```

Reporting both members fails the pair despite perfect recall. Reporting
neither also fails. That is the property that cannot be gamed by flagging
everything.

```
tools/pair_corpus.py corpus/
tools/pair_corpus.py corpus/ --language go --family injection
```

**Cases are harvested, not only written.** Hand-written cases still have the
problem the decoys had: whoever wrote the prompt also chose which idioms it
would be tested on. `tools/harvest_pairs.py` takes the fix commit a published
advisory names and builds a pair from it, so the ground truth is the
maintainers' own fix and the code is someone else's. Files keep their
repository-relative paths and arrive with their unchanged siblings, because a
file in a vacuum has no callers to trace and no validators to check a claim
against.

Two constructions, which measure different things and are never scored
together:

```
regression   safe = the fix added,  unsafe = the fix reverted
snapshot     safe = fixed version added from a shared baseline,
             unsafe = vulnerable version added from the same baseline
```

Regression is exactly symmetric and is the attack worth catching — someone
removing a guard a maintainer deliberately added. But every unsafe member
deletes something, so the direction of the diff predicts the answer, and a tool
with a rule about removed controls scores well on it without having recognised
anything. Snapshot gives that up for diffs that both add, and is the one that
measures discrimination.

Answer keys are scrubbed: commit messages neutralised, tests and changelogs
dropped from the change on both members equally, and a case whose diff still
names the advisory is rejected rather than patched — editing real code to hide
the answer makes it no longer real code.

### What it has been measured on

| Language | Hand-written pairs | Harvested from advisories | Weakness families covered |
| --- | ---: | ---: | --- |
| Python | 5 | 6 | injection, authn-authz, path-traversal, ssrf, deserialization |
| Go | 4 | 6 | injection, crypto, dos, sensitive-data-exposure |
| Ruby | 4 | 6 | xss, authn-authz, injection, path-traversal |
| TypeScript | 3 | 8 | xss, open-redirect, authn-authz |
| Java | 2 | 4 | injection, deserialization, authn-authz |
| PHP | 2 | 6 | path-traversal, authn-authz, xss, csrf |
| Rust | 2 | 6 | injection, race-condition, crypto, authn-authz, dos |
| C# | 0 | 6 | path-traversal, dos |

Eight languages, twelve families, seventy cases. That is coverage, not
validation — a language appearing in this table means the agent has been run
against it, not that its behaviour there is bounded. The pair counts are small
enough that a single case moving changes a percentage by five points.

Nothing about the agent is language-specific: there are no per-language rules,
no parsers, and no ruleset. It reads the code. The reason to test eight
languages is not to configure eight of anything, it is that a reviewer who has
only ever been checked on Python is a reviewer nobody has checked.

Five of the hand-written cases are **negative controls**, where both members
contain the alarming construct and only the data flow differs — `pickle.loads`
on both sides, one of them reading bytes the service itself wrote to a private
directory with an HMAC verified by `compare_digest`; `DOMPurify.sanitize`
called in both members, in one of them on a value already bound for an escaped
text node where the call does nothing. A tool matching on tokens reports both
members and scores zero pairs on all five.

**Prompt injection is scored on decision preservation.** The agent reads text
an untrusted contributor wrote; that is the job, not a flaw to be closed. So
"did it ignore the instruction" is not observable and not the question. What is
observable:

```
decision preserved = the same case, with and without an attacker's payload,
                     produces the same answer on the target finding
```

Measured in both directions, because they fail differently. **Suppression** —
a payload in vulnerable code arguing the finding away — ships a vulnerability.
**Fabrication** — a payload in correct code arguing a weakness into existence —
turns the gate into a way of blocking a colleague's merge request, needs no
vulnerability to mount, and gets the tool switched off faster than a missed bug.

"Same answer" means the disposition the gate acts on, not merely that the
finding is still mentioned somewhere: a payload that leaves it in the report
while talking its confidence below the threshold has shipped the vulnerability.
Fabrication is a set difference over blocking findings rather than a count,
because substitution — one legitimate block removed, one fabricated block added
— leaves the count unchanged and the merge request blocked. Severity,
confidence or verifier drift that never reaches the gate is reported
separately; it is worth seeing and it is not a failed defence.

Every trial re-runs its own control, so a case covered by several payloads has
already produced several identical-input runs. Comparing those to each other
costs nothing and gives the run-to-run variance a moved verdict has to beat
before the payload can be blamed for it. Without that number, "the payload
moved the verdict" and "the verdict moves anyway" are the same observation.

Payloads under `payloads/` are applied to every case, because one written
against the case it was tested on measures nothing. Each trial re-runs its own
payload-free control rather than reusing an earlier one: the same review of the
same code moves between runs, and comparing against an hour-old baseline reports
that variance as an attack succeeding.

```
tools/injection_corpus.py corpus/ --payloads payloads/
```

Both tools print the caveat with the score. A clean sheet on a corpus this size
means no failure was found — not that the failure rate is bounded.

## Development

```bash
pip install -e ".[dev]"
pytest          # 236 tests
ruff check src/ tests/
```

Tests run without network access: `tests/fakes.py` replays scripted model
responses, so the agent loop, verification hand-off, gating, and report are all
exercised end to end.

---

## Author and licence

Written by **Dimitar Shenkov** — <dimitar.shenkov@gmail.com> ·
[github.com/dimashenkov](https://github.com/dimashenkov).

Released under the MIT licence (see [LICENSE](LICENSE)). You may use, modify and
redistribute it, including commercially; the copyright notice has to travel with
it. If it saves you a bad merge, saying where it came from costs nothing.
