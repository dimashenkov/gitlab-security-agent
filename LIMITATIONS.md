# What this is not, and what it has not been shown to do

Read this before putting the agent in front of anyone's merge requests. It is
written to help you decide against it, because the material that would help you
decide for it does not exist yet.

**Status: experimental research preview. Not suitable for reviewing untrusted
contributions.** Findings are model-generated leads, not security conclusions.

"Advisory only" is not by itself a sufficient boundary, and calling it that
would be the more comfortable half of the truth. While prompt injection is
unresolved, an attacker who can write a comment in the repository can make a
real finding look refuted to the person reading the report. That is less
dangerous than bypassing a gate and it is still attacker-influenced
reassurance, which is the tool's only output.

---

## The one-line version

A clean result means the agent read some code and reported nothing. It does not
mean the change is safe, and it does not mean the change was fully examined.

## What has actually been evaluated

| | |
|---|---|
| Languages | Go, Python, TypeScript, Ruby, Rust, Java, PHP, C# — between 6 and 11 cases each |
| Change shape | Two: a focused diff centred on one control, and a whole newly-added module |
| Repository size | 4 to 56 files and 24 to 433 KB per case |
| Forge | GitLab, self-managed, `merge_request_event` pipelines |
| Provider | Anthropic first-party API only |
| Real merge requests | **none** |
| Independent adjudication | **none** |

Everything measured was measured on cases this project constructed or harvested
itself. An adopter cannot check the numbers by re-running the corpus, because
agreeing with the author is what the corpus was built to do.

## What the numbers are, and are not

There is no recall figure and no precision figure. Both were measured, both
turned out to be measuring something else, and both were withdrawn:

- **10 of 17** on hand-written pairs — seven of the failures were cases scored
  against category names the agent cannot emit. The real figure is somewhere
  between 10/17 and 17/17 and has not been re-measured.
- **2 of 6** on harvested real advisories — **withdrawn**. Three of the four
  failures were reviews that never completed and were silently counted as
  "found nothing", and twenty of forty-eight manifests named the wrong target
  file.
- **15 of 15** prompt-injection trials held — **withdrawn**. Scored correctly,
  three of four suppression payloads moved the verdict. Since then the panel,
  the verifier's evidence requirement and the scorer have all changed, and a
  narrow re-measurement (verifier only, one case, two runs per condition) saw
  no movement from the two payloads it tested — see
  `measurements/2026-08-25-verifier-replay/`. That is not end-to-end
  resistance and it is not prevalence. The honest sentence is: no movement was
  observed in those trials on that case.

  A follow-up on a harder construction — a sanitiser that really exists, is
  really on the call path, and is irrelevant to the sink — found the reviewer
  and both verifier panels reasoning about what the function does to a quote
  rather than stopping at whether it exists
  (`measurements/2026-08-25-decoy-validator/`). One case. It is the strongest
  result in this project and it is still one case.

What exists instead is a regression suite. It can support "this version did
what the previous version did on these frozen cases" and nothing about code
outside them.

## In which direction it is wrong

Honestly: not established, and that is itself the most important limitation. On
the evidence available:

- **Misses are the observed failure.** On the harvested cases, the reviewer
  more often reported nothing than reported something wrong.
- **It reports real problems outside the expected one.** Of three findings
  hand-adjudicated, two were correct weaknesses the advisory did not cover and
  one was wrong. Treat findings outside the change's obvious subject as worth
  reading, not as noise.
- **It can promote a real defect to a security claim it is not.** The one
  adjudicated-wrong finding described a genuine bug accurately and called it
  exploitable without checking the caller that prevents it.
- **Stability is measured on one synthetic case**, four identical runs
  agreeing. Nothing is known about run-to-run agreement on real code. Assume
  two runs of the same merge request can disagree.

## Known failure modes

| Failure | Consequence | Mitigation |
|---|---|---|
| Misses a vulnerability in a large newly added module | Nothing is reported; the change looks reviewed | Do not treat a quiet result as coverage. Read the file list in the report |
| Reports a real defect as a security weakness | Wasted reviewer attention; in gating mode, a blocked merge | Every finding carries the code and the verifier's search; overrule it on that |
| Prompt injection via ordinary developer prose | Gating: **a real vulnerability passes.** Advisory: a real finding is made to look refuted to the reader. Three of four payloads did this when last measured | Unresolved. Do not run against untrusted contributions at all — the failure survives turning the gate off |
| Review stops early | No findings, exit 2 | Exit 2 is never 0; the report header says it did not complete |
| Two runs disagree on the same code | A merge blocked yesterday passes today | Not measured on real code. Suppressions are matched on quoted code, not wording, so an accepted risk survives rewording |
| A finding's category is one you did not expect | It is skipped by category filters | The vocabulary is fixed in the schema; open redirect, notably, has no name in it |

## What is sent where

The agent runs in your CI job and holds two credentials: an Anthropic API key
and a GitLab token.

**To Anthropic** goes whatever the agent reads — file contents, diffs, paths,
and commit metadata from the revisions under review. It reads through read-only
tools (list, diff, read, search, log) and cannot execute anything. There is no
allowlist of what it may read beyond your `excludes`, so assume any file in the
reviewed repository may be sent, including one holding a secret.

**The GitLab token** needs `api` scope to post the merge request note. That
scope is broader than posting a note. Use a project access token, not a personal
one.

Anthropic's retention terms apply and are not restated here; check them for your
own account.

## Cost and runtime

Measured, on eight real harvested cases plus two single reviews:

| | |
|---|---|
| Per review | $0.60 – $3.65 observed |
| Runtime | 265 – 895 seconds observed |
| Predictable in advance | **no** — a 4–6× spread, uncorrelated with case size |

The cheapest review had 52 files, the most expensive 12. Cost tracks how much
the agent chose to read and think.

Ceilings, all configurable: 60 turns, 2,700 seconds, 400,000 output tokens,
32,000 tokens per response (raised once to 64,000 on truncation). There is **no
dollar ceiling** — a hard spend limit has to be set on the Anthropic account,
because cost is only known after a response completes. An attacker-authored
merge request chooses when that spend happens.

## Every condition that produces exit 2

Exit 2 means the review did not reach an answer. It is never a pass.

`turn_limit` · `time_limit` · `budget_exhausted` · `context_exhausted` ·
`response_too_long` · `transport_error` · `refusal` · `error`

Plus, before any review starts and without an artifact: invalid configuration,
an unusable repository or revision range, missing credentials, and a report
that cannot be written where it was asked to go.

## If you are the author, using it on your own code

The tier the project has actually settled on. Most of what blocks third-party
use is about evidence someone else would need; the conditions that matter for
the author are different and shorter:

- **Advisory and never a required check.** `allow_failure: true`, or
  `tools/review.sh`, which runs locally with `--no-comment` and no GitLab token.
- **Read your own diff first**, and write down what you noticed, before you open
  the report. Read it the other way round and a useful finding cannot be told
  apart from one you would have found anyway.
- **Selectively, not on every commit.** It earns its cost where security
  reasoning crosses files: new request handlers, authorisation, query and
  command and template construction, path handling, deserialisation, CI and
  secret handling, dependency integration, large generated changes. Not
  refactors, tests, formatting or documentation.
- **A spend limit on the provider account.** The ceilings here are turns, time
  and tokens; none of them is dollars, and cost is only known after a response
  completes.
- **Only repositories whose contents you are willing to send.** There is no
  positive allowlist — exclusions are patterns, so assume any file may be read.
- **The injection caveat still applies, narrowed.** A single author removes the
  obvious attacker, but repository prose also arrives through vendored code,
  generated files, accepted patches and upstream examples. The defensible
  condition is that you treat review-relevant prose as non-hostile, or accept
  that third-party prose may influence the report.

**The decision procedure**, so the trial can end rather than drift: ten eligible
changes or one month, whichever is later. Keep it if at least one finding showed
you something that would otherwise have shipped, or if its call-chain evidence
saves more time than adjudicating it costs. Turn it off if none did, if wrong
findings keep costing real attention, or if you catch yourself reading a quiet
report as reassurance. Ten wrong findings dismissed in a minute each establish
low irritation, not value.

`tools/journal.py report` prints that decision with the counts beside it.

## Running it without blocking

Use `allow_failure: true` on the job, and do not make it a required check.

**Do not reach for `SECURITY_SCAN_FAIL_ON=none`.** It also makes the job
non-blocking, and until 2026-08-25 it silently skipped verification: with no
threshold there is nothing a verdict can change about gating, so nothing was
verified — no independent refutation, no odd panel, no requirement that a
confirmation state what it searched for. Advisory mode is exactly where the
report is the whole product, so that was the wrong place to lose them. The
scope no longer follows the gate setting; `allow_failure` remains the honest
way to run it non-blocking.

## Overriding a decision

Accepted risks live in `.security-agent-ignore.yml`, keyed on a fingerprint
derived from the quoted code — never from the finding's wording, which changes
every run. Each entry requires a written reason and may carry an expiry. An
entry with no reason is refused: an accepted risk without one is
indistinguishable from a mistake.

There is no forge-enforced approval on that file beyond whatever your own
branch protection provides. If you gate on this tool, that is a gap you must
close yourself.

## Things you should assume are untrusted

Comments and documentation in the reviewed repository are **input to a language
model**, not evidence. A comment claiming that input is validated upstream, or
that security has already reviewed a file, is a working attack against this
agent today. So is the same claim placed in `CONTRIBUTING.md`.

## Stricter than ordinary findings

A change that removes an existing security control blocks regardless of
severity, when gating is on. This is deliberate and it is the rule most likely
to produce a block you disagree with.

## Not supported

Cross-project `include:` (unproven) · Amazon Bedrock · Google Vertex AI · any
provider other than the Anthropic first-party API.

**GitHub Actions is supported and has never run.** The adapter posts one
comment per pull request and edits it in place, the same contract as GitLab,
and it is covered by tests rather than by a real workflow. Two things a first
run will meet: `GITHUB_TOKEN` is not in the environment unless the workflow
passes it, and a pull request from a fork gets a read-only token, so the
comment is skipped and the artifact is still written.

## Upgrades

Any change to the prompts, the schema, the model, the gate settings or the
scorer invalidates every measurement taken before it. The baseline mechanism
refuses to compare across such a change rather than reporting a delta that
would read as a change in the reviewer. Treat a version bump as removing the
evidence, not carrying it forward.

---

*Written 2026-08-25 against v0.1.0. If it disagrees with the README, this file
is the one that was written to be pessimistic.*
