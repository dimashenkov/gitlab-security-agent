---
name: security-review-in-ci
description: Run or configure gitlab-security-agent to review the security impact of a code diff, branch, merge request, or pull request. Use when the user asks for a security review of changed code, wants the reviewer added to GitLab CI or GitHub Actions, or needs help reading its findings, incomplete runs, exit codes, or configuration. Default CI adoption to advisory use; consult LIMITATIONS.md before making it a required merge check.
license: MIT
metadata:
  author: dimashenkov
  homepage: https://github.com/dimashenkov/gitlab-security-agent
---

# Security review of a code change

Answers one question: **does this change make things less safe?** It reads the
diff, then decides for itself what else to open — the caller that makes a line
exploitable, or the validation that makes it harmless, is almost never inside
the hunk. Read-only tools. It never executes the code under review.

Gate-eligible findings are citation-checked (the quoted code must exist in the
file, which is deterministic) and then independently verified in a fresh context
by a verifier asked to refute them, with an odd panel deciding by majority.
**Not every reported finding is verified**: informational findings can skip it,
the `probe` profile has no verifiers at all, and findings past
`SECURITY_SCAN_VERIFY_MAX` are reported unverified. The report marks which is
which — read that mark before repeating a finding to the user as confirmed.

## Adoption policy — apply this before configuring anything

Default to **advisory** use: a comment on the merge request that a human reads.

Do not represent a quiet result as evidence that a change is safe. Before
configuring this as a required check, tell the user in one sentence that recall,
false-positive rate, and resistance to repository-supplied prompt injection are
**not established** for this tool, and point them at `LIMITATIONS.md` in the
agent repository. If they still want a hard gate, that is their decision — set
it up.

---

# Step 0 — locate or install the agent

Everything below refers to paths inside the **agent's** repository, not the
user's. Do not run `tools/review.sh` from the repository under review; it will
not exist there.

Install the command, which is the path that does not depend on a checkout:

```bash
pip install "gitlab-security-agent @ git+https://github.com/dimashenkov/gitlab-security-agent@<commit>"
```

Pin a commit or tag, never `@main`: this step installs executable code and the
next one hands it an API key. That gives you the `gitlab-security-agent` command.

If you need `tools/review.sh`, `templates/`, or `LIMITATIONS.md`, you need a
checkout of the agent repository:

```bash
git clone https://github.com/dimashenkov/gitlab-security-agent
```

Keep the four in step — the skill, the pinned template, the installed command,
and the `LIMITATIONS.md` you cite must be the same release. Mixing versions is
how a stale claim survives.

---

# Option A — a branch, locally, no API key

From the **agent checkout**, with the repository under review as the working
directory target:

```bash
tools/review.sh --noticed "what you spotted reading the diff yourself"
```

**It reviews committed history, not your working tree.** `review.sh` diffs
commits ending at `HEAD`. If you have just edited files, commit them first or
the review will confidently examine the previous commit instead of your changes.
Do not edit and immediately review.

Nothing is posted and nothing is blocked. The report lands in `.security-scan/`
and the run is filed in `journal/`.

This runs on the user's **own `claude` CLI**, under whatever login it has, and
needs no `ANTHROPIC_API_KEY`:

- `ANTHROPIC_API_KEY` and `ANTHROPIC_AUTH_TOKEN` are removed from the child
  process, so the review cannot reach for a key set for something else;
- it runs `claude auth status` first. A **definite** missing or logged-out CLI
  is a refusal. An `auth status` that is unparseable, unsupported, or times out
  is treated as unknown and the review **proceeds** with a warning — so absence
  of a refusal is not proof of a subscription login;
- it never falls back to the paid API on its own. There is no automatic
  provider; `--provider anthropic-api` is the only way there, by name.

Tell the user to read their own diff first and pass what they saw via
`--noticed`. Read the report first and a useful finding can no longer be told
apart from one they would have found anyway.

```bash
tools/review.sh --profile probe            # small enough to run on every save
tools/review.sh --path src/auth            # only what changed there
tools/review.sh --provider anthropic-api   # the paid path, named explicitly
```

`probe` is six turns and no verifiers. It is *deliberately unable to conclude*
and **always exits 2**, unconditionally — that is a property of the profile, not
a policy about partial reviews, so no setting makes it a pass. What it produces
is a lead. Never report a quiet `probe` run as "no issues found".

`--path` narrows what the review is answerable *for*, never what it may read;
the agent still follows callers anywhere in the repository, because that is the
only way a finding gets checked. A scoped run says so in its report.

---

# Exit codes

    0   nothing blocking
    1   blocking findings          — the change author's problem
    2   the review did not conclude — the pipeline owner's problem

Keep 2 distinct from both. Gate on the code itself; never treat "not 1" as
success, and never report exit 2 to the user as a clean result.

**Two cases are unconditionally exit 2** and no setting forgives them: a
non-conclusive profile such as `probe`, and a run where no part of the change is
recorded as having reached the reviewer.

**Everything else partial is a policy choice.** By default
`SECURITY_SCAN_FAIL_ON_INCOMPLETE=true` and a partial run — including one that
exhausted `SECURITY_SCAN_MAX_OUTPUT_TOKENS`, hit a turn or time limit, or was
refused — exits 2. Set it to `false` and such a run can exit **0** once some
coverage exists. The report still states that coverage was partial. If you set
it, say out loud that you have turned an incomplete review into a passing one.

`SECURITY_SCAN_FAIL_ON=none` is **not** the way to make the job advisory. It
removes the severity threshold so nothing blocks and it changes which findings
get verified. It does not touch incomplete-run handling at all — that decision
is made earlier. To make findings advisory, keep the job non-blocking at the CI
level: `continue-on-error: true` in GitHub Actions, `allow_failure: true` in
GitLab.

A quiet result is not proof of safety. Excluded files, a `--path` scope, and a
diff truncated at `SECURITY_SCAN_DIFF_CEILING_BYTES` all narrow coverage, and
the report says so. Read that before summarising.

---

# Option B — GitLab CI

**1. Credentials.** Separate what is needed to *review* from what is needed to
*comment*:

| Variable | Needed for | Note |
|---|---|---|
| `ANTHROPIC_API_KEY` | reviewing, on the default API provider | Not needed for `--provider claude-cli`, and deliberately removed from that runner's environment. |
| `SECURITY_SCAN_GITLAB_TOKEN` | **commenting only** | Optional. Project or group token with `api` scope. `CI_JOB_TOKEN` cannot create notes, so without this the review still runs and is attached as an artifact — just not commented. |

Mask and protect both, so they are not exposed on unprotected branches. A fork
pipeline receives neither.

**2. Include the template:**

```yaml
include:
  - project: 'security/gitlab-security-agent'   # where the agent is hosted
    ref: main                                   # pin a tag in production
    file: '/templates/security-scan.yml'
    inputs:
      image: registry.example.com/security/gitlab-security-agent@sha256:<digest>
      stage: test
```

`image` is required and has **no default**, on purpose: the image is pushed to
the registry of whichever project hosts the agent, so it cannot be guessed. A
plausible default would fail at job start with a pull error; required, GitLab
refuses to create the pipeline and names the missing input. Prefer a digest over
`latest` — the job holds an API key and a forge token.

**The failure that reads like a typo and is not.** For `include: project:` the
consuming project must be able to read the agent project: same GitLab instance,
and either the agent project is public/internal, or the consuming project is on
the agent's Settings → CI/CD → Job token permissions allowlist. A private agent
project with an empty allowlist fails with "Project not found or access denied",
which looks like a wrong path.

---

# Option C — GitHub Actions

Copy `templates/github-actions.yml` from the agent checkout to
`.github/workflows/security-review.yml` in the user's repository.

It needs `ANTHROPIC_API_KEY` as a repository secret and `permissions:
pull-requests: write`. `GITHUB_TOKEN` must be passed through **explicitly** — it
is not in the environment otherwise. A fork's pull request gets a read-only
token, so the comment is skipped and the artifact is still written.

Three things to get right:

- **It installs the agent from the agent's repository, not the user's.** Not
  `pip install -e .`, which would install *their* project, where
  `gitlab-security-agent` is not a command that exists.
- **Keep it pinned.** The template ships pinned to a commit. Move it
  deliberately, having read what changed.
- **Not `.github/workflows/self-review.yml`.** That is the agent repository's
  own job and was never a template. It installs and runs the pull request's own
  tree and then hands it the API key — safe from a fork, which gets no secrets,
  and not safe from anyone who can push a branch.

The template ships `continue-on-error: true`, so findings are advisory. Remove
that line to make a finding fail the check.

It also sets `SECURITY_SCAN_COMMENT_AUTHOR: github-actions[bot]`. Keep it when
using `GITHUB_TOKEN`: that is an installation token and is refused at `GET
/user`, so without it the agent cannot prove which comment is its own and will
post a new one on every push rather than edit in place. A token whose identity
`/user` does return does not need it.

---

# Settings worth knowing

| Variable | When to touch it |
|---|---|
| `SECURITY_SCAN_FAIL_ON_INCOMPLETE` | Default true. False lets a partially covered run exit 0. See the exit-code section before setting it. |
| `SECURITY_SCAN_MAX_OUTPUT_TOKENS` | The run's output-token budget. Raise it rather than accepting an incomplete review. |
| `SECURITY_SCAN_DIFF_CEILING_BYTES` | How much of a large change is read. Over the ceiling the change is reviewed in part and the report says so — raise it, split the change, or narrow with `--path`. |
| `SECURITY_SCAN_GATE_REMOVED_CONTROLS` | Default true: a change deleting a security control blocks regardless of the rating. A deleted guard is not a low-severity opinion. |
| `SECURITY_SCAN_VERIFY_EFFORT` | Default `high`. A verifier that thinks less than the reviewer is not an independent check. |
| `SECURITY_SCAN_VERIFIER_CONTEXT` | Below this size the verifier sees the whole file rather than a window. The control that settles a question is routinely outside a window. |
| `SECURITY_SCAN_IGNORE_FILE` | Accepted-risk file, default `.security-agent-ignore.yml`. An entry added *by the change under review* does not apply to it. |
| `SECURITY_SCAN_PROMPT_DIR` | Where prompts and the finding schema live. When it resolves inside the reviewed repository, a change touching anything beneath it is refused with exit 2 before review — it would be supplying the rules it is judged by. |
| `SECURITY_SCAN_OUTPUT_DIR` | Report and `findings.json`, default `.security-scan`. A symlink anywhere on that path is refused rather than followed. |

---

# When the user asks "is it any good"

Give what is measured and what is not, in that order, and do not invent a
percentage. **Measured:** a regression suite over cases this project built
itself, and a documented set of misses in `LIMITATIONS.md`, each named
individually. **Not measured:** how often it reports something on ordinary code
with no vulnerability in it — the number that decides whether a team leaves the
tool switched on.

Do not compare it to a scanner that publishes a headline accuracy figure and no
false-alarm rate. Those are not the same claim.
