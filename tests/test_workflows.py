"""The CI files, which nobody was checking and which hold a secret.

`.github/workflows/security-review.yml` handed an API key to a third-party
action referenced as `@main`. A branch is whatever that branch holds on the
morning the job runs, so the key was trusted to code nobody here had read and
that could change between two runs — and this particular file exists to compare
two tools on identical input, which a silently moving version defeats twice
over.

Nothing here had a test. These files are configuration, so they fail at three
in the morning on somebody else's machine rather than in a suite, which is the
argument for checking them here rather than against it.
"""

from __future__ import annotations

import re
import shlex
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = sorted((ROOT / ".github" / "workflows").glob("*.yml"))

# The GitHub-shaped files, which is the workflows plus the template a reader is
# told to copy. The template is handed a secret and decides whether a finding
# fails a build exactly as the live ones do, so every rule below applies to it
# — a template held to a weaker standard than the file it stands in for is a
# recommendation to do the thing we would not do.
#
# `templates/security-scan.yml` is not here: it is GitLab's format, with no
# `jobs`/`steps`, and running these against it would pass by finding nothing.
GITHUB_YAML = [*WORKFLOWS, ROOT / "templates" / "github-actions.yml"]

# `owner/repo@ref`, which is a third party. `./local` and `docker://` are not,
# and neither is a step that runs a command rather than an action.
THIRD_PARTY = re.compile(r"^([\w.-]+)/([\w.-]+)(?:/[\w./-]+)?@(.+)$")
FORTY_HEX = re.compile(r"^[0-9a-f]{40}$")


def steps(path: Path):
    """Each step with the job that holds it, because some settings live there.

    `continue-on-error` is legal in both places and means the same thing, and
    our own workflow sets it on the job — which is the stronger form, since it
    covers every step rather than the one somebody remembered.
    """
    body = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    for job in (body.get("jobs") or {}).values():
        for step in (job.get("steps") or []):
            if isinstance(step, dict):
                yield job, step


def test_there_are_workflows_to_check():
    """Guards every test below: a glob that matches nothing passes them all."""
    assert WORKFLOWS, "no workflow files found"


@pytest.mark.parametrize("path", GITHUB_YAML, ids=lambda p: p.name)
def test_an_action_given_a_secret_is_pinned_to_a_commit(path):
    """A tag and a branch are both mutable; only a commit is a version.

    Checked for the steps that receive a secret rather than for all of them,
    because that is where the argument is strongest and a rule wider than its
    reason gets waived rather than followed. `actions/checkout@v4` gets no
    secret and stays as it is.
    """
    offenders = []
    for _job, step in steps(path):
        uses = str(step.get("uses") or "")
        match = THIRD_PARTY.match(uses)
        if not match:
            continue
        takes_secret = "secrets." in yaml.safe_dump(
            {k: v for k, v in step.items() if k != "uses"})
        if takes_secret and not FORTY_HEX.match(match.group(3)):
            offenders.append(uses)
    assert not offenders, "given a secret at a mutable ref: {}".format(offenders)


@pytest.mark.parametrize("path", GITHUB_YAML, ids=lambda p: p.name)
def test_a_workflow_asks_for_no_more_permission_than_it_uses(path):
    """`contents: read` and one narrow write at most.

    A review job reads a diff and leaves a comment. Anything wider is a token
    an attacker gets to borrow if the job can be made to run their code, which
    is exactly what a pull request from a fork is.
    """
    body = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    granted = body.get("permissions")
    assert isinstance(granted, dict), (
        "{} grants no explicit permissions, so it inherits whatever the "
        "repository default is".format(path.name))
    writes = sorted(k for k, v in granted.items() if v == "write")
    assert writes in ([], ["pull-requests"]), writes


def reviewing_steps(path: Path) -> list:
    """The steps that perform a review, found by a property rather than a name.

    A review calls a model, so it is handed an API key; nothing else in these
    files is. The first version of this looked for the strings
    `security-review`, `security-scan` and `cli`, and our own workflow runs
    `gitlab-security-agent` — so the test that says a review must not gate the
    build reached no step at all in the file it most needed to check. A list of
    spellings is the shape this repository has been caught by four times.
    """
    found = []
    for job, step in steps(path):
        rendered = yaml.safe_dump(step)
        if "API_KEY" in rendered or "api-key" in rendered:
            found.append((job, step))
    return found


@pytest.mark.parametrize("path", GITHUB_YAML, ids=lambda p: p.name)
def test_every_workflow_has_a_step_that_reviews(path):
    """Guards the test below, which passes trivially over an empty list."""
    assert reviewing_steps(path), (
        "{}: no step is given an API key, so nothing here reviews "
        "anything".format(path.name))


@pytest.mark.parametrize("path", GITHUB_YAML, ids=lambda p: p.name)
def test_a_review_job_never_gates_the_build(path):
    """Advisory by construction, not by configuration.

    Setting `SECURITY_SCAN_FAIL_ON=none` would also narrow verification, so the
    two must not be confused: the report is the product here, and a run that
    cannot conclude has to stay visible rather than be turned into a pass.
    """
    for job, step in reviewing_steps(path):
        advisory = (step.get("continue-on-error") is True
                    or job.get("continue-on-error") is True)
        assert advisory, (
            "{}: the review step can fail the build".format(path.name))


# ------------------------------------------ what the README tells a reader to copy


TEMPLATES = ROOT / "templates"


def test_a_template_never_installs_the_repository_it_is_copied_into():
    """`pip install -e .` installs whatever was checked out.

    In this repository that is the agent, which is why it went unnoticed. In
    the repository of somebody who copied the file it is their project, and the
    next line — `run: gitlab-security-agent` — is then a command that does not
    exist. The README named `.github/workflows/self-review.yml` as the thing to
    copy for a day, so the instruction did not work anywhere but here.

    Read from the steps rather than from the file's text, which is how the
    first version of this failed: it found the string inside the comment
    explaining why the string must not be there.
    """
    checked = 0
    for path in sorted(TEMPLATES.glob("*.yml")):
        for _job, step in steps(path):
            command = str(step.get("run") or "")
            if not command:
                continue
            checked += 1
            assert "install -e ." not in command, (
                "{} installs the repository it is copied into".format(path.name))
    assert checked, "no template runs any command, so nothing was checked"


def test_a_template_installs_the_agent_at_a_pinned_commit():
    """A template that says "pin this" and ships `@main` recommends what it
    does not do.

    This step installs executable code and the next one hands it an API key,
    which is the same argument that pinned the third-party action above — and
    the first version of this template shipped `@main` with a comment about it.
    """
    seen = 0
    for path in sorted(TEMPLATES.glob("*.yml")):
        for _job, step in steps(path):
            for ref in re.findall(r"git\+https://\S+?@([\w.-]+)",
                                  str(step.get("run") or "")):
                seen += 1
                assert FORTY_HEX.match(ref), (
                    "{} installs from a mutable ref: {}".format(path.name, ref))
    assert seen, "no template installs anything from git, so nothing was checked"


def test_the_readme_points_at_a_template_and_not_at_our_own_job():
    """A workflow under `.github/workflows/` is a job this repository runs.
    A template is a file somebody else copies. They are not interchangeable and
    the README named one while meaning the other.

    The `Copy ...` sentence specifically, not "the section mentions a template
    somewhere": the section explains why *not* to copy `self-review.yml`, so a
    test reading the whole section passes with the instruction changed back.
    """
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    section = readme[readme.index("### GitHub Actions"):]
    section = section[:section.index("### GitLab CI")]

    instruction = re.search(r"Copy\s+`([\w./-]+\.ya?ml)`", " ".join(section.split()))
    assert instruction, "the section gives no `Copy <file>` instruction"
    named = instruction.group(1)
    assert named.startswith("templates/"), (
        "the reader is told to copy {}, which is not a template".format(named))
    assert (ROOT / named).is_file(), "{} does not exist".format(named)


@pytest.mark.parametrize("path", sorted(TEMPLATES.glob("*.yml")),
                         ids=lambda p: p.name)
def test_a_template_is_not_also_a_live_workflow(path):
    """Anything under `.github/workflows/` runs here. A template must not."""
    assert not (ROOT / ".github" / "workflows" / path.name).exists(), (
        "{} exists both as a template and as a job this repository runs"
        .format(path.name))


def test_the_pinned_benchmark_names_what_it_pinned():
    """A forty-character hash tells a reader nothing on its own. The comment
    beside it is what makes moving the pin a decision rather than a chore.

    In *comment* lines, which the first version of this did not say: it looked
    for the short hash anywhere in the file, and the short hash is a prefix of
    the forty-character one it had just found there. The assertion could not
    fail. That is this repository's own recurring defect — a check satisfied by
    a shape rather than by the thing — written into the test meant to catch it.
    """
    text = (ROOT / ".github" / "workflows" / "security-review.yml").read_text(
        encoding="utf-8")
    pin = re.search(r"@([0-9a-f]{40})", text)
    assert pin, "the benchmark action is not pinned to a commit"

    comments = "\n".join(line for line in text.splitlines()
                         if line.lstrip().startswith("#"))
    assert pin.group(1)[:7] in comments, (
        "no comment names the pinned commit, so nobody can tell what it is")


# ----------------------------------------------- the GitLab-shaped CI files
#
# `.gitlab-ci.yml` is the pipeline this repository runs; `security-scan.yml` is
# the file the README tells a GitLab user to include. Neither was read by
# anything: two audit items were closed by editing them, and both edits could
# be undone with the suite still green.
#
# GitLab's format has `rules`, not `steps`, and a rule decides whether the job
# is *created at all* — which is the whole subject below, because a job that
# does not exist leaves no artifact and no note.

GITLAB_YAML = [ROOT / ".gitlab-ci.yml", ROOT / "templates" / "security-scan.yml"]

# The variables a rule may not read. `CI_MERGE_REQUEST_LABELS` is the merge
# request's labels; `inputs.skip_label` is the template's own name for the one
# that means "skip". Either in a rule is the same decision: the label removes
# the job.
LABEL_VARIABLES = ("CI_MERGE_REQUEST_LABELS", "inputs.skip_label")


def gitlab_jobs(path: Path) -> dict:
    """Top-level keys that are jobs, which in GitLab means they have a script.

    `stages`, `variables` and `default` are not jobs; `default` is the one that
    would otherwise slip through, because it holds `before_script`.
    """
    body = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return {name: job for name, job in body.items()
            if isinstance(job, dict) and job.get("script")}


def reviewing_jobs(path: Path) -> dict:
    """The jobs that run a review, found by what they run.

    By the command rather than by the job's name, for the reason
    `reviewing_steps` above gives: the names differ between the two files
    (`self-review`, `$[[ inputs.job_name ]]`) and one of them is not even a
    literal, so a list of names would quietly check nothing in the file that
    matters most.
    """
    return {name: job for name, job in gitlab_jobs(path).items()
            if any("gitlab-security-agent" in str(line) for line in job["script"])}


def merge_request_review_job(path: Path) -> tuple:
    """The review job a merge request pipeline creates.

    Told apart from the scheduled whole-repository sweep by the rule that
    brings it into being, not by its name. The sweep has no merge request, so
    no label and no note, and none of this applies to it.
    """
    for name, job in reviewing_jobs(path).items():
        for rule in job.get("rules") or []:
            if isinstance(rule, dict) and "CI_MERGE_REQUEST_IID" in str(rule.get("if") or ""):
                return name, job
    return "", {}


@pytest.mark.parametrize("path", GITLAB_YAML, ids=lambda p: p.name)
def test_there_is_a_review_job_to_check(path):
    """Guards the two tests below, which pass over an empty mapping."""
    assert reviewing_jobs(path), (
        "{}: no job runs the agent, so nothing here reviews anything"
        .format(path.name))
    name, _job = merge_request_review_job(path)
    assert name, "{}: no review job runs on a merge request".format(path.name)


@pytest.mark.parametrize("path", GITLAB_YAML, ids=lambda p: p.name)
def test_the_skip_label_never_decides_whether_the_job_exists(path):
    """The label is honoured inside the job, and nowhere else.

    Both files used to carry `when: never` on the skip label. That produced no
    job, no artifact and no note — and the note left by the run *before* the
    label went on stayed up on the merge request, still claiming its verdict.
    The label became a way to keep a stale pass visible.

    The fix moved the decision into the program: it exits 0 without contacting
    the model and writes an artifact saying the review was skipped, which costs
    runner seconds and buys a record that the review did not happen. That fix
    lives half in `cli.py`, which `TestSkipHatches` holds, and half in these
    two files, which nothing read.

    Asserted against the parsed rules rather than against the file's text: both
    files explain in a comment why `when: never` is not there, and a check on
    the text finds the explanation and passes.
    """
    for name, job in reviewing_jobs(path).items():
        rules = job.get("rules") or []
        assert rules, "{}: {} has no rules at all".format(path.name, name)
        for rule in rules:
            assert isinstance(rule, dict), rule
            condition = str(rule.get("if") or "")
            reads_labels = [v for v in LABEL_VARIABLES if v in condition]
            assert not reads_labels, (
                "{}: a rule on {} decides from {} (when: {!r}), so a labelled "
                "merge request gets no job, no artifact and no note"
                .format(path.name, name, reads_labels, rule.get("when")))


def test_the_template_hands_the_skip_label_to_the_program():
    """The other half: the job runs, and it is told which label to honour.

    Dropping `--skip-label` from the script is the same defect wearing the
    opposite shape — the job exists, and reviews a merge request that asked not
    to be reviewed.

    Parsed by the CLI's own argparse, with a sentinel substituted for the
    input. Never the template's real default: `--skip-label` defaults to
    exactly that string in `cli.py`, so a script that stopped passing the flag
    would parse to the same value and this would assert nothing.
    """
    from security_agent import cli

    path = ROOT / "templates" / "security-scan.yml"
    body = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    inputs = (body.get("spec") or {}).get("inputs") or {}
    assert "skip_label" in inputs, "the template no longer takes a skip label"

    name, job = merge_request_review_job(path)
    sentinel = "not-the-default-label"
    parsed = []
    for command in job["script"]:
        argv = shlex.split(command.replace("$[[ inputs.skip_label ]]", sentinel))
        assert argv[0] == "gitlab-security-agent", argv
        parsed.append(cli._parse_args(argv[1:]))

    assert [args.skip_label for args in parsed] == [sentinel], (
        "{}: {} does not pass the skip_label input to the agent".format(
            path.name, name))


def test_the_corpus_job_names_the_account_it_charges():
    """`--provider` became required an hour before this line was found missing.

    Omitting it used to select the paid path silently, and this job is 48
    reviews — the one place where the paid path is the right answer, so it has
    to say so. `.gitlab-ci.yml` was left without the argument, which meant the
    job exited on argparse having measured nothing, and nothing in `tests/`
    reads `.gitlab-ci.yml`.

    Checked against the tool's real parser rather than by looking for the
    string: `--provider` is there in spellings the parser rejects, and the
    failure mode being guarded against is a command line that does not run.
    """
    sys.path.insert(0, str(ROOT / "tools"))
    from pair_corpus import _build_parser

    body = yaml.safe_load((ROOT / ".gitlab-ci.yml").read_text(encoding="utf-8"))
    job = body["eval-corpus"]
    variables = {name: str(value)
                 for name, value in (job.get("variables") or {}).items()}
    commands = [line for line in job["script"] if "pair_corpus.py" in line]
    assert len(commands) == 1, commands

    argv = [re.sub(r"\$(\w+)", lambda m: variables.get(m.group(1), m.group(0)), word)
            for word in shlex.split(commands[0])]
    assert argv[0] == "python3" and argv[1].endswith("pair_corpus.py"), argv

    args = _build_parser().parse_args(argv[2:])

    assert args.provider == "anthropic-api"
    assert args.cases == "corpus/"


def test_the_provider_is_what_that_command_would_die_without():
    """The control for the test above.

    An assertion that a command line parses proves nothing unless something
    could have made it fail. Strip the one argument and the same line exits
    non-zero before a single review runs, which is what the job did.
    """
    sys.path.insert(0, str(ROOT / "tools"))
    from pair_corpus import _build_parser

    with pytest.raises(SystemExit):
        _build_parser().parse_args(
            ["corpus/", "--concurrency", "1", "--json", "corpus-result.json"])
