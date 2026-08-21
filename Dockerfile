# The image the CI job runs in.
#
# Built once and pulled per job, rather than `pip install` at review time. Two
# reasons, and the second is the one that matters: a job that installs from PyPI
# on every merge request adds a minute to every review, and it resolves and
# executes third-party package code inside a job that holds an Anthropic API key
# and a GitLab token. Pinning that surface into a reviewed, rebuilt image is a
# smaller target than resolving it fresh against a live index each time.

FROM python:3.12-slim AS base

# git is not optional here — the agent's entire view of the repository comes
# through it. tini reaps the process properly when a runner cancels the job.
RUN apt-get update \
    && apt-get install --no-install-recommends -y git tini ca-certificates \
    && rm -rf /var/lib/apt/lists/*

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /opt/security-agent

# Dependencies first: they change far less often than the agent's own code, so
# this layer stays cached across almost every rebuild.
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY pyproject.toml README.md ./
COPY src/ ./src/
RUN pip install --no-cache-dir --no-deps .

# The prompts live outside the package and are read from here at runtime. They
# are deliberately never loaded from the repository under review — the system
# prompt is what keeps repository content from being treated as instructions, so
# it cannot come from the thing being reviewed.
COPY prompts/ ./prompts/
ENV SECURITY_SCAN_PROMPT_DIR=/opt/security-agent/prompts

# The agent only ever reads the checkout, so it has no reason to run as root.
# `git` refuses to operate on a repository owned by another user unless told the
# ownership is expected, which is exactly the situation inside a CI runner.
RUN useradd --create-home --uid 10001 scanner \
    && git config --system --add safe.directory '*'
USER scanner
WORKDIR /builds

ENTRYPOINT ["/usr/bin/tini", "--", "gitlab-security-agent"]
CMD ["--help"]
