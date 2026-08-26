"""Configuration, resolved from CI variables with CLI overrides on top."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from .models import CONFIDENCE_ORDER, SEVERITY_ORDER

# Paths that cost tokens without carrying signal. Lockfiles and vendored trees
# are dependency data rather than reviewable logic (supply-chain risk is caught
# from the manifest instead); minified and generated output is not something a
# reviewer can act on.
DEFAULT_EXCLUDES: Sequence[str] = (
    "*.lock", "*.min.js", "*.min.css", "*.map", "*.snap",
    "*.svg", "*.png", "*.jpg", "*.jpeg", "*.gif", "*.ico", "*.pdf",
    "*.woff", "*.woff2", "*.ttf", "*.eot", "*.mo",
    "*.pb.go", "*_pb2.py", "*.pyc",
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock",
    "Cargo.lock", "composer.lock", "Gemfile.lock", "go.sum",
    "*/vendor/*", "*/node_modules/*", "*/dist/*", "*/build/*",
    "*/.terraform/*", "*/__snapshots__/*",
)

# Per-1M-token rates used only for the cost line in the report. Wrong numbers
# here mis-report spend; they never affect behaviour.
MODEL_PRICING = {
    "claude-opus-5": (5.0, 25.0),
    "claude-opus-4-8": (5.0, 25.0),
    "claude-sonnet-5": (3.0, 15.0),
    "claude-haiku-4-5": (1.0, 5.0),
}


class ConfigError(Exception):
    """Configuration is unusable; exit before calling the API."""


def _env(name: str, default: str = "") -> str:
    value = os.environ.get(name)
    return default if value is None or value.strip() == "" else value.strip()


def _env_bool(name: str, default: bool) -> bool:
    raw = _env(name).lower()
    if raw == "":
        return default
    if raw in ("1", "true", "yes", "on"):
        return True
    if raw in ("0", "false", "no", "off"):
        return False
    raise ConfigError("{}: expected true or false, got {!r}".format(name, raw))


def _env_int(name: str, default: int) -> int:
    raw = _env(name)
    if raw == "":
        return default
    try:
        return int(raw)
    except ValueError:
        raise ConfigError("{}: expected an integer, got {!r}".format(name, raw)) from None


def _env_list(name: str) -> List[str]:
    raw = _env(name)
    return [item.strip() for item in raw.split(",") if item.strip()] if raw else []


@dataclass
class ForgeContext:
    """What the agent needs to know about the change it is reviewing.

    One shape for both forges. The field names are GitLab's because they were
    first and renaming them would ripple through the briefing, the gate, the
    report and the tests without buying anything — `mr_iid` holds a pull
    request number on GitHub and means the same thing.

    `kind` decides where a comment goes. It is also the honest answer to "which
    forge is this": absent both, it is `none`, and the agent still reviews and
    still writes its artifact, it just has nowhere to post.
    """

    kind: str = "gitlab"
    api_url: str = ""
    project_id: str = ""
    project_path: str = ""
    token: str = ""
    mr_iid: str = ""
    mr_title: str = ""
    mr_description: str = ""
    mr_labels: List[str] = field(default_factory=list)
    source_branch: str = ""
    target_branch: str = ""
    diff_base_sha: str = ""
    source_branch_sha: str = ""
    default_branch: str = "main"
    pipeline_source: str = ""
    job_url: str = ""
    commit_sha: str = ""

    @property
    def is_merge_request(self) -> bool:
        return bool(self.mr_iid)

    @property
    def can_comment(self) -> bool:
        return bool(self.token and self.project_id and self.mr_iid and self.api_url)

    @classmethod
    def from_env(cls) -> "ForgeContext":
        """Whichever forge this is running on, or neither.

        GitHub is checked first because a GitHub Actions runner sets `CI` and a
        handful of generic variables too, and a GitLab-shaped read of those
        produces a context that looks half-populated instead of empty — which
        is worse than no context at all, because it fails at posting rather
        than at detection.
        """
        if _env("GITHUB_ACTIONS") or _env("GITHUB_REPOSITORY"):
            return cls.from_github_env()
        return cls.from_gitlab_env()

    @classmethod
    def from_github_env(cls) -> "ForgeContext":
        """GitHub Actions. Most of it is in the event payload, not the env.

        `GITHUB_REF` gives `refs/pull/N/merge` on a pull request, but nothing
        in the environment carries the title, the labels, or the base sha — so
        the event payload is read when it is there, and its absence degrades to
        a review without a comment rather than to a crash.
        """
        event = _github_event()
        pull = event.get("pull_request") or {}
        repository = event.get("repository") or {}
        server = _env("GITHUB_SERVER_URL", "https://github.com")
        slug = _env("GITHUB_REPOSITORY")
        number = str(pull.get("number") or "")
        if not number:
            ref = _env("GITHUB_REF")            # refs/pull/12/merge
            parts = ref.split("/")
            if len(parts) > 2 and parts[1] == "pull":
                number = parts[2]
        return cls(
            kind="github",
            api_url=_env("GITHUB_API_URL", "https://api.github.com"),
            project_id=slug,
            project_path=slug,
            # A workflow must pass it in: `GITHUB_TOKEN` is not exported to the
            # environment by default, and the automatic token cannot comment on
            # a pull request from a fork.
            token=_env("SECURITY_SCAN_GITHUB_TOKEN") or _env("GITHUB_TOKEN"),
            mr_iid=number,
            mr_title=str(pull.get("title") or ""),
            mr_description=str(pull.get("body") or ""),
            mr_labels=[str(label.get("name", "")) for label in pull.get("labels") or []],
            source_branch=_env("GITHUB_HEAD_REF"),
            target_branch=_env("GITHUB_BASE_REF"),
            diff_base_sha=str((pull.get("base") or {}).get("sha") or ""),
            source_branch_sha=str((pull.get("head") or {}).get("sha") or _env("GITHUB_SHA")),
            default_branch=str(repository.get("default_branch") or "main"),
            pipeline_source=_env("GITHUB_EVENT_NAME"),
            job_url="{}/{}/actions/runs/{}".format(
                server, slug, _env("GITHUB_RUN_ID")) if slug else "",
            commit_sha=_env("GITHUB_SHA"),
        )

    @classmethod
    def from_gitlab_env(cls) -> "ForgeContext":
        return cls(
            kind="gitlab",
            api_url=_env("CI_API_V4_URL"),
            project_id=_env("CI_PROJECT_ID"),
            project_path=_env("CI_PROJECT_PATH"),
            # CI_JOB_TOKEN cannot create merge request notes, so it is not a
            # fallback here. A project or group access token with `api` scope is
            # required; without one the agent still scans and skips the comment.
            token=_env("SECURITY_SCAN_GITLAB_TOKEN") or _env("GITLAB_API_TOKEN"),
            mr_iid=_env("CI_MERGE_REQUEST_IID"),
            mr_title=_env("CI_MERGE_REQUEST_TITLE"),
            mr_description=_env("CI_MERGE_REQUEST_DESCRIPTION"),
            mr_labels=[
                label.strip()
                for label in _env("CI_MERGE_REQUEST_LABELS").split(",")
                if label.strip()
            ],
            source_branch=_env("CI_MERGE_REQUEST_SOURCE_BRANCH_NAME"),
            target_branch=_env("CI_MERGE_REQUEST_TARGET_BRANCH_NAME"),
            diff_base_sha=_env("CI_MERGE_REQUEST_DIFF_BASE_SHA"),
            source_branch_sha=_env("CI_MERGE_REQUEST_SOURCE_BRANCH_SHA"),
            default_branch=_env("CI_DEFAULT_BRANCH", "main"),
            pipeline_source=_env("CI_PIPELINE_SOURCE"),
            job_url=_env("CI_JOB_URL"),
            commit_sha=_env("CI_COMMIT_SHA"),
        )


# The old name, kept because it appears in tests and in anything anyone wrote
# against this before there were two forges.
GitLabContext = ForgeContext


def blob_url(ctx: ForgeContext, path: str, line: int) -> str:
    """A link to the exact line, at the exact commit, or "".

    Most of what an inline review comment buys, without any of the machinery.
    Anthropic's action anchors findings to diff positions and their own code
    says "in production you'd want more sophisticated line mapping"; a finding
    without a resolvable line silently becomes line 1, and one in the hundred
    and first changed file is dropped with a log line claiming it is not in the
    diff. A permalink needs none of that and cannot be wrong in those ways.

    Pinned to the reviewed commit, never to a branch: a link to `main` points
    at whatever `main` says next week, which is the same mistake as an artifact
    that records only `HEAD`. No commit, no link — a 404 in a security report
    costs more trust than a plain path.
    """
    sha = ctx.source_branch_sha or ctx.commit_sha
    if not (sha and path and ctx.project_path):
        return ""
    anchor = "#L{}".format(line) if line else ""
    if ctx.kind == "github":
        server = (ctx.api_url or "").replace("//api.", "//").rstrip("/")
        if server.endswith("/api/v3"):
            server = server[: -len("/api/v3")]
        return "{}/{}/blob/{}/{}{}".format(
            server or "https://github.com", ctx.project_path, sha, path, anchor)
    if ctx.kind == "gitlab":
        # `CI_API_V4_URL` is the only project URL the agent is given, and the
        # web root is it without the API suffix.
        server = (ctx.api_url or "").rstrip("/")
        if server.endswith("/api/v4"):
            server = server[: -len("/api/v4")]
        if not server:
            return ""
        return "{}/{}/-/blob/{}/{}{}".format(
            server, ctx.project_path, sha, path, anchor)
    return ""


def _inside(path: Path, root: Path) -> bool:
    """Is `path` at or under `root`? Both must already be resolved.

    Compared on parts rather than string prefixes: `/repo-backup` starts with
    `/repo` and is a different directory.
    """
    return path == root or root in path.parents


def prompt_dir_risk(prompt_dir: Path, repo_root: Path,
                    changed: Sequence[str]) -> Optional[str]:
    """Can the change under review rewrite the rules used to review it?

    The documented guarantee — prompts never come from the repository under
    review — was written three times and enforced nowhere. Anthropic's action
    ships the same hole as a feature: its filtering instructions are read from
    a path inside the checkout, so on a `pull_request` build the author of the
    change supplies the rules used to filter findings about it.

    A blanket refusal was the first attempt and it was wrong. Running from a
    source checkout of the agent's own repository puts the prompts inside the
    reviewed tree by construction, and that is the author's normal workflow,
    not an attack. What matters is narrower and exactly checkable: **is a
    prompt file part of this change?**

    Returns None when there is nothing to say, a warning string when the
    prompts sit inside the tree but the change does not touch them, and a
    string beginning with "REFUSE" when it does.
    """
    prompt_dir, repo_root = prompt_dir.resolve(), repo_root.resolve()
    if not _inside(prompt_dir, repo_root):
        return None

    try:
        relative = prompt_dir.relative_to(repo_root)
    except ValueError:                      # pragma: no cover - guarded above
        return None
    prefix = str(relative).rstrip("/") + "/"
    touched = sorted(path for path in changed if path.startswith(prefix))

    if touched:
        return (
            "REFUSE: this change edits {}, and those files are the prompts this "
            "review would run under — the change would be judged by rules it "
            "wrote. Point SECURITY_SCAN_PROMPT_DIR at the agent's own prompts, "
            "outside the checkout, or review this change with a trusted "
            "build.".format(", ".join(touched))
        )
    return (
        "the prompts are being read from {}, inside the repository under "
        "review. Nothing in this change touches them, so this review is sound "
        "— but a change that did would be judged by its own rules.".format(
            prompt_dir)
    )


def _github_event() -> Dict[str, Any]:
    """The event payload, or an empty one.

    Unreadable or malformed is not an error worth failing a review over: the
    consequence is a review that cannot post its comment, and that has always
    been survivable. A crash here would turn a missing file into a failed
    security check, which is the inversion this project exists to avoid.
    """
    path = _env("GITHUB_EVENT_PATH")
    if not path:
        return {}
    try:
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


@dataclass
class Config:
    # --- model ---
    model: str = "claude-opus-5"
    effort: str = "high"
    max_tokens: int = 32_000
    cache_ttl: str = "1h"
    max_retries: int = 3
    request_timeout: float = 900.0
    use_refusal_fallback: bool = True
    use_task_budget: bool = True
    task_budget_tokens: int = 250_000

    # --- agent limits ---
    max_turns: int = 60
    max_runtime_seconds: int = 2_700
    max_output_tokens_total: int = 400_000

    # --- scan scope ---
    mode: str = "auto"  # auto | diff | repo
    diff_context_lines: int = 12
    excludes: Sequence[str] = DEFAULT_EXCLUDES
    # Which of the changed files this run is answerable for. Empty means all of
    # them, which is the only sensible default for a gate.
    #
    # It narrows what must be **reviewed**, never what may be **read**. The
    # whole design rests on following code out of the hunk — the validation
    # that makes a change safe and the caller that makes it exploitable live
    # elsewhere — so a scope that also fenced the reading tools would turn every
    # unreachable control into a false positive. Scope is a statement about
    # which findings this run is responsible for, not about what exists.
    scope: Sequence[str] = ()

    # --- verification (layer 2/3 of the hallucination check) ---
    verify: bool = True
    verify_votes: int = 1
    verify_model: str = ""  # falls back to `model`
    verify_effort: str = "high"
    verify_max_findings: int = 40
    # Below this, the verifier's opening brief carries the whole file
    # rather than a window around the finding. A sixty-line window is an
    # arbitrary boundary and the control that decides a finding is
    # routinely on the other side of it. Deliberately conservative: this
    # is the opening prompt, where one large claim would otherwise eat
    # the response budget for the whole panel.
    verifier_context_chars: int = 20_000
    # Verifier calls are independent, so they run concurrently. The ceiling
    # keeps a run with many findings from opening dozens of connections at once
    # and hitting rate limits — the wall-clock win is already most of the way
    # there at four.
    verify_concurrency: int = 4

    # --- gating ---
    fail_on: str = "high"  # critical | high | medium | low | none
    min_confidence: str = "medium"
    fail_on_incomplete: bool = True
    gate_pre_existing: bool = False
    # A change that removes a security control blocks regardless of severity.
    # The question there is not "how bad is this" but "why is a guard someone
    # deliberately added being taken away", and that belongs to the author of
    # the change rather than to a CVSS-shaped scale.
    gate_removed_controls: bool = True
    # Categories this project has decided not to gate on. Distinct from a
    # suppression: a suppression is "we accept this specific risk", and it is
    # per-finding and shown as dropped. This is a standing policy, so the
    # finding is reported in full — code, exploit path, verdict — and only its
    # ability to stop the merge is withheld. Deleting the finding instead would
    # let a policy decision quietly become a coverage gap that nobody can see.
    ungated_categories: Sequence[str] = ()

    # --- output ---
    output_dir: Path = Path(".security-scan")
    post_comment: bool = True
    ignore_file: Path = Path(".security-agent-ignore.yml")
    prompt_dir: Optional[Path] = None

    gitlab: GitLabContext = field(default_factory=GitLabContext)

    # ------------------------------------------------------------------ env

    @classmethod
    def from_env(cls) -> "Config":
        prompt_dir = _env("SECURITY_SCAN_PROMPT_DIR")
        cfg = cls(
            model=_env("SECURITY_SCAN_MODEL", "claude-opus-5"),
            effort=_env("SECURITY_SCAN_EFFORT", "high"),
            max_tokens=_env_int("SECURITY_SCAN_MAX_TOKENS", 32_000),
            cache_ttl=_env("SECURITY_SCAN_CACHE_TTL", "1h"),
            max_retries=_env_int("SECURITY_SCAN_MAX_RETRIES", 3),
            request_timeout=float(_env_int("SECURITY_SCAN_REQUEST_TIMEOUT", 900)),
            use_refusal_fallback=_env_bool("SECURITY_SCAN_REFUSAL_FALLBACK", True),
            use_task_budget=_env_bool("SECURITY_SCAN_TASK_BUDGET_ENABLED", True),
            task_budget_tokens=_env_int("SECURITY_SCAN_TASK_BUDGET", 250_000),
            max_turns=_env_int("SECURITY_SCAN_MAX_TURNS", 60),
            max_runtime_seconds=_env_int("SECURITY_SCAN_MAX_RUNTIME", 2_700),
            max_output_tokens_total=_env_int("SECURITY_SCAN_MAX_OUTPUT_TOKENS", 400_000),
            mode=_env("SECURITY_SCAN_MODE", "auto"),
            diff_context_lines=_env_int("SECURITY_SCAN_CONTEXT_LINES", 12),
            verify=_env_bool("SECURITY_SCAN_VERIFY", True),
            verify_votes=_env_int("SECURITY_SCAN_VERIFY_VOTES", 1),
            verify_model=_env("SECURITY_SCAN_VERIFY_MODEL"),
            verify_effort=_env("SECURITY_SCAN_VERIFY_EFFORT", "high"),
            verifier_context_chars=_env_int(
                "SECURITY_SCAN_VERIFIER_CONTEXT", 20_000),
            verify_max_findings=_env_int("SECURITY_SCAN_VERIFY_MAX", 40),
            verify_concurrency=_env_int("SECURITY_SCAN_VERIFY_CONCURRENCY", 4),
            fail_on=_env("SECURITY_SCAN_FAIL_ON", "high"),
            min_confidence=_env("SECURITY_SCAN_MIN_CONFIDENCE", "medium"),
            fail_on_incomplete=_env_bool("SECURITY_SCAN_FAIL_ON_INCOMPLETE", True),
            gate_pre_existing=_env_bool("SECURITY_SCAN_GATE_PRE_EXISTING", False),
            gate_removed_controls=_env_bool("SECURITY_SCAN_GATE_REMOVED_CONTROLS", True),
            ungated_categories=tuple(_env_list("SECURITY_SCAN_UNGATED_CATEGORIES")),
            output_dir=Path(_env("SECURITY_SCAN_OUTPUT_DIR", ".security-scan")),
            post_comment=_env_bool("SECURITY_SCAN_POST_COMMENT", True),
            ignore_file=Path(_env("SECURITY_SCAN_IGNORE_FILE", ".security-agent-ignore.yml")),
            prompt_dir=Path(prompt_dir) if prompt_dir else None,
            gitlab=GitLabContext.from_env(),
        )
        extra = _env_list("SECURITY_SCAN_EXCLUDE")
        if extra:
            cfg.excludes = tuple(cfg.excludes) + tuple(extra)
        cfg.validate()
        return cfg

    # ------------------------------------------------------------- validate

    def validate(self) -> None:
        allowed_fail = (*tuple(SEVERITY_ORDER), "none")
        if self.fail_on not in allowed_fail:
            raise ConfigError(
                "SECURITY_SCAN_FAIL_ON must be one of {}, got {!r}".format(
                    "|".join(allowed_fail), self.fail_on)
            )
        if self.min_confidence not in CONFIDENCE_ORDER:
            raise ConfigError(
                "SECURITY_SCAN_MIN_CONFIDENCE must be one of {}, got {!r}".format(
                    "|".join(CONFIDENCE_ORDER), self.min_confidence)
            )
        if self.ungated_categories:
            from .vocabulary import categories, normalise

            resolved, unknown = [], []
            for name in self.ungated_categories:
                match = normalise(name)
                (resolved if match else unknown).append(match or name)
            if unknown:
                raise ConfigError(
                    "SECURITY_SCAN_UNGATED_CATEGORIES names {} that the agent "
                    "never reports, so it would exclude nothing while looking "
                    "as though it excluded something. Valid categories: "
                    "{}".format(
                        ", ".join(repr(u) for u in unknown),
                        ", ".join(categories()))
                )
            self.ungated_categories = tuple(resolved)

        if self.mode not in ("auto", "diff", "repo"):
            raise ConfigError(
                "SECURITY_SCAN_MODE must be auto|diff|repo, got {!r}".format(self.mode))
        for name, value in (("SECURITY_SCAN_EFFORT", self.effort),
                            ("SECURITY_SCAN_VERIFY_EFFORT", self.verify_effort)):
            if value not in ("low", "medium", "high", "xhigh", "max"):
                raise ConfigError(
                    "{} must be low|medium|high|xhigh|max, got {!r}".format(name, value))
        if self.max_tokens < 4_000:
            raise ConfigError("SECURITY_SCAN_MAX_TOKENS must be at least 4000")
        if self.max_turns < 1:
            raise ConfigError("SECURITY_SCAN_MAX_TURNS must be at least 1")
        if not 1 <= self.verify_concurrency <= 16:
            raise ConfigError("SECURITY_SCAN_VERIFY_CONCURRENCY must be between 1 and 16")
        if not 1 <= self.verify_votes <= 5:
            raise ConfigError("SECURITY_SCAN_VERIFY_VOTES must be between 1 and 5")
        # The API rejects a task budget below 20000; catch it here with a message
        # that names the variable rather than surfacing a raw 400.
        if self.use_task_budget and self.task_budget_tokens < 20_000:
            raise ConfigError("SECURITY_SCAN_TASK_BUDGET must be at least 20000")
        if self.cache_ttl not in ("5m", "1h"):
            raise ConfigError("SECURITY_SCAN_CACHE_TTL must be 5m or 1h")

    # -------------------------------------------------------------- derived

    @property
    def fail_threshold(self) -> Optional[str]:
        return None if self.fail_on == "none" else self.fail_on

    @property
    def verifier_model(self) -> str:
        return self.verify_model or self.model

    def pricing(self) -> tuple:
        return MODEL_PRICING.get(self.model, (5.0, 25.0))

    def resolve_mode(self) -> str:
        """Pick diff vs. repo when the mode is left on ``auto``.

        A merge request has a well-defined base to diff against, so review what
        the author changed. Anything else — a scheduled run, a push to the
        default branch — has no meaningful base, so review the tree.
        """
        if self.mode != "auto":
            return self.mode
        return "diff" if self.gitlab.is_merge_request else "repo"

    def resolved_prompt_dir(self) -> Path:
        """Locate the prompt directory — never inside the repository under review.

        The system prompt is what keeps the agent from treating repository
        content as instructions. Loading it from the working directory would
        hand that control to whoever opened the merge request, so the search
        covers only the operator's own setting and the agent's installation.

        That rule was written here three times and enforced nowhere: the check
        was only that two files exist. Anthropic's action ships the same hole as
        a feature — its false-positive instructions are read from a path inside
        the checkout, so on a `pull_request` build the author of the change
        supplies the rules used to filter findings about it. Criticising that
        while relying on documentation for the same guarantee was not a
        position worth keeping.

        `repo_root` is the repository under review. Passing it turns the rule
        into a check; omitting it keeps the old behaviour for callers that have
        no repository in hand, such as `--version`.
        """
        candidates = []
        if self.prompt_dir:
            candidates.append(Path(self.prompt_dir))
        # Source checkout: src/security_agent/config.py -> <repo>/prompts
        candidates.append(Path(__file__).resolve().parents[2] / "prompts")
        # Installed layout: site-packages/security_agent/ -> /opt/security-agent/prompts
        candidates.append(Path("/opt/security-agent/prompts"))

        for candidate in candidates:
            if (candidate / "system.md").is_file() and (
                candidate / "findings.schema.json"
            ).is_file():
                return candidate.resolve()

        raise ConfigError(
            "cannot find the prompt directory (needs system.md and "
            "findings.schema.json). Looked in: {}. Set SECURITY_SCAN_PROMPT_DIR "
            "to the agent's own prompts directory — never to a path inside the "
            "repository being reviewed.".format(
                ", ".join(str(c) for c in candidates))
        )
