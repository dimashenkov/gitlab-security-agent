"""Configuration, resolved from CI variables with CLI overrides on top."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Sequence

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
class GitLabContext:
    """The slice of GitLab's predefined variables the agent actually uses."""

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
    def from_env(cls) -> "GitLabContext":
        return cls(
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

    # --- verification (layer 2/3 of the hallucination check) ---
    verify: bool = True
    verify_votes: int = 1
    verify_model: str = ""  # falls back to `model`
    verify_effort: str = "high"
    verify_max_findings: int = 40

    # --- gating ---
    fail_on: str = "high"  # critical | high | medium | low | none
    min_confidence: str = "medium"
    fail_on_incomplete: bool = True
    gate_pre_existing: bool = False

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
            verify_max_findings=_env_int("SECURITY_SCAN_VERIFY_MAX", 40),
            fail_on=_env("SECURITY_SCAN_FAIL_ON", "high"),
            min_confidence=_env("SECURITY_SCAN_MIN_CONFIDENCE", "medium"),
            fail_on_incomplete=_env_bool("SECURITY_SCAN_FAIL_ON_INCOMPLETE", True),
            gate_pre_existing=_env_bool("SECURITY_SCAN_GATE_PRE_EXISTING", False),
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
