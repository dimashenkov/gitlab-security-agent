"""Rendering the review: a Markdown report and a machine-readable artifact.

The report is written for the person deciding whether to trust it. Every finding
carries the code it is about, the exploit path claimed for it, and the verdict
of the verifier that tried to refute it — so a reviewer can overrule the gate on
evidence instead of on faith. Findings that were dropped are shown too, in their
own sections, for the same reason.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Sequence

from .config import Config
from .gate import Decision
from .models import (
    SEVERITY_EMOJI,
    STOP_EXPLANATIONS,
    VERDICT_CONFIRMED,
    VERDICT_UNCERTAIN,
    Candidate,
    ScanOutcome,
)

# Lets GitLab find and update the agent's own note instead of adding a new one
# on every pipeline run.
COMMENT_MARKER = "<!-- ai-security-scan -->"

_FENCE_LANGUAGES = {
    "py": "python", "js": "javascript", "jsx": "javascript", "mjs": "javascript",
    "cjs": "javascript", "ts": "typescript", "tsx": "tsx", "rb": "ruby",
    "go": "go", "java": "java", "kt": "kotlin", "cs": "csharp", "php": "php",
    "rs": "rust", "c": "c", "h": "c", "cc": "cpp", "cpp": "cpp", "hpp": "cpp",
    "swift": "swift", "sh": "bash", "bash": "bash", "zsh": "bash", "ps1": "powershell",
    "sql": "sql", "yml": "yaml", "yaml": "yaml", "json": "json", "tf": "hcl",
    "html": "html", "htm": "html", "css": "css", "scss": "scss", "vue": "vue",
    "ex": "elixir", "exs": "elixir", "scala": "scala", "pl": "perl", "m": "objectivec",
}


def render_markdown(cfg: Config, outcome: ScanOutcome, decision: Decision) -> str:
    lines: List[str] = [COMMENT_MARKER, ""]
    lines += _header(cfg, outcome, decision)
    lines += _meta_line(cfg, outcome)

    if outcome.summary:
        lines += ["", "> " + outcome.summary.replace("\n", "\n> "), ""]

    if not outcome.complete:
        lines += _incomplete_warning(outcome)

    blocking_ids = {id(c) for c in decision.blocking}
    blocking = decision.blocking
    other = [c for c in outcome.reported if id(c) not in blocking_ids]

    if blocking:
        lines += ["", "---", "", "## Blocking findings", ""]
        lines += _findings_section(blocking)

    if other:
        title = "## Other findings" if blocking else "## Findings"
        lines += ["", "---", "", title, ""]
        if blocking:
            lines.append("_These do not block the merge._")
            lines.append("")
        lines += _findings_section(other)

    if outcome.refuted:
        lines += _collapsed(
            "Refuted during verification ({})".format(len(outcome.refuted)),
            _refuted_section(outcome.refuted),
            note=(
                "An independent verifier read the code and could not confirm "
                "these. They are kept here so you can overrule that call."
            ),
        )

    if outcome.suppressed:
        lines += _collapsed(
            "Suppressed by {} ({})".format(cfg.ignore_file, len(outcome.suppressed)),
            _suppressed_section(outcome.suppressed),
        )

    if outcome.rejected_claims:
        lines += _collapsed(
            "Claims rejected before reporting ({})".format(len(outcome.rejected_claims)),
            _rejected_section(outcome),
            note=(
                "The agent proposed these but could not point at code that "
                "matched them, so they were never recorded."
            ),
        )

    lines += _collapsed("What was reviewed", _coverage_section(cfg, outcome, decision))

    if decision.non_blocking_reasons:
        lines += [
            "",
            "_Not gated on: {}._".format("; ".join(decision.non_blocking_reasons)),
        ]

    lines += ["", "---", "", _footer(cfg, outcome)]
    return "\n".join(lines).rstrip() + "\n"


# ------------------------------------------------------------------- sections


def _header(cfg: Config, outcome: ScanOutcome, decision: Decision) -> List[str]:
    if decision.exit_code == 2:
        return ["## ⚠️ AI security review did not complete", "", decision.reason]
    if decision.blocking:
        worst = SEVERITY_EMOJI.get(decision.blocking[0].severity, "🔴")
        return [
            "## {} AI security review — {} blocking finding{}".format(
                worst, len(decision.blocking),
                "" if len(decision.blocking) == 1 else "s"),
            "",
            decision.reason,
        ]
    if outcome.reported:
        return [
            "## 🟡 AI security review — {} finding{}, none blocking".format(
                len(outcome.reported), "" if len(outcome.reported) == 1 else "s"),
        ]
    return ["## ✅ AI security review — no findings"]


def _meta_line(cfg: Config, outcome: ScanOutcome) -> List[str]:
    usage = outcome.total_usage()
    input_rate, output_rate = cfg.pricing()
    bits = [
        "{} mode".format(outcome.mode),
        "{} file{} examined".format(
            len(outcome.files_examined), "" if len(outcome.files_examined) == 1 else "s"),
        "{} tool call{}".format(
            len(outcome.tool_calls), "" if len(outcome.tool_calls) == 1 else "s"),
        "{} turn{}".format(outcome.turns, "" if outcome.turns == 1 else "s"),
        outcome.model,
        "~${:.2f}".format(usage.cost_usd(input_rate, output_rate)),
    ]
    return ["", "_{}_".format(" · ".join(bits))]


def _incomplete_warning(outcome: ScanOutcome) -> List[str]:
    explanation = STOP_EXPLANATIONS.get(outcome.stop_reason, "the review did not complete")
    detail = " — {}".format(outcome.stop_detail) if outcome.stop_detail else ""
    return [
        "",
        "> [!WARNING]",
        "> **Coverage is partial:** {}{}. Anything not listed below was not "
        "necessarily checked.".format(explanation, detail),
    ]


def _findings_section(candidates: Sequence[Candidate]) -> List[str]:
    lines: List[str] = []
    for candidate in sorted(candidates, key=lambda c: c.sort_key):
        lines += _finding(candidate)
    return lines


def _finding(candidate: Candidate) -> List[str]:
    finding = candidate.finding
    emoji = SEVERITY_EMOJI.get(candidate.severity, "⚪")

    tags = ["confidence: {}".format(candidate.confidence)]
    if not candidate.in_changed_lines:
        tags.append("pre-existing")
    if candidate.verdict == VERDICT_UNCERTAIN:
        tags.append("unverified chain")
    if candidate.votes:
        agreeing = sum(1 for v in candidate.votes if v.verdict == candidate.verdict)
        tags.append("verified {}/{}".format(agreeing, len(candidate.votes)))

    lines = [
        "### {} `{}` · {} — {}".format(
            emoji, candidate.severity, finding.category, finding.title),
        "",
        "`{}:{}` · {}".format(finding.file, candidate.line, " · ".join(tags)),
        "",
        "```{}".format(_fence_language(finding.file)),
        finding.evidence.strip(),
        "```",
        "",
        "**What is wrong.** {}".format(finding.description.strip()),
        "",
        "**How it is exploited.** {}".format(finding.exploit_scenario.strip()),
        "",
        "**Fix.** {}".format(finding.recommendation.strip()),
        "",
    ]

    if candidate.verdict_reason:
        label = (
            "Verification" if candidate.verdict == VERDICT_CONFIRMED
            else "Verification — {}".format(candidate.verdict)
        )
        lines += [
            "<details><summary>{}</summary>".format(label),
            "",
            candidate.verdict_reason,
            "",
            "</details>",
            "",
        ]

    lines += [
        "<sub>Accept this risk by adding `fingerprint: {}` to "
        "`.security-agent-ignore.yml` with a reason.</sub>".format(candidate.fingerprint),
        "",
    ]
    return lines


def _refuted_section(candidates: Sequence[Candidate]) -> List[str]:
    lines: List[str] = []
    for candidate in sorted(candidates, key=lambda c: c.sort_key):
        lines += [
            "**{} `{}` — {}** · `{}:{}`".format(
                SEVERITY_EMOJI.get(candidate.finding.severity, "⚪"),
                candidate.finding.severity,
                candidate.finding.title,
                candidate.finding.file,
                candidate.line),
            "",
            "Claimed: {}".format(candidate.finding.description.strip()),
            "",
            "Refuted: {}".format(candidate.verdict_reason or "no reason recorded"),
            "",
        ]
    return lines


def _suppressed_section(candidates: Sequence[Candidate]) -> List[str]:
    lines: List[str] = []
    for candidate in sorted(candidates, key=lambda c: c.sort_key):
        lines += [
            "- **{}** (`{}:{}`, {}) — {}".format(
                candidate.finding.title, candidate.finding.file, candidate.line,
                candidate.severity, candidate.suppressed_by),
        ]
    return [*lines, ""]


def _rejected_section(outcome: ScanOutcome) -> List[str]:
    reasons = {
        "unknown-path": "cited a file that does not exist",
        "evidence-not-found": "quoted code that is not in the file",
    }
    lines = []
    for claim in outcome.rejected_claims:
        lines.append("- **{}** (`{}`) — {}".format(
            claim.title, claim.file,
            reasons.get(claim.reason, claim.reason)))
    return [*lines, ""]


def _coverage_section(cfg: Config, outcome: ScanOutcome, decision: Decision) -> List[str]:
    usage = outcome.total_usage()
    lines = [
        "**Files opened by the agent ({}):**".format(len(outcome.files_examined)),
        "",
    ]
    if outcome.files_examined:
        lines += ["- `{}`".format(path) for path in sorted(outcome.files_examined)]
    else:
        lines.append("- _none_")

    lines += [
        "",
        "**Investigation:** {} turns, {} tool calls".format(
            outcome.turns, len(outcome.tool_calls)),
        "",
    ]

    counts: Dict[str, int] = {}
    for call in outcome.tool_calls:
        counts[call.name] = counts.get(call.name, 0) + 1
    if counts:
        lines.append("| Tool | Calls |")
        lines.append("| --- | --- |")
        for name, count in sorted(counts.items(), key=lambda kv: -kv[1]):
            lines.append("| `{}` | {} |".format(name, count))
        lines.append("")

    lines += [
        "**Settings:** fail on `{}` · minimum confidence `{}` · verification "
        "`{}`{} · model `{}` · effort `{}`".format(
            cfg.fail_on, cfg.min_confidence,
            "on" if cfg.verify else "off",
            " ({} vote{})".format(cfg.verify_votes, "" if cfg.verify_votes == 1 else "s")
            if cfg.verify else "",
            cfg.model, cfg.effort),
        "",
        "**Tokens:** {:,} in · {:,} out · {:,} read from cache · {:,} written to "
        "cache, across {} request(s)".format(
            usage.input_tokens, usage.output_tokens,
            usage.cache_read_tokens, usage.cache_write_tokens, usage.requests),
        "",
    ]
    if outcome.duplicates_dropped:
        lines.append("**Duplicate reports collapsed:** {}".format(outcome.duplicates_dropped))
        lines.append("")
    return lines


def _footer(cfg: Config, outcome: ScanOutcome) -> str:
    when = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    job = cfg.gitlab.job_url
    tail = " · [job log]({})".format(job) if job else ""
    return (
        "<sub>Reviewed by an AI agent using `{}`. Findings are checked against "
        "the real files and independently verified, but this is an assistant, "
        "not a substitute for review. {}{}</sub>".format(outcome.model, when, tail)
    )


def _collapsed(title: str, body: Sequence[str], note: str = "") -> List[str]:
    if not body:
        return []
    lines = ["", "<details><summary>{}</summary>".format(title), ""]
    if note:
        lines += ["_{}_".format(note), ""]
    lines += list(body)
    lines += ["", "</details>", ""]
    return lines


def _fence_language(path: str) -> str:
    ext = path.rsplit(".", 1)[-1].lower() if "." in path else ""
    return _FENCE_LANGUAGES.get(ext, "")


# ------------------------------------------------------------------ artifact


def build_json(cfg: Config, outcome: ScanOutcome, decision: Decision) -> Dict[str, Any]:
    """The machine-readable result, for artifacts and downstream tooling."""
    usage = outcome.total_usage()
    return {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "summary": outcome.summary,
        "mode": outcome.mode,
        "model": outcome.model,
        "complete": outcome.complete,
        "stop_reason": outcome.stop_reason,
        "stop_detail": outcome.stop_detail,
        "verdict": {
            "exit_code": decision.exit_code,
            "blocked": decision.blocked,
            "reason": decision.reason,
            "blocking_fingerprints": [c.fingerprint for c in decision.blocking],
            "not_gated_on": decision.non_blocking_reasons,
        },
        "counts": {
            "reported": len(outcome.reported),
            "blocking": len(decision.blocking),
            "refuted": len(outcome.refuted),
            "suppressed": len(outcome.suppressed),
            "rejected_claims": len(outcome.rejected_claims),
            "by_severity": outcome.counts_by_severity(),
        },
        "findings": [c.to_dict() for c in sorted(outcome.reported, key=lambda c: c.sort_key)],
        "refuted": [c.to_dict() for c in outcome.refuted],
        "suppressed": [c.to_dict() for c in outcome.suppressed],
        "rejected_claims": [
            {"title": c.title, "file": c.file, "reason": c.reason, "detail": c.detail}
            for c in outcome.rejected_claims
        ],
        "coverage": {
            "files_examined": sorted(outcome.files_examined),
            "turns": outcome.turns,
            "tool_calls": [
                {"turn": t.turn, "tool": t.name, "summary": t.summary, "rejected": t.is_error}
                for t in outcome.tool_calls
            ],
        },
        "usage": usage.to_dict(),
        "settings": {
            "fail_on": cfg.fail_on,
            "min_confidence": cfg.min_confidence,
            "gate_pre_existing": cfg.gate_pre_existing,
            "verify": cfg.verify,
            "verify_votes": cfg.verify_votes,
            "effort": cfg.effort,
        },
    }


def write_artifacts(
    cfg: Config, outcome: ScanOutcome, decision: Decision
) -> Dict[str, str]:
    """Write the report and the JSON result. Returns {kind: path}."""
    cfg.output_dir.mkdir(parents=True, exist_ok=True)
    markdown_path = cfg.output_dir / "report.md"
    json_path = cfg.output_dir / "findings.json"

    markdown_path.write_text(render_markdown(cfg, outcome, decision), encoding="utf-8")
    json_path.write_text(
        json.dumps(build_json(cfg, outcome, decision), indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return {"markdown": str(markdown_path), "json": str(json_path)}


def render_terminal(outcome: ScanOutcome, decision: Decision) -> str:
    """A compact view for the job log, where nobody renders Markdown."""
    lines = ["", "=" * 72]
    for candidate in sorted(outcome.reported, key=lambda c: c.sort_key):
        blocking = "BLOCKS" if candidate in decision.blocking else "      "
        lines.append("{} {:>8} {:<12} {}:{}".format(
            blocking, candidate.severity, candidate.finding.category,
            candidate.finding.file, candidate.line))
        lines.append("         {}".format(candidate.finding.title))
    if not outcome.reported:
        lines.append("No findings reported.")
    lines += ["=" * 72, decision.reason, ""]
    return "\n".join(lines)
