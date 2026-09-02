"""Rendering the review: a Markdown report and a machine-readable artifact.

The report is written for the person deciding whether to trust it. Every finding
carries the code it is about, the exploit path claimed for it, and the verdict
of the verifier that tried to refute it — so a reviewer can overrule the gate on
evidence instead of on faith. Findings that were dropped are shown too, in their
own sections, for the same reason.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set

from . import AUTHOR_URL, PROJECT_NAME, PROJECT_URL, __version__
from .config import Config
from .gate import Decision
from .identity import review_identity
from .models import (
    SEVERITY_EMOJI,
    STOP_EXPLANATIONS,
    VERDICT_CONFIRMED,
    VERDICT_UNCERTAIN,
    Candidate,
    ScanOutcome,
    severity_rank,
)
from .rendering import Rendered, code_span, plain


# Lets GitLab find and update the agent's own note instead of adding a new one
# on every pipeline run.
class ReportError(Exception):
    """The report cannot be written where it was asked to go."""


log = logging.getLogger(__name__)

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
        # Escaped like every other sentence the model contributes. This was the
        # sixth of six report sections to interpolate model text raw, and the
        # only one left after the other five were fixed — it sits directly under
        # the verdict line, so a summary carrying `</blockquote>` and a heading
        # of its own renders a second, attacker-chosen banner inside the comment
        # the security agent posts under its name.
        #
        # `plain` collapses to one line, which is right here: its documented
        # precondition is never to be placed at the start of a line, and a
        # blockquote continuation is exactly that.
        lines += ["", "> " + plain(outcome.summary), ""]

    if not outcome.complete:
        lines += _incomplete_warning(outcome)

    lines += _truncated_diff_note(outcome)
    lines += _whole_diff_note(outcome)
    lines += _context_refusal_note(outcome)
    lines += _scope_note(cfg, outcome)
    lines += _sign_off(outcome)

    blocking_ids = {id(c) for c in decision.blocking}
    blocking = decision.blocking
    other = [c for c in outcome.reported if id(c) not in blocking_ids]

    if blocking:
        lines += ["", "---", "", "## Blocking findings", ""]
        lines += _findings_section(cfg, blocking)

    if other:
        title = "## Other findings" if blocking else "## Findings"
        lines += ["", "---", "", title, ""]
        if blocking:
            lines.append("_These do not block the merge._")
            lines.append("")
        lines += _findings_section(cfg, other, {id(c) for c in decision.policy_excluded})

    if outcome.refuted:
        # Split by what the refutation cost. A refuted finding that would
        # otherwise have blocked is the exact thing a prompt-injection payload
        # aims at: the working attacks do not erase the finding, they leave it
        # in the report and move its disposition. Collapsing those behind a
        # `<details>` is how an attacker-influenced disposition becomes hidden
        # evidence — so they are shown open, with the caveat, and the reader
        # decides. The rest stay collapsed; a refuted `low` is noise.
        loud = [c for c in outcome.refuted if _would_have_blocked(cfg, c)]
        quiet = [c for c in outcome.refuted if c not in loud]
        if loud:
            lines += [
                "",
                "---",
                "",
                "## Disputed — found, then not confirmed ({})".format(len(loud)),
                "",
                "> [!WARNING]",
                "> A verifier read the code and could not confirm these, so they "
                "do not block. Each would have, had it been confirmed.",
                "> **Comments and documentation in the reviewed repository are "
                "input to the model, not evidence.** Text written by whoever "
                "opened this merge request may have influenced the disposition "
                "below. Read the code, not the verdict.",
                "",
            ]
            lines += _refuted_section(cfg, loud)
        if quiet:
            lines += _collapsed(
                "Refuted during verification ({})".format(len(quiet)),
                _refuted_section(cfg, quiet),
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


def _would_have_blocked(cfg: Config, candidate: Candidate) -> bool:
    """Would this candidate have blocked, if the verifier had confirmed it?

    Asked of the model's own severity and confidence rather than the derived
    ones, because a refutation is what stopped the derivation. This is the set
    an attacker is aiming at, and the set that must not be hidden.
    """
    if cfg.fail_threshold is None:
        return False
    if candidate.finding.category.lower() in {c.lower() for c in cfg.ungated_categories}:
        return False
    if not candidate.in_changed_lines and not cfg.gate_pre_existing:
        return False
    return severity_rank(candidate.finding.severity) >= severity_rank(cfg.fail_on)


def _header(cfg: Config, outcome: ScanOutcome, decision: Decision) -> List[str]:
    # Keyed on whether the review finished, NOT on the exit code. Those come
    # apart: `SECURITY_SCAN_FAIL_ON_INCOMPLETE=false` makes the gate return 0
    # on a review that stopped early, and this then printed "✅ no findings" —
    # the one line a reader sees in the merge request preview — over a review
    # that never looked. The warning further down the body does not undo a
    # green tick at the top.
    if not outcome.complete:
        return [
            "## ⚠️ AI security review did not complete",
            "",
            # Escaped: `decide` builds this sentence around `stop_detail`, and
            # on the CLI runner that carries the tail of the child's standard
            # error — file names, git's messages about them, tool summaries.
            # A test written for the warning further down found it here, three
            # lines under the banner a reader trusts most.
            plain(decision.reason) if decision.reason else STOP_EXPLANATIONS.get(
                outcome.stop_reason, "the review did not finish"),
        ]
    if decision.exit_code == 2:
        return ["## ⚠️ AI security review did not complete", "",
                plain(decision.reason)]
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
    disputed = [c for c in outcome.refuted if _would_have_blocked(cfg, c)]
    if disputed:
        # Quiet only because a verifier disagreed. A green tick here says the
        # opposite of what happened, and it is the line a reader stops at.
        return [
            "## 🟠 AI security review — {} disputed finding{}, none confirmed".format(
                len(disputed), "" if len(disputed) == 1 else "s"),
            "",
            "Each of these would have blocked if the verifier had confirmed it.",
        ]
    # "no findings reported", never "no vulnerabilities". The agent read what
    # it read and said nothing about the rest.
    return ["## ✅ AI security review — no findings reported"]


def _tokens_line(usage) -> str:
    """The token row, or the sentence that replaces it when it would be a lie.

    The partial branch names the count of stages that reported nothing rather
    than the stages themselves: which stage it was is in the artifact, and a
    reader who needs that has it. What they must not be able to do is read
    these figures as the whole review's.
    """
    if not usage.reported:
        return ("**Tokens:** not reported by this runner — absent, not zero, "
                "and this review is not therefore a cheap one")
    counted = (
        "**Tokens:** {:,} in · {:,} out · {:,} read from cache · {:,} written "
        "to cache, across {} request(s)".format(
            usage.input_tokens, usage.output_tokens, usage.cache_read_tokens,
            usage.cache_write_tokens, usage.requests))
    if usage.complete:
        return counted
    return counted + (" — and {} further stage(s) of this review reported "
                      "nothing, so this is a floor and not the total".format(
                          usage.unreported_stages))


def _cost_bit(cost: Optional[float], floor: Optional[float], gaps: int) -> str:
    """The three answers a review can give about what it cost.

    One function, because the three were being decided at two call sites and
    the partial case was missing from both — which is how a total covering one
    of two stages got printed as the total.
    """
    if cost is not None:
        return "~${:.2f}".format(cost)
    if floor is not None:
        return "at least ~${:.2f} — {} stage(s) reported nothing".format(floor, gaps)
    return "cost not reported by this runner"


def _meta_line(cfg: Config, outcome: ScanOutcome) -> List[str]:
    usage = outcome.total_usage()
    input_rate, output_rate = cfg.pricing()
    cost = usage.cost_usd(input_rate, output_rate, cfg.cache_ttl)
    floor = usage.partial_cost_usd(input_rate, output_rate, cfg.cache_ttl)
    bits = [
        "{} mode".format(outcome.mode),
        "{} file{} examined".format(
            len(outcome.files_examined), "" if len(outcome.files_examined) == 1 else "s"),
        "{} tool call{}".format(
            len(outcome.tool_calls), "" if len(outcome.tool_calls) == 1 else "s"),
        "{} turn{}".format(outcome.turns, "" if outcome.turns == 1 else "s"),
        outcome.model,
        # Never `~$0.00` for a run whose usage never arrived. On the Claude
        # Code runner that is every run, and the cheapest-looking line on the
        # comment was the one nobody could substantiate.
        #
        # And never a bare figure for a review only part of which was counted:
        # "at least" is the difference between a total and a floor, and
        # without it a review whose verifier reported nothing shows its review
        # stage's cost as the price of the whole thing.
        _cost_bit(cost, floor, usage.unreported_stages),
    ]
    return ["", "_{}_".format(" · ".join(bits))]


def _incomplete_warning(outcome: ScanOutcome) -> List[str]:
    explanation = STOP_EXPLANATIONS.get(outcome.stop_reason, "the review did not complete")
    lines = [
        "",
        "> [!WARNING]",
        "> **Coverage is partial:** {}. Anything not listed below was not "
        "necessarily checked.".format(explanation),
    ]
    if outcome.stop_detail:
        # Always escaped, never conditionally. On the CLI runner this string can
        # carry the tail of the child's standard error — file names, git's
        # messages about them, tool summaries — and all of that comes from the
        # repository under review.
        lines.append("> {}".format(plain(outcome.stop_detail)))
    if outcome.trace_markdown:
        # The one channel in this document that emits a string without escaping
        # it, so it accepts only a string this project rendered. `Rendered` is a
        # marker type carrying provenance, which a `str` does not — and the
        # first version of this branch decided the same question by counting
        # newlines, which any attacker-authored string can satisfy.
        #
        # Anything else is escaped rather than refused. Refusing would lose the
        # diagnostics of a run that already failed, which is when a person needs
        # them most; escaping keeps them and makes them inert.
        if isinstance(outcome.trace_markdown, Rendered):
            lines += ["", outcome.trace_markdown]
        else:
            log.warning("a crash trace arrived as a plain string and was "
                        "escaped rather than rendered")
            # Prefixed, not bare. `plain` deliberately does not escape `#`,
            # `|` or `-`, and its docstring states the precondition that pays
            # for that: never at the start of a line. Emitting the result at
            # column zero is what makes a collapsed `## heading` a heading
            # again — the escaper doing its job while the caller undoes it.
            lines += ["", "> " + plain(outcome.trace_markdown)]
    return lines


def _truncated_diff_note(outcome: ScanOutcome) -> List[str]:
    """The change was larger than the reviewer could be shown.

    A warning rather than a footnote, and above the verdict rather than under
    it. A reviewer that signed off having seen the first part of a diff has
    reviewed the first part of a change, and nothing else in this document says
    so — the notice appended to the diff itself is read by the model, not by the
    person deciding whether to merge.

    This is not a statement that the change is abnormal. Genuine changes exceed
    the ceiling; what it says is that the review was partial.
    """
    if not outcome.coverage.diff_truncated:
        return []
    return [
        "",
        "> [!WARNING]",
        "> **The change was too large to show in full.** The reviewer was given "
        "the first part of the diff and no more, so anything after that point "
        "was not examined through it. Narrow the review with `--path`, split "
        "the change, or raise `SECURITY_SCAN_DIFF_CEILING_BYTES`, for a "
        "complete reading.",
    ]


def _whole_diff_note(outcome: ScanOutcome) -> List[str]:
    """The whole change was never put in front of the reviewer in one piece.

    A note and not a warning, and not a gate. Whether a healthy review reliably
    asks for the whole diff has never been measured — the artifacts already paid
    for do not record which tools were called — and a rule set from an
    expectation is how the two earlier completeness proposals would have failed
    reviews that were fine. This is the measurement that has to exist before the
    rule, in the document the reader already opens.

    It stays quiet for a truncated diff, and only for that. A cut diff *is* this
    fact in other words — the reviewer was handed the first part of the change —
    and the warning above says so with its own remedy.

    A refused result is not. The refusal counter does not record which tool was
    refused, so silencing on it meant one rejected `read_file` could hide the
    observation about the diff, and the observation is the whole reason this
    fact is recorded rather than gated on. Two notes about two different things
    is the correct amount of noise.
    """
    coverage = outcome.coverage
    if coverage.whole_diff_delivered:
        return []
    if coverage.diff_truncated:
        return []
    return [
        "",
        "> [!NOTE]",
        "> **The change was never shown to the reviewer as a whole.** It worked "
        "from individual files, searches, or the file list. That can be a "
        "complete review and it is not treated as an incomplete one — it is "
        "recorded because what a reviewer was shown is a fact about the run, "
        "not an impression of it.",
    ]


def _context_refusal_note(outcome: ScanOutcome) -> List[str]:
    """The reviewer asked for code and the context budget did not hand it over.

    Beside the truncated-diff warning and for the same reason: the refusal was a
    tool result the *model* read, and the person deciding whether to merge never
    sees it. The remedy is two-sided on purpose — a broad request can be narrowed
    and read, or the limit can be raised — because a warning whose only remedy is
    "configure it differently" gets configured away.
    """
    if outcome.coverage.context_would_refuse:
        # Observing. Nothing was kept out, so this is not a warning about the
        # review — it is the measurement the limit was set to take, and saying
        # it here is what stops somebody enforcing a number nobody checked.
        return [
            "",
            "> [!NOTE]",
            "> **Context limit observed, not enforced.** {} tool result(s) "
            "would have been refused under `SECURITY_SCAN_MAX_CONTEXT_MODE="
            "enforce`. Every one of them was returned in full, so this review "
            "is unaffected.".format(outcome.coverage.context_would_refuse),
        ]
    refusals = outcome.coverage.context_refusals
    if not refusals:
        return []
    return [
        "",
        "> [!WARNING]",
        "> **{} tool result(s) were too large for the review's context budget "
        "and were not returned.** The reviewer asked for code and saw none of "
        "it, so this reading has a hole in it. Narrow those reads, or raise "
        "`SECURITY_SCAN_MAX_CONTEXT`, for a complete review.".format(refusals),
    ]


def _scope_note(cfg: Config, outcome: ScanOutcome) -> List[str]:
    """Say that this run was asked to look at less than the change.

    "No findings" from a scoped review and "no findings" from a full one are
    the same sentence and opposite statements, and the scoped one is the one
    that gets pasted into a merge request. A warning rather than a footnote:
    the reader has to see it before the verdict, not after.
    """
    if not cfg.scope:
        return []

    skipped = outcome.coverage.out_of_scope
    lines = [
        "",
        "> [!WARNING]",
        "> **Scoped review:** only changed files matching {} were reviewed."
        .format(", ".join(_code_span(pattern) for pattern in cfg.scope)),
    ]
    if skipped:
        shown = [_code_span(path) for path in skipped[:8]]
        more = "" if len(skipped) <= 8 else " and {} more".format(len(skipped) - 8)
        lines.append(
            "> {} other changed file(s) were not reviewed: {}{}."
            .format(len(skipped), ", ".join(shown), more))
    lines.append(
        "> This is not a review of the change. Anything outside that scope was "
        "not looked at, whatever this report concludes.")
    return lines


def _sign_off(outcome: ScanOutcome) -> List[str]:
    """What the reviewer could not settle, and whether it signed off at all.

    Both halves say the same thing from opposite ends: a review is not only
    what it found. A gap the reviewer names is worth more to the reader than
    the finding above it, and a review that never said it was done is a review
    whose silence has not been accounted for.
    """
    lines: List[str] = []

    if outcome.unresolved:
        lines += ["", "**Not settled by this review:**", ""]
        # Model-written prose about attacker-authored code — escaped, like
        # every other sentence the model contributes to this document.
        lines += ["- {}".format(_plain(item)) for item in outcome.unresolved]
        lines.append("")

    if outcome.complete and not outcome.finished_explicitly:
        lines += [
            "",
            "> [!NOTE]",
            "> The reviewer stopped without signing off. The run reached the "
            "end of its loop, so this is not a failure — but nothing states "
            "that the review was finished rather than abandoned, and the "
            "summary above is whatever it happened to say last.",
        ]

    return lines


def _findings_section(
    cfg: Config, candidates: Sequence[Candidate],
    excluded_ids: Optional[Set[int]] = None
) -> List[str]:
    excluded_ids = excluded_ids or set()
    lines: List[str] = []
    for candidate in sorted(candidates, key=lambda c: c.sort_key):
        lines += _finding(cfg, candidate, id(candidate) in excluded_ids)
    return lines


def _finding(cfg: Config, candidate: Candidate,
             excluded_by_policy: bool = False) -> List[str]:
    finding = candidate.finding
    emoji = SEVERITY_EMOJI.get(candidate.severity, "⚪")

    tags = ["confidence: {}".format(candidate.confidence)]
    if excluded_by_policy:
        # Beside the finding, not only in the footer. A reader who sees a `high`
        # under a green pipeline decides at that moment whether the tool is
        # broken or the project made a choice.
        tags.append("**not gated — category excluded by policy**")
    if not candidate.in_changed_lines:
        tags.append("pre-existing")
    if candidate.verdict == VERDICT_UNCERTAIN:
        tags.append("unverified chain")
    if candidate.votes:
        agreeing = sum(1 for v in candidate.votes if v.verdict == candidate.verdict)
        tags.append("verified {}/{}".format(agreeing, len(candidate.votes)))

    lines = [
        "### {} `{}` · {} — {}".format(
            emoji, candidate.severity, _plain(finding.category),
            _plain(finding.title)),
        "",
        "{} · {}".format(
            _located(cfg, finding.file, candidate.line), " · ".join(tags)),
        "",
        *_fenced(finding.evidence.strip(), _fence_language(finding.file)),
        "",
        "**What is wrong.** {}".format(_plain(finding.description)),
        "",
        "**How it is exploited.** {}".format(_plain(finding.exploit_scenario)),
        "",
        "**Fix.** {}".format(_plain(finding.recommendation)),
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
            _plain(candidate.verdict_reason),
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


def _refuted_section(cfg: Config, candidates: Sequence[Candidate]) -> List[str]:
    lines: List[str] = []
    for candidate in sorted(candidates, key=lambda c: c.sort_key):
        lines += [
            "**{} `{}` — {}** · {}".format(
                SEVERITY_EMOJI.get(candidate.finding.severity, "⚪"),
                candidate.finding.severity,
                _plain(candidate.finding.title),
                _code_span("{}:{}".format(candidate.finding.file, candidate.line))),
            "",
            "Claimed: {}".format(_plain(candidate.finding.description)),
            "",
            "Refuted: {}".format(
                _plain(candidate.verdict_reason) or "no reason recorded"),
            "",
        ]
    return lines


def _suppressed_section(candidates: Sequence[Candidate]) -> List[str]:
    lines: List[str] = []
    for candidate in sorted(candidates, key=lambda c: c.sort_key):
        lines += [
            "- **{}** ({}, {}) — {}".format(
                _plain(candidate.finding.title),
                _code_span("{}:{}".format(candidate.finding.file, candidate.line)),
                candidate.severity, _plain(candidate.suppressed_by)),
        ]
    return [*lines, ""]


def _rejected_section(outcome: ScanOutcome) -> List[str]:
    reasons = {
        "unknown-path": "cited a file that does not exist",
        "evidence-not-found": "quoted code that is not in the file",
    }
    lines = []
    for claim in outcome.rejected_claims:
        lines.append("- **{}** ({}) — {}".format(
            _plain(claim.title), _code_span(claim.file),
            reasons.get(claim.reason, claim.reason)))
    return [*lines, ""]


def _cost_note(prov) -> str:
    """What the run cost, appended to the billing line, or "".

    The figure was written into the artifact and rendered nowhere, so seeing it
    meant opening JSON. It goes beside `Billing:` and not on a line of its own
    because the two are one fact: a number without who paid it is the confusion
    this project has already built three wrong rules on.

    On the CLI path `total_cost_usd` arrives on a subscription too — a two-token
    reply on a Max plan came back as $0.29 — so it is marked as list price for
    the tokens used rather than presented as an amount charged. When the
    provider reported nothing the line simply does not gain a figure; "$0.00"
    would be a measurement, and there was none.
    """
    cost = getattr(prov, "reported_cost_usd", None)
    if not isinstance(cost, (int, float)):
        return ""
    # From the authentication, not the provider. `claude-cli` says how the run
    # was launched; a CLI whose stored login is an API key is charged, and the
    # first version of this called that notional — the confusion this line was
    # added to resolve, reproduced inside it.
    method = (getattr(prov, "auth_method", "") or "").strip()
    if getattr(prov, "provider", "") == "anthropic-api" or method in ("api-key", "console"):
        return " · **${:.2f}** charged".format(cost)
    if method == "claude.ai" and getattr(prov, "auth_subscription", ""):
        return (" · **${:.2f}** at API list price for the tokens used — "
                "not an amount charged".format(cost))
    # Nobody established how this was billed, so the figure is stated without a
    # claim about who paid it rather than assigned to the cheaper reading.
    return (" · **${:.2f}** at API list price; how this run was billed was "
            "not established".format(cost))


def _coverage_section(cfg: Config, outcome: ScanOutcome, decision: Decision) -> List[str]:
    usage = outcome.total_usage()
    lines: List[str] = []

    # First, because everything below it is a claim about this code and no
    # other. A reader checking a finding needs the commit before the finding.
    revision = outcome.revision
    if revision.head_sha or revision.base_sha:
        lines.append("**Reviewed at:**")
        lines.append("")
        if revision.base_sha:
            lines.append("- base {} ({})".format(
                _code_span(revision.base_sha[:12]), _plain(revision.base) or "resolved"))
        lines.append("- head {} ({})".format(
            _code_span(revision.head_sha[:12]), _plain(revision.head) or "resolved"))
        lines.append("")

    lines += [
        "**Files opened by the agent ({}):**".format(len(outcome.files_examined)),
        "",
    ]
    if outcome.files_examined:
        lines += ["- {}".format(_code_span(path)) for path in sorted(outcome.files_examined)]
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

    prov = outcome.provenance
    lines += [
        "**Provenance:** model `{}`{} · prompts `{}`/`{}` · schema `{}` · agent `{}`".format(
            prov.model_requested,
            # The review's models only. A smaller model serving part of the
            # verification is said separately below rather than in the same
            # breath, because "answered by X" beside the requested model reads
            # as the review having run on X.
            " — **answered by {}**".format(", ".join(prov.review_models))
            if prov.model_substituted else "",
            prov.system_prompt_sha[:8], prov.verifier_prompt_sha[:8],
            prov.schema_sha[:8], prov.agent_version),
        "",
    ]
    if prov.verifier_substituted:
        lines += [
            "Verification was served by {} rather than the requested model. "
            "That is the verifier, not the review — said here rather than "
            "beside the model above, where it would read as the review having "
            "run on something else.".format(", ".join(prov.models_verified)),
            "",
        ]
    if prov.auth_method or prov.auth_subscription:
        # Only when the provider said something. A line reading "not
        # established" on every API run would be noise, and the honest silence
        # is the absence of the line rather than a sentence about not knowing.
        lines += ["**Billing:** {}{}".format(prov.billing, _cost_note(prov)), ""]
    lines += [
        "**Settings:** fail on `{}` · minimum confidence `{}` · verification "
        "`{}`{} · model `{}` · effort `{}`".format(
            cfg.fail_on, cfg.min_confidence,
            "on" if cfg.verify else "off",
            " ({} vote{})".format(cfg.verify_votes, "" if cfg.verify_votes == 1 else "s")
            if cfg.verify else "",
            cfg.model, cfg.effort),
        "",
        # A sentence about the gap, never a row of zeros. `0 in · 0 out · 0
        # read from cache` is a claim that the review used nothing, and on the
        # Claude Code runner — where the CLI's usage block reaches `CliResult`
        # and is read by nobody — it was printed under every single review.
        _tokens_line(usage),
        "",
    ]
    m = outcome.metrics
    cov = outcome.coverage
    if cov.changed:
        lines += [
            "**Coverage:** {} of {} changed file(s) opened{}".format(
                len([f for f in cov.changed if f in set(cov.examined)]),
                len(cov.changed),
                "" if cov.complete else " — not opened: " + ", ".join(
                    "`{}`".format(f) for f in cov.unopened[:8])),
            "",
        ]
    if cov.deleted:
        # Deletions are filtered out of `changed` — that list is what a reviewer
        # is asked to open, and a deleted file cannot be opened — so until this
        # line existed a deletion appeared nowhere in the report. Its removed
        # lines are in the diff and a deleted security control is one of the
        # things this product exists to catch.
        lines += [
            "**Deleted ({}):** {}".format(
                len(cov.deleted),
                ", ".join("`{}`".format(path) for path in cov.deleted[:8])),
            "",
        ]
    if cov.unreadable:
        # Beside the coverage line and not folded into it. "2 of 5 changed
        # files opened" reads as a thin review when three of the five had no
        # line in them to open — and a mode change is still worth a reader's
        # eye, so it is named rather than silently subtracted.
        #
        # "No source lines" rather than "no text to read": a mode header and a
        # submodule's two commit ids are readable and security-relevant, they
        # are simply not source. The looser wording said something false about
        # exactly the entries it was listing.
        lines += [
            "**No source lines to read ({}):** {}".format(
                len(cov.unreadable),
                ", ".join("`{}` ({})".format(path, why)
                          for path, why in cov.unreadable[:8])),
            "",
        ]
    rejected = (m.citations_rejected_not_found + m.citations_rejected_ambiguous
                + m.citations_rejected_too_short + m.citations_rejected_unknown_path)
    if m.citations_accepted or rejected:
        lines += [
            "**Citation checks:** {} accepted, {} rejected{}{}".format(
                m.citations_accepted, rejected,
                " ({} ambiguous)".format(m.citations_rejected_ambiguous)
                if m.citations_rejected_ambiguous else "",
                " · {} line(s) corrected".format(m.lines_corrected)
                if m.lines_corrected else ""),
            "",
            "**Verification:** {} verified, {} skipped as non-blocking, "
            "{} changed a verdict{}".format(
                m.verified, m.verification_skipped, m.verdicts_changed,
                " · {} could not run".format(m.verification_failed)
                if m.verification_failed else ""),
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
    # "Experimental" in the footer of every report, not only in a README
    # nobody opens. The measured evidence is a regression suite of this
    # project's own construction; there is no production deployment and no
    # independent adjudication behind any number here, and a report that does
    # not say so will be read as though there were.
    return (
        "<sub>**Experimental.** Reviewed by an AI agent using `{}`. Findings "
        "are checked against the real files and independently verified, but "
        "this is an assistant, not a substitute for review, and a quiet result "
        "is not evidence that the change is safe. {}{}<br>"
        "[{}]({}) v{} — by [Dimitar Shenkov]({}), MIT licensed.</sub>".format(
            outcome.model, when, tail, PROJECT_NAME, PROJECT_URL, __version__,
            AUTHOR_URL)
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


def _fenced(code: str, language: str) -> List[str]:
    """A code block that attacker-authored code cannot break out of.

    The quoted code is written by whoever opened the merge request. A fixed
    three-backtick fence ends the moment their code contains one, and every
    line after that renders as report content — headings, links, raw HTML —
    published by a bot holding a GitLab token, under the security tool's name.
    A contributor could make the security report say anything.

    CommonMark closes a fence only on a run of backticks at least as long as
    the one that opened it, so the fence is made one longer than the longest
    run in the content. The code itself is never altered: mangling the evidence
    would break the one property layer 1 exists to guarantee — that the quote
    matches the file.
    """
    longest = 0
    run = 0
    for character in code:
        run = run + 1 if character == "`" else 0
        longest = max(longest, run)
    fence = "`" * max(3, longest + 1)
    return [fence + language, code, fence]


# The two escaping rules live in `rendering` because the crash trace needs
# them too, and a second implementation of a containment rule is a second
# thing to get right. Bound to local names so the call sites below read the
# same as they did when the functions were defined here.
_plain = plain
_code_span = code_span


def _located(cfg: Config, path: str, line: int) -> str:
    """`path:line` as a code span, linked to the commit when one is known."""
    from .config import blob_url

    label = _code_span("{}:{}".format(path, line))
    url = blob_url(cfg.gitlab, path, line)
    # The label keeps its span, so a hostile path is still inert inside the
    # link text; the URL itself is built from the path and is only ever
    # emitted when the forge context supplied a commit.
    return "[{}]({})".format(label, url) if url else label


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
        # Two different questions. `complete` is whether the run reached the end
        # of its loop; this is whether the reviewer said it was done. A provider
        # that owns its loop can satisfy the first without the second, which is
        # exactly the case this product must not render as a clean review.
        "finished_explicitly": outcome.finished_explicitly,
        "unresolved": list(outcome.unresolved),
        "stop_reason": outcome.stop_reason,
        "stop_detail": outcome.stop_detail,
        "trace_markdown": outcome.trace_markdown,
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
            # What actually reached the model, `(path, channel)`, and the only
            # record that any of the change was inspected at all. The gate has
            # read it in-process since the six-way exit-0 hole; it was never
            # written down, so nothing *reading the artifact* could tell a
            # review from a run that never got anything to read. `reusable`
            # now needs it — a skipped run writes a complete artifact with an
            # exit code of 0, and without this it was a cacheable clean bill
            # of health for code nobody looked at.
            "exposures": sorted(list(e) for e in outcome.exposures),
            "turns": outcome.turns,
            "tool_calls": [
                {"turn": t.turn, "tool": t.name, "summary": t.summary, "rejected": t.is_error}
                for t in outcome.tool_calls
            ],
        },
        "usage": usage.to_dict(),
        # Which commits were read. A finding is a claim about code at a
        # moment, and an artifact recording only `HEAD` cannot say which.
        "revision": outcome.revision.to_dict(),
        # What would have to match for another run to be the same review — the
        # key for reusing this artifact instead of paying for it again, and the
        # same one `baseline.py` refuses a comparison across.
        "identity": review_identity(cfg, outcome.revision, outcome.provenance,
                                    outcome.suppressions_digest),
        "provenance": outcome.provenance.to_dict(),
        "coverage_accounting": outcome.coverage.to_dict(),
        "stage_metrics": outcome.metrics.to_dict(),
        # Per turn, not just the total. A total says what a review cost
        # and nothing about where it went, and "which turn, holding how
        # much, asking for how much room" is the question an incomplete
        # run has to answer from its own artifact.
        "turns_detail": [r.to_dict() for r in outcome.turn_records],
        "settings": {
            "fail_on": cfg.fail_on,
            "min_confidence": cfg.min_confidence,
            "gate_pre_existing": cfg.gate_pre_existing,
            # Recorded because an archived artifact has to be able to say which
            # policy produced it. Without this, two runs of the same code under
            # opposite gating settings are indistinguishable after the fact,
            # and any experiment comparing them is unfalsifiable.
            "gate_removed_controls": cfg.gate_removed_controls,
            "ungated_categories": list(cfg.ungated_categories),
            "verify": cfg.verify,
            "verify_votes": cfg.verify_votes,
            "effort": cfg.effort,
            # An empty list means the whole change. Recorded either way, because
            # "no findings" from a scoped run and "no findings" from a full one
            # are the same sentence and opposite statements.
            "scope": list(cfg.scope),
        },
    }


def _safe_output_dir(requested: Path) -> Path:
    """Refuse to write the report through anything the repository controls.

    The default output directory sits inside the checkout, and the report file
    names are fixed. A committed symlink at that path redirects both writes
    somewhere of the contributor's choosing — the report is written by a job
    that has a GitLab token, so where it lands is not a cosmetic question.

    Any symlink on the path is refused rather than resolved. Resolving it would
    "work", which is the problem: the write would silently go somewhere else.
    Set SECURITY_SCAN_OUTPUT_DIR to a runner-provided directory outside the
    checkout to avoid the question entirely.
    """
    requested = Path(requested)
    probe = requested if requested.is_absolute() else Path.cwd() / requested
    walked = Path(probe.anchor or ".")
    for part in probe.parts[1:] if probe.anchor else probe.parts:
        walked = walked / part
        if walked.is_symlink():
            raise ReportError(
                "refusing to write the report through the symlink at {}. The "
                "output path must not pass through a link the repository "
                "controls; set SECURITY_SCAN_OUTPUT_DIR to a directory outside "
                "the checkout.".format(walked)
            )

    requested.mkdir(parents=True, exist_ok=True)
    for name in ("report.md", "findings.json"):
        target = requested / name
        if target.is_symlink():
            raise ReportError(
                "refusing to overwrite {}: it is a symlink, and the report "
                "would be written to wherever it points.".format(target))
    return requested


def write_artifacts(
    cfg: Config, outcome: ScanOutcome, decision: Decision
) -> Dict[str, str]:
    """Write the report and the JSON result. Returns {kind: path}."""
    out_dir = _safe_output_dir(cfg.output_dir)
    markdown_path = out_dir / "report.md"
    json_path = out_dir / "findings.json"

    markdown_path.write_text(render_markdown(cfg, outcome, decision), encoding="utf-8")
    json_path.write_text(
        json.dumps(build_json(cfg, outcome, decision), indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return {"markdown": str(markdown_path), "json": str(json_path)}


# The job log view lives in `terminal.py`. It is a different document for a
# different reader — skimmed in a browser while a pipeline runs, not read as a
# report — and keeping it here invited the two to drift into one mediocre
# format that served neither.
