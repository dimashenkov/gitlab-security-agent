"""What makes two reviews the same review.

Two questions need this and they pull in the same direction. Can a repeated
pipeline reuse a result instead of paying for it again? And can two results be
compared at all, or are they about different things? Both are answered by the
same digest, so there is one definition rather than two that drift.

Anthropic's action solves the cost half by running once per pull request, keyed
on a cache marker. That is too coarse: a new commit is new code, and reusing an
older review for it reports on something that no longer exists. Their own issue
tracker carries a report of prefix cache matching skipping new commits, which
is that failure arriving.

Keyed on the **requested** model, never the served one. A server-side fallback
can substitute a model mid-review, so the served model is a fact about a
finished run and cannot be part of a key computed before one starts. It is
recorded in provenance and it is why `baseline.py` refuses a comparison across
it — different question, same field.

Nothing here decides *whether* to reuse. It says what would have to match.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Dict


def review_identity(cfg: Any, revision: Any, provenance: Any) -> Dict[str, Any]:
    """Everything that has to be equal for two reviews to be the same one.

    A field left out is a field that can change without anyone being told,
    which is how a stale result gets reused for code it never saw.
    """
    return {
        # What was read. Both, not just head: the same commit reviewed against
        # a different base is a different diff and a different review.
        "base_sha": getattr(revision, "base_sha", "") or "",
        "head_sha": getattr(revision, "head_sha", "") or "",
        "mode": getattr(revision, "mode", "") or "",
        # What read it.
        "agent_version": getattr(provenance, "agent_version", "") or "",
        "model_requested": getattr(provenance, "model_requested", "") or "",
        "system_prompt_sha": getattr(provenance, "system_prompt_sha", "") or "",
        "verifier_prompt_sha": getattr(provenance, "verifier_prompt_sha", "") or "",
        "schema_sha": getattr(provenance, "schema_sha", "") or "",
        # Under what policy. The gate settings change which findings are
        # verified at all, so a result produced under one is not a result under
        # another even when the code is identical.
        "settings": {
            "fail_on": getattr(cfg, "fail_on", ""),
            "min_confidence": getattr(cfg, "min_confidence", ""),
            "gate_pre_existing": bool(getattr(cfg, "gate_pre_existing", False)),
            "gate_removed_controls": bool(getattr(cfg, "gate_removed_controls", False)),
            "ungated_categories": sorted(getattr(cfg, "ungated_categories", ()) or ()),
            "verify": bool(getattr(cfg, "verify", True)),
            "verify_votes": getattr(cfg, "verify_votes", 0),
            "effort": getattr(cfg, "effort", ""),
            # What the verifier was shown to start from. A run that
            # saw whole files is not comparable with one that saw a
            # window around each finding.
            "verifier_context_chars": getattr(cfg, "verifier_context_chars", 0),
            # What the model was allowed to see. Changing the exclusions
            # changes the review without changing a line of code.
            "excludes": sorted(getattr(cfg, "excludes", ()) or ()),
        },
    }


def digest(identity: Dict[str, Any]) -> str:
    """A short stable key for the identity above."""
    return hashlib.sha256(
        json.dumps(identity, sort_keys=True, default=str).encode("utf-8")
    ).hexdigest()[:16]


def reusable(previous: Dict[str, Any], current: Dict[str, Any]) -> bool:
    """Would the earlier artifact answer the current question?

    Only when the identity matches **and** the earlier run finished. An
    incomplete run is not a cheaper result, it is an absent one, and caching it
    as an answer is the same confusion that turned three reviews which never
    ran into a 2-of-6 recall figure.
    """
    if not previous.get("complete"):
        return False
    return digest(previous.get("identity") or {}) == digest(current)
