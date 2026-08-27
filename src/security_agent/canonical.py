"""Which half of the artifact is the decision, and which half is the provider.

Two runners will produce the same review and different artifacts. One reports
tokens and the other cannot; one knows how many turns it took and the other
sees a single blob at the end; the served model string carries a date suffix on
one path and not the other. None of that is the review. All of it is in the
same JSON object as the review.

So the comparison between runners needs a line, and this module is the line:

    canonical_result    everything that could change the decision — compared
                        byte for byte
    provider_telemetry  everything that is allowed to differ — validated for
                        shape, never for value

Codex's instruction, which this follows literally: *do not scatter exclusions
across the test.* A conformance test carrying its own list of fields to skip
grows one entry per argument and ends up excluding the thing under test. The
list lives here, once, and the test compares what is left.

**A field nobody classified is canonical.** `TELEMETRY_PATHS` is an allowlist,
not a denylist, so a key added tomorrow is compared until someone decides
otherwise. That direction is deliberate: an unclassified decision field left in
the comparison makes a test fail and someone look; an unclassified decision
field dropped from the comparison makes nothing happen at all. This is the same
rule the gate follows for an unrecognised severity — the unreadable case fails
toward being noticed.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Tuple

# Paths into the artifact that may legitimately differ between runners.
#
# Dotted, with `[]` for "each element of this list". A path naming a container
# takes the whole subtree; a path naming a leaf takes only that leaf.
#
# Each entry is here for a stated reason. "It is noisy" is not one — noise in a
# comparison is a signal that the two runners disagree about something, and the
# entries below are the cases where the disagreement is about the provider
# rather than about the code.
TELEMETRY_PATHS: Tuple[str, ...] = (
    # When the artifact was written. Two runs are never simultaneous.
    "generated_at",
    # Tokens, cache and cost. The Claude Code CLI reports usage per run, the
    # Messages API per turn, and a subscription may report nothing at all —
    # which `budget.py` renders as "not reported by this runner" rather than
    # as zero.
    "usage",
    # Per-turn context and token figures. A runner that returns one JSON
    # document at the end has no per-turn view to report.
    "turns_detail",
    # How many turns the model took. Ours is a count of loop iterations; a
    # provider that runs its own loop counts differently, and neither number
    # changes what was decided.
    "coverage.turns",
    "coverage.tool_calls[].turn",
    # What actually answered. `model_requested` stays canonical — it is part of
    # the review's identity — but the served string carries provider-side
    # detail (a dated variant, a fallback) that identity deliberately excludes.
    "model",
    "provenance.models_served",
    "provenance.model_substituted",
    # The diagnostic under the stop reason. `stop_reason` itself is canonical:
    # "did this run finish" is the decision this project exists to protect.
    # The sentence explaining *how* it failed is provider prose.
    "stop_detail",
    # The crash trace, and only the runner that can be killed mid-review ever
    # produces one. It is diagnostics by construction — `crash_journal` refuses
    # to carry the fields a finding is made of — so it decides nothing, and
    # comparing it would compare which provider died rather than what either
    # concluded.
    "trace_markdown",
)

_MISSING = object()


def _walk(node: Any, segments: List[str], take: bool) -> Any:
    """Return the value at `segments`, removing it from `node` when `take`."""
    head, rest = segments[0], segments[1:]

    if head.endswith("[]"):
        key = head[:-2]
        if not isinstance(node, dict) or key not in node:
            return _MISSING
        items = node[key]
        if not isinstance(items, list):
            return _MISSING
        collected = [_walk(item, rest, take) for item in items]
        collected = [c for c in collected if c is not _MISSING]
        return collected or _MISSING

    if not isinstance(node, dict) or head not in node:
        return _MISSING
    if not rest:
        return node.pop(head) if take else node[head]
    return _walk(node[head], rest, take)


def _place(node: Dict[str, Any], segments: List[str], value: Any) -> None:
    head, rest = segments[0], segments[1:]
    key = head[:-2] if head.endswith("[]") else head
    if not rest:
        node[key] = value
        return
    node.setdefault(key, {})
    _place(node[key], rest, value)


ABSENT = _MISSING


def lookup(artifact: Dict[str, Any], path: str) -> Any:
    """The value at a dotted path, or `ABSENT`. Never modifies the artifact.

    Exists so a test can ask the question that matters about a declared
    exclusion — is this path real, and did it actually leave — rather than
    reconstructing the walk and testing its own reconstruction.
    """
    return _walk(json.loads(json.dumps(artifact)), path.split("."), take=False)


def split(artifact: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Partition one artifact into (canonical_result, provider_telemetry).

    The input is not modified. A declared path that is absent is not an error —
    a runner that reports no usage has no `usage` key, and demanding one would
    turn "this runner cannot tell us" into a crash.
    """
    canonical = json.loads(json.dumps(artifact))
    telemetry: Dict[str, Any] = {}
    for path in TELEMETRY_PATHS:
        segments = path.split(".")
        value = _walk(canonical, segments, take=True)
        if value is not _MISSING:
            _place(telemetry, segments, value)
    return canonical, telemetry


def canonical_bytes(artifact: Dict[str, Any]) -> bytes:
    """The comparable form: telemetry removed, keys ordered, one encoding.

    Sorted keys because dictionary order is an implementation detail of
    whichever code assembled the artifact, and a conformance failure that turns
    out to be key order teaches a team to stop reading conformance failures.
    """
    canonical, _ = split(artifact)
    return json.dumps(canonical, sort_keys=True, ensure_ascii=False,
                      separators=(",", ":")).encode("utf-8")


def identical(left: Dict[str, Any], right: Dict[str, Any]) -> bool:
    return canonical_bytes(left) == canonical_bytes(right)


def differences(left: Dict[str, Any], right: Dict[str, Any]) -> List[str]:
    """Where two canonical results disagree, as paths a person can look up.

    A failing byte comparison says only that two long strings differ. This says
    which field, which is the difference between a test that gets fixed and a
    test that gets deleted.
    """
    return sorted(_diff(split(left)[0], split(right)[0], ""))


def _diff(left: Any, right: Any, path: str) -> List[str]:
    if type(left) is not type(right):
        return ["{}: {} vs {}".format(path or "(root)",
                                      type(left).__name__, type(right).__name__)]
    if isinstance(left, dict):
        out: List[str] = []
        for key in sorted(set(left) | set(right)):
            where = "{}.{}".format(path, key) if path else key
            if key not in left:
                out.append("{}: absent on the left".format(where))
            elif key not in right:
                out.append("{}: absent on the right".format(where))
            else:
                out += _diff(left[key], right[key], where)
        return out
    if isinstance(left, list):
        if len(left) != len(right):
            return ["{}: {} entries vs {}".format(path, len(left), len(right))]
        out = []
        for index, (a, b) in enumerate(zip(left, right)):
            out += _diff(a, b, "{}[{}]".format(path, index))
        return out
    return [] if left == right else ["{}: {!r} vs {!r}".format(path, left, right)]


def telemetry_leaks(canonical: Dict[str, Any]) -> List[str]:
    """Leaf names in a canonical result that look like provider telemetry.

    A second, cruder check that exists because `TELEMETRY_PATHS` is a list of
    paths and a restructured artifact moves paths. If `usage` is nested one
    level deeper tomorrow, the path stops matching, the exclusion silently stops
    applying, and the byte comparison starts failing for a reason nobody will
    guess from the diff. This names it instead.
    """
    suspicious = {
        "input_tokens", "output_tokens", "cache_read_tokens",
        "cache_write_tokens", "cost_usd", "duration_ms", "session_id",
        "generated_at", "elapsed_seconds",
    }
    found: List[str] = []

    def visit(node: Any, path: str) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                where = "{}.{}".format(path, key) if path else key
                if key in suspicious:
                    found.append(where)
                visit(value, where)
        elif isinstance(node, list):
            for index, item in enumerate(node):
                visit(item, "{}[{}]".format(path, index))

    visit(canonical, "")
    return sorted(found)
