"""Deriving severity from facts instead of asking for a judgement.

Measured across runs, the one thing that moved was the severity label: the same
finding came out `high` on one run and `medium` on the next, and the gate is a
step function on exactly that. Two mature tools disagreed by a full step on the
same CVE.

The cause is not carelessness. "How bad is this" depends on facts that are not
in the diff — whether the service faces the internet, who can reach the
endpoint, how much data sits behind it — so each run invents its own assumptions
and lands somewhere different. Whereas "does this reach a sink without
authentication" is answerable from the code, and answers the same way every
time.

So the model is no longer asked for the number. It is asked three questions it
can answer by reading, and the number is computed here — deterministically,
inspectably, and identically on every run. When the model genuinely cannot tell,
`unclear` is a real answer that is treated the same way every time, which is
better than a guess that differs each run.

The table below is a judgement, but it is *one* judgement, written down once and
applied uniformly, rather than a fresh one per finding per run.
"""

from __future__ import annotations

from typing import Tuple

from .models import SEVERITY_ORDER, severity_rank

# What the attacker gets, before any discount for how hard it is to reach.
BASE_SEVERITY = {
    "code_execution": "critical",
    "broad_data_access": "high",     # whole tables, arbitrary files, other users
    "state_change": "high",          # writes or acts as someone else
    "narrow_data_access": "medium",  # one record or file they should not see
    "metadata_disclosure": "low",    # only useful as a step toward something
    "denial_of_service": "low",
}

# Categories whose base is raised regardless of the stated impact, because the
# artifact itself is the problem and "impact" does not describe it well. A
# committed credential grants whatever that credential grants.
CATEGORY_FLOOR = {
    "secrets": "high",
}


def derive(
    impact: str,
    reachable_without_authentication: str,
    requires_user_interaction: str,
    category: str = "",
) -> Tuple[str, str]:
    """Return (severity, one-line explanation of how it was reached).

    The explanation goes in the report. A derived number nobody can retrace is
    no better than a guessed one.
    """
    base = BASE_SEVERITY.get(impact)
    if base is None:
        # An impact value outside the schema means the finding predates this
        # scheme or the model returned something unexpected; say so rather than
        # inventing a number.
        return "", "impact {!r} is not one the severity table covers".format(impact)

    steps = []
    level = base
    steps.append("{} → {}".format(impact, base))

    floor = CATEGORY_FLOOR.get(category)
    if floor and severity_rank(floor) > severity_rank(level):
        level = floor
        steps.append("{} category raises it to {}".format(category, floor))

    # Each discount is one step, and only for a definite "no"/"yes". `unclear`
    # deliberately changes nothing: it is the one answer that must not move the
    # result, or the model is rewarded for guessing.
    if reachable_without_authentication == "no":
        level = _step_down(level)
        steps.append("authentication required → {}".format(level))
    if requires_user_interaction == "yes":
        level = _step_down(level)
        steps.append("needs a victim to act → {}".format(level))

    return level, "; ".join(steps)


def _step_down(level: str) -> str:
    index = severity_rank(level)
    return SEVERITY_ORDER[max(0, index - 1)]
