"""Was a review performed at all — a third question the artifact could not answer.

`stop_reason` says how a review ended; `complete` says whether it reached its
expected end. Neither can say that none was attempted, and three routes reach
that state: excludes hiding every file, a `--path` leaving every file out, and
a merge request labelled to skip the review.

`_nothing_to_review` built a `ScanOutcome` with no `stop_reason`, so it
defaulted to `completed` and the artifact said `complete: true` with no
findings. `pair_corpus.hits_target` reads exactly those two fields, so an
unsafe case scored as a **miss** over a run that had looked at nothing.
`hits_target`'s own docstring records the same defect found and fixed once
before, for runs that exited 2; the skip path brought it back by a route where
the exit code is 0.

The obvious repair is wrong and the ruling says why: `complete = False` makes
`_partial` true, `fail_on_incomplete` defaults true, so "skip this review"
would become "block this merge" — and an escape hatch that cannot be used gets
deleted rather than obeyed.

Adjudicated by Codex on 2026-09-08. Built 2026-09-09.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tools"))

import pair_corpus
from security_agent.config import Config
from security_agent.gate import decide
from security_agent.identity import digest, reusable
from security_agent.models import (
    REVIEW_NOTHING_REVIEWABLE,
    REVIEW_PERFORMED,
    REVIEW_SKIPPED,
    ScanOutcome,
)
from security_agent.report import render_markdown


def outcome(status=REVIEW_PERFORMED) -> ScanOutcome:
    out = ScanOutcome(mode="diff", model="claude-opus-5",
                      review_status=status)
    out.summary = "Nothing was examined."
    return out


class TestTheArtifactSaysWhetherAReviewHappened:
    def test_a_performed_review_is_the_default(self):
        """The only outcomes that claim otherwise are the ones that say so.
        A default of `nothing_reviewable` would make every ordinary run
        unreusable and every recall figure `None`."""
        assert ScanOutcome(mode="diff").review_status == REVIEW_PERFORMED

    @pytest.mark.parametrize("status", [REVIEW_SKIPPED,
                                        REVIEW_NOTHING_REVIEWABLE])
    def test_a_run_that_did_not_review_still_completes_and_exits_zero(
            self, status):
        """The ruling's central constraint. `complete = False` would make
        `_partial` true and `fail_on_incomplete` defaults true, so a skip label
        would block the merge it exists to unblock."""
        out = outcome(status)

        assert decide(Config(), out).exit_code == 0
        assert out.complete is True


class TestTheGradingToolWillNotScoreARunThatLookedAtNothing:
    def base(self, **over):
        body = {"complete": True, "findings": [],
                "review_status": REVIEW_PERFORMED}
        body.update(over)
        return body

    CASE = {"category": "injection", "file": "app/views.py"}

    def test_a_performed_review_with_no_findings_is_a_miss(self):
        """The control, and it must stay a miss: a reviewer that looked and
        found nothing on an unsafe case really did miss it."""
        assert pair_corpus.hits_target(self.base(), self.CASE) is False

    @pytest.mark.parametrize("status", [REVIEW_SKIPPED,
                                        REVIEW_NOTHING_REVIEWABLE])
    def test_a_run_that_did_not_review_is_not_an_answer(self, status):
        """`None`, the third answer this function already had for runs that
        stopped early. An empty finding list from a run that never looked is
        an absence of evidence."""
        assert pair_corpus.hits_target(
            self.base(review_status=status), self.CASE) is None

    # Byte for byte what `_nothing_to_review` wrote before `review_status`
    # existed: complete, no finding, and a coverage block recording that
    # nothing happened.
    OLD_SKIP = {"complete": True, "findings": [],
                "coverage": {"files_examined": [], "exposures": [],
                             "turns": 0, "tool_calls": []}}

    # The same era, a run that did review.
    # `measurements/2026-08-25-decoy-validator/reviewer-only.json`: complete,
    # one finding, ten turns, thirteen tool calls, and **no `exposures` key** —
    # that field was only written from 2026-08-28.
    OLD_PERFORMED = {"complete": True, "findings": [],
                     "coverage": {"files_examined": ["app/views.py"],
                                  "turns": 10,
                                  "tool_calls": [{"tool": "get_diff"}]}}

    def test_an_old_skip_shaped_artifact_is_not_scored_as_a_miss(self):
        """The first repair read a missing `review_status` as `performed`, on
        the ground that every artifact predating the field was a real review.
        The repository disproves it: `_nothing_to_review` has written artifacts
        since 2026-08-26 and the skip route since 2026-09-03, and none of them
        carries the field. Codex, 2026-09-09 — absence read as agreement, in
        the repair for absence read as agreement.
        """
        assert pair_corpus.hits_target(self.OLD_SKIP, self.CASE) is None

    def test_an_old_genuine_review_with_no_exposures_is_still_a_miss(self):
        """The control against the over-strict repair, which is the one most
        likely to be reached for: testing `exposures` alone reclassifies this
        shape as a run that never looked, and it exists on disk twice.

        Said plainly — this test does **not** catch the reverted fix. It pins
        the other side. Neither alone establishes the rule.
        """
        assert pair_corpus.hits_target(self.OLD_PERFORMED, self.CASE) is False


class TestTheOneLineAReaderSeesDoesNotClaimAReview:
    """Codex found this without being asked: the terminal already said
    `NOT REVIEWED` and the markdown immediately under it rendered
    "✅ AI security review — no findings reported"."""

    @pytest.mark.parametrize("status, expected", [
        (REVIEW_SKIPPED, "not run, this change carries the skip label"),
        (REVIEW_NOTHING_REVIEWABLE, "nothing to review"),
    ])
    def test_a_run_that_did_not_review_gets_no_green_tick(self, status,
                                                          expected):
        cfg = Config(post_comment=False)
        out = outcome(status)

        text = render_markdown(cfg, out, decide(cfg, out))
        heading = next(line for line in text.splitlines()
                       if line.startswith("## "))

        assert expected in heading
        assert "✅" not in heading
        assert "no findings reported" not in heading

    def test_a_performed_review_with_nothing_found_still_gets_one(self):
        """The control. A tick withheld from every clean review is a tick
        nobody believes when it appears."""
        cfg = Config(post_comment=False)
        out = outcome()

        heading = next(line for line in
                       render_markdown(cfg, out, decide(cfg, out)).splitlines()
                       if line.startswith("## "))

        assert "✅" in heading
        assert "no findings reported" in heading


class TestARunThatDidNotReviewIsNeverReused:
    """Named in the ruling as a thing the repair must not break: anything other
    than `performed` must never be reusable as a clean review. A skipped run is
    `complete: true` and exits 0 by design, so `complete` alone would have let
    a labelled skip serve as the stored answer for the next run."""

    # Every field `reusable` requires. A fixture short of one of them makes
    # the control below pass for the wrong reason — the guard refusing on the
    # missing field rather than on the status.
    IDENTITY = {"system_prompt_sha": "aaa", "verifier_prompt_sha": "bbb",
                "schema_sha": "ccc", "agent_version": "0.1.0",
                "model_requested": "claude-opus-5"}

    def stored(self, **over):
        body = {"complete": True,
                "review_status": REVIEW_PERFORMED,
                "identity": dict(self.IDENTITY),
                "identity_digest": digest(self.IDENTITY),
                "coverage": {"exposures": [["app/views.py", "get_diff"]]}}
        body.update(over)
        return body

    @pytest.mark.parametrize("status", [REVIEW_SKIPPED,
                                        REVIEW_NOTHING_REVIEWABLE])
    def test_it_is_refused(self, status):
        assert reusable(self.stored(review_status=status),
                        dict(self.IDENTITY)) is False

    def test_a_performed_one_is_still_reusable(self):
        """The control, or the test above passes on a guard that refuses
        everything and the reuse path quietly stops working."""
        assert reusable(self.stored(), dict(self.IDENTITY)) is True

    def test_an_artifact_from_before_the_field_is_still_reusable(self):
        body = self.stored()
        del body["review_status"]

        assert reusable(body, dict(self.IDENTITY)) is True
