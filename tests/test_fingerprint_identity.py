"""The report told people to write down an identity nothing would match.

A finding is identified by the lines of code it quotes, filtered to the ones
that say something specific — a name, a call, a literal. A quote made entirely
of `if err != nil {` and `return err` leaves that list empty, and the identity
then fell back to a digest of the category and the file with an *empty* anchor.
That value was printed under "accept this risk by adding `fingerprint: …`" and
was not among the values `suppress.Rule.matches` compares against, which is the
whole list. So the entry was written, the reason was recorded, the merge blocked
again on the next run, and nothing anywhere said why.

The direction of the fix matters. Making the fallback the empty anchor
*matchable* would have given every anchorless finding in one file and category
the same identity — and `report_finding` drops a finding whose fingerprint
equals an earlier one as a duplicate, so that repair would delete findings
rather than merely over-suppress them. The fallback is the whole quote instead:
less stable between runs than an anchor, which costs a second suppression entry,
and never shared with a different finding.
"""

from __future__ import annotations

import re

import pytest

from conftest import make_candidate, make_finding
from security_agent.config import Config, GitLabContext
from security_agent.gate import decide
from security_agent.models import ScanOutcome
from security_agent.report import render_markdown
from security_agent.suppress import Rule, apply, load

# Every line boilerplate, and long enough to pass the citation checker's
# minimum — this is a quote a real Go review produces, not a contrivance.
BOILERPLATE_QUOTE = "if err != nil {\n\treturn err\n}"
OTHER_BOILERPLATE_QUOTE = "} else {\n\treturn nil, err\n}"


@pytest.fixture
def cfg(tmp_path):
    config = Config(gitlab=GitLabContext())
    config.ignore_file = tmp_path / ".security-agent-ignore.yml"
    return config


def _printed_fingerprint(cfg, candidate) -> str:
    """The value a person copies, taken from the rendered report rather than
    from the object — the defect was that those two were not the same value."""
    outcome = ScanOutcome(mode="diff")
    outcome.reported = [candidate]
    markdown = render_markdown(cfg, outcome, decide(cfg, outcome))
    found = re.search(r"fingerprint: ([0-9a-f]+)", markdown)
    assert found, "the report no longer tells anyone how to accept a risk"
    return found.group(1)


def _rule(fingerprint: str):
    return [Rule(fingerprint=fingerprint, reason="accepted")]


class TestTheEscapeHatchWorks:
    def test_a_finding_with_no_distinctive_quote_can_be_suppressed(self, cfg, tmp_path):
        """Report to ignore file to gate, the way a person walks it.

        Every step of this passed before: the fingerprint rendered, the YAML
        loaded, the rule was well formed. Only the comparison at the end
        returned False, and nothing on the path said so.
        """
        candidate = make_candidate(evidence=BOILERPLATE_QUOTE)
        printed = _printed_fingerprint(cfg, candidate)

        cfg.ignore_file.write_text(
            "ignore:\n"
            "  - fingerprint: {}\n"
            "    reason: accepted by the platform team\n".format(printed),
            encoding="utf-8",
        )
        rules, warnings = load(cfg.ignore_file)
        kept, suppressed = apply([candidate], rules)

        assert warnings == []
        assert [c.fingerprint for c in suppressed] == [printed]
        assert kept == []

    def test_the_ordinary_case_still_works(self, cfg):
        """The control. Anchored findings were never broken, which is why this
        went unnoticed: every case anyone tried by hand had a real quote."""
        candidate = make_candidate()
        printed = _printed_fingerprint(cfg, candidate)

        _, suppressed = apply([candidate], _rule(printed))

        assert len(suppressed) == 1

    def test_the_printed_identity_is_one_of_the_matched_ones(self):
        """Stated directly, because that equality is the contract between two
        files: `Finding.fingerprint` is what the report prints, and
        `Finding.fingerprints` is what suppression compares against."""
        for quote in (BOILERPLATE_QUOTE, OTHER_BOILERPLATE_QUOTE,
                      'db.execute("SELECT * FROM users WHERE id = " + user_id)'):
            finding = make_finding(evidence=quote)

            assert finding.fingerprint in finding.fingerprints


class TestTheFallbackIsNotShared:
    """An identity that matches too much is worse than one that matches too
    little: `report_finding` treats an equal fingerprint as a duplicate and
    drops the finding, so a shared fallback would hide weaknesses rather than
    over-suppress them."""

    def test_two_anchorless_findings_in_one_file_differ(self):
        first = make_finding(evidence=BOILERPLATE_QUOTE)
        second = make_finding(evidence=OTHER_BOILERPLATE_QUOTE)

        assert first.anchors == [] and second.anchors == []
        assert first.fingerprint != second.fingerprint

    def test_a_suppression_written_for_one_does_not_silence_the_other(self, cfg):
        first = make_candidate(evidence=BOILERPLATE_QUOTE)
        second = make_candidate(evidence=OTHER_BOILERPLATE_QUOTE)

        kept, suppressed = apply(
            [first, second], _rule(_printed_fingerprint(cfg, first)))

        assert [c.finding.evidence for c in kept] == [OTHER_BOILERPLATE_QUOTE]
        assert len(suppressed) == 1

    def test_the_same_quote_is_the_same_finding_between_runs(self):
        """The property the fallback still has to keep: two runs quoting the
        same code agree, whitespace and diff markers aside."""
        first = make_finding(evidence=BOILERPLATE_QUOTE)
        second = make_finding(evidence="+  if err != nil {\n+      return err\n+  }")

        assert first.fingerprint == second.fingerprint
