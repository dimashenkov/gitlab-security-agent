"""The cost was written into the artifact and rendered nowhere.

Seeing what a review cost meant opening `findings.json`. The number now appears
on the report's `Billing:` line — beside who paid rather than on a line of its
own, because a figure without who paid it is the confusion this project has
already built three wrong rules on.

The first version of this file keyed on `provenance.provider` and asserted that
`claude-cli` means nobody was charged. That was wrong and these tests encoded it:
`claude-cli` says how the run was launched, and `Authentication.method` says how
its login is billed — `claude.ai` with a plan is a subscription, `api-key` and
`console` are charged, and empty is the CLI declining to say. A CLI run on an
API-key login is a bill, and the tool written to keep bills apart from list
prices was calling it free.
"""
from __future__ import annotations

from security_agent.report import _cost_note


class Provenance:
    def __init__(self, provider="claude-cli", cost=1.25,
                 auth_method="claude.ai", auth_subscription="max"):
        self.provider = provider
        self.reported_cost_usd = cost
        self.auth_method = auth_method
        self.auth_subscription = auth_subscription


class TestWhoPaidComesFromTheLogin:
    def test_the_api_provider_is_charged(self):
        note = _cost_note(Provenance(provider="anthropic-api", cost=2.5,
                                     auth_method="", auth_subscription=""))
        assert "$2.50" in note and "charged" in note
        assert "list price" not in note

    def test_a_subscription_login_is_not(self):
        note = _cost_note(Provenance(auth_method="claude.ai",
                                     auth_subscription="max", cost=2.5))
        assert "$2.50" in note and "not an amount charged" in note

    def test_a_cli_run_on_an_api_key_login_is_charged(self):
        """The defect this file used to assert the opposite of."""
        note = _cost_note(Provenance(provider="claude-cli", auth_method="api-key",
                                     auth_subscription="", cost=2.5))
        assert "charged" in note
        assert "not an amount charged" not in note

    def test_a_console_login_is_charged_too(self):
        note = _cost_note(Provenance(auth_method="console", auth_subscription=""))
        assert "charged" in note
        assert "not an amount charged" not in note

    def test_a_large_subscription_figure_is_still_not_a_bill(self):
        note = _cost_note(Provenance(cost=999.0))
        assert "not an amount charged" in note

    def test_a_tiny_charged_figure_is_still_a_bill(self):
        note = _cost_note(Provenance(auth_method="api-key", auth_subscription="",
                                     cost=0.004))
        assert "charged" in note and "not an amount charged" not in note


class TestUnknownStaysUnknown:
    """Guessing understates a bill, and an understated cost is believed."""

    def test_no_auth_method_claims_nothing_about_who_paid(self):
        note = _cost_note(Provenance(auth_method="", auth_subscription=""))
        assert "was not established" in note
        assert "not an amount charged" not in note
        assert "charged" not in note.replace("was not established", "")

    def test_claude_ai_without_a_plan_is_not_assumed_to_be_a_subscription(self):
        """`subscription_backed` needs both; one alone establishes nothing."""
        note = _cost_note(Provenance(auth_method="claude.ai", auth_subscription=""))
        assert "was not established" in note


class TestAbsentIsNotZero:
    def test_no_reported_cost_adds_nothing_at_all(self):
        assert _cost_note(Provenance(cost=None)) == ""

    def test_a_missing_attribute_is_not_an_error(self):
        class Bare:
            provider = "claude-cli"

        assert _cost_note(Bare()) == ""

    def test_a_non_numeric_value_is_ignored(self):
        assert _cost_note(Provenance(cost="1.25")) == ""

    def test_a_genuine_zero_is_shown(self):
        """Zero reported is a measurement; zero assumed is not."""
        assert "$0.00" in _cost_note(Provenance(cost=0.0))
