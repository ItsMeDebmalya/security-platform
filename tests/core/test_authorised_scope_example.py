"""The worked example in config/authorised_scope.example.yaml must be correct.

An example an operator copies is a piece of the security control, not
documentation about it. If its rows do not behave the way its comments claim,
it teaches the wrong thing - so it is tested like anything else.
"""

from __future__ import annotations

from datetime import date
from pathlib import Path

import pytest
import yaml

from core.authz import AuthorisedScope
from core.models import Asset

ROOT = Path(__file__).resolve().parents[2]
EXAMPLE = ROOT / "config" / "authorised_scope.example.yaml"
LIVE = ROOT / "config" / "authorised_scope.yaml"

# The example's dates are fixed, so the test pins "today" rather than drifting
# with the wall clock.
TODAY = date(2026, 8, 24)


@pytest.fixture
def scope():
    return AuthorisedScope.load(EXAMPLE)


def _domain(value):
    return Asset(type="domain", value=value)


def test_the_example_file_loads():
    AuthorisedScope.load(EXAMPLE)


def test_the_examples_demo_domains_never_leak_into_the_live_file():
    """The example exists to be copied and edited, not pasted.

    Its rows are illustrations on reserved domains. If one turns up verbatim in
    the file core/authz.py actually reads, someone copied without reading -
    and `acme.example` authorises nothing real, so the mistake would be silent.
    """
    example_ids = {row["authz_id"] for row in yaml.safe_load(EXAMPLE.read_text())}
    live_ids = {row["authz_id"] for row in yaml.safe_load(LIVE.read_text()) or []}

    assert example_ids & live_ids == set()


# --- the four shapes a row can take -----------------------------------------


def test_a_verified_row_permits_standard_mode(scope):
    decision = scope.authorise(_domain("acme.example"), mode="standard", today=TODAY)

    assert decision.allowed
    assert decision.authz_ref == "allowlist:authz_2026-08-24-001#acme.example"


def test_the_wildcard_row_covers_subdomains(scope):
    assert scope.authorise(_domain("api.acme.example"), mode="standard", today=TODAY).allowed


def test_the_non_wildcard_row_does_not_cover_subdomains(scope):
    decision = scope.authorise(_domain("mail.corpus-pnone.example"), mode="standard", today=TODAY)

    assert not decision.allowed


def test_the_self_owned_row_permits_standard_mode(scope):
    assert scope.authorise(_domain("corpus-pnone.example"), mode="standard", today=TODAY).allowed


def test_the_lapsed_row_is_denied(scope):
    decision = scope.authorise(_domain("lapsed.example"), mode="standard", today=TODAY)

    assert not decision.allowed
    assert "expired" in decision.reason


def test_the_revoked_row_is_denied_even_though_it_is_still_in_date(scope):
    decision = scope.authorise(_domain("former-client.example"), mode="standard", today=TODAY)

    assert not decision.allowed
    assert "revoked" in decision.reason


def test_a_domain_absent_from_the_example_is_denied(scope):
    assert not scope.authorise(_domain("python.org"), mode="standard", today=TODAY).allowed


def test_light_mode_ignores_the_file_entirely(scope):
    assert scope.authorise(_domain("python.org"), mode="light", today=TODAY).allowed


# --- the example must practise what it preaches -----------------------------


def test_every_example_row_cites_a_proof_file_that_exists():
    """'A row asserting verification without its proof is not verification.'"""
    rows = yaml.safe_load(EXAMPLE.read_text())

    missing = [
        row["proof"]["evidence_file"]
        for row in rows
        if not (ROOT / row["proof"]["evidence_file"]).exists()
    ]

    assert missing == []


def test_every_example_row_uses_a_reserved_domain():
    """RFC 2606 reserves .example, .test, .invalid and .localhost. An example
    pointing at a registrable domain is an invitation to scan it.

    `localhost` (bare, no TLD) is the one exception: RFC 6761 reserves it
    outright, unregistrable by construction, and it is the literal target of
    the local TLS lab used to demonstrate docs/03-roadmap.md 0b.6 - TLS
    needing authorisation in Light mode - in docs/12-cli-runbook.md §5.
    """
    rows = yaml.safe_load(EXAMPLE.read_text())

    assert all(
        row["target"]["value"].endswith(".example") or row["target"]["value"] == "localhost"
        for row in rows
    )


def test_no_example_authorisation_runs_longer_than_ninety_days():
    rows = yaml.safe_load(EXAMPLE.read_text())

    for row in rows:
        span = (row["expires_at"] - row["verified_at"]).days
        assert span <= 90, f"{row['authz_id']} runs for {span} days"
