"""Scope enforcement and the ownership gate. Deny by default.

This is a legal requirement, not a product feature: docs/06-guidelines.md
non-negotiable #2, and it applies from the first Standard-mode check.
"""

from __future__ import annotations

from datetime import date

import pytest

from core.authz import AuthorisationDeniedError, AuthorisedScope, Scope

TODAY = date(2026, 8, 22)

SCOPE_FILE = """
- authz_id: authz_2026-08-22-001
  org_id: org_internal
  target: { type: domain, value: example.com, wildcard: false }
  method: dns_txt
  proof:
    observed: 'sp-verify=7f3a at _scanverify.example.com'
    observed_at: 2026-08-22T09:14:00Z
    evidence_file: corpus/authz/example.com-2026-08-22.txt
  verified_at: 2026-08-22
  expires_at: 2026-11-20
  verified_by: operator:satwik
  attestation_ref: null

- authz_id: authz_2026-01-01-002
  org_id: org_internal
  target: { type: domain, value: expired.example, wildcard: false }
  method: dns_txt
  proof:
    observed: 'sp-verify=aaaa at _scanverify.expired.example'
    observed_at: 2026-01-01T00:00:00Z
    evidence_file: corpus/authz/expired.example-2026-01-01.txt
  verified_at: 2026-01-01
  expires_at: 2026-04-01
  verified_by: operator:satwik

- authz_id: authz_2026-08-01-003
  org_id: org_internal
  target: { type: domain, value: wild.example, wildcard: true }
  method: self_owned
  proof:
    observed: 'we own this zone; see registrar account'
    observed_at: 2026-08-01T00:00:00Z
    evidence_file: corpus/authz/wild.example-2026-08-01.txt
  verified_at: 2026-08-01
  expires_at: 2026-10-30
  verified_by: operator:satwik

- authz_id: authz_2026-08-02-004
  org_id: org_internal
  target: { type: domain, value: revoked.example, wildcard: false }
  method: dns_txt
  proof:
    observed: 'sp-verify=bbbb at _scanverify.revoked.example'
    observed_at: 2026-08-02T00:00:00Z
    evidence_file: corpus/authz/revoked.example-2026-08-02.txt
  verified_at: 2026-08-02
  expires_at: 2026-10-31
  verified_by: operator:satwik
  revoked_at: 2026-08-10
  revocation_reason: customer request
"""


@pytest.fixture
def scope(tmp_path):
    path = tmp_path / "authorised_scope.yaml"
    path.write_text(SCOPE_FILE)
    return AuthorisedScope.load(path)


def _target(value, type_="domain"):
    from core.models import Asset

    return Asset(type=type_, value=value)


# --- the ownership gate ----------------------------------------------------


def test_light_mode_needs_no_authorisation(scope):
    decision = scope.authorise(_target("stranger.example"), mode="light", today=TODAY)

    assert decision.allowed
    assert decision.authz_ref is None


def test_standard_mode_against_a_verified_target_is_allowed_and_cites_its_record(scope):
    decision = scope.authorise(_target("example.com"), mode="standard", today=TODAY)

    assert decision.allowed
    assert decision.authz_ref == "allowlist:authz_2026-08-22-001#example.com"


def test_standard_mode_against_a_target_absent_from_the_file_is_denied(scope):
    decision = scope.authorise(_target("stranger.example"), mode="standard", today=TODAY)

    assert not decision.allowed
    assert "no authorisation record" in decision.reason


def test_standard_mode_against_an_expired_record_is_denied(scope):
    decision = scope.authorise(_target("expired.example"), mode="standard", today=TODAY)

    assert not decision.allowed
    assert "expired" in decision.reason


def test_standard_mode_against_a_revoked_record_is_denied(scope):
    decision = scope.authorise(_target("revoked.example"), mode="standard", today=TODAY)

    assert not decision.allowed
    assert "revoked" in decision.reason


def test_deep_mode_is_gated_the_same_way_as_standard(scope):
    decision = scope.authorise(_target("stranger.example"), mode="deep", today=TODAY)

    assert not decision.allowed


def test_an_empty_scope_file_denies_everything_active(tmp_path):
    path = tmp_path / "authorised_scope.yaml"
    path.write_text("[]\n")

    decision = AuthorisedScope.load(path).authorise(
        _target("example.com"), mode="standard", today=TODAY
    )

    assert not decision.allowed


def test_a_missing_scope_file_denies_rather_than_defaulting_open(tmp_path):
    decision = AuthorisedScope.load(tmp_path / "nope.yaml").authorise(
        _target("example.com"), mode="standard", today=TODAY
    )

    assert not decision.allowed


def test_a_wildcard_record_covers_subdomains(scope):
    decision = scope.authorise(_target("api.wild.example"), mode="standard", today=TODAY)

    assert decision.allowed


def test_a_non_wildcard_record_does_not_cover_subdomains(scope):
    decision = scope.authorise(_target("api.example.com"), mode="standard", today=TODAY)

    assert not decision.allowed


def test_a_record_without_its_proof_file_is_not_verification(tmp_path):
    """docs/09: a row asserting verification without its proof is not verification."""
    path = tmp_path / "authorised_scope.yaml"
    path.write_text(
        SCOPE_FILE.replace("    evidence_file: corpus/authz/example.com-2026-08-22.txt\n", "", 1)
    )

    with pytest.raises(ValueError, match="evidence_file"):
        AuthorisedScope.load(path)


def test_require_raises_rather_than_returning_a_decision_to_ignore(scope):
    with pytest.raises(AuthorisationDeniedError):
        scope.require(_target("stranger.example"), mode="standard", today=TODAY)


# --- outbound request scope ------------------------------------------------


def test_a_request_to_the_target_host_is_in_scope():
    assert Scope.for_target(_target("example.com")).permits("example.com")


def test_a_request_to_a_subdomain_of_the_target_is_in_scope():
    assert Scope.for_target(_target("example.com")).permits("www.example.com")


def test_a_request_to_a_third_party_host_is_out_of_scope():
    """An SSRF probe never targets a third party; a redirect never leaves scope."""
    assert not Scope.for_target(_target("example.com")).permits("evil.example")


def test_a_lookalike_host_is_not_in_scope():
    assert not Scope.for_target(_target("example.com")).permits("notexample.com")


def test_a_url_target_scopes_to_its_host():
    assert Scope.for_target(_target("https://example.com/app", "url")).permits("example.com")


def test_scope_reads_the_scheme_rather_than_the_declared_target_type():
    """The CLI defaults --target-type to `domain`, so a pasted URL arrives as a
    domain whose value is a URL. Found live: the scope then contained the
    literal string "https://www.google.com" and refused the connection to
    www.google.com as out of scope."""
    scope = Scope.for_target(_target("https://www.google.com", "domain"))

    assert scope.permits("www.google.com")


def test_scope_still_handles_a_bare_domain():
    assert Scope.for_target(_target("example.com")).permits("example.com")


def test_scope_ignores_a_port_when_deriving_the_host():
    scope = Scope.for_target(_target("https://example.com:8443", "domain"))

    assert scope.permits("example.com")
