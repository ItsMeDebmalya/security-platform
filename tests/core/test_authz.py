"""Scope enforcement and the ownership gate. Deny by default.

This is a legal requirement, not a product feature: docs/06-guidelines.md
non-negotiable #2, and it applies from the first Standard-mode check.
"""

from __future__ import annotations

from datetime import date

import pytest

from core.authz import AuthorisationDeniedError, AuthorisedScope, Scope
from core.models import Asset

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


# --- a target is a host, however it was typed --------------------------------


def _record(value, wildcard=False):
    from core.authz import AuthorisationRecord

    return AuthorisationRecord(
        authz_id="authz_t",
        org_id="org_internal",
        target_type="domain",
        target_value=value,
        wildcard=wildcard,
        method="dns_txt",
        expires_at=date(2027, 1, 1),
        evidence_file="corpus/authz/x.txt",
    )


@pytest.mark.parametrize(
    ("asset_type", "value"),
    [
        ("domain", "example.com"),
        ("domain", "https://example.com"),
        ("domain", "example.com:8443"),
        ("url", "https://example.com/some/path"),
        ("url", "https://example.com:8443/"),
    ],
)
def test_authorising_a_domain_covers_it_however_the_target_is_typed(asset_type, value):
    """Found live: authorising expired.badssl.com still denied a scan of
    https://expired.badssl.com, because the record was compared against the raw
    target string. Nobody would guess they had to authorise the URL form too."""
    scope = AuthorisedScope([_record("example.com")])

    decision = scope.authorise(Asset(type=asset_type, value=value), mode="standard", today=TODAY)

    assert decision.allowed, decision.reason


def test_a_different_host_is_still_denied_however_it_is_typed():
    scope = AuthorisedScope([_record("example.com")])

    assert not scope.authorise(
        Asset(type="url", value="https://evil.example/"), mode="standard", today=TODAY
    ).allowed


def test_a_wildcard_record_still_covers_subdomains_via_a_url():
    scope = AuthorisedScope([_record("example.com", wildcard=True)])

    assert scope.authorise(
        Asset(type="url", value="https://api.example.com/"), mode="standard", today=TODAY
    ).allowed


def test_the_denial_message_names_the_host_not_the_raw_string():
    scope = AuthorisedScope([])

    reason = scope.authorise(
        Asset(type="url", value="https://example.com/path"), mode="standard", today=TODAY
    ).reason

    assert "example.com" in reason and "https://" not in reason


# --- a port names a service --------------------------------------------------


def _port_record(value, type_="url"):
    from core.authz import AuthorisationRecord

    return AuthorisationRecord(
        authz_id="authz_p",
        org_id="org_internal",
        target_type=type_,
        target_value=value,
        wildcard=False,
        method="self_owned",
        expires_at=date(2027, 1, 1),
        evidence_file="corpus/authz/x.txt",
    )


def test_a_row_for_one_port_does_not_authorise_another():
    """Juice Shop on :3000 and VAmPI on :5000 are different services that happen
    to share a host. A row naming one must not authorise the other."""
    scope = AuthorisedScope([_port_record("http://127.0.0.1:3000")])

    decision = scope.authorise(
        _target("http://127.0.0.1:5000", "url"), mode="standard", today=TODAY
    )

    assert not decision.allowed


def test_a_row_for_a_port_authorises_that_port():
    scope = AuthorisedScope([_port_record("http://127.0.0.1:3000")])

    assert scope.authorise(
        _target("http://127.0.0.1:3000", "url"), mode="standard", today=TODAY
    ).allowed


def test_a_row_naming_a_port_does_not_authorise_the_bare_host():
    scope = AuthorisedScope([_port_record("http://127.0.0.1:3000")])

    assert not scope.authorise(_target("127.0.0.1", "ip"), mode="standard", today=TODAY).allowed


def test_a_row_without_a_port_still_covers_the_whole_host():
    """Authorising a domain is about the host. Requiring a port there would mean
    naming every service separately, which nobody would do correctly."""
    scope = AuthorisedScope([_port_record("example.com", "domain")])

    for value, kind in [
        ("example.com", "domain"),
        ("https://example.com", "url"),
        ("https://example.com:8443/admin", "url"),
    ]:
        assert scope.authorise(_target(value, kind), mode="standard", today=TODAY).allowed, value
