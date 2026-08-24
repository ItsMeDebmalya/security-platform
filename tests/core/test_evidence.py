"""Evidence capture: redact at capture time, cap size, stay replayable."""

from __future__ import annotations

import pytest

from core.dns import DnsResponse
from core.evidence import (
    REDACTED,
    capture_http_pair,
    dns_evidence,
    redact_body,
    redact_headers,
    to_curl,
    truncate_body,
)


def test_a_session_cookie_never_reaches_storage():
    headers, redacted = redact_headers({"Cookie": "session=abc123", "Accept": "*/*"})

    assert headers == {"Cookie": REDACTED, "Accept": "*/*"}
    assert redacted == ["cookie"]


def test_an_authorization_header_never_reaches_storage():
    headers, redacted = redact_headers({"Authorization": "Bearer abc.def.ghi"})

    assert headers["Authorization"] == REDACTED
    assert redacted == ["authorization"]


def test_set_cookie_from_the_response_is_redacted_too():
    headers, redacted = redact_headers({"Set-Cookie": "session=abc123; HttpOnly"})

    assert headers["Set-Cookie"] == REDACTED
    assert redacted == ["set-cookie"]


def test_header_matching_is_case_insensitive():
    headers, _ = redact_headers({"authorization": "Bearer x"})

    assert headers["authorization"] == REDACTED


def test_an_ordinary_header_is_left_alone():
    headers, redacted = redact_headers({"Content-Type": "text/html"})

    assert headers == {"Content-Type": "text/html"}
    assert redacted == []


@pytest.mark.parametrize(
    "secret",
    [
        "AKIAIOSFODNN7EXAMPLE",
        "ghp_16CharactersLongTokenHere000000000000",
        "-----BEGIN RSA PRIVATE KEY-----",
        "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.abc.def",
    ],
)
def test_a_secret_in_a_body_is_redacted_at_capture_time(secret):
    body, redacted = redact_body(f"prefix {secret} suffix")

    assert secret not in body
    assert redacted


def test_an_ordinary_body_is_left_alone():
    body, redacted = redact_body("<html>hello</html>")

    assert body == "<html>hello</html>"
    assert redacted == []


# --- size caps --------------------------------------------------------------


def test_a_body_under_the_cap_is_kept_whole():
    body, truncated = truncate_body("x" * 100, cap=1000)

    assert body == "x" * 100
    assert truncated is False


def test_a_body_over_the_cap_keeps_its_head_and_tail_and_says_so():
    body, truncated = truncate_body("a" * 500 + "b" * 500, cap=200)

    assert truncated is True
    assert body.startswith("a")
    assert body.endswith("b")
    assert "truncated" in body


def test_a_truncated_body_is_no_larger_than_the_cap_plus_its_marker():
    body, _ = truncate_body("x" * 10_000, cap=256)

    assert len(body) < 256 + 120


# --- replayability ----------------------------------------------------------


def test_an_http_pair_exports_as_a_runnable_curl_command():
    evidence = capture_http_pair(
        label="Missing security header",
        control_request={"method": "GET", "url": "https://example.com/", "headers": {}},
        control_response={"status": 200, "headers": {}, "body": "ok"},
        test_request={
            "method": "GET",
            "url": "https://example.com/admin",
            "headers": {"Cookie": "session=abc123"},
        },
        test_response={"status": 200, "headers": {}, "body": "ok"},
    )

    command = to_curl(evidence.test.request)

    assert command.startswith("curl -X GET 'https://example.com/admin'")
    assert "abc123" not in command


def test_captured_evidence_lists_what_it_redacted():
    evidence = capture_http_pair(
        label="Missing security header",
        control_request={"method": "GET", "url": "https://example.com/", "headers": {}},
        control_response={"status": 200, "headers": {}, "body": "ok"},
        test_request={
            "method": "GET",
            "url": "https://example.com/admin",
            "headers": {"Authorization": "Bearer x"},
        },
        test_response={"status": 200, "headers": {"Set-Cookie": "s=1"}, "body": "ok"},
    )

    assert set(evidence.redactions) == {"authorization", "set-cookie"}


# --- dns evidence -----------------------------------------------------------


def _answer(name, rcode="NOERROR", records=("v=DMARC1; p=none",)):
    return DnsResponse(name=name, rrtype="TXT", rcode=rcode, records=list(records), ttl=300)


def test_dns_evidence_pairs_the_lookup_with_its_wildcard_control():
    evidence = dns_evidence(
        label="TXT at _dmarc.example.com",
        test=_answer("_dmarc.example.com"),
        control=_answer("sp-wildcard-probe-9f3a.example.com", rcode="NXDOMAIN", records=()),
        control_rationale="random-label probe proves the zone has no TXT wildcard",
    )

    assert evidence.has_control()
    assert evidence.control is not None
    assert evidence.control.answer.rcode == "NXDOMAIN"


def test_dns_evidence_without_a_control_must_say_why():
    with pytest.raises(ValueError, match="rationale"):
        dns_evidence(
            label="TXT at _dmarc.example.com",
            test=_answer("_dmarc.example.com"),
            control=None,
            control_rationale="",
        )


def test_dns_evidence_records_the_resolver_that_answered():
    evidence = dns_evidence(
        label="TXT at _dmarc.example.com",
        test=DnsResponse(
            name="_dmarc.example.com",
            rrtype="TXT",
            rcode="NOERROR",
            records=["v=DMARC1; p=none"],
            ttl=300,
            resolver="1.1.1.1",
        ),
        control=None,
        control_rationale="the zone has no wildcard; probe recorded on the spf check",
    )

    assert evidence.test.query.resolver == "1.1.1.1"


# --- tls evidence -----------------------------------------------------------


def _observation(**overrides):
    import datetime as _dt

    from core.tls import CertificateInfo, TlsObservation

    cert = CertificateInfo(
        subject="CN=example.com",
        subject_cn="example.com",
        issuer="CN=Example CA",
        issuer_cn="Example CA",
        serial="01",
        not_before=_dt.datetime(2026, 1, 1, tzinfo=_dt.UTC),
        not_after=_dt.datetime(2026, 9, 1, tzinfo=_dt.UTC),
        sans=["example.com"],
        key_type="rsa",
        key_bits=2048,
        signature_algorithm="sha256",
        self_signed=False,
        has_sct=True,
        fingerprint_sha256="ab" * 32,
    )
    base = dict(
        host="example.com",
        port=443,
        servername="example.com",
        reachable=True,
        observed_at=_dt.datetime(2026, 8, 24, tzinfo=_dt.UTC),
        protocol="TLSv1.3",
        cipher="TLS_AES_256_GCM_SHA384",
        cipher_bits=256,
        certificate=cert,
        trusted=True,
    )
    base.update(overrides)
    return TlsObservation(**base)


def test_tls_evidence_pairs_what_was_served_with_the_strict_verdict():
    from core.evidence import tls_evidence

    evidence = tls_evidence(
        label="TLS handshake with example.com:443",
        observation=_observation(
            trusted=False, verify_code=18, verify_message="self-signed certificate"
        ),
    )

    assert evidence.kind == "tls_handshake"
    assert evidence.has_control()
    assert evidence.control["trusted"] is False
    assert evidence.control["verify_message"] == "self-signed certificate"


def test_tls_evidence_records_what_the_server_actually_presented():
    from core.evidence import tls_evidence

    evidence = tls_evidence(label="handshake", observation=_observation())

    assert evidence.test["protocol"] == "TLSv1.3"
    assert evidence.test["certificate"]["key_bits"] == 2048
    assert evidence.test["certificate"]["fingerprint_sha256"] == "ab" * 32


def test_tls_evidence_can_compare_two_observations():
    """Protocol enumeration needs observation-vs-observation, not verdict."""
    from core.evidence import tls_evidence

    evidence = tls_evidence(
        label="TLS 1.0 is still offered",
        observation=_observation(protocol="TLSv1"),
        compared_with=_observation(protocol="TLSv1.3"),
        control_rationale="the same server negotiating a current protocol, for comparison",
    )

    assert evidence.control["protocol"] == "TLSv1.3"
    assert evidence.test["protocol"] == "TLSv1"


def test_tls_evidence_carries_when_it_was_observed():
    from core.evidence import tls_evidence

    evidence = tls_evidence(label="handshake", observation=_observation())

    assert evidence.observed_at.year == 2026


def test_tls_evidence_needs_a_rationale_when_nothing_was_compared():
    from core.evidence import tls_evidence

    with pytest.raises(ValueError, match="rationale"):
        tls_evidence(
            label="handshake",
            observation=_observation(trusted=None),
            control_rationale="",
        )
