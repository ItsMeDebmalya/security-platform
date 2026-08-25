"""The testssl.sh cross-check.

The parsing and comparison logic is tested here against captured testssl.sh
output. Running testssl.sh itself is not: it is slow, optional, and not
installed on every machine - so the harness must degrade to a clear message
rather than a failure, and that is tested too.
"""

from __future__ import annotations

import datetime as dt

from core.tls import CertificateInfo, TlsObservation
from corpus.crosscheck.testssl import available, compare, main

# Real output from testssl.sh 3.2.4 against a lab server, trimmed.
HEALTHY = {
    "cert_signatureAlgorithm": "SHA256 with RSA",
    "cert_keySize": "RSA 2048 bits (exponent is 65537)",
    "cert_commonName": "localhost",
    "cert_subjectAltName": "localhost",
    "cert_notAfter": "2027-08-25 05:26",
    "cert_fingerprintSHA256": "9006371245b1657e87fa85edbf31d1b008889d20b6b3a1f5b0e4717eeeab0000",
    "certificate_transparency": "N/A",
    "cert_chain_of_trust": "failed (self signed CA in chain).",
    "TLS1": "not offered",
    "TLS1_1": "not offered",
    "TLS1_2": "offered",
    "TLS1_3": "offered with final",
}


def _observation(**overrides) -> TlsObservation:
    cert = CertificateInfo(
        subject="CN=localhost",
        subject_cn="localhost",
        issuer="CN=localhost Test Root",
        issuer_cn="localhost Test Root",
        serial="2b",
        not_before=dt.datetime(2026, 7, 26, tzinfo=dt.UTC),
        not_after=dt.datetime(2027, 8, 25, 5, 26, tzinfo=dt.UTC),
        sans=["localhost"],
        key_type="rsa",
        key_bits=2048,
        signature_algorithm="sha256",
        self_signed=False,
        has_sct=False,
        fingerprint_sha256="9006371245b1657e87fa85edbf31d1b008889d20b6b3a1f5b0e4717eeeab0000",
    )
    base = dict(
        host="localhost",
        port=443,
        servername="localhost",
        reachable=True,
        observed_at=dt.datetime(2026, 8, 24, tzinfo=dt.UTC),
        protocol="TLSv1.3",
        cipher="TLS_AES_256_GCM_SHA384",
        certificate=cert,
        trusted=False,
    )
    base.update(overrides)
    return TlsObservation(**base)


PROTOCOLS = {"TLSv1": False, "TLSv1.1": False, "TLSv1.2": True, "TLSv1.3": True}


def test_two_readings_of_the_same_server_agree_on_every_fact():
    results = compare(_observation(), HEALTHY, PROTOCOLS)

    assert results
    assert all(r.agreed for r in results), [r for r in results if not r.agreed]


def test_the_fingerprint_is_compared_because_it_anchors_everything_else():
    facts = {r.fact for r in compare(_observation(), HEALTHY, PROTOCOLS)}

    assert "fingerprint" in facts


def test_a_disagreement_about_key_size_is_reported():
    cert = _observation().certificate
    wrong = _observation(certificate=CertificateInfo(**{**cert.__dict__, "key_bits": 4096}))

    results = compare(wrong, HEALTHY, PROTOCOLS)

    assert any(r.fact == "key_bits" and not r.agreed for r in results)


def test_a_disagreement_about_protocol_support_is_reported():
    results = compare(_observation(), HEALTHY, {**PROTOCOLS, "TLSv1": True})

    assert any(r.fact == "protocol:TLSv1" and not r.agreed for r in results)


def test_a_fact_only_one_side_reported_is_skipped_rather_than_failed():
    """Silence is not disagreement."""
    results = compare(_observation(), {"cert_keySize": "RSA 2048 bits"}, None)

    assert [r.fact for r in results] == ["key_bits"]


def test_trust_verdicts_are_skipped_when_the_trust_stores_differ():
    """With a private anchor we would be comparing configuration, not correctness."""
    facts = {r.fact for r in compare(_observation(), HEALTHY, PROTOCOLS, shares_trust_store=False)}

    assert "chain_trusted" not in facts


def test_trust_verdicts_are_compared_when_both_use_the_public_store():
    facts = {r.fact for r in compare(_observation(), HEALTHY, PROTOCOLS)}

    assert "chain_trusted" in facts


def test_chain_of_trust_is_not_read_as_the_leaf_being_self_signed():
    """testssl says "failed (self signed CA in chain)" for any untrusted root.

    Reading that as "the leaf is self-signed" is the conflation that made us
    report untrusted-root.badssl.com wrongly. The leaf here is CA-issued.
    """
    results = compare(_observation(), HEALTHY, PROTOCOLS)
    trust = next(r for r in results if r.fact == "chain_trusted")

    assert trust.ours is False and trust.theirs is False
    assert not any(r.fact == "self_signed" for r in results)


def test_the_harness_reports_cleanly_when_testssl_is_not_installed(monkeypatch, capsys):
    monkeypatch.setattr("corpus.crosscheck.testssl.available", lambda: False)

    assert main() == 0
    assert "not installed" in capsys.readouterr().out


def test_availability_is_reported_honestly():
    assert isinstance(available(), bool)
