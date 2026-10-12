"""The SSL/TLS Analyzer. Every check gets a positive and a negative case."""

from __future__ import annotations

import ssl

import pytest

from core.authz import Scope
from core.context import ScanContext
from core.models import Asset
from core.tls import TlsClient
from corpus.generators.tls_lab import LAB_ADDRESSES, LabDns, lab_server
from scanners.tls import TlsScanner

LOOPBACK = Scope(frozenset({"localhost"}))
"""The lab listens on 127.0.0.1, which `localhost` resolves to. Targeting the
name rather than the address means the scanner is exercised exactly as it will
be in production - no test-only parameter on run()."""


def scan(server, mode="light", servername="localhost"):
    ctx = ScanContext(dns=LabDns(), addresses=LAB_ADDRESSES, tls=TlsClient(scope=LOOPBACK))
    target = Asset(type="url", value=f"https://{servername}:{server.port}")
    return TlsScanner().run(target, mode, ctx)


def findings(server, check_id, **kwargs):
    result = scan(server, **kwargs)
    return [f for f in result.findings if f.check_id == check_id]


def claims(result):
    return [f.check_id for f in result.findings if f.state in ("confirmed", "highly_likely")]


# --- the healthy baseline ---------------------------------------------------


def test_a_healthy_server_produces_no_claims_beyond_its_trust_anchor():
    """The lab's certificates are self-signed, so an untrusted finding is
    expected and correct. Nothing else should fire."""
    with lab_server(common_name="localhost", sans=["localhost"]) as srv:
        reported = claims(scan(srv, mode="standard"))

    assert set(reported) <= {"tls-cert-self-signed"}


def test_every_check_that_ran_is_accounted_for():
    with lab_server(common_name="localhost") as srv:
        result = scan(srv, mode="standard")

    assert len(result.telemetry.checks_run) >= 8


def test_light_mode_runs_fewer_checks_than_standard():
    with lab_server(common_name="localhost") as srv:
        light = len(scan(srv, mode="light").telemetry.checks_run)
        standard = len(scan(srv, mode="standard").telemetry.checks_run)

    assert light < standard


# --- expiry -----------------------------------------------------------------


def test_an_expired_certificate_is_reported():
    with lab_server(common_name="localhost", not_before_days=-800, not_after_days=-400) as srv:
        found = findings(srv, "tls-cert-expired")

    assert found and found[0].severity == "critical"


def test_a_current_certificate_is_not_reported_as_expired():
    with lab_server(common_name="localhost") as srv:
        assert findings(srv, "tls-cert-expired") == []


def test_an_expired_certificate_reaches_confirmed_on_two_independent_readings():
    """We parsed the date and the trust path refused it. Different code,
    different failure modes, same conclusion."""
    import tempfile
    from pathlib import Path

    from corpus.generators.tls_lab import LabServer, mint

    with tempfile.TemporaryDirectory() as tmp:
        minted = mint(
            Path(tmp),
            "old",
            common_name="localhost",
            sans=["localhost"],
            not_before_days=-800,
            not_after_days=-400,
        )
        server = LabServer(minted)
        try:
            ctx = ScanContext(
                dns=LabDns(),
                addresses=LAB_ADDRESSES,
                tls=TlsClient(scope=LOOPBACK, trust_anchor=str(minted.cert_path)),
            )
            result = TlsScanner().run(
                Asset(type="url", value=f"https://localhost:{server.port}"), "light", ctx
            )
        finally:
            server.close()

    expired = next(f for f in result.findings if f.check_id == "tls-cert-expired")
    assert {m.independence_class for m in expired.detection_methods} == {
        "certificate",
        "trust_path",
    }
    assert expired.state == "highly_likely"


def test_a_certificate_expiring_soon_is_reported():
    """Whole days are floored, so a certificate minted with 10 days left reports
    9. Understating the time remaining is the safe direction for an expiry
    warning, and rounding up would tell someone they have a day they do not."""
    with lab_server(common_name="localhost", not_after_days=10) as srv:
        found = findings(srv, "tls-cert-expiring-soon")

    assert found
    assert "9 days" in found[0].description


def test_a_certificate_expiring_within_a_week_is_more_severe():
    with lab_server(common_name="localhost", not_after_days=3) as srv:
        found = findings(srv, "tls-cert-expiring-soon")

    assert found[0].severity == "high"


def test_a_certificate_with_months_left_is_not_reported():
    with lab_server(common_name="localhost", not_after_days=200) as srv:
        assert findings(srv, "tls-cert-expiring-soon") == []


def test_an_already_expired_certificate_is_not_also_reported_as_expiring():
    """One problem, one finding."""
    with lab_server(common_name="localhost", not_before_days=-800, not_after_days=-400) as srv:
        assert findings(srv, "tls-cert-expiring-soon") == []


def test_a_certificate_not_yet_valid_is_reported():
    with lab_server(common_name="localhost", not_before_days=30, not_after_days=400) as srv:
        assert findings(srv, "tls-cert-not-yet-valid")


# --- identity ---------------------------------------------------------------


def test_a_certificate_for_another_name_is_reported():
    with lab_server(common_name="other.test", sans=["other.test"]) as srv:
        found = findings(srv, "tls-hostname-mismatch")

    assert found and "other.test" in found[0].description


def test_a_matching_certificate_is_not_reported():
    with lab_server(common_name="localhost", sans=["localhost"]) as srv:
        assert findings(srv, "tls-hostname-mismatch") == []


def test_a_self_signed_certificate_is_reported():
    with lab_server(common_name="localhost") as srv:
        assert findings(srv, "tls-cert-self-signed")


def test_a_self_signed_finding_names_the_consequence_for_a_visitor():
    with lab_server(common_name="localhost") as srv:
        found = findings(srv, "tls-cert-self-signed")

    assert "warning" in found[0].impact.lower() or "browser" in found[0].impact.lower()


# --- protocols --------------------------------------------------------------


def test_a_server_offering_tls_one_zero_is_reported():
    with lab_server(common_name="localhost", max_version=ssl.TLSVersion.TLSv1) as srv:
        found = findings(srv, "tls-protocol-obsolete", mode="standard")

    assert found and "TLSv1" in found[0].description


def test_a_modern_server_is_not_reported():
    with lab_server(common_name="localhost", min_version=ssl.TLSVersion.TLSv1_2) as srv:
        assert findings(srv, "tls-protocol-obsolete", mode="standard") == []


def test_the_obsolete_protocol_finding_shows_a_current_one_as_its_control():
    with lab_server(common_name="localhost") as srv:
        found = findings(srv, "tls-protocol-obsolete", mode="standard")

    if found:  # only when the lab server actually offers an obsolete version
        assert found[0].evidence[0].control is not None


# --- D17: chain-incompleteness masked by an earlier verify failure ---------


def _expired_incomplete_chain_server(tmp_path):
    from corpus.generators.tls_lab import LabServer, mint_three_level

    root, _, leaf, _ = mint_three_level(
        tmp_path,
        "expinc",
        common_name="localhost",
        sans=["localhost"],
        not_before_days=-800,
        not_after_days=-400,
    )
    return LabServer(leaf, min_version=ssl.TLSVersion.TLSv1_2), root


def test_an_expired_and_incomplete_chain_reports_both_findings(tmp_path):
    server, root = _expired_incomplete_chain_server(tmp_path)
    ctx = ScanContext(
        dns=LabDns(),
        addresses=LAB_ADDRESSES,
        tls=TlsClient(scope=LOOPBACK, trust_anchor=str(root.cert_path)),
    )
    target = Asset(type="url", value=f"https://localhost:{server.port}")
    try:
        result = TlsScanner().run(target, "light", ctx)
    finally:
        server.close()

    reported = {f.check_id for f in result.findings}
    assert "tls-cert-expired" in reported
    assert "tls-chain-incomplete" in reported


def test_expired_and_chain_incomplete_are_two_separate_findings_not_one(tmp_path):
    """One problem, one finding - a certificate that is both expired and
    missing its intermediate is two separate problems, and reporting both is
    correct rather than a double-report of one (docs/14-progress-ledger.md,
    D17)."""
    server, root = _expired_incomplete_chain_server(tmp_path)
    ctx = ScanContext(
        dns=LabDns(),
        addresses=LAB_ADDRESSES,
        tls=TlsClient(scope=LOOPBACK, trust_anchor=str(root.cert_path)),
    )
    target = Asset(type="url", value=f"https://localhost:{server.port}")
    try:
        result = TlsScanner().run(target, "light", ctx)
    finally:
        server.close()

    expired = next(f for f in result.findings if f.check_id == "tls-cert-expired")
    chain = next(f for f in result.findings if f.check_id == "tls-chain-incomplete")
    assert expired.id != chain.id


def test_the_time_neutral_probe_stands_down_once_the_chain_is_already_explained(tmp_path):
    """A genuinely missing chain fails with 'unable to get local issuer'
    whether or not dates are checked (OpenSSL builds the path before it
    checks validity) - so the ordinary `verify_code` already carries the
    no-issuer code here, and the time-neutral probe agrees rather than
    revealing anything further. `verify_code_no_time` is asserted directly
    at the client layer in tests/core/test_tls.py; this proves the scanner's
    finding is unaffected by which of the two branches supplied it."""
    server, root = _expired_incomplete_chain_server(tmp_path)
    ctx = ScanContext(
        dns=LabDns(),
        addresses=LAB_ADDRESSES,
        tls=TlsClient(scope=LOOPBACK, trust_anchor=str(root.cert_path)),
    )
    target = Asset(type="url", value=f"https://localhost:{server.port}")
    try:
        result = TlsScanner().run(target, "light", ctx)
    finally:
        server.close()

    chain_finding = next(f for f in result.findings if f.check_id == "tls-chain-incomplete")
    assert "issuer" in chain_finding.description.lower()


# --- BEAST (first derived finding, ADR-018) ---------------------------------


def test_tls_one_zero_with_a_cbc_cipher_reports_beast():
    with lab_server(
        common_name="localhost", ciphers="AES128-SHA:@SECLEVEL=0", max_version=ssl.TLSVersion.TLSv1
    ) as srv:
        found = findings(srv, "tls-vuln-beast", mode="standard")

    assert found
    assert found[0].derivation == "derived"
    assert found[0].derived_from


def test_beast_confidence_is_exactly_inherited_from_its_premise():
    with lab_server(
        common_name="localhost", ciphers="AES128-SHA:@SECLEVEL=0", max_version=ssl.TLSVersion.TLSv1
    ) as srv:
        result = scan(srv, mode="standard")

    premise = next(f for f in result.findings if f.check_id == "tls-protocol-obsolete")
    beast = next(f for f in result.findings if f.check_id == "tls-vuln-beast")

    assert beast.derived_from == premise.id
    assert beast.confidence == premise.confidence


def test_beast_shares_the_premises_independence_class():
    with lab_server(
        common_name="localhost", ciphers="AES128-SHA:@SECLEVEL=0", max_version=ssl.TLSVersion.TLSv1
    ) as srv:
        found = findings(srv, "tls-vuln-beast", mode="standard")

    assert found
    classes = {m.independence_class for m in found[0].detection_methods}
    assert classes == {"negotiation"}


def test_a_modern_server_does_not_report_beast():
    with lab_server(common_name="localhost", min_version=ssl.TLSVersion.TLSv1_2) as srv:
        assert findings(srv, "tls-vuln-beast", mode="standard") == []


def test_beast_severity_is_medium_and_honest_about_mitigation():
    with lab_server(
        common_name="localhost", ciphers="AES128-SHA:@SECLEVEL=0", max_version=ssl.TLSVersion.TLSv1
    ) as srv:
        found = findings(srv, "tls-vuln-beast", mode="standard")

    assert found and found[0].severity == "medium"
    assert "mitigated" in found[0].impact.lower()


def test_light_mode_never_reports_beast():
    """BEAST depends on protocol enumeration, which is standard-mode only."""
    with lab_server(
        common_name="localhost", ciphers="AES128-SHA:@SECLEVEL=0", max_version=ssl.TLSVersion.TLSv1
    ) as srv:
        assert findings(srv, "tls-vuln-beast", mode="light") == []


# --- certificate strength ---------------------------------------------------


def test_a_weak_key_is_reported():
    with lab_server(common_name="localhost", key_bits=1024) as srv:
        found = findings(srv, "tls-weak-key", mode="standard")

    assert found and "1024" in found[0].description


def test_a_strong_key_is_not_reported():
    with lab_server(common_name="localhost", key_bits=2048) as srv:
        assert findings(srv, "tls-weak-key", mode="standard") == []


def test_a_sha1_signature_is_reported():
    with lab_server(common_name="localhost", digest="sha1") as srv:
        found = findings(srv, "tls-weak-signature", mode="standard")

    assert found and "sha1" in found[0].description.lower()


def test_a_sha256_signature_is_not_reported():
    with lab_server(common_name="localhost") as srv:
        assert findings(srv, "tls-weak-signature", mode="standard") == []


def test_a_certificate_without_transparency_proof_is_informational_only():
    with lab_server(common_name="localhost") as srv:
        found = findings(srv, "tls-no-certificate-transparency", mode="standard")

    assert found and found[0].state == "informational"


# --- when we cannot tell ----------------------------------------------------


def test_an_unreachable_port_is_inconclusive_not_a_finding():
    class Closed:
        port = 1

    result = scan(Closed())

    assert result.errors == []
    assert all(f.state == "inconclusive" for f in result.findings)


def test_an_unreachable_port_does_not_claim_the_certificate_is_bad():
    class Closed:
        port = 1

    assert claims(scan(Closed())) == []


def test_an_unreachable_target_counts_towards_the_inconclusive_rate():
    class Closed:
        port = 1

    assert scan(Closed()).inconclusive_rate() > 0


# --- contract compliance ----------------------------------------------------


def test_every_finding_carries_a_control_alongside_its_test():
    with lab_server(common_name="localhost", key_bits=1024, not_after_days=5) as srv:
        result = scan(srv, mode="standard")

    for finding in result.findings:
        if finding.derivation == "derived":
            # ADR-018: a derived finding makes no new observation of the
            # target - its evidence is the premise finding plus the rule
            # applied, not a control-vs-test pair. core/correlation.py's
            # composition findings are the same shape.
            continue
        assert any(e.has_control() for e in finding.evidence), finding.check_id


def test_every_finding_declares_a_justified_prior():
    with lab_server(common_name="localhost", key_bits=1024) as srv:
        result = scan(srv, mode="standard")

    for finding in result.findings:
        for method in finding.detection_methods:
            assert method.prior_justification, finding.check_id


def test_every_finding_has_actionable_remediation():
    with lab_server(common_name="localhost", key_bits=1024, not_after_days=5) as srv:
        result = scan(srv, mode="standard")

    for finding in result.findings:
        assert len(finding.remediation) > 40, finding.check_id


def test_the_result_validates_against_the_frozen_schema():
    import json
    from pathlib import Path

    from jsonschema import Draft202012Validator
    from referencing import Registry, Resource

    contracts = Path(__file__).resolve().parents[3] / "contracts"
    registry = Registry()
    schemas = {}
    for path in contracts.glob("*.schema.json"):
        schema = json.loads(path.read_text())
        schemas[path.name] = schema
        registry = registry.with_resource(schema["$id"], Resource.from_contents(schema))

    with lab_server(common_name="localhost", key_bits=1024, not_after_days=5) as srv:
        result = scan(srv, mode="standard")

    Draft202012Validator(schemas["scanresult.schema.json"], registry=registry).validate(
        json.loads(result.model_dump_json())
    )


def test_the_scanner_rejects_a_target_type_it_cannot_handle():
    from core.scanner import UnsupportedTargetError

    with pytest.raises(UnsupportedTargetError):
        TlsScanner().validate(Asset(type="repo", value="git@example.com:x/y.git"))


def test_the_scanner_is_registered():
    from core.registry import get_scanner

    assert get_scanner("tls") is TlsScanner


# --- how a target gets turned into an endpoint ------------------------------


@pytest.mark.parametrize(
    ("asset_type", "value", "expected"),
    [
        ("url", "https://example.com/path", ("example.com", 443)),
        ("url", "https://example.com:8443/", ("example.com", 8443)),
        ("domain", "example.com", ("example.com", 443)),
        ("domain", "example.com:8443", ("example.com", 8443)),
        ("ip", "192.0.2.1", ("192.0.2.1", 443)),
        # A URL handed in under the default target type. Found live: the CLI
        # defaults to `domain`, so this is what most people will actually type.
        ("domain", "https://example.com", ("example.com", 443)),
        ("domain", "https://example.com:8443", ("example.com", 8443)),
    ],
)
def test_the_endpoint_is_parsed_however_the_target_was_expressed(asset_type, value, expected):
    from scanners.tls.scanner import _endpoint

    assert _endpoint(Asset(type=asset_type, value=value)) == expected


# --- untrusted root is not a self-signed certificate ------------------------


def _chain_server(tmp, **leaf_kwargs):
    from pathlib import Path

    from corpus.generators.tls_lab import LabServer, mint_chain

    _, leaf, chain = mint_chain(
        Path(tmp), "c", common_name="localhost", sans=["localhost"], **leaf_kwargs
    )
    return LabServer(leaf, chain_file=chain)


def test_a_chain_ending_at_an_unknown_root_is_not_called_self_signed():
    """Found live: untrusted-root.badssl.com was reported as self-signed, when
    its subject and issuer plainly differ. OpenSSL's code 19 says a root in the
    chain is self-signed - which every root is - and says nothing about the leaf."""
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        server = _chain_server(tmp)
        try:
            result = scan(server)
        finally:
            server.close()

    reported = {f.check_id for f in result.findings if f.state != "inconclusive"}
    assert "tls-untrusted-root" in reported
    assert "tls-cert-self-signed" not in reported


def test_the_untrusted_root_finding_names_the_issuer_rather_than_the_leaf():
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        server = _chain_server(tmp)
        try:
            found = [f for f in scan(server).findings if f.check_id == "tls-untrusted-root"]
        finally:
            server.close()

    assert found and "Test Root" in found[0].description


def test_a_self_signed_leaf_is_still_reported_as_self_signed():
    with lab_server(common_name="localhost", sans=["localhost"]) as srv:
        reported = {f.check_id for f in scan(srv).findings if f.state != "inconclusive"}

    assert "tls-cert-self-signed" in reported
    assert "tls-untrusted-root" not in reported


# --- two implementations of RFC 6125 ----------------------------------------


def test_a_hostname_mismatch_is_corroborated_by_openssl():
    """Our matcher and OpenSSL's are independent implementations of one rule."""
    with lab_server(common_name="other.test", sans=["other.test"]) as srv:
        found = findings(srv, "tls-hostname-mismatch")

    assert {m.independence_class for m in found[0].detection_methods} == {
        "certificate",
        "trust_path",
    }
    assert found[0].state == "highly_likely"


# --- when there is no TLS service at all ------------------------------------


class _Closed:
    port = 1


def test_a_target_with_no_tls_service_produces_one_finding_not_thirteen():
    """Found live against httpforever.com, an HTTP-only host: seven rows of
    "critical ... inconclusive tls-cert-expired" for a server whose only
    problem is that it does not speak TLS. Each row was individually honest
    and the wall of them was not."""
    result = scan(_Closed())

    assert len(result.findings) == 1
    assert result.findings[0].check_id == "tls-no-handshake"
    assert result.findings[0].state == "inconclusive"


def test_the_no_handshake_finding_says_what_actually_happened():
    finding = scan(_Closed()).findings[0]

    assert "handshake" in finding.description.lower()
    assert finding.evidence[0].test["error"]


def test_checks_that_could_not_run_are_not_claimed_to_have_run():
    """A certificate check on a host with no certificate did not run. Recording
    it would put twelve rows into the inconclusive rate for one closed port."""
    ran = {c.check_id for c in scan(_Closed()).telemetry.checks_run}

    assert ran == {"tls-no-handshake"}


def test_a_refused_handshake_is_still_not_a_scan_error():
    result = scan(_Closed())

    assert result.errors == []
    assert result.outcome == "succeeded"


# --- the evidence must contain the thing the finding claims -----------------


def _obsolete_finding():
    """A server offering TLS 1.0 *and* a current version - the realistic case."""
    with lab_server(common_name="localhost", sans=["localhost"]) as srv:
        return findings(srv, "tls-protocol-obsolete", mode="standard")


def test_the_obsolete_protocol_evidence_shows_the_obsolete_handshake():
    """Found live: the finding said "completed a handshake using TLSv1" while its
    evidence showed a TLS 1.3 handshake twice - test and control byte-identical.
    A claim that is not in its own evidence is the one thing this product
    cannot ship."""
    found = _obsolete_finding()

    assert found, "lab server should offer TLS 1.0"
    assert found[0].evidence[0].test["protocol"] in ("TLSv1", "TLSv1.1")


def test_the_control_shows_the_server_speaking_something_current():
    found = _obsolete_finding()

    control = found[0].evidence[0].control
    assert control is not None
    assert control["protocol"] in ("TLSv1.2", "TLSv1.3")


def test_the_test_and_control_are_not_the_same_observation():
    found = _obsolete_finding()
    evidence = found[0].evidence[0]

    assert evidence.test["protocol"] != evidence.control["protocol"]


def test_a_common_name_only_certificate_is_a_mismatch_and_says_why():
    """D48: RFC 9525 §2 forbids matching the CN, for both readings, and the
    description must not call the certificate "valid for" its CN."""
    import yaml

    from cli.corpus import ROOT, _run_case

    cases = yaml.safe_load((ROOT / "corpus" / "targets" / "tls.yaml").read_text())["cases"]
    (case,) = [c for c in cases if c["id"] == "cn-only"]

    result = _run_case("tls", case)

    (finding,) = [f for f in result.findings if f.check_id == "tls-hostname-mismatch"]
    assert finding.state == "highly_likely"  # our matcher and OpenSSL's agree
    assert "valid for" not in finding.description
    assert "RFC 9525" in finding.description
    assert finding.references == ["https://www.rfc-editor.org/rfc/rfc9525"]


def _scan_ip(server):
    ctx = ScanContext(
        dns=LabDns(), addresses=LAB_ADDRESSES, tls=TlsClient(scope=Scope(frozenset({"127.0.0.1"})))
    )
    target = Asset(type="url", value=f"https://127.0.0.1:{server.port}")
    return TlsScanner().run(target, "light", ctx)


def test_an_ip_target_with_its_ip_san_is_no_mismatch():
    """D48 review, BLOCKER: a valid IP certificate gave a false high mismatch."""
    with lab_server(common_name="127.0.0.1", sans=[], ip_sans=["127.0.0.1"]) as srv:
        result = _scan_ip(srv)

    assert not [f for f in result.findings if f.check_id == "tls-hostname-mismatch"]


def test_a_mismatch_lists_ip_sans_and_never_says_there_are_none():
    with lab_server(common_name="10.0.0.9", sans=[], ip_sans=["10.0.0.9"]) as srv:
        result = _scan_ip(srv)

    (finding,) = [f for f in result.findings if f.check_id == "tls-hostname-mismatch"]
    assert "10.0.0.9" in finding.description
    assert "no subjectAltName" not in finding.description


def test_the_scanner_reports_an_unencodable_host_as_inconclusive():
    """ADR-030: a name idna rejects (a joiner outside CONTEXTJ) is no verdict."""
    from dataclasses import replace

    with lab_server(common_name="ab.example", sans=["ab.example"]) as srv:
        real = TlsClient(scope=LOOPBACK, dns=LabDns(), addresses=LAB_ADDRESSES).inspect(
            "localhost", srv.port, servername="localhost"
        )

    class _Fake(TlsClient):
        def inspect(self, host, port, *, servername=None, **_):
            return replace(real, host=host, port=port, servername=servername)

    host = "a\u200db.example"
    ctx = ScanContext(
        dns=LabDns(), addresses=LAB_ADDRESSES, tls=_Fake(scope=Scope(frozenset({host})))
    )
    result = TlsScanner().run(Asset(type="url", value=f"https://{host}"), "light", ctx)

    (finding,) = [f for f in result.findings if f.check_id == "tls-hostname-mismatch"]
    assert finding.state == "inconclusive"
    assert "UTS-46" in finding.description
