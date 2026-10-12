"""D60: a TLS target whose name resolves to a non-global address.

Nothing is connected to. The scan says so, names the address and what it
usually means, and never reads like an unreachable server or a clean one.
"""

from __future__ import annotations

from core.authz import Scope
from core.context import ScanContext
from core.models import Asset
from core.tls import TlsClient
from corpus.generators.tls_lab import LabDns
from scanners.tls import TlsScanner


def _scan(address: str, mode: str = "light"):
    ctx = ScanContext(
        dns=LabDns(address),
        tls=TlsClient(scope=Scope(frozenset({"example.test"}))),
    )
    return TlsScanner().run(Asset(type="url", value="https://example.test"), mode, ctx)


def test_a_private_address_is_refused_named_and_inconclusive() -> None:
    result = _scan("10.0.0.5")

    [finding] = [f for f in result.findings if f.check_id == "tls-no-handshake"]
    assert finding.state == "inconclusive"
    assert finding.no_verdict_reason == "blocked_prerequisite"
    assert "10.0.0.5" in finding.description
    assert "private-use" in finding.description
    assert "not connected to" in finding.description
    assert "split-horizon" in finding.impact
    assert "firewall" not in finding.remediation
    # No certificate check claims anything about a server we never reached.
    assert {f.check_id for f in result.findings} == {"tls-no-handshake"}


def test_cloud_metadata_is_refused_in_standard_mode_too() -> None:
    result = _scan("169.254.169.254", mode="standard")
    [finding] = [f for f in result.findings if f.check_id == "tls-no-handshake"]
    assert "169.254.169.254" in finding.description
    assert "link-local" in finding.description


def test_an_address_target_is_described_as_an_address_not_a_name() -> None:
    ctx = ScanContext(dns=LabDns(), tls=TlsClient(scope=Scope(frozenset({"127.0.0.1"}))))
    result = TlsScanner().run(Asset(type="url", value="https://127.0.0.1:8443"), "light", ctx)
    [finding] = result.findings
    assert "127.0.0.1 is a non-global address (127.0.0.1: loopback (RFC 1122))" in (
        finding.description
    )
    assert "resolves" not in finding.description
    assert "split-horizon" not in finding.impact


def test_a_name_that_does_not_resolve_gets_dns_advice_not_firewall_advice() -> None:
    class NoRecords:
        def query(self, name, rrtype, *, resolver=None):
            from core.dns import DnsResponse

            return DnsResponse(name, rrtype, "NXDOMAIN", [])

    ctx = ScanContext(dns=NoRecords(), tls=TlsClient(scope=Scope(frozenset({"example.test"}))))
    [finding] = (
        TlsScanner().run(Asset(type="url", value="https://example.test"), "light", ctx).findings
    )
    assert "could not be resolved" in finding.description
    assert "address_unresolved:" not in finding.description
    assert "firewall" not in finding.remediation
    assert "DNS" in finding.remediation
