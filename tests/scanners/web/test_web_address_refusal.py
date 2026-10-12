"""D60: a web target, or a redirect hop, resolving to a non-global address.

Nothing is fetched from it. Every check that needed the response is an
`inconclusive` that names the address and why, never a generic transport
error and never a clean result.
"""

from __future__ import annotations

import httpx

from core.context import ScanContext
from core.http import HttpClient
from core.models import Asset
from corpus.generators.tls_lab import LabDns
from scanners.web.scanner import WebScanner
from tests.core.named_transport import named

TARGET = Asset(type="domain", value="example.test")


def _scan(dns, transport=None):
    http = HttpClient.for_scan(TARGET, service_hosts=frozenset(), transport=transport)
    return WebScanner().run(TARGET, "light", ScanContext(dns=dns, http=http))


def test_a_target_resolving_to_private_space_is_named_in_every_inconclusive() -> None:
    result = _scan(LabDns("10.0.0.5"))

    assert result.findings
    for finding in result.findings:
        assert finding.state == "inconclusive"
        assert finding.no_verdict_reason == "blocked_prerequisite"
        assert "10.0.0.5" in finding.description, finding.check_id
        assert "transport error" not in finding.description


def test_a_redirect_into_private_space_is_refused_at_that_hop_and_named() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "example.test":
            return httpx.Response(301, headers={"location": "https://internal.example.test/"})
        return httpx.Response(200, text="must never be fetched")

    pinned: list[str] = []
    dns = LabDns("93.184.215.14", answers={"internal.example.test": "192.168.1.10"})
    result = _scan(dns, transport=named(handler, pinned))

    assert "192.168.1.10" not in pinned
    hsts = next(f for f in result.findings if f.check_id == "web-hsts-missing")
    assert hsts.state == "inconclusive"
    assert "internal.example.test" in hsts.description
    assert "192.168.1.10" in hsts.description


def test_an_address_target_is_not_explained_as_a_dns_problem() -> None:
    """Review nit 4: no DNS was involved, so no split-horizon explanation."""
    target = Asset(type="url", value="http://10.0.0.5/")
    http = HttpClient.for_scan(target, service_hosts=frozenset())
    result = WebScanner().run(target, "light", ScanContext(dns=LabDns(), http=http))
    for finding in result.findings:
        assert "10.0.0.5 is a non-global address" in finding.description, finding.check_id
        assert "split-horizon" not in finding.description


def test_a_name_with_no_address_records_says_the_dns_lookup_failed() -> None:
    """Review round 3: before D60 httpx's own resolver failure read "DNS lookup
    failed"; the policy's must not regress to "transport error"."""
    from core.dns import DnsResponse

    class NoRecords:
        def query(self, name, rrtype, *, resolver=None):
            return DnsResponse(name, rrtype, "NXDOMAIN", [])

    result = _scan(NoRecords())
    for finding in result.findings:
        assert "DNS lookup failed" in finding.description, finding.check_id
        assert "transport error" not in finding.description


def test_an_unwired_resolver_is_a_scan_error_not_an_inconclusive() -> None:
    """A missing resolver is our wiring bug, never a fact about the target."""
    import pytest

    from core.addresses import ResolverNotWiredError

    http = HttpClient.for_scan(TARGET, service_hosts=frozenset())
    with pytest.raises(ResolverNotWiredError):
        WebScanner().run(TARGET, "light", ScanContext(http=http))
