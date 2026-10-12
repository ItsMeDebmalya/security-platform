"""D60 (ADR-036 decision 2): a public name with a non-global record.

The platform refuses to connect to such a name, and says why in the tls and
web checks. The record itself is worth showing the customer: it usually means
split-horizon DNS leaking to public resolvers, or a stale record. `dns-records`
already reads every name's A and AAAA answers, so it carries it, informational,
with no contract change.
"""

from __future__ import annotations

from core.authz import Scope
from core.context import ScanContext
from core.dns import DnsClient
from core.http import HttpClient
from core.models import Asset
from corpus.generators.domscout import FakeResolver, apex_zone, http_backend, live_subdomain
from scanners.domscout.scanner import DomscoutScanner

D = "corpus-split.test"


def _dns_records(apex_ip: str, subs: dict[str, str]):
    zone = {}
    for label, ip in subs.items():
        zone.update(live_subdomain(D, label, ip))
    target = Asset(type="domain", value=D)
    ctx = ScanContext(
        dns=DnsClient(
            resolver=FakeResolver(apex_zone(D, a=apex_ip, subdomains=zone)),
            resolvers=["1.1.1.1", "8.8.8.8"],
        ),
        http=HttpClient.for_scan(
            target,
            service_hosts=DomscoutScanner.service_hosts_for(target),
            backend=http_backend(D, ct_names=[f"{label}.{D}" for label in subs]),
        ),
        scope=Scope(frozenset({D})),
    )
    result = DomscoutScanner().run(target, "light", ctx)
    return [f for f in result.findings if f.check_id == "dns-records"]


def test_a_subdomain_in_private_space_is_named_with_what_it_usually_means() -> None:
    [finding] = _dns_records("93.184.215.14", {"www": "93.184.215.14", "intranet": "10.0.0.5"})

    assert finding.state == "informational"
    assert f"intranet.{D}" in finding.description
    assert "10.0.0.5" in finding.description
    assert "private-use" in finding.description
    assert "split-horizon" in finding.impact
    analysis = finding.evidence[0].analysis
    assert analysis["non_global_addresses"] == {
        f"intranet.{D}": {"10.0.0.5": "private-use (RFC 1918)"}
    }


def test_an_apex_in_metadata_space_is_reported_even_with_no_subdomains() -> None:
    [finding] = _dns_records("169.254.169.254", {})
    assert D in finding.description
    assert "169.254.169.254" in finding.description


def test_all_public_addresses_add_nothing() -> None:
    [finding] = _dns_records("93.184.215.14", {"www": "93.184.215.14"})
    assert "non-global" not in finding.description
    assert finding.evidence[0].analysis["non_global_addresses"] == {}


def test_no_subdomains_and_a_public_apex_still_reports_nothing() -> None:
    assert _dns_records("93.184.215.14", {}) == []
