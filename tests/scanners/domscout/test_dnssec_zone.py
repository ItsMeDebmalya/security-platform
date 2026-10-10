"""D53: DNSSEC is judged at the zone a name belongs to, never at the name itself.

DS records exist only at delegations, so a name inside a signed zone has no DS
of its own. Judging www.nixi.in by its own (empty) DS and DNSKEY claimed "not
signed" at `confirmed`, although nixi.in is signed.
"""

from __future__ import annotations

from core.authz import Scope
from core.context import ScanContext
from core.dns import DnsClient, FakeResolver
from core.http import HttpClient
from core.models import Asset
from scanners.domscout.scanner import DomscoutScanner
from tests.scanners.domscout.test_domscout_scanner import (
    FakeHttpBackend,
    answer,
    crtsh_json,
)


def test_the_real_www_nixi_in_recording_claims_nothing_about_dnssec():
    """Regression case, recorded live: nixi.in is signed; www.nixi.in is inside it."""
    from cli.corpus import _run_case
    from tests.contract.test_not_applicable_contract import CASES

    (case,) = [c for s, c in CASES if s == "domscout" and c["id"] == "real-subdomain-signed"]
    result = _run_case("domscout", case)

    assert [f for f in result.findings if f.check_id == "dnssec-status"] == []
    assert [r.outcome for r in result.telemetry.checks_run if r.check_id == "dnssec-status"] == [
        "clear"
    ]


# --- synthetic: the zone walk -------------------------------------------------------

APEX = "corpus-zone.test"


def _zone(signed: bool) -> dict:
    nodata = dict(rcode="NODATA")
    out = {}
    for name in (APEX, f"www.{APEX}", f"deep.www.{APEX}"):
        for rr in ("A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "DS", "DNSKEY"):
            out[(name, rr)] = answer(name, rr, **nodata)
        out[(name, "A")] = answer(name, "A", "192.0.2.1")
    out[(APEX, "SOA")] = answer(APEX, "SOA", f"ns1.{APEX}. h.{APEX}. 1 2 3 4 5")
    if signed:
        out[(APEX, "DS")] = answer(APEX, "DS", "1 13 2 ABCDEF")
        out[(APEX, "DNSKEY")] = answer(APEX, "DNSKEY", "257 3 13 AwEAAa==")
    return out


def _scan(name: str, answers: dict):
    target = Asset(type="domain", value=name)
    scope = Scope(frozenset({name, "crt.sh"}))
    http = FakeHttpBackend(
        {
            f"https://crt.sh/?q=%25.{name}&output=json": (200, crtsh_json([])),
            f"https://crt.sh/?q={name}&output=json": (200, crtsh_json([])),
        }
    )
    ctx = ScanContext(
        dns=DnsClient(resolver=FakeResolver(answers), resolvers=["1.1.1.1", "8.8.8.8"]),
        http=HttpClient(scope=scope, backend=http),
        scope=scope,
    )
    return DomscoutScanner().run(target, "light", ctx)


def _dnssec(result):
    return [f for f in result.findings if f.check_id == "dnssec-status"]


def test_a_subdomain_of_a_signed_zone_is_clear():
    assert _dnssec(_scan(f"deep.www.{APEX}", _zone(signed=True))) == []


def test_a_subdomain_of_an_unsigned_zone_reports_the_zone_by_name():
    (finding,) = _dnssec(_scan(f"www.{APEX}", _zone(signed=False)))

    assert finding.state == "confirmed"
    assert finding.description.startswith(f"www.{APEX} is in the zone {APEX}, which publishes")


def test_the_apex_is_judged_as_itself():
    (finding,) = _dnssec(_scan(APEX, _zone(signed=False)))

    assert finding.description.startswith(f"{APEX} publishes no DS record")


def test_a_cname_is_never_taken_for_a_zone_apex():
    """dnspython follows a CNAME, so a SOA query there can return the target zone's SOA."""
    answers = _zone(signed=True)
    name = f"www.{APEX}"
    answers[(name, "CNAME")] = answer(name, "CNAME", "elsewhere.example.")
    answers[(name, "SOA")] = answer(name, "SOA", "ns.elsewhere.example. h. 1 2 3 4 5")

    assert _dnssec(_scan(name, answers)) == []


def test_a_zone_walk_that_cannot_finish_is_inconclusive():
    answers = _zone(signed=True)
    answers[(APEX, "SOA")] = answer(APEX, "SOA", rcode="SERVFAIL")

    (finding,) = _dnssec(_scan(f"www.{APEX}", answers))
    assert finding.state == "inconclusive"
    assert "zone" in finding.description
