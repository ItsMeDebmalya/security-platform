"""D28 / ADR-031 / ADR-032: registration expiry read from the registry's own RDAP server."""

from __future__ import annotations

import json
from datetime import UTC, date, datetime, timedelta

import pytest

from core.authz import Scope
from core.context import ScanContext
from core.dns import DnsClient, FakeResolver
from core.http import HttpClient, RawHttpResponse
from core.models import Asset
from scanners.domscout.scanner import DomscoutScanner
from tests.scanners.domscout.test_domscout_scanner import answer, crtsh_json, rdap_json

VERISIGN = "https://rdap.verisign.com/com/v1/domain/"


class Backend:
    def __init__(self, responses: dict[str, tuple[int, str, dict[str, str]]]):
        self._responses = responses
        self.calls: list[str] = []

    def send(self, method, url, *, body_cap, **kwargs):
        self.calls.append(url)
        if url.startswith("https://crt.sh/"):
            return RawHttpResponse(
                status_code=200, headers={}, text=crtsh_json([]), url=url, elapsed_ms=1
            )
        status, body, headers = self._responses.get(url, (404, "", {}))
        return RawHttpResponse(
            status_code=status, headers=headers, text=body, url=url, elapsed_ms=1
        )


def _dns(apex: str) -> dict:
    out = {
        (apex, rr): answer(apex, rr, rcode="NODATA")
        for rr in ("AAAA", "CNAME", "MX", "TXT", "DS", "DNSKEY")
    }
    out[(apex, "A")] = answer(apex, "A", "192.0.2.1")
    out[(apex, "NS")] = answer(apex, "NS", f"ns1.{apex}.")
    out[(apex, "SOA")] = answer(apex, "SOA", f"ns1.{apex}. h.{apex}. 1 2 3 4 5")
    return out


def _scan(apex: str, responses: dict[str, tuple[int, str, dict[str, str]]] | None = None):
    backend = Backend(responses or {})
    target = Asset(type="domain", value=apex)
    scope = Scope(
        frozenset(Scope.for_target(target).hosts | DomscoutScanner.service_hosts_for(target))
    )
    ctx = ScanContext(
        dns=DnsClient(resolver=FakeResolver(_dns(apex)), resolvers=["1.1.1.1", "8.8.8.8"]),
        http=HttpClient(scope=scope, backend=backend),
        scope=scope,
    )
    return DomscoutScanner().run(target, "light", ctx), backend


def _runs(result, check_id):
    return [c for c in result.telemetry.checks_run if c.check_id == check_id]


def _expiry_finding(result):
    return [f for f in result.findings if f.check_id in ("domain-expiring", "domain-expired")]


def _iso(days: int) -> str:
    return (datetime.now(UTC).date() + timedelta(days=days)).isoformat() + "T00:00:00Z"


# --- which hosts a scan may reach --------------------------------------------


@pytest.mark.parametrize(
    ("domain", "hosts"),
    [
        ("amazon.in", {"crt.sh", "rdap.nixiregistry.in"}),
        ("example.com", {"crt.sh", "rdap.verisign.com"}),
        ("corpus-x.test", {"crt.sh"}),
        ("codez.io", {"crt.sh"}),
    ],
)
def test_service_hosts_are_crt_sh_plus_only_the_target_s_own_registry(domain, hosts):
    assert DomscoutScanner.service_hosts_for(Asset(type="domain", value=domain)) == hosts


# --- special-use names: expiry does not apply, said explicitly -----------------


def test_a_special_use_name_is_not_applicable_never_a_silent_pass():
    result, backend = _scan("corpus-x.test")

    for check_id in ("domain-expiring", "domain-expired"):
        (run,) = _runs(result, check_id)
        assert (run.outcome, run.reason) == ("not_applicable", "special-use-name")
    assert _expiry_finding(result) == []
    assert not [c for c in backend.calls if "rdap" in c]
    assert result.not_applicable_count() == 2


# --- read from the registry ----------------------------------------------------


def test_the_registry_is_queried_directly_and_rdap_org_never():
    result, backend = _scan(
        "corpus-x.com", {VERISIGN + "corpus-x.com": (200, rdap_json(expiry=_iso(400)), {})}
    )

    assert VERISIGN + "corpus-x.com" in backend.calls
    assert not [c for c in backend.calls if "rdap.org" in c]
    assert [r.outcome for r in _runs(result, "domain-expiring")] == ["clear"]
    assert [r.outcome for r in _runs(result, "domain-expired")] == ["clear"]


def test_an_expiry_within_30_days_is_reported_from_the_registry_s_record():
    result, _ = _scan(
        "corpus-x.com", {VERISIGN + "corpus-x.com": (200, rdap_json(expiry=_iso(10)), {})}
    )

    (finding,) = _expiry_finding(result)
    assert finding.check_id == "domain-expiring"
    assert finding.state == "suspected"
    assert finding.materialises_at == date.fromisoformat(_iso(10)[:10])
    assert finding.evidence[0].test.request.url == VERISIGN + "corpus-x.com"


def test_an_expiry_in_the_past_is_domain_expired():
    result, _ = _scan(
        "corpus-x.com", {VERISIGN + "corpus-x.com": (200, rdap_json(expiry=_iso(-3)), {})}
    )

    assert [f.check_id for f in _expiry_finding(result)] == ["domain-expired"]


# --- every way of not reading it is said as what happened -------------------------


def test_a_redirect_is_reported_as_a_redirect_never_parsed_as_a_body():
    redirect = (302, "", {"location": "https://rdap.elsewhere.example/domain/corpus-x.com"})
    result, _ = _scan("corpus-x.com", {VERISIGN + "corpus-x.com": redirect})

    (finding,) = _expiry_finding(result)
    assert finding.state == "inconclusive"
    assert "redirected to rdap.elsewhere.example" in finding.description
    assert "may not contact" in finding.description
    assert "expiration event" not in finding.description


def test_a_name_the_registry_does_not_hold_says_so_and_names_the_psl_gap():
    result, _ = _scan("sub.corpus-x.com")

    (finding,) = _expiry_finding(result)
    assert finding.state == "inconclusive"
    assert "has no registration for sub.corpus-x.com (HTTP 404)" in finding.description
    assert "D49" in finding.description


def test_a_tld_missing_from_the_bootstrap_sends_no_request_and_is_inconclusive():
    result, backend = _scan("codez.io")

    (finding,) = _expiry_finding(result)
    assert finding.state == "inconclusive"
    assert "lists no RDAP server" in finding.description
    assert not [c for c in backend.calls if not c.startswith("https://crt.sh/")]


def test_a_record_with_no_expiration_event_is_the_registry_s_record_and_says_so():
    result, _ = _scan("corpus-x.com", {VERISIGN + "corpus-x.com": (200, rdap_json(), {})})

    (finding,) = _expiry_finding(result)
    assert finding.state == "inconclusive"
    assert (
        "from the registry (rdap.verisign.com) carries no expiration event" in finding.description
    )


def test_a_client_error_is_its_own_inconclusive_not_a_parsed_empty_body():
    result, _ = _scan("corpus-x.com", {VERISIGN + "corpus-x.com": (403, "denied", {})})

    (finding,) = _expiry_finding(result)
    assert "returned HTTP 403" in finding.description


# --- the record names what it is about (NIXI, 2026-10-10) ------------------------

NIXI = "https://rdap.nixiregistry.in/rdap/domain/"


def _record(name: str, days: int) -> str:
    body = json.loads(rdap_json(expiry=_iso(days)))
    body["ldhName"] = name
    return json.dumps(body)


def test_a_parent_s_record_is_reported_under_the_parent_s_name():
    """NIXI answers www.<d> with <d>'s record; the date is <d>'s, and says so."""
    result, _ = _scan(
        "www.corpus-x.in", {NIXI + "www.corpus-x.in": (200, _record("CORPUS-X.IN", 5), {})}
    )

    (finding,) = _expiry_finding(result)
    assert finding.check_id == "domain-expiring"
    assert finding.description.startswith(
        "corpus-x.in (the registered domain above www.corpus-x.in, "
        "as the registry's record names it)"
    )


def test_a_record_for_an_unrelated_name_is_never_attributed():
    result, _ = _scan("corpus-x.in", {NIXI + "corpus-x.in": (200, _record("other.in", 5), {})})

    (finding,) = _expiry_finding(result)
    assert finding.state == "inconclusive"
    assert "with the record for other.in" in finding.description


def test_a_pir_style_400_reads_like_a_404():
    pir = "https://rdap.publicinterestregistry.org/rdap/domain/www.corpus-x.org"
    result, _ = _scan("www.corpus-x.org", {pir: (400, "{}", {})})

    (finding,) = _expiry_finding(result)
    assert "has no registration for www.corpus-x.org (HTTP 400)" in finding.description
    assert "D49" in finding.description


# --- real registries, recorded (corpus) -----------------------------------------


@pytest.mark.parametrize(
    ("case_id", "registry"),
    [
        ("real-verisign", "rdap.verisign.com"),
        ("real-pir", "rdap.publicinterestregistry.org"),
        ("real-nixi", "rdap.nixiregistry.in"),
    ],
)
def test_a_real_registry_s_recorded_record_is_read(case_id, registry):
    """The verdict moves with today's date; that the expiry is read must not."""
    from cli.corpus import _run_case
    from tests.contract.test_not_applicable_contract import CASES

    (case,) = [c for s, c in CASES if s == "domscout" and c["id"] == case_id]
    result = _run_case("domscout", case)

    runs = {r.check_id: r.outcome for r in result.telemetry.checks_run}
    assert runs["domain-expiring"] in ("clear", "reported")
    assert not [f for f in _expiry_finding(result) if f.state == "inconclusive"]
