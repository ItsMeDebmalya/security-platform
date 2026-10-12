"""The DomScout Scanner — orchestration, discovery, evidence, honesty."""

from __future__ import annotations

import json

from core.authz import Scope
from core.context import ScanContext
from core.dns import DnsClient, DnsResponse, FakeResolver
from core.http import HttpClient, RawHttpResponse
from core.models import Asset

APEX = "x.test"


def answer(name, rrtype, *records, rcode="NOERROR", ttl=300):
    return DnsResponse(name=name, rrtype=rrtype, rcode=rcode, records=list(records), ttl=ttl)


class FakeHttpBackend:
    """Records URLs served by fixed status/body, or raises for a listed URL."""

    connects = False  # opens no socket; serves canned answers (D60: backends must say)

    def __init__(self, responses: dict[str, tuple[int, str]], *, fail: set[str] | None = None):
        self._responses = responses
        self._fail = fail or set()
        self.calls: list[str] = []

    def send(self, method, url, *, body_cap, **kwargs):
        self.calls.append(url)
        if url in self._fail:
            raise ConnectionError(f"simulated failure for {url}")
        status, body = self._responses.get(url, (404, ""))
        return RawHttpResponse(
            status_code=status,
            headers={},
            text=body,
            url=url,
            elapsed_ms=1,
        )


def crtsh_json(names: list[str]) -> str:
    return json.dumps([{"name_value": n} for n in names])


def rdap_json(*, expiry: str | None = None) -> str:
    events = []
    if expiry:
        events.append({"eventAction": "expiration", "eventDate": expiry})
    return json.dumps({"events": events, "status": [], "entities": []})


def build_ctx(dns_answers, http_backend, *, org_id="org_internal"):
    domain_scope = Scope(frozenset({APEX, "crt.sh", "rdap.org"}))
    return ScanContext(
        org_id=org_id,
        dns=DnsClient(resolver=FakeResolver(dns_answers), resolvers=["1.1.1.1", "8.8.8.8"]),
        http=HttpClient(scope=domain_scope, backend=http_backend),
        scope=domain_scope,
    )


def run_scan(dns_answers, http_backend):
    from scanners.domscout.scanner import DomscoutScanner

    ctx = build_ctx(dns_answers, http_backend)
    result = DomscoutScanner().run(Asset(type="domain", value=APEX), "light", ctx)
    return result, ctx


def crtsh_test_url() -> str:
    return f"https://crt.sh/?q=%25.{APEX}&output=json"


def crtsh_control_url() -> str:
    return f"https://crt.sh/?q={APEX}&output=json"


def rdap_url() -> str:
    return f"https://rdap.org/domain/{APEX}"


def base_dns() -> dict:
    """Apex resolves, no DS/DNSKEY, wildcard probe NXDOMAIN."""
    return {
        (APEX, "A"): answer(APEX, "A", "192.0.2.1"),
        (APEX, "AAAA"): answer(APEX, "AAAA", rcode="NODATA"),
        (APEX, "CNAME"): answer(APEX, "CNAME", rcode="NODATA"),
        (APEX, "MX"): answer(APEX, "MX", rcode="NODATA"),
        (APEX, "NS"): answer(APEX, "NS", "ns1.x.test."),
        (APEX, "TXT"): answer(APEX, "TXT", rcode="NODATA"),
        (APEX, "SOA"): answer(APEX, "SOA", "ns1.x.test. hostmaster.x.test. 1 2 3 4 5"),
        (APEX, "DS"): answer(APEX, "DS", rcode="NODATA"),
        (APEX, "DNSKEY"): answer(APEX, "DNSKEY", rcode="NODATA"),
    }


def no_op_http(extra: dict[str, tuple[int, str]] | None = None) -> FakeHttpBackend:
    responses = {
        crtsh_test_url(): (200, crtsh_json([])),
        crtsh_control_url(): (200, crtsh_json([])),
        rdap_url(): (200, rdap_json()),
    }
    responses.update(extra or {})
    return FakeHttpBackend(responses)


# --- happy path --------------------------------------------------------


def test_discovers_resolving_subdomain_and_contributes_asset():
    dns_answers = base_dns()
    dns_answers[(f"api.{APEX}", "A")] = answer(f"api.{APEX}", "A", "192.0.2.9")
    dns_answers[(f"api.{APEX}", "AAAA")] = answer(f"api.{APEX}", "AAAA", rcode="NODATA")
    dns_answers[(f"api.{APEX}", "CNAME")] = answer(f"api.{APEX}", "CNAME", rcode="NODATA")

    http = no_op_http({crtsh_test_url(): (200, crtsh_json([f"api.{APEX}"]))})
    result, ctx = run_scan(dns_answers, http)

    ids = {f.check_id for f in result.findings}
    assert "dns-records" in ids

    contributed = ctx.assets.all()
    assert [d.asset.value for d in contributed] == [f"api.{APEX}"]
    assert contributed[0].discovered_by == "domscout"

    check_ids = {c.check_id for c in result.telemetry.checks_run}
    assert check_ids >= {"subdomains-ct-log", "dns-records", "dnssec-status", "subdomain-takeover"}


def test_every_finding_has_a_control_or_a_control_rationale():
    dns_answers = base_dns()
    dns_answers[(f"api.{APEX}", "A")] = answer(f"api.{APEX}", "A", "192.0.2.9")
    dns_answers[(f"api.{APEX}", "AAAA")] = answer(f"api.{APEX}", "AAAA", rcode="NODATA")
    dns_answers[(f"api.{APEX}", "CNAME")] = answer(f"api.{APEX}", "CNAME", rcode="NODATA")

    http = no_op_http({crtsh_test_url(): (200, crtsh_json([f"api.{APEX}"]))})
    result, _ctx = run_scan(dns_answers, http)

    assert result.findings
    for finding in result.findings:
        evidence = finding.evidence[0]
        assert evidence.has_control() or getattr(evidence, "control_rationale", "")


# --- wildcard zone -------------------------------------------------------


def test_wildcard_shadowed_name_is_not_contributed():
    dns_answers = base_dns()
    # A wildcard: the probe and the CT-discovered name resolve to the same address.
    wildcard_addr = "203.0.113.5"
    dns_answers[(f"ghost.{APEX}", "A")] = answer(f"ghost.{APEX}", "A", wildcard_addr)
    dns_answers[(f"ghost.{APEX}", "AAAA")] = answer(f"ghost.{APEX}", "AAAA", rcode="NODATA")
    dns_answers[(f"ghost.{APEX}", "CNAME")] = answer(f"ghost.{APEX}", "CNAME", rcode="NODATA")

    # FakeResolver: unknown names are NXDOMAIN, so any query the scanner makes
    # for a random wildcard-probe label needs a matching answer. We patch the
    # resolver after construction is impractical here, so instead we build a
    # resolver subclass-free approach: seed every possible probe by using a
    # custom FakeResolver wrapper.
    class WildcardResolver(FakeResolver):
        def resolve(self, name, rrtype, resolver=None):
            if name.lower().startswith("sp-wildcard-probe-") and rrtype.upper() == "A":
                return answer(name, "A", wildcard_addr)
            return super().resolve(name, rrtype, resolver)

    http = no_op_http({crtsh_test_url(): (200, crtsh_json([f"ghost.{APEX}"]))})
    ctx = ScanContext(
        dns=DnsClient(resolver=WildcardResolver(dns_answers), resolvers=["1.1.1.1", "8.8.8.8"]),
        http=HttpClient(scope=Scope(frozenset({APEX, "crt.sh", "rdap.org"})), backend=http),
        scope=Scope(frozenset({APEX, "crt.sh", "rdap.org"})),
    )
    from scanners.domscout.scanner import DomscoutScanner

    result = DomscoutScanner().run(Asset(type="domain", value=APEX), "light", ctx)

    assert ctx.assets.all() == []
    reported = [f for f in result.findings if f.state in ("confirmed", "highly_likely")]
    assert not any(f"ghost.{APEX}" in f.description for f in reported)


# --- crt.sh unavailable ---------------------------------------------------


def test_crtsh_unavailable_is_inconclusive_but_other_checks_still_run():
    dns_answers = base_dns()
    http = no_op_http()
    http._fail = {crtsh_test_url(), crtsh_control_url()}

    result, _ctx = run_scan(dns_answers, http)

    ct_checks = [c for c in result.telemetry.checks_run if c.check_id == "subdomains-ct-log"]
    assert ct_checks and ct_checks[0].outcome == "inconclusive"
    ct_findings = [f for f in result.findings if f.check_id == "subdomains-ct-log"]
    assert ct_findings and ct_findings[0].no_verdict_reason is not None

    check_ids = {c.check_id for c in result.telemetry.checks_run}
    assert "dnssec-status" in check_ids
    assert "domain-expiring" in check_ids or "domain-expired" in check_ids


# --- SERVFAIL on apex A ---------------------------------------------------


def test_servfail_on_apex_a_is_inconclusive_not_no_subdomains():
    dns_answers = base_dns()
    dns_answers[(APEX, "A")] = answer(APEX, "A", rcode="SERVFAIL")
    http = no_op_http()

    result, _ctx = run_scan(dns_answers, http)

    dns_records = [f for f in result.findings if f.check_id == "dns-records"]
    assert dns_records
    assert dns_records[0].no_verdict_reason == "servfail"


# --- takeover: dangling and non-dangling ----------------------------------


_S3_NO_SUCH_BUCKET = (
    '<?xml version="1.0" encoding="UTF-8"?>\n<Error><Code>NoSuchBucket</Code>'
    "<Message>The specified bucket does not exist</Message></Error>"
)


def _s3_candidate(dns_answers, sub):
    """D31: the bucket endpoint resolves, as every real one does (recorded)."""
    dns_answers[(sub, "A")] = answer(sub, "A", rcode="NODATA")
    dns_answers[(sub, "AAAA")] = answer(sub, "AAAA", rcode="NODATA")
    dns_answers[(sub, "CNAME")] = answer(sub, "CNAME", "bucket-x.s3.amazonaws.com.")
    dns_answers[("bucket-x.s3.amazonaws.com", "A")] = answer(
        "bucket-x.s3.amazonaws.com", "A", "16.182.41.90"
    )


def test_dangling_s3_cname_is_reported_as_suspected_takeover():
    dns_answers = base_dns()
    sub = f"static.{APEX}"
    _s3_candidate(dns_answers, sub)
    http = no_op_http(
        {crtsh_test_url(): (200, crtsh_json([sub])), f"http://{sub}/": (404, _S3_NO_SUCH_BUCKET)}
    )
    result, _ctx = run_scan(dns_answers, http)

    takeover_findings = [f for f in result.findings if f.check_id == "subdomain-takeover"]
    assert takeover_findings
    assert takeover_findings[0].state == "suspected"
    assert takeover_findings[0].evidence[0].test.request.url == f"http://{sub}/"


def test_non_dangling_cname_to_live_service_is_silent():
    dns_answers = base_dns()
    sub = f"static.{APEX}"
    _s3_candidate(dns_answers, sub)
    http = no_op_http(
        {
            crtsh_test_url(): (200, crtsh_json([sub])),
            f"http://{sub}/": (403, "<Error><Code>AccessDenied</Code></Error>"),
        }
    )
    result, _ctx = run_scan(dns_answers, http)

    takeover_findings = [
        f for f in result.findings if f.check_id == "subdomain-takeover" and f.location == sub
    ]
    assert takeover_findings == []


def test_an_unclaimed_page_served_only_over_https_is_not_what_we_fetch():
    """The fetch is http:// (recorded: over https a custom domain fails the
    provider's certificate). A body served only at https:// is never consulted."""
    dns_answers = base_dns()
    sub = f"static.{APEX}"
    _s3_candidate(dns_answers, sub)
    http = no_op_http(
        {crtsh_test_url(): (200, crtsh_json([sub])), f"https://{sub}/": (404, _S3_NO_SUCH_BUCKET)}
    )
    result, _ctx = run_scan(dns_answers, http)

    assert not [
        f
        for f in result.findings
        if f.check_id == "subdomain-takeover" and f.location == sub and f.state == "suspected"
    ]


# --- CNAME to third party and MX target: RelatedAsset, not contributed ----


def test_third_party_cname_and_mx_target_are_related_assets_not_contributed():
    dns_answers = base_dns()
    dns_answers[(APEX, "MX")] = answer(APEX, "MX", "10 mail.thirdparty.example.")
    sub = f"blog.{APEX}"
    dns_answers[(sub, "A")] = answer(sub, "A", rcode="NODATA")
    dns_answers[(sub, "AAAA")] = answer(sub, "AAAA", rcode="NODATA")
    dns_answers[(sub, "CNAME")] = answer(sub, "CNAME", "blog.thirdparty.example.")

    http = no_op_http({crtsh_test_url(): (200, crtsh_json([sub]))})
    result, ctx = run_scan(dns_answers, http)

    contributed_values = {d.asset.value for d in ctx.assets.all()}
    assert "blog.thirdparty.example" not in contributed_values
    assert "mail.thirdparty.example" not in contributed_values

    dns_records = [f for f in result.findings if f.check_id == "dns-records"]
    if dns_records:
        related_values = {r.value for r in dns_records[0].related_assets}
        assert "blog.thirdparty.example" in related_values or "mail.thirdparty.example" in (
            related_values
        )


def test_resolving_cname_subdomain_is_contributed_with_target_related():
    """A CNAME'd subdomain that RESOLVES is a live owned name — it is contributed
    to the graph, while its third-party target stays a related asset only.

    Regression for the 2026-09-03 live cross-check finding: dropping CNAME'd
    names lost www/accounts/... from real infrastructure."""
    dns_answers = base_dns()
    # accounts -> third-party CNAME that resolves (the A query follows the CNAME).
    acc = f"accounts.{APEX}"
    dns_answers[(acc, "CNAME")] = answer(acc, "CNAME", "customer-books.zoho.com.")
    dns_answers[(acc, "A")] = answer(acc, "A", "204.141.42.79")
    dns_answers[(acc, "AAAA")] = answer(acc, "AAAA", rcode="NODATA")
    # www -> internal alias to the apex, resolving.
    www = f"www.{APEX}"
    dns_answers[(www, "CNAME")] = answer(www, "CNAME", f"{APEX}.")
    dns_answers[(www, "A")] = answer(www, "A", "116.203.1.171")
    dns_answers[(www, "AAAA")] = answer(www, "AAAA", rcode="NODATA")

    http = no_op_http({crtsh_test_url(): (200, crtsh_json([acc, www]))})
    result, ctx = run_scan(dns_answers, http)

    contributed = {d.asset.value for d in ctx.assets.all()}
    assert acc in contributed  # the source name is a discovered subdomain
    assert www in contributed  # an internal alias is still a live name
    assert "customer-books.zoho.com" not in contributed  # never scan the third party
    assert APEX not in contributed  # the apex is the target, not a discovery

    # the third-party target is recorded as a relationship
    dns_rec = next(f for f in result.findings if f.check_id == "dns-records")
    related = {r.value for r in dns_rec.related_assets}
    assert "customer-books.zoho.com" in related
