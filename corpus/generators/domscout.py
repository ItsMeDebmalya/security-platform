"""Generate the frozen DNS + HTTP fixtures for the DomScout corpus.

Each case is a synthetic zone with a known-correct answer, recorded by
**running the scanner itself** through a recording resolver and a recording
HTTP backend — so what is frozen is exactly the queries the scanner makes,
including the second-resolver DNSSEC validation queries (easy to forget by
hand, and their absence would silently turn validation into a no-op on
replay) and the crt.sh / RDAP / takeover HTTP fetches.

Re-run after changing which names or URLs the scanner touches:

    uv run python -m corpus.generators.domscout

What the corpus does and does NOT measure (see the design spec, revised):

- **Subdomain enumeration is informational inventory, not a vulnerability**,
  so it is excluded from the precision/recall gate by design. The corpus
  guards it only against *false discovery* (the known-good and wildcard cases
  must report and contribute nothing false). Completeness ("did we miss a
  subdomain") is unknowable on a frozen set and is assessed live against
  subfinder/crt.sh, never scored.
- **The gate applies to the real security findings.** Only `dnssec-status`
  reaches a validated `confirmed` claim (independent second resolver); the
  expiry and takeover findings are honest `suspected` and excused from the
  gate on both sides. So the gate rests on a small claim count — stated
  loudly, exactly as TLS's does.
- `domain-expiring` (within 30 days) is deliberately NOT a frozen case: the
  scanner compares against wall-clock today, so a fixed near-future date would
  rot. `domain-expired` uses a fixed past date and is stable. The expiring
  path is covered by the scanner unit tests instead.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from core.authz import Scope
from core.context import ScanContext
from core.dns import DnsClient, DnsResponse, FakeResolver, RecordingResolver
from core.http import HttpClient, RawHttpResponse, RecordingHttpBackend
from core.models import Asset
from scanners.domscout import DomscoutScanner

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "corpus" / "fixtures" / "domscout"

FAR_FUTURE = "2035-01-01T00:00:00Z"
LONG_PAST = "2020-01-01T00:00:00Z"
SIGNED_DS = "12345 13 2 0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"
SIGNED_DNSKEY = "257 3 13 AwEAAetc0123456789ABCDEFsignedkeymaterialforcorpususeonly=="


def rr(
    name: str, rrtype: str, *records: str, rcode: str = "NOERROR", ttl: int = 300
) -> DnsResponse:
    return DnsResponse(name=name, rrtype=rrtype, rcode=rcode, records=list(records), ttl=ttl)


def crtsh_json(names: list[str]) -> str:
    return json.dumps([{"name_value": n} for n in names])


def rdap_json(expiry: str | None) -> str:
    events = [{"eventAction": "expiration", "eventDate": expiry}] if expiry else []
    return json.dumps({"events": events, "status": [], "entities": []})


def apex_zone(
    domain: str,
    *,
    a: str | None = "192.0.2.10",
    ds: bool = True,
    subdomains: dict[str, DnsResponse] | None = None,
) -> dict[tuple[str, str], DnsResponse]:
    """The apex's own records. DS/DNSKEY present unless ds=False (unsigned)."""
    answers: dict[tuple[str, str], DnsResponse] = {
        (domain, "A"): rr(domain, "A", *([a] if a else []), rcode="NOERROR" if a else "NODATA"),
        (domain, "AAAA"): rr(domain, "AAAA", rcode="NODATA"),
        (domain, "CNAME"): rr(domain, "CNAME", rcode="NODATA"),
        (domain, "MX"): rr(domain, "MX", rcode="NODATA"),
        (domain, "NS"): rr(domain, "NS", f"ns1.{domain}.", f"ns2.{domain}."),
        (domain, "TXT"): rr(domain, "TXT", rcode="NODATA"),
        (domain, "SOA"): rr(domain, "SOA", f"ns1.{domain}. hostmaster.{domain}. 1 2 3 4 5"),
        (domain, "DS"): (rr(domain, "DS", SIGNED_DS) if ds else rr(domain, "DS", rcode="NODATA")),
        (domain, "DNSKEY"): (
            rr(domain, "DNSKEY", SIGNED_DNSKEY) if ds else rr(domain, "DNSKEY", rcode="NODATA")
        ),
    }
    answers.update(subdomains or {})
    return answers


def live_subdomain(
    domain: str, label: str, ip: str = "192.0.2.20"
) -> dict[tuple[str, str], DnsResponse]:
    name = f"{label}.{domain}"
    return {
        (name, "A"): rr(name, "A", ip),
        (name, "AAAA"): rr(name, "AAAA", rcode="NODATA"),
        (name, "CNAME"): rr(name, "CNAME", rcode="NODATA"),
    }


def cname_subdomain(domain: str, label: str, target: str) -> dict[tuple[str, str], DnsResponse]:
    name = f"{label}.{domain}"
    return {
        (name, "A"): rr(name, "A", rcode="NXDOMAIN"),
        (name, "AAAA"): rr(name, "AAAA", rcode="NXDOMAIN"),
        (name, "CNAME"): rr(name, "CNAME", f"{target}."),
    }


def resolving_cname_subdomain(
    domain: str, label: str, target: str, ip: str = "203.0.113.9"
) -> dict[tuple[str, str], DnsResponse]:
    """A CNAME'd subdomain that RESOLVES: the A query follows the CNAME and
    returns the final address, as a real resolver does. Such a name is a live
    owned subdomain and must be contributed (2026-09-03 live-cross-check fix)."""
    name = f"{label}.{domain}"
    return {
        (name, "A"): rr(name, "A", ip),
        (name, "AAAA"): rr(name, "AAAA", rcode="NODATA"),
        (name, "CNAME"): rr(name, "CNAME", f"{target}."),
    }


class ServfailResolver:
    """Every lookup fails. The scanner must say inconclusive, not "nothing"."""

    def resolve(self, name: str, rrtype: str, resolver: str | None = None) -> DnsResponse:
        return DnsResponse(name=name, rrtype=rrtype, rcode="SERVFAIL", records=[], ttl=None)


class WildcardAResolver:
    """Answers every A query under the apex with one fixed address (a real
    wildcard zone), delegating all other rrtypes to a base FakeResolver.

    Lets the corpus prove a CT-log name that only "resolves" via the wildcard
    is not contributed and not confirmed — the core no-false-discovery
    property — which a plain FakeResolver cannot express (its random
    wildcard probe would fall through to NXDOMAIN)."""

    def __init__(self, domain: str, base: dict[tuple[str, str], DnsResponse], ip: str) -> None:
        self._domain = domain
        self._base = FakeResolver(base)
        self._ip = ip

    def resolve(self, name: str, rrtype: str, resolver: str | None = None) -> DnsResponse:
        lname = name.lower().rstrip(".")
        if rrtype.upper() == "A" and (lname == self._domain or lname.endswith("." + self._domain)):
            return rr(name, "A", self._ip)
        return self._base.resolve(name, rrtype, resolver)


class FakeHttpBackend:
    """Serves fixed status/body per URL; raises for a URL in `fail`."""

    def __init__(
        self, responses: dict[str, tuple[int, str]], *, fail: set[str] | None = None
    ) -> None:
        self._responses = responses
        self._fail = fail or set()

    def send(self, method: str, url: str, *, body_cap: int, **kwargs: object) -> RawHttpResponse:
        if url in self._fail:
            raise ConnectionError(f"simulated failure for {url}")
        status, body = self._responses.get(url, (404, ""))
        return RawHttpResponse(status_code=status, headers={}, text=body, url=url, elapsed_ms=1)


def crtsh_urls(domain: str) -> tuple[str, str]:
    return (
        f"https://crt.sh/?q=%25.{domain}&output=json",
        f"https://crt.sh/?q={domain}&output=json",
    )


def http_backend(
    domain: str,
    *,
    ct_names: list[str],
    expiry: str | None,
    extra: dict[str, tuple[int, str]] | None = None,
    fail: set[str] | None = None,
) -> FakeHttpBackend:
    test_url, control_url = crtsh_urls(domain)
    responses: dict[str, tuple[int, str]] = {
        test_url: (200, crtsh_json(ct_names)),
        control_url: (200, crtsh_json([])),
        f"https://rdap.org/domain/{domain}": (200, rdap_json(expiry)),
    }
    responses.update(extra or {})
    return FakeHttpBackend(responses, fail=fail)


# case_id -> (domain, dns_resolver, http_backend, mode)
def _cases() -> dict[str, tuple[str, object, FakeHttpBackend, str]]:
    cases: dict[str, tuple[str, object, FakeHttpBackend, str]] = {}

    # 1. known-good: signed, expiry far, no subdomains. Report nothing.
    d = "corpus-good.test"
    cases["known-good"] = (
        d,
        FakeResolver(apex_zone(d)),
        http_backend(d, ct_names=[], expiry=FAR_FUTURE),
        "light",
    )

    # 2. enum-basic: three live subdomains discovered; no security flaw.
    d = "corpus-enum.test"
    subs = {**live_subdomain(d, "www"), **live_subdomain(d, "api"), **live_subdomain(d, "blog")}
    cases["enum-basic"] = (
        d,
        FakeResolver(apex_zone(d, subdomains=subs)),
        http_backend(d, ct_names=[f"www.{d}", f"api.{d}", f"blog.{d}"], expiry=FAR_FUTURE),
        "light",
    )

    # 2b. enum-cname: a CNAME'd subdomain that resolves is contributed (its
    # third-party target stays a related asset); an internal www alias too.
    d = "corpus-cname.test"
    subs = {
        # a generic SaaS target (not a takeover fingerprint) so this case
        # exercises CNAME contribution only, not the takeover path.
        **resolving_cname_subdomain(d, "app", "customer-books.zoho.com"),
        **resolving_cname_subdomain(d, "www", d),
    }
    cases["enum-cname"] = (
        d,
        FakeResolver(apex_zone(d, subdomains=subs)),
        http_backend(d, ct_names=[f"app.{d}", f"www.{d}"], expiry=FAR_FUTURE),
        "light",
    )

    # 3. dnssec-insecure: no DS/DNSKEY -> confirmed via second resolver.
    d = "corpus-nodnssec.test"
    cases["dnssec-insecure"] = (
        d,
        FakeResolver(apex_zone(d, ds=False)),
        http_backend(d, ct_names=[], expiry=FAR_FUTURE),
        "light",
    )

    # 4. domain-expired: fixed past date -> stable. Suspected (single RDAP source).
    d = "corpus-expired.test"
    cases["domain-expired"] = (
        d,
        FakeResolver(apex_zone(d)),
        http_backend(d, ct_names=[], expiry=LONG_PAST),
        "light",
    )

    # 5. takeover-positive: dangling S3 CNAME (target NXDOMAIN, DNS-only).
    d = "corpus-takeover.test"
    subs = cname_subdomain(d, "gone", "bucket-abandoned.s3.amazonaws.com")
    cases["takeover-positive"] = (
        d,
        FakeResolver(apex_zone(d, subdomains=subs)),
        http_backend(d, ct_names=[f"gone.{d}"], expiry=FAR_FUTURE),
        "light",
    )

    # 6. takeover-negative: CNAME to a live GitHub Pages site -> silent.
    d = "corpus-liveghp.test"
    subs = {
        **cname_subdomain(d, "blog", "owner.github.io"),
        ("owner.github.io", "A"): rr("owner.github.io", "A", "185.199.108.153"),
        ("owner.github.io", "AAAA"): rr("owner.github.io", "AAAA", rcode="NODATA"),
        ("owner.github.io", "CNAME"): rr("owner.github.io", "CNAME", rcode="NODATA"),
    }
    cases["takeover-negative"] = (
        d,
        FakeResolver(apex_zone(d, subdomains=subs)),
        http_backend(
            d,
            ct_names=[f"blog.{d}"],
            expiry=FAR_FUTURE,
            extra={f"https://blog.{d}/": (200, "<html><body>a real published blog</body></html>")},
        ),
        "light",
    )

    # 6b. takeover-secret (ADR-029): the dangling GitHub Pages subdomain's page
    # also serves a credential-shaped key, AWS's own documented example key.
    # The takeover evidence cites that response, so its receipt is reported.
    d = "corpus-takesecret.test"
    subs = {
        **cname_subdomain(d, "docs", "owner.github.io"),
        ("owner.github.io", "A"): rr("owner.github.io", "A", "185.199.108.153"),
        ("owner.github.io", "AAAA"): rr("owner.github.io", "AAAA", rcode="NODATA"),
        ("owner.github.io", "CNAME"): rr("owner.github.io", "CNAME", rcode="NODATA"),
    }
    cases["takeover-secret"] = (
        d,
        FakeResolver(apex_zone(d, subdomains=subs)),
        http_backend(
            d,
            ct_names=[f"docs.{d}"],
            expiry=FAR_FUTURE,
            extra={
                f"https://docs.{d}/": (
                    404,
                    "<html><body>There isn't a GitHub Pages site here. "
                    "<!-- deploy key AKIAIOSFODNN7EXAMPLE --></body></html>",
                )
            },
        ),
        "light",
    )

    # 7. wildcard-zone: every A resolves; CT ghosts must not be contributed.
    d = "corpus-wildcard.test"
    cases["wildcard-zone"] = (
        d,
        WildcardAResolver(d, apex_zone(d), ip="198.51.100.7"),
        http_backend(d, ct_names=[f"ghost1.{d}", f"ghost2.{d}"], expiry=FAR_FUTURE),
        "light",
    )

    # 8. servfail: DNS + crt.sh + RDAP all fail -> inconclusive, not "nothing".
    d = "corpus-broken.test"
    test_url, control_url = crtsh_urls(d)
    cases["servfail"] = (
        d,
        ServfailResolver(),
        FakeHttpBackend(
            {},
            fail={test_url, control_url, f"https://rdap.org/domain/{d}"},
        ),
        "light",
    )
    return cases


def generate(only: set[str] | None = None) -> None:
    for case_id, (domain, resolver, backend, mode) in _cases().items():
        if only is not None and case_id not in only:
            continue
        directory = FIXTURES / case_id
        if directory.exists():
            shutil.rmtree(directory)
        directory.mkdir(parents=True, exist_ok=True)
        scope = Scope(frozenset({domain, "crt.sh", "rdap.org"}))
        ctx = ScanContext(
            dns=DnsClient(
                resolver=RecordingResolver(resolver, directory),
                resolvers=["1.1.1.1", "8.8.8.8"],
            ),
            http=HttpClient(scope=scope, backend=RecordingHttpBackend(directory, backend)),
            scope=scope,
            progress=lambda message, fraction: None,
        )
        result = DomscoutScanner().run(Asset(type="domain", value=domain), mode, ctx)
        reported = [
            f"{f.check_id}@{f.location}"
            for f in result.findings
            if f.state in ("confirmed", "highly_likely")
        ]
        suspected = [f.check_id for f in result.findings if f.state == "suspected"]
        inconclusive = [f.check_id for f in result.findings if f.state == "inconclusive"]
        assets = [a.asset.value for a in ctx.assets.all()]
        print(
            f"{case_id:<20} {len(list(directory.iterdir())):>3} fixtures  "
            f"reported={reported} suspected={suspected} "
            f"inconclusive={inconclusive} assets={assets}"
        )


if __name__ == "__main__":
    import sys

    generate(set(sys.argv[1:]) or None)
