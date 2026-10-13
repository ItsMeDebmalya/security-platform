"""A wiring or fixture error is never a statement about the target (D66).

domscout's three `except Exception` handlers each turn a failed fetch into an
`inconclusive` finding, which is right for a network failure: "this source
could not be read" is true, and it is what the customer should be told. It is
wrong for two errors that are about us, not about the target:

- `ResolverNotWiredError` - the scan was built without a resolver, so the
  address policy could not run. D60 settled that this is a scan error, never
  an inconclusive.
- `MissingFixtureError` - a replay asked for an interaction that was never
  recorded. The check did not run.

Reporting either to a customer as "we could not determine this" is defect
class (e): the wrapper reporting something the check never established. Let
them through as errors.
"""

from __future__ import annotations

import pytest

from core.addresses import ResolverNotWiredError
from core.models import Asset
from core.replay import MissingFixtureError
from scanners.domscout.scanner import DomscoutScanner
from tests.scanners.domscout.test_domscout_scanner import (
    APEX,
    answer,
    build_ctx,
    crtsh_json,
)

WIRING_ERRORS = [
    ResolverNotWiredError("no resolver was wired into this scan"),
    MissingFixtureError("no recorded response for GET https://crt.sh/"),
]


class _Raiser:
    """An HTTP backend that raises the given error on every send."""

    connects = False

    def __init__(self, exc: Exception, *, only: str | None = None) -> None:
        self._exc = exc
        self._only = only
        self.calls: list[str] = []

    def send(self, method, url, *, body_cap, **kwargs):
        self.calls.append(url)
        if self._only is None or url.startswith(self._only):
            raise self._exc
        from core.http import RawHttpResponse

        return RawHttpResponse(status_code=404, headers={}, text="", url=url, elapsed_ms=1)


def _zone():
    return {
        (APEX, "A"): answer(APEX, "A", "93.184.216.34"),
        (APEX, "NS"): answer(APEX, "NS", "ns1.x.test."),
        (APEX, "SOA"): answer(APEX, "SOA", "ns1.x.test. hostmaster.x.test. 1 2 3 4 5"),
    }


@pytest.mark.parametrize("exc", WIRING_ERRORS, ids=lambda e: type(e).__name__)
def test_a_wiring_error_on_the_ct_fetch_is_raised_not_reported_as_inconclusive(exc) -> None:
    ctx = build_ctx(_zone(), _Raiser(exc))
    with pytest.raises(type(exc)):
        DomscoutScanner().run(Asset(type="domain", value=APEX), "light", ctx)


@pytest.mark.parametrize("exc", WIRING_ERRORS, ids=lambda e: type(e).__name__)
def test_a_wiring_error_on_the_rdap_fetch_is_raised_not_reported_as_inconclusive(exc) -> None:
    """The CT fetch answers; only the registry fetch hits the error. A real TLD,
    because a special-use name never reaches RDAP at all (D28)."""
    from core.authz import Scope
    from core.context import ScanContext
    from core.dns import DnsClient, FakeResolver
    from core.http import HttpClient, RawHttpResponse

    apex = "corpus-x.com"

    class _Registry:
        connects = False

        def send(self, method, url, *, body_cap, **kwargs):
            if "crt.sh" in url:
                return RawHttpResponse(
                    status_code=200, headers={}, text=crtsh_json([]), url=url, elapsed_ms=1
                )
            raise exc

    target = Asset(type="domain", value=apex)
    scope = Scope(
        frozenset(Scope.for_target(target).hosts | DomscoutScanner.service_hosts_for(target))
    )
    zone = {
        (apex, rr): answer(apex, rr, rcode="NODATA")
        for rr in ("AAAA", "CNAME", "MX", "TXT", "DS", "DNSKEY")
    }
    zone[(apex, "A")] = answer(apex, "A", "192.0.2.1")
    zone[(apex, "NS")] = answer(apex, "NS", f"ns1.{apex}.")
    zone[(apex, "SOA")] = answer(apex, "SOA", f"ns1.{apex}. h.{apex}. 1 2 3 4 5")
    ctx = ScanContext(
        dns=DnsClient(resolver=FakeResolver(zone), resolvers=["1.1.1.1", "8.8.8.8"]),
        http=HttpClient(scope=scope, backend=_Registry()),
        scope=scope,
    )
    with pytest.raises(type(exc)):
        DomscoutScanner().run(target, "light", ctx)


@pytest.mark.parametrize("exc", WIRING_ERRORS, ids=lambda e: type(e).__name__)
def test_a_wiring_error_on_a_takeover_fetch_is_raised_not_reported_as_inconclusive(exc) -> None:
    """A CNAME matching a fingerprint, whose body fetch hits a wiring error."""
    name = f"app.{APEX}"
    target = "unclaimed.github.io"
    zone = _zone()
    zone[(name, "CNAME")] = answer(name, "CNAME", f"{target}.")
    zone[(name, "A")] = answer(name, "A", rcode="NXDOMAIN")
    zone[(target, "A")] = answer(target, "A", rcode="NXDOMAIN")

    class _Mixed(_Raiser):
        def send(self, method, url, *, body_cap, **kwargs):
            self.calls.append(url)
            if name in url:
                raise exc
            from core.http import RawHttpResponse

            body = crtsh_json([name]) if "crt.sh" in url else ""
            return RawHttpResponse(status_code=200, headers={}, text=body, url=url, elapsed_ms=1)

    ctx = build_ctx(zone, _Mixed(exc))
    with pytest.raises(type(exc)):
        DomscoutScanner().run(Asset(type="domain", value=APEX), "light", ctx)


def test_an_ordinary_network_failure_is_still_an_honest_inconclusive() -> None:
    """The handlers stay: a source that could not be read is a fact about the
    scan worth reporting, and is reported as inconclusive, not as an error."""
    ctx = build_ctx(_zone(), _Raiser(ConnectionError("connection refused")))
    result = DomscoutScanner().run(Asset(type="domain", value=APEX), "light", ctx)
    ct = [f for f in result.findings if f.check_id == "subdomains-ct-log"]
    assert ct and all(f.state == "inconclusive" for f in ct)
    assert not result.errors or all("ConnectionError" not in e.message for e in result.errors)
