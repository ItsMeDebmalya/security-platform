"""The one HTTP client.

A scanner that constructs its own HTTP client is a bug: rate limiting, scope
enforcement, request recording and the kill switch are only guarantees while
every outbound byte goes through here.

What this client promises:

- our user agent on every request, so a target can identify us
- the kill switch checked **before every request**, not between phases
- the rate limiter consulted per host, and its feedback loop fed by the
  responses we get back
- **no request to a host outside scope, and no redirect that leaves it** - an
  SSRF probe never targets a third party
- bodies redacted and size-capped at capture, so evidence is ready to store
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

import httpx

from core.authz import Scope
from core.cost import CostMeter
from core.evidence import DEFAULT_BODY_CAP, redact_body, redact_headers, truncate_body
from core.killswitch import KillSwitch

DEFAULT_USER_AGENT = "SecurityPlatform-Scanner/0.1 (+https://example.invalid/scanner)"
MAX_REDIRECTS = 5


class OutOfScopeError(PermissionError):
    """A request was attempted against a host this scan is not authorised to touch."""


@dataclass
class CapturedResponse:
    """An httpx response plus the redacted, capped capture we would store."""

    status_code: int
    text: str
    headers: dict[str, str]
    captured: dict[str, Any]
    url: str


class HttpClient:
    def __init__(
        self,
        *,
        scope: Scope,
        transport: httpx.BaseTransport | None = None,
        user_agent: str = DEFAULT_USER_AGENT,
        timeout_s: float = 15.0,
        body_cap: int = DEFAULT_BODY_CAP,
        cost: CostMeter | None = None,
        killswitch: KillSwitch | None = None,
        ratelimit: Any = None,
        scan_id: str = "local",
        org_id: str = "org_internal",
    ) -> None:
        self._scope = scope
        self._body_cap = body_cap
        self._cost = cost
        self._killswitch = killswitch
        self._ratelimit = ratelimit
        self._scan_id = scan_id
        self._org_id = org_id
        self._client = httpx.Client(
            transport=transport,
            timeout=timeout_s,
            follow_redirects=False,
            headers={"User-Agent": user_agent},
        )

    def get(self, url: str, **kwargs: Any) -> CapturedResponse:
        return self.request("GET", url, **kwargs)

    def request(self, method: str, url: str, **kwargs: Any) -> CapturedResponse:
        for _ in range(MAX_REDIRECTS):
            response = self._send_once(method, url, **kwargs)
            location = response.headers.get("location")
            if response.status_code not in (301, 302, 303, 307, 308) or not location:
                return response

            target = str(httpx.URL(response.url).join(location))
            host = httpx.URL(target).host
            if not self._scope.permits(host):
                # Not an error: the redirect itself is a fact worth reporting.
                # We simply decline to follow it out of scope.
                return response
            url, method = target, "GET" if response.status_code == 303 else method
        return response

    def _send_once(self, method: str, url: str, **kwargs: Any) -> CapturedResponse:
        host = httpx.URL(url).host
        if not self._scope.permits(host):
            raise OutOfScopeError(
                f"{host} is outside the scope of this scan; "
                "requests to third parties are never sent"
            )

        if self._killswitch is not None:
            self._killswitch.check(scan_id=self._scan_id, org_id=self._org_id)
        if self._ratelimit is not None:
            self._ratelimit.acquire(host)

        started = time.monotonic()
        response = self._client.request(method, url, **kwargs)
        elapsed_ms = int((time.monotonic() - started) * 1000)

        if self._cost is not None:
            self._cost.record_request()
        if self._ratelimit is not None:
            self._ratelimit.observe(
                host,
                status=response.status_code,
                latency_ms=elapsed_ms,
            )

        return CapturedResponse(
            status_code=response.status_code,
            text=response.text,
            headers=dict(response.headers),
            captured=self._capture(response, elapsed_ms),
            url=str(response.url),
        )

    def _capture(self, response: httpx.Response, elapsed_ms: int) -> dict[str, Any]:
        headers, header_hits = redact_headers(dict(response.headers))
        body, body_hits = redact_body(response.text)
        body, truncated = truncate_body(body, self._body_cap)
        return {
            "status": response.status_code,
            "headers": headers,
            "body": body,
            "body_truncated": truncated,
            "elapsed_ms": elapsed_ms,
            "redactions": sorted(set(header_hits + body_hits)),
        }

    def close(self) -> None:
        self._client.close()
