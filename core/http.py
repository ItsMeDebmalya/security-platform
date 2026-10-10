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

**Record/replay is at the backend layer, like DNS and TLS** (`core/replay.py`).
`HttpBackend.send()` is the one thing a recording or a replay stands in for;
everything above it - the redirect loop, the scope check on each hop, the
capture and redaction - is real code that runs identically whether the
backend is a live socket or a fixture, so a replayed multi-hop redirect chain
(including a hop declined for being out of scope) exercises the same logic a
live run does.

Unlike DNS and TLS, **the HTTP recording backend redacts before it writes**.
A DNS answer or a TLS handshake cannot carry a customer's secret; an HTTP
response can (a session cookie, an API key in a body). CLAUDE.md's rule is
redact at capture time, not at display time, so the fixture on disk is the
redacted, size-capped capture - never the raw response - and replaying it
reproduces exactly that capture, truncation included.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

import httpx

from core.authz import Scope
from core.cost import CostMeter
from core.evidence import DEFAULT_BODY_CAP, truncate_body
from core.killswitch import KillSwitch
from core.models import Asset
from core.redaction import (
    Receipts,
    add_receipts,
    receipt_list,
    receipts_from,
    redact_header_map,
    redact_text,
)
from core.replay import (
    FixtureStore,
    fixture_digest,
    fixture_filename,
    missing_fixture_message,
    sanitize_filename_part,
)
from core.replay import (
    MissingFixtureError as MissingFixtureError,
)

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


# --- backends -----------------------------------------------------------


@dataclass(frozen=True)
class RawHttpResponse:
    """What a backend returns: the wire facts, before redirect-following,
    scope checks or capture happen above it.

    `redactions` is `None` for a live response - the facts are raw, and
    `HttpClient` still has to redact and truncate them into a capture.
    `ReplayHttpBackend` instead hands back the fixture's own already-redacted,
    already-truncated capture verbatim, with `redactions` set to the list
    that was recorded: redacting or truncating it a second time would corrupt
    it (truncation inserts a marker, so truncating an already-truncated body
    truncates *that*, nesting markers). `HttpClient` treats `redactions is
    not None` as "this is already a capture, use it as-is."
    """

    status_code: int
    headers: dict[str, str]
    text: str
    url: str
    elapsed_ms: int
    body_truncated: bool = False
    redactions: list[str] | None = None
    redaction_receipts: list[dict[str, Any]] | None = None
    """ADR-029, with `redactions`: the fixture's recorded receipts on replay."""


class HttpBackend(Protocol):
    def send(self, method: str, url: str, *, body_cap: int, **kwargs: Any) -> RawHttpResponse: ...


class SystemHttpBackend:
    """Real sockets, via httpx. Constructed by the CLI or the worker, never by
    a scanner. `transport` exists for tests - `httpx.MockTransport` stands in
    for the network without touching it."""

    def __init__(
        self,
        *,
        transport: httpx.BaseTransport | None = None,
        user_agent: str = DEFAULT_USER_AGENT,
        timeout_s: float = 15.0,
    ) -> None:
        self._client = httpx.Client(
            transport=transport,
            timeout=timeout_s,
            follow_redirects=False,
            headers={"User-Agent": user_agent},
        )

    def send(self, method: str, url: str, *, body_cap: int, **kwargs: Any) -> RawHttpResponse:
        # `body_cap` is part of `HttpBackend` because `RecordingHttpBackend`
        # needs it to write a correctly-capped fixture; a live wire response
        # is never capped here (`HttpClient` applies the cap once, in its own
        # capture step), so it is unused on this path.
        del body_cap
        started = time.monotonic()
        response = self._client.request(method, url, **kwargs)
        elapsed_ms = int((time.monotonic() - started) * 1000)
        return RawHttpResponse(
            status_code=response.status_code,
            headers=dict(response.headers),
            text=response.text,
            url=str(response.url),
            elapsed_ms=elapsed_ms,
        )

    def close(self) -> None:
        self._client.close()


def _capture_payload(
    *, status_code: int, headers: dict[str, str], text: str, elapsed_ms: int, body_cap: int
) -> dict[str, Any]:
    """The redacted, size-capped shape stored as evidence - and, for HTTP,
    also the shape stored as a fixture. Shared so recording never drifts from
    the capture `HttpClient` computes for a live run."""
    header_counts: dict[str, int] = {}
    clean_headers = redact_header_map(dict(headers), header_counts)
    body, body_counts = redact_text(text)
    body, truncated = truncate_body(body, body_cap)
    receipts: Receipts = {}
    add_receipts(receipts, header_counts, "response.headers")
    add_receipts(receipts, body_counts, "response.body")
    return {
        "status": status_code,
        "headers": clean_headers,
        "body": body,
        "body_truncated": truncated,
        "elapsed_ms": elapsed_ms,
        "redactions": sorted(set(header_counts) | set(body_counts)),
        "redaction_receipts": receipt_list(receipts),
    }


def _fixture_name(method: str, url: str) -> str:
    """One file per (method, url).

    Sufficient today: every current and planned Light-mode check is an
    idempotent GET, and a scanner never sends two different bodies to the
    same URL in one run. A scanner that started doing that would collide on
    replay - worth revisiting then, not worth a request-body hash now for a
    case nothing exercises.
    """
    # The stem is readable, so it is built from the redacted URL: a secret in a
    # path must not end up in a file name (review of D21, 6).
    parsed = httpx.URL(redact_text(url)[0] or url)
    stem = sanitize_filename_part(f"{parsed.host}{parsed.path or '/'}")
    key = f"{method.upper()}|{url}"
    return fixture_filename(stem, method.upper(), digest=fixture_digest(key))


class RecordingHttpBackend:
    """Wraps a backend and writes a redacted, capped capture of every response
    to disk for later replay.

    Redaction happens here, at capture time - never later, and never as a
    step the replay path could skip. What is returned to the caller is the
    real, unredacted response, exactly as a live run without recording would
    see it; only what lands on disk is redacted.
    """

    def __init__(self, directory: str | Path, inner: HttpBackend | None = None) -> None:
        self._store = FixtureStore(Path(directory))
        self._inner = inner or SystemHttpBackend()

    def send(self, method: str, url: str, *, body_cap: int, **kwargs: Any) -> RawHttpResponse:
        # `body_cap` comes from the caller on every call (`HttpClient` passes
        # its own `body_cap` through) rather than being configured here too.
        # A second place to set the same cap is exactly the shape of bug
        # 0b.1 found: a value that can silently diverge from the one the
        # live capture used, with a default quietly filling the gap.
        raw = self._inner.send(method, url, body_cap=body_cap, **kwargs)
        payload = _capture_payload(
            status_code=raw.status_code,
            headers=raw.headers,
            text=raw.text,
            elapsed_ms=raw.elapsed_ms,
            body_cap=body_cap,
        )
        payload["url"] = redact_text(raw.url)[0] or raw.url
        self._store.write(_fixture_name(method, url), payload)
        return raw


class ReplayHttpBackend:
    """Serves recorded captures and never opens a socket.

    What replays is the *capture*, not the original wire response: it is
    already redacted and size-capped, and a replay must be indistinguishable
    from what recording stored - truncation included - rather than
    reconstructing something that was never written to disk.
    """

    def __init__(self, directory: str | Path) -> None:
        self._store = FixtureStore(Path(directory))

    def send(self, method: str, url: str, *, body_cap: int, **kwargs: Any) -> RawHttpResponse:
        # `body_cap` is accepted only to satisfy `HttpBackend`'s shape; a
        # replay always serves the fixture's own recorded truncation,
        # regardless of the cap configured for this run - see the class
        # docstring for why re-truncating it would corrupt it.
        del body_cap
        data = self._store.read(_fixture_name(method, url))
        if data is None:
            raise MissingFixtureError(
                missing_fixture_message(
                    kind="response",
                    subject=f"{method.upper()} {url}",
                    directory=self._store.directory,
                )
            )
        # ADR-028 clause 7: a replayed capture is redacted again. Running the
        # redactor twice is the same as once, so a correct fixture is unchanged;
        # a fixture written by core before ADR-028 (BEGIN line replaced, key body
        # kept) is cut here, with `legacy=True` making the old marker an anchor.
        # It is never re-truncated: that would nest truncation notes.
        counts: dict[str, int] = {}
        headers = redact_header_map(dict(data["headers"]), counts)
        body, body_counts = redact_text(data["body"] or "", legacy=True)
        stored_url, url_counts = redact_text(data["url"])
        found = set(data["redactions"]) | set(counts) | set(body_counts) | set(url_counts)
        # ADR-029: the recorded receipts, plus anything cut only now (a legacy
        # fixture's key body). A fixture recorded before ADR-029 has none, and
        # none are invented for it.
        receipts = receipts_from(data.get("redaction_receipts"))
        add_receipts(receipts, counts, "response.headers")
        add_receipts(receipts, body_counts, "response.body")
        return RawHttpResponse(
            status_code=data["status"],
            headers=headers,
            text=body or "",
            url=stored_url or data["url"],
            elapsed_ms=data["elapsed_ms"],
            body_truncated=data["body_truncated"],
            redactions=sorted(found),
            redaction_receipts=receipt_list(receipts),
        )


class HttpClient:
    def __init__(
        self,
        *,
        scope: Scope,
        service_hosts: frozenset[str] = frozenset(),
        transport: httpx.BaseTransport | None = None,
        backend: HttpBackend | None = None,
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
        self._service_hosts = frozenset(h.lower().rstrip(".") for h in service_hosts)
        """ADR-031 (D54): a request to one of these never follows a redirect, so it
        only ever reaches the host it was declared for, never the scanned site."""
        self._body_cap = body_cap
        self._cost = cost
        self._killswitch = killswitch
        self._ratelimit = ratelimit
        self._scan_id = scan_id
        self._org_id = org_id
        self._exposures: Any = None
        """The scan's `core.exposure.ExposureLog`, wired in by `ScanContext`."""
        # `transport` (an `httpx.MockTransport` in tests) only makes sense for
        # the default live backend; a caller supplying its own `backend`
        # (Recording/Replay) owns its own transport concerns.
        self._backend = backend or SystemHttpBackend(
            transport=transport, user_agent=user_agent, timeout_s=timeout_s
        )

    @classmethod
    def for_scan(cls, target: Asset, *, service_hosts: frozenset[str], **kwargs: Any) -> HttpClient:
        """The client for one scan: scope is the target plus its service hosts, and
        the same declaration makes them no-follow. Derived together so they cannot
        be wired apart (review of D54). `api/` and any worker must build it here."""
        scope = Scope(frozenset(Scope.for_target(target).hosts | service_hosts))
        return cls(scope=scope, service_hosts=service_hosts, **kwargs)

    def get(self, url: str, *, follow_redirects: bool = True, **kwargs: Any) -> CapturedResponse:
        return self.request("GET", url, follow_redirects=follow_redirects, **kwargs)

    def request(
        self, method: str, url: str, *, follow_redirects: bool = True, **kwargs: Any
    ) -> CapturedResponse:
        for _ in range(MAX_REDIRECTS):
            response = self._send_once(method, url, **kwargs)
            location = response.headers.get("location")
            if response.status_code not in (301, 302, 303, 307, 308) or not location:
                return response
            # D54, at every hop: a service host's redirect is returned, never
            # followed, so a registry cannot send our request to the scanned site.
            if not follow_redirects or self._is_service_host(httpx.URL(url).host):
                return response

            target = str(httpx.URL(response.url).join(location))
            host = httpx.URL(target).host
            # Nor is any request followed into a service host: a service host is
            # reached only when asked for directly, so its answer can never pass
            # for the target's (ADR-031 clause 6; review of D54).
            if self._is_service_host(host):
                return response
            if not self._scope.permits(host):
                # Not an error: the redirect itself is a fact worth reporting.
                # We simply decline to follow it out of scope.
                return response
            url, method = target, "GET" if response.status_code == 303 else method
        return response

    def _is_service_host(self, host: str) -> bool:
        """Exact match: a service host is one declared host, never a zone, so a
        target name under it keeps ordinary behaviour (review of D54)."""
        return host.lower().rstrip(".") in self._service_hosts

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

        raw = self._backend.send(method, url, body_cap=self._body_cap, **kwargs)

        if self._cost is not None:
            self._cost.record_request()
        if self._ratelimit is not None:
            self._ratelimit.observe(
                host,
                status=raw.status_code,
                latency_ms=raw.elapsed_ms,
            )

        response = CapturedResponse(
            status_code=raw.status_code,
            text=raw.text,
            headers=dict(raw.headers),
            captured=self._capture(raw),
            url=raw.url,
        )
        if self._exposures is not None:
            # ADR-029: every public capture is seen, cited by a finding or not
            self._exposures.observe_http(response.url, response.captured)
        return response

    def _capture(self, raw: RawHttpResponse) -> dict[str, Any]:
        if raw.redactions is not None:
            # Already a capture - `ReplayHttpBackend` handed back exactly what
            # recording wrote. Redacting or truncating it again would corrupt
            # it (see `RawHttpResponse`'s docstring), so it is used as-is.
            return {
                "status": raw.status_code,
                "headers": dict(raw.headers),
                "body": raw.text,
                "body_truncated": raw.body_truncated,
                "elapsed_ms": raw.elapsed_ms,
                "redactions": list(raw.redactions),
                "redaction_receipts": list(raw.redaction_receipts or []),
            }
        return _capture_payload(
            status_code=raw.status_code,
            headers=raw.headers,
            text=raw.text,
            elapsed_ms=raw.elapsed_ms,
            body_cap=self._body_cap,
        )

    def close(self) -> None:
        close = getattr(self._backend, "close", None)
        if close is not None:
            close()
