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
- **no connection to a non-global address, and the address connected to is
  the one checked** (D60, ADR-036). Each request, every redirect hop included,
  resolves its host once through the scan's `DnsClient`, checks every address
  with `core.addresses`, and the backend connects to that address literal
  with the name carried in the Host header and as SNI. httpx is never handed
  a name to resolve, and never reads the process environment (no proxy
  variables, no trust-anchor overrides: D62)
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

import ssl
import time
from dataclasses import dataclass
from http.cookiejar import CookieJar, DefaultCookiePolicy
from pathlib import Path
from typing import Any, Protocol

import httpx

from core.addresses import AddressPolicy, AddressRefusedError, AddressUnresolvedError
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
    address: str | None = None
    """D60: the checked address the request was sent to; `None` on a fixture
    recorded before D60."""


class HttpBackend(Protocol):
    """`connects` says whether `send` opens a socket. A backend that does is
    handed `addresses`, the checked literals for the URL's host, and must
    connect to one of them, never to the name (D60). One that does not (a
    replay) is handed nothing and needs no lookup."""

    connects: bool

    def send(self, method: str, url: str, *, body_cap: int, **kwargs: Any) -> RawHttpResponse: ...


class SystemHttpBackend:
    """Real sockets, via httpx. Constructed by the CLI or the worker, never by
    a scanner. `transport` exists for tests - `httpx.MockTransport` stands in
    for the network without touching it. `trust_anchor` is a CA file to trust
    instead of the system store, for the lab.

    D60: it connects only to an address it is handed, already checked. The
    URL's host is replaced with that literal; the name goes in the Host header
    and, for https, as SNI (httpx's `sni_hostname` request extension), so the
    certificate is still checked against the name. Three httpx defaults are
    switched off because each would let something other than our check
    choose the destination or the trust:
    - `trust_env`: proxy variables would route the request through a proxy
      that resolves the name itself; `SSL_CERT_FILE`/`SSL_CERT_DIR` would
      replace the trust store (D62);
    - keep-alive: connections are pooled by address, so two names on one
      address could share a TLS session negotiated with the other's SNI;
    - the cookie jar: cookies are not carried between requests. With address
      URLs a jar would file a cookie under the address, and send one name's
      cookie to another name on that address. Measured before it was removed
      (ledger, D60): the web scanner's 13 live hand-verified hosts gave the
      same outcome for every request with and without the jar.
    """

    connects = True

    def __init__(
        self,
        *,
        transport: httpx.BaseTransport | None = None,
        user_agent: str = DEFAULT_USER_AGENT,
        timeout_s: float = 15.0,
        trust_anchor: str | None = None,
    ) -> None:
        verify: ssl.SSLContext | bool = (
            ssl.create_default_context(cafile=trust_anchor) if trust_anchor else True
        )
        self._client = httpx.Client(
            transport=transport,
            timeout=timeout_s,
            follow_redirects=False,
            headers={"User-Agent": user_agent},
            trust_env=False,
            verify=verify,
            cookies=CookieJar(policy=DefaultCookiePolicy(allowed_domains=[])),
            limits=httpx.Limits(max_keepalive_connections=0),
        )

    def send(
        self,
        method: str,
        url: str,
        *,
        body_cap: int,
        addresses: tuple[str, ...] | None = None,
        **kwargs: Any,
    ) -> RawHttpResponse:
        # `body_cap` is part of `HttpBackend` because `RecordingHttpBackend`
        # needs it to write a correctly-capped fixture; a live wire response
        # is never capped here (`HttpClient` applies the cap once, in its own
        # capture step), so it is unused on this path.
        del body_cap
        if not addresses:
            raise ValueError(
                "the live HTTP backend connects only to a checked address; "
                "HttpClient resolves and checks the host first (D60)"
            )
        logical = httpx.URL(url)
        headers = dict(kwargs.pop("headers", None) or {})
        headers["Host"] = logical.netloc.decode("ascii")
        extensions = dict(kwargs.pop("extensions", None) or {})
        if logical.scheme == "https":
            extensions["sni_hostname"] = logical.raw_host.decode("ascii")

        last: httpx.ConnectError | httpx.ConnectTimeout | None = None
        for address in addresses:
            started = time.monotonic()
            try:
                response = self._client.request(
                    method,
                    logical.copy_with(host=address),
                    headers=headers,
                    extensions=extensions,
                    **kwargs,
                )
            except (httpx.ConnectError, httpx.ConnectTimeout) as exc:
                if _is_tls_failure(exc):
                    raise  # a TLS failure is the answer, not a reason to try elsewhere
                last = exc
                continue
            elapsed_ms = int((time.monotonic() - started) * 1000)
            return RawHttpResponse(
                status_code=response.status_code,
                headers=dict(response.headers),
                text=response.text,
                url=url,
                elapsed_ms=elapsed_ms,
                address=address,
            )
        assert last is not None
        raise last

    def close(self) -> None:
        self._client.close()


def _is_tls_failure(exc: BaseException) -> bool:
    """Whether an `ssl.SSLError` is anywhere in the chain.

    httpx wraps httpcore's `ConnectError`, which carries the `SSLError` as an
    argument, so `__cause__` alone never reaches it (review of D60, round 1)."""
    seen: set[int] = set()
    stack: list[BaseException] = [exc]
    while stack:
        current = stack.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        if isinstance(current, ssl.SSLError):
            return True
        stack.extend(
            linked
            for linked in (current.__cause__, current.__context__, *current.args)
            if isinstance(linked, BaseException)
        )
    return False


def _capture_payload(
    *,
    status_code: int,
    headers: dict[str, str],
    text: str,
    elapsed_ms: int,
    body_cap: int,
    address: str | None = None,
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
    payload = {
        "status": status_code,
        "headers": clean_headers,
        "body": body,
        "body_truncated": truncated,
        "elapsed_ms": elapsed_ms,
        "redactions": sorted(set(header_counts) | set(body_counts)),
        "redaction_receipts": receipt_list(receipts),
    }
    if address is not None:
        payload["address"] = address  # D60: where it went, as evidence
    return payload


def _fixture_name(method: str, url: str) -> str:
    """One file per (method, url).

    Sufficient today: every current and planned Light-mode check is an
    idempotent GET, and a scanner never sends two different bodies to the
    same URL in one run. A scanner that started doing that would collide on
    replay - worth revisiting then, not worth a request-body hash now for a
    case nothing exercises.

    A request the address policy refused (D60) shares the name with the
    response it would have had. If a name's DNS answer changed mid-recording
    so that one URL was both refused and answered, the last write wins. A
    response fixture never has an `address_policy` key, so replay cannot read
    one as the other.
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

    @property
    def connects(self) -> bool:
        # Silence means connecting, through a wrapper too (fail closed).
        return bool(getattr(self._inner, "connects", True))

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
            address=raw.address,
        )
        payload["url"] = redact_text(raw.url)[0] or raw.url
        self._store.write(_fixture_name(method, url), payload)
        return raw

    def record_refusal(
        self, method: str, url: str, exc: AddressRefusedError | AddressUnresolvedError
    ) -> None:
        """D60: a request the address policy stopped, so its replay stops it too."""
        refusal: dict[str, Any]
        if isinstance(exc, AddressRefusedError):
            refusal = {"host": exc.host, "refused": exc.refused, "literal": exc.literal}
        else:
            refusal = {"unresolved": str(exc)}
        # Redacted at capture, like every other fixture (ADR-028; review of D60,
        # round 2): a refused redirect's URL can carry a token.
        stored_url = redact_text(url)[0] or url
        self._store.write(
            _fixture_name(method, url), {"url": stored_url, "address_policy": refusal}
        )


class ReplayHttpBackend:
    """Serves recorded captures and never opens a socket.

    What replays is the *capture*, not the original wire response: it is
    already redacted and size-capped, and a replay must be indistinguishable
    from what recording stored - truncation included - rather than
    reconstructing something that was never written to disk.
    """

    connects = False

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
        refusal = data.get("address_policy")
        if refusal is not None:
            # D60: recorded as stopped by the address policy; nothing was sent.
            if "unresolved" in refusal:
                raise AddressUnresolvedError(refusal["unresolved"])
            raise AddressRefusedError(
                refusal["host"], refusal["refused"], literal=refusal.get("literal", False)
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
            address=data.get("address"),
        )


class HttpClient:
    def __init__(
        self,
        *,
        scope: Scope,
        service_hosts: frozenset[str] = frozenset(),
        follow_scope: Scope | None = None,
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
        dns: Any = None,
        addresses: AddressPolicy | None = None,
    ) -> None:
        self._scope = scope
        self._dns = dns
        """The scan's `DnsClient`, wired in by `ScanContext` (D60)."""
        self._addresses = addresses
        """The scan's `AddressPolicy`, wired in by `ScanContext`; a client never
        given one uses the default, which has no override (D60)."""
        self._service_hosts = frozenset(h.lower().rstrip(".") for h in service_hosts)
        """ADR-031 (D54): a request to one of these never follows a redirect, so it
        only ever reaches the host it was declared for, never the scanned site."""
        self._follow_scope = follow_scope or scope
        """Where a redirect may be followed. `for_scan` sets it to the target's own
        scope, so a target request is never followed to a service host or to a name
        under one (unless that name is also the target's own), whose answer would
        pass for the target's (review of D54, round 2)."""
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
        own = Scope.for_target(target)
        scope = Scope(frozenset(own.hosts | service_hosts))
        return cls(scope=scope, service_hosts=service_hosts, follow_scope=own, **kwargs)

    @property
    def dns(self) -> Any:
        return self._dns

    @property
    def addresses(self) -> AddressPolicy | None:
        return self._addresses

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
            if not self._follow_scope.permits(host):
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
        # Fail closed: a backend that does not say it opens no socket is pinned.
        if getattr(self._backend, "connects", True):
            # D60, at every hop: resolved once, checked, and only the checked
            # literals go down. Nothing is inherited from an earlier hop.
            policy = self._addresses or AddressPolicy()
            try:
                pinned = policy.pin(httpx.URL(url).raw_host.decode("ascii"), self._dns)
            except (AddressRefusedError, AddressUnresolvedError) as exc:
                # A recording keeps the refusal, so its replay says the same
                # (review of D60, round 1). Nothing was sent.
                record = getattr(self._backend, "record_refusal", None)
                if record is not None:
                    record(method, url, exc)
                raise
            kwargs = {**kwargs, "addresses": pinned.addresses}
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
                **({"address": raw.address} if raw.address is not None else {}),
            }
        return _capture_payload(
            status_code=raw.status_code,
            headers=raw.headers,
            text=raw.text,
            elapsed_ms=raw.elapsed_ms,
            body_cap=self._body_cap,
            address=raw.address,
        )

    def close(self) -> None:
        close = getattr(self._backend, "close", None)
        if close is not None:
            close()
