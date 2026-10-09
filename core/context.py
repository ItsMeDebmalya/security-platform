"""`ScanContext` - everything ambient a scanner is allowed to touch.

A scanner never constructs its own HTTP or DNS client. Rate limiting, scope
enforcement, request recording and the kill switch are guarantees only while
every outbound byte goes through a client handed to it here.

Clients that have not been configured raise rather than defaulting to
something unsafe, so "I forgot to wire the real client" fails loudly in a test
instead of quietly reaching the internet.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Protocol

from core.assetgraph import AssetGraph
from core.authz import Scope
from core.cost import CostMeter
from core.dns import DnsClient
from core.exposure import ExposureLog
from core.http import HttpClient
from core.killswitch import KillSwitch
from core.ratelimit import ConcurrencyCap, RateLimiter
from core.testssl import StubTestsslClient, TestsslClient
from core.tls import TlsClient

ProgressReporter = Callable[[str, float], None]


class OobUnavailableError(RuntimeError):
    """The out-of-band callback server is not available.

    A scanner that needs it must return an `inconclusive` finding with
    `no_verdict_reason="oob_unavailable"`. It must never crash, and it must
    never guess.
    """


class OobClient(Protocol):
    def allocate_token(self) -> str: ...

    def poll(self, token: str, *, window_s: int) -> object | None: ...


class StubOobClient:
    """The Phase 0 out-of-band client. Phase 2a replaces it."""

    def allocate_token(self) -> str:
        raise OobUnavailableError("the out-of-band callback server is not built until Phase 2a")

    def poll(self, token: str, *, window_s: int) -> object | None:
        raise OobUnavailableError("the out-of-band callback server is not built until Phase 2a")


class UnconfiguredClient:
    """Placeholder for a client the caller did not provide.

    Raises on any attribute access, which is the point: reaching the network
    through a client `core/` did not construct is the failure mode this whole
    design exists to prevent.
    """

    def __init__(self, kind: str) -> None:
        self._kind = kind

    def __getattr__(self, item: str) -> object:
        raise RuntimeError(
            f"no {self._kind} client on this ScanContext; scanners must never construct their own"
        )


def _noop_progress(message: str, fraction: float) -> None:
    return None


@dataclass
class ScanContext:
    """Handed to `BaseScanner.run`. Constructed by the CLI or the worker."""

    scan_id: str = "01J8TESTTESTTESTTESTTESTTE"
    org_id: str = "org_internal"
    authz_ref: str | None = None
    http: HttpClient | UnconfiguredClient = field(
        default_factory=lambda: UnconfiguredClient("http")
    )
    dns: DnsClient | UnconfiguredClient = field(default_factory=lambda: UnconfiguredClient("dns"))
    tls: TlsClient | UnconfiguredClient = field(default_factory=lambda: UnconfiguredClient("tls"))
    scope: Scope | None = None
    assets: AssetGraph = field(default_factory=AssetGraph)
    """The run's shared asset graph (ADR-019). A scanner that never touches
    this field behaves exactly as it did before the graph existed — the
    default is an empty graph, not one that must be wired up to be safe.
    Contributing to it or reading from it confers no authorisation; that is
    still and only `core/authz.py`'s job."""
    ratelimit: RateLimiter = field(default_factory=RateLimiter)
    concurrency: ConcurrencyCap = field(default_factory=ConcurrencyCap)
    oob: OobClient = field(default_factory=StubOobClient)
    testssl: TestsslClient = field(default_factory=StubTestsslClient)
    """D20: the runtime testssl.sh wrap for the TLS scanner's four
    legacy-cipher checks (Standard mode only). Same shape as `oob` - the
    Phase-0-style default raises `TestsslUnavailableError` so a scan never
    reaches a subprocess it was not explicitly wired up with."""
    killswitch: KillSwitch = field(default_factory=KillSwitch)
    cost: CostMeter = field(default_factory=CostMeter)
    progress: ProgressReporter = _noop_progress
    exposures: ExposureLog = field(default_factory=ExposureLog)
    """ADR-029: every public capture this scan made, for `secret-exposed`."""

    def __post_init__(self) -> None:
        """Wire the ambient services into the clients we were handed.

        A client constructed without a cost meter or a kill switch would
        silently opt out of accounting and cancellation. Rather than trusting
        every caller to pass them, the context fills in what is missing - it
        never overwrites something the caller set deliberately.

        The clients differ in whether they hold these privately or as public
        dataclass fields, so both spellings are tried. That is a small ugliness
        bought deliberately: the alternative is every client growing a wiring
        method, which is more code and one more thing to forget.
        """
        for client in (self.http, self.dns, self.tls):
            if isinstance(client, UnconfiguredClient):
                continue
            self._adopt(client, "cost", self.cost)
            self._adopt(client, "killswitch", self.killswitch)
            self._adopt(client, "scan_id", self.scan_id, placeholder="local")
            self._adopt(client, "org_id", self.org_id, placeholder="org_internal")
            self._adopt(client, "exposures", self.exposures)

    @staticmethod
    def _adopt(client: object, name: str, value: object, placeholder: object = None) -> None:
        for attribute in (f"_{name}", name):
            if not hasattr(client, attribute):
                continue
            current = getattr(client, attribute)
            if current is None or (placeholder is not None and current == placeholder):
                setattr(client, attribute, value)
            return

    def check_alive(self) -> None:
        """Raise `ScanKilledError` if this scan must stop. Call between every request."""
        self.killswitch.check(scan_id=self.scan_id, org_id=self.org_id)
