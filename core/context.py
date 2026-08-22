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

from core.authz import Scope
from core.cost import CostMeter
from core.dns import DnsClient
from core.http import HttpClient
from core.killswitch import KillSwitch
from core.ratelimit import ConcurrencyCap, RateLimiter

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
    scope: Scope | None = None
    ratelimit: RateLimiter = field(default_factory=RateLimiter)
    concurrency: ConcurrencyCap = field(default_factory=ConcurrencyCap)
    oob: OobClient = field(default_factory=StubOobClient)
    killswitch: KillSwitch = field(default_factory=KillSwitch)
    cost: CostMeter = field(default_factory=CostMeter)
    progress: ProgressReporter = _noop_progress

    def __post_init__(self) -> None:
        """Wire the ambient services into the clients we were handed.

        A client constructed without a cost meter or a kill switch would
        silently opt out of accounting and cancellation. Rather than trusting
        every caller to pass them, the context fills in what is missing - it
        never overwrites something the caller set deliberately.
        """
        for client in (self.http, self.dns):
            if isinstance(client, UnconfiguredClient):
                continue
            if getattr(client, "_cost", None) is None:
                client._cost = self.cost
            if getattr(client, "_killswitch", None) is None:
                client._killswitch = self.killswitch
            if getattr(client, "_scan_id", None) in (None, "local"):
                client._scan_id = self.scan_id
            if getattr(client, "_org_id", None) in (None, "org_internal"):
                client._org_id = self.org_id

    def check_alive(self) -> None:
        """Raise `ScanKilledError` if this scan must stop. Call between every request."""
        self.killswitch.check(scan_id=self.scan_id, org_id=self.org_id)
