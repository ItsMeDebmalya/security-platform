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

from core.cost import CostMeter
from core.killswitch import KillSwitch

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
    http: object = field(default_factory=lambda: UnconfiguredClient("http"))
    dns: object = field(default_factory=lambda: UnconfiguredClient("dns"))
    oob: OobClient = field(default_factory=StubOobClient)
    killswitch: KillSwitch = field(default_factory=KillSwitch)
    cost: CostMeter = field(default_factory=CostMeter)
    progress: ProgressReporter = _noop_progress

    def check_alive(self) -> None:
        """Raise `ScanKilledError` if this scan must stop. Call between every request."""
        self.killswitch.check(scan_id=self.scan_id, org_id=self.org_id)
