"""The kill switch, at three levels: one scan, one customer, everything.

Checked **between every request**, not just between phases. If a code path can
send a request without checking it, that path is a bug.

In-process for now. Phase 6 backs it with shared state (a Redis key or a
database flag) so it works across workers; the interface does not change.
"""

from __future__ import annotations

from dataclasses import dataclass, field


class ScanKilledError(RuntimeError):
    """Raised at the next checkpoint after a scan has been killed."""

    def __init__(self, level: str, reason: str) -> None:
        super().__init__(f"scan killed at {level} level: {reason}")
        self.level = level
        self.reason = reason


@dataclass
class KillSwitch:
    _all: str | None = None
    _orgs: dict[str, str] = field(default_factory=dict)
    _scans: dict[str, str] = field(default_factory=dict)

    def kill_all(self, *, reason: str) -> None:
        self._all = reason

    def kill_org(self, org_id: str, *, reason: str) -> None:
        self._orgs[org_id] = reason

    def kill(self, *, scan_id: str, reason: str) -> None:
        self._scans[scan_id] = reason

    def check(self, *, scan_id: str, org_id: str) -> None:
        """Raise if this scan must stop. Call between every request."""
        if self._all is not None:
            raise ScanKilledError("global", self._all)
        if org_id in self._orgs:
            raise ScanKilledError("org", self._orgs[org_id])
        if scan_id in self._scans:
            raise ScanKilledError("scan", self._scans[scan_id])
