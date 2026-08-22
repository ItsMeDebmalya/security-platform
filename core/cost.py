"""Per-scan cost accounting.

Counted from the very first scan, per docs/06-guidelines.md: without it we do
not learn our margins until it is too late to fix them.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from core.models import Cost


@dataclass
class CostMeter:
    requests: int = 0
    ai_tokens: int = 0
    _started_at: float = field(default_factory=time.monotonic)

    def record_request(self, count: int = 1) -> None:
        self.requests += count

    def record_ai_tokens(self, count: int) -> None:
        self.ai_tokens += count

    def snapshot(self) -> Cost:
        return Cost(
            requests=self.requests,
            wall_ms=int((time.monotonic() - self._started_at) * 1000),
            ai_tokens=self.ai_tokens,
        )
