"""Per-host token bucket with adaptive backoff, and a per-organisation cap.

Enforced in `core/` because per-scanner means eventually forgotten. Back off
before the target notices, not after: rising latency shrinks the bucket just
as 429 and 503 do.

The clock and the sleep function are injectable so the behaviour is testable
without any test actually waiting.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from statistics import median

BACKOFF_FACTOR = 0.5
"""How hard a 429/503 shrinks the bucket. Halving is conventional and cheap to reason about."""

LATENCY_BACKOFF_FACTOR = 0.75
LATENCY_SPIKE_MULTIPLE = 3.0
"""A response three times slower than the host's recent median is the target struggling."""

RECOVERY_FACTOR = 1.02
"""Recovery is deliberately much slower than backoff."""

LATENCY_WINDOW = 8
MIN_LATENCY_SAMPLES = 4


@dataclass
class _Bucket:
    rate_per_s: float
    tokens: float
    last_refill: float
    latencies: deque[float] = field(default_factory=lambda: deque(maxlen=LATENCY_WINDOW))


class RateLimiter:
    def __init__(
        self,
        *,
        rate_per_s: float = 2.0,
        burst: int = 5,
        min_rate_per_s: float = 0.2,
        clock: Callable[[], float] = time.monotonic,
        sleeper: Callable[[float], None] = time.sleep,
    ) -> None:
        self.rate_per_s = rate_per_s
        self.burst = burst
        self.min_rate_per_s = min_rate_per_s
        self._clock = clock
        self._sleep = sleeper
        self._buckets: dict[str, _Bucket] = {}
        self._lock = threading.Lock()

    def _bucket(self, host: str) -> _Bucket:
        host = host.lower()
        bucket = self._buckets.get(host)
        if bucket is None:
            bucket = _Bucket(self.rate_per_s, float(self.burst), self._clock())
            self._buckets[host] = bucket
        return bucket

    def rate_for(self, host: str) -> float:
        return self._bucket(host).rate_per_s

    def acquire(self, host: str, tokens: float = 1.0) -> None:
        """Block until this host's bucket can pay for the request."""
        with self._lock:
            bucket = self._bucket(host)
            now = self._clock()
            bucket.tokens = min(
                float(self.burst), bucket.tokens + (now - bucket.last_refill) * bucket.rate_per_s
            )
            bucket.last_refill = now
            if bucket.tokens < tokens:
                wait = (tokens - bucket.tokens) / bucket.rate_per_s
                self._sleep(wait)
                bucket.last_refill = self._clock()
                bucket.tokens = tokens
            bucket.tokens -= tokens

    def observe(self, host: str, *, status: int, latency_ms: float | None = None) -> None:
        """Feed the outcome of a request back into the bucket for this host."""
        with self._lock:
            bucket = self._bucket(host)

            if status in (429, 503):
                bucket.rate_per_s = max(self.min_rate_per_s, bucket.rate_per_s * BACKOFF_FACTOR)
                return

            if latency_ms is not None:
                if (
                    len(bucket.latencies) >= MIN_LATENCY_SAMPLES
                    and latency_ms > median(bucket.latencies) * LATENCY_SPIKE_MULTIPLE
                ):
                    bucket.rate_per_s = max(
                        self.min_rate_per_s, bucket.rate_per_s * LATENCY_BACKOFF_FACTOR
                    )
                    bucket.latencies.append(latency_ms)
                    return
                bucket.latencies.append(latency_ms)

            bucket.rate_per_s = min(self.rate_per_s, bucket.rate_per_s * RECOVERY_FACTOR)


class ConcurrencyExceededError(RuntimeError):
    """The organisation already has as many scans in flight as it is allowed."""


class ConcurrencyCap:
    """Global concurrency cap per target organisation.

    Scanning 50 subdomains in parallel must not become an accidental load test.
    Refuses rather than queueing forever, so the caller decides what to do.
    """

    def __init__(self, *, limit: int = 8, timeout_s: float = 30.0) -> None:
        self.limit = limit
        self.timeout_s = timeout_s
        self._semaphores: dict[str, threading.BoundedSemaphore] = {}
        self._in_flight: dict[str, int] = {}
        self._lock = threading.Lock()

    def in_flight(self, org_id: str) -> int:
        return self._in_flight.get(org_id, 0)

    @contextmanager
    def slot(self, org_id: str) -> Iterator[None]:
        with self._lock:
            semaphore = self._semaphores.setdefault(org_id, threading.BoundedSemaphore(self.limit))
        if not semaphore.acquire(timeout=self.timeout_s):
            raise ConcurrencyExceededError(f"{org_id} already has {self.limit} scans in flight")
        with self._lock:
            self._in_flight[org_id] = self._in_flight.get(org_id, 0) + 1
        try:
            yield
        finally:
            with self._lock:
                self._in_flight[org_id] -= 1
            semaphore.release()
