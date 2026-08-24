"""Token bucket, adaptive backoff, and the per-organisation concurrency cap.

Our scanners talk to systems other people depend on. Deterministic here: the
clock and the sleep function are injected, so no test ever really waits.
"""

from __future__ import annotations

import pytest

from core.ratelimit import ConcurrencyCap, ConcurrencyExceededError, RateLimiter


class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0
        self.slept = 0.0

    def time(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.slept += seconds
        self.now += seconds


@pytest.fixture
def clock():
    return FakeClock()


@pytest.fixture
def limiter(clock):
    return RateLimiter(rate_per_s=2.0, burst=3, clock=clock.time, sleeper=clock.sleep)


def test_a_burst_of_requests_does_not_wait(limiter, clock):
    for _ in range(3):
        limiter.acquire("example.com")

    assert clock.slept == 0.0


def test_the_request_after_the_burst_waits_for_a_token(limiter, clock):
    for _ in range(3):
        limiter.acquire("example.com")

    limiter.acquire("example.com")

    assert clock.slept == pytest.approx(0.5)


def test_tokens_refill_with_the_passage_of_time(limiter, clock):
    for _ in range(3):
        limiter.acquire("example.com")
    clock.now += 10

    limiter.acquire("example.com")

    assert clock.slept == 0.0


def test_each_host_gets_its_own_bucket(limiter, clock):
    for _ in range(3):
        limiter.acquire("example.com")

    limiter.acquire("other.example")

    assert clock.slept == 0.0


def test_a_429_shrinks_the_bucket_for_that_host(limiter):
    limiter.observe("example.com", status=429)

    assert limiter.rate_for("example.com") == pytest.approx(1.0)


def test_a_503_shrinks_the_bucket_too(limiter):
    limiter.observe("example.com", status=503)

    assert limiter.rate_for("example.com") == pytest.approx(1.0)


def test_backing_off_on_one_host_leaves_others_alone(limiter):
    limiter.observe("example.com", status=429)

    assert limiter.rate_for("other.example") == pytest.approx(2.0)


def test_rising_latency_shrinks_the_bucket_before_the_target_complains(limiter):
    for _ in range(5):
        limiter.observe("example.com", status=200, latency_ms=100)

    limiter.observe("example.com", status=200, latency_ms=900)

    assert limiter.rate_for("example.com") < 2.0


def test_steady_latency_does_not_shrink_the_bucket(limiter):
    for _ in range(8):
        limiter.observe("example.com", status=200, latency_ms=100)

    assert limiter.rate_for("example.com") == pytest.approx(2.0)


def test_the_rate_never_falls_below_the_floor(limiter):
    for _ in range(20):
        limiter.observe("example.com", status=429)

    assert limiter.rate_for("example.com") >= limiter.min_rate_per_s


def test_the_rate_recovers_slowly_after_a_clean_run(limiter):
    limiter.observe("example.com", status=429)
    backed_off = limiter.rate_for("example.com")

    for _ in range(50):
        limiter.observe("example.com", status=200, latency_ms=100)

    recovered = limiter.rate_for("example.com")
    assert backed_off < recovered <= 2.0


def test_recovery_never_exceeds_the_configured_rate(limiter):
    for _ in range(200):
        limiter.observe("example.com", status=200, latency_ms=100)

    assert limiter.rate_for("example.com") == pytest.approx(2.0)


# --- concurrency ------------------------------------------------------------


def test_an_organisation_may_run_up_to_its_cap(clock):
    cap = ConcurrencyCap(limit=2)

    with cap.slot("org_a"), cap.slot("org_a"):
        assert cap.in_flight("org_a") == 2


def test_exceeding_the_cap_is_refused_rather_than_queued_forever():
    """50 subdomains must not become an accidental load test."""
    cap = ConcurrencyCap(limit=2, timeout_s=0)

    with cap.slot("org_a"), cap.slot("org_a"), pytest.raises(ConcurrencyExceededError):
        cap.slot("org_a").__enter__()


def test_a_slot_is_released_when_its_block_ends():
    cap = ConcurrencyCap(limit=1, timeout_s=0)

    with cap.slot("org_a"):
        pass
    with cap.slot("org_a"):
        assert cap.in_flight("org_a") == 1


def test_a_slot_is_released_even_when_the_block_raises():
    cap = ConcurrencyCap(limit=1, timeout_s=0)

    with pytest.raises(RuntimeError), cap.slot("org_a"):
        raise RuntimeError("boom")

    assert cap.in_flight("org_a") == 0


def test_organisations_do_not_share_a_cap():
    cap = ConcurrencyCap(limit=1, timeout_s=0)

    with cap.slot("org_a"), cap.slot("org_b"):
        assert cap.in_flight("org_a") == 1


# --- who the limit is actually protecting -----------------------------------


def test_a_target_host_gets_the_conservative_limit():
    """We are a guest on someone's infrastructure. Be quiet."""
    limiter = RateLimiter.for_target()

    assert limiter.rate_per_s <= 5


def test_a_public_resolver_gets_a_higher_limit_than_a_target():
    """A public recursive resolver is not the system being scanned.

    It is built for billions of queries a day, and its cache is what shields
    the target's own nameservers from us. Throttling DNS at the target rate
    protects nobody and makes a real-world sweep take forty minutes.
    """
    assert RateLimiter.for_resolver().rate_per_s > RateLimiter.for_target().rate_per_s


def test_a_scanners_worth_of_dns_queries_does_not_crawl(clock):
    """One email scan is ~25 lookups. That must not take twelve seconds."""
    limiter = RateLimiter.for_resolver(clock=clock.time, sleeper=clock.sleep)

    for _ in range(25):
        limiter.acquire("1.1.1.1")

    assert clock.slept < 1.0


def test_the_resolver_limit_still_backs_off_when_the_resolver_complains():
    """Higher is not unlimited. A resolver that rate-limits us is still obeyed."""
    limiter = RateLimiter.for_resolver()
    before = limiter.rate_for("1.1.1.1")

    limiter.observe("1.1.1.1", status=429)

    assert limiter.rate_for("1.1.1.1") < before
