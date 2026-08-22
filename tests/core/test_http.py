"""The one HTTP client. Every guarantee we make about touching a target lives here."""

from __future__ import annotations

import httpx
import pytest

from core.authz import Scope
from core.http import HttpClient, OutOfScopeError
from core.killswitch import KillSwitch, ScanKilledError
from core.models import Asset
from core.ratelimit import RateLimiter

SCOPE = Scope.for_target(Asset(type="domain", value="example.com"))


def _client(handler, **kwargs):
    return HttpClient(
        scope=kwargs.pop("scope", SCOPE),
        transport=httpx.MockTransport(handler),
        **kwargs,
    )


def _ok(request: httpx.Request) -> httpx.Response:
    return httpx.Response(200, text="ok")


def test_our_user_agent_identifies_us_to_the_target():
    seen: list[str] = []

    def handler(request):
        seen.append(request.headers["user-agent"])
        return httpx.Response(200, text="ok")

    _client(handler, user_agent="SecurityPlatform-Scanner/0.1").get("https://example.com/")

    assert seen == ["SecurityPlatform-Scanner/0.1"]


def test_a_request_to_a_host_outside_scope_is_refused_before_it_is_sent():
    sent: list[str] = []

    def handler(request):
        sent.append(str(request.url))
        return httpx.Response(200)

    with pytest.raises(OutOfScopeError):
        _client(handler).get("https://evil.example/")

    assert sent == []


def test_a_request_to_a_subdomain_of_the_target_is_allowed():
    assert _client(_ok).get("https://www.example.com/").status_code == 200


def test_a_redirect_within_scope_is_followed():
    def handler(request):
        if request.url.path == "/start":
            return httpx.Response(302, headers={"location": "https://example.com/end"})
        return httpx.Response(200, text="arrived")

    response = _client(handler).get("https://example.com/start")

    assert response.text == "arrived"


def test_a_redirect_leaving_scope_is_not_followed():
    def handler(request):
        if request.url.host == "example.com":
            return httpx.Response(302, headers={"location": "https://evil.example/"})
        raise AssertionError("the client followed a redirect out of scope")

    response = _client(handler).get("https://example.com/start")

    assert response.status_code == 302


def test_the_kill_switch_is_checked_before_every_request():
    switch = KillSwitch()
    client = _client(_ok, killswitch=switch, scan_id="s1", org_id="org_a")
    client.get("https://example.com/")

    switch.kill(scan_id="s1", reason="operator")

    with pytest.raises(ScanKilledError):
        client.get("https://example.com/other")


def test_the_rate_limiter_is_consulted_per_target_host():
    seen: list[str] = []

    class SpyLimiter(RateLimiter):
        def acquire(self, host: str, tokens: float = 1.0) -> None:
            seen.append(host)

    _client(_ok, ratelimit=SpyLimiter()).get("https://www.example.com/")

    assert seen == ["www.example.com"]


def test_a_429_feeds_back_into_the_rate_limiter():
    limiter = RateLimiter(rate_per_s=2.0)
    client = _client(lambda r: httpx.Response(429), ratelimit=limiter)

    client.get("https://example.com/")

    assert limiter.rate_for("example.com") < 2.0


def test_requests_count_towards_the_scan_cost():
    from core.cost import CostMeter

    meter = CostMeter()
    client = _client(_ok, cost=meter)

    client.get("https://example.com/a")
    client.get("https://example.com/b")

    assert meter.snapshot().requests == 2


def test_an_oversized_body_is_capped_at_capture():
    client = _client(lambda r: httpx.Response(200, text="x" * 5000), body_cap=1000)

    captured = client.get("https://example.com/").captured

    assert captured["body_truncated"] is True
    assert len(captured["body"]) < 1200


def test_a_captured_response_is_ready_to_become_evidence():
    client = _client(lambda r: httpx.Response(200, text="ok", headers={"Set-Cookie": "s=1"}))

    captured = client.get("https://example.com/").captured

    assert captured["status"] == 200
    assert captured["headers"]["set-cookie"] == "[redacted]"
