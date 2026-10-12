"""The one HTTP client. Every guarantee we make about touching a target lives here."""

from __future__ import annotations

import httpx
import pytest

from core.authz import Scope
from core.http import HttpClient, OutOfScopeError
from core.killswitch import KillSwitch, ScanKilledError
from core.models import Asset
from core.ratelimit import RateLimiter
from tests.core.named_transport import PUBLIC_DNS, named

SCOPE = Scope.for_target(Asset(type="domain", value="example.com"))


def _client(handler, **kwargs):
    return HttpClient(
        scope=kwargs.pop("scope", SCOPE),
        dns=kwargs.pop("dns", PUBLIC_DNS),
        transport=named(handler),
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


# --- D54: a service-host request reaches only the declared host ------------------

REGISTRY = "rdap.registry.example"
WITH_SERVICE = Scope(frozenset(SCOPE.hosts | {REGISTRY}))


def _recording(sent: list[str], answers):
    def handler(request):
        sent.append(str(request.url))
        return answers(request)

    return handler


def test_a_service_host_redirect_to_the_target_is_never_followed():
    """ADR-031: a registry's redirect must never send a request to the scanned site."""
    sent: list[str] = []

    def answers(request):
        if request.url.host == REGISTRY:
            return httpx.Response(302, headers={"location": "https://example.com/rdap"})
        return httpx.Response(200, text="the target's own page")

    client = _client(
        _recording(sent, answers), scope=WITH_SERVICE, service_hosts=frozenset({REGISTRY})
    )
    response = client.get(f"https://{REGISTRY}/domain/example.com")

    assert response.status_code == 302
    assert sent == [f"https://{REGISTRY}/domain/example.com"]


def test_a_service_host_redirect_within_its_own_host_is_not_followed_either():
    sent: list[str] = []

    def answers(request):
        return httpx.Response(302, headers={"location": f"https://{REGISTRY}/elsewhere"})

    client = _client(
        _recording(sent, answers), scope=WITH_SERVICE, service_hosts=frozenset({REGISTRY})
    )

    assert client.get(f"https://{REGISTRY}/domain/x").status_code == 302
    assert len(sent) == 1


def test_follow_redirects_false_returns_the_redirect_itself():
    sent: list[str] = []

    def answers(request):
        if request.url.path == "/start":
            return httpx.Response(302, headers={"location": "https://example.com/end"})
        return httpx.Response(200, text="arrived")

    response = _client(_recording(sent, answers)).get(
        "https://example.com/start", follow_redirects=False
    )

    assert response.status_code == 302
    assert sent == ["https://example.com/start"]


def test_target_requests_still_follow_in_scope_redirects_with_service_hosts_declared():
    def handler(request):
        if request.url.path == "/start":
            return httpx.Response(302, headers={"location": "https://example.com/end"})
        return httpx.Response(200, text="arrived")

    client = _client(handler, scope=WITH_SERVICE, service_hosts=frozenset({REGISTRY}))

    assert client.get("https://example.com/start").text == "arrived"


# --- independent review of D54 (2026-10-10): each finding is a test ---------------


def test_a_service_host_reached_mid_chain_never_redirects_on_to_the_target():
    """Finding 1: the rule holds at every hop, not only on the first URL."""
    sent: list[str] = []

    def answers(request):
        if request.url.host == REGISTRY:
            return httpx.Response(302, headers={"location": "https://example.com/secret"})
        if request.url.path == "/":
            return httpx.Response(302, headers={"location": f"https://{REGISTRY}/x"})
        return httpx.Response(200, text="the target's secret page")

    client = _client(
        _recording(sent, answers), scope=WITH_SERVICE, service_hosts=frozenset({REGISTRY})
    )
    response = client.get("https://example.com/")

    assert "https://example.com/secret" not in sent
    assert response.status_code == 302


def test_a_target_request_is_never_followed_into_a_service_host():
    """Related: crt.sh's or a registry's answer must never pass for the target's."""
    sent: list[str] = []

    def answers(request):
        if request.url.host == REGISTRY:
            return httpx.Response(200, text="registry body")
        return httpx.Response(302, headers={"location": f"https://{REGISTRY}/x"})

    client = _client(
        _recording(sent, answers), scope=WITH_SERVICE, service_hosts=frozenset({REGISTRY})
    )
    response = client.get("https://example.com/")

    assert sent == ["https://example.com/"]
    assert response.status_code == 302


def test_service_hosts_match_exactly_never_their_subdomains():
    """Finding 3: a target name under a service host keeps ordinary behaviour."""

    def handler(request):
        if request.url.path == "/start":
            return httpx.Response(302, headers={"location": f"http://a.{REGISTRY}/end"})
        return httpx.Response(200, text="arrived")

    scope = Scope(frozenset({REGISTRY}))
    client = _client(handler, scope=scope, service_hosts=frozenset({"nothing.example"}))
    assert client.get(f"http://a.{REGISTRY}/start").text == "arrived"

    client = _client(handler, scope=scope, service_hosts=frozenset({REGISTRY}))
    assert client.get(f"http://a.{REGISTRY}/start").text == "arrived"


def test_for_scan_builds_scope_and_service_hosts_from_one_declaration():
    """Finding 4: one helper, so the two cannot be wired apart."""
    target = Asset(type="domain", value="example.com")
    client = HttpClient.for_scan(
        target, service_hosts=frozenset({REGISTRY}), transport=named(_ok), dns=PUBLIC_DNS
    )

    assert client._service_hosts == frozenset({REGISTRY})
    assert client.get(f"https://{REGISTRY}/").status_code == 200
    assert client.get("https://www.example.com/").status_code == 200


# --- independent review of D54, round 2 -----------------------------------------


def test_a_target_request_is_never_followed_under_a_service_host():
    """Scope admits subdomains, so `www.<service host>` must be refused as a redirect
    target too: only the target's own scope may be followed into."""
    sent: list[str] = []

    def answers(request):
        if request.url.host == "example.com":
            return httpx.Response(302, headers={"location": f"https://www.{REGISTRY}/x"})
        return httpx.Response(200, text="a third party's body")

    client = HttpClient.for_scan(
        Asset(type="domain", value="example.com"),
        service_hosts=frozenset({REGISTRY}),
        transport=named(_recording(sent, answers)),
        dns=PUBLIC_DNS,
    )
    response = client.get("https://example.com/")

    assert sent == ["https://example.com/"]
    assert response.status_code == 302
