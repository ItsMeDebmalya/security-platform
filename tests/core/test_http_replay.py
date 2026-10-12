"""Record/replay for the HTTP client, built on `core/replay.py`.

Mirrors `tests/core/test_dns.py` and `tests/core/test_tls.py`'s replay
sections: record through a fake/mock backend, replay from the same
directory, and assert the round trip preserves what matters rather than
merely that it runs.
"""

from __future__ import annotations

import httpx
import pytest

from core.authz import Scope
from core.http import (
    HttpClient,
    MissingFixtureError,
    RecordingHttpBackend,
    ReplayHttpBackend,
    SystemHttpBackend,
)
from core.models import Asset
from tests.core.named_transport import PUBLIC_DNS, named

SCOPE = Scope.for_target(Asset(type="domain", value="example.com"))


def _recording_client(handler, directory, **kwargs):
    inner = SystemHttpBackend(transport=named(handler))
    kwargs.setdefault("dns", PUBLIC_DNS)
    return HttpClient(scope=SCOPE, backend=RecordingHttpBackend(directory, inner), **kwargs)


def _replay_client(directory, **kwargs):
    return HttpClient(scope=SCOPE, backend=ReplayHttpBackend(directory), **kwargs)


def test_a_recorded_response_replays_identically(tmp_path):
    def handler(request):
        return httpx.Response(200, text="hello world", headers={"content-type": "text/plain"})

    recorded = _recording_client(handler, tmp_path).get("https://example.com/page")
    replayed = _replay_client(tmp_path).get("https://example.com/page")

    assert replayed.status_code == recorded.status_code == 200
    assert replayed.text == "hello world"


def test_replaying_a_url_that_was_never_recorded_fails_loudly(tmp_path):
    client = _replay_client(tmp_path)

    with pytest.raises(MissingFixtureError, match="never-recorded"):
        client.get("https://example.com/never-recorded")


def test_a_secret_in_the_live_response_never_reaches_the_fixture_file(tmp_path):
    def handler(request):
        return httpx.Response(200, text="ok", headers={"Set-Cookie": "session=super-secret"})

    _recording_client(handler, tmp_path).get("https://example.com/login")

    for fixture in tmp_path.glob("*.json"):
        assert "super-secret" not in fixture.read_text()

    replayed = _replay_client(tmp_path).get("https://example.com/login")
    assert replayed.captured["headers"]["set-cookie"] == "[redacted]"


def test_truncation_is_recorded_and_replays_as_truncated_not_re_truncated(tmp_path):
    def handler(request):
        return httpx.Response(200, text="x" * 5000)

    recorded = _recording_client(handler, tmp_path, body_cap=1000).get("https://example.com/big")
    assert recorded.captured["body_truncated"] is True
    recorded_body = recorded.captured["body"]

    # Replay must not reapply truncate_body to an already-truncated body -
    # doing so would nest a second "[N bytes truncated]" marker into text
    # that is already below the cap once the marker is counted.
    replayed = _replay_client(tmp_path, body_cap=1000).get("https://example.com/big")
    assert replayed.captured["body_truncated"] is True
    assert replayed.captured["body"] == recorded_body
    assert replayed.captured["body"].count("bytes truncated") == 1


def test_a_redirect_chain_replays_the_same_hops(tmp_path):
    def handler(request):
        if request.url.path == "/start":
            return httpx.Response(302, headers={"location": "https://example.com/end"})
        return httpx.Response(200, text="arrived")

    recorded = _recording_client(handler, tmp_path).get("https://example.com/start")
    replayed = _replay_client(tmp_path).get("https://example.com/start")

    assert recorded.text == replayed.text == "arrived"
    assert replayed.url == "https://example.com/end"


def test_a_redirect_declined_for_leaving_scope_replays_as_declined(tmp_path):
    def handler(request):
        return httpx.Response(302, headers={"location": "https://evil.example/"})

    recorded = _recording_client(handler, tmp_path).get("https://example.com/start")
    assert recorded.status_code == 302

    replayed = _replay_client(tmp_path).get("https://example.com/start")
    assert replayed.status_code == 302
    assert replayed.headers["location"] == "https://evil.example/"


def test_requests_are_keyed_by_method_and_url_not_just_url(tmp_path):
    def handler(request):
        if request.method == "GET":
            return httpx.Response(200, text="got")
        return httpx.Response(200, text="posted")

    _recording_client(handler, tmp_path).get("https://example.com/thing")
    _recording_client(handler, tmp_path).request("POST", "https://example.com/thing")

    assert _replay_client(tmp_path).get("https://example.com/thing").text == "got"
    assert _replay_client(tmp_path).request("POST", "https://example.com/thing").text == "posted"
