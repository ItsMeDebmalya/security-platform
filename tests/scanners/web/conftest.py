"""A fake website for the web scanner tests: URL -> (status, headers, body)."""

from __future__ import annotations

import pytest

from core.authz import Scope
from core.context import ScanContext
from core.http import HttpClient, RawHttpResponse

NOT_FOUND = (404, {"content-type": "text/html"}, "<html><body><h1>404 Not Found</h1></body></html>")


class ConnectTimeout(Exception):  # noqa: N818 - the name must contain "timeout"
    """Named like httpx's, which fetch maps to no_verdict_reason="timeout"."""


class FakeSite:
    def __init__(self, host: str = "x.test", default=NOT_FOUND) -> None:
        self.host = host
        self.default = default
        self.responses: dict[str, tuple[int, dict[str, str], str]] = {}
        self.fail: dict[str, Exception] = {}
        self.calls: list[str] = []

    def serve(self, url, status=200, headers=None, body=""):
        self.responses[url] = (status, dict(headers or {}), body)
        return self

    def raise_on(self, url, exc):
        self.fail[url] = exc
        return self

    def send(self, method, url, *, body_cap, **kwargs):
        self.calls.append(url)
        if url in self.fail:
            raise self.fail[url]
        status, headers, body = self.responses.get(url, self.default)
        return RawHttpResponse(
            status_code=status, headers=dict(headers), text=body, url=url, elapsed_ms=1
        )

    def ctx(self) -> ScanContext:
        scope = Scope(frozenset({self.host}))
        return ScanContext(http=HttpClient(scope=scope, backend=self), scope=scope)


@pytest.fixture
def site() -> FakeSite:
    return FakeSite()
