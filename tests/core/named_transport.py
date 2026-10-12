"""A `MockTransport` that shows its handler the request by name (D60).

Since D60 the live HTTP backend sends to the checked address literal and puts
the name in the Host header. Tests written against `request.url.host` keep
their meaning through this adapter: it rebuilds the request with the Host
header's name in the URL before the handler sees it, and records the address
the request was really pinned to.
"""

from __future__ import annotations

from collections.abc import Callable

import httpx

from corpus.generators.tls_lab import LabDns

PUBLIC = "93.184.215.14"
PUBLIC_DNS = LabDns(PUBLIC)
"""Every name resolves to one public literal. MockTransport opens no socket."""


def named(handler: Callable[[httpx.Request], httpx.Response], pinned: list[str] | None = None):
    def by_name(request: httpx.Request) -> httpx.Response:
        if pinned is not None:
            pinned.append(request.url.host)
        host, _, port = request.headers["host"].partition(":")
        url = request.url.copy_with(host=host, port=int(port) if port else None)
        logical = httpx.Request(
            request.method, url, headers=request.headers, content=request.content
        )
        return handler(logical)

    return httpx.MockTransport(by_name)
