"""The bounded request plan (design spec section 2).

At most MAX_REQUESTS ordinary GETs, made once, in a fixed order. Nothing is
requested that the site did not point at itself, except the deterministic 404
control. Deterministic, not random: a random path would never match a frozen
fixture on replay.

A failed request is recorded, never raised - except MissingFixtureError (a
corpus gap is a bug, not a target condition) and ScanKilledError.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

from core.addresses import AddressRefusedError
from core.context import ScanContext
from core.evidence import redact_body
from core.http import CapturedResponse, HttpClient, MissingFixtureError, OutOfScopeError
from core.killswitch import ScanKilledError
from core.models import Asset
from scanners.web import challenge, html
from scanners.web.headers import get

MAX_REQUESTS = 12
MAX_DIRECTORIES = 4
MAX_SITEMAPS = 2
PROBE_PREFIX = "sp-404-probe-"


def probe_path(host: str) -> str:
    return f"/{PROBE_PREFIX}{hashlib.sha256(host.encode()).hexdigest()[:16]}"


_DETAIL_CAP = 200
_SSL_TOKEN = re.compile(r"\[SSL: [A-Z0-9_]+\]")
_DNS_MARKERS = (
    "name or service not known",
    "nodename nor servname",
    "getaddrinfo",
    "temporary failure in name resolution",
)


def describe_transport_failure(exc: BaseException) -> str:
    """Say why a request could not complete, from the exception's class and message."""
    name, msg = type(exc).__name__, str(exc)
    low = msg.lower()
    text: str
    if isinstance(exc, AddressRefusedError):
        # D60: said as what it is, naming the hop's name and address
        text = (
            f"{exc.summary}, so it was not connected to (often split-horizon DNS or a stale record)"
        )
    elif "CERTIFICATE_VERIFY_FAILED" in msg:
        reason = msg.split("certificate verify failed:", 1)[-1].split(" (_ssl", 1)[0]
        text = f"TLS certificate verification failed ({reason.strip().rstrip('.')})"
    elif (token := _SSL_TOKEN.search(msg)) is not None:
        rest = msg[token.end() :].split(" (_ssl", 1)[0]
        text = f"TLS handshake failed ({rest.strip()})"
    elif "timeout" in name.lower():
        text = "connection timed out"
    elif "refused" in low:
        text = "connection refused"
    elif any(m in low for m in _DNS_MARKERS):
        text = "DNS lookup failed"
    else:
        text = f"transport error ({name})"
    redacted = redact_body(text)[0] or text
    return redacted[:_DETAIL_CAP]


@dataclass(frozen=True)
class Fetched:
    label: str
    url: str
    path: str
    response: CapturedResponse | None
    failure: str | None
    detail: str | None = None

    @property
    def usable(self) -> bool:
        return self.response is not None and self.failure is None

    @property
    def final_scheme(self) -> str | None:
        return urlsplit(self.response.url).scheme.lower() if self.response else None


@dataclass(frozen=True)
class Observations:
    host: str
    root_path: str
    probe_path: str
    https_root: Fetched
    http_root: Fetched
    https_probe: Fetched
    http_probe: Fetched
    robots: Fetched
    sitemaps: tuple[Fetched, ...]
    security_txt: Fetched
    directories: tuple[Fetched, ...]
    page: html.PageFacts | None
    page_url: str | None
    requests_made: int

    @property
    def root(self) -> Fetched:
        return self.https_root if self.https_root.response is not None else self.http_root

    @property
    def probe(self) -> Fetched:
        return self.https_probe if self.https_root.response is not None else self.http_probe

    def same_origin_fetches(self) -> list[Fetched]:
        candidates = [
            self.root,
            self.probe,
            self.robots,
            *self.sitemaps,
            self.security_txt,
            *self.directories,
        ]
        return [f for f in candidates if f.usable]


def origins(target: Asset) -> tuple[str, str | None, str | None, str]:
    """(host, https origin, http origin, root path). The other scheme is derived
    only on default ports - on an explicit port we cannot know it. Raises
    ValueError on a port that is not a number in range (WebScanner.validate
    rejects such a target before any request)."""
    value = target.value.strip()
    if target.type == "url" or "://" in value:
        parts = urlsplit(value if "://" in value else f"https://{value}")
        host = (parts.hostname or "").lower().rstrip(".")
        path = parts.path or "/"
        if parts.port is None:
            return host, f"https://{host}", f"http://{host}", path
        netloc = f"{host}:{parts.port}"
        if parts.scheme.lower() == "https":
            return host, f"https://{netloc}", None, path
        return host, None, f"http://{netloc}", path
    host = value.lower().rstrip(".")
    return host, f"https://{host}", f"http://{host}", "/"


class _Fetcher:
    def __init__(self, ctx: ScanContext, http: HttpClient) -> None:
        self.ctx = ctx
        self.http = http
        self.count = 0

    def get(self, label: str, url: str) -> Fetched:
        path = urlsplit(url).path or "/"
        if self.count >= MAX_REQUESTS:
            raise RuntimeError("web request plan exceeded MAX_REQUESTS - a scanner bug")
        self.ctx.check_alive()
        self.count += 1
        try:
            response = self.http.get(url)
        except (MissingFixtureError, ScanKilledError):
            raise
        except OutOfScopeError:
            return Fetched(
                label, url, path, None, "blocked_prerequisite", "the request left the scan's scope"
            )
        except Exception as exc:  # a transport failure: we could not find out
            reason = (
                "timeout" if "timeout" in type(exc).__name__.lower() else "blocked_prerequisite"
            )
            return Fetched(label, url, path, None, reason, describe_transport_failure(exc))
        if response.status_code == 429:
            return Fetched(label, url, path, response, "rate_limited")
        if challenge.detect(response.status_code, response.headers, response.text):
            return Fetched(label, url, path, response, "waf_block")
        return Fetched(label, url, path, response, None)

    def maybe(self, label: str, origin: str | None, path: str, scheme: str, host: str) -> Fetched:
        if origin is None:
            return Fetched(label, f"{scheme}://{host}{path}", path, None, "blocked_prerequisite")
        return self.get(label, origin + path)


def _is_html(response: CapturedResponse) -> bool:
    content_type = (get(response.headers, "content-type") or "").lower()
    return "html" in content_type or response.text.lstrip()[:1] == "<"


def _sitemaps(robots: Fetched, host: str) -> list[str]:
    if not robots.usable or robots.response is None or robots.response.status_code != 200:
        return []
    urls = []
    for line in robots.response.text.splitlines():
        key, _, value = line.partition(":")
        if key.strip().lower() == "sitemap":
            url = value.strip()
            if (urlsplit(url).hostname or "").lower() == host and url not in urls:
                urls.append(url)
    return urls[:MAX_SITEMAPS]


def gather(ctx: ScanContext, http: HttpClient, target: Asset) -> Observations:
    host, https_origin, http_origin, root_path = origins(target)
    f = _Fetcher(ctx, http)
    probe = probe_path(host)

    https_root = f.maybe("https root", https_origin, root_path, "https", host)
    http_root = f.maybe("http root", http_origin, root_path, "http", host)
    https_probe = f.maybe("https 404 control", https_origin, probe, "https", host)
    http_probe = f.maybe("http 404 control", http_origin, probe, "http", host)

    base = (
        https_origin
        if https_root.response is not None
        else http_origin
        if http_root.response is not None
        else https_origin or http_origin
    )
    if base is None:  # unreachable: origins() always yields at least one origin
        raise RuntimeError("web derived no origin for the target - a scanner bug")
    robots = f.get("robots.txt", base + "/robots.txt")
    sitemaps = tuple(f.get("sitemap", url) for url in _sitemaps(robots, host))
    security_txt = f.get("security.txt", base + "/.well-known/security.txt")

    root = https_root if https_root.response is not None else http_root
    page: html.PageFacts | None = None
    page_url: str | None = None
    directories: tuple[Fetched, ...] = ()
    if root.usable and root.response is not None and _is_html(root.response):
        page_url = root.response.url
        page = html.extract(root.response.text, page_url)
        parts = urlsplit(page_url)
        origin = f"{parts.scheme}://{parts.netloc}"
        directories = tuple(
            f.get("directory", origin + d)
            for d in html.same_origin_directories(page, page_url, limit=MAX_DIRECTORIES)
        )

    return Observations(
        host=host,
        root_path=root_path,
        probe_path=probe,
        https_root=https_root,
        http_root=http_root,
        https_probe=https_probe,
        http_probe=http_probe,
        robots=robots,
        sitemaps=sitemaps,
        security_txt=security_txt,
        directories=directories,
        page=page,
        page_url=page_url,
        requests_made=f.count,
    )
