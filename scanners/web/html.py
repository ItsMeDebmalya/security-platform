"""Extract the facts the web checks read from one HTML document.

Stdlib `html.parser` only. Forgiving by design: real pages are malformed, and
an extractor that raised on bad markup would turn a messy page into an
"inconclusive" for every content check.
"""

from __future__ import annotations

from dataclasses import dataclass
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit


@dataclass(frozen=True)
class Script:
    src: str
    integrity: str | None


@dataclass(frozen=True)
class PageFacts:
    scripts: tuple[Script, ...]
    stylesheets: tuple[str, ...]
    meta_csp: tuple[str, ...]
    generator: str | None
    asset_urls: tuple[str, ...]


class _Extractor(HTMLParser):
    def __init__(self, base_url: str) -> None:
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.scripts: list[Script] = []
        self.stylesheets: list[str] = []
        self.meta_csp: list[str] = []
        self.generator: str | None = None
        self.assets: list[str] = []

    def _abs(self, value: str) -> str | None:
        try:
            return urljoin(self.base_url, value.strip())
        except ValueError:
            return None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "script" and a.get("src"):
            url = self._abs(a["src"])
            if url is not None:
                self.scripts.append(Script(src=url, integrity=a.get("integrity") or None))
                self.assets.append(url)
        elif tag == "link" and a.get("href"):
            url = self._abs(a["href"])
            if url is not None:
                if "stylesheet" in a.get("rel", "").lower().split():
                    self.stylesheets.append(url)
                self.assets.append(url)
        elif tag == "img" and a.get("src"):
            url = self._abs(a["src"])
            if url is not None:
                self.assets.append(url)
        elif tag == "meta":
            equiv = a.get("http-equiv", "").strip().lower()
            name = a.get("name", "").strip().lower()
            if equiv == "content-security-policy" and a.get("content"):
                self.meta_csp.append(a["content"])
            elif name == "generator" and a.get("content") and self.generator is None:
                self.generator = a["content"].strip()

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.handle_starttag(tag, attrs)


def extract(body: str, base_url: str) -> PageFacts:
    parser = _Extractor(base_url)
    parser.feed(body or "")
    parser.close()
    return PageFacts(
        scripts=tuple(parser.scripts),
        stylesheets=tuple(parser.stylesheets),
        meta_csp=tuple(parser.meta_csp),
        generator=parser.generator,
        asset_urls=tuple(parser.assets),
    )


def _origin(url: str) -> tuple[str, str, int | None] | None:
    try:
        parts = urlsplit(url)
        return parts.scheme.lower(), (parts.hostname or "").lower(), parts.port
    except ValueError:
        return None


def is_same_origin(url: str, base_url: str) -> bool:
    url_origin = _origin(url)
    base_origin = _origin(base_url)
    return url_origin is not None and base_origin is not None and url_origin == base_origin


def _parent(path: str) -> str | None:
    if "/" not in path:
        return None
    parent = path.rsplit("/", 1)[0] + "/"
    return None if parent == "/" else parent


def same_origin_directories(facts: PageFacts, base_url: str, limit: int = 4) -> list[str]:
    dirs = {
        parent
        for url in facts.asset_urls
        if is_same_origin(url, base_url) and (parent := _parent(urlsplit(url).path))
    }
    return sorted(dirs)[:limit]


def linked_files(facts: PageFacts, base_url: str) -> dict[str, frozenset[str]]:
    grouped: dict[str, set[str]] = {}
    for url in facts.asset_urls:
        if not is_same_origin(url, base_url):
            continue
        path = urlsplit(url).path
        parent = _parent(path)
        name = path.rsplit("/", 1)[-1]
        if parent and name:
            grouped.setdefault(parent, set()).add(name)
    return {d: frozenset(n) for d, n in grouped.items()}
