"""Directory-listing (autoindex) detection.

A title or marker the server itself generates, never prose: "Index of" in a
blog post is not a listing.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import unquote

_KINDS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("index-of", re.compile(r"<title>\s*Index of /[^<]*</title>", re.IGNORECASE)),
    (
        "python-http-server",
        re.compile(r"<title>\s*Directory listing for /[^<]*</title>", re.IGNORECASE),
    ),
    ("iis", re.compile(r"\[To Parent Directory\]")),
)
_HREF = re.compile(r'<a\s[^>]*href="([^"]+)"', re.IGNORECASE)


@dataclass(frozen=True)
class Listing:
    kind: str
    entries: frozenset[str]


def detect(body: str) -> Listing | None:
    if not body:
        return None
    kind = next((name for name, pattern in _KINDS if pattern.search(body)), None)
    if kind is None:
        return None
    entries: set[str] = set()
    for href in _HREF.findall(body):
        if href.startswith(("?", "#")) or href in ("/", "../", "./") or "://" in href:
            continue
        name = unquote(href.split("?")[0]).rstrip("/").rsplit("/", 1)[-1]
        if name and name != "..":
            entries.add(name)
    return Listing(kind=kind, entries=frozenset(entries))
