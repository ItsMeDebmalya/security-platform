"""Directory-listing (autoindex) detection.

A title or marker the server itself generates, never prose: "Index of" in a
blog post is not a listing. Requires two server-generated markers: title + h1
for Apache/nginx, title + h1 for Python http.server, or [To Parent Directory]
in <pre> for IIS.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import unquote

_INDEX_OF_TITLE = re.compile(
    r"<title>\s*Index of (/[^<]*?)</title>",
    re.IGNORECASE,
)
_INDEX_OF_H1 = re.compile(
    r"<h1>\s*Index of (/[^<]*?)</h1>",
    re.IGNORECASE,
)
_DIR_LISTING_TITLE = re.compile(
    r"<title>\s*Directory listing for (/[^<]*?)</title>",
    re.IGNORECASE,
)
_DIR_LISTING_H1 = re.compile(
    r"<h1>\s*Directory listing for (/[^<]*?)</h1>",
    re.IGNORECASE,
)
_IIS_MARKER = re.compile(
    r"<pre[^>]*>.*?\[To Parent Directory\].*?</pre>", re.IGNORECASE | re.DOTALL
)
_HREF = re.compile(r'<a\s[^>]*href="([^"]+)"', re.IGNORECASE)


@dataclass(frozen=True)
class Listing:
    kind: str
    entries: frozenset[str]


def _extract_path(match: re.Match[str]) -> str:
    """Extract the path from a regex match group 1."""
    return match.group(1).rstrip("/") if match else ""


def _is_under_path(href: str, base_path: str) -> bool:
    """Check if an absolute path href is under base_path."""
    if not href.startswith("/"):
        return True
    cleaned_href = href.rstrip("/")
    if cleaned_href == base_path:
        return False
    return cleaned_href.startswith(base_path + "/")


def detect(body: str) -> Listing | None:
    if not body:
        return None

    kind: str | None = None
    listed_path = ""

    index_of_title = _INDEX_OF_TITLE.search(body)
    index_of_h1 = _INDEX_OF_H1.search(body)
    if index_of_title and index_of_h1:
        kind = "index-of"
        listed_path = _extract_path(index_of_h1)

    dir_listing_title = _DIR_LISTING_TITLE.search(body)
    dir_listing_h1 = _DIR_LISTING_H1.search(body)
    if not kind and dir_listing_title and dir_listing_h1:
        kind = "python-http-server"
        listed_path = _extract_path(dir_listing_h1)

    if not kind and _IIS_MARKER.search(body):
        kind = "iis"
        # For IIS, try to extract path from h1 or title if available
        if index_of_h1:
            listed_path = _extract_path(index_of_h1)

    if kind is None:
        return None

    entries: set[str] = set()
    for href in _HREF.findall(body):
        if href.startswith(("?", "#")) or href in ("/", "../", "./") or "://" in href:
            continue
        if href.startswith("/") and listed_path and not _is_under_path(href, listed_path):
            continue
        name = unquote(href.split("?")[0]).rstrip("/").rsplit("/", 1)[-1]
        if name and name != "..":
            entries.add(name)
    return Listing(kind=kind, entries=frozenset(entries))
