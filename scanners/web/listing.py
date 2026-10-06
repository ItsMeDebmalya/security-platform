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
_IIS_PARENT_LINK = re.compile(
    r'<a\s[^>]*href="([^"]+)"[^>]*>\s*\[To Parent Directory\]',
    re.IGNORECASE,
)


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
    # URL-decode both paths before comparison
    decoded_href = unquote(href.rstrip("/"))
    decoded_base = unquote(base_path)
    if decoded_href == decoded_base:
        return False
    return decoded_href.startswith(decoded_base + "/")


def _longest_common_prefix(paths: list[str]) -> str:
    """Find longest common directory prefix of absolute paths."""
    if not paths:
        return ""

    decoded = [unquote(p) for p in paths]
    decoded = [p.rstrip("/") for p in decoded]

    if len(decoded) == 1:
        p = decoded[0]
        if "/" in p and p != "/":
            return p.rsplit("/", 1)[0]
        return ""

    # Multiple paths - find common prefix components
    split_paths = [p.split("/") for p in decoded]

    common_parts = []
    for i in range(min(len(sp) for sp in split_paths)):
        if all(sp[i] == split_paths[0][i] for sp in split_paths):
            common_parts.append(split_paths[0][i])
        else:
            break

    if common_parts:
        result = "/".join(common_parts)
        return result if result != "/" else ""

    return ""


def detect(body: str) -> Listing | None:
    if not body:
        return None

    kind: str | None = None
    listed_path = ""
    parent_href = ""

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
        # For IIS, find and extract the parent link
        parent_match = _IIS_PARENT_LINK.search(body)
        if parent_match:
            parent_href = parent_match.group(1)
        # Collect all hrefs to derive the listed path
        all_hrefs = [
            h
            for h in _HREF.findall(body)
            if h.startswith("/") and h not in ("/", "../", "./") and "://" not in h
        ]
        if parent_href:
            all_hrefs = [h for h in all_hrefs if h != parent_href]
        if all_hrefs:
            listed_path = _longest_common_prefix(all_hrefs)

    if kind is None:
        return None

    entries: set[str] = set()
    for href in _HREF.findall(body):
        if href.startswith(("?", "#")) or href in ("/", "../", "./") or "://" in href:
            continue
        if href == parent_href:
            continue
        if href.startswith("/") and listed_path and not _is_under_path(href, listed_path):
            continue
        name = unquote(href.split("?")[0]).rstrip("/").rsplit("/", 1)[-1]
        if name and name != "..":
            entries.add(name)
    return Listing(kind=kind, entries=frozenset(entries))
