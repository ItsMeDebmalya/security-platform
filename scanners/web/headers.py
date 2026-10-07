"""Header parsing and verdicts. Pure: a Mapping in, a verdict out.

Repeated headers arrive comma-joined (core's capture uses dict(headers)), so
every list-valued verdict tolerates "DENY, DENY" rather than misreading it.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Literal

HSTS_MIN_MAX_AGE = 15_768_000
"""Six months - Mozilla Observatory's threshold for a meaningful HSTS policy."""

_MAX_AGE = re.compile(r'max-age\s*=\s*"?(\d+)"?', re.IGNORECASE)
REFERRER_VALID = frozenset(
    {
        "no-referrer",
        "no-referrer-when-downgrade",
        "same-origin",
        "origin",
        "strict-origin",
        "origin-when-cross-origin",
        "strict-origin-when-cross-origin",
        "unsafe-url",
    }
)
REFERRER_UNSAFE = frozenset({"unsafe-url", "no-referrer-when-downgrade"})


def get(headers: Mapping[str, str], name: str) -> str | None:
    wanted = name.lower()
    for key, value in headers.items():
        if key.lower() == wanted:
            return value
    return None


def _tokens(value: str | None) -> set[str]:
    return {t.strip().lower() for t in (value or "").split(",") if t.strip()}


def hsts_verdict(value: str | None) -> tuple[Literal["missing", "weak", "ok"], int | None]:
    if value is None or not value.strip():
        return "missing", None
    first = value.split(",")[0]  # RFC 6797 8.1: only the first header is processed
    match = _MAX_AGE.search(first)
    if match is None:
        return "weak", None
    age = int(match.group(1))
    return ("ok" if age >= HSTS_MIN_MAX_AGE else "weak"), age


def xfo_protects(value: str | None) -> bool:
    tokens = _tokens(value)
    return bool(tokens) and tokens <= {"deny", "sameorigin"}


def xcto_ok(value: str | None) -> bool:
    """Fetch reads only the first value of a repeated header, so "nosniff, sniff" is ok."""
    first = (value or "").split(",")[0]
    return first.strip().lower() == "nosniff"


def referrer_verdict(value: str | None) -> tuple[Literal["missing", "unsafe", "ok"], str | None]:
    known = [
        t.strip().lower() for t in (value or "").split(",") if t.strip().lower() in REFERRER_VALID
    ]
    if not known:
        return "missing", None
    effective = known[-1]  # the last recognised token wins (Referrer Policy spec)
    return ("unsafe" if effective in REFERRER_UNSAFE else "ok"), effective


def cors_wildcard(value: str | None) -> bool:
    return value is not None and "*" in {t.strip() for t in value.split(",")}
