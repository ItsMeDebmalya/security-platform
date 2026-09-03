"""Certificate Transparency name normalization and crt.sh JSON parsing.

Pure functions only - no network, no scanner imports. Callers are
responsible for fetching crt.sh output and for their own apex bookkeeping
(the bare apex is deliberately excluded from `parse_crtsh`'s results, since
it is not a discovered subdomain).
"""

from __future__ import annotations

import json


def is_within_apex(name: str, apex: str) -> bool:
    """Label-boundary suffix match: rejects `example.com.evil.com`."""
    return name == apex or name.endswith("." + apex)


def normalize_name(raw: str, apex: str) -> str | None:
    """Lowercase, strip trailing dot and leading `*.`, IDNA-encode to A-labels.

    Returns None if the result is not within `apex`, or if it normalizes to
    the bare apex (that is apex bookkeeping, not a discovered subdomain).
    """
    name = raw.strip().rstrip(".")
    if name.startswith("*."):
        name = name[2:]
    if not name:
        return None
    try:
        encoded = name.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    encoded = encoded.lower()
    if encoded == apex:
        return None
    if not is_within_apex(encoded, apex):
        return None
    return encoded


def parse_crtsh(json_text: str, apex: str) -> list[str]:
    """Parse crt.sh `output=json`: a list of objects with `name_value`.

    `name_value` may contain multiple newline-separated names and `*.`
    wildcards. Returns sorted unique in-apex names, excluding the bare apex.
    """
    entries = json.loads(json_text)
    names: set[str] = set()
    for entry in entries:
        raw_value = entry.get("name_value", "")
        for raw_name in raw_value.split("\n"):
            normalized = normalize_name(raw_name, apex)
            if normalized is not None:
                names.add(normalized)
    return sorted(names)
