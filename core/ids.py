"""Deterministic finding identity.

    id = sha256(scanner + check_id + target.value + normalise(location) + (instance_key or ""))

`scanner_version` is deliberately not an input: a re-scan after a logic change
must map to the same finding, or every improvement would look like a mass
close-and-reopen. When a version bump changes what a check *means*, that is a
`check_id` rename plus a `renamed_from` entry, not a silent redefinition.
"""

from __future__ import annotations

import hashlib
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

TARGET_LEVEL = "$"
"""Reserved location meaning "the target as a whole"."""

VOLATILE_PARAMS = frozenset(
    {
        "_",
        "cb",
        "cachebuster",
        "csrf",
        "csrftoken",
        "jsessionid",
        "nonce",
        "phpsessid",
        "rand",
        "sid",
        "session",
        "sessionid",
        "t",
        "timestamp",
        "ts",
        "xsrf",
    }
)
"""Query parameters that change between scans of an unchanged target.

Conservative on purpose: a parameter wrongly listed here merges two findings
that should stay separate, which is worse than an id that churns.
"""


def normalise_location(location: str) -> str:
    """Strip the volatile parts of a location so re-scans produce one identity.

    Removes session ids and cache-busters, and sorts the remaining query
    parameters so ordering does not change the id. Non-URL locations (a DNS
    name, a file path, the reserved "$") pass through lowercased and stripped.
    """
    location = location.strip()
    if not location:
        raise ValueError("location must not be empty; use '$' for a target-level finding")
    if location == TARGET_LEVEL:
        return TARGET_LEVEL

    parts = urlsplit(location)
    if not parts.query:
        return location.rstrip("/").lower() or "/"

    kept = sorted(
        (k, v)
        for k, v in parse_qsl(parts.query, keep_blank_values=True)
        if k.lower() not in VOLATILE_PARAMS
    )
    rebuilt = urlunsplit((parts.scheme, parts.netloc, parts.path.rstrip("/"), urlencode(kept), ""))
    return rebuilt.lower()


def finding_id(
    *,
    scanner: str,
    check_id: str,
    target_value: str,
    location: str,
    instance_key: str | None = None,
) -> str:
    material = "".join(
        [
            scanner,
            check_id,
            target_value.lower(),
            normalise_location(location),
            instance_key or "",
        ]
    )
    return "sha256:" + hashlib.sha256(material.encode("utf-8")).hexdigest()
