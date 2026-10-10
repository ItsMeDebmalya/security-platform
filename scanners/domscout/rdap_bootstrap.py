"""Which registry's RDAP server answers for a domain (ADR-031, RFC 9224).

The registry's server comes from a vendored copy of IANA's "Bootstrap Service
Registry for Domain Name Space" (`data/iana-rdap-dns.json`, from
`https://data.iana.org/rdap/dns.json`, CC0 1.0, registry entry
`iana-rdap-dns-bootstrap`). RFC 9224 §8 says clients SHOULD cache it: the
vendored copy is that cache, and a test fails CI once its `publication` is
more than `MAX_AGE_DAYS` old. A stale copy fails to `inconclusive`, never to a
false claim (ADR-031 clause 4).

Special-use names (IANA's Special-Use Domain Names registry, RFC 6761) have no
registry, so registration expiry does not apply to them (operator ruling,
2026-10-10). That is reported as `not_applicable`, never as a pass (ADR-032).

No network and no I/O beyond reading the vendored file once.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from functools import cache
from pathlib import Path

from core.tls import a_label

BOOTSTRAP_FILE = Path(__file__).parent / "data" / "iana-rdap-dns.json"
MAX_AGE_DAYS = 90

SPECIAL_USE_NAMES = frozenset(
    {
        # IANA Special-Use Domain Names registry, updated 2026-05-22, read 2026-10-10.
        "alt",  # RFC 9476
        "6tisch.arpa",  # RFC 9031
        "eap.arpa",  # RFC 9965
        "eap-noob.arpa",  # RFC 9140, deprecated by RFC 9965
        "home.arpa",  # RFC 8375
        "10.in-addr.arpa",  # RFC 6761
        "254.169.in-addr.arpa",  # RFC 6762
        *(f"{n}.172.in-addr.arpa" for n in range(16, 32)),  # RFC 6761
        "170.0.0.192.in-addr.arpa",  # RFC 8880
        "171.0.0.192.in-addr.arpa",  # RFC 8880
        "168.192.in-addr.arpa",  # RFC 6761
        "8.e.f.ip6.arpa",  # RFC 6762
        "9.e.f.ip6.arpa",  # RFC 6762
        "a.e.f.ip6.arpa",  # RFC 6762
        "b.e.f.ip6.arpa",  # RFC 6762
        "ipv4only.arpa",  # RFC 8880
        "resolver.arpa",  # RFC 9462
        "service.arpa",  # RFC 9665
        "example",  # RFC 6761
        "invalid",  # RFC 6761
        "local",  # RFC 6762
        "localhost",  # RFC 6761
        "onion",  # RFC 7686
        "test",  # RFC 6761
    }
)
"""Left out on purpose: `example.com`, `example.net` and `example.org`. RFC 6761
reserves them too, but a real registry holds each, with an RDAP record and an
expiry date, so "no registry delegates it" would be false. They take the normal
RDAP path."""


@dataclass(frozen=True)
class Bootstrap:
    publication: datetime
    services: dict[str, str]
    """Lowercase A-label suffix -> the registry's RDAP base URL (https, ends `/`)."""


@cache
def bootstrap() -> Bootstrap:
    data = json.loads(BOOTSTRAP_FILE.read_text())
    services: dict[str, str] = {}
    for labels, urls in data["services"]:
        # RFC 9224 §4: prefer an https URL when the entry lists several.
        https = [u for u in urls if u.lower().startswith("https://")]
        if not https:
            continue
        base = https[0] if https[0].endswith("/") else https[0] + "/"
        for label in labels:
            services[label.lower().rstrip(".")] = base
    publication = datetime.fromisoformat(data["publication"].replace("Z", "+00:00"))
    return Bootstrap(publication=publication.astimezone(UTC), services=services)


def _suffixes(name: str) -> list[str]:
    """`a.b.c` -> `["a.b.c", "b.c", "c"]`: longest first, label-wise (RFC 9224 §4),
    as A-labels (the bootstrap lists IDN TLDs as `xn--`, ADR-030). A name that
    does not encode has none, so no registry is found for it."""
    encoded = a_label(name)
    if not encoded:
        return []
    labels = encoded.split(".")
    return [".".join(labels[i:]) for i in range(len(labels))]


def is_special_use(name: str) -> bool:
    return any(suffix in SPECIAL_USE_NAMES for suffix in _suffixes(name))


def rdap_base(name: str) -> str | None:
    """The RDAP base URL for `name`'s registry, or None if the bootstrap has none."""
    services = bootstrap().services
    for suffix in _suffixes(name):
        if suffix in services:
            return services[suffix]
    return None


def rdap_url(name: str) -> str | None:
    """RFC 9082 §3.1.3: `<base>domain/<A-label name>`."""
    base = rdap_base(name)
    encoded = a_label(name)
    return None if base is None or not encoded else f"{base}domain/{encoded}"
