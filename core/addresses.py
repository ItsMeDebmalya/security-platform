"""The one address policy (D60, ADR-036).

What this module promises, and no more: **from a customer-facing scan the
platform does not connect to a non-global address, and the address it
connects to is the one it checked.** It is not a claim that every request-
forgery route is closed. It covers addresses, and only for the clients that
call it: `core/http.py` (every hop of a redirect included), `core/tls.py`
and `core/testssl.py`.

How a client uses it:

1. resolve the name **once**, through the scan's own `DnsClient` (kill switch,
   resolver limit, recording), never the operating system's resolver;
2. check every address with `refusal()`; if any is refused, the whole name
   is refused, naming the address and its registry category;
3. connect to a checked address literal, carrying the hostname as SNI and in
   the Host header. Nothing below this step is handed a name, so nothing
   below it can resolve again and land somewhere else (DNS rebinding).

**The rule** is IANA's special-purpose address registries, applied through
the standard library where it agrees with them:

- `ipaddress`'s `is_global` (Python 3.13 implements the registries'
  "Globally Reachable" column);
- plus what `is_global` gets wrong for our purpose, measured on 3.13.15
  against the registries fetched 2026-10-12: multicast (Python calls it
  global), 192.88.99.0/24 (deprecated 6to4 relay anycast), and for IPv6
  anything outside global unicast `2000::/3`, which also refuses
  IPv4-mapped and IPv4-compatible forms, NAT64's `64:ff9b::/96` (its IPv4
  side is not ours to check), `100:0:0:1::/64`, `5f00::/16` and the
  deprecated site-local `fec0::/10`.

`tests/core/test_addresses.py` checks every registry row against this rule,
so a Python upgrade or a registry change fails a test instead of quietly
widening what we connect to.

**The lab override.** One `LabOverride`, held by one `AddressPolicy`, which
`ScanContext` hands to every client. Off by default. A test walks every
customer-facing package for any route to it; only this module may name it.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Any

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

_GLOBAL_UNICAST_V6 = ipaddress.ip_network("2000::/3")

_ALSO_REFUSED = (ipaddress.ip_network("192.88.99.0/24"),)
"""Python 3.13 calls these global; the registry does not (see the docstring)."""

_CATEGORIES: tuple[tuple[str, str], ...] = (
    # IPv4 special-purpose registry
    ("0.0.0.0/8", '"this network" (RFC 791)'),
    ("10.0.0.0/8", "private-use (RFC 1918)"),
    ("100.64.0.0/10", "shared address space, carrier-grade NAT (RFC 6598)"),
    ("127.0.0.0/8", "loopback (RFC 1122)"),
    ("169.254.0.0/16", "link-local, where cloud metadata services live (RFC 3927)"),
    ("172.16.0.0/12", "private-use (RFC 1918)"),
    ("192.0.0.0/24", "IETF protocol assignments (RFC 6890)"),
    ("192.0.2.0/24", "documentation (RFC 5737)"),
    ("192.88.99.0/24", "deprecated 6to4 relay anycast (RFC 7526)"),
    ("192.168.0.0/16", "private-use (RFC 1918)"),
    ("198.18.0.0/15", "benchmarking (RFC 2544)"),
    ("198.51.100.0/24", "documentation (RFC 5737)"),
    ("203.0.113.0/24", "documentation (RFC 5737)"),
    ("224.0.0.0/4", "multicast (RFC 5771)"),
    ("240.0.0.0/4", "reserved (RFC 1112)"),
    ("255.255.255.255/32", "limited broadcast (RFC 919)"),
    # IPv6 special-purpose registry, and the address architecture
    ("::1/128", "loopback (RFC 4291)"),
    ("::/128", "unspecified (RFC 4291)"),
    ("::ffff:0:0/96", "IPv4-mapped (RFC 4291)"),
    ("::/96", "deprecated IPv4-compatible (RFC 4291)"),
    ("64:ff9b::/96", "NAT64 translation; its IPv4 side is unchecked (RFC 6052)"),
    ("64:ff9b:1::/48", "local-use NAT64 translation (RFC 8215)"),
    ("100::/64", "discard-only (RFC 6666)"),
    ("100:0:0:1::/64", "dummy prefix (RFC 9780)"),
    ("2001::/32", "Teredo (RFC 4380)"),
    ("2001::/23", "IETF protocol assignments (RFC 2928)"),
    ("2001:2::/48", "benchmarking (RFC 5180)"),
    ("2001:10::/28", "deprecated ORCHID (RFC 4843)"),
    ("2001:db8::/32", "documentation (RFC 3849)"),
    ("2002::/16", "6to4 (RFC 3056)"),
    ("3fff::/20", "documentation (RFC 9637)"),
    ("5f00::/16", "SRv6 SIDs (RFC 9602)"),
    ("fc00::/7", "unique-local (RFC 4193)"),
    ("fe80::/10", "link-local (RFC 4291)"),
    ("fec0::/10", "deprecated site-local (RFC 3879)"),
    ("ff00::/8", "multicast (RFC 4291)"),
)
_NETWORKS = sorted(
    ((ipaddress.ip_network(net), label) for net, label in _CATEGORIES),
    key=lambda pair: -pair[0].prefixlen,
)
"""Most specific first, so an address is named by the narrowest block holding it."""


def _parse(address: str) -> IPAddress | None:
    try:
        return ipaddress.ip_address(address.strip().removeprefix("[").removesuffix("]"))
    except ValueError:
        return None


def _category(ip: IPAddress) -> str | None:
    for network, label in _NETWORKS:
        if ip.version == network.version and ip in network:
            return label
    return None


def refusal(address: str) -> str | None:
    """Why we will not connect to this address, or `None` if we may.

    Anything that is not an address literal is refused: this function never
    resolves a name.
    """
    ip = _parse(address)
    if ip is None:
        return "not an address literal; names are resolved through the scan's resolver"
    named = _category(ip)
    if isinstance(ip, ipaddress.IPv6Address) and ip not in _GLOBAL_UNICAST_V6:
        return named or "outside IPv6 global unicast, 2000::/3 (RFC 4291)"
    if ip.is_multicast or any(ip in net for net in _ALSO_REFUSED if net.version == ip.version):
        return named or "multicast"
    if not ip.is_global:
        return named or "not globally reachable (IANA special-purpose address registry)"
    return None


# --- errors -----------------------------------------------------------------


class AddressRefusedError(PermissionError):
    """A name resolved to an address the policy refuses, so nothing was sent.

    Not an "unreachable" and not a clean result: a scanner reports it as an
    `inconclusive` that names the address and what it usually means.
    """

    def __init__(self, host: str, refused: dict[str, str], *, literal: bool = False) -> None:
        self.host = host
        self.refused = dict(refused)
        self.literal = literal
        """The target was an address, not a name: nothing was resolved."""
        listed = "; ".join(f"{address}: {why}" for address, why in self.refused.items())
        self.summary = (
            f"{host} is a non-global address ({listed})"
            if literal
            else f"{host} resolves to a non-global address ({listed})"
        )
        """The fact alone, for a scanner to build its own wording around."""
        meaning = (
            ""
            if literal
            else ". A public name with such a record usually means split-horizon DNS or a "
            "stale record pointing somewhere it should not"
        )
        super().__init__(f"{self.summary}, so it was not connected to{meaning}")


class AddressUnresolvedError(ConnectionError):
    """The name gave us no address we could check, so nothing was sent."""


# --- the policy -------------------------------------------------------------


@dataclass(frozen=True)
class LabOverride:
    """Permission to work without one of the platform's consent conditions.

    For the lab capture and the corpus recordings only, never a
    customer-facing path. It is the only override there is: `core/testssl.py`
    reads it, through `AddressPolicy.lab_reason`, as the waiver of the
    dedicated-address condition (D59), and `allow_non_global` lets the
    address policy connect to loopback and private addresses (the local labs).
    `reason` is recorded wherever it is used.
    """

    reason: str
    allow_non_global: bool = False

    def __post_init__(self) -> None:
        if not self.reason.strip():
            raise ValueError("a lab override must say why it is being used")


@dataclass(frozen=True)
class Pinned:
    """A name and the addresses we checked for it, in the order to try them."""

    host: str
    addresses: tuple[str, ...]


@dataclass(frozen=True)
class AddressPolicy:
    """The scan's address policy. `ScanContext` hands the same one to every client."""

    lab_override: LabOverride | None = None

    def __post_init__(self) -> None:
        if self.lab_override is not None and not isinstance(self.lab_override, LabOverride):
            raise TypeError("only a real LabOverride can relax the address policy")

    @property
    def lab_reason(self) -> str | None:
        """The override's reason, or `None` outside the lab."""
        return self.lab_override.reason if self.lab_override is not None else None

    def refusal(self, address: str) -> str | None:
        """`refusal()`, with the lab's permission for non-global addresses."""
        why = refusal(address)
        if why is None or _parse(address) is None:
            return why
        if self.lab_override is not None and self.lab_override.allow_non_global:
            return None
        return why

    def pin(self, host: str, dns: Any) -> Pinned:
        """Resolve `host` once through the scan's resolver and check every address.

        IPv4 first, then IPv6. One refused address refuses the whole name
        (ADR-036 decision 2). A family that fails to resolve adds nothing;
        both failing, or no address at all, is `AddressUnresolvedError`.
        """
        name = host.strip().lower().rstrip(".")
        literal = _parse(name)
        if literal is not None:
            address = str(literal)
            why = self.refusal(address)
            if why is not None:
                raise AddressRefusedError(host, {address: why}, literal=True)
            return Pinned(host=name, addresses=(address,))
        if dns is None:
            raise AddressUnresolvedError(
                f"no resolver for {name}: the scan's DNS client was not wired, "
                "so nothing was connected to"
            )

        addresses: list[str] = []
        failures: list[str] = []
        for rrtype, version in (("A", 4), ("AAAA", 6)):
            answer = dns.query(name, rrtype)
            if answer.rcode not in ("NOERROR", "NODATA"):
                failures.append(f"{rrtype} {answer.rcode}")
                continue
            for record in answer.records:
                ip = _parse(record)
                if ip is not None and ip.version == version and str(ip) not in addresses:
                    addresses.append(str(ip))

        if not addresses:
            if failures:
                raise AddressUnresolvedError(
                    f"{name} could not be resolved ({', '.join(failures)}), "
                    "so nothing was connected to"
                )
            raise AddressUnresolvedError(
                f"{name} has no A or AAAA record, so there is no address to connect to"
            )
        refused = {a: why for a in addresses if (why := self.refusal(a)) is not None}
        if refused:
            raise AddressRefusedError(name, refused)
        return Pinned(host=name, addresses=tuple(addresses))


def url_host(address: str) -> str:
    """An address as it goes in a URL: IPv6 in brackets."""
    return f"[{address}]" if ":" in address else address


__all__ = [
    "AddressPolicy",
    "AddressRefusedError",
    "AddressUnresolvedError",
    "LabOverride",
    "Pinned",
    "refusal",
    "url_host",
]
