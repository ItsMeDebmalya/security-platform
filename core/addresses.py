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
from dataclasses import dataclass, field
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

    def __init__(self, message: str, *, lookup_failed: bool = False) -> None:
        super().__init__(message)
        self.lookup_failed = lookup_failed
        """True when a lookup failed (TIMEOUT, SERVFAIL...), which says nothing
        about whether the name has records; False when the answers were
        definite and held no address (review of D60, round 4)."""


class ResolverNotWiredError(RuntimeError):
    """A connecting client was given no resolver: our wiring bug, never a fact
    about the target, so it is a scan error and never an `inconclusive`
    (review of D60, round 3). Nothing was connected to."""


# --- the policy -------------------------------------------------------------


LAB_NETWORKS: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = (
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
)
"""Where a lab override may ever reach (ADR-036 decision 10): purpose-built
lab boxes only, boxes we created to be scanned. **Never a production address,
network or name.** Loopback only until docs/26 Step 3 adds the lab VMs' own
network, by a reviewed change here. The fleet is reached through agent
snapshots, never through the lab path."""


class AddressScope:
    """Addresses inside a declared set of networks, and nothing else.

    D61's first instance: an address-level scope check. The lab uses it for
    its inventory; a customer-facing address scope (an address shown to be
    the customer's) is meant to reuse this, not to grow a second one.
    """

    def __init__(self, networks: tuple[str, ...]) -> None:
        self.networks = tuple(ipaddress.ip_network(n, strict=False) for n in networks)

    def permits(self, address: str) -> bool:
        ip = _parse(address)
        return ip is not None and any(
            ip.version == net.version and ip in net for net in self.networks
        )


def _within_lab_networks(network: ipaddress.IPv4Network | ipaddress.IPv6Network) -> bool:
    return any(
        network.version == lab.version and network.subnet_of(lab)  # type: ignore[arg-type]
        for lab in LAB_NETWORKS
    )


@dataclass(frozen=True)
class LabOverride:
    """Permission to work without one of the platform's consent conditions.

    For the lab and the corpus recordings only, never a customer-facing path.
    It is the only override there is, and it says exactly what it covers:
    - `networks`: the non-global addresses the policy may connect to. Each
      must sit inside `LAB_NETWORKS`; anything else is refused when the
      override is made, so no lab use can name a production network.
    - `hosts`: the targets for which testssl.sh's dedicated-address condition
      (D59) is waived. The waiver keys off the target being named here, never
      off an override merely being present.
    `reason` is recorded wherever it is used.
    """

    reason: str
    networks: tuple[str, ...] = ()
    hosts: frozenset[str] = frozenset()

    def __init_subclass__(cls, **kwargs: Any) -> None:
        raise TypeError("LabOverride cannot be subclassed (ADR-036 decision 6)")

    def __post_init__(self) -> None:
        if not self.reason.strip():
            raise ValueError("a lab override must say why it is being used")
        for network in self.networks:
            # Strict: `127.5.5.5/8` is refused, never silently widened to 127/8.
            parsed = ipaddress.ip_network(network)
            if not _within_lab_networks(parsed):
                raise ValueError(
                    f"{network} is not inside a declared lab network "
                    f"({', '.join(str(n) for n in LAB_NETWORKS)}). The lab may never reach a "
                    "production address, network or name (ADR-036 decision 10)"
                )
        object.__setattr__(
            self, "hosts", frozenset(h.strip().lower().rstrip(".") for h in self.hosts)
        )


@dataclass(frozen=True)
class Pinned:
    """A name and the addresses we checked for it, in the order to try them."""

    host: str
    addresses: tuple[str, ...]


@dataclass(frozen=True)
class AddressPolicy:
    """The scan's address policy. `ScanContext` hands the same one to every client."""

    lab_override: LabOverride | None = field(default=None, kw_only=True)
    """Keyword-only, so every use names it (`lab_override=`) where the override
    walk can see it (review of the lab entry point, round 2)."""

    def __init_subclass__(cls, **kwargs: Any) -> None:
        # A subclass overriding `refusal` would relax the policy without naming
        # the override, out of the walk's sight (review of D60, round 1).
        raise TypeError("AddressPolicy cannot be subclassed (ADR-036 decision 6)")

    def __post_init__(self) -> None:
        if self.lab_override is not None and type(self.lab_override) is not LabOverride:
            raise TypeError("only a real LabOverride can relax the address policy")

    @property
    def lab_reason(self) -> str | None:
        """The override's reason, or `None` outside the lab."""
        return self.lab_override.reason if self.lab_override is not None else None

    def refusal(self, address: str) -> str | None:
        """`refusal()`, with the lab's permission for its own networks only."""
        why = refusal(address)
        if why is None or _parse(address) is None:
            return why
        if self.lab_override is not None and AddressScope(self.lab_override.networks).permits(
            address
        ):
            return None
        return why

    def waives_dedicated_address(self, host: str) -> bool:
        """Whether testssl.sh's dedicated-address condition is waived for this
        target: only when the lab override names it (ADR-036 decision 10)."""
        return (
            self.lab_override is not None
            and host.strip().lower().rstrip(".") in self.lab_override.hosts
        )

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
            raise ResolverNotWiredError(
                f"no resolver for {name}: the scan's DNS client was not wired, "
                "so nothing was connected to"
            )

        addresses: list[str] = []
        failures: list[str] = []
        second = getattr(dns, "second_resolver", lambda: None)()
        for rrtype, version in (("A", 4), ("AAAA", 6)):
            answer = dns.query(name, rrtype)
            if answer.rcode not in _DEFINITE and second is not None:
                # The scan caches failures too, so one dropped packet would
                # otherwise refuse this name for the whole scan. Ask the
                # second resolver once; its answer is checked like any other
                # and, being cached per resolver, holds for the scan
                # (review of D60, round 5).
                answer = dns.query(name, rrtype, resolver=second)
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
                    "so nothing was connected to",
                    # NXDOMAIN on either family is a definite "no such name"
                    # for the whole name; otherwise TIMEOUT, SERVFAIL or
                    # REFUSED means the lookup failed to answer at all.
                    lookup_failed=not any(f.endswith(" NXDOMAIN") for f in failures),
                )
            raise AddressUnresolvedError(
                f"{name} has no A or AAAA record, so there is no address to connect to"
            )
        refused = {a: why for a in addresses if (why := self.refusal(a)) is not None}
        if refused:
            raise AddressRefusedError(name, refused)
        return Pinned(host=name, addresses=tuple(addresses))


_DEFINITE = ("NOERROR", "NODATA", "NXDOMAIN")
"""Answers that say something about the name; anything else is a failure to answer."""


def url_host(address: str) -> str:
    """An address as it goes in a URL: IPv6 in brackets."""
    return f"[{address}]" if ":" in address else address


__all__ = [
    "LAB_NETWORKS",
    "AddressPolicy",
    "AddressRefusedError",
    "AddressScope",
    "AddressUnresolvedError",
    "LabOverride",
    "Pinned",
    "ResolverNotWiredError",
    "refusal",
    "url_host",
]
