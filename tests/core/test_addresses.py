"""D60: the one address policy (`core/addresses.py`, ADR-036).

From a customer-facing scan the platform does not connect to a non-global
address, and the address it connects to is the one it checked. This file
covers the rule and the lookup; `test_address_pinning.py` covers the
connections.

The refusal list is checked against IANA's own special-purpose registries,
vendored unmodified in `tests/core/data/iana/` (fetched 2026-10-12; licence in
`tools/registry.yaml`). A Python upgrade that changes `ipaddress`'s
classification, or a registry refresh that adds a range, fails here rather
than quietly widening what we connect to.
"""

from __future__ import annotations

import csv
import ipaddress
import re
from pathlib import Path

import pytest

from core.addresses import (
    AddressPolicy,
    AddressRefusedError,
    AddressUnresolvedError,
    LabOverride,
    refusal,
)
from core.dns import DnsResponse

DATA = Path(__file__).parent / "data" / "iana"
REGISTRIES = {
    4: DATA / "iana-ipv4-special-registry-1.csv",
    6: DATA / "iana-ipv6-special-registry-1.csv",
}

STRICTER_THAN_THE_REGISTRY = {
    "64:ff9b::/96": "NAT64: the IPv4 address it translates to is not ours to check",
    "2001:1::3/128": "Python 3.13's ipaddress classes it non-global; refusing is the safe side",
}
"""Rows the registry marks globally reachable that we still refuse, each with
its reason. Anything else marked globally reachable must be permitted:
refusing more than the rule says is a coverage loss nobody chose."""


def _rows(version: int) -> list[tuple[list[ipaddress.IPv4Network | ipaddress.IPv6Network], str]]:
    rows = []
    with REGISTRIES[version].open(newline="") as handle:
        for row in csv.DictReader(handle):
            blocks = [
                ipaddress.ip_network(re.sub(r"\s*\[\d+\]", "", part).strip())
                for part in row["Address Block"].split(",")
            ]
            reachable = row["Globally Reachable"].strip()
            rows.append((blocks, reachable))
    return rows


def _samples(network) -> list[str]:
    first = network.network_address
    last = network.broadcast_address
    out = {first, last}
    if network.num_addresses > 2:
        out.add(first + 1)
    return sorted(str(a) for a in out)


def _registry_cases():
    """Every sampled address of every registry row, with what the row says."""
    for version in (4, 6):
        rows = _rows(version)
        reachable_blocks = [b for blocks, r in rows if r.startswith("True") for b in blocks]
        for blocks, reachable in rows:
            for block in blocks:
                for address in _samples(block):
                    ip = ipaddress.ip_address(address)
                    if not reachable.startswith("True") and any(
                        ip in b for b in reachable_blocks if b != block
                    ):
                        # A more specific row overrides this one ([1] footnotes).
                        continue
                    yield pytest.param(str(block), reachable, address, id=f"{block}-{address}")


@pytest.mark.parametrize(("block", "reachable", "address"), list(_registry_cases()))
def test_every_registry_row_is_honoured(block, reachable, address) -> None:
    if reachable.startswith("True") and block not in STRICTER_THAN_THE_REGISTRY:
        assert refusal(address) is None, f"{address} ({block}) is globally reachable"
    else:
        # False, N/A, blank (deprecated), or one of our stated exceptions.
        assert refusal(address) is not None, f"{address} ({block}) must be refused"


def test_the_stated_exceptions_are_still_in_the_registry() -> None:
    blocks = {str(b) for v in (4, 6) for bs, _ in _rows(v) for b in bs}
    assert set(STRICTER_THAN_THE_REGISTRY) <= blocks


@pytest.mark.parametrize(
    ("address", "named"),
    [
        ("127.0.0.1", "loopback"),
        ("10.0.0.5", "private-use"),
        ("172.16.1.1", "private-use"),
        ("192.168.1.1", "private-use"),
        ("100.64.0.1", "shared address space"),
        ("169.254.169.254", "link-local"),
        ("0.0.0.0", "this network"),
        ("255.255.255.255", "limited broadcast"),
        ("224.0.0.1", "multicast"),
        ("239.255.255.250", "multicast"),
        ("240.0.0.1", "reserved"),
        ("192.0.2.1", "documentation"),
        ("192.88.99.1", "6to4 relay"),
        ("::1", "loopback"),
        ("::", "unspecified"),
        ("::ffff:10.0.0.1", "ipv4-mapped"),
        ("::ffff:8.8.8.8", "ipv4-mapped"),
        ("::a00:1", "ipv4-compatible"),
        ("64:ff9b::a00:1", "nat64"),
        ("fc00::1", "unique-local"),
        ("fd12:3456::1", "unique-local"),
        ("fe80::1", "link-local"),
        ("fec0::1", "site-local"),
        ("ff02::1", "multicast"),
        ("ff0e::1", "multicast"),
        ("100:0:0:1::1", "dummy"),
        ("5f00::1", "srv6"),
        ("2001:db8::1", "documentation"),
        ("2002:a00:1::1", "6to4"),
        ("2001::1", "teredo"),
    ],
)
def test_a_refused_address_is_named_with_its_registry_category(address, named) -> None:
    reason = refusal(address)
    assert reason is not None
    assert named in reason.lower()
    assert "RFC" in reason


@pytest.mark.parametrize(
    "address", ["93.184.215.14", "8.8.8.8", "2606:4700::1111", "2a00:1450:4001:80b::200e"]
)
def test_ordinary_public_addresses_are_permitted(address) -> None:
    assert refusal(address) is None


def test_a_non_literal_is_refused_not_resolved() -> None:
    assert refusal("example.com") is not None


# --- the lookup -------------------------------------------------------------


class FakeDns:
    def __init__(self, answers: dict[tuple[str, str], list[str] | str]) -> None:
        self.answers = answers
        self.queries: list[tuple[str, str]] = []

    def query(self, name: str, rrtype: str, *, resolver: str | None = None) -> DnsResponse:
        self.queries.append((name, rrtype))
        answer = self.answers.get((name, rrtype), [])
        if isinstance(answer, str):  # an rcode
            return DnsResponse(name, rrtype, answer, [])
        return DnsResponse(name, rrtype, "NOERROR" if answer else "NODATA", list(answer))


def test_a_name_is_resolved_through_the_scan_resolver_ipv4_first() -> None:
    dns = FakeDns(
        {("example.test", "A"): ["93.184.215.14"], ("example.test", "AAAA"): ["2606:4700::1"]}
    )
    pinned = AddressPolicy().pin("example.test", dns)
    assert pinned.host == "example.test"
    assert pinned.addresses == ("93.184.215.14", "2606:4700::1")
    assert dns.queries == [("example.test", "A"), ("example.test", "AAAA")]


def test_one_non_global_address_refuses_the_whole_name_and_names_it() -> None:
    """Decision 2: a public name with a private record is the split-horizon or
    stale-record signal worth showing, and connecting to the rest would hide it."""
    dns = FakeDns({("example.test", "A"): ["93.184.215.14", "10.0.0.5"]})
    with pytest.raises(AddressRefusedError) as caught:
        AddressPolicy().pin("example.test", dns)
    assert caught.value.host == "example.test"
    assert caught.value.refused == {"10.0.0.5": refusal("10.0.0.5")}
    assert "10.0.0.5" in str(caught.value)
    assert "private-use" in str(caught.value).lower()


def test_a_refusal_in_the_aaaa_answer_refuses_the_name_too() -> None:
    dns = FakeDns({("example.test", "A"): ["93.184.215.14"], ("example.test", "AAAA"): ["::1"]})
    with pytest.raises(AddressRefusedError, match="::1"):
        AddressPolicy().pin("example.test", dns)


def test_an_address_literal_is_checked_without_a_lookup() -> None:
    dns = FakeDns({})
    assert AddressPolicy().pin("93.184.215.14", dns).addresses == ("93.184.215.14",)
    with pytest.raises(AddressRefusedError, match=re.escape("169.254.169.254")):
        AddressPolicy().pin("169.254.169.254", dns)
    with pytest.raises(AddressRefusedError):
        AddressPolicy().pin("[::1]", dns)
    assert dns.queries == []


def test_no_resolver_fails_closed_and_loudly() -> None:
    """A wiring bug, not a fact about the target: never an `inconclusive`."""
    from core.addresses import ResolverNotWiredError

    assert not issubclass(ResolverNotWiredError, AddressUnresolvedError)
    with pytest.raises(ResolverNotWiredError, match="no resolver"):
        AddressPolicy().pin("example.test", None)


@pytest.mark.parametrize("rcode", ["NXDOMAIN", "SERVFAIL"])
def test_a_lookup_failure_is_unresolved_and_says_which(rcode) -> None:
    dns = FakeDns({("example.test", "A"): rcode, ("example.test", "AAAA"): rcode})
    with pytest.raises(AddressUnresolvedError, match=rcode):
        AddressPolicy().pin("example.test", dns)


def test_a_name_with_no_address_records_is_unresolved() -> None:
    with pytest.raises(AddressUnresolvedError, match="no A or AAAA"):
        AddressPolicy().pin("example.test", FakeDns({}))
    with pytest.raises(AddressUnresolvedError) as caught:
        AddressPolicy().pin("example.test", FakeDns({}))
    assert caught.value.lookup_failed is False


def test_a_failed_lookup_is_marked_as_one() -> None:
    dns = FakeDns({("example.test", "A"): "TIMEOUT", ("example.test", "AAAA"): "SERVFAIL"})
    with pytest.raises(AddressUnresolvedError) as caught:
        AddressPolicy().pin("example.test", dns)
    assert caught.value.lookup_failed is True


def test_one_family_failing_still_pins_the_other() -> None:
    """We connect only to addresses we checked; an unanswered family adds none."""
    dns = FakeDns({("example.test", "A"): ["93.184.215.14"], ("example.test", "AAAA"): "SERVFAIL"})
    assert AddressPolicy().pin("example.test", dns).addresses == ("93.184.215.14",)


def test_records_that_are_not_addresses_of_that_family_are_ignored() -> None:
    dns = FakeDns({("example.test", "A"): ["93.184.215.14", "not-an-address", "2606:4700::1"]})
    assert AddressPolicy().pin("example.test", dns).addresses == ("93.184.215.14",)


def test_the_name_is_compared_case_and_dot_insensitively() -> None:
    dns = FakeDns({("example.test", "A"): ["93.184.215.14"]})
    assert AddressPolicy().pin("Example.TEST.", dns).addresses == ("93.184.215.14",)


# --- the one lab override ---------------------------------------------------


def test_the_policy_has_no_override_by_default() -> None:
    assert AddressPolicy().lab_reason is None


def test_the_lab_override_permits_only_its_own_networks() -> None:
    """Lab entry point: `networks` replaced the blanket `allow_non_global`, so a
    lab use names exactly what it may reach."""
    policy = AddressPolicy(lab_override=LabOverride(reason="unit test", networks=("127.0.0.1/32",)))
    dns = FakeDns({("localhost", "A"): ["127.0.0.1"], ("other.test", "A"): ["127.0.0.2"]})
    assert policy.pin("localhost", dns).addresses == ("127.0.0.1",)
    assert policy.lab_reason == "unit test"
    with pytest.raises(AddressRefusedError, match=re.escape("127.0.0.2")):
        policy.pin("other.test", dns)


def test_an_override_with_no_networks_permits_nothing_extra() -> None:
    policy = AddressPolicy(lab_override=LabOverride(reason="unit test"))
    with pytest.raises(AddressRefusedError):
        policy.pin("127.0.0.1", FakeDns({}))


@pytest.mark.parametrize(
    "network",
    [
        "10.0.0.0/8",  # the shape of a fleet subnet: never a lab network
        "192.168.0.0/16",
        "172.16.5.0/24",
        "169.254.169.254/32",  # cloud metadata
        "fe80::/10",
        "93.184.215.0/24",  # global: the policy never needed permission for it
        "0.0.0.0/0",
    ],
)
def test_a_lab_override_cannot_name_a_network_outside_the_declared_lab_networks(
    network,
) -> None:
    """ADR-036 decision 10: the lab may never reach a production address. Its
    networks must sit inside LAB_NETWORKS, which a reviewed change to core
    widens, one purpose-built lab at a time."""
    with pytest.raises(ValueError, match="lab network"):
        LabOverride(reason="unit test", networks=(network,))


def test_a_lab_network_written_with_host_bits_is_refused_not_widened() -> None:
    """`127.5.5.5/8` is a typo for something; normalising it to all of 127/8
    would widen the lab silently (review of the lab entry point, round 1)."""
    with pytest.raises(ValueError):
        LabOverride(reason="unit test", networks=("127.5.5.5/8",))


def test_the_declared_lab_networks_are_loopback_only_until_step_3() -> None:
    from core.addresses import LAB_NETWORKS

    assert {str(n) for n in LAB_NETWORKS} == {"127.0.0.0/8", "::1/128"}


def test_the_dedicated_address_waiver_keys_off_the_named_hosts() -> None:
    """Condition 4: the waiver is for targets the override names, not for any
    target scanned while an override happens to be present."""
    policy = AddressPolicy(
        lab_override=LabOverride(reason="unit test", hosts=frozenset({"localhost"}))
    )
    assert policy.waives_dedicated_address("localhost")
    assert policy.waives_dedicated_address("LOCALHOST.")
    assert not policy.waives_dedicated_address("example.com")
    assert not AddressPolicy().waives_dedicated_address("localhost")


# --- the address-scope check (D61's first instance) -------------------------


def test_an_address_scope_permits_its_networks_and_refuses_everything_else() -> None:
    from core.addresses import AddressScope

    scope = AddressScope(("127.0.0.1/32", "::1/128"))
    assert scope.permits("127.0.0.1")
    assert scope.permits("::1")
    assert not scope.permits("127.0.0.2")
    assert not scope.permits("93.184.215.14")
    assert not scope.permits("not-an-address")
    assert not AddressScope(()).permits("127.0.0.1")


def test_only_a_real_lab_override_is_accepted() -> None:
    from types import SimpleNamespace

    with pytest.raises(TypeError):
        AddressPolicy(lab_override=SimpleNamespace(reason="x", networks=()))  # type: ignore[arg-type]


def test_a_lab_override_must_say_why() -> None:
    with pytest.raises(ValueError):
        LabOverride(reason="  ")


def test_nxdomain_is_a_definite_answer_not_a_failed_lookup() -> None:
    dns = FakeDns({("example.test", "A"): "NXDOMAIN", ("example.test", "AAAA"): "NXDOMAIN"})
    with pytest.raises(AddressUnresolvedError, match="NXDOMAIN") as caught:
        AddressPolicy().pin("example.test", dns)
    assert caught.value.lookup_failed is False


# --- review of D60, round 5 ---------------------------------------------------


class _TwoResolvers:
    """The real DnsClient, with a primary that times out and a second that answers."""

    def __init__(self, second_answers: dict[str, str]) -> None:
        from core.dns import DnsClient

        outer = self

        class _Resolver:
            def resolve(self, name, rrtype, upstream):
                outer.asked.append((name, rrtype, upstream))
                if upstream == "192.0.2.1":
                    return DnsResponse(name, rrtype, "TIMEOUT", [])
                ip = second_answers.get(name) if rrtype == "A" else None
                return DnsResponse(name, rrtype, "NOERROR" if ip else "NODATA", [ip] if ip else [])

        self.asked: list[tuple[str, str, str | None]] = []
        self.client = DnsClient(resolver=_Resolver(), resolvers=["192.0.2.1", "192.0.2.2"])


def test_a_lookup_that_fails_to_answer_is_asked_again_of_the_second_resolver() -> None:
    """Round 5: the cache keeps failures, so one dropped packet on the first
    lookup would otherwise refuse the name for the whole scan."""
    two = _TwoResolvers({"example.test": "93.184.215.14"})
    policy = AddressPolicy()
    assert policy.pin("example.test", two.client).addresses == ("93.184.215.14",)
    asked_once = list(two.asked)
    assert ("example.test", "A", "192.0.2.2") in asked_once
    # The same answer for the rest of the scan, and no new queries.
    assert policy.pin("example.test", two.client).addresses == ("93.184.215.14",)
    assert two.asked == asked_once


def test_the_second_answer_is_checked_like_the_first() -> None:
    two = _TwoResolvers({"example.test": "10.0.0.5"})
    with pytest.raises(AddressRefusedError, match=re.escape("10.0.0.5")):
        AddressPolicy().pin("example.test", two.client)


def test_nxdomain_on_either_family_means_the_name_does_not_exist() -> None:
    dns = FakeDns({("example.test", "A"): "NXDOMAIN", ("example.test", "AAAA"): "SERVFAIL"})
    with pytest.raises(AddressUnresolvedError) as caught:
        AddressPolicy().pin("example.test", dns)
    assert caught.value.lookup_failed is False
