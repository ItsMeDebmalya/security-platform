"""The lab entry point: scan a purpose-built lab box (ADR-036 decision 10).

    uv run python -m corpus.lab.scan web --target http://localhost:3000 --target-type url

`scan run` refuses loopback and private addresses, and it resolves names only
through public resolvers, so it cannot reach the docs/13 containers or the
docs/26 Step 3 lab boxes. This module can, and it is deliberately not a flag on
`scan run`: no customer-facing code path can reach it (`cli/` may not import
from `corpus/`, and the override walk in tests/core/test_testssl_scope.py
covers it).

It runs `scan run`'s own `_execute`, so the authorisation check, the name
scope, the kill switch, the rate limits, cost counting, redaction and the
testssl.sh argument allowlist are exactly the customer path's. What it changes,
and only for the boxes in `inventory.yaml`:

- the address policy may connect to each box's own address (each one is
  inside `core.addresses.LAB_NETWORKS`, which holds no production network);
- each box's name resolves to its address here (so `localhost` works again),
  while every other name still goes to the public resolvers;
- testssl.sh's dedicated-address condition is waived for these targets,
  because it is true of them: a box we started serves nobody else.

A target that is not in the inventory is refused before anything runs.
"""

from __future__ import annotations

import argparse
import ipaddress
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

import yaml

from cli.main import (
    SCOPE_PATH,
    _as_target_type,
    _echo,
    _execute,
    _print_table,
)
from cli.replay_counts import Counts, write_manifest
from core.addresses import AddressPolicy, LabOverride, refusal
from core.authz import AuthorisationDeniedError
from core.dns import DnsResponse, MissingFixtureError, Resolver
from core.http import OutOfScopeError
from core.models import Asset, ScanResult

INVENTORY = Path(__file__).with_name("inventory.yaml")
RESERVED_SUFFIXES = (".test", ".example", ".invalid", ".localhost")
REASON = "lab entry point: purpose-built lab boxes listed in corpus/lab/inventory.yaml"


def _reserved(name: str) -> bool:
    return name == "localhost" or name.endswith(RESERVED_SUFFIXES)


@dataclass(frozen=True)
class Inventory:
    entries: dict[str, str]
    """Box name -> its address."""

    @property
    def hosts(self) -> frozenset[str]:
        """What may be named as a target: each box's name or its address."""
        return frozenset(self.entries) | frozenset(self.entries.values())

    def override(self) -> LabOverride:
        networks = tuple(
            f"{a}/{32 if ipaddress.ip_address(a).version == 4 else 128}"
            for a in self.entries.values()
        )
        return LabOverride(reason=REASON, networks=networks, hosts=self.hosts)

    def resolver(self, inner: Resolver) -> Resolver:
        return _LabResolver(self.entries, inner)


class _LabResolver:
    """Answers the inventory's names from the inventory; passes on every other name."""

    def __init__(self, entries: dict[str, str], inner: Resolver) -> None:
        self._entries = entries
        self._inner = inner

    def resolve(self, name: str, rrtype: str, upstream: str | None = None) -> DnsResponse:
        key = name.strip().lower().rstrip(".")
        if key not in self._entries:
            return self._inner.resolve(name, rrtype, upstream)
        address = self._entries[key]
        family = "A" if ipaddress.ip_address(address).version == 4 else "AAAA"
        if rrtype.upper() == family:
            return DnsResponse(key, rrtype.upper(), "NOERROR", [address], resolver=upstream)
        return DnsResponse(key, rrtype.upper(), "NODATA", [], resolver=upstream)


def load_inventory(path: Path) -> Inventory:
    """Read and check the inventory. Any entry outside the rules is refused."""
    data = yaml.safe_load(path.read_text()) or {}
    boxes = data.get("boxes") if isinstance(data, dict) else None
    if not isinstance(boxes, list) or not all(
        isinstance(b, dict) and {"name", "address"} <= set(b) for b in boxes
    ):
        raise ValueError(
            f"{path}: the lab inventory must be `boxes:`, a list of {{name, address}} entries"
        )
    entries: dict[str, str] = {}
    for box in boxes:
        name = str(box["name"]).strip().lower().rstrip(".")
        address = str(ipaddress.ip_address(str(box["address"])))
        if not _reserved(name):
            raise ValueError(
                f"{name}: a lab box needs `localhost` or an RFC 2606 reserved name "
                "(.test, .example, .invalid, .localhost), never a real domain"
            )
        if refusal(address) is None:
            raise ValueError(f"{name}: {address} is a global address; a lab box is never one")
        LabOverride(reason=REASON, networks=(address,))  # refuses one outside LAB_NETWORKS
        if name in entries:
            raise ValueError(f"{name} appears twice in the lab inventory")
        entries[name] = address
    return Inventory(entries)


def _target_host(target: Asset) -> str:
    value = target.value.strip()
    if target.type == "url" or "://" in value:
        value = urlsplit(value).hostname or ""
    return value.lower().rstrip(".").strip("[]")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m corpus.lab.scan", description=__doc__)
    parser.add_argument("scanner")
    parser.add_argument("--target", "-t", required=True)
    parser.add_argument("--mode", "-m", default="light")
    parser.add_argument("--target-type", default="domain")
    parser.add_argument(
        "--format", dest="output_format", default="table", choices=("table", "json")
    )
    parser.add_argument("--record", type=Path, default=None)
    parser.add_argument("--scope-file", type=Path, default=SCOPE_PATH)
    args = parser.parse_args(argv)

    try:
        inventory = load_inventory(INVENTORY)
        target = Asset(type=_as_target_type(args.target_type), value=args.target)
    except ValueError as exc:
        _echo(f"error: {exc}")
        return 1
    host = _target_host(target)
    if host not in inventory.hosts:
        _echo(
            f"refused: {host} is not in the lab inventory (corpus/lab/inventory.yaml). The "
            "lab path scans only purpose-built lab boxes listed there (ADR-036 decision 10); "
            "use `scan run` for anything else."
        )
        return 1

    counts = Counts()
    try:
        result = _execute(
            scanner_name=args.scanner,
            target=target,
            mode=args.mode,
            record=args.record,
            replay=None,
            scope_file=args.scope_file,
            address_policy=AddressPolicy(lab_override=inventory.override()),
            wrap_resolver=inventory.resolver,
            counts=counts,
        )
    except KeyError as exc:
        _echo(str(exc).strip('"'))
        return 1
    except AuthorisationDeniedError as exc:
        _echo(f"authorisation denied: {exc}")
        return 1
    except OutOfScopeError as exc:
        _echo(f"out of scope: {exc}")
        return 1
    except MissingFixtureError as exc:
        _echo(str(exc))
        return 1
    except ValueError as exc:
        _echo(f"error: {exc}")
        return 1

    # Re-validated at the storage boundary, as `scan run` does (ADR-028).
    result = ScanResult.model_validate(result.model_dump())
    # D64: and the same manifest `scan run --record` writes, so a lab recording
    # replayed through `scan run --replay` can say what the live run counted
    # rather than reporting a different number for the same field.
    if args.record is not None:
        write_manifest(args.record, counts=counts, requests_counted=result.telemetry.requests)
    if args.output_format == "json":
        _echo(result.model_dump_json(indent=2))
    else:
        _print_table(result)
    return 0


if __name__ == "__main__":
    sys.exit(main())
