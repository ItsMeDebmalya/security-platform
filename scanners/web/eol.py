"""End-of-life branch matching, driven by data/eol.yaml.

Only branches already past end-of-life when the entry was written are listed,
so no entry ever changes status at runtime and frozen fixtures cannot rot.
Freshness is a CI property (tests/scanners/web/test_data.py), not a runtime one.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any, cast

import yaml

from scanners.web.sources import parse_source

DATA = Path(__file__).parent / "data" / "eol.yaml"


@dataclass(frozen=True)
class EolEntry:
    product: str
    branch: str
    eol_date: date
    source: str
    reviewed_on: date
    source_note: str | None = None


def _entry(e: dict[str, Any]) -> EolEntry:
    label = f"{e['product']} {e['branch']}"
    try:
        source = parse_source(e.get("source"))
    except ValueError as exc:
        raise ValueError(f"{label}: {exc}") from exc
    if source.tier != "vendor":
        raise ValueError(f"{label}: an end-of-life date must come from a vendor-tier source")
    return EolEntry(
        e["product"],
        str(e["branch"]),
        e["eol_date"],
        cast(str, source.url),
        e["reviewed_on"],
        source.note,
    )


def load(path: Path = DATA) -> tuple[EolEntry, ...]:
    raw: list[dict[str, Any]] = yaml.safe_load(path.read_text())
    return tuple(_entry(e) for e in raw)


def branch_matches(version: str, branch: str) -> bool:
    v, b = version.split("."), branch.split(".")
    return v[: len(b)] == b


def match(entries: Sequence[EolEntry], product: str, version: str) -> EolEntry | None:
    candidates = [e for e in entries if e.product == product and branch_matches(version, e.branch)]
    return max(candidates, key=lambda e: len(e.branch.split(".")), default=None)
