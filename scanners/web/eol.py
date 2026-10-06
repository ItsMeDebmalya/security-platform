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
from typing import Any

import yaml

DATA = Path(__file__).parent / "data" / "eol.yaml"


@dataclass(frozen=True)
class EolEntry:
    product: str
    branch: str
    eol_date: date
    source: str
    reviewed_on: date


def load(path: Path = DATA) -> tuple[EolEntry, ...]:
    raw: list[dict[str, Any]] = yaml.safe_load(path.read_text())
    return tuple(
        EolEntry(e["product"], str(e["branch"]), e["eol_date"], e["source"], e["reviewed_on"])
        for e in raw
    )


def branch_matches(version: str, branch: str) -> bool:
    v, b = version.split("."), branch.split(".")
    return v[: len(b)] == b


def match(entries: Sequence[EolEntry], product: str, version: str) -> EolEntry | None:
    candidates = [e for e in entries if e.product == product and branch_matches(version, e.branch)]
    return max(candidates, key=lambda e: len(e.branch.split(".")), default=None)
