"""Technology detection, driven entirely by data/fingerprints.yaml.

Data, not code, because this database grows for years (05-phase-1 Tool 4).
Authored from vendor documentation and our own observation only — never
seeded from another tool's fingerprint data (SPEC A1 licence guardrail).
Cookie-name signals are unavailable: core redacts Set-Cookie whole (D-W1).
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any

import yaml

from scanners.web.headers import get
from scanners.web.sources import Source, parse_source

DATA = Path(__file__).parent / "data" / "fingerprints.yaml"


@dataclass(frozen=True)
class Fingerprint:
    name: str
    category: str
    source: Source
    reviewed_on: date
    headers: tuple[tuple[str, re.Pattern[str]], ...]
    html: tuple[re.Pattern[str], ...]
    asset: tuple[re.Pattern[str], ...]
    generator: tuple[re.Pattern[str], ...]


@dataclass(frozen=True)
class Detection:
    name: str
    category: str
    version: str | None
    evidence: str
    source: str


def _patterns(values: Sequence[str] | None) -> tuple[re.Pattern[str], ...]:
    return tuple(re.compile(v, re.IGNORECASE) for v in (values or []))


def load(path: Path = DATA) -> tuple[Fingerprint, ...]:
    raw: list[dict[str, Any]] = yaml.safe_load(path.read_text())
    out = []
    for entry in raw:
        match = entry.get("match") or {}
        try:
            source = parse_source(entry.get("source"))
        except ValueError as exc:
            raise ValueError(f"{entry.get('name')}: {exc}") from exc
        out.append(
            Fingerprint(
                name=entry["name"],
                category=entry["category"],
                source=source,
                reviewed_on=entry["reviewed_on"],
                headers=tuple(
                    (k.lower(), re.compile(v, re.IGNORECASE))
                    for k, v in (match.get("headers") or {}).items()
                ),
                html=_patterns(match.get("html")),
                asset=_patterns(match.get("asset")),
                generator=_patterns(match.get("generator")),
            )
        )
    return tuple(out)


def detect(
    fingerprints: Sequence[Fingerprint],
    *,
    headers: Mapping[str, str],
    body: str,
    asset_urls: Sequence[str],
    generator: str | None,
) -> list[Detection]:
    detections = []
    for fp in fingerprints:
        version: str | None = None
        evidence: str | None = None

        def hit(match: re.Match[str], where: str) -> None:
            nonlocal version, evidence
            evidence = evidence or where
            version = version or match.groupdict().get("version")

        for name, pattern in fp.headers:
            value = get(headers, name)
            if value and (m := pattern.search(value)):
                hit(m, f"{name}: {value}")
        for pattern in fp.generator:
            if generator and (m := pattern.search(generator)):
                hit(m, f"meta generator: {generator}")
        for pattern in fp.asset:
            for url in asset_urls:
                if m := pattern.search(url):
                    hit(m, f"asset: {url}")
        for pattern in fp.html:
            if body and (m := pattern.search(body)):
                hit(m, f"markup matching {pattern.pattern}")
        if evidence:
            detections.append(
                Detection(fp.name, fp.category, version, evidence, fp.source.reference)
            )
    return detections
