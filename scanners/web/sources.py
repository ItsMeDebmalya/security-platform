"""Source tiers for fingerprint and EOL data. Pure: parsing and validation only.

`vendor`: a primary vendor page, https URL required.
`observed`: our own live capture; host, UTC date and the exact string seen, all required.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from typing import Any, Literal, cast


@dataclass(frozen=True)
class Observation:
    host: str
    date: date
    seen: str


@dataclass(frozen=True)
class Source:
    tier: Literal["vendor", "observed"]
    url: str | None
    note: str | None
    observations: tuple[Observation, ...]

    @property
    def reference(self) -> str:
        """vendor -> the URL; observed -> 'observed <host> <date>: <seen>' joined by '; '."""
        if self.tier == "vendor":
            return cast(str, self.url)
        return "; ".join(
            f"observed {o.host} {o.date.isoformat()}: {o.seen}" for o in self.observations
        )


def _observation(raw: object, index: int) -> Observation:
    if not isinstance(raw, dict):
        raise ValueError(f"observation {index} must be a mapping")
    host, seen, when = raw.get("host"), raw.get("seen"), raw.get("date")
    if not isinstance(host, str) or not host:
        raise ValueError(f"observation {index}: host must be a non-empty string")
    if isinstance(when, bool) or not isinstance(when, date) or hasattr(when, "hour"):
        raise ValueError(f"observation {index}: date must be a YAML date (unquoted)")
    if not isinstance(seen, str) or not seen:
        raise ValueError(f"observation {index}: seen must be a non-empty string")
    return Observation(host, when, seen)


def parse_source(raw: object) -> Source:
    if not isinstance(raw, dict):
        raise ValueError("source must be a mapping with a tier")
    data: dict[str, Any] = raw
    tier = data.get("tier")
    if tier not in ("vendor", "observed"):
        raise ValueError(f"tier must be 'vendor' or 'observed', got {tier!r}")
    note = data.get("note")
    if note is not None and not isinstance(note, str):
        raise ValueError("note must be a string")
    if tier == "vendor":
        url = data.get("url")
        if not isinstance(url, str) or not url.startswith("https://"):
            raise ValueError("vendor source requires an https:// url")
        return Source("vendor", url, note, ())
    observations = data.get("observations")
    if not isinstance(observations, list) or not observations:
        raise ValueError("observed source requires a non-empty observations list")
    return Source(
        "observed", None, note, tuple(_observation(o, i) for i, o in enumerate(observations))
    )
