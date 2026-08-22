"""DMARC parsing, per RFC 7489.

A DMARC record is a tag-value list, and the ordering rules matter: `v` must be
first and `p` must immediately follow it. A record that violates those is
ignored by receivers entirely - so reporting "policy is none" from a record a
receiver would discard would be wrong twice over.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

VERSION = "DMARC1"
POLICIES = frozenset({"none", "quarantine", "reject"})
ALIGNMENT = frozenset({"r", "s"})
KNOWN_TAGS = frozenset({"v", "p", "sp", "pct", "rua", "ruf", "adkim", "aspf", "fo", "rf", "ri"})


@dataclass(frozen=True)
class DmarcRecord:
    raw: str
    tags: dict[str, str] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)

    @property
    def valid(self) -> bool:
        return not self.errors

    @property
    def policy(self) -> str | None:
        value = self.tags.get("p")
        return value.lower() if value else None

    @property
    def subdomain_policy(self) -> str | None:
        value = self.tags.get("sp")
        return value.lower() if value else None

    @property
    def effective_subdomain_policy(self) -> str | None:
        """RFC 7489: sp defaults to p when absent."""
        return self.subdomain_policy or self.policy

    @property
    def pct(self) -> int:
        """RFC 7489: pct defaults to 100."""
        try:
            return int(self.tags.get("pct", "100"))
        except ValueError:
            return 100

    @property
    def adkim(self) -> str:
        return self.tags.get("adkim", "r").lower()

    @property
    def aspf(self) -> str:
        return self.tags.get("aspf", "r").lower()

    @property
    def rua(self) -> list[str]:
        return [part.strip() for part in self.tags.get("rua", "").split(",") if part.strip()]

    @property
    def ruf(self) -> list[str]:
        return [part.strip() for part in self.tags.get("ruf", "").split(",") if part.strip()]

    def to_dict(self) -> dict[str, Any]:
        return {
            "raw": self.raw,
            "valid": self.valid,
            "tags": dict(self.tags),
            "errors": list(self.errors),
            "policy": self.policy,
            "effective_subdomain_policy": self.effective_subdomain_policy,
            "pct": self.pct,
            "adkim": self.adkim,
            "aspf": self.aspf,
            "rua": self.rua,
        }


def parse_dmarc(text: str) -> DmarcRecord:
    raw = text.strip()
    pairs: list[tuple[str, str]] = []
    errors: list[str] = []

    for part in raw.split(";"):
        part = part.strip()
        if not part:
            continue
        if "=" not in part:
            errors.append(f"cannot parse tag {part!r}")
            continue
        name, _, value = part.partition("=")
        pairs.append((name.strip().lower(), value.strip()))

    tags: dict[str, str] = {}
    for name, value in pairs:
        if name in tags:
            errors.append(f"tag {name}= appears more than once")
            continue
        tags[name] = value

    names = [name for name, _ in pairs]
    if not names or names[0] != "v" or tags.get("v", "").upper() != VERSION:
        errors.append(f"record does not begin with v={VERSION}")
        return DmarcRecord(raw=raw, tags=tags, errors=errors)

    if "p" not in tags:
        errors.append(
            "no p= tag; RFC 7489 requires a policy and receivers ignore a record without one"
        )
    elif len(names) > 1 and names[1] != "p":
        errors.append("p= must immediately follow v=; receivers ignore a record where it does not")
    elif tags["p"].lower() not in POLICIES:
        errors.append(
            f"unknown policy {tags['p']!r}; expected one of {', '.join(sorted(POLICIES))}"
        )

    if "sp" in tags and tags["sp"].lower() not in POLICIES:
        errors.append(f"unknown subdomain policy {tags['sp']!r}")

    if "pct" in tags:
        try:
            pct = int(tags["pct"])
        except ValueError:
            errors.append(f"pct={tags['pct']!r} is not a number")
        else:
            if not 0 <= pct <= 100:
                errors.append(f"pct={pct} is outside 0-100")

    for tag in ("adkim", "aspf"):
        if tag in tags and tags[tag].lower() not in ALIGNMENT:
            errors.append(f"{tag}={tags[tag]!r} is not 'r' or 's'")

    return DmarcRecord(raw=raw, tags=tags, errors=errors)
