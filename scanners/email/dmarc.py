"""DMARC parsing, per RFC 7489.

A DMARC record is a tag-value list, and the ordering rules matter: `v` must be
first and `p` must immediately follow it.

What a receiver does with a broken record is a separate question, and RFC 7489
answers it only for some errors. `receiver_handling` records which answer
applies, so a finding says what the spec says and no more:

- `ignored` - `v` is not first or not `DMARC1`: "the entire retrieved record
  MUST be ignored" (section 6.3).
- `no_processing` / `treat_as_none` - no valid `p`, or an invalid `sp`.
  Section 6.6.3 step 6: with a syntactically valid `rua` the receiver SHOULD act
  as if the record said `p=none`; without one it applies no DMARC processing.
- `discard_tag` - a malformed tag after `v` and `p`. Section 6.3: such errors
  "SHOULD be discarded in favor of default values (if any) or ignored outright".
  The record still counts.
- `undefined` - a duplicated tag, or `p` not immediately after `v`. Both are
  forbidden (duplicates through DKIM's tag-list rule, RFC 6376 section 3.2,
  which section 6.3 adopts), but no spec says what a receiver then does.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

VERSION = "DMARC1"
POLICIES = frozenset({"none", "quarantine", "reject"})
ALIGNMENT = frozenset({"r", "s"})
KNOWN_TAGS = frozenset({"v", "p", "sp", "pct", "rua", "ruf", "adkim", "aspf", "fo", "rf", "ri"})
# A DMARC URI (RFC 7489 section 6.4): a URI, optionally followed by "!" and a size limit.
_DMARC_URI = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:[^\s!,;]+(![0-9]+[kmgt]?)?$")


@dataclass(frozen=True)
class DmarcRecord:
    raw: str
    tags: dict[str, str] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    receiver_handling: str | None = None

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
            "receiver_handling": self.receiver_handling,
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
    duplicated = False
    for name, value in pairs:
        if name in tags:
            errors.append(f"tag {name}= appears more than once")
            duplicated = True
            continue
        tags[name] = value

    names = [name for name, _ in pairs]
    if not names or names[0] != "v" or tags.get("v", "").upper() != VERSION:
        errors.append(f"record does not begin with v={VERSION}")
        return DmarcRecord(raw=raw, tags=tags, errors=errors, receiver_handling="ignored")

    policy_usable = True
    misordered = False
    if "p" not in tags:
        errors.append("no p= tag; RFC 7489 requires a policy")
        policy_usable = False
    elif tags["p"].lower() not in POLICIES:
        errors.append(
            f"unknown policy {tags['p']!r}; expected one of {', '.join(sorted(POLICIES))}"
        )
        policy_usable = False
    elif len(names) > 1 and names[1] != "p":
        errors.append("p= must immediately follow v=")
        misordered = True

    if "sp" in tags and tags["sp"].lower() not in POLICIES:
        errors.append(f"unknown subdomain policy {tags['sp']!r}")
        policy_usable = False

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

    handling: str | None = None
    if not policy_usable:
        handling = "treat_as_none" if _has_valid_rua(tags) else "no_processing"
    elif duplicated or misordered:
        handling = "undefined"
    elif errors:
        handling = "discard_tag"
    return DmarcRecord(raw=raw, tags=tags, errors=errors, receiver_handling=handling)


def _has_valid_rua(tags: dict[str, str]) -> bool:
    """RFC 7489 6.6.3 step 6: 'at least one syntactically valid reporting URI'."""
    return any(_DMARC_URI.match(uri.strip()) for uri in tags.get("rua", "").split(","))
