"""DMARC parsing, per RFC 9989 (May 2026), with RFC 7489's differences kept visible.

RFC 9989 obsoletes RFC 7489 (ledger D44). It is the primary reading here.
Receivers implementing either will be in service for some time, so where the
two disagree the record carries both, and a finding states both (the dual
reading, ADR-017).

What a receiver does with a broken record, by `receiver_handling`:

- `ignored`: `v` is not first or not exactly `DMARC1` (case-sensitive). "The
  entire record MUST be ignored" (RFC 7489 section 6.3, RFC 9989 section 4.7).
- `no_processing` / `treat_as_none`: an invalid `p`, `sp` or `np` value (RFC
  9989 section 4.10.1, MUST; RFC 7489 section 6.6.3 step 6, SHOULD). With a
  syntactically valid `rua` the receiver acts as if the record said `p=none`;
  without one it applies no DMARC processing. RFC 7489 does not know `np`, so an
  invalid `np` is `np_invalid_only`: a 9989-only problem.
- `discard_tag`: a malformed tag. Both RFCs discard it in favour of its default
  ("MUST" in RFC 9989 section 4.8, "SHOULD" in RFC 7489 section 6.3). The
  record still counts.
- `undefined`: a duplicated tag. DKIM's tag-list rule (RFC 6376 section 3.2,
  adopted by both RFCs) makes the tag list invalid, but neither says what a
  receiver then does.

No longer errors under RFC 9989, recorded instead:

- an absent `p`: treated as `p=none` (section 4.7). `p_absent` keeps it visible,
  because RFC 7489 applied no DMARC processing to such a record.
- `p` not straight after `v`: the order is free (section 4.8). It is a
  `legacy_issue`, because RFC 7489 required it.
- `pct`, `rf`, `ri` and report size limits: removed (Appendix C). Listed in
  `obsolete_tags`.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

VERSION = "DMARC1"
POLICIES = frozenset({"none", "quarantine", "reject"})
ALIGNMENT = frozenset({"r", "s"})
KNOWN_TAGS = frozenset(
    {"v", "p", "sp", "np", "psd", "t", "rua", "ruf", "adkim", "aspf", "fo", "pct", "rf", "ri"}
)
PSD_VALUES = frozenset({"y", "n", "u"})
TEST_VALUES = frozenset({"y", "n"})
# A DMARC URI (RFC 7489 section 6.4): a URI, optionally followed by "!" and a size limit.
_DMARC_URI = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:[^\s!,;]+(![0-9]+[kmgt]?)?$")


@dataclass(frozen=True)
class DmarcRecord:
    raw: str
    tags: dict[str, str] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    receiver_handling: str | None = None
    legacy_issues: list[str] = field(default_factory=list)
    """Valid under RFC 9989, but not under RFC 7489."""
    np_invalid_only: bool = False

    @property
    def valid(self) -> bool:
        return not self.errors

    @property
    def usable(self) -> bool:
        """Whether receivers apply the record: valid, or only a malformed tag discarded."""
        return self.receiver_handling in (None, "discard_tag")

    @property
    def p_absent(self) -> bool:
        return "p" not in self.tags

    @property
    def policy(self) -> str | None:
        """RFC 9989 4.7: an absent p is treated as p=none."""
        if self.p_absent:
            return "none"
        value = self.tags.get("p")
        return value.lower() if value else None

    @property
    def np(self) -> str | None:
        value = self.tags.get("np")
        return value.lower() if value else None

    @property
    def testing(self) -> bool:
        """RFC 9989 4.7: t=y asks receivers to apply one level below the policy."""
        return self.tags.get("t", "n").lower() == "y"

    @property
    def psd(self) -> str:
        return self.tags.get("psd", "u").lower()

    @property
    def obsolete_tags(self) -> list[str]:
        """Tags RFC 9989 removed (Appendix C.4, C.5.2), in a fixed order."""
        found: list[str] = [tag for tag in ("pct", "rf", "ri") if tag in self.tags]
        uris = self.rua + self.ruf
        if any("!" in uri for uri in uris):
            found.append("rua size limit" if any("!" in u for u in self.rua) else "ruf size limit")
        return found

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
        """RFC 7489: pct defaults to 100, and a malformed one is discarded for it (6.3)."""
        try:
            pct = int(self.tags.get("pct", "100"))
        except ValueError:
            return 100
        return pct if 0 <= pct <= 100 else 100

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
            "legacy_issues": list(self.legacy_issues),
            "obsolete_tags": self.obsolete_tags,
            "p_absent": self.p_absent,
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
    # Case-sensitive (D45): RFC 7489 6.3 "MUST match precisely", RFC 9989 4.7
    # "the tag value is case sensitive". 'v=dmarc1' is a record receivers ignore.
    if not names or names[0] != "v" or tags.get("v", "") != VERSION:
        found = tags.get("v")
        errors.append(
            f"the version is {found!r}, not exactly {VERSION!r}"
            if found is not None and names and names[0] == "v"
            else f"record does not begin with v={VERSION}"
        )
        return DmarcRecord(raw=raw, tags=tags, errors=errors, receiver_handling="ignored")

    policy_usable = True
    np_invalid = False
    legacy: list[str] = []
    if "p" in tags and tags["p"].lower() not in POLICIES:
        errors.append(
            f"unknown policy {tags['p']!r}; expected one of {', '.join(sorted(POLICIES))}"
        )
        policy_usable = False
    elif "p" in tags and len(names) > 1 and names[1] != "p":
        legacy.append("p= is not the tag straight after v= (RFC 7489 required it)")
    formats = [f.strip().lower() for f in tags.get("rf", "").split(":") if f.strip()]
    if any(f != "afrf" for f in formats):
        # RFC 7489 6.3: "a Mail Receiver observing a different value SHOULD
        # ignore it or MAY ignore the entire DMARC record" (review S6).
        legacy.append(
            f"rf={tags['rf']} asks for a report format other than afrf, and RFC 7489 lets a "
            "receiver ignore the entire record for that"
        )

    if "sp" in tags and tags["sp"].lower() not in POLICIES:
        errors.append(f"unknown subdomain policy {tags['sp']!r}")
        policy_usable = False
    if "np" in tags and tags["np"].lower() not in POLICIES:
        errors.append(f"unknown non-existent-subdomain policy {tags['np']!r}")
        np_invalid = policy_usable
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
    if "t" in tags and tags["t"].lower() not in TEST_VALUES:
        errors.append(f"t={tags['t']!r} is not 'y' or 'n'")
    if "psd" in tags and tags["psd"].lower() not in PSD_VALUES:
        errors.append(f"psd={tags['psd']!r} is not 'y', 'n' or 'u'")

    handling: str | None = None
    if not policy_usable:
        handling = "treat_as_none" if has_valid_rua(tags) else "no_processing"
    elif duplicated:
        handling = "undefined"
    elif errors:
        handling = "discard_tag"
    return DmarcRecord(
        raw=raw,
        tags=tags,
        errors=errors,
        receiver_handling=handling,
        legacy_issues=legacy,
        np_invalid_only=np_invalid and not duplicated,
    )


def has_valid_rua(tags: dict[str, str]) -> bool:
    """'At least one syntactically valid reporting URI' (RFC 9989 4.10.1, RFC 7489 6.6.3)."""
    return any(_DMARC_URI.match(uri.strip()) for uri in tags.get("rua", "").split(","))
