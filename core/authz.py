"""Authorisation and scope enforcement. Deny by default.

Two related jobs live here:

- **The ownership gate.** Standard and Deep mode require a valid, unexpired,
  unrevoked authorisation record for the target. Light mode is passive and
  needs none. This is a legal requirement (docs/09-ownership-verification.md),
  enforced from the first Standard-mode check rather than from Phase 6.
- **Outbound request scope.** Every request the HTTP client makes is checked
  against the scope of the scan. Redirects that leave scope are not followed,
  and an SSRF probe never targets a third party.

Until Phase 6 the records come from `config/authorised_scope.yaml`; after it,
from the database. The interface does not change.

A note on DNS: scope covers requests we send *to a target*. Passive DNS
lookups resolve names through a public resolver rather than touching the
target, and legitimately follow chains onto third-party names - an SPF
`include:` chain is exactly that. `core/dns.py` therefore enforces the
resolver it may talk to, not the names it may ask about.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import yaml

from core.models import Asset, Mode

ACTIVE_MODES = frozenset({"standard", "deep"})


class AuthorisationDeniedError(PermissionError):
    """Raised when an active scan has no valid authorisation for its target."""


@dataclass(frozen=True)
class AuthzDecision:
    allowed: bool
    authz_ref: str | None
    reason: str


@dataclass(frozen=True)
class AuthorisationRecord:
    authz_id: str
    org_id: str
    target_type: str
    target_value: str
    wildcard: bool
    method: str
    expires_at: date
    evidence_file: str
    revoked_at: date | None = None
    revocation_reason: str | None = None

    def covers(self, target: Asset) -> bool:
        if target.type != self.target_type:
            return False
        value = target.value.lower().rstrip(".")
        own = self.target_value.lower().rstrip(".")
        if value == own:
            return True
        return self.wildcard and value.endswith("." + own)

    def authz_ref(self, target: Asset) -> str:
        return f"allowlist:{self.authz_id}#{target.value}"


def _record_from_row(row: dict[str, Any], source: Path) -> AuthorisationRecord:
    try:
        target = row["target"]
        proof = row["proof"]
        evidence_file = proof["evidence_file"]
    except KeyError as exc:
        raise ValueError(
            f"{source}: authorisation row {row.get('authz_id', '?')} is missing {exc}. "
            "A row asserting verification without its proof is not verification."
        ) from None
    if not evidence_file:
        raise ValueError(
            f"{source}: authorisation row {row['authz_id']} has an empty evidence_file"
        )
    return AuthorisationRecord(
        authz_id=row["authz_id"],
        org_id=row["org_id"],
        target_type=target["type"],
        target_value=target["value"],
        wildcard=bool(target.get("wildcard", False)),
        method=row["method"],
        expires_at=_as_date(row["expires_at"]),
        evidence_file=evidence_file,
        revoked_at=_as_date(row["revoked_at"]) if row.get("revoked_at") else None,
        revocation_reason=row.get("revocation_reason"),
    )


def _as_date(value: object) -> date:
    if isinstance(value, date):
        return value
    return date.fromisoformat(str(value)[:10])


class AuthorisedScope:
    """The interim allowlist from docs/09-ownership-verification.md."""

    def __init__(self, records: list[AuthorisationRecord], source: Path | None = None) -> None:
        self._records = records
        self.source = source

    @classmethod
    def load(cls, path: str | Path) -> AuthorisedScope:
        """Read the allowlist. A missing file means an empty allowlist, not an open door."""
        path = Path(path)
        if not path.exists():
            return cls([], path)
        rows = yaml.safe_load(path.read_text()) or []
        return cls([_record_from_row(row, path) for row in rows], path)

    def authorise(self, target: Asset, *, mode: Mode, today: date | None = None) -> AuthzDecision:
        if mode not in ACTIVE_MODES:
            return AuthzDecision(True, None, "light mode is passive and needs no authorisation")

        today = today or date.today()
        matches = [r for r in self._records if r.covers(target)]
        if not matches:
            return AuthzDecision(
                False, None, f"no authorisation record for {target.value} in {self.source}"
            )
        for record in matches:
            if record.revoked_at is not None:
                return AuthzDecision(
                    False,
                    None,
                    f"authorisation {record.authz_id} was revoked on {record.revoked_at}",
                )
            if record.expires_at < today:
                return AuthzDecision(
                    False, None, f"authorisation {record.authz_id} expired on {record.expires_at}"
                )
            return AuthzDecision(True, record.authz_ref(target), "verified")
        raise AssertionError("unreachable")

    def require(self, target: Asset, *, mode: Mode, today: date | None = None) -> str | None:
        """Authorise or raise. Returns the `authz_ref` to record on the ScanRun."""
        decision = self.authorise(target, mode=mode, today=today)
        if not decision.allowed:
            raise AuthorisationDeniedError(decision.reason)
        return decision.authz_ref


@dataclass(frozen=True)
class Scope:
    """The hosts a scan may send requests to."""

    hosts: frozenset[str]

    @classmethod
    def for_target(cls, target: Asset) -> Scope:
        """The host this scan may talk to.

        The scheme decides, not the declared target type: a URL pasted into a
        `--target-type domain` field is the common case, not an edge one, and
        trusting the declaration put the literal string "https://example.com"
        into the scope and then refused the connection to example.com.
        """
        value = target.value
        if "://" in value:
            value = urlsplit(value).hostname or value
        elif ":" in value and not value.startswith("["):
            host, _, port = value.rpartition(":")
            if port.isdigit():
                value = host
        return cls(frozenset({value.lower().rstrip(".")}))

    def permits(self, host: str) -> bool:
        host = host.lower().rstrip(".")
        return any(host == h or host.endswith("." + h) for h in self.hosts)
