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

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import urlsplit

import yaml

from core.models import Asset, Mode

ACTIVE_MODES = frozenset({"standard", "deep"})


class DeclaresPassivity(Protocol):
    """What `checks_require_authorisation` needs from a check.

    Matches the shape `scanners/*/checks.py`'s `Check` dataclass already
    has, without this module importing any scanner (core never imports a
    scanner - `docs/06-guidelines.md`). Declared as read-only properties
    rather than plain attributes so a frozen dataclass with extra fields
    (severity, likelihood_ratio, ...) satisfies this structurally under
    mypy's strict Protocol variance rules.
    """

    @property
    def passive(self) -> bool: ...

    @property
    def mode(self) -> str: ...


def checks_require_authorisation(checks: Iterable[DeclaresPassivity], *, mode: Mode) -> bool:
    """True if any check that would run in `mode` is declared active.

    This is the mechanism docs/03-roadmap.md 0b.6 asks for: "the gate should
    enforce a declaration, not trust the author's filing." `passive` has no
    default on `Check` (see `scanners/email/checks.py`,
    `scanners/tls/checks.py`), so every entry in a catalogue this is called
    with states it explicitly - there is no undeclared check for this
    function to read as passive. A scanner's `Check` catalogue is the single
    place the declaration lives; this function only asks it a question.
    """
    for check in checks:
        if mode == "light" and check.mode != "light":
            continue  # would not run in this mode - see the `if self.mode !=
            # "light"` gating in scanners/{email,tls}/scanner.py
        if not check.passive:
            return True
    return False


def host_of(target: Asset) -> str:
    """The host an authorisation is really about.

    A target arrives in whatever form someone typed - a bare domain, a URL, a
    host:port. All three name the same asset, and an authorisation record is
    about the asset. Comparing raw strings meant authorising `example.com` and
    then being denied a scan of `https://example.com`, which nobody would guess
    they had to authorise separately.
    """
    value = target.value.strip()
    if "://" in value:
        value = urlsplit(value).hostname or value
    elif ":" in value and not value.startswith("["):
        head, _, port = value.rpartition(":")
        if port.isdigit():
            value = head
    return value.lower().rstrip(".")


def port_of(target: Asset) -> int | None:
    """The port a target names explicitly, or None if it names the whole host.

    A record naming a port names a *service*: Juice Shop on :3000 and VAmPI on
    :5000 share a host and are not the same asset. A record with no port is
    about the host, and covers whatever runs on it - which is the right reading
    for a domain you own, and the only one anybody would maintain correctly.
    """
    value = target.value.strip()
    if "://" in value:
        return urlsplit(value).port
    if ":" in value and not value.startswith("["):
        _, _, port = value.rpartition(":")
        if port.isdigit():
            return int(port)
    return None


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
        # A url target and a domain record can name the same host, so the host
        # is compared rather than the declared type.
        own_asset = Asset(type="domain", value=self.target_value)
        own_port = port_of(own_asset)
        if own_port is not None and port_of(target) != own_port:
            # This record is about one service, not the whole host.
            return False

        value = host_of(target)
        own = host_of(own_asset)
        if value == own:
            return True
        return self.wildcard and value.endswith("." + own)

    def authz_ref(self, target: Asset) -> str:
        return f"allowlist:{self.authz_id}#{host_of(target)}"


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

    def authorise(
        self,
        target: Asset,
        *,
        mode: Mode,
        passive: bool | None = None,
        today: date | None = None,
    ) -> AuthzDecision:
        """Decide whether this scan may proceed. Deny by default.

        `passive` is the 0b.6 declaration - computed by
        `checks_require_authorisation` from a scanner's own `Check`
        catalogue and passed in as `not requires_authorisation`. It governs
        regardless of `mode`, including `light`, which is what closes the
        gap this task exists to close: a check makes one HTTP request to a
        target's admin panel is active whatever mode label it runs under.

        `passive=None` is the legacy path, kept only for a scanner (like the
        reference `example` scanner) that has not migrated to per-check
        declarations - it falls back to the old mode-based rule, unchanged.
        `passive=None` must never be confused with `passive=False`: the
        first means "this caller has no opinion, fall back"; the second
        means "this caller looked at its checks and at least one is active",
        which requires a record even in `light` mode. Neither value ever
        widens what light mode was already allowed to do.
        """
        if passive is True:
            return AuthzDecision(
                True,
                None,
                "every check that would run is declared passive (docs/03-roadmap.md 0b.6)",
            )
        if passive is None and mode not in ACTIVE_MODES:
            return AuthzDecision(True, None, "light mode is passive and needs no authorisation")

        today = today or date.today()
        matches = [r for r in self._records if r.covers(target)]
        if not matches:
            return AuthzDecision(
                False, None, f"no authorisation record for {host_of(target)} in {self.source}"
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

    def require(
        self,
        target: Asset,
        *,
        mode: Mode,
        passive: bool | None = None,
        today: date | None = None,
    ) -> str | None:
        """Authorise or raise. Returns the `authz_ref` to record on the ScanRun."""
        decision = self.authorise(target, mode=mode, passive=passive, today=today)
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
        return cls(frozenset({host_of(target)}))

    def permits(self, host: str) -> bool:
        host = host.lower().rstrip(".")
        return any(host == h or host.endswith("." + h) for h in self.hosts)
