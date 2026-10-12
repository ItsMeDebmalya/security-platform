"""`BaseScanner` - the interface every tool implements.

Nothing else in the system knows or cares what a scanner does internally.
Because the interface is fixed, the CLI and the eventual scan worker are two
callers of one contract, and `scanners/` is identical in both worlds.
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from typing import ClassVar

from core.context import ScanContext
from core.models import Asset, Engagement, Mode, ScanResult, Vantage

SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+$")


class UnsupportedTargetError(ValueError):
    """This scanner cannot handle this kind of target."""


class UnsupportedModeError(ValueError):
    """This scanner does not implement this mode."""


class BaseScanner(ABC):
    name: ClassVar[str]
    version: ClassVar[str]
    supported_modes: ClassVar[frozenset[Mode]]
    target_types: ClassVar[frozenset[str]]
    vantage: ClassVar[Vantage | None] = None
    engagement: ClassVar[Engagement | None] = None
    """ADR-034: where this scanner observes from, and the nature of its interaction
    with the target. A scanner that emits findings declares both and passes them on
    every finding it creates; a contract test checks every registered scanner."""
    service_hosts: ClassVar[frozenset[str]] = frozenset()
    """Public third-party hosts this scanner talks to beyond the target
    itself (a CT log, an RDAP service). Additive and defaulted to empty so
    scanners that talk only to the target (email, tls) are unaffected;
    domscout is first to set it non-empty."""

    @classmethod
    def service_hosts_for(cls, target: Asset) -> frozenset[str]:
        """The service hosts for one target (ADR-031 clause 2): read-only public
        services, GET only, never the target. Defaults to the static
        `service_hosts`; domscout adds only the RDAP server for the target's TLD.
        Callers build a scan's HTTP scope from this, never from `service_hosts`."""
        return cls.service_hosts

    def validate(self, target: Asset, mode: Mode = "light") -> None:
        """Reject targets and modes this scanner cannot handle. Raises."""
        if target.type not in self.target_types:
            raise UnsupportedTargetError(
                f"{self.name} handles {sorted(self.target_types)}, not {target.type!r}"
            )
        if mode not in self.supported_modes:
            raise UnsupportedModeError(
                f"{self.name} supports {sorted(self.supported_modes)}, not {mode!r}"
            )

    def requires_authorisation(self, mode: Mode) -> bool | None:
        """Whether this scanner needs a valid authorisation record in `mode`.

        `None` (the default) means "no per-check declaration; the caller
        falls back to `core.authz`'s legacy mode-based rule" - light is
        assumed passive, standard/deep assumed active. That is the pre-0b.6
        behaviour, kept as the default so a scanner that has not migrated to
        a `Check` catalogue with `passive` declarations (the reference
        `example` scanner, today) is unaffected.

        A scanner with such a catalogue overrides this to answer from its
        own checks instead of trusting mode alone
        (docs/03-roadmap.md 0b.6, `core.authz.checks_require_authorisation`).
        Returning `None` here is not itself a declaration and must never be
        read as "passive" - see `AuthorisedScope.authorise`'s docstring.
        """
        return None

    @abstractmethod
    def run(self, target: Asset, mode: Mode, ctx: ScanContext) -> ScanResult:
        """Do the work.

        Must be cancellable via `ctx.check_alive()`, must emit progress via
        `ctx.progress()`, and must never construct its own clients.
        """
