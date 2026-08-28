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
from core.models import Asset, Mode, ScanResult

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
