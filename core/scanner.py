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

    @abstractmethod
    def run(self, target: Asset, mode: Mode, ctx: ScanContext) -> ScanResult:
        """Do the work.

        Must be cancellable via `ctx.check_alive()`, must emit progress via
        `ctx.progress()`, and must never construct its own clients.
        """
