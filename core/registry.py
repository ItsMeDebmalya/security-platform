"""name -> scanner class lookup."""

from __future__ import annotations

from typing import Any

from core.scanner import SEMVER_RE, BaseScanner


class ScannerRegistry:
    def __init__(self) -> None:
        self._scanners: dict[str, type[BaseScanner]] = {}

    def register(self, scanner: type[BaseScanner]) -> type[BaseScanner]:
        """Register a scanner class. Usable as a decorator."""
        name = getattr(scanner, "name", "")
        if not name:
            raise ValueError(f"{scanner.__name__} must declare a name")
        if not SEMVER_RE.match(getattr(scanner, "version", "")):
            raise ValueError(f"{name} must declare a semver version, got {scanner.version!r}")
        if not scanner.supported_modes:
            raise ValueError(f"{name} must declare at least one supported mode")
        if not scanner.target_types:
            raise ValueError(f"{name} must declare at least one target type")
        if name in self._scanners:
            raise ValueError(f"{name} is already registered")
        self._scanners[name] = scanner
        return scanner

    def get(self, name: str) -> type[BaseScanner]:
        try:
            return self._scanners[name]
        except KeyError:
            available = ", ".join(sorted(self._scanners)) or "none"
            raise KeyError(f"no scanner named {name!r}; registered: {available}") from None

    def names(self) -> list[str]:
        return sorted(self._scanners)

    def describe(self) -> list[dict[str, Any]]:
        return [
            {
                "name": s.name,
                "version": s.version,
                "modes": sorted(s.supported_modes),
                "target_types": sorted(s.target_types),
            }
            for s in (self._scanners[n] for n in self.names())
        ]


registry = ScannerRegistry()
"""The process-wide registry. `scanners/<tool>/__init__.py` registers into it."""


def register(scanner: type[BaseScanner]) -> type[BaseScanner]:
    return registry.register(scanner)


def get_scanner(name: str) -> type[BaseScanner]:
    return registry.get(name)


def discover() -> ScannerRegistry:
    """Import every package under `scanners/` so its registration runs.

    Explicit and eager: a scanner that is only registered when something
    happens to import it is a scanner that silently disappears from `scan
    list`.
    """
    import importlib
    import pkgutil

    import scanners

    for module in pkgutil.iter_modules(scanners.__path__):
        if module.ispkg:
            importlib.import_module(f"scanners.{module.name}")
    return registry
