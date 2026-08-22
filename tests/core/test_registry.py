"""Scanner registration: name -> class, with no import-order surprises."""

from __future__ import annotations

import pytest

from core.registry import ScannerRegistry
from core.scanner import BaseScanner


class _Dummy(BaseScanner):
    name = "dummy"
    version = "1.0.0"
    supported_modes = frozenset({"light"})
    target_types = frozenset({"domain"})

    def run(self, target, mode, ctx):  # pragma: no cover - not exercised here
        raise NotImplementedError


def test_a_registered_scanner_is_retrievable_by_name():
    registry = ScannerRegistry()
    registry.register(_Dummy)

    assert registry.get("dummy") is _Dummy


def test_registering_two_scanners_under_one_name_is_rejected():
    registry = ScannerRegistry()
    registry.register(_Dummy)

    with pytest.raises(ValueError, match="already registered"):
        registry.register(_Dummy)


def test_an_unknown_scanner_name_names_what_is_available():
    registry = ScannerRegistry()
    registry.register(_Dummy)

    with pytest.raises(KeyError, match="dummy"):
        registry.get("nope")


def test_listing_scanners_reports_versions_and_modes():
    registry = ScannerRegistry()
    registry.register(_Dummy)

    assert registry.describe() == [
        {
            "name": "dummy",
            "version": "1.0.0",
            "modes": ["light"],
            "target_types": ["domain"],
        }
    ]


def test_a_scanner_with_a_non_semver_version_cannot_register():
    class Bad(_Dummy):
        name = "bad"
        version = "1.0"

    with pytest.raises(ValueError, match="semver"):
        ScannerRegistry().register(Bad)


def test_a_scanner_declaring_no_modes_cannot_register():
    class Bad(_Dummy):
        name = "bad"
        supported_modes = frozenset()

    with pytest.raises(ValueError, match="mode"):
        ScannerRegistry().register(Bad)
