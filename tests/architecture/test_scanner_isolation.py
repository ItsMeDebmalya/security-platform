"""Architectural invariants, enforced by a test rather than by memory.

- A scanner never constructs its own HTTP or DNS client. Everything ambient
  comes from ScanContext, which is how rate limiting, scope enforcement and
  the kill switch stay guaranteed.
- A scanner never imports from another scanner. Shared logic moves to core/.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCANNERS = ROOT / "scanners"

FORBIDDEN_MODULES = {
    "httpx": "use ctx.http",
    "requests": "use ctx.http",
    "urllib.request": "use ctx.http",
    "http.client": "use ctx.http",
    "dns": "use ctx.dns",
    "dns.resolver": "use ctx.dns",
    "socket": "use ctx.http or ctx.dns",
    "aiohttp": "use ctx.http",
}


def _scanner_sources() -> list[Path]:
    return sorted(SCANNERS.rglob("*.py"))


def _imported_modules(tree: ast.AST) -> set[str]:
    modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            modules.add(node.module)
    return modules


@pytest.mark.parametrize("path", _scanner_sources(), ids=lambda p: str(p.relative_to(ROOT)))
def test_a_scanner_does_not_construct_its_own_clients(path):
    modules = _imported_modules(ast.parse(path.read_text()))

    offenders = {
        module: reason
        for module, reason in FORBIDDEN_MODULES.items()
        if module in modules or any(m.startswith(module + ".") for m in modules)
    }

    assert offenders == {}, (
        f"{path.relative_to(ROOT)} imports {sorted(offenders)} directly; "
        f"{'; '.join(offenders.values())}"
    )


@pytest.mark.parametrize("path", _scanner_sources(), ids=lambda p: str(p.relative_to(ROOT)))
def test_a_scanner_does_not_import_another_scanner(path):
    own_package = path.relative_to(SCANNERS).parts[0]
    modules = _imported_modules(ast.parse(path.read_text()))

    cross = [
        module
        for module in modules
        if module.startswith("scanners.") and module.split(".")[1] not in {own_package, ""}
    ]

    assert cross == [], (
        f"{path.relative_to(ROOT)} imports {cross}; shared logic moves to core/, "
        "a cross-scanner import is a refactor signal"
    )
