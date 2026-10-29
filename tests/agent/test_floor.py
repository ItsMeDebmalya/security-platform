"""B2: the 3.6 floor and the stdlib-only rule, over every file in agent/."""

import ast
import sys
from pathlib import Path

import pytest

from agent import version

ROOT = Path(__file__).resolve().parents[2]
FILES = sorted((ROOT / "agent").rglob("*.py"))


def test_there_are_agent_files():
    assert FILES


def test_floor_is_one_constant():
    assert version.FLOOR == (3, 6)
    hits = [p.name for p in FILES if "(3, 6)" in p.read_text() and p.name != "version.py"]
    assert hits == []


@pytest.mark.parametrize("path", FILES, ids=lambda p: p.name)
def test_parses_at_the_floor(path):
    ast.parse(path.read_text(), filename=str(path), feature_version=version.FLOOR)


def _imports(tree):
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                yield a.name, 0
        elif isinstance(node, ast.ImportFrom):
            yield node.module or "", node.level


@pytest.mark.parametrize("path", FILES, ids=lambda p: p.name)
def test_stdlib_only(path):
    stdlib = set(sys.stdlib_module_names)
    for module, level in _imports(ast.parse(path.read_text())):
        top = module.split(".")[0]
        if level:
            continue
        assert top in stdlib or top in ("agent", "version", "snapshot", "redact"), (
            path.name,
            module,
        )
        assert top not in ("core", "contracts", "scanners", "cli"), (path.name, module)
