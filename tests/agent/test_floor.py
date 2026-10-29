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


_BUILTIN_GENERICS = {"list", "dict", "tuple", "set", "frozenset", "type"}


def runtime_syntax_problems(source):
    """3.9+ constructs that ast.parse(feature_version=(3, 6)) does not reject:
    subscripted builtin generics and `|` unions inside annotations."""
    tree = ast.parse(source)
    annotations = []
    for node in ast.walk(tree):
        if isinstance(node, ast.arg) and node.annotation is not None:
            annotations.append(node.annotation)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.returns:
            annotations.append(node.returns)
        elif isinstance(node, ast.AnnAssign):
            annotations.append(node.annotation)
    problems = []
    for annotation in annotations:
        for n in ast.walk(annotation):
            if (
                isinstance(n, ast.Subscript)
                and isinstance(n.value, ast.Name)
                and n.value.id in _BUILTIN_GENERICS
            ):
                problems.append("builtin generic " + n.value.id)
            if isinstance(n, ast.BinOp) and isinstance(n.op, ast.BitOr):
                problems.append("| between annotations")
    return problems


def test_detector_catches_the_constructs():
    assert runtime_syntax_problems("def f(x: list[str]): pass")
    assert runtime_syntax_problems("def f() -> dict[str, int]: pass")
    assert runtime_syntax_problems("def f(x: int | None): pass")
    assert runtime_syntax_problems("y: tuple[int, ...] = ()")
    assert not runtime_syntax_problems("from typing import List\ndef f(x: List[str]): pass")


@pytest.mark.parametrize("path", FILES, ids=lambda p: p.name)
def test_no_runtime_evaluated_39_plus_annotations(path):
    assert runtime_syntax_problems(path.read_text()) == []
