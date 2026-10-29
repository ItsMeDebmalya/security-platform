"""B2b: the entry shim parses under 2.7 syntax and reports an unsupported runtime."""

import ast
import json
import re
import subprocess
import sys
from pathlib import Path

from agent import snapshot, version

ROOT = Path(__file__).resolve().parents[2]
SHIM = ROOT / "agent" / "__main__.py"
VERSION_PY = ROOT / "agent" / "version.py"


def _py27_violations(path):
    src = path.read_text()
    tree = ast.parse(src, feature_version=(3, 4))
    bad = []
    for n in ast.walk(tree):
        if isinstance(
            n,
            (
                ast.AnnAssign,
                ast.JoinedStr,
                ast.AsyncFunctionDef,
                ast.Await,
                ast.Nonlocal,
                ast.YieldFrom,
                ast.MatMult,
            ),
        ):
            bad.append(type(n).__name__)
        if isinstance(n, ast.FunctionDef) and n.returns is not None:
            bad.append("return annotation")
        if isinstance(n, ast.arg) and n.annotation is not None:
            bad.append("annotation")
        if isinstance(n, ast.arguments) and (n.kwonlyargs or n.kw_defaults):
            bad.append("keyword-only")
        if isinstance(n, ast.Starred):
            bad.append("starred")
        if isinstance(n, ast.Raise) and n.cause:
            bad.append("raise from")
    if re.search(r"\bf[\"']", src):
        bad.append("f-string literal")
    return bad


def test_shim_and_version_parse_as_27_dialect():
    assert _py27_violations(SHIM) == []
    assert _py27_violations(VERSION_PY) == []


def _run(*args, **kw):
    return subprocess.run(
        [sys.executable, "-m", "agent", *args],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        **kw,
    )


def test_unsupported_interpreter_writes_valid_snapshot(tmp_path):
    out = tmp_path / "s.json"
    proc = _run("--output", str(out), "--simulate-version", "2.7.5")
    assert proc.returncode != 0 or out.exists()
    snap = json.loads(out.read_text())
    assert snapshot.verify(snap)
    assert snap["snapshot_version"] == version.SNAPSHOT_VERSION
    assert snap["schema"] == version.SCHEMA
    assert snap["sections"] == {}
    assert [m["section"] for m in snap["manifest"]] == list(version.SECTIONS)
    for m in snap["manifest"]:
        assert (m["status"], m["reason"]) == ("unavailable", "unsupported_runtime")
    assert snap["runtime"]["found"] == "2.7.5"
    assert snap["runtime"]["required"] == "3.6"
    assert "executable" in snap["runtime"] and "searched" in snap["runtime"]
    c = snap["counts"]
    assert c["commands_run"] == 0 and c["sections_unavailable"] == len(version.SECTIONS)
    assert "requests" not in c
    assert snap["receipt"]["interpreter"]["found"] == "2.7.5"
    assert snap["host"]["hostname"]


def test_non_linux_writes_no_snapshot_and_exits_nonzero(tmp_path):
    out = tmp_path / "s.json"
    proc = _run("--output", str(out), "--simulate-platform", "win32")
    assert proc.returncode != 0
    assert not out.exists()
    assert "linux" in proc.stderr.lower()


def test_supported_runtime_on_linux_does_not_report_unsupported(tmp_path):
    out = tmp_path / "s.json"
    proc = _run("--output", str(out))
    # the real collector arrives in a later task; the shim must not claim unsupported
    assert not out.exists() or "runtime" not in json.loads(out.read_text())
    assert "unsupported_runtime" not in proc.stdout
