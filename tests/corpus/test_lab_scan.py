"""The lab entry point (`corpus/lab/scan.py`, ADR-036 decision 10).

It lets the operator scan purpose-built lab boxes, which live on loopback or
private addresses that `scan run` refuses. It is a module under `corpus/`,
never a CLI flag. It reuses `scan run`'s own `_execute`, so the authorisation
check, the name scope, the kill switch, the rate limits, cost and redaction
are the customer path's. It relaxes the address policy only for addresses in
`corpus/lab/inventory.yaml`, and that inventory may never hold a production
address, network or name.
"""

from __future__ import annotations

import ast
import http.server
import json
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import pytest

from core.dns import DnsResponse
from corpus.lab import scan as lab

ROOT = Path(__file__).resolve().parents[2]


# --- the inventory -----------------------------------------------------------


def test_the_committed_inventory_holds_loopback_only_and_says_why_at_the_top() -> None:
    inventory = lab.load_inventory(lab.INVENTORY)
    assert inventory.entries == {"localhost": "127.0.0.1"}
    head = lab.INVENTORY.read_text().splitlines()[:12]
    assert any("never contain a production address, network or name" in line for line in head)


def _write(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "inventory.yaml"
    path.write_text(body)
    return path


@pytest.mark.parametrize(
    "body",
    ["- {name: localhost, address: 127.0.0.1}\n", "boxes:\n  - {name: localhost}\n", "boxes: 7\n"],
)
def test_an_inventory_of_the_wrong_shape_is_a_clear_error(tmp_path, body) -> None:
    with pytest.raises(ValueError, match="inventory"):
        lab.load_inventory(_write(tmp_path, body))


@pytest.mark.parametrize(
    ("body", "why"),
    [
        ("boxes:\n  - {name: web.lab.test, address: 93.184.215.14}\n", "global"),
        ("boxes:\n  - {name: web.lab.test, address: 10.0.0.5}\n", "lab network"),
        ("boxes:\n  - {name: web.lab.test, address: 169.254.169.254}\n", "lab network"),
        ("boxes:\n  - {name: intranet.corp.example.com, address: 127.0.0.2}\n", "reserved"),
        ("boxes:\n  - {name: erp.internal, address: 127.0.0.2}\n", "reserved"),
        (
            "boxes:\n  - {name: a.lab.test, address: 127.0.0.2}\n"
            "  - {name: a.lab.test, address: 127.0.0.3}\n",
            "twice",
        ),
    ],
)
def test_an_inventory_entry_outside_the_rules_is_refused(tmp_path, body, why) -> None:
    with pytest.raises(ValueError, match=why):
        lab.load_inventory(_write(tmp_path, body))


def test_the_inventory_override_names_exactly_its_boxes(tmp_path) -> None:
    inventory = lab.load_inventory(
        _write(tmp_path, "boxes:\n  - {name: localhost, address: 127.0.0.1}\n")
    )
    override = inventory.override()
    assert override.networks == ("127.0.0.1/32",)
    assert override.hosts == frozenset({"localhost", "127.0.0.1"})


# --- localhost resolves again, in the lab path only ----------------------------


class _Inner:
    def __init__(self) -> None:
        self.asked: list[tuple[str, str]] = []

    def resolve(self, name, rrtype, upstream):
        self.asked.append((name, rrtype))
        return DnsResponse(name, rrtype, "NXDOMAIN", [])


def test_the_lab_resolver_answers_inventory_names_and_passes_on_the_rest() -> None:
    inner = _Inner()
    resolver = lab.load_inventory(lab.INVENTORY).resolver(inner)

    assert resolver.resolve("localhost", "A", "1.1.1.1").records == ["127.0.0.1"]
    assert resolver.resolve("localhost", "AAAA", "1.1.1.1").rcode == "NODATA"
    assert inner.asked == []
    assert resolver.resolve("example.com", "A", "1.1.1.1").rcode == "NXDOMAIN"
    assert inner.asked == [("example.com", "A")]


# --- the entry point ---------------------------------------------------------


def test_a_target_not_in_the_inventory_is_refused_before_anything_runs(monkeypatch, capsys) -> None:
    def _never(**kwargs):
        raise AssertionError("_execute must not run for a target outside the inventory")

    monkeypatch.setattr(lab, "_execute", _never)
    code = lab.main(["web", "--target", "http://10.0.0.5/", "--target-type", "url"])
    assert code == 1
    assert "not in the lab inventory" in capsys.readouterr().out


@contextmanager
def _site() -> Iterator[tuple[int, list[str]]]:
    seen: list[str] = []

    class _Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            seen.append(self.headers.get("Host", ""))
            body = b"<html><body>lab</body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args) -> None:
            return None

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield server.server_address[1], seen
    finally:
        server.shutdown()
        server.server_close()


def test_the_lab_path_scans_a_box_on_loopback_by_name(capsys) -> None:
    with _site() as (port, seen):
        code = lab.main(
            [
                "web",
                "--target",
                f"http://localhost:{port}/",
                "--target-type",
                "url",
                "--format",
                "json",
            ]
        )
    assert code == 0
    result = json.loads(capsys.readouterr().out)
    assert result["outcome"] == "succeeded"
    assert seen and all(host == f"localhost:{port}" for host in seen)
    assert not any("non-global" in f["description"] for f in result["findings"])


def test_the_same_box_through_scan_run_is_still_refused() -> None:
    """The customer path is unchanged: loopback is refused, with no flag to relax it."""
    from cli.main import _execute
    from core.models import Asset

    with _site() as (port, seen):
        result = _execute(
            scanner_name="web",
            target=Asset(type="url", value=f"http://127.0.0.1:{port}/"),
            mode="light",
            record=None,
            replay=None,
            scope_file=ROOT / "config" / "authorised_scope.yaml",
        )
    assert seen == []
    assert result.findings
    assert all(f.state == "inconclusive" for f in result.findings)
    # The plain-HTTP fetches were refused and say so; an http:// target has no
    # HTTPS origin to fetch at all, which the https checks report separately.
    over_http = [f for f in result.findings if "https://" not in f.description]
    assert over_http
    assert all("non-global address" in f.description for f in over_http)


def test_the_authorisation_check_still_applies_in_the_lab_path(tmp_path, capsys) -> None:
    """An active check with no scope row is denied, lab or not."""
    empty = tmp_path / "scope.yaml"
    empty.write_text("[]\n")
    code = lab.main(
        ["example", "--target", "localhost", "--mode", "standard", "--scope-file", str(empty)]
    )
    assert code == 1
    assert "authorisation denied" in capsys.readouterr().out


# --- the two parameters the customer path never passes ------------------------

LAB_ONLY = {"address_policy", "wrap_resolver"}
SOURCE_DIRS = ("cli", "scanners", "core", "api", "web", "corpus", "tools")


def _lab_parameter_uses(rel: str, tree: ast.AST) -> list[str]:
    """Every way a module could hand `_execute` the lab parameters, or reach
    `_execute` other than by calling it directly: the keywords themselves, a
    keyword splat into a call to it, an alias or reference to it (a
    `functools.partial`, a variable), an import under another name, or a
    string naming it (`getattr`). Review of the lab entry point, round 1.

    Not chased (round 2): deliberate obfuscation, such as a name assembled
    from pieces or `exec` of a built string. `address_policy` is useless
    without a `LabOverride`, which the override walk bars, and `wrap_resolver`
    alone cannot reach a non-global address.

    If a future module legitimately needs a parameter called `address_policy`
    or `wrap_resolver`, rename it there; do not weaken this check."""
    uses = []
    direct = {
        id(node.func)
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and (getattr(node.func, "id", None) or getattr(node.func, "attr", None)) == "_execute"
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.keyword) and node.arg in LAB_ONLY and rel != "corpus/lab/scan.py":
            uses.append(f"{rel}:{node.value.lineno} keyword {node.arg}")
        elif isinstance(node, ast.Call) and id(node.func) in direct:
            if any(k.arg is None for k in node.keywords) and rel != "corpus/lab/scan.py":
                uses.append(f"{rel}:{node.lineno} keyword splat into _execute")
        elif isinstance(node, ast.Name | ast.Attribute):
            name = node.id if isinstance(node, ast.Name) else node.attr
            if name == "_execute" and id(node) not in direct and rel != "cli/main.py":
                uses.append(f"{rel}:{node.lineno} reference to _execute that is not a call")
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                if alias.name == "_execute" and alias.asname not in (None, "_execute"):
                    uses.append(f"{rel}:{node.lineno} _execute imported as {alias.asname}")
        elif isinstance(node, ast.Constant) and node.value == "_execute":
            uses.append(f"{rel}:{node.lineno} string naming _execute")
    return uses


def test_only_the_lab_entry_point_passes_the_lab_parameters_to_execute() -> None:
    """Condition 1: the design is safe only while `scan run` cannot reach these
    two parameters. Checked at the source, not only by behaviour."""
    offenders = []
    for top in SOURCE_DIRS:
        for path in (ROOT / top).rglob("*.py") if (ROOT / top).exists() else []:
            rel = path.relative_to(ROOT).as_posix()
            offenders += _lab_parameter_uses(rel, ast.parse(path.read_text()))
    assert offenders == []


@pytest.mark.parametrize(
    "source",
    [
        "from cli.main import _execute\nex = _execute\nex(address_policy=1)",
        "import functools\nfrom cli.main import _execute\n"
        "functools.partial(_execute, wrap_resolver=2)()",
        "import cli.main as main\ngetattr(main, '_execute')(address_policy=3)",
        "from cli.main import _execute as run\nrun(scanner_name='web')",
        "from cli.main import _execute\n_execute(**options)",
        "anything(wrap_resolver=f)",
    ],
)
def test_the_source_check_catches_indirect_routes(source) -> None:
    assert _lab_parameter_uses("cli/elsewhere.py", ast.parse(source))


def test_the_source_check_allows_the_lab_entry_point_its_one_call() -> None:
    source = (ROOT / "corpus" / "lab" / "scan.py").read_text()
    assert _lab_parameter_uses("corpus/lab/scan.py", ast.parse(source)) == []


def test_the_lab_parameters_are_keyword_only_and_default_to_none() -> None:
    tree = ast.parse((ROOT / "cli" / "main.py").read_text())
    [execute] = [
        n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "_execute"
    ]
    kwonly = {
        a.arg: d for a, d in zip(execute.args.kwonlyargs, execute.args.kw_defaults, strict=True)
    }
    for name in LAB_ONLY:
        assert name in kwonly
        default = kwonly[name]
        assert isinstance(default, ast.Constant) and default.value is None
    assert not execute.args.args and execute.args.vararg is None and execute.args.kwarg is None


def test_cli_never_imports_the_lab() -> None:
    for path in (ROOT / "cli").rglob("*.py"):
        for node in ast.walk(ast.parse(path.read_text())):
            if isinstance(node, ast.ImportFrom):
                assert not (node.module or "").startswith("corpus"), path
            if isinstance(node, ast.Import):
                assert not any(a.name.startswith("corpus") for a in node.names), path
