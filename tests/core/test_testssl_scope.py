"""D59: testssl.sh runs only where the platform's controls reach it.

- **Dedicated-address condition (ADR-023, D59 amendment).** testssl.sh can
  send hellos with no SNI. On a shared address those reach whatever site the
  address serves by default, which may belong to a party who has not
  authorised us. We cannot establish today that an address is dedicated, so
  outside the lab the four checks do not run at all: no lookup, no process.
- **Addresses.** Only IPv4 addresses our own resolver returned for the
  in-scope name, pinned with `--ip=`, and testssl.sh does no DNS of its own.
  At most `MAX_ADDRESSES`; the rest are named as untested. Non-global
  addresses (loopback, private, link-local, metadata) are refused unless a
  lab override says otherwise.
- **Kill switch.** The process group is polled and torn down.
- **Traffic budget.** Pre-charged on the target's rate-limit bucket. It bounds
  the average over the reserved window, not the burst inside testssl.sh.

Everything here is offline. The kill-switch tests use a stand-in shell script
in place of testssl.sh; it only sleeps.
"""

from __future__ import annotations

import ast
import json
import os
import subprocess
import threading
import time
from pathlib import Path

import pytest

from core.addresses import AddressPolicy, LabOverride
from core.authz import Scope
from core.context import ScanContext
from core.dns import DnsResponse
from core.killswitch import KillSwitch, ScanKilledError
from core.testssl import (
    MAX_ADDRESSES,
    TESTSSL_CONNECTION_BUDGET,
    TESTSSL_VERSION,
    LiveTestsslClient,
)
from core.testssl import TestsslArgumentRefusedError as RefusedError
from core.testssl import TestsslNotPermittedError as NotPermittedError

ROOT = Path(__file__).resolve().parents[2]
PUBLIC = ["93.184.215.14", "93.184.215.15", "93.184.215.16", "93.184.215.17", "93.184.215.18"]
"""Global unicast literals. Nothing in this file opens a socket to them."""


def _report(**severities: str) -> dict:
    items = [
        {"id": i, "severity": "OK", "finding": "not vulnerable"}
        for i in ("RC4", "SWEET32", "FREAK", "LOGJAM")
    ]
    for item in items:
        if item["id"] in severities:
            item["severity"] = severities[item["id"]]
            item["finding"] = "VULNERABLE"
    return {"scanResult": [{"vulnerabilities": items}]}


class FakeDns:
    def __init__(self, answers: dict[str, list[str]]) -> None:
        self.answers = answers
        self.queries: list[tuple[str, str]] = []

    def query(self, name: str, rrtype: str, *, resolver: str | None = None) -> DnsResponse:
        self.queries.append((name, rrtype))
        records = self.answers.get(name, []) if rrtype == "A" else []
        return DnsResponse(name, rrtype, "NOERROR" if records else "NODATA", list(records))


class FakeLimiter:
    def __init__(self) -> None:
        self.calls: list[tuple[str, float]] = []

    def acquire(self, host: str, tokens: float = 1.0) -> None:
        self.calls.append((host, tokens))


def lab(**kwargs) -> LabOverride:
    kwargs.setdefault("hosts", frozenset({"example.test", "localhost"}))
    return LabOverride(reason="unit test", **kwargs)


def client(answers=None, *, override=True, **kwargs) -> LiveTestsslClient:
    return LiveTestsslClient(
        dns=FakeDns(answers if answers is not None else {"example.test": PUBLIC[:1]}),
        scope=Scope(frozenset({"example.test"})),
        addresses=AddressPolicy(lab_override=lab()) if override else None,
        **kwargs,
    )


@pytest.fixture
def runs(monkeypatch) -> list[list[str]]:
    """Replace the process runner; every run reports clean unless told otherwise."""

    class _Calls(list):
        verdicts: dict[str, dict]

    calls = _Calls()
    calls.verdicts = verdicts = {}

    def _fake(argv, env, *, timeout_s, alive):
        calls.append(list(argv))
        address = next(a for a in argv if a.startswith("--ip=")).removeprefix("--ip=")
        out = next(a for a in argv if a.endswith(".json"))
        Path(out).write_text(json.dumps(verdicts.get(address, _report())))

    monkeypatch.setattr("core.testssl.available", lambda: True)
    monkeypatch.setattr("core.testssl._run_process", _fake)
    return calls


# --- the dedicated-address condition -----------------------------------------


def test_the_lab_override_is_off_by_default() -> None:
    assert LiveTestsslClient().addresses is None
    assert ScanContext(testssl=LiveTestsslClient()).addresses.lab_reason is None


def test_without_the_override_nothing_is_resolved_and_nothing_starts(runs) -> None:
    """B: the condition is unproven, so the four checks do not run. Not a
    lookup, not a process: the refusal comes before either."""
    c = client(override=False)
    with pytest.raises(NotPermittedError, match="dedicated"):
        c.legacy_ciphers("example.test", 443)
    assert runs == []
    assert c.dns.queries == []


def test_an_override_that_does_not_name_the_target_does_not_waive_the_condition(runs) -> None:
    """Lab entry point, condition 4: the waiver keys off the target, not off an
    override merely being present."""
    c = LiveTestsslClient(
        dns=FakeDns({"example.test": PUBLIC[:1]}),
        scope=Scope(frozenset({"example.test"})),
        addresses=AddressPolicy(lab_override=lab(hosts=frozenset({"localhost"}))),
    )
    with pytest.raises(NotPermittedError, match="dedicated"):
        c.legacy_ciphers("example.test", 443)
    assert runs == []
    assert c.dns.queries == []


def test_a_not_permitted_refusal_is_the_scanners_inconclusive_path() -> None:
    from core.testssl import TestsslUnavailableError

    assert issubclass(NotPermittedError, TestsslUnavailableError)


CUSTOMER_FACING = ("cli", "scanners", "core", "api", "web")
DEFINED_IN = ROOT / "core" / "addresses.py"
"""D60: the one override lives in the one address policy (ADR-036)."""


IMPORTERS = ("import_module", "__import__")
"""Import by string: allowed only as a direct call whose module path visibly
starts outside `corpus` (core's scanner discovery imports `scanners.*`)."""

LOADERS = ("run_module", "run_path", "spec_from_file_location", "spec_from_loader")
"""Code loading by path or module name: never needed on a customer path."""


def _imports_outside_corpus(call: ast.Call) -> bool:
    if not call.args or call.keywords:
        return False
    first = call.args[0]
    if isinstance(first, ast.JoinedStr) and first.values:
        first = first.values[0]
    if not (isinstance(first, ast.Constant) and isinstance(first.value, str)):
        return False  # dynamic: cannot be shown not to reach corpus/
    head = first.value.split(".", 1)[0]
    return head not in ("", "corpus")


def _docstrings(tree: ast.AST) -> set[int]:
    return {
        id(node.body[0].value)
        for node in ast.walk(tree)
        if isinstance(node, ast.Module | ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef)
        and node.body
        and isinstance(node.body[0], ast.Expr)
        and isinstance(node.body[0].value, ast.Constant)
    }


def _override_uses(tree: ast.AST) -> list[tuple[int, str]]:
    """Any way a module could reach a lab override:
    - the name (called, aliased or referenced), an attribute or `getattr`
      string naming it, a `lab_override=` keyword or assignment;
    - an `AddressPolicy` given any positional argument (round 2: the
      override can be passed positionally; it is keyword-only now too);
    - an import from `corpus`, which holds ready-made overrides, by statement,
      by string (`import_module`, `__import__`, aliased or not), by loader
      (`runpy`, `spec_from_file_location`), or a `corpus.` module path in any
      string (`sys.modules[...]`).
    Not chased: deliberate obfuscation such as `exec` of a built string;
    that is review's job, and a relaxed policy still needs an override."""
    uses = []
    direct = {id(n.func) for n in ast.walk(tree) if isinstance(n, ast.Call)}
    docstrings = _docstrings(tree)
    for node in ast.walk(tree):
        name = (
            node.id
            if isinstance(node, ast.Name)
            else node.attr
            if isinstance(node, ast.Attribute)
            else None
        )
        if name == "LabOverride":
            uses.append((node.lineno, "name"))  # type: ignore[attr-defined]
        elif isinstance(node, ast.Attribute) and node.attr == "lab_override":
            uses.append((node.lineno, "attribute lab_override"))
        elif name in IMPORTERS + LOADERS and id(node) not in direct:
            uses.append((node.lineno, f"reference to {name} that is not a call"))  # type: ignore[attr-defined]
        elif isinstance(node, ast.Constant) and node.value in ("LabOverride", "lab_override"):
            uses.append((node.lineno, f"string {node.value!r}"))
        elif (
            isinstance(node, ast.Constant)
            and isinstance(node.value, str)
            and id(node) not in docstrings
            and node.value.startswith("corpus.")
        ):
            uses.append((node.lineno, f"module path {node.value!r}"))
        elif isinstance(node, ast.keyword) and node.arg == "lab_override":
            uses.append((node.value.lineno, "keyword lab_override"))
        elif isinstance(node, ast.ImportFrom) and (node.module or "").split(".")[0] == "corpus":
            uses.append((node.lineno, f"import from {node.module}"))
        elif isinstance(node, ast.ImportFrom) and any(
            a.name in ("LabOverride", *IMPORTERS, *LOADERS) for a in node.names
        ):
            uses.append((node.lineno, "import of LabOverride or an importer"))
        elif isinstance(node, ast.Call):
            called = getattr(node.func, "id", None) or getattr(node.func, "attr", None)
            if called in IMPORTERS and not _imports_outside_corpus(node):
                uses.append((node.lineno, "import by string"))
            elif called in LOADERS:
                uses.append((node.lineno, f"code loaded by {called}"))
            elif called == "AddressPolicy" and node.args:
                uses.append((node.lineno, "AddressPolicy given a positional argument"))
        elif isinstance(node, ast.Import) and any(
            a.name.split(".")[0] == "corpus" for a in node.names
        ):
            uses.append((node.lineno, "import corpus"))
    return uses


def test_no_customer_facing_code_path_can_reach_the_lab_override() -> None:
    """C: the override exists for the lab and the corpus recordings only."""
    offenders = []
    for top in CUSTOMER_FACING:
        for path in (ROOT / top).rglob("*.py") if (ROOT / top).exists() else []:
            if path == DEFINED_IN:
                continue
            for line, how in _override_uses(ast.parse(path.read_text())):
                offenders.append(f"{path.relative_to(ROOT)}:{line} ({how})")
    assert offenders == []


@pytest.mark.parametrize(
    "source",
    [
        "from core.addresses import LabOverride as Lab\nLab('x')",
        "import core.addresses\ngetattr(core.addresses, 'LabOverride')('x')",
        "AddressPolicy(lab_override=object())",
        "ScanContext(addresses=AddressPolicy(lab_override=x))",
        "import core.testssl\ngetattr(core.testssl, 'LabOverride')('x')",
        "from corpus.generators.testssl import OVERRIDE",
        "HttpClient(scope=s, addresses=AddressPolicy(lab_override=o))",
        "client.lab_override = something",
        "import importlib\nimportlib.import_module('corpus.lab.scan')",
        "__import__('corpus.generators.testssl')",
        "import importlib\nimportlib.import_module(name)",
        # Review of the lab entry point, round 2: aliased and runpy routes.
        "from importlib import import_module as im\nim('corpus.lab.scan')",
        "import importlib\nim = importlib.import_module",
        "import runpy\nrunpy.run_module('corpus.lab.scan')",
        "import runpy\nrunpy.run_path(path)",
        "import importlib.util\nimportlib.util.spec_from_file_location('x', p)",
        "import sys\nsys.modules['corpus.lab.scan']",
        "AddressPolicy(override)",
    ],
)
def test_the_walk_catches_indirect_routes(source) -> None:
    assert _override_uses(ast.parse(source))


@pytest.mark.parametrize(
    "source",
    [
        "import importlib\nimportlib.import_module(f'scanners.{name}')",
        "import importlib\nimportlib.import_module('json')",
        "__import__('os')",
        "ROOT = Path('corpus')",
        '"""Reads corpus/fixtures, as the harness does."""',
    ],
)
def test_the_walk_does_not_flag_ordinary_code(source) -> None:
    assert _override_uses(ast.parse(source)) == []


def test_address_policy_takes_its_override_by_keyword_only() -> None:
    """Round 2: a positional override slipped past the `lab_override=` rule."""
    with pytest.raises(TypeError):
        AddressPolicy(lab())  # type: ignore[misc]


def test_anything_but_a_real_lab_override_is_not_permission(runs) -> None:
    from types import SimpleNamespace

    c = client(override=False)
    c.addresses = SimpleNamespace(  # type: ignore[assignment]
        lab_reason="x", lab_override=SimpleNamespace(reason="x", networks=("127.0.0.1/32",))
    )
    with pytest.raises(NotPermittedError):
        c.legacy_ciphers("example.test", 443)
    assert runs == []


# --- addresses ---------------------------------------------------------------


def test_only_addresses_our_resolver_returned_are_tested(runs) -> None:
    c = client({"example.test": PUBLIC[:2]})
    report = c.legacy_ciphers("example.test", 443)

    assert [next(a for a in argv if a.startswith("--ip=")) for argv in runs] == [
        f"--ip={PUBLIC[0]}",
        f"--ip={PUBLIC[1]}",
    ]
    assert all(argv[-1] == "example.test:443" for argv in runs)  # the name stays the SNI
    assert report.addresses_tested == tuple(PUBLIC[:2])
    assert report.addresses_untested == ()
    # D60: the one policy reads both families, so a non-global AAAA refuses
    # the name here too; testssl.sh is still run on the IPv4 addresses only.
    assert c.dns.queries == [("example.test", "A"), ("example.test", "AAAA")]


def test_testssl_does_no_dns_of_its_own(runs) -> None:
    client().legacy_ciphers("example.test", 443)
    (argv,) = runs
    assert "--nodns=none" in argv


def test_at_most_four_addresses_are_tested_and_the_rest_are_named(runs) -> None:
    assert MAX_ADDRESSES == 4
    report = client({"example.test": PUBLIC}).legacy_ciphers("example.test", 443)

    assert len(runs) == 4
    assert report.addresses_tested == tuple(PUBLIC[:4])
    assert report.addresses_untested == (PUBLIC[4],)


def test_the_worst_verdict_across_addresses_wins_and_each_is_kept(runs) -> None:
    runs.verdicts[PUBLIC[1]] = _report(RC4="HIGH")
    report = client({"example.test": PUBLIC[:2]}).legacy_ciphers("example.test", 443)

    assert report.findings["RC4"].severity == "HIGH"
    assert report.per_address[PUBLIC[0]]["RC4"].severity == "OK"
    assert report.per_address[PUBLIC[1]]["RC4"].severity == "HIGH"


def test_an_address_with_no_verdict_counts_as_untested_for_that_check(runs) -> None:
    """Decision A: a run that produced no verdict for an id (for example a
    testssl.sh fatal error written as a scan problem) did not test it."""
    runs.verdicts[PUBLIC[1]] = {"scanResult": [{"scanProblem": [{"id": "scanProblem"}]}]}
    report = client({"example.test": PUBLIC[:2]}).legacy_ciphers("example.test", 443)

    assert report.coverage("RC4") == ((PUBLIC[0],), (PUBLIC[1],))


def test_coverage_counts_addresses_past_the_cap_as_untested(runs) -> None:
    report = client({"example.test": PUBLIC}).legacy_ciphers("example.test", 443)
    assert report.coverage("RC4") == (tuple(PUBLIC[:4]), (PUBLIC[4],))


def test_a_name_with_no_ipv4_address_is_refused_honestly(runs) -> None:
    class _Ipv6Only(FakeDns):
        def query(self, name, rrtype, *, resolver=None):
            records = ["2606:4700::1"] if rrtype == "AAAA" else []
            return DnsResponse(name, rrtype, "NOERROR" if records else "NODATA", records)

    c = client()
    c.dns = _Ipv6Only({})
    with pytest.raises(RefusedError, match="IPv4"):
        c.legacy_ciphers("example.test", 443)
    assert runs == []


def test_a_name_with_no_address_at_all_says_so(runs) -> None:
    from core.testssl import TestsslUnavailableError

    with pytest.raises(TestsslUnavailableError, match="no A or AAAA"):
        client({"example.test": []}).legacy_ciphers("example.test", 443)
    assert runs == []


@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1",
        "10.0.0.5",
        "172.16.1.1",
        "192.168.1.1",
        "169.254.169.254",
        "100.64.0.1",
        "0.0.0.0",
        "192.0.2.10",
        "224.0.0.1",
        "255.255.255.255",
    ],
)
def test_a_non_global_address_is_refused_and_named(runs, address) -> None:
    with pytest.raises(RefusedError, match=address.replace(".", r"\.")):
        client({"example.test": [PUBLIC[0], address]}).legacy_ciphers("example.test", 443)
    assert runs == []


def test_the_lab_override_can_allow_a_non_global_address(runs) -> None:
    c = LiveTestsslClient(
        dns=FakeDns({"localhost": ["127.0.0.1"]}),
        scope=Scope(frozenset({"localhost"})),
        addresses=AddressPolicy(lab_override=lab(networks=("127.0.0.1/32",))),
    )
    report = c.legacy_ciphers("localhost", 8443)
    assert report.addresses_tested == ("127.0.0.1",)


def test_a_host_outside_the_scope_is_refused_before_any_lookup(runs) -> None:
    c = client()
    # Named by the override, so the scope check (not the waiver) is what refuses.
    c.addresses = AddressPolicy(lab_override=lab(hosts=frozenset({"elsewhere.test"})))
    with pytest.raises(RefusedError, match="scope"):
        c.legacy_ciphers("elsewhere.test", 443)
    assert c.dns.queries == [] and runs == []


def test_a_client_with_no_scope_refuses(runs) -> None:
    c = LiveTestsslClient(
        dns=FakeDns({"example.test": PUBLIC[:1]}), addresses=AddressPolicy(lab_override=lab())
    )
    with pytest.raises(RefusedError, match="scope"):
        c.legacy_ciphers("example.test", 443)


# --- traffic budget ----------------------------------------------------------


def test_each_address_pre_charges_the_declared_budget(runs) -> None:
    limiter = FakeLimiter()
    client({"example.test": PUBLIC[:2]}, ratelimit=limiter).legacy_ciphers("example.test", 443)
    assert limiter.calls == [("example.test", float(TESTSSL_CONNECTION_BUDGET))] * 2


def test_a_kill_during_the_budget_wait_starts_nothing(runs) -> None:
    killswitch = KillSwitch()

    class _KillWhileWaiting(FakeLimiter):
        def acquire(self, host, tokens=1.0):
            super().acquire(host, tokens)
            killswitch.kill(scan_id="s", reason="stop during the wait")

    c = client(ratelimit=_KillWhileWaiting(), killswitch=killswitch, scan_id="s", org_id="o")
    with pytest.raises(ScanKilledError):
        c.legacy_ciphers("example.test", 443)
    assert runs == []


def test_a_missing_binary_charges_no_budget(monkeypatch) -> None:
    from core.testssl import TestsslUnavailableError

    monkeypatch.setattr("core.testssl.available", lambda: False)
    limiter = FakeLimiter()
    with pytest.raises(TestsslUnavailableError, match="not installed"):
        client(ratelimit=limiter).legacy_ciphers("example.test", 443)
    assert limiter.calls == []


def test_a_lookup_failure_is_not_called_an_ipv6_only_name(runs) -> None:
    from core.testssl import TestsslUnavailableError

    class _Fails(FakeDns):
        def query(self, name, rrtype, *, resolver=None):
            return DnsResponse(name, rrtype, "SERVFAIL", [])

    c = client()
    c.dns = _Fails({})
    with pytest.raises(TestsslUnavailableError, match="SERVFAIL") as exc:
        c.legacy_ciphers("example.test", 443)
    assert not isinstance(exc.value, RefusedError)


def test_the_budget_is_pinned_to_the_lab_measurement() -> None:
    """D: the lab capture records the connections one run makes. A new
    testssl.sh version fails here until the capture is re-run. The capture
    itself fails loudly (exit 1, "OVER BUDGET") on a count over the budget and
    never writes one, so this check guards a hand-edited baseline."""
    baseline = json.loads((ROOT / "corpus" / "lab" / "testssl_capture_baseline.json").read_text())
    assert baseline["testssl_version"] == TESTSSL_VERSION, "re-run the lab capture"
    assert baseline["connections"] <= TESTSSL_CONNECTION_BUDGET, (
        f"testssl.sh made {baseline['connections']} connections, over the declared budget "
        f"of {TESTSSL_CONNECTION_BUDGET}; that needs a decision, not a bigger number"
    )


def test_runs_against_one_host_never_overlap(monkeypatch) -> None:
    active, overlaps = [0], [0]
    lock = threading.Lock()

    def _slow(argv, env, *, timeout_s, alive):
        with lock:
            active[0] += 1
            overlaps[0] = max(overlaps[0], active[0])
        time.sleep(0.1)
        Path(next(a for a in argv if a.endswith(".json"))).write_text(json.dumps(_report()))
        with lock:
            active[0] -= 1

    monkeypatch.setattr("core.testssl.available", lambda: True)
    monkeypatch.setattr("core.testssl._run_process", _slow)
    threads = [
        threading.Thread(target=client().legacy_ciphers, args=("example.test", 443))
        for _ in range(3)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert overlaps[0] == 1


# --- the scan context wires the client in ------------------------------------


def test_the_scan_context_hands_its_controls_to_the_client() -> None:
    dns, killswitch = FakeDns({}), KillSwitch()
    scope = Scope(frozenset({"example.test"}))
    live = LiveTestsslClient()
    ctx = ScanContext(
        scan_id="scan-1", org_id="org-1", dns=dns, scope=scope, killswitch=killswitch, testssl=live
    )  # type: ignore[arg-type]

    assert live.dns is dns
    assert live.scope is scope
    assert live.killswitch is killswitch
    assert live.ratelimit is ctx.ratelimit
    assert live.cost is ctx.cost
    assert (live.scan_id, live.org_id) == ("scan-1", "org-1")
    assert live.addresses is ctx.addresses
    assert ctx.addresses.lab_reason is None


# --- the kill switch reaches a running process -------------------------------


def _stand_in(tmp_path: Path, pids: Path) -> Path:
    """Sleeps, and starts a child that sleeps, recording both pids."""
    script = tmp_path / "testssl.sh"
    script.write_text(
        f"#!/usr/bin/env bash\nsleep 60 & echo $! >> {pids}\necho $$ >> {pids}\nwait\n"
    )
    script.chmod(0o755)
    return script


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    try:  # a zombie is gone for our purposes
        return Path(f"/proc/{pid}/stat").read_text().split()[2] != "Z"
    except FileNotFoundError:
        return False


def _wait_for_pids(pids: Path, n: int) -> list[int]:
    for _ in range(100):
        if pids.exists() and len(pids.read_text().split()) >= n:
            return [int(p) for p in pids.read_text().split()]
        time.sleep(0.05)
    raise AssertionError("stand-in never started")


def test_a_kill_reaches_the_whole_process_group_within_seconds(tmp_path, monkeypatch) -> None:
    pids = tmp_path / "pids"
    monkeypatch.setattr("core.testssl.TESTSSL_PATH", _stand_in(tmp_path, pids))
    killswitch = KillSwitch()
    c = client(killswitch=killswitch, scan_id="s", org_id="o")

    def _kill_soon() -> None:
        _wait_for_pids(pids, 2)
        killswitch.kill(scan_id="s", reason="operator stop")

    threading.Thread(target=_kill_soon).start()
    started = time.monotonic()
    with pytest.raises(ScanKilledError):
        c.legacy_ciphers("example.test", 443)
    elapsed = time.monotonic() - started

    procs = _wait_for_pids(pids, 2)
    assert not any(_alive(p) for p in procs), "a process outlived the kill"
    assert elapsed < 5.0


def test_a_timeout_tears_down_the_whole_group(tmp_path, monkeypatch) -> None:
    pids = tmp_path / "pids"
    monkeypatch.setattr("core.testssl.TESTSSL_PATH", _stand_in(tmp_path, pids))
    from core.testssl import TestsslUnavailableError

    with pytest.raises(TestsslUnavailableError, match="timed out"):
        client(timeout_s=1).legacy_ciphers("example.test", 443)
    assert not any(_alive(p) for p in _wait_for_pids(pids, 2))


def test_the_process_gets_no_terminal_and_its_own_group(monkeypatch, tmp_path) -> None:
    from core import testssl

    seen: dict = {}

    class _Proc:
        pid = 999999

        def wait(self, timeout=None):
            return 0

    def _popen(argv, **kwargs):
        seen.update(kwargs)
        return _Proc()

    monkeypatch.setattr("core.testssl.subprocess.Popen", _popen)
    monkeypatch.setattr("core.testssl.os.killpg", lambda *a: None)
    testssl._run_process(["x"], {}, timeout_s=1, alive=lambda: None)
    assert seen["stdin"] is subprocess.DEVNULL
    assert seen["start_new_session"] is True
