"""The runtime testssl.sh wrapper for the four legacy-cipher checks (D20).

[ADR-016](../docs/02-decisions.md) chose to build our own TLS engine and keep
testssl.sh as a corpus-time cross-check only. This module is the per-check
reversal that decision explicitly reserved: "If the cross-check shows us
materially behind testssl.sh on the corpus after Tool 2 ships ... wrap it for
the checks we are losing and keep our own for the rest. That is a per-check
decision, not an all-or-nothing one."

RC4, 3DES and export-grade RSA/DH are compiled out of OpenSSL 3.5 - our own
engine's handshake attempts against them fail with "No cipher can be
selected", so it structurally cannot observe whether a server still offers
them. testssl.sh drives its own bundled OpenSSL build and can. We invoke it
**at runtime, for these four checks only, in Standard mode only** - so the
1-3 minute/host cost lands on deep scans, never on the free Light tier which
never reaches this module.

testssl.sh is GPLv2. It runs as a **subprocess only** - never imported, never
copied (ADR-003, constraint 4 in CLAUDE.md). This module shells out to the
pinned binary at `tools/bin/` and parses its JSON; nothing from its source is
in this tree.

Three backends, the same shape as every other protocol client in `core/`:

- `LiveTestsslClient` - the real subprocess, used by production Standard scans.
- `RecordingTestsslClient` - wraps it and freezes the raw testssl JSON to a
  fixture, via `core.replay.FixtureStore` (0b.3). Used only by the corpus
  generator, never by a scan.
- `ReplayTestsslClient` - reads a frozen fixture. The lab cannot serve legacy
  ciphers (same OpenSSL 3.5 limitation as our own engine), so the corpus is
  necessarily frozen recordings against public badssl.com weak endpoints
  rather than the local lab.

**Never crashes.** Binary missing, subprocess error, timeout, unparsable
JSON, or (on replay) nothing recorded - all of it becomes
`TestsslUnavailableError`, the one error type a scanner catches to emit
`inconclusive` rather than fail the scan. Same shape as
`core.context.OobUnavailableError` / `StubOobClient`.
"""

from __future__ import annotations

import contextlib
import ipaddress
import json
import os
import re
import shutil
import signal
import subprocess
import tempfile
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

from core.addresses import AddressPolicy, AddressRefusedError, AddressUnresolvedError
from core.authz import Scope
from core.cost import CostMeter
from core.killswitch import KillSwitch
from core.replay import (
    FixtureStore,
    MissingFixtureError,
    fixture_digest,
    fixture_filename,
    missing_fixture_message,
    sanitize_filename_part,
)

TESTSSL_VERSION = "3.2.4"
ROOT = Path(__file__).resolve().parents[1]
TESTSSL_PATH = ROOT / "tools" / "bin" / f"testssl.sh-{TESTSSL_VERSION}" / "testssl.sh"
"""Same pinned binary `tools/fetch-testssl.sh` installs and
`corpus/crosscheck/testssl.py` cross-checks against - one binary, two
callers. Not imported from there: `core/` never depends on `corpus/`."""

TESTSSL_ARGS: tuple[str, ...] = (
    "--rc4",
    "--sweet32",
    "--freak",
    "--logjam",
    "--ids-friendly",
    "--quiet",
    "--nodns=none",
    "--connect-timeout=10",
    "--openssl-timeout=10",
)
"""The declared argument allowlist (D56 and D59; ADR-023 amendments).

The four flags select exactly the four cipher-offer tests the checks read,
and nothing else. They replaced `--vulnerable`, which also runs Heartbleed,
CCS injection, Ticketbleed and ROBOT (testssl.sh itself labels these
offensive) and the renegotiation, CRIME, BREACH, POODLE, fallback-SCSV,
DROWN, Lucky13, Winshock and STARTTLS-injection tests. A run with **no**
test flag is worse still: testssl.sh treats it as "run everything".

`--ids-friendly` sets testssl.sh's `OFFENSIVE=false`, the switch behind its
Heartbleed, CCS-injection, Ticketbleed and ROBOT group. In 3.2.4 none of the
four selected tests reads it, so it changes nothing; it is kept as a second
line in case one ever does. `--quiet` drops the banner.

D59: `--nodns=none` stops testssl.sh doing any DNS of its own, and every run
also carries `--ip=<address>`, one IPv4 address our own resolver returned
for the in-scope name, so testssl.sh tests that address and nothing else
(the name stays the SNI). The two timeouts bound a hung connection.

The complete command line is
`TESTSSL_PATH, *TESTSSL_ARGS, "--ip=<IPv4>", "--jsonfile-pretty", <temp file>, host:port`,
and `guard_invocation` refuses anything else before the subprocess starts.

Some traffic runs regardless of the selection, and is accepted as passive in
the ADR-023 amendment (with `--nodns=none`, no DNS lookups any more); a bare
TCP connect and testssl.sh's connection- and protocol-detection handshakes
(TLS 1.3 hellos including pre-RFC draft versions, TLS 1.2 hellos, and, only
if those all fail, TLS 1.1/1.0/SSLv3 and SSLv2 hellos, plus up to seven
`openssl s_client` handshakes); one ordinary HTTPS `GET /` to identify the
service; and one large but well-formed ClientHello (129 cipher suites) that
detects an old-hardware size-limit bug. No flag disables any of it, and all
of it is well-formed handshakes or an ordinary request.
"""

CROSSCHECK_ARGS: tuple[str, ...] = ("--protocols", "--server-defaults", "--quiet")
"""The corpus cross-check's allowlist (`corpus/crosscheck/testssl.py`):
ordinary protocol and certificate handshakes, no vulnerability tests.
Declared here, beside the runtime list, so the guard can refuse any list
that is not declared."""

DECLARED_ARG_LISTS: frozenset[tuple[str, ...]] = frozenset({TESTSSL_ARGS, CROSSCHECK_ARGS})
"""Every argument list any caller may run testssl.sh with. `guard_invocation`
refuses an `allowed_args` that is not one of these, so a caller cannot widen
its own list by passing, say, `("--vulnerable",)`, or `()`, which testssl.sh
treats as "run everything"."""

TESTSSL_ENV_KEYS: tuple[str, ...] = ("PATH", "LANG")
"""The only environment variables the subprocess receives.

testssl.sh reads many of its settings from the environment, including
`OFFENSIVE=${OFFENSIVE:-true}`, so an inherited environment is an argument
list nobody declared."""

_TARGET = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?:[0-9]{1,5}")
"""An ASCII hostname (A-labels) or IPv4 address, then a port. Never starts
with `-`, so it cannot be read as a flag. IPv6 literals are refused: they
need brackets testssl.sh parses differently, and this wrapper never handled
them."""

DEFAULT_TIMEOUT_S = 220
"""1-3 minutes per address per the decision this module implements, plus headroom."""

MAX_ADDRESSES = 4
"""D59, decision A: every resolved IPv4 address is tested, up to this many.
Testing only the first would let a clean result on one address read as
clean for the host. Past the cap, the addresses not tested are named, and a
clean result is reported as `inconclusive`, never `clear`."""

TESTSSL_CONNECTION_BUDGET = 40
"""Connections one testssl.sh run is charged against the target's rate-limit
bucket before it starts (D59, decision D). The lab capture measured 23 for
3.2.4 against an ordinary server (`corpus/lab/testssl_capture_baseline.json`);
this is that plus margin. It is a budget, not a rate limit: pre-charging
bounds the average rate over the reserved window, not the burst inside
testssl.sh, which our limiter cannot pace. The capture fails loudly (exit 1,
"OVER BUDGET") on a count over this number and never records one, and
`tests/core/test_testssl_scope.py` fails when testssl.sh's version changes
until the capture is re-run. Neither raises the number."""

POLL_S = 0.5
"""How often a running testssl.sh is checked against the kill switch."""

TERMINATE_GRACE_S = 2.0
"""SIGTERM to the process group, then this long, then SIGKILL."""

# The four checks this module exists for, and the testssl.sh finding `id`
# each reads. Each is selected by its own flag in `TESTSSL_ARGS`.
CHECK_TO_TESTSSL_ID: dict[str, str] = {
    "tls-vuln-rc4": "RC4",
    "tls-vuln-sweet32": "SWEET32",
    "tls-vuln-freak": "FREAK",
    "tls-vuln-logjam": "LOGJAM",
}

_NOT_VULNERABLE = {"OK", "INFO"}
_SEVERITY_RANK = {"OK": 0, "INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


class TestsslUnavailableError(RuntimeError):
    """testssl.sh could not be run, or produced nothing usable.

    A scanner catching this must emit `inconclusive` with
    `no_verdict_reason="blocked_prerequisite"` - it must never crash, and it
    must never guess at whether a legacy cipher is offered.
    """


class TestsslArgumentRefusedError(TestsslUnavailableError):
    """The command line, environment, target or one of its addresses fell
    outside what may be tested, so testssl.sh was never started.

    A subclass of `TestsslUnavailableError` so a hostile or malformed target
    becomes the scanner's ordinary `inconclusive`, never a crash and never a
    probe.
    """


class TestsslNotPermittedError(TestsslUnavailableError):
    """The dedicated-address condition is unproven, so the four checks may not
    run (D59, decision B; ADR-023 and ADR-033 decision 8).

    testssl.sh's legacy-cipher tests can send SSLv2 hellos, which carry no
    SNI. On a shared address such a hello reaches whatever site the address
    serves by default, which may belong to a party who has not authorised
    us. Nothing today can show that an address is dedicated to the verified
    customer, so outside the lab nothing is resolved and nothing starts.
    """


@dataclass(frozen=True)
class LegacyCipherFinding:
    """One testssl.sh vulnerability verdict, already reduced to the worst
    severity when testssl reported the same `id` more than once (dh512's
    LOGJAM check does this: one verdict per DH-parameter source it tried)."""

    testssl_id: str
    severity: str
    detail: str
    cve: str | None

    @property
    def vulnerable(self) -> bool:
        return self.severity not in _NOT_VULNERABLE


@dataclass(frozen=True)
class LegacyCipherReport:
    host: str
    port: int
    recorded_at: datetime
    findings: dict[str, LegacyCipherFinding] = field(default_factory=dict)
    """The worst verdict per id across every address tested."""
    addresses_tested: tuple[str, ...] = ()
    addresses_untested: tuple[str, ...] = ()
    """Resolved but past `MAX_ADDRESSES`. Non-empty means a clean result
    covers only part of the host."""
    per_address: dict[str, dict[str, LegacyCipherFinding]] = field(default_factory=dict)
    lab_reason: str | None = None
    """The lab override's reason, when the run was made under one."""

    def for_check(self, check_id: str) -> LegacyCipherFinding | None:
        testssl_id = CHECK_TO_TESTSSL_ID.get(check_id)
        if testssl_id is None:
            return None
        return self.findings.get(testssl_id)

    def coverage(self, testssl_id: str) -> tuple[tuple[str, ...], tuple[str, ...]]:
        """(addresses that returned a verdict for this id, addresses that did not).

        An address whose run produced no verdict for the id (a testssl.sh
        fatal error, say) did not test it, so it counts as untested, as do
        the addresses past `MAX_ADDRESSES` (D59, decision A). A report with no
        per-address record returns its address lists as they are; one from
        before D59 has none, so nothing counts as tested and every clean
        check is `inconclusive`. That fails closed. Every fixture in the
        corpus was re-recorded with per-address verdicts."""
        if not self.per_address:
            return self.addresses_tested, self.addresses_untested
        tested = tuple(
            a for a in self.addresses_tested if testssl_id in self.per_address.get(a, {})
        )
        missed = tuple(a for a in self.addresses_tested if a not in tested)
        return tested, missed + self.addresses_untested


class TestsslClient(Protocol):
    def legacy_ciphers(self, host: str, port: int) -> LegacyCipherReport: ...


class StubTestsslClient:
    """The Phase-0-style default: no scan can reach testssl.sh unless a
    `ScanContext` is wired up with a client that can. Mirrors
    `core.context.StubOobClient`."""

    def legacy_ciphers(self, host: str, port: int) -> LegacyCipherReport:
        raise TestsslUnavailableError(
            "no testssl.sh client configured on this ScanContext; the legacy-cipher "
            "checks (tls-vuln-rc4/sweet32/freak/logjam) cannot run"
        )


def available() -> bool:
    return TESTSSL_PATH.exists() and shutil.which("bash") is not None


def _command(host: str, port: int, address: str, out: Path) -> list[str]:
    return [
        str(TESTSSL_PATH),
        *TESTSSL_ARGS,
        f"--ip={address}",
        "--jsonfile-pretty",
        str(out),
        f"{host}:{port}",
    ]


def _ipv4_literal(value: str) -> bool:
    try:
        ipaddress.IPv4Address(value)
    except ValueError:
        return False
    return True


def environment() -> dict[str, str]:
    """The pinned environment for any testssl.sh subprocess."""
    return {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LANG": "C"}


def guard_invocation(
    argv: list[str], env: dict[str, str], *, allowed_args: tuple[str, ...] = TESTSSL_ARGS
) -> None:
    """Refuse any command line or environment outside the declared allowlist.

    Exact, not a denylist: an added, missing, duplicated or reordered
    argument is refused, so a flag nobody has heard of yet is refused too.
    The environment must be exactly `PATH` (inherited, so testssl.sh can find
    bash and its tools) and `LANG=C`. Pinned by `tests/core/test_testssl.py`.

    `allowed_args` selects one of `DECLARED_ARG_LISTS`; anything else is
    refused. The default is the runtime wrapper's list.
    """
    if not isinstance(allowed_args, tuple) or allowed_args not in DECLARED_ARG_LISTS:
        raise TestsslArgumentRefusedError(
            f"testssl.sh argument list is not a declared one: {allowed_args!r}"
        )
    pinned = allowed_args == TESTSSL_ARGS
    head_len = 1 + len(allowed_args)
    head, rest = argv[:head_len], argv[head_len:]
    if pinned:
        # D59: the runtime wrapper always names the one address it tests.
        if not rest or not rest[0].startswith("--ip="):
            raise TestsslArgumentRefusedError(
                f"testssl.sh command line has no pinned address: {argv!r}"
            )
        if not _ipv4_literal(rest[0].removeprefix("--ip=")):
            raise TestsslArgumentRefusedError(
                f"testssl.sh address must be an IPv4 literal: {rest[0]!r}"
            )
        rest = rest[1:]
    if head != [str(TESTSSL_PATH), *allowed_args] or rest[:1] != ["--jsonfile-pretty"]:
        raise TestsslArgumentRefusedError(
            f"testssl.sh command line is outside the declared allowlist: {argv!r}"
        )
    rest = rest[1:]
    if len(rest) != 2:
        raise TestsslArgumentRefusedError(
            f"testssl.sh command line is outside the declared allowlist: {argv!r}"
        )
    out, target = rest
    if out.startswith("-") or not out.endswith(".json") or not os.path.isabs(out):
        raise TestsslArgumentRefusedError(f"testssl.sh output path refused: {out!r}")
    if not _TARGET.fullmatch(target) or not 1 <= int(target.rsplit(":", 1)[1]) <= 65535:
        raise TestsslArgumentRefusedError(f"testssl.sh target refused: {target!r}")
    if set(env) != set(TESTSSL_ENV_KEYS) or env.get("LANG") != "C":
        raise TestsslArgumentRefusedError(
            f"testssl.sh environment is outside the declared allowlist: {sorted(env)!r}"
        )


def _terminate(proc: subprocess.Popen[bytes]) -> None:
    """SIGTERM the whole process group, wait, then SIGKILL it.

    testssl.sh is a bash script that starts `openssl` and `timeout` children;
    killing only the script would leave them running. The group exists
    because the process was started with `start_new_session=True`."""
    try:
        with contextlib.suppress(ProcessLookupError, PermissionError):
            os.killpg(proc.pid, signal.SIGTERM)
        with contextlib.suppress(subprocess.TimeoutExpired):
            proc.wait(timeout=TERMINATE_GRACE_S)
    finally:  # even if interrupted during the grace period
        with contextlib.suppress(ProcessLookupError, PermissionError):
            os.killpg(proc.pid, signal.SIGKILL)
        proc.wait()


def _run_process(
    argv: list[str], env: dict[str, str], *, timeout_s: float, alive: Callable[[], None]
) -> None:
    """Run testssl.sh in its own process group, checking the kill switch.

    `alive` raises `ScanKilledError` when the scan has been killed; it is
    called every `POLL_S`. On a kill, a timeout or any other exception
    (Ctrl-C included) the whole group is torn down before the exception
    propagates. Stragglers are reaped after a normal exit too. A kill
    reaches the process within `POLL_S` plus `TERMINATE_GRACE_S` of being
    set in this process; across workers it needs the shared kill switch
    (Phase 6), which this loop reads the same way.
    """
    proc = subprocess.Popen(
        argv,
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    deadline = time.monotonic() + timeout_s
    try:
        while True:
            try:
                proc.wait(timeout=POLL_S)
                break
            except subprocess.TimeoutExpired:
                pass
            alive()
            if time.monotonic() > deadline:
                raise subprocess.TimeoutExpired(argv, timeout_s)
    except BaseException:
        _terminate(proc)
        raise
    with contextlib.suppress(ProcessLookupError, PermissionError):
        os.killpg(proc.pid, signal.SIGKILL)


def _run_one(
    host: str, port: int, address: str, *, timeout_s: float, alive: Callable[[], None]
) -> dict[str, Any]:
    """One guarded testssl.sh run against one pinned address; its full JSON."""
    if not available():
        raise TestsslUnavailableError(
            f"testssl.sh {TESTSSL_VERSION} is not installed at {TESTSSL_PATH}. "
            "Run tools/fetch-testssl.sh first."
        )

    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "out.json"
        argv = _command(host, port, address, out)
        env = environment()
        guard_invocation(argv, env)
        try:
            _run_process(argv, env, timeout_s=timeout_s, alive=alive)
        except subprocess.TimeoutExpired as exc:
            raise TestsslUnavailableError(
                f"testssl.sh against {host}:{port} ({address}) timed out after {timeout_s} s; "
                "its process group was stopped"
            ) from exc
        except OSError as exc:
            raise TestsslUnavailableError(
                f"testssl.sh against {host}:{port} ({address}) failed: {exc}"
            ) from exc

        if not out.exists():
            raise TestsslUnavailableError(
                f"testssl.sh against {host}:{port} ({address}) produced no output"
            )
        try:
            data: dict[str, Any] = json.loads(out.read_text())
            return data
        except json.JSONDecodeError as exc:
            raise TestsslUnavailableError(
                f"testssl.sh against {host}:{port} ({address}) produced unparsable JSON: {exc}"
            ) from exc


def _parse(report: dict[str, Any]) -> dict[str, LegacyCipherFinding]:
    """Flatten testssl's `scanResult` and keep the worst verdict per id we
    care about. Only `CHECK_TO_TESTSSL_ID`'s four ids are kept; anything else
    in the report (service, rDNS, scan metadata) is not a verdict these
    checks read."""
    wanted = set(CHECK_TO_TESTSSL_ID.values())
    best: dict[str, LegacyCipherFinding] = {}
    for block in report.get("scanResult") or []:
        for section in block.values():
            if not isinstance(section, list):
                continue
            for item in section:
                if not isinstance(item, dict):
                    continue
                testssl_id = item.get("id")
                if testssl_id not in wanted:
                    continue
                severity = str(item.get("severity", "OK")).upper()
                candidate = LegacyCipherFinding(
                    testssl_id=testssl_id,
                    severity=severity,
                    detail=str(item.get("finding", "")),
                    cve=item.get("cve") or None,
                )
                current = best.get(testssl_id)
                if current is None or _SEVERITY_RANK.get(severity, 0) > _SEVERITY_RANK.get(
                    current.severity, 0
                ):
                    best[testssl_id] = candidate
    return best


_HOST_LOCKS: dict[str, threading.Lock] = {}
_HOST_LOCKS_GUARD = threading.Lock()


def _host_lock(host: str) -> threading.Lock:
    with _HOST_LOCKS_GUARD:
        return _HOST_LOCKS.setdefault(host.lower().rstrip("."), threading.Lock())


def _worst(
    per_address: dict[str, dict[str, LegacyCipherFinding]],
) -> dict[str, LegacyCipherFinding]:
    worst: dict[str, LegacyCipherFinding] = {}
    for findings in per_address.values():
        for testssl_id, finding in findings.items():
            current = worst.get(testssl_id)
            if current is None or _SEVERITY_RANK.get(finding.severity, 0) > _SEVERITY_RANK.get(
                current.severity, 0
            ):
                worst[testssl_id] = finding
    return worst


@dataclass
class LiveTestsslClient:
    """Runs the real subprocess under the platform's controls (D59).

    `ScanContext` hands it the scan's DNS client, scope, kill switch, target
    rate limiter, cost meter and address policy, the same way it wires every
    other client. The policy carries a lab override only in the lab; without
    one the four checks do not run (`TestsslNotPermittedError`). Its addresses
    come from the platform's one address policy (D60, ADR-036), which
    superseded the local non-global rule D59 put here.
    """

    timeout_s: int = DEFAULT_TIMEOUT_S
    dns: Any = None
    scope: Scope | None = None
    addresses: AddressPolicy | None = None
    killswitch: KillSwitch | None = None
    ratelimit: Any = None
    cost: CostMeter | None = None
    scan_id: str = "local"
    org_id: str = "org_internal"

    def _alive(self) -> None:
        if self.killswitch is not None:
            self.killswitch.check(scan_id=self.scan_id, org_id=self.org_id)

    def _resolve_addresses(self, host: str) -> tuple[list[str], list[str]]:
        if self.scope is None or not self.scope.permits(host):
            raise TestsslArgumentRefusedError(
                f"{host} is outside the scope of this scan; testssl.sh was not started"
            )
        if self.dns is None:
            raise TestsslUnavailableError("no DNS client to resolve the target's addresses")
        self._alive()
        try:
            pinned = self._policy().pin(host, self.dns)
        except AddressRefusedError as exc:
            raise TestsslArgumentRefusedError(f"{exc}; testssl.sh was not started") from exc
        except AddressUnresolvedError as exc:
            raise TestsslUnavailableError(f"{exc}; testssl.sh was not started") from exc
        addresses = [a for a in pinned.addresses if _ipv4_literal(a)]
        if not addresses:
            raise TestsslArgumentRefusedError(
                f"{host} has no IPv4 address (no A record; it may be IPv6-only); "
                "testssl.sh is run against IPv4 addresses only"
            )
        return addresses[:MAX_ADDRESSES], addresses[MAX_ADDRESSES:]

    def _policy(self) -> AddressPolicy:
        return self.addresses if isinstance(self.addresses, AddressPolicy) else AddressPolicy()

    def legacy_ciphers(self, host: str, port: int) -> LegacyCipherReport:
        policy = self._policy()
        lab_reason = policy.lab_reason
        # Waived only for a target the lab override names (ADR-036 decision 10):
        # an override merely being present is not enough.
        if lab_reason is None or not policy.waives_dedicated_address(host):
            raise TestsslNotPermittedError(
                "not run: the dedicated-address condition is unproven. testssl.sh's "
                "legacy-cipher tests can send hellos with no SNI, which on a shared address "
                "reach a site that is not this customer's, and we cannot yet show that "
                f"{host}'s address serves only this customer (ADR-023, D59)"
            )
        tested, untested = self._resolve_addresses(host)
        per_address: dict[str, dict[str, LegacyCipherFinding]] = {}
        with _host_lock(host):
            for address in tested:
                if not available():
                    raise TestsslUnavailableError(
                        f"testssl.sh {TESTSSL_VERSION} is not installed at {TESTSSL_PATH}. "
                        "Run tools/fetch-testssl.sh first."
                    )
                self._alive()
                if self.ratelimit is not None:
                    # Can wait a long time; a kill set meanwhile must still stop the run.
                    self.ratelimit.acquire(host, float(TESTSSL_CONNECTION_BUDGET))
                self._alive()
                if self.cost is not None:
                    self.cost.record_request(TESTSSL_CONNECTION_BUDGET)
                raw = _run_one(host, port, address, timeout_s=self.timeout_s, alive=self._alive)
                per_address[address] = _parse(raw)
        return LegacyCipherReport(
            host=host,
            port=port,
            recorded_at=datetime.now(UTC),
            findings=_worst(per_address),
            addresses_tested=tuple(tested),
            addresses_untested=tuple(untested),
            per_address=per_address,
            lab_reason=lab_reason,
        )


def _fixture_name(host: str, port: int) -> str:
    key = f"{host}:{port}"
    stem = sanitize_filename_part(host)
    return fixture_filename(stem, str(port), digest=fixture_digest(key, length=10))


def _findings_to_dict(findings: dict[str, LegacyCipherFinding]) -> dict[str, Any]:
    return {
        testssl_id: {
            "testssl_id": f.testssl_id,
            "severity": f.severity,
            "detail": f.detail,
            "cve": f.cve,
        }
        for testssl_id, f in findings.items()
    }


def _findings_from_dict(data: dict[str, Any]) -> dict[str, LegacyCipherFinding]:
    return {
        testssl_id: LegacyCipherFinding(
            testssl_id=f["testssl_id"],
            severity=f["severity"],
            detail=f["detail"],
            cve=f.get("cve"),
        )
        for testssl_id, f in data.items()
    }


def _report_to_dict(report: LegacyCipherReport) -> dict[str, Any]:
    return {
        "host": report.host,
        "port": report.port,
        "recorded_at": report.recorded_at.isoformat(),
        "findings": _findings_to_dict(report.findings),
        "addresses_tested": list(report.addresses_tested),
        "addresses_untested": list(report.addresses_untested),
        "per_address": {a: _findings_to_dict(f) for a, f in report.per_address.items()},
        "lab_reason": report.lab_reason,
    }


def _report_from_dict(data: dict[str, Any]) -> LegacyCipherReport:
    return LegacyCipherReport(
        host=data["host"],
        port=data["port"],
        recorded_at=datetime.fromisoformat(data["recorded_at"]),
        findings=_findings_from_dict(data.get("findings", {})),
        addresses_tested=tuple(data.get("addresses_tested", ())),
        addresses_untested=tuple(data.get("addresses_untested", ())),
        per_address={a: _findings_from_dict(f) for a, f in data.get("per_address", {}).items()},
        lab_reason=data.get("lab_reason"),
    )


@dataclass
class RecordingTestsslClient:
    """Runs the real subprocess and freezes the result. Only the corpus
    generator uses this - never a scan."""

    directory: str | Path
    inner: LiveTestsslClient = field(default_factory=LiveTestsslClient)

    def __post_init__(self) -> None:
        self._store = FixtureStore(Path(self.directory))

    def legacy_ciphers(self, host: str, port: int) -> LegacyCipherReport:
        report = self.inner.legacy_ciphers(host, port)
        self._store.write(_fixture_name(host, port), _report_to_dict(report))
        return report


@dataclass
class ReplayTestsslClient:
    """Reads a frozen fixture. Used by the corpus and by tests - never
    reaches the network or the testssl.sh binary.

    A missing fixture becomes `TestsslUnavailableError`, the same error the
    live path raises when the binary is missing - one error type for a
    scanner to catch regardless of why testssl could not answer, matching
    every other protocol's `MissingFixtureError` convention but folded into
    this module's own error so `_check_legacy_ciphers` only ever needs to
    handle one exception.
    """

    directory: str | Path

    def __post_init__(self) -> None:
        self._store = FixtureStore(Path(self.directory))

    def legacy_ciphers(self, host: str, port: int) -> LegacyCipherReport:
        data = self._store.read(_fixture_name(host, port))
        if data is None:
            raise TestsslUnavailableError(
                missing_fixture_message(
                    kind="testssl report",
                    subject=f"{host}:{port}",
                    directory=self.directory,
                )
            )
        try:
            return _report_from_dict(data)
        except (KeyError, ValueError) as exc:
            raise TestsslUnavailableError(
                f"corrupt testssl fixture for {host}:{port}: {exc}"
            ) from exc


__all__ = [
    "CHECK_TO_TESTSSL_ID",
    "CROSSCHECK_ARGS",
    "DECLARED_ARG_LISTS",
    "MAX_ADDRESSES",
    "TESTSSL_ARGS",
    "TESTSSL_CONNECTION_BUDGET",
    "TESTSSL_ENV_KEYS",
    "TESTSSL_PATH",
    "TESTSSL_VERSION",
    "LegacyCipherFinding",
    "LegacyCipherReport",
    "LiveTestsslClient",
    "MissingFixtureError",
    "RecordingTestsslClient",
    "ReplayTestsslClient",
    "StubTestsslClient",
    "TestsslArgumentRefusedError",
    "TestsslClient",
    "TestsslNotPermittedError",
    "TestsslUnavailableError",
    "available",
    "environment",
    "guard_invocation",
]
