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

import json
import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

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
)
"""The declared argument allowlist (D56; ADR-023 amendment, clause 2).

The four flags select exactly the four cipher-offer tests the checks read,
and nothing else. They replaced `--vulnerable`, which also runs Heartbleed,
CCS injection, Ticketbleed and ROBOT (testssl.sh itself labels these
offensive) and the renegotiation, CRIME, BREACH, POODLE, fallback-SCSV,
DROWN, Lucky13, Winshock and STARTTLS-injection tests. A run with **no**
test flag is worse still: testssl.sh treats it as "run everything".

`--ids-friendly` sets testssl.sh's `OFFENSIVE=false`, the switch behind its
Heartbleed, CCS-injection, Ticketbleed and ROBOT group. In 3.2.4 none of the
four selected tests reads it, so it changes nothing; it is kept as a second
line in case one ever does. `--quiet` drops the banner. The complete command line is
`TESTSSL_PATH, *TESTSSL_ARGS, "--jsonfile-pretty", <temp file>, host:port`,
and `guard_invocation` refuses anything else before the subprocess starts.

Some traffic runs regardless of the selection, and is accepted as passive in
the ADR-023 amendment: a reverse-DNS lookup (to DNS, not the target); a bare
TCP connect and testssl.sh's connection- and protocol-detection handshakes
(TLS 1.3 hellos including pre-RFC draft versions, TLS 1.2 hellos, and, only
if those all fail, TLS 1.1/1.0/SSLv3 and SSLv2 hellos, plus up to seven
`openssl s_client` handshakes); one ordinary HTTPS `GET /` to identify the
service; and one large but well-formed ClientHello (129 cipher suites) that
detects an old-hardware size-limit bug. No flag disables any of it, and all
of it is well-formed handshakes or an ordinary request.
"""

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
"""1-3 minutes/host per the decision this module implements, plus headroom."""

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
    """The command line or environment fell outside the declared allowlist,
    so testssl.sh was never started.

    A subclass of `TestsslUnavailableError` so a hostile or malformed target
    becomes the scanner's ordinary `inconclusive`, never a crash and never a
    probe.
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

    def for_check(self, check_id: str) -> LegacyCipherFinding | None:
        testssl_id = CHECK_TO_TESTSSL_ID.get(check_id)
        if testssl_id is None:
            return None
        return self.findings.get(testssl_id)


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


def _command(host: str, port: int, out: Path) -> list[str]:
    return [str(TESTSSL_PATH), *TESTSSL_ARGS, "--jsonfile-pretty", str(out), f"{host}:{port}"]


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

    `allowed_args` lets another caller of the same binary declare its own
    exact list (`corpus/crosscheck/testssl.py`); the default is this
    module's.
    """
    expected_head = [str(TESTSSL_PATH), *allowed_args, "--jsonfile-pretty"]
    head, rest = argv[: len(expected_head)], argv[len(expected_head) :]
    if head != expected_head or len(rest) != 2:
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


def _run_raw(host: str, port: int, *, timeout_s: int) -> dict[str, Any]:
    """Run testssl.sh's four cipher-offer tests and return its full JSON report.

    Exactly `TESTSSL_ARGS`, checked by `guard_invocation` before the
    subprocess starts (D56). `--jsonfile-pretty` to a temp file and no
    severity filter: dropping `OK` findings would drop exactly the negative
    evidence a control case needs.
    """
    if not available():
        raise TestsslUnavailableError(
            f"testssl.sh {TESTSSL_VERSION} is not installed at {TESTSSL_PATH}. "
            "Run tools/fetch-testssl.sh first."
        )

    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "out.json"
        argv = _command(host, port, out)
        env = environment()
        guard_invocation(argv, env)
        try:
            subprocess.run(
                argv,
                env=env,
                capture_output=True,
                timeout=timeout_s,
                check=False,
            )
        except (subprocess.TimeoutExpired, OSError) as exc:
            raise TestsslUnavailableError(
                f"testssl.sh against {host}:{port} failed: {exc}"
            ) from exc

        if not out.exists():
            raise TestsslUnavailableError(f"testssl.sh against {host}:{port} produced no output")
        try:
            data: dict[str, Any] = json.loads(out.read_text())
            return data
        except json.JSONDecodeError as exc:
            raise TestsslUnavailableError(
                f"testssl.sh against {host}:{port} produced unparsable JSON: {exc}"
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


@dataclass
class LiveTestsslClient:
    """Runs the real subprocess. This is what a production Standard scan uses."""

    timeout_s: int = DEFAULT_TIMEOUT_S

    def legacy_ciphers(self, host: str, port: int) -> LegacyCipherReport:
        report = _run_raw(host, port, timeout_s=self.timeout_s)
        return LegacyCipherReport(
            host=host,
            port=port,
            recorded_at=datetime.now(UTC),
            findings=_parse(report),
        )


def _fixture_name(host: str, port: int) -> str:
    key = f"{host}:{port}"
    stem = sanitize_filename_part(host)
    return fixture_filename(stem, str(port), digest=fixture_digest(key, length=10))


def _report_to_dict(report: LegacyCipherReport) -> dict[str, Any]:
    return {
        "host": report.host,
        "port": report.port,
        "recorded_at": report.recorded_at.isoformat(),
        "findings": {
            testssl_id: {
                "testssl_id": f.testssl_id,
                "severity": f.severity,
                "detail": f.detail,
                "cve": f.cve,
            }
            for testssl_id, f in report.findings.items()
        },
    }


def _report_from_dict(data: dict[str, Any]) -> LegacyCipherReport:
    return LegacyCipherReport(
        host=data["host"],
        port=data["port"],
        recorded_at=datetime.fromisoformat(data["recorded_at"]),
        findings={
            testssl_id: LegacyCipherFinding(
                testssl_id=f["testssl_id"],
                severity=f["severity"],
                detail=f["detail"],
                cve=f.get("cve"),
            )
            for testssl_id, f in data.get("findings", {}).items()
        },
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
    "TESTSSL_ARGS",
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
    "TestsslUnavailableError",
    "available",
    "environment",
    "guard_invocation",
]
