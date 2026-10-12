"""D59: how the tls scanner reports the four testssl.sh checks when they
cannot or may not run, and when only some addresses were tested.

A refusal is an honest `inconclusive` that says why, never "install
testssl.sh" when the binary is not the problem, and never a `clear`.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from core.authz import Scope
from core.context import ScanContext
from core.models import Asset
from core.testssl import LegacyCipherFinding, LegacyCipherReport
from core.testssl import TestsslArgumentRefusedError as RefusedError
from core.testssl import TestsslNotPermittedError as NotPermittedError
from core.testssl import TestsslUnavailableError as UnavailableError
from core.tls import TlsClient
from corpus.generators.tls_lab import lab_server
from scanners.tls import TlsScanner

LEGACY = ("tls-vuln-rc4", "tls-vuln-sweet32", "tls-vuln-freak", "tls-vuln-logjam")


class _Raises:
    def __init__(self, exc: Exception) -> None:
        self.exc = exc

    def legacy_ciphers(self, host, port):
        raise self.exc


class _Returns:
    def __init__(self, report: LegacyCipherReport) -> None:
        self.report = report

    def legacy_ciphers(self, host, port):
        return self.report


def _scan(testssl):
    with lab_server(common_name="localhost", sans=["localhost"]) as srv:
        ctx = ScanContext(tls=TlsClient(scope=Scope(frozenset({"localhost"}))), testssl=testssl)
        return TlsScanner().run(
            Asset(type="url", value=f"https://localhost:{srv.port}"), "standard", ctx
        )


def _legacy(result):
    return {f.check_id: f for f in result.findings if f.check_id in LEGACY}


def _outcomes(result):
    return {c.check_id: c.outcome for c in result.telemetry.checks_run if c.check_id in LEGACY}


def test_the_dedicated_address_refusal_is_inconclusive_and_says_why():
    result = _scan(_Raises(NotPermittedError("dedicated-address condition unproven")))

    found = _legacy(result)
    assert set(found) == set(LEGACY)
    for f in found.values():
        assert f.state == "inconclusive"
        assert f.no_verdict_reason == "blocked_prerequisite"
        assert "dedicated" in f.description
        assert "Install testssl.sh" not in f.remediation
    assert set(_outcomes(result).values()) == {"inconclusive"}


def test_a_refused_target_says_why_and_not_install_testssl():
    result = _scan(_Raises(RefusedError("169.254.169.254 is not a global address")))

    for f in _legacy(result).values():
        assert f.state == "inconclusive"
        assert "169.254.169.254" in f.description
        assert "Install testssl.sh" not in f.remediation


def test_a_missing_binary_still_says_install():
    result = _scan(_Raises(UnavailableError("testssl.sh is not installed")))
    for f in _legacy(result).values():
        assert "Install testssl.sh" in f.remediation


def _report(per_address, untested=()):
    worst = {}
    for findings in per_address.values():
        for tid, f in findings.items():
            if tid not in worst or (f.vulnerable and not worst[tid].vulnerable):
                worst[tid] = f
    return LegacyCipherReport(
        host="localhost",
        port=443,
        recorded_at=datetime.now(UTC),
        findings=worst,
        addresses_tested=tuple(per_address),
        addresses_untested=tuple(untested),
        per_address=per_address,
    )


def _ok(tid):
    return LegacyCipherFinding(tid, "OK", "not vulnerable", None)


ALL_OK = {tid: _ok(tid) for tid in ("RC4", "SWEET32", "FREAK", "LOGJAM")}


def test_clean_on_every_address_is_clear():
    result = _scan(_Returns(_report({"93.184.215.14": ALL_OK})))
    assert _legacy(result) == {}
    assert set(_outcomes(result).values()) == {"clear"}


def test_clean_on_four_of_six_addresses_is_not_clear_and_names_them():
    """A: a silent truncation would be a coverage claim we can't support."""
    tested = {f"93.184.215.{i}": ALL_OK for i in range(1, 5)}
    result = _scan(_Returns(_report(tested, untested=("93.184.215.5", "93.184.215.6"))))

    found = _legacy(result)
    assert set(found) == set(LEGACY)
    for f in found.values():
        assert f.state == "inconclusive"
        for address in (*tested, "93.184.215.5", "93.184.215.6"):
            assert address in f.description
    assert set(_outcomes(result).values()) == {"inconclusive"}


@pytest.mark.parametrize("untested", [(), ("93.184.215.9",)])
def test_a_vulnerable_address_is_reported_with_every_addresss_verdict(untested):
    vulnerable = dict(ALL_OK, RC4=LegacyCipherFinding("RC4", "HIGH", "VULNERABLE", "CVE-2013-2566"))
    per = {"93.184.215.1": ALL_OK, "93.184.215.2": vulnerable}
    result = _scan(_Returns(_report(per, untested=untested)))

    rc4 = _legacy(result)["tls-vuln-rc4"]
    assert rc4.state != "inconclusive"
    data = rc4.evidence[0].data
    assert data["per_address"] == {"93.184.215.1": "OK", "93.184.215.2": "HIGH"}
    assert data["addresses_untested"] == list(untested)
    if untested:
        assert "93.184.215.9" in rc4.description
