"""D20: the runtime testssl.sh wrapper for the four legacy-cipher checks.

Everything here runs offline. `LiveTestsslClient` (the real subprocess) is
exercised only by `corpus/generators/testssl.py`, deliberately run by hand
against public badssl.com endpoints - never by the test suite.
"""

from __future__ import annotations

import subprocess

import pytest

from core.testssl import (
    CHECK_TO_TESTSSL_ID,
    LegacyCipherReport,
    LiveTestsslClient,
    RecordingTestsslClient,
    ReplayTestsslClient,
    StubTestsslClient,
    _parse,
)
from core.testssl import TestsslUnavailableError as UnavailableError

RC4_REPORT = {
    "scanResult": [
        {
            "vulnerabilities": [
                {
                    "id": "RC4",
                    "severity": "HIGH",
                    "cve": "CVE-2013-2566 CVE-2015-2808",
                    "finding": "VULNERABLE, Detected ciphers: ECDHE-RSA-RC4-SHA RC4-SHA",
                },
                {"id": "SWEET32", "severity": "OK", "finding": "not vulnerable"},
                {"id": "FREAK", "severity": "OK", "finding": "not vulnerable"},
                {"id": "LOGJAM", "severity": "OK", "finding": "not vulnerable"},
                {"id": "BEAST", "severity": "OK", "finding": "not vulnerable"},
            ]
        }
    ]
}

CLEAN_REPORT = {
    "scanResult": [
        {
            "vulnerabilities": [
                {"id": "RC4", "severity": "OK", "finding": "not vulnerable"},
                {"id": "SWEET32", "severity": "OK", "finding": "not vulnerable"},
                {"id": "FREAK", "severity": "OK", "finding": "not vulnerable"},
                {"id": "LOGJAM", "severity": "OK", "finding": "not vulnerable"},
            ]
        }
    ]
}

DUPLICATE_LOGJAM_REPORT = {
    "scanResult": [
        {
            "vulnerabilities": [
                {"id": "LOGJAM", "severity": "OK", "finding": "not vulnerable, no DH EXPORT"},
                {
                    "id": "LOGJAM",
                    "severity": "CRITICAL",
                    "finding": "Unknown DH group has only 512 bits",
                },
            ]
        }
    ]
}


# --- parsing -----------------------------------------------------------------


def test_parse_marks_rc4_vulnerable() -> None:
    findings = _parse(RC4_REPORT)
    assert findings["RC4"].vulnerable is True
    assert findings["RC4"].severity == "HIGH"
    assert "RC4-SHA" in findings["RC4"].detail
    assert findings["SWEET32"].vulnerable is False


def test_parse_clean_report_has_no_vulnerable_findings() -> None:
    findings = _parse(CLEAN_REPORT)
    assert all(not f.vulnerable for f in findings.values())


def test_parse_keeps_worst_severity_when_id_repeats() -> None:
    """dh512 reports two LOGJAM verdicts (one per DH-parameter source tried);
    the worse one - the actual weak-group finding - must win, not whichever
    testssl happened to print second."""
    findings = _parse(DUPLICATE_LOGJAM_REPORT)
    assert findings["LOGJAM"].severity == "CRITICAL"
    assert findings["LOGJAM"].vulnerable is True


def test_parse_ignores_ids_outside_the_four_checks() -> None:
    findings = _parse(RC4_REPORT)
    assert "BEAST" not in findings


def test_check_to_testssl_id_covers_all_four_checks() -> None:
    assert set(CHECK_TO_TESTSSL_ID) == {
        "tls-vuln-rc4",
        "tls-vuln-sweet32",
        "tls-vuln-freak",
        "tls-vuln-logjam",
    }
    assert set(CHECK_TO_TESTSSL_ID.values()) == {"RC4", "SWEET32", "FREAK", "LOGJAM"}


# --- degrade-never-crash ------------------------------------------------------


def test_stub_client_raises_unavailable() -> None:
    with pytest.raises(UnavailableError):
        StubTestsslClient().legacy_ciphers("example.test", 443)


def test_live_client_raises_unavailable_when_binary_missing(monkeypatch, tmp_path) -> None:
    missing = tmp_path / "no-such-testssl.sh"
    monkeypatch.setattr("core.testssl.TESTSSL_PATH", missing)
    with pytest.raises(UnavailableError):
        LiveTestsslClient().legacy_ciphers("example.test", 443)


def test_live_client_raises_unavailable_on_timeout(monkeypatch) -> None:
    monkeypatch.setattr("core.testssl.available", lambda: True)

    def _raise_timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd="testssl.sh", timeout=1)

    monkeypatch.setattr("core.testssl.subprocess.run", _raise_timeout)
    with pytest.raises(UnavailableError):
        LiveTestsslClient(timeout_s=1).legacy_ciphers("example.test", 443)


def test_live_client_raises_unavailable_on_unparsable_json(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr("core.testssl.available", lambda: True)

    def _fake_run(cmd, **kwargs):
        out_path = next(c for c in cmd if c.endswith(".json"))
        with open(out_path, "w") as fh:
            fh.write("not json")
        return subprocess.CompletedProcess(cmd, 0)

    monkeypatch.setattr("core.testssl.subprocess.run", _fake_run)
    with pytest.raises(UnavailableError):
        LiveTestsslClient().legacy_ciphers("example.test", 443)


def test_replay_client_raises_unavailable_when_nothing_recorded(tmp_path) -> None:
    client = ReplayTestsslClient(tmp_path)
    with pytest.raises(UnavailableError):
        client.legacy_ciphers("never-recorded.test", 443)


def test_replay_client_never_touches_the_network(tmp_path, monkeypatch) -> None:
    """The corpus must run fully offline - assert replay never calls out."""

    def _fail(*args, **kwargs):
        raise AssertionError("ReplayTestsslClient must never shell out")

    monkeypatch.setattr("core.testssl.subprocess.run", _fail)
    client = ReplayTestsslClient(tmp_path)
    with pytest.raises(UnavailableError):
        client.legacy_ciphers("never-recorded.test", 443)


# --- record/replay round trip -------------------------------------------------


def test_record_then_replay_round_trips(tmp_path, monkeypatch) -> None:
    def _fake_run(cmd, **kwargs):
        out_path = next(c for c in cmd if c.endswith(".json"))
        import json

        with open(out_path, "w") as fh:
            json.dump(RC4_REPORT, fh)
        return subprocess.CompletedProcess(cmd, 0)

    monkeypatch.setattr("core.testssl.available", lambda: True)
    monkeypatch.setattr("core.testssl.subprocess.run", _fake_run)

    recorder = RecordingTestsslClient(tmp_path)
    recorded = recorder.legacy_ciphers("rc4.badssl.com", 443)
    assert recorded.findings["RC4"].vulnerable is True

    replayed = ReplayTestsslClient(tmp_path).legacy_ciphers("rc4.badssl.com", 443)
    assert replayed.findings["RC4"].vulnerable is True
    assert replayed.findings["RC4"].severity == "HIGH"
    assert replayed.host == "rc4.badssl.com"
    assert replayed.port == 443


def test_replay_report_for_check_maps_check_id_to_testssl_id(tmp_path) -> None:
    from core.testssl import LegacyCipherFinding

    report = LegacyCipherReport(
        host="rc4.badssl.com",
        port=443,
        recorded_at=__import__("datetime").datetime.now(tz=__import__("datetime").UTC),
        findings={"RC4": LegacyCipherFinding("RC4", "HIGH", "VULNERABLE", "CVE-2013-2566")},
    )
    assert report.for_check("tls-vuln-rc4").vulnerable is True
    assert report.for_check("tls-vuln-sweet32") is None
    assert report.for_check("not-a-real-check") is None
