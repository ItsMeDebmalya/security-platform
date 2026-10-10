"""D52: a wildcard record holding a secret is one exposure, reported once.

Deduplicated by the record's content and its actual source. The source is a
wildcard only when the scan's random probe name, which cannot exist, was served
the same content. A wildcard never matches its own owner (RFC 4592), so the
owner's answer is a separate record. Identical answers with no probe hit stay
separate: they may be separate records.
"""

from __future__ import annotations

from core.dns import WILDCARD_PROBE_PREFIX, DnsResponse
from core.exposure import ExposureLog, secret_exposure_findings, unreported_exposures
from core.models import Asset, ScanResult, Telemetry
from tests.core.test_redaction import AWS

ZONE = "corpus-wild.test"
TARGET = Asset(type="domain", value=ZONE)
KEY_TXT = f"deploy-key={AWS}"
OTHER_TXT = "deploy-key=AKIAI44QH8DHBEXAMPLE"


def _txt(name: str, value: str) -> DnsResponse:
    return DnsResponse(name=name, rrtype="TXT", rcode="NOERROR", records=[value])


def _log(*answers: DnsResponse) -> ExposureLog:
    log = ExposureLog()
    for a in answers:
        log.observe_dns(a)
    return log


def _report(log: ExposureLog):
    return secret_exposure_findings(
        [],
        scanner="email",
        scanner_version="9.9.9",
        target=TARGET,
        org_id="org_internal",
        scan_id="s",
        log=log,
    )


PROBE = f"{WILDCARD_PROBE_PREFIX}0123abcd.{ZONE}"


def test_a_wildcard_proven_by_the_probe_is_one_finding_with_its_names():
    log = _log(
        _txt(PROBE, KEY_TXT),
        _txt(f"k1._domainkey.{ZONE}", KEY_TXT),
        _txt(f"_dmarc.{ZONE}", KEY_TXT),
    )

    (finding,) = _report(log)
    assert finding.location == f"dns:*.{ZONE}/TXT"
    assert "seen at 3 names" in finding.description
    assert f"k1._domainkey.{ZONE}" in finding.description
    assert AWS not in finding.model_dump_json()


def test_the_owner_s_own_answer_is_a_separate_record():
    log = _log(_txt(PROBE, KEY_TXT), _txt(f"a.{ZONE}", KEY_TXT), _txt(ZONE, KEY_TXT))

    assert [f.location for f in _report(log)] == [f"dns:*.{ZONE}/TXT", f"dns:{ZONE}/TXT"]


def test_different_content_at_a_name_under_the_wildcard_is_its_own_record():
    log = _log(_txt(PROBE, KEY_TXT), _txt(f"a.{ZONE}", KEY_TXT), _txt(f"b.{ZONE}", OTHER_TXT))

    assert [f.location for f in _report(log)] == [f"dns:*.{ZONE}/TXT", f"dns:b.{ZONE}/TXT"]


def test_identical_answers_without_a_probe_hit_stay_separate():
    log = _log(_txt(f"a.{ZONE}", KEY_TXT), _txt(f"b.{ZONE}", KEY_TXT))

    assert [f.location for f in _report(log)] == [f"dns:a.{ZONE}/TXT", f"dns:b.{ZONE}/TXT"]


def test_the_contract_counts_every_folded_name_as_reported():
    from datetime import UTC, datetime

    from core.exposure import check_runs

    log = _log(_txt(PROBE, KEY_TXT), _txt(f"a.{ZONE}", KEY_TXT), _txt(f"b.{ZONE}", KEY_TXT))
    findings = _report(log)
    result = ScanResult(
        scanner="email",
        scanner_version="9.9.9",
        target=TARGET,
        mode="light",
        findings=findings,
        errors=[],
        telemetry=Telemetry(checks_run=check_runs(findings)),
        finished_at=datetime.now(UTC),
    )

    assert unreported_exposures(result, log) == []
