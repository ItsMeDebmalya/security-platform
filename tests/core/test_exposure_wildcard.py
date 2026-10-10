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


# --- independent review of D52 (2026-10-10): each finding is a test ---------------

GITHUB_TXT = "token=ghp_" + "a" * 36


def test_a_name_whose_resolvers_disagree_is_never_folded():
    """Finding 1: a different secret behind one name must not vanish into the wildcard."""
    log = _log(
        _txt(PROBE, KEY_TXT),
        _txt(f"a.{ZONE}", KEY_TXT),
        DnsResponse(
            name=f"a.{ZONE}",
            rrtype="TXT",
            rcode="NOERROR",
            records=[GITHUB_TXT],
            resolver="8.8.8.8",
        ),
    )

    locations = [f.location for f in _report(log)]
    assert f"dns:a.{ZONE}/TXT" in locations


def test_only_the_probe_holding_the_secret_reads_correctly():
    """Finding 2: no other queried name returned the wildcard content."""
    (finding,) = _report(_log(_txt(PROBE, KEY_TXT)))

    assert finding.location == f"dns:*.{ZONE}/TXT"
    assert "seen at 1 name," not in finding.description
    assert ": ," not in finding.description
    assert "only at a random name that cannot exist" in finding.description


def test_the_description_claims_only_what_was_observed():
    """Finding 3: names with records of their own are not served by a wildcard."""
    (finding,) = _report(_log(_txt(PROBE, KEY_TXT), _txt(f"a.{ZONE}", KEY_TXT)))

    assert "Every name under it serves the same record" not in finding.description
    assert "without records of its own" in finding.description
    assert "either from the wildcard or from an identical record" in finding.description
    assert "seen at 2 names" in finding.description


def test_nested_probes_fold_deterministically_to_the_most_specific_wildcard():
    """Finding 4: the result must not depend on the probes' random labels."""
    outcomes = set()
    for hexes in (("00", "ff"), ("ff", "00"), ("5a", "a5")):
        log = _log(
            _txt(f"{WILDCARD_PROBE_PREFIX}{hexes[0]}.{ZONE}", KEY_TXT),
            _txt(f"{WILDCARD_PROBE_PREFIX}{hexes[1]}._dmarc.{ZONE}", KEY_TXT),
            _txt(f"x._dmarc.{ZONE}", KEY_TXT),
        )
        outcomes.add(tuple(f.location for f in _report(log)))

    assert outcomes == {(f"dns:*._dmarc.{ZONE}/TXT", f"dns:*.{ZONE}/TXT")}


def test_two_records_are_not_the_same_content_as_one_record_with_a_newline():
    """Finding 5: the digest input has one reading."""
    log = _log(
        DnsResponse(name=PROBE, rrtype="TXT", rcode="NOERROR", records=[KEY_TXT, "v=spf1 -all"]),
        DnsResponse(
            name=f"a.{ZONE}", rrtype="TXT", rcode="NOERROR", records=[KEY_TXT + "\nv=spf1 -all"]
        ),
    )

    assert f"dns:a.{ZONE}/TXT" in [f.location for f in _report(log)]
