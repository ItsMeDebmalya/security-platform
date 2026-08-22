"""The reference scanner, and the whole loop it exercises.

Registry -> context -> DNS client -> evidence -> confidence -> state -> schema.
If this scanner works end to end, a new scanner is a matter of checks.
"""

from __future__ import annotations

import pytest

from core.context import ScanContext
from core.dns import DnsClient, DnsResponse, FakeResolver
from core.models import Asset
from core.registry import get_scanner
from core.scanner import UnsupportedModeError, UnsupportedTargetError
from scanners.example import ExampleScanner


def _ctx(answers, resolvers=("1.1.1.1", "8.8.8.8")):
    return ScanContext(dns=DnsClient(resolver=FakeResolver(answers), resolvers=list(resolvers)))


def _a(name, rcode="NOERROR", records=("93.184.216.34",)):
    return DnsResponse(name=name, rrtype="A", rcode=rcode, records=list(records), ttl=300)


RESOLVING = {("example.com", "A"): _a("example.com")}
NO_A_RECORD = {("no-a.example", "A"): _a("no-a.example", rcode="NODATA", records=())}
BROKEN = {("broken.example", "A"): _a("broken.example", rcode="SERVFAIL", records=())}


def _run(answers, domain, mode="light", ctx=None):
    scanner = ExampleScanner()
    return scanner.run(Asset(type="domain", value=domain), mode, ctx or _ctx(answers))


# --- registration ------------------------------------------------------------


def test_the_scanner_is_registered_under_its_name():
    assert get_scanner("example") is ExampleScanner


def test_it_declares_a_semver_version():
    assert ExampleScanner.version.count(".") == 2


def test_it_rejects_a_target_type_it_cannot_handle():
    with pytest.raises(UnsupportedTargetError):
        ExampleScanner().validate(Asset(type="ip", value="93.184.216.34"))


def test_it_rejects_an_unsupported_mode():
    with pytest.raises(UnsupportedModeError):
        ExampleScanner().validate(Asset(type="domain", value="example.com"), mode="deep")


# --- the negative case -------------------------------------------------------


def test_a_domain_that_resolves_produces_no_finding():
    result = _run(RESOLVING, "example.com")

    assert result.findings == []


def test_a_domain_that_resolves_still_accounts_for_the_check_having_run():
    result = _run(RESOLVING, "example.com")

    assert [c.outcome for c in result.telemetry.checks_run] == ["clear"]


# --- the positive case -------------------------------------------------------


def test_a_domain_with_no_a_record_produces_a_finding():
    result = _run(NO_A_RECORD, "no-a.example")

    assert [f.check_id for f in result.findings] == ["example-a-record-missing"]


def test_the_finding_is_a_target_level_finding():
    finding = _run(NO_A_RECORD, "no-a.example").findings[0]

    assert finding.location == "$"


def test_the_finding_carries_the_dns_answer_as_evidence():
    finding = _run(NO_A_RECORD, "no-a.example").findings[0]

    assert finding.evidence[0].kind == "dns_answer"
    assert finding.evidence[0].test.answer.rcode == "NODATA"


def test_the_finding_carries_a_control_alongside_its_test():
    """'The server errored' is not evidence. The control is the wildcard probe."""
    finding = _run(NO_A_RECORD, "no-a.example").findings[0]

    assert finding.evidence[0].has_control()


def test_the_finding_declares_its_detection_method_and_independence_class():
    finding = _run(NO_A_RECORD, "no-a.example").findings[0]

    assert finding.detection_methods[0].independence_class == "dns"
    assert finding.detection_methods[0].prior_justification


def test_the_finding_confidence_is_provisional_until_calibration():
    finding = _run(NO_A_RECORD, "no-a.example").findings[0]

    assert finding.confidence_provisional is True


def test_a_second_resolver_agreeing_validates_the_finding():
    finding = _run(NO_A_RECORD, "no-a.example").findings[0]

    assert finding.validation.outcome == "passed"
    assert finding.validation.method == "independent_resolver"
    assert finding.state == "confirmed"


def test_with_only_one_resolver_validation_is_unavailable_and_the_state_is_lower():
    ctx = _ctx(NO_A_RECORD, resolvers=("1.1.1.1",))
    finding = _run(NO_A_RECORD, "no-a.example", ctx=ctx).findings[0]

    assert finding.validation.outcome == "unavailable"
    assert finding.state != "confirmed"


def test_a_second_resolver_disagreeing_downgrades_rather_than_deleting():
    class Disagreeing:
        def resolve(self, name, rrtype, resolver=None):
            if resolver == "8.8.8.8":
                return _a(name)
            return _a(name, rcode="NODATA", records=())

    ctx = ScanContext(dns=DnsClient(resolver=Disagreeing(), resolvers=["1.1.1.1", "8.8.8.8"]))
    finding = _run(NO_A_RECORD, "no-a.example", ctx=ctx).findings[0]

    assert finding.validation.outcome == "failed"
    assert finding.state == "suspected"
    assert finding.confidence <= 0.5


# --- the inconclusive case ---------------------------------------------------


def test_a_servfail_is_inconclusive_and_never_reported_as_missing():
    result = _run(BROKEN, "broken.example")

    assert [f.state for f in result.findings] == ["inconclusive"]
    assert result.findings[0].no_verdict_reason == "servfail"


def test_an_inconclusive_result_is_not_a_scan_error():
    result = _run(BROKEN, "broken.example")

    assert result.errors == []
    assert result.outcome == "succeeded"


def test_the_inconclusive_rate_counts_the_check_that_could_not_decide():
    result = _run(BROKEN, "broken.example")

    assert result.inconclusive_rate() == 1.0


def test_a_wildcarded_zone_is_inconclusive_rather_than_a_confident_answer():
    class Wildcarded:
        def resolve(self, name, rrtype, resolver=None):
            return _a(name)

    ctx = ScanContext(dns=DnsClient(resolver=Wildcarded(), resolvers=["1.1.1.1", "8.8.8.8"]))
    result = _run({}, "wild.example", ctx=ctx)

    assert result.findings == [] or result.findings[0].state == "inconclusive"


# --- contract compliance -----------------------------------------------------


def test_the_result_validates_against_the_frozen_schema():
    import json
    from pathlib import Path

    from jsonschema import Draft202012Validator
    from referencing import Registry, Resource

    contracts = Path(__file__).resolve().parents[2] / "contracts"
    registry = Registry()
    schemas = {}
    for path in contracts.glob("*.schema.json"):
        schema = json.loads(path.read_text())
        schemas[path.name] = schema
        registry = registry.with_resource(schema["$id"], Resource.from_contents(schema))

    result = _run(NO_A_RECORD, "no-a.example")
    validator = Draft202012Validator(schemas["scanresult.schema.json"], registry=registry)

    validator.validate(json.loads(result.model_dump_json()))


def test_the_scan_counts_its_own_cost():
    ctx = _ctx(NO_A_RECORD)
    result = _run(NO_A_RECORD, "no-a.example", ctx=ctx)

    assert result.telemetry.requests > 0


def test_the_scanner_reports_progress_through_the_context():
    seen = []
    ctx = ScanContext(
        dns=DnsClient(resolver=FakeResolver(RESOLVING), resolvers=["1.1.1.1"]),
        progress=lambda message, fraction: seen.append(message),
    )

    _run(RESOLVING, "example.com", ctx=ctx)

    assert seen
