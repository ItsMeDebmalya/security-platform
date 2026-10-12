"""ADR-034: the Stage A contract extension. Every addition is optional."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from core.models import Asset, CheckRun, Finding, ScanResult, Telemetry
from tests.core.test_redaction import AWS
from tests.core.test_redaction_storage import _finding_kwargs

OTHER = "sha256:" + "a" * 64


def _finding(**over) -> Finding:
    return Finding.create(**_finding_kwargs(**over))


# --- 1. host targets --------------------------------------------------------------


def test_a_host_asset_takes_a_hostname_and_its_addresses():
    asset = Asset(type="host", value="web-01.internal", addresses=["10.0.0.5", "fd00::5"])

    assert asset.addresses == ["10.0.0.5", "fd00::5"]


def test_a_host_asset_may_be_an_address_alone():
    assert Asset(type="host", value="10.0.0.5").addresses == []


def test_addresses_must_be_ip_literals():
    with pytest.raises(ValidationError):
        Asset(type="host", value="web-01", addresses=["not-an-ip"])


def test_addresses_belong_only_to_host_assets():
    with pytest.raises(ValidationError):
        Asset(type="domain", value="example.com", addresses=["10.0.0.5"])


def test_a_finding_and_a_scan_result_accept_a_host_target():
    target = {"type": "host", "value": "web-01.internal", "addresses": ["10.0.0.5"]}
    finding = _finding(target=target)
    result = ScanResult(
        scanner="example",
        scanner_version="1.0.0",
        target=target,
        mode="light",
        findings=[finding],
        errors=[],
        telemetry=Telemetry(checks_run=[CheckRun(check_id="c", outcome="reported")]),
        finished_at=datetime.now(UTC),
    )
    assert result.target.type == "host"


# --- 2 and 3. vantage and engagement ---------------------------------------------


def test_vantage_and_engagement_are_optional_and_default_to_not_recorded():
    finding = _finding()

    assert (finding.vantage, finding.engagement) == (None, None)


def test_vantage_and_engagement_take_only_their_values():
    finding = _finding(vantage="agent", engagement="defensive")
    assert (finding.vantage, finding.engagement) == ("agent", "defensive")

    with pytest.raises(ValidationError):
        _finding(vantage="inside")
    with pytest.raises(ValidationError):
        _finding(engagement="light")


def test_the_new_fields_never_change_a_finding_id():
    plain = _finding()
    tagged = _finding(
        vantage="external_unauthenticated",
        engagement="defensive",
        links=[{"relation": "explains", "finding_id": OTHER}],
    )

    assert plain.id == tagged.id


# --- 4. links ------------------------------------------------------------------------


def test_links_explain_or_chain_to_another_finding():
    finding = _finding(
        links=[
            {"relation": "explains", "finding_id": OTHER},
            {"relation": "chains_to", "finding_id": OTHER},
        ]
    )

    assert [link.relation for link in finding.links] == ["explains", "chains_to"]


@pytest.mark.parametrize(
    "links",
    [
        [{"relation": "causes", "finding_id": OTHER}],
        [{"relation": "explains", "finding_id": "not-an-id"}],
        [{"relation": "explains", "finding_id": OTHER}] * 2,
    ],
)
def test_bad_links_are_refused(links):
    with pytest.raises(ValidationError):
        _finding(links=links)


def test_a_finding_cannot_link_to_itself():
    own_id = _finding().id

    with pytest.raises(ValidationError, match="itself"):
        _finding(links=[{"relation": "explains", "finding_id": own_id}])


# --- 5. state_change -----------------------------------------------------------------

CHANGE = {
    "changes": [{"action": "created", "what": "a test account", "where": "/admin/users"}],
    "cleanup": {"status": "done", "performed_at": "2026-10-12T00:00:00Z", "detail": "deleted"},
}


def test_state_change_is_allowed_only_on_an_offensive_finding():
    finding = _finding(engagement="offensive", state_change=CHANGE)
    assert finding.state_change.cleanup.status == "done"

    for engagement in ("defensive", None):
        with pytest.raises(ValidationError, match="offensive"):
            _finding(engagement=engagement, state_change=CHANGE)


def test_state_change_needs_at_least_one_change():
    with pytest.raises(ValidationError):
        _finding(engagement="offensive", state_change={**CHANGE, "changes": []})


def test_state_change_text_is_redacted():
    change = {
        "changes": [{"action": "modified", "what": f"key {AWS}", "where": "/x"}],
        "cleanup": {"status": "pending", "performed_at": None, "detail": f"rotate {AWS}"},
    }
    finding = _finding(engagement="offensive", state_change=change)

    assert AWS not in finding.model_dump_json()


def test_the_runtime_guard_refuses_any_result_carrying_a_state_change():
    """ADR-034: until ADR-025's preconditions exist, 'we can't', not 'we don't'."""
    from core.applicability import StateChangeRefusedError, enforce

    finding = _finding(engagement="offensive", state_change=CHANGE)
    result = ScanResult(
        scanner="example",
        scanner_version="1.0.0",
        target=finding.target,
        mode="light",
        findings=[finding],
        errors=[],
        telemetry=Telemetry(checks_run=[CheckRun(check_id=finding.check_id, outcome="reported")]),
        finished_at=datetime.now(UTC),
    )

    with pytest.raises(StateChangeRefusedError):
        enforce(result)


# --- the schema says the same as the models (ADR-034) ---------------------------------


def _schema_validator():
    import json
    from pathlib import Path

    from jsonschema import Draft202012Validator
    from referencing import Registry, Resource

    contracts = Path(__file__).resolve().parents[2] / "contracts"
    schemas = {p.name: json.loads(p.read_text()) for p in contracts.glob("*.schema.json")}
    registry = Registry()
    for schema in schemas.values():
        registry = registry.with_resource(schema["$id"], Resource.from_contents(schema))
    return Draft202012Validator(schemas["finding.schema.json"], registry=registry), schemas


def test_the_schema_refuses_a_state_change_unless_offensive():
    validator, schemas = _schema_validator()
    offensive = schemas["finding.schema.json"]["examples"][3]
    assert offensive["state_change"] and offensive["engagement"] == "offensive"
    validator.validate(offensive)

    for engagement in ("defensive", None):
        assert not validator.is_valid({**offensive, "engagement": engagement})


def test_the_schema_refuses_addresses_on_a_non_host_asset():
    validator, schemas = _schema_validator()
    example = schemas["finding.schema.json"]["examples"][0]
    bad = {
        **example,
        "target": {"type": "domain", "value": "example.com", "addresses": ["10.0.0.5"]},
    }

    assert not validator.is_valid(bad)
