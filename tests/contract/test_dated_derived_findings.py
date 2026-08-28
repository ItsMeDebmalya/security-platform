"""ADR-018: a finding carries a date, and says whether it was detected or derived.

Four additive, optional fields on Finding: `materialises_at`,
`materialises_reason`, `derivation`, `derived_from`. Existing findings default
to null / "detected" and must validate exactly as they did before v3.4.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from referencing import Registry, Resource

CONTRACTS = Path(__file__).resolve().parents[2] / "contracts"


def _schema(name: str) -> dict:
    return json.loads((CONTRACTS / name).read_text())


def _registry() -> Registry:
    registry = Registry()
    for path in CONTRACTS.glob("*.schema.json"):
        schema = json.loads(path.read_text())
        registry = registry.with_resource(schema["$id"], Resource.from_contents(schema))
    return registry


def _validate_finding(payload: dict) -> None:
    schema = _schema("finding.schema.json")
    Draft202012Validator(schema, registry=_registry()).validate(payload)


# --- existing findings are unaffected ---------------------------------------


def test_a_finding_with_no_new_fields_still_validates(make_finding):
    finding = make_finding()

    assert finding.materialises_at is None
    assert finding.materialises_reason is None
    assert finding.derivation == "detected"
    assert finding.derived_from is None


def test_the_schema_example_validates_unchanged():
    example = _schema("finding.schema.json")["examples"][0]
    assert "materialises_at" not in example

    _validate_finding(example)


def test_a_dated_finding_validates_against_the_schema(make_finding):
    finding = make_finding(
        materialises_at="2027-03-15",
        materialises_reason="CA/Browser Forum SC-081v3 reduces max cert lifetime to 100 days",
    )
    payload = json.loads(finding.model_dump_json(by_alias=True))

    _validate_finding(payload)


# --- materialises_at / materialises_reason co-dependency --------------------


def test_a_materialises_at_with_no_reason_is_rejected(make_finding):
    with pytest.raises(ValueError, match="materialises_reason is required"):
        make_finding(materialises_at="2027-03-15")


def test_a_materialises_reason_with_no_date_is_rejected(make_finding):
    with pytest.raises(ValueError, match="materialises_reason is meaningless"):
        make_finding(materialises_reason="some future rule")


def test_a_dated_finding_keeps_its_computed_state(make_finding):
    """A dated finding is not forced to `info`: severity means 'how bad when
    it lands', and the truth table does not move for it."""
    finding = make_finding(
        materialises_at="2027-03-15",
        materialises_reason="the certificate stops being issuable at this length",
    )

    assert finding.state == "confirmed"
    assert finding.severity == "medium"


# --- derivation / derived_from co-dependency --------------------------------


def test_derived_requires_derived_from(make_finding):
    with pytest.raises(ValueError, match="derived_from is required"):
        make_finding(derivation="derived")


def test_detected_forbids_derived_from(make_finding):
    with pytest.raises(ValueError, match="derived_from is forbidden"):
        make_finding(derivation="detected", derived_from="sha256:" + "0" * 64)


def test_a_derived_finding_names_its_premise(make_finding):
    premise_id = "sha256:" + "1" * 64
    finding = make_finding(derivation="derived", derived_from=premise_id)

    assert finding.derivation == "derived"
    assert finding.derived_from == premise_id
