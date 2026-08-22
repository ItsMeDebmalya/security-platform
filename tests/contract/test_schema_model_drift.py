"""The JSON Schemas in contracts/ are authoritative; core/models.py mirrors them.

Every schema example is round-tripped through the models and back, and the
model output is validated against the schema. Either direction diverging is a
failure, which is what stops the two sources of truth drifting apart.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from core.models import Evidence, Finding, ScanResult, ScanRun

CONTRACTS = Path(__file__).resolve().parents[2] / "contracts"

MODEL_FOR_SCHEMA = {
    "finding.schema.json": Finding,
    "evidence.schema.json": Evidence,
    "scanresult.schema.json": ScanResult,
    "scanrun.schema.json": ScanRun,
}


def _schemas() -> dict[str, dict[str, Any]]:
    return {p.name: json.loads(p.read_text()) for p in sorted(CONTRACTS.glob("*.schema.json"))}


def _registry(schemas: dict[str, dict[str, Any]]) -> Registry:
    registry = Registry()
    for schema in schemas.values():
        registry = registry.with_resource(schema["$id"], Resource.from_contents(schema))
    return registry


ALL = _schemas()


def test_every_contract_named_in_the_plan_exists():
    assert set(ALL) == set(MODEL_FOR_SCHEMA)


@pytest.mark.parametrize("name", sorted(ALL))
def test_schema_is_a_valid_json_schema(name):
    Draft202012Validator.check_schema(ALL[name])


@pytest.mark.parametrize("name", sorted(ALL))
def test_every_schema_carries_at_least_one_example(name):
    assert ALL[name].get("examples"), f"{name} has no examples to check drift against"


@pytest.mark.parametrize("name", sorted(ALL))
def test_schema_examples_are_valid_against_their_own_schema(name):
    validator = Draft202012Validator(ALL[name], registry=_registry(ALL))
    for example in ALL[name]["examples"]:
        validator.validate(example)


@pytest.mark.parametrize("name", sorted(ALL))
def test_schema_examples_round_trip_through_the_models_unchanged(name):
    model = MODEL_FOR_SCHEMA[name]
    validator = Draft202012Validator(ALL[name], registry=_registry(ALL))

    for example in ALL[name]["examples"]:
        obj = model.model_validate(example)
        emitted = json.loads(obj.model_dump_json(exclude_none=False, by_alias=True))
        validator.validate(emitted)

        _assert_preserved(emitted, example, name, path="")


def _assert_preserved(emitted: Any, example: Any, name: str, path: str) -> None:
    """Every value the example states must survive the round-trip.

    Fields the example omits may be filled in with their documented defaults -
    that is the schema doing its job, not drift. Dropping or changing a stated
    value is drift.
    """
    if isinstance(example, dict):
        assert isinstance(emitted, dict), f"{name}{path}: expected an object, got {emitted!r}"
        for key, value in example.items():
            assert key in emitted, f"{name}{path}: model dropped field {key!r}"
            _assert_preserved(emitted[key], value, name, f"{path}.{key}")
    elif isinstance(example, list):
        assert isinstance(emitted, list) and len(emitted) == len(example), (
            f"{name}{path}: list changed: {example!r} -> {emitted!r}"
        )
        for i, value in enumerate(example):
            _assert_preserved(emitted[i], value, name, f"{path}[{i}]")
    else:
        assert emitted == example or _same_datetime(emitted, example), (
            f"{name}{path}: changed in round-trip: {example!r} -> {emitted!r}"
        )


def _same_datetime(a: object, b: object) -> bool:
    if not (isinstance(a, str) and isinstance(b, str)):
        return False
    from datetime import datetime

    try:
        return datetime.fromisoformat(a) == datetime.fromisoformat(b)
    except ValueError:
        return False
