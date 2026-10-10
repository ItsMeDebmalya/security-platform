"""ADR-032: `not_applicable` exists only with a registered, declared reason."""

from __future__ import annotations

import json
from pathlib import Path
from typing import get_args

import pytest
from pydantic import ValidationError

from core.applicability import REASONS, not_applicable
from core.models import CheckRun, NotApplicableReason

SCHEMA = Path(__file__).resolve().parents[2] / "contracts" / "scanresult.schema.json"


def test_a_declared_registered_reason_makes_a_not_applicable_run():
    run = not_applicable(
        "domain-expiring", "special-use-name", declared=frozenset({"special-use-name"})
    )

    assert run == CheckRun(
        check_id="domain-expiring", outcome="not_applicable", reason="special-use-name"
    )


def test_a_reason_the_check_did_not_declare_is_refused():
    with pytest.raises(ValueError, match="does not declare"):
        not_applicable("domain-expiring", "special-use-name", declared=frozenset())


def test_a_reason_nobody_registered_is_refused():
    with pytest.raises(ValueError, match="not a registered"):
        not_applicable("domain-expiring", "too-hard", declared=frozenset({"too-hard"}))


def test_the_model_refuses_not_applicable_without_a_reason():
    with pytest.raises(ValidationError):
        CheckRun(check_id="x", outcome="not_applicable")


def test_the_model_refuses_free_text_reasons():
    with pytest.raises(ValidationError):
        CheckRun(check_id="x", outcome="not_applicable", reason="it seemed hard")


def test_the_model_refuses_a_reason_on_any_other_outcome():
    with pytest.raises(ValidationError):
        CheckRun(check_id="x", outcome="clear", reason="special-use-name")


def test_the_schema_enumerates_exactly_the_registered_reasons():
    schema = json.loads(SCHEMA.read_text())
    run = schema["properties"]["telemetry"]["properties"]["checks_run"]["items"]

    assert set(run["properties"]["reason"]["enum"]) - {None} == set(REASONS)
    assert "not_applicable" in run["properties"]["outcome"]["enum"]


def test_the_model_accepts_exactly_the_registered_reasons():
    assert set(get_args(NotApplicableReason)) == set(REASONS)


def test_every_reason_says_why_in_words():
    for reason, text in REASONS.items():
        assert reason == reason.lower() and " " not in reason
        assert len(text.split()) >= 5
