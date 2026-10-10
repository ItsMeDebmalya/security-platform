"""ADR-032: `not_applicable` judged nothing, so it is outside the inconclusive rate."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from cli.corpus import _score
from core.models import Asset, CheckRun, Finding, ScanResult, Telemetry
from tests.core.test_redaction_storage import _finding_kwargs


def _finding(check_id: str) -> Finding:
    return Finding.create(**_finding_kwargs(scanner="domscout", check_id=check_id))


def _result(*runs: CheckRun, findings: list[Finding] | None = None) -> ScanResult:
    return ScanResult(
        scanner="domscout",
        scanner_version="1.0.0",
        target=Asset(type="domain", value="x.test"),
        mode="light",
        findings=findings or [],
        errors=[],
        telemetry=Telemetry(checks_run=list(runs)),
        finished_at=datetime.now(UTC),
    )


RUNS = (
    CheckRun(check_id="b", outcome="clear"),
    CheckRun(check_id="c", outcome="not_applicable", reason="special-use-name"),
)


def test_the_inconclusive_rate_leaves_not_applicable_out_of_the_denominator():
    result = _result(*RUNS)

    assert result.inconclusive_rate() == 0.0
    assert result.not_applicable_count() == 1
    only = _result(RUNS[1])
    assert only.inconclusive_rate() == 0.0


def test_the_corpus_score_counts_not_applicable_apart_and_excuses_its_expectation():
    score = _score(_result(*RUNS), [{"check_id": "c", "location": "$"}])

    assert score.checks_run == 1
    assert score.not_applicable == 1
    assert score.fn == 0


def test_a_check_cannot_report_where_it_declared_itself_not_applicable():
    with pytest.raises(ValidationError, match="not applicable"):
        _result(
            CheckRun(check_id="c", outcome="reported"),
            CheckRun(check_id="c", outcome="not_applicable", reason="special-use-name"),
            findings=[_finding("c")],
        )
