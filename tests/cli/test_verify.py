"""`scan verify` - the "close" half of ADR-022 (docs/03-roadmap.md 0b.8).

The one thing this command must never do is close a finding because a check
failed to reproduce it. Every failure mode short of a positive, evidenced
`clear` - a timeout, a rate limit, a WAF block, an error, an `inconclusive`
verdict, a skipped prerequisite, an authorisation denial - must leave the
finding exactly as it was.

A fake scanner is registered here (never one of the real ones, and never
anything under `scanners/`) so each `telemetry.checks_run` outcome can be
driven directly and deterministically, rather than fished for through a real
network protocol.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime

import pytest
from typer.testing import CliRunner

from cli.main import app
from core.context import ScanContext
from core.models import Asset, CheckRun, Finding, Mode, ScanResult, Suppressed, Telemetry
from core.registry import registry
from core.scanner import BaseScanner
from core.store import FindingStore

runner = CliRunner()

CHECK_ID = "fake-check"
SCAN_1 = "01J8AAAAAAAAAAAAAAAAAAAAAA"
Behaviour = Callable[[Asset, Mode, ScanContext], ScanResult]


class _Slot:
    """Per-test hook: what the fake scanner's `run` does. Reset by the fixture."""

    fn: Behaviour | None = None
    active = False


class FakeScanner(BaseScanner):
    name = "faketool"
    version = "1.0.0"
    supported_modes = frozenset({"light"})
    target_types = frozenset({"domain"})

    def requires_authorisation(self, mode: Mode) -> bool:
        return _Slot.active

    def run(self, target: Asset, mode: Mode, ctx: ScanContext) -> ScanResult:
        assert _Slot.fn is not None, "test forgot to set _Slot.fn"
        return _Slot.fn(target, mode, ctx)


@pytest.fixture(autouse=True)
def _fake_scanner():
    registry.register(FakeScanner)
    _Slot.fn = None
    _Slot.active = False
    try:
        yield
    finally:
        del registry._scanners["faketool"]
        _Slot.fn = None
        _Slot.active = False


def _result(*, findings=None, checks_run=None, suppressed=None) -> Callable[..., ScanResult]:
    def _build(target: Asset, mode: Mode, ctx: ScanContext) -> ScanResult:
        return ScanResult(
            scanner="faketool",
            scanner_version="1.0.0",
            target=target,
            mode=mode,
            findings=findings or [],
            errors=[],
            telemetry=Telemetry(checks_run=checks_run or [], suppressed=suppressed or []),
            finished_at=datetime.now(UTC),
        )

    return _build


def _finding(**overrides) -> Finding:
    kwargs: dict[str, object] = {
        "org_id": "org_internal",
        "scanner": "faketool",
        "scanner_version": "1.0.0",
        "check_id": CHECK_ID,
        "title": "A fake problem",
        "target": {"type": "domain", "value": "verify.example"},
        "location": "$",
        "severity": "medium",
        "confidence": 0.9,
        "detection_methods": [
            {
                "method": "fake_probe",
                "likelihood_ratio": 20.0,
                "independence_class": "http",
                "prior": 0.5,
                "prior_justification": "test fixture, not a real prior",
            }
        ],
        "validation": {"attempted": False, "outcome": "not_applicable"},
        "evidence": [
            {
                "kind": "http_pair",
                "label": "fake evidence",
                "captured_at": datetime(2026, 8, 28, tzinfo=UTC),
                "control": {
                    "request": {"method": "GET", "url": "https://verify.example/"},
                    "response": {"status": 200, "headers": {}},
                },
                "test": {
                    "request": {"method": "GET", "url": "https://verify.example/x"},
                    "response": {"status": 500, "headers": {}},
                },
            }
        ],
        "description": "A fake problem, for testing scan verify.",
        "impact": "none - this is a test fixture",
        "remediation": "fix the fake problem",
        "first_seen": datetime(2026, 8, 28, tzinfo=UTC),
        "first_seen_scan_id": SCAN_1,
        "last_seen": datetime(2026, 8, 28, tzinfo=UTC),
        "last_seen_scan_id": SCAN_1,
    }
    kwargs.update(overrides)
    return Finding.create(**kwargs)


def _seed(store_path, finding: Finding) -> None:
    with FindingStore(store_path) as store:
        store.ingest([finding])


def _verify(finding_id: str, store_path, *, scope_file=None):
    args = ["verify", finding_id, "--store", str(store_path)]
    if scope_file is not None:
        args += ["--scope-file", str(scope_file)]
    return runner.invoke(app, args)


def _status(store_path, finding: Finding) -> str:
    with FindingStore(store_path) as store:
        stored = store.get(finding.id, finding.org_id)
    assert stored is not None
    return stored.status


# --- the close path -----------------------------------------------------


def test_verify_closes_a_finding_the_check_confirms_is_gone(tmp_path):
    store_path = tmp_path / "s.sqlite3"
    finding = _finding()
    _seed(store_path, finding)
    _Slot.fn = _result(checks_run=[CheckRun(check_id=CHECK_ID, outcome="clear", location="$")])

    result = _verify(finding.id, store_path)

    assert result.exit_code == 0, result.stdout
    assert "closed" in result.stdout
    stored_status = _status(store_path, finding)
    assert stored_status == "closed"
    with FindingStore(store_path) as store:
        stored = store.get(finding.id, finding.org_id)
    assert stored.status_history[-1].to == "closed"
    assert stored.status_history[-1].from_ == "open"


def test_reclosing_an_already_closed_finding_does_not_duplicate_history(tmp_path):
    store_path = tmp_path / "s.sqlite3"
    finding = _finding()
    _seed(store_path, finding)
    _Slot.fn = _result(checks_run=[CheckRun(check_id=CHECK_ID, outcome="clear", location="$")])
    _verify(finding.id, store_path)

    result = _verify(finding.id, store_path)

    assert result.exit_code == 0
    assert "already closed" in result.stdout
    with FindingStore(store_path) as store:
        stored = store.get(finding.id, finding.org_id)
    assert len(stored.status_history) == 1


def test_a_finding_that_reappears_after_being_closed_is_reopened(tmp_path):
    store_path = tmp_path / "s.sqlite3"
    finding = _finding()
    _seed(store_path, finding)
    _Slot.fn = _result(checks_run=[CheckRun(check_id=CHECK_ID, outcome="clear", location="$")])
    _verify(finding.id, store_path)
    assert _status(store_path, finding) == "closed"

    _Slot.fn = _result(
        findings=[_finding()],
        checks_run=[CheckRun(check_id=CHECK_ID, outcome="reported", location="$")],
    )
    result = _verify(finding.id, store_path)

    assert result.exit_code == 0
    assert "reopened" in result.stdout
    assert _status(store_path, finding) == "open"


# --- every way a check can fail to prove the fix: the finding stays open ---


def test_stays_open_when_the_problem_is_still_reported(tmp_path):
    store_path = tmp_path / "s.sqlite3"
    finding = _finding()
    _seed(store_path, finding)
    _Slot.fn = _result(
        findings=[_finding()],
        checks_run=[CheckRun(check_id=CHECK_ID, outcome="reported", location="$")],
    )

    result = _verify(finding.id, store_path)

    assert result.exit_code == 0
    assert "unchanged" in result.stdout
    assert _status(store_path, finding) == "open"


def test_stays_open_when_the_check_is_inconclusive(tmp_path):
    """SERVFAIL, a stale cache, an ambiguous response - none of it is a fix."""
    store_path = tmp_path / "s.sqlite3"
    finding = _finding()
    _seed(store_path, finding)
    _Slot.fn = _result(
        checks_run=[CheckRun(check_id=CHECK_ID, outcome="inconclusive", location="$")]
    )

    result = _verify(finding.id, store_path)

    assert result.exit_code == 1
    assert "no verdict" in result.stdout
    assert _status(store_path, finding) == "open"


def test_stays_open_when_the_check_is_not_applicable(tmp_path, monkeypatch):
    """ADR-032: not_applicable judged nothing, so it is never a pass and never closes."""
    import core.applicability

    monkeypatch.setattr(
        core.applicability,
        "declared_reasons",
        lambda scanner: {CHECK_ID: frozenset({"special-use-name"})},
    )
    store_path = tmp_path / "s.sqlite3"
    finding = _finding()
    _seed(store_path, finding)
    _Slot.fn = _result(
        checks_run=[
            CheckRun(
                check_id=CHECK_ID, outcome="not_applicable", reason="special-use-name", location="$"
            )
        ]
    )

    result = _verify(finding.id, store_path)

    assert result.exit_code == 1
    assert "no verdict" in result.stdout
    assert _status(store_path, finding) == "open"


def test_stays_open_when_rate_limited_or_waf_blocked(tmp_path):
    """Represented as `suppressed`: the check ran but its result was withheld."""
    store_path = tmp_path / "s.sqlite3"
    finding = _finding()
    _seed(store_path, finding)
    _Slot.fn = _result(
        checks_run=[CheckRun(check_id=CHECK_ID, outcome="suppressed", location="$")],
        suppressed=[
            Suppressed(check_id=CHECK_ID, location="$", confidence=0.2, reason="waf_block")
        ],
    )

    result = _verify(finding.id, store_path)

    assert result.exit_code == 1
    assert "no verdict" in result.stdout
    assert _status(store_path, finding) == "open"


def test_stays_open_when_the_scan_reports_a_check_error(tmp_path):
    store_path = tmp_path / "s.sqlite3"
    finding = _finding()
    _seed(store_path, finding)
    _Slot.fn = _result(checks_run=[CheckRun(check_id=CHECK_ID, outcome="error", location="$")])

    result = _verify(finding.id, store_path)

    assert result.exit_code == 1
    assert "no verdict" in result.stdout
    assert _status(store_path, finding) == "open"


def test_stays_open_when_the_check_never_ran_at_all(tmp_path):
    """A missing prerequisite, or a scanner that silently skipped the check."""
    store_path = tmp_path / "s.sqlite3"
    finding = _finding()
    _seed(store_path, finding)
    _Slot.fn = _result(checks_run=[])  # no entry for CHECK_ID whatsoever

    result = _verify(finding.id, store_path)

    assert result.exit_code == 1
    assert "did not run" in result.stdout
    assert _status(store_path, finding) == "open"


def test_stays_open_when_the_scan_times_out_or_errors_outright(tmp_path):
    """The scanner process itself failed - no ScanResult was ever produced."""
    store_path = tmp_path / "s.sqlite3"
    finding = _finding()
    _seed(store_path, finding)

    def _timeout(target, mode, ctx):
        raise TimeoutError("verify.example did not respond")

    _Slot.fn = _timeout

    result = _verify(finding.id, store_path)

    assert result.exit_code == 1
    assert "could not run" in result.stdout
    assert _status(store_path, finding) == "open"


def test_stays_open_when_verification_is_denied_authorisation(tmp_path):
    """An active check without a valid record is denied, exactly as `scan run` is."""
    store_path = tmp_path / "s.sqlite3"
    finding = _finding()
    _seed(store_path, finding)
    _Slot.active = True  # this check is declared active: needs a record even in light mode
    _Slot.fn = _result(checks_run=[CheckRun(check_id=CHECK_ID, outcome="clear", location="$")])
    empty_scope = tmp_path / "no_such_scope.yaml"

    result = _verify(finding.id, store_path, scope_file=empty_scope)

    assert result.exit_code == 1
    assert "authorisation denied" in result.stdout
    assert _status(store_path, finding) == "open"


def test_verify_fails_cleanly_for_an_unknown_finding_id(tmp_path):
    store_path = tmp_path / "s.sqlite3"
    FindingStore(store_path).close()  # create an empty store

    result = _verify("sha256:" + "0" * 64, store_path)

    assert result.exit_code == 1
    assert "no stored finding" in result.stdout


# --- a read-only store ---------------------------------------------------


def test_verify_on_a_read_only_store_stops_before_scanning(tmp_path, monkeypatch):
    """verify records its outcome, so a read-only copy is refused up front, unchanged."""
    import os

    store_path = tmp_path / "s.sqlite3"
    finding = _finding()
    _seed(store_path, finding)
    before = store_path.read_bytes()
    real = os.access
    monkeypatch.setattr(
        "core.store.os.access", lambda p, mode: False if mode & os.W_OK else real(p, mode)
    )

    def _must_not_run(*_args):
        raise AssertionError("the scan ran against a read-only store")

    _Slot.fn = _must_not_run

    result = _verify(finding.id, store_path)

    assert result.exit_code == 1
    assert "is read-only" in result.stdout and "writable copy" in result.stdout
    assert store_path.read_bytes() == before


def test_scan_run_with_a_read_only_store_stops_before_scanning(tmp_path, monkeypatch):
    import os

    store_path = tmp_path / "s.sqlite3"
    _seed(store_path, _finding())
    before = store_path.read_bytes()
    real = os.access
    monkeypatch.setattr(
        "core.store.os.access", lambda p, mode: False if mode & os.W_OK else real(p, mode)
    )

    def _must_not_run(*_args):
        raise AssertionError("the scan ran against a read-only store")

    _Slot.fn = _must_not_run

    result = runner.invoke(
        app, ["run", "faketool", "--target", "x.test", "--store", str(store_path)]
    )

    assert result.exit_code == 1, result.stdout
    assert "is read-only" in result.stdout and "writable copy" in result.stdout
    assert store_path.read_bytes() == before
