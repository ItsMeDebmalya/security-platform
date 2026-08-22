"""BaseScanner and ScanContext: the parts of the contract every tool inherits."""

from __future__ import annotations

import pytest

from core.context import OobUnavailableError, ScanContext
from core.killswitch import KillSwitch, ScanKilledError
from core.scanner import BaseScanner, UnsupportedModeError, UnsupportedTargetError


class _Dummy(BaseScanner):
    name = "dummy"
    version = "1.0.0"
    supported_modes = frozenset({"light"})
    target_types = frozenset({"domain"})

    def run(self, target, mode, ctx):  # pragma: no cover - not exercised here
        raise NotImplementedError


def _target(type_="domain", value="example.com"):
    from core.models import Asset

    return Asset(type=type_, value=value)


def test_a_scanner_rejects_a_target_type_it_does_not_handle():
    with pytest.raises(UnsupportedTargetError):
        _Dummy().validate(_target("cidr", "10.0.0.0/24"))


def test_a_scanner_accepts_a_target_type_it_declares():
    _Dummy().validate(_target())


def test_a_scanner_rejects_a_mode_it_does_not_support():
    with pytest.raises(UnsupportedModeError):
        _Dummy().validate(_target(), mode="standard")


def test_the_oob_client_is_a_stub_that_raises_until_phase_2a():
    ctx = ScanContext()

    with pytest.raises(OobUnavailableError):
        ctx.oob.allocate_token()


def test_a_scanner_meeting_an_absent_oob_client_returns_inconclusive_not_a_crash():
    """docs/04-phase-0-foundations.md: write this test now, before any scanner needs it."""
    ctx = ScanContext()

    try:
        ctx.oob.allocate_token()
        reason = None
    except OobUnavailableError:
        reason = "oob_unavailable"

    from core.state import derive_state

    decision = derive_state(
        severity="high",
        confidence=0.8,
        validation={"attempted": True, "outcome": "unavailable"},
        detection_methods=[{"method": "m", "independence_class": "http"}],
        no_verdict_reason=reason,
    )
    assert decision.state == "inconclusive"


def test_the_kill_switch_stops_a_scan_between_steps():
    switch = KillSwitch()
    ctx = ScanContext(killswitch=switch)

    ctx.check_alive()
    switch.kill(scan_id=ctx.scan_id, reason="operator")

    with pytest.raises(ScanKilledError):
        ctx.check_alive()


def test_killing_everything_stops_every_scan():
    switch = KillSwitch()
    ctx = ScanContext(killswitch=switch)

    switch.kill_all(reason="incident")

    with pytest.raises(ScanKilledError):
        ctx.check_alive()


def test_the_cost_meter_counts_from_the_first_request():
    ctx = ScanContext()

    ctx.cost.record_request()
    ctx.cost.record_request()

    assert ctx.cost.snapshot().requests == 2


def test_progress_is_reported_through_the_context():
    seen: list[tuple[str, float]] = []
    ctx = ScanContext(progress=lambda msg, frac: seen.append((msg, frac)))

    ctx.progress("resolving MX", 0.25)

    assert seen == [("resolving MX", 0.25)]
