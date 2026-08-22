"""One test per row of the state-derivation truth table in docs/01-architecture.md.

State is a pure function. Scanners never set it by hand.
"""

from __future__ import annotations

import pytest

from core.state import derive_state

DNS = {"method": "dns_txt_parse", "independence_class": "dns"}
SMTP = {"method": "smtp_probe", "independence_class": "smtp"}
DNS_VARIANT = {"method": "dns_soa_probe", "independence_class": "dns"}

PASSED = {"attempted": True, "outcome": "passed", "method": "independent_reparse"}
FAILED = {"attempted": True, "outcome": "failed", "method": "independent_reparse"}
UNAVAILABLE = {"attempted": True, "outcome": "unavailable", "method": "oob_callback"}
NOT_ATTEMPTED = {"attempted": False, "outcome": "not_applicable", "method": None}


def test_row_1_no_verdict_reached_is_inconclusive():
    d = derive_state(
        severity="medium",
        confidence=0.9,
        validation=PASSED,
        detection_methods=[DNS, SMTP],
        no_verdict_reason="waf_block",
    )

    assert d.state == "inconclusive"


def test_row_1_covers_an_unavailable_oob_callback():
    """A scanner whose OOB prerequisite is missing says inconclusive, never guesses."""
    d = derive_state(
        severity="high",
        confidence=0.8,
        validation=UNAVAILABLE,
        detection_methods=[DNS],
        no_verdict_reason="oob_unavailable",
    )

    assert d.state == "inconclusive"


def test_row_2_info_severity_is_informational():
    d = derive_state(
        severity="info",
        confidence=0.99,
        validation=PASSED,
        detection_methods=[DNS, SMTP],
        no_verdict_reason=None,
    )

    assert d.state == "informational"


def test_row_3_failed_validation_is_suspected_and_caps_confidence_at_half():
    d = derive_state(
        severity="high",
        confidence=0.98,
        validation=FAILED,
        detection_methods=[DNS, SMTP],
        no_verdict_reason=None,
    )

    assert d.state == "suspected"
    assert d.confidence == 0.5


def test_row_4_passed_validation_at_high_confidence_is_confirmed():
    d = derive_state(
        severity="high",
        confidence=0.96,
        validation=PASSED,
        detection_methods=[DNS],
        no_verdict_reason=None,
    )

    assert d.state == "confirmed"


def test_confirmed_requires_validation_to_have_actually_run():
    """A high score alone never earns `confirmed`."""
    d = derive_state(
        severity="high",
        confidence=0.99,
        validation=NOT_ATTEMPTED,
        detection_methods=[DNS, SMTP],
        no_verdict_reason=None,
    )

    assert d.state == "highly_likely"


def test_row_5_two_independent_methods_above_threshold_are_highly_likely():
    d = derive_state(
        severity="medium",
        confidence=0.8,
        validation=NOT_ATTEMPTED,
        detection_methods=[DNS, SMTP],
        no_verdict_reason=None,
    )

    assert d.state == "highly_likely"


def test_row_6_three_variants_of_one_technique_are_one_signal_restated():
    d = derive_state(
        severity="medium",
        confidence=0.9,
        validation=NOT_ATTEMPTED,
        detection_methods=[DNS, DNS_VARIANT],
        no_verdict_reason=None,
    )

    assert d.state == "suspected"


def test_row_7_middling_confidence_is_suspected():
    d = derive_state(
        severity="medium",
        confidence=0.55,
        validation=NOT_ATTEMPTED,
        detection_methods=[DNS, SMTP],
        no_verdict_reason=None,
    )

    assert d.state == "suspected"


def test_row_8_below_threshold_is_not_reported_as_a_finding():
    d = derive_state(
        severity="medium",
        confidence=0.31,
        validation=NOT_ATTEMPTED,
        detection_methods=[DNS],
        no_verdict_reason=None,
    )

    assert d.state is None
    assert d.rule == "below_reporting_threshold"


@pytest.mark.parametrize(
    ("confidence", "expected"),
    [(0.39, None), (0.40, "suspected"), (0.74, "suspected"), (0.75, "highly_likely")],
)
def test_the_thresholds_are_inclusive_at_the_stated_boundaries(confidence, expected):
    d = derive_state(
        severity="medium",
        confidence=confidence,
        validation=NOT_ATTEMPTED,
        detection_methods=[DNS, SMTP],
        no_verdict_reason=None,
    )

    assert d.state == expected


def test_a_finding_below_threshold_stays_unreported_even_when_validation_failed():
    d = derive_state(
        severity="high",
        confidence=0.2,
        validation=FAILED,
        detection_methods=[DNS],
        no_verdict_reason=None,
    )

    assert d.state is None
