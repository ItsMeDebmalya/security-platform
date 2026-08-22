"""The five design checks from docs/04-phase-0-foundations.md, task 0.2.

These are the acceptance criteria for the Scanner Contract. The contract is
frozen once they pass; changing it afterwards is a migration, not an edit.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from core.models import Evidence, ScanError, ScanResult, Telemetry

NOW = datetime(2026, 8, 22, 9, 14, tzinfo=UTC)


# --- 1. Can a finding express "we tried and could not tell"? ----------------


def test_a_check_that_reached_no_verdict_is_expressible_as_inconclusive(make_finding):
    finding = make_finding(no_verdict_reason="servfail")

    assert finding.state == "inconclusive"


def test_inconclusive_requires_a_stated_reason(make_finding):
    """`inconclusive` with no reason is a shrug, not a result."""
    finding = make_finding()

    assert finding.state != "inconclusive"


# --- 2. Control-vs-test evidence, including the non-pair kinds --------------


def test_http_pair_evidence_carries_a_control_and_a_test():
    ev = Evidence.model_validate(
        {
            "kind": "http_pair",
            "label": "Boolean-based SQL injection: true vs false condition",
            "control": {
                "request": {"method": "GET", "url": "https://t/?id=1 AND 1=2"},
                "response": {"status": 200, "body": "", "headers": {}},
            },
            "test": {
                "request": {"method": "GET", "url": "https://t/?id=1 AND 1=1"},
                "response": {"status": 200, "body": "47 rows", "headers": {}},
            },
            "delta": {"status": "200 -> 200", "length": "8421 -> 122"},
            "payload_id": "sqli/boolean/or-1-1-v3",
            "captured_at": NOW,
            "redactions": ["set-cookie"],
        }
    )

    assert ev.has_control()


def test_oob_callback_evidence_expresses_its_control_as_unhit_tokens():
    """The control for an out-of-band callback is a token that was never hit."""
    ev = Evidence.model_validate(
        {
            "kind": "oob_callback",
            "label": "Blind SSRF via Location header",
            "token": "abc123",
            "emitted_in": "param=q",
            "emitted_at": NOW,
            "hit": {
                "received_at": NOW,
                "source_ip": "203.0.113.7",
                "protocol": "dns",
                "raw_request": "abc123.oob.example.invalid IN A",
            },
            "window_s": 60,
            "control_tokens_unhit": ["def456"],
            "captured_at": NOW,
        }
    )

    assert ev.has_control()


def test_oob_callback_without_an_unhit_control_token_is_rejected():
    with pytest.raises(ValueError):
        Evidence.model_validate(
            {
                "kind": "oob_callback",
                "label": "Blind SSRF via Location header",
                "token": "abc123",
                "emitted_in": "param=q",
                "emitted_at": NOW,
                "hit": None,
                "window_s": 60,
                "control_tokens_unhit": [],
                "captured_at": NOW,
            }
        )


def test_timing_evidence_expresses_its_control_as_baseline_samples():
    ev = Evidence.model_validate(
        {
            "kind": "timing",
            "label": "Time-based blind SQL injection",
            "baseline_samples_ms": [102, 98, 110, 101, 99, 104],
            "test_samples_ms": [5104, 5098, 5110, 5101, 5099, 5104],
            "n": 12,
            "delta_ms": 5000,
            "method": "welch_t",
            "p_value": 0.0001,
            "captured_at": NOW,
        }
    )

    assert ev.has_control()


def test_timing_evidence_with_a_single_sample_pair_is_rejected():
    """One before/after pair is not how timing is validated."""
    with pytest.raises(ValueError):
        Evidence.model_validate(
            {
                "kind": "timing",
                "label": "Time-based blind SQL injection",
                "baseline_samples_ms": [102],
                "test_samples_ms": [5104],
                "n": 2,
                "delta_ms": 5000,
                "method": "welch_t",
                "p_value": 0.0001,
                "captured_at": NOW,
            }
        )


# --- 3. Traceability to methods and payload --------------------------------


def test_a_finding_traces_to_every_contributing_method_with_its_independence_class(
    make_finding,
):
    finding = make_finding(
        detection_methods=[
            {
                "method": "dns_txt_parse",
                "likelihood_ratio": 12.0,
                "independence_class": "dns",
                "prior": 0.5,
                "prior_justification": "DMARC records are unambiguous when they parse",
            },
            {
                "method": "smtp_banner_probe",
                "likelihood_ratio": 3.0,
                "independence_class": "smtp",
                "prior": 0.4,
                "prior_justification": "banner corroborates the provider, weakly",
            },
        ]
    )

    assert [m.method for m in finding.detection_methods] == [
        "dns_txt_parse",
        "smtp_banner_probe",
    ]
    assert {m.independence_class for m in finding.detection_methods} == {"dns", "smtp"}


def test_a_detection_method_without_a_justified_prior_is_rejected(make_finding):
    """docs/10-measurement.md: no detection ships without a justified prior."""
    with pytest.raises(ValueError):
        make_finding(
            detection_methods=[
                {
                    "method": "dns_txt_parse",
                    "likelihood_ratio": 12.0,
                    "independence_class": "dns",
                    "prior": 0.5,
                    "prior_justification": "",
                }
            ]
        )


def test_a_finding_traces_to_the_payload_that_produced_it(make_finding):
    finding = make_finding(
        instance_key="sqli/boolean/or-1-1-v3",
        evidence=[
            {
                "kind": "http_pair",
                "label": "Boolean-based SQL injection",
                "control": {
                    "request": {"method": "GET", "url": "https://t/?id=1 AND 1=2"},
                    "response": {"status": 200, "body": "", "headers": {}},
                },
                "test": {
                    "request": {"method": "GET", "url": "https://t/?id=1 AND 1=1"},
                    "response": {"status": 200, "body": "47 rows", "headers": {}},
                },
                "payload_id": "sqli/boolean/or-1-1-v3",
                "captured_at": NOW,
            }
        ],
    )

    assert finding.payload_ids() == ["sqli/boolean/or-1-1-v3"]


# --- 4. Deterministic IDs ---------------------------------------------------


def test_the_same_finding_rescanned_keeps_its_id(make_finding):
    first = make_finding(first_seen_scan_id="01J8AAAAAAAAAAAAAAAAAAAAAA")
    second = make_finding(
        first_seen_scan_id="01J8BBBBBBBBBBBBBBBBBBBBBB",
        scanner_version="2.4.1",
        confidence=0.96,
    )

    assert first.id == second.id


def test_a_target_level_finding_uses_the_reserved_location(make_finding):
    target_level = make_finding(location="$")
    at_a_place = make_finding(location="_dmarc.example.com")

    assert target_level.id != at_a_place.id


def test_two_instances_of_one_check_at_one_location_get_different_ids(make_finding):
    first = make_finding(location="/search", instance_key="sqli/boolean/or-1-1-v3")
    second = make_finding(location="/search", instance_key="sqli/boolean/tautology-v1")

    assert first.id != second.id


def test_a_renamed_check_keeps_the_history_of_its_former_id(make_finding):
    renamed = make_finding(
        check_id="dmarc-policy-monitoring-only", renamed_from=["dmarc-policy-none"]
    )

    assert renamed.matches_stored_check_id("dmarc-policy-none")
    assert renamed.matches_stored_check_id("dmarc-policy-monitoring-only")
    assert not renamed.matches_stored_check_id("spf-missing")


def test_id_normalisation_ignores_volatile_parts_of_a_location(make_finding):
    with_session = make_finding(location="/search?q=a&sid=9f3a2b&_=17298312")
    without = make_finding(location="/search?q=a")

    assert with_session.id == without.id


# --- 5. Scan error vs inconclusive finding ---------------------------------


def _telemetry(**kw):
    base = {"checks_run": ["dmarc-policy-none"], "requests": 3, "wall_ms": 412}
    base.update(kw)
    return Telemetry.model_validate(base)


def test_a_scanner_that_cannot_execute_produces_zero_findings_and_an_error(make_finding):
    result = ScanResult(
        scanner="email",
        scanner_version="1.0.0",
        target={"type": "domain", "value": "example.com"},
        mode="light",
        findings=[],
        errors=[
            ScanError(
                stage="preflight",
                message="no resolver reachable",
                fatal=True,
            )
        ],
        telemetry=_telemetry(checks_run=[]),
    )

    assert result.outcome == "errored"


def test_a_fatal_error_alongside_findings_is_rejected(make_finding):
    with pytest.raises(ValueError):
        ScanResult(
            scanner="email",
            scanner_version="1.0.0",
            target={"type": "domain", "value": "example.com"},
            mode="light",
            findings=[make_finding()],
            errors=[ScanError(stage="preflight", message="no resolver reachable", fatal=True)],
            telemetry=_telemetry(),
        )


def test_a_check_that_ran_without_a_verdict_emits_an_inconclusive_finding(make_finding):
    result = ScanResult(
        scanner="email",
        scanner_version="1.0.0",
        target={"type": "domain", "value": "example.com"},
        mode="light",
        findings=[make_finding(no_verdict_reason="servfail")],
        errors=[],
        telemetry=_telemetry(),
    )

    assert result.outcome == "succeeded"
    assert [f.state for f in result.findings] == ["inconclusive"]


def test_a_check_that_ran_but_reported_nothing_at_all_is_rejected(make_finding):
    """Silently dropping a check that ran is the behaviour that destroys trust."""
    with pytest.raises(ValueError):
        ScanResult(
            scanner="email",
            scanner_version="1.0.0",
            target={"type": "domain", "value": "example.com"},
            mode="light",
            findings=[],
            errors=[],
            telemetry=_telemetry(checks_run=["dmarc-policy-none"]),
        )


def test_a_check_below_the_reporting_threshold_is_accounted_for_in_telemetry():
    result = ScanResult(
        scanner="email",
        scanner_version="1.0.0",
        target={"type": "domain", "value": "example.com"},
        mode="light",
        findings=[],
        errors=[],
        telemetry=_telemetry(
            suppressed=[
                {
                    "check_id": "dmarc-policy-none",
                    "location": "$",
                    "confidence": 0.22,
                    "reason": "below_reporting_threshold",
                }
            ]
        ),
    )

    assert result.outcome == "succeeded"
