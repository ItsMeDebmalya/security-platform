"""The confidence engine: log-odds combination, independence collapse, no calibration yet."""

from __future__ import annotations

import pytest

from core.confidence import ConfidenceEngine, Signal, bucket_key


def _signal(method, lr, cls, prior=0.5):
    return Signal(
        method=method,
        prior=prior,
        likelihood_ratio=lr,
        independence_class=cls,
        prior_justification=f"hand-assigned for {method}; provisional until Phase 4",
    )


DNS_PARSE = _signal("dns_txt_parse", 12.0, "dns")
DNS_VARIANT = _signal("dns_soa_probe", 4.0, "dns")
SMTP_PROBE = _signal("smtp_banner", 4.0, "smtp")


@pytest.fixture
def engine():
    return ConfidenceEngine()


def test_one_signal_moves_confidence_above_its_prior(engine):
    result = engine.combine([DNS_PARSE])

    assert 0.5 < result.confidence < 1.0


def test_a_signal_that_argues_against_lowers_confidence(engine):
    result = engine.combine([_signal("m", 0.1, "dns")])

    assert result.confidence < 0.5


def test_two_independent_signals_corroborate(engine):
    one = engine.combine([DNS_PARSE]).confidence
    both = engine.combine([DNS_PARSE, SMTP_PROBE]).confidence

    assert both > one


def test_two_signals_of_one_class_count_once(engine):
    """Three variants of one technique are one signal, not three."""
    alone = engine.combine([DNS_PARSE]).confidence
    with_variant = engine.combine([DNS_PARSE, DNS_VARIANT]).confidence

    assert with_variant == pytest.approx(alone)


def test_the_strongest_signal_in_a_class_is_the_one_that_counts(engine):
    weak_first = engine.combine([DNS_VARIANT, DNS_PARSE]).confidence
    strong_only = engine.combine([DNS_PARSE]).confidence

    assert weak_first == pytest.approx(strong_only)


def test_confidence_is_clamped_to_the_unit_interval(engine):
    huge = [_signal("m", 1e9, "dns", prior=0.99)]

    assert engine.combine(huge).confidence < 1.0


def test_combining_nothing_is_an_error(engine):
    with pytest.raises(ValueError, match="at least one"):
        engine.combine([])


# --- the version-string rule ------------------------------------------------


def test_a_version_only_finding_is_capped_at_point_six(engine):
    """Distributions backport patches without bumping versions."""
    result = engine.combine([DNS_PARSE, SMTP_PROBE], version_only=True)

    assert result.confidence <= 0.6


def test_the_version_cap_records_why_it_applied(engine):
    result = engine.combine([DNS_PARSE, SMTP_PROBE], version_only=True)

    assert "version" in result.notes[0]


# --- calibration ------------------------------------------------------------


def test_confidence_is_provisional_until_phase_4(engine):
    assert engine.combine([DNS_PARSE]).provisional is True


def test_calibration_is_the_identity_function_for_now(engine):
    assert engine.calibrate(0.73, scanner="email", method="dns_txt_parse") == 0.73


def test_calibration_buckets_are_per_scanner_and_method_never_per_check():
    assert bucket_key(scanner="email", method="dns_txt_parse") == "email:dns_txt_parse"


def test_a_bucket_below_the_labelled_sample_floor_keeps_its_prior(engine):
    """A fitted calibration needs >= 30 labelled outcomes; below that the prior stands."""
    engine.record_labels("email:dns_txt_parse", labelled=29)

    assert engine.is_calibrated("email:dns_txt_parse") is False


def test_a_bucket_at_the_sample_floor_becomes_calibratable(engine):
    engine.record_labels("email:dns_txt_parse", labelled=30)

    assert engine.is_calibrated("email:dns_txt_parse") is True


def test_the_detection_methods_a_finding_reports_come_from_the_signals(engine):
    result = engine.combine([DNS_PARSE, SMTP_PROBE])

    assert [m["method"] for m in result.detection_methods] == ["dns_txt_parse", "smtp_banner"]
    assert result.detection_methods[0]["independence_class"] == "dns"


def test_every_reported_method_carries_its_justified_prior(engine):
    """docs/10-measurement.md: a detection without a justified prior is not shippable."""
    result = engine.combine([DNS_PARSE])

    assert result.detection_methods[0]["prior_justification"]


def test_a_signal_without_a_justified_prior_is_refused():
    with pytest.raises(ValueError, match="justification"):
        Signal(
            method="m",
            prior=0.5,
            likelihood_ratio=2.0,
            independence_class="dns",
            prior_justification="  ",
        )
