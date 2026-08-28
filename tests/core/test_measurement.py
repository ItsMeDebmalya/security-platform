"""How precision, recall and the gates are computed. docs/10-measurement.md.

A scanner emits five states and a continuous confidence, which plain binary
precision/recall does not fit. These rules are the answer, in one place, so
every scanner's numbers stay comparable.
"""

from __future__ import annotations

import pytest

from core.measurement import CaseScore, Expected, Gate, Observation, score_case, summarise


def _obs(check_id, state, location="$", severity="medium", derivation="detected"):
    return Observation(
        check_id=check_id,
        location=location,
        state=state,
        severity=severity,
        derivation=derivation,
    )


def _expected(*pairs):
    return [Expected(check_id=c, location=loc) for c, loc in pairs]


# --- what counts as a claim -------------------------------------------------


def test_a_confirmed_finding_in_the_expected_set_is_a_true_positive():
    score = score_case(
        observations=[_obs("dmarc-policy-none", "confirmed")],
        expected=_expected(("dmarc-policy-none", "$")),
        checks_run=1,
    )

    assert (score.tp, score.fp, score.fn) == (1, 0, 0)


def test_a_highly_likely_finding_is_also_a_claim():
    score = score_case(
        observations=[_obs("dmarc-policy-none", "highly_likely")],
        expected=_expected(("dmarc-policy-none", "$")),
        checks_run=1,
    )

    assert score.tp == 1


def test_a_claim_that_is_not_expected_is_a_false_positive():
    score = score_case(
        observations=[_obs("spf-missing", "confirmed")],
        expected=_expected(("dmarc-policy-none", "$")),
        checks_run=2,
    )

    assert (score.tp, score.fp, score.fn) == (0, 1, 1)


def test_something_expected_and_never_reported_is_a_false_negative():
    score = score_case(observations=[], expected=_expected(("spf-missing", "$")), checks_run=1)

    assert score.fn == 1


def test_location_is_part_of_the_identity_of_a_claim():
    score = score_case(
        observations=[_obs("missing-header", "confirmed", location="/admin")],
        expected=_expected(("missing-header", "/login")),
        checks_run=1,
    )

    assert (score.tp, score.fp, score.fn) == (0, 1, 1)


# --- the hedges -------------------------------------------------------------


def test_a_suspected_finding_is_excluded_from_the_gate_and_tracked():
    score = score_case(
        observations=[_obs("dmarc-policy-none", "suspected")],
        expected=_expected(("dmarc-policy-none", "$")),
        checks_run=1,
    )

    assert (score.tp, score.fp) == (0, 0)
    assert score.suspected == 1


def test_a_suspected_finding_for_something_expected_is_not_counted_as_a_miss():
    """Counting the hedge as a miss would push authors to over-claim."""
    score = score_case(
        observations=[_obs("dmarc-policy-none", "suspected")],
        expected=_expected(("dmarc-policy-none", "$")),
        checks_run=1,
    )

    assert score.fn == 0


def test_an_informational_finding_is_excluded_entirely():
    score = score_case(
        observations=[_obs("dkim-selector-found", "informational", severity="info")],
        expected=[],
        checks_run=1,
    )

    assert (score.tp, score.fp, score.fn, score.suspected) == (0, 0, 0, 0)


def test_an_inconclusive_finding_is_in_neither_numerator_nor_denominator():
    score = score_case(
        observations=[_obs("dmarc-policy-none", "inconclusive")],
        expected=_expected(("dmarc-policy-none", "$")),
        checks_run=1,
    )

    assert (score.tp, score.fp, score.fn) == (0, 0, 0)
    assert score.inconclusive == 1


# --- aggregation ------------------------------------------------------------


def _summary(scores, tier="frozen", **kw):
    return summarise({tier: scores}, **kw)[tier]


def test_precision_is_true_positives_over_everything_claimed():
    summary = _summary([CaseScore(tp=3, fp=1, fn=0, suspected=0, inconclusive=0, checks_run=4)])

    assert summary.precision == pytest.approx(0.75)


def test_recall_is_true_positives_over_everything_that_was_there():
    summary = _summary([CaseScore(tp=3, fp=0, fn=1, suspected=0, inconclusive=0, checks_run=4)])

    assert summary.recall == pytest.approx(0.75)


def test_the_inconclusive_rate_is_over_every_check_that_ran():
    summary = _summary([CaseScore(tp=1, fp=0, fn=0, suspected=0, inconclusive=3, checks_run=20)])

    assert summary.inconclusive_rate == pytest.approx(0.15)


def test_a_scanner_that_claimed_nothing_has_no_precision_rather_than_a_perfect_one():
    summary = _summary([CaseScore(tp=0, fp=0, fn=0, suspected=2, inconclusive=0, checks_run=2)])

    assert summary.precision is None


# --- the gate ---------------------------------------------------------------


GATE = Gate(precision=0.99, recall=0.95, inconclusive_max=0.15)


def test_a_scanner_meeting_all_three_numbers_passes():
    summary = _summary([CaseScore(tp=100, fp=0, fn=2, suspected=0, inconclusive=5, checks_run=200)])

    assert GATE.evaluate(summary).passed


def test_falling_precision_fails_the_gate():
    summary = _summary([CaseScore(tp=90, fp=10, fn=0, suspected=0, inconclusive=0, checks_run=100)])

    assert not GATE.evaluate(summary).passed
    assert "precision" in GATE.evaluate(summary).reason


def test_falling_recall_fails_the_gate():
    summary = _summary([CaseScore(tp=50, fp=0, fn=50, suspected=0, inconclusive=0, checks_run=100)])

    assert not GATE.evaluate(summary).passed


def test_shrugging_at_everything_fails_the_gate_however_good_the_precision():
    """Excluding inconclusive without capping it lets a scanner score perfectly
    by declining to answer."""
    summary = _summary([CaseScore(tp=1, fp=0, fn=0, suspected=0, inconclusive=50, checks_run=100)])

    assert not GATE.evaluate(summary).passed
    assert "inconclusive" in GATE.evaluate(summary).reason


# --- the known-good tier ----------------------------------------------------


def test_a_single_finding_on_a_known_good_target_is_a_failure():
    """No threshold. Anything reported on a correctly configured asset is a
    false positive by definition."""
    summaries = summarise(
        {"known_good": [CaseScore(tp=0, fp=1, fn=0, suspected=0, inconclusive=0, checks_run=10)]}
    )

    assert summaries["known_good"].false_positives_on_known_good == 1


def test_a_hedged_finding_on_a_known_good_target_is_still_a_false_positive():
    """There is nothing to be uncertain about on a target we know is correct,
    so `suspected` would otherwise be a place to hide a false positive."""
    summaries = summarise(
        {"known_good": [CaseScore(tp=0, fp=0, fn=0, suspected=1, inconclusive=0, checks_run=10)]}
    )

    assert summaries["known_good"].false_positives_on_known_good == 1


def test_an_inconclusive_on_a_known_good_target_is_not_a_false_positive():
    summaries = summarise(
        {"known_good": [CaseScore(tp=0, fp=0, fn=0, suspected=0, inconclusive=1, checks_run=10)]}
    )

    assert summaries["known_good"].false_positives_on_known_good == 0


def test_a_hedge_on_a_vulnerable_target_is_not_a_false_positive():
    summaries = summarise(
        {"vulnerable": [CaseScore(tp=0, fp=0, fn=0, suspected=1, inconclusive=0, checks_run=10)]}
    )

    assert summaries["vulnerable"].false_positives_on_known_good == 0


def test_a_clean_known_good_tier_reports_no_false_positives():
    summaries = summarise(
        {"known_good": [CaseScore(tp=0, fp=0, fn=0, suspected=0, inconclusive=0, checks_run=10)]}
    )

    assert summaries["known_good"].false_positives_on_known_good == 0


# --- honesty about recall ---------------------------------------------------


def test_a_gate_must_state_whether_its_recall_is_absolute_or_corpus_relative():
    with pytest.raises(ValueError, match="recall_definition"):
        Gate(precision=0.95, recall=0.8, inconclusive_max=0.15, recall_definition="unstated")


def test_corpus_relative_recall_is_labelled_as_such_in_the_report():
    gate = Gate(
        precision=0.95, recall=0.8, inconclusive_max=0.15, recall_definition="corpus_relative"
    )

    assert "corpus" in gate.recall_label.lower()


# --- detected vs derived claim counts (ADR-018) -----------------------------
#
# docs/10-measurement.md: "precision 1.000 across derived claims is a weaker
# statement than the same figure across detected ones... report the split;
# never merge them into one number." This never changes tp/fp/fn or what the
# gate passes on - it only tells the two apart within them.


def test_an_observation_defaults_to_detected():
    """Every observation from before v3.4 carries no derivation - it must
    still score as a detected claim, unchanged."""
    score = score_case(
        observations=[_obs("dmarc-policy-none", "confirmed")],
        expected=_expected(("dmarc-policy-none", "$")),
        checks_run=1,
    )

    assert (score.tp_detected, score.tp_derived) == (1, 0)


def test_a_derived_true_positive_is_counted_in_the_derived_bucket_only():
    score = score_case(
        observations=[_obs("cert-lifetime-noncompliant-2027", "confirmed", derivation="derived")],
        expected=_expected(("cert-lifetime-noncompliant-2027", "$")),
        checks_run=1,
    )

    assert (score.tp, score.tp_detected, score.tp_derived) == (1, 0, 1)


def test_a_derived_false_positive_is_counted_in_the_derived_bucket_only():
    score = score_case(
        observations=[_obs("cert-lifetime-noncompliant-2027", "confirmed", derivation="derived")],
        expected=[],
        checks_run=1,
    )

    assert (score.fp, score.fp_detected, score.fp_derived) == (1, 0, 1)


def test_the_combined_tp_fp_are_unaffected_by_the_split():
    score = score_case(
        observations=[
            _obs("dmarc-policy-none", "confirmed", derivation="detected"),
            _obs("cert-lifetime-noncompliant-2027", "confirmed", derivation="derived"),
        ],
        expected=_expected(("dmarc-policy-none", "$"), ("cert-lifetime-noncompliant-2027", "$")),
        checks_run=2,
    )

    assert (score.tp, score.tp_detected, score.tp_derived) == (2, 1, 1)


def test_precision_detected_and_precision_derived_are_reported_separately():
    summary = _summary(
        [
            CaseScore(
                tp=3,
                fp=1,
                tp_detected=2,
                fp_detected=0,
                tp_derived=1,
                fp_derived=1,
                checks_run=4,
            )
        ]
    )

    assert summary.precision == pytest.approx(0.75)
    assert summary.precision_detected == pytest.approx(1.0)
    assert summary.precision_derived == pytest.approx(0.5)


def test_a_tier_with_no_derived_claims_reports_no_derived_precision():
    summary = _summary([CaseScore(tp=1, fp=0, tp_detected=1, checks_run=1)])

    assert summary.precision_derived is None


def test_the_gate_still_evaluates_off_the_combined_number_not_the_split():
    """0b.1 does not change what the gate passes or fails on - only detected
    findings exist in the shipped scanners today, so the combined and
    detected-only numbers agree, and the gate must still read the combined
    one."""
    summary = _summary(
        [CaseScore(tp=100, fp=0, fn=2, tp_detected=100, checks_run=200, inconclusive=5)]
    )

    assert GATE.evaluate(summary).passed


def test_to_dict_carries_the_detected_derived_breakdown():
    summary = _summary([CaseScore(tp=2, fp=0, tp_detected=1, tp_derived=1, checks_run=2)])

    claims = summary.to_dict()["claims"]
    assert claims["detected"]["tp"] == 1
    assert claims["derived"]["tp"] == 1
