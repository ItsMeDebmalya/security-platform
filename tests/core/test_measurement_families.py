from core.measurement import (
    Expected,
    Gate,
    Observation,
    score_case,
    summarise,
)

ENUM = frozenset({"subdomains-ct-log", "dns-records"})


def test_score_case_buckets_by_family() -> None:
    obs = [
        Observation("dns-records", "api.x.test", "highly_likely", "info"),  # enum TP
        Observation("dnssec-status", "$", "highly_likely", "medium"),  # finite TP
    ]
    exp = [
        Expected("dns-records", "api.x.test"),
        Expected("dnssec-status", "$"),
        Expected("subdomains-ct-log", "gone.x.test"),
    ]  # enum FN (never found)
    score = score_case(observations=obs, expected=exp, checks_run=3, enumeration_check_ids=ENUM)
    assert (score.tp_enum, score.fn_enum) == (1, 1)
    assert (score.tp_finite, score.fn_finite) == (1, 0)
    # combined totals unchanged by the split
    assert score.tp == 2 and score.fn == 1


def test_tier_summary_family_properties_and_gate() -> None:
    obs = [Observation("dns-records", "a.x.test", "highly_likely", "info")]
    exp = [Expected("dns-records", "a.x.test"), Expected("subdomains-ct-log", "b.x.test")]
    score = score_case(observations=obs, expected=exp, checks_run=2, enumeration_check_ids=ENUM)
    summary = summarise({"frozen": [score]})["frozen"]
    assert summary.recall_enumeration == 0.5  # 1 of 2 enum found
    assert summary.recall_finite is None  # no finite expectations
    gate = Gate(
        precision=0.95,
        recall=0.80,
        recall_definition="corpus_relative",
        finite={"precision": 0.95, "recall": 0.95},
        enumeration_check_ids=list(ENUM),
    )
    result = gate.evaluate(summary)
    assert result.passed is False  # enum recall 0.5 < 0.80
    assert "enumeration recall" in result.reason
