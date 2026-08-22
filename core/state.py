"""The state-derivation function.

`state` is a pure function of severity, confidence, validation outcome and
detection-method independence. It is **computed here and nowhere else** — a
scanner that hand-sets `state` is a bug, because the calibration promise
depends on state being reproducible rather than an author's judgement.

The truth table is transcribed from docs/01-architecture.md. Two orderings
that document leaves implicit and this module fixes:

- The "< 0.40 is not reported" rule is a floor applied to *all* rows, checked
  after `inconclusive`. A failed validation caps confidence at 0.5, but it
  cannot lift a 0.2 detection into being reported at all.
- `informational` is decided before validation outcome: `severity: info` means
  "true but not directly dangerous", which is a claim about the finding class,
  not about how well we proved it.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Literal

State = Literal["confirmed", "highly_likely", "suspected", "informational", "inconclusive"]

REPORTING_THRESHOLD = 0.40
SUSPECTED_CEILING = 0.75
CONFIRMED_THRESHOLD = 0.95
FAILED_VALIDATION_CAP = 0.5


@dataclass(frozen=True)
class StateDecision:
    """The outcome of state derivation.

    `state is None` means the candidate is below the reporting threshold: it is
    logged to telemetry and never surfaces as a finding.
    """

    state: State | None
    confidence: float
    rule: str


def _attr(obj: object, name: str) -> Any:
    """Read a field from either a mapping or an object with attributes.

    Both shapes occur: pydantic models in production, plain dicts in tests and
    in JSON loaded straight off disk.
    """
    if isinstance(obj, Mapping):
        return obj.get(name)
    return getattr(obj, name, None)


def derive_state(
    *,
    severity: str,
    confidence: float,
    validation: object,
    detection_methods: Sequence[object],
    no_verdict_reason: str | None,
) -> StateDecision:
    if no_verdict_reason:
        return StateDecision("inconclusive", confidence, "no_verdict_reached")

    outcome = _attr(validation, "outcome")

    if outcome == "failed":
        confidence = min(confidence, FAILED_VALIDATION_CAP)

    if confidence < REPORTING_THRESHOLD:
        return StateDecision(None, confidence, "below_reporting_threshold")

    if severity == "info":
        return StateDecision("informational", confidence, "info_severity")

    if outcome == "failed":
        return StateDecision("suspected", confidence, "validation_failed")

    if outcome == "passed" and confidence >= CONFIRMED_THRESHOLD:
        return StateDecision("confirmed", confidence, "validated_and_high_confidence")

    classes = {_attr(m, "independence_class") for m in detection_methods}
    if confidence >= SUSPECTED_CEILING:
        if len(classes) >= 2:
            return StateDecision("highly_likely", confidence, "independent_corroboration")
        return StateDecision("suspected", confidence, "single_independence_class")

    return StateDecision("suspected", confidence, "middling_confidence")
