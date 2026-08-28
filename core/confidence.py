"""The confidence engine.

Not a vibe. Two stages:

**Stage 1 - combine.** Each detection method has a prior reliability and each
piece of evidence a likelihood ratio, combined in log-odds:

    logit(P) = logit(prior) + sum(log(LR_i))

Methods sharing an `independence_class` collapse to their strongest single
contribution before combining, so three variants of one technique cannot
masquerade as corroboration.

**Stage 2 - calibrate.** The identity function until Phase 4. Everything this
module emits is `provisional`, and for low-volume buckets that may be
permanent - which the UI must say, rather than treating it as a milestone we
are waiting on.

Calibration is bucketed per **(scanner x detection_method)**, never per
`check_id`: a few hundred labels a year across ~150 checks would leave
per-check buckets undersampled forever and produce confident-looking noise.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any

MIN_LABELS_FOR_CALIBRATION = 30
"""Below this a fitted calibration is noise; the hand-assigned prior stands."""

VERSION_ONLY_CAP = 0.6
"""Version strings lie: distributions backport patches without bumping versions."""

_FLOOR = 1e-3
_CEILING = 1 - 1e-3


@dataclass(frozen=True)
class Signal:
    """One detection method's contribution."""

    method: str
    prior: float
    likelihood_ratio: float
    independence_class: str
    prior_justification: str

    def __post_init__(self) -> None:
        if not self.prior_justification.strip():
            raise ValueError(
                f"{self.method}: a prior needs a written justification before it ships"
            )
        if not 0.0 < self.prior < 1.0:
            raise ValueError(f"{self.method}: prior must be strictly between 0 and 1")
        if self.likelihood_ratio <= 0:
            raise ValueError(f"{self.method}: likelihood ratio must be positive")


@dataclass(frozen=True)
class ConfidenceResult:
    confidence: float
    detection_methods: list[dict[str, Any]]
    provisional: bool = True
    notes: list[str] = field(default_factory=list)


def bucket_key(*, scanner: str, method: str) -> str:
    return f"{scanner}:{method}"


def _logit(p: float) -> float:
    p = min(max(p, _FLOOR), _CEILING)
    return math.log(p / (1 - p))


def _sigmoid(x: float) -> float:
    return min(max(1 / (1 + math.exp(-x)), _FLOOR), _CEILING)


class ConfidenceEngine:
    def __init__(self) -> None:
        self._labels: dict[str, int] = {}

    def combine(self, signals: list[Signal], *, version_only: bool = False) -> ConfidenceResult:
        if not signals:
            raise ValueError("confidence needs at least one detection signal")

        strongest: dict[str, Signal] = {}
        for signal in signals:
            current = strongest.get(signal.independence_class)
            if current is None or abs(math.log(signal.likelihood_ratio)) > abs(
                math.log(current.likelihood_ratio)
            ):
                strongest[signal.independence_class] = signal

        surviving = list(strongest.values())
        base = max(surviving, key=lambda s: abs(math.log(s.likelihood_ratio)))
        log_odds = _logit(base.prior) + sum(math.log(s.likelihood_ratio) for s in surviving)
        confidence = _sigmoid(log_odds)

        notes: list[str] = []
        collapsed = len(signals) - len(surviving)
        if collapsed:
            notes.append(
                f"{collapsed} signal(s) collapsed: methods sharing an independence class "
                "corroborate nothing"
            )
        if version_only:
            if confidence > VERSION_ONLY_CAP:
                confidence = VERSION_ONLY_CAP
            notes.insert(
                0,
                "capped at 0.6: derived from a version string alone, and distributions "
                "backport patches without bumping versions",
            )

        return ConfidenceResult(
            confidence=round(confidence, 4),
            detection_methods=[
                {
                    "method": s.method,
                    "likelihood_ratio": s.likelihood_ratio,
                    "independence_class": s.independence_class,
                    "prior": s.prior,
                    "prior_justification": s.prior_justification,
                }
                for s in signals
            ],
            provisional=True,
            notes=notes,
        )

    def inherit(self, premise_confidences: list[float]) -> float:
        """Stage 0, before combine - confidence for a *derived* finding.

        ADR-018: a derived finding is a rule applied to something already
        detected, not a new observation. A calendar date is arithmetic, not
        evidence - pushing it through `combine()` would mean inventing a
        likelihood ratio to make the arithmetic clear the reporting
        threshold, which would corrupt the one thing that method exists to
        do (weighing genuine evidence).

        So a derived finding inherits confidence rather than earning it: it
        is never more confident than its premise. When a derivation chains
        from several premises, ADR-022's rule applies - confidence inherits
        from the weakest link, because a chain of claims is only as strong
        as the least certain one in it.
        """
        if not premise_confidences:
            raise ValueError("a derived finding needs at least one premise to inherit from")
        return min(premise_confidences)

    def calibrate(self, confidence: float, *, scanner: str, method: str) -> float:
        """The identity function until Phase 4, per docs/04-phase-0-foundations.md."""
        return confidence

    def record_labels(self, bucket: str, *, labelled: int) -> None:
        self._labels[bucket] = labelled

    def is_calibrated(self, bucket: str) -> bool:
        return self._labels.get(bucket, 0) >= MIN_LABELS_FOR_CALIBRATION
