"""Precision, recall, and the accuracy gates. docs/10-measurement.md.

A scanner emits five states and a continuous confidence, which plain binary
precision/recall does not fit. The rules live here, once, so every scanner's
numbers stay comparable:

- **Reported positive** = `confirmed` or `highly_likely`. Those are the claims
  we make to a user, and they alone count in the gate.
- **`suspected`** is excluded and tracked. It is an honest hedge, not a claim.
  Counting it as a positive would punish the calibrated behaviour we want;
  counting it as a miss would push authors to over-claim.
- **`informational`** is excluded entirely - it is not a vulnerability claim.
- **`inconclusive`** is excluded from both sides and *capped*, because
  excluding it without a cap lets a scanner score perfect precision by
  declining to answer.

The gate is three numbers, never two: precision AND recall AND inconclusive
rate.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

REPORTED_STATES = frozenset({"confirmed", "highly_likely"})
DEFAULT_INCONCLUSIVE_MAX = 0.15

RecallDefinition = Literal["absolute", "corpus_relative"]
RECALL_LABELS = {
    "absolute": "absolute (the true set is knowable for this scanner)",
    "corpus_relative": "corpus-relative only - never publish this as absolute",
}


@dataclass(frozen=True)
class Expected:
    check_id: str
    location: str = "$"

    def key(self) -> tuple[str, str]:
        return (self.check_id, self.location)


@dataclass(frozen=True)
class Observation:
    check_id: str
    location: str
    state: str
    severity: str

    def key(self) -> tuple[str, str]:
        return (self.check_id, self.location)


@dataclass(frozen=True)
class CaseScore:
    tp: int = 0
    fp: int = 0
    fn: int = 0
    suspected: int = 0
    inconclusive: int = 0
    checks_run: int = 0


def score_case(
    *, observations: list[Observation], expected: list[Expected], checks_run: int
) -> CaseScore:
    expected_keys = {e.key() for e in expected}

    claimed = {o.key() for o in observations if o.state in REPORTED_STATES}
    hedged = {o.key() for o in observations if o.state == "suspected"}
    unresolved = {o.key() for o in observations if o.state == "inconclusive"}

    # An expectation the scanner hedged or could not resolve is neither a hit
    # nor a miss: it is excluded, and its rate is tracked instead.
    excused = hedged | unresolved

    return CaseScore(
        tp=len(claimed & expected_keys),
        fp=len(claimed - expected_keys),
        fn=len(expected_keys - claimed - excused),
        suspected=len(hedged),
        inconclusive=len(unresolved),
        checks_run=checks_run,
    )


@dataclass(frozen=True)
class TierSummary:
    tier: str
    tp: int
    fp: int
    fn: int
    suspected: int
    inconclusive: int
    checks_run: int
    cases: int

    @property
    def precision(self) -> float | None:
        """None, not 1.0, when nothing was claimed. A scanner that made no
        claims has no precision to report."""
        claimed = self.tp + self.fp
        return self.tp / claimed if claimed else None

    @property
    def recall(self) -> float | None:
        actual = self.tp + self.fn
        return self.tp / actual if actual else None

    @property
    def inconclusive_rate(self) -> float:
        return self.inconclusive / self.checks_run if self.checks_run else 0.0

    @property
    def suspected_rate(self) -> float:
        return self.suspected / self.checks_run if self.checks_run else 0.0

    @property
    def false_positives_on_known_good(self) -> int:
        """Anything reported on a known-good target is a false positive.

        Hedges count here, unlike in precision. On a target we know to be
        correctly configured there is nothing to be uncertain about, so a
        `suspected` finding is a false positive that happens to be wearing a
        hedge - and excluding it would leave an obvious place to hide one.
        `informational` and `inconclusive` are not counted: the first is not a
        claim, and the second is the scanner saying it could not tell.
        """
        if self.tier != "known_good":
            return 0
        return self.fp + self.suspected

    def to_dict(self) -> dict[str, object]:
        return {
            "tier": self.tier,
            "cases": self.cases,
            "checks_run": self.checks_run,
            "tp": self.tp,
            "fp": self.fp,
            "fn": self.fn,
            "precision": self.precision,
            "recall": self.recall,
            "suspected_rate": self.suspected_rate,
            "inconclusive_rate": self.inconclusive_rate,
            "false_positives_on_known_good": self.false_positives_on_known_good,
        }


def summarise(scores_by_tier: dict[str, list[CaseScore]]) -> dict[str, TierSummary]:
    summaries: dict[str, TierSummary] = {}
    for tier, scores in scores_by_tier.items():
        summaries[tier] = TierSummary(
            tier=tier,
            tp=sum(s.tp for s in scores),
            fp=sum(s.fp for s in scores),
            fn=sum(s.fn for s in scores),
            suspected=sum(s.suspected for s in scores),
            inconclusive=sum(s.inconclusive for s in scores),
            checks_run=sum(s.checks_run for s in scores),
            cases=len(scores),
        )
    return summaries


@dataclass(frozen=True)
class GateResult:
    passed: bool
    reason: str


@dataclass(frozen=True)
class Gate:
    precision: float
    recall: float
    inconclusive_max: float = DEFAULT_INCONCLUSIVE_MAX
    recall_definition: RecallDefinition = "absolute"
    notes: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.recall_definition not in RECALL_LABELS:
            raise ValueError(
                f"recall_definition must be one of {sorted(RECALL_LABELS)}; "
                "a recall number whose meaning is unstated is the kind of dishonesty "
                "this product exists to avoid"
            )

    @property
    def recall_label(self) -> str:
        return RECALL_LABELS[self.recall_definition]

    def evaluate(self, summary: TierSummary) -> GateResult:
        failures: list[str] = []
        if summary.precision is None or summary.precision < self.precision:
            failures.append(f"precision {_fmt(summary.precision)} < {self.precision:.3f}")
        if summary.recall is None or summary.recall < self.recall:
            failures.append(f"recall {_fmt(summary.recall)} < {self.recall:.3f}")
        if summary.inconclusive_rate > self.inconclusive_max:
            failures.append(
                f"inconclusive rate {summary.inconclusive_rate:.3f} > {self.inconclusive_max:.3f}"
            )
        if failures:
            return GateResult(False, "; ".join(failures))
        return GateResult(True, "pass")


def _fmt(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.3f}"
