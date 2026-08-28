"""The correlation pass — ADR-022 "Connect", docs/03-roadmap.md 0b.9.

After every scanner in a run has finished, this module reads the run's
findings plus its asset graph and emits `derived` "story" findings that
connect related findings into one attack story. It runs in `core/`, imports
no scanner, and is driven entirely by **composition rules loaded from
`config/composition_rules.yaml`** — curated, reviewed data, in the same
discipline `core/deprecation_calendar.py` established in 0b.7. There is no
scored heuristic and no graph traversal in this file; see the module
docstring on the data file for why that boundary is deliberate (ADR-014).

Two invariants this module must never violate:

- **Confidence is inherited, never recalculated.** `ConfidenceEngine.combine()`
  weighs genuine evidence; a composition rule is arithmetic over findings we
  already have, and pushing it through `combine()` would mean inventing a
  fake likelihood ratio, exactly the corruption ADR-018 exists to prevent.
  `ConfidenceEngine.inherit()` — the minimum of the premise confidences — is
  the only thing that may set a story's confidence.
- **A rule fires only when every one of its premises is present**, as an
  actual finding on the same asset, in a state that reflects a resolved
  verdict rather than an absent one (`confirmed`, `highly_likely`,
  `suspected` or `informational` — see `ELIGIBLE_PREMISE_STATES` below;
  `inconclusive` is the one state excluded). A partly-satisfied rule emits
  nothing. There is no hedged, half-drawn story: under-telling beats
  over-telling (ADR-022).
"""

from __future__ import annotations

from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

import yaml
from pydantic import Field, ValidationError

from core.assetgraph import AssetGraph
from core.confidence import ConfidenceEngine
from core.models import Asset, Finding, Strict

DEFAULT_PATH = Path("config/composition_rules.yaml")

CORRELATION_SCANNER = "correlation"
CORRELATION_SCANNER_VERSION = "0.1.0"

ELIGIBLE_PREMISE_STATES = frozenset({"confirmed", "highly_likely", "suspected", "informational"})
"""What counts as a usable premise.

`confirmed`/`highly_likely`/`suspected` are docs/10-measurement.md's
"reported positive" plus the honest hedge — a scanner making a claim, however
confident. `informational` also counts: docs/01-architecture.md's own words
for that state are "true but not directly dangerous" — a claim about the
finding *class*, not about how well it was proved. It is still an evidenced,
true observation (e.g. "this certificate carries no CT proof"), and several
real composition rules need exactly that kind of fact as a premise even
though it carries no severity of its own — `expiring-cert-blind-to-renewal`
is one.

Only `inconclusive` is excluded. That is the one state that means "no
verdict reached" - composing an absence of a verdict into a story would
manufacture certainty from not knowing, which is the actual failure
under-telling (ADR-022) guards against. `informational` never had that
problem: it is not a hedge on an unresolved question, it is a resolved,
low-severity fact.
"""


class CorrelationRulesError(ValueError):
    """A malformed, unjustified, or otherwise inadmissible rules file.

    Raised at load time, not discovered later — a rule that fails to parse
    must never be silently skipped (same discipline as
    core.deprecation_calendar.DeprecationCalendarError).
    """


class Premise(Strict):
    scanner: str = Field(min_length=1)
    check_id: str = Field(min_length=1)


class Conclusion(Strict):
    title: str = Field(min_length=1)
    severity: str = Field(min_length=1)
    description: str = Field(min_length=1)
    impact: str = Field(min_length=1)
    remediation: str = Field(min_length=1)
    references: list[str] = Field(default_factory=list)
    taxonomy: dict[str, list[str]] = Field(default_factory=dict)


class CompositionRule(Strict):
    """One hand-written composition rule.

    `premises` requires at least two entries: a "rule" with one premise is
    not a composition, it is a restatement of a single finding, and does
    not belong in this file.
    """

    id: str = Field(min_length=1)
    title: str = Field(min_length=1)
    premises: list[Premise] = Field(min_length=2)
    conclusion: Conclusion
    why: str = Field(min_length=1)
    reviewed_by: str = Field(min_length=1)
    reviewed_at: date


def _rule_from_row(row: Any, path: Path, *, index: int) -> CompositionRule:
    if not isinstance(row, dict):
        raise CorrelationRulesError(
            f"{path}: rule {index} is not a mapping, got {type(row).__name__}"
        )
    try:
        return CompositionRule(**row)
    except ValidationError as exc:
        rule_id = row.get("id", f"<no id, rule {index}>")
        raise CorrelationRulesError(f"{path}: rule {rule_id!r} is invalid: {exc}") from exc


def load_composition_rules(path: str | Path = DEFAULT_PATH) -> list[CompositionRule]:
    """Read and strictly validate the composition rules file.

    A missing file is an error, not an empty rule set — the same reasoning
    `DeprecationCalendar.load()` gives: either the file is meant to exist and
    does not (a deployment bug), or nothing calls this yet, in which case
    nothing should call `load()` either.
    """
    path = Path(path)
    if not path.exists():
        raise CorrelationRulesError(f"no composition rules file at {path}")

    raw = yaml.safe_load(path.read_text())
    if raw is None:
        raw = []
    if not isinstance(raw, list):
        raise CorrelationRulesError(
            f"{path}: expected a YAML list of rules, got {type(raw).__name__}"
        )

    rules = [_rule_from_row(row, path, index=i) for i, row in enumerate(raw)]

    seen_ids: set[str] = set()
    for rule in rules:
        if rule.id in seen_ids:
            raise CorrelationRulesError(f"{path}: duplicate rule id {rule.id!r}")
        seen_ids.add(rule.id)
    return rules


def _known_asset_values(asset_graph: AssetGraph, primary_target: Asset) -> set[str]:
    return {primary_target.value} | {a.asset.value for a in asset_graph.all()}


def _matches(finding: Finding, premise: Premise) -> bool:
    return (
        finding.scanner == premise.scanner
        and finding.matches_stored_check_id(premise.check_id)
        and finding.state in ELIGIBLE_PREMISE_STATES
    )


def _try_rule(rule: CompositionRule, findings_on_asset: list[Finding]) -> list[Finding] | None:
    """The premise findings satisfying `rule` on one asset, or None if any
    premise has no match. One matching finding is picked per premise — the
    first, for determinism — so a rule with N premises always chains
    exactly N findings, never fewer."""
    chosen: list[Finding] = []
    for premise in rule.premises:
        match = next((f for f in findings_on_asset if _matches(f, premise)), None)
        if match is None:
            return None
        chosen.append(match)
    return chosen


def correlate(
    *,
    findings: list[Finding],
    asset_graph: AssetGraph,
    primary_target: Asset,
    org_id: str,
    scan_id: str,
    rules: list[CompositionRule] | None = None,
    engine: ConfidenceEngine | None = None,
    now: datetime | None = None,
) -> list[Finding]:
    """Run the correlation pass over one run's findings.

    Groups findings by asset (`finding.target.value`). A group is only
    considered for a rule if its asset is either the run's own primary
    target or an asset present in `asset_graph` — i.e. an asset this run can
    actually account for the provenance of (ADR-019). This is the only use
    this module makes of the asset graph: it gates composition on a known,
    provenanced asset. It does not traverse the graph to discover new
    chains — that is exactly the boundary ADR-014 draws.

    Every returned `Finding` is `derivation="derived"`, with `derived_from`
    naming the comma-joined ids of the premise findings that produced it,
    and confidence set by `ConfidenceEngine.inherit()` over exactly those
    premises' confidences — never recomputed, never higher than the
    weakest one.
    """
    rules = rules if rules is not None else load_composition_rules()
    engine = engine or ConfidenceEngine()
    now = now or datetime.now(UTC)
    known_assets = _known_asset_values(asset_graph, primary_target)

    by_asset: dict[str, list[Finding]] = {}
    for finding in findings:
        by_asset.setdefault(finding.target.value, []).append(finding)

    stories: list[Finding] = []
    for asset_value, group in by_asset.items():
        if asset_value not in known_assets:
            continue
        for rule in rules:
            chosen = _try_rule(rule, group)
            if chosen is None:
                continue
            stories.append(
                _build_story(rule, chosen, org_id=org_id, scan_id=scan_id, now=now, engine=engine)
            )
    return stories


def _build_story(
    rule: CompositionRule,
    premises: list[Finding],
    *,
    org_id: str,
    scan_id: str,
    now: datetime,
    engine: ConfidenceEngine,
) -> Finding:
    confidence = engine.inherit([p.confidence for p in premises])
    derived_from = ",".join(sorted(p.id for p in premises))
    premise_lines = "\n".join(
        f"- {p.check_id} ({p.scanner}) at confidence {p.confidence}: {p.title}" for p in premises
    )

    return Finding.create(
        org_id=org_id,
        scanner=CORRELATION_SCANNER,
        scanner_version=CORRELATION_SCANNER_VERSION,
        check_id=rule.id,
        title=rule.conclusion.title,
        target=premises[0].target,
        location="$",
        severity=rule.conclusion.severity,
        confidence=confidence,
        confidence_provisional=True,
        detection_methods=[
            {
                "method": "composition_rule",
                "likelihood_ratio": 1.0,
                "independence_class": "derived_composition",
                "prior": 0.5,
                "prior_justification": (
                    "A derived finding's confidence is inherited (ADR-018/ADR-022), never "
                    "combined; this signal is a schema placeholder that contributes no "
                    "likelihood shift, kept neutral (LR=1.0) on purpose."
                ),
            }
        ],
        validation={"attempted": False, "outcome": "not_applicable"},
        evidence=[
            {
                "kind": "file_excerpt",
                "label": f"composition rule {rule.id}",
                "captured_at": now,
                "control_rationale": (
                    "A correlation makes no new observation of the target; its 'control' is "
                    "the premise findings themselves, already evidenced independently. This "
                    "is deliberately reported as no control (has_control()=False) rather than "
                    "borrowing the premises' controls as its own."
                ),
                "data": {
                    "rule_id": rule.id,
                    "rule_why": rule.why,
                    "premise_finding_ids": [p.id for p in premises],
                    "premises": premise_lines,
                },
            }
        ],
        description=rule.conclusion.description,
        impact=rule.conclusion.impact,
        remediation=rule.conclusion.remediation,
        references=list(rule.conclusion.references),
        taxonomy=dict(rule.conclusion.taxonomy),
        first_seen=now,
        first_seen_scan_id=scan_id,
        last_seen=now,
        last_seen_scan_id=scan_id,
        derivation="derived",
        derived_from=derived_from,
    )
