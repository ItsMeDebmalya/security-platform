"""`make corpus` - run every scanner against its ground-truth corpus and score it.

This is the gate. A scanner is not done because it runs; it is done when it
hits its three numbers on targets whose right answer we already know.

Everything CI gates on runs from frozen fixtures (`source: frozen`), replayed
offline: corpus tests that hit the live internet are slow, flaky, and rude to
third parties.

CI compares against `corpus/results/baseline.json` and fails on:
  - any drop in precision
  - any rise in the inconclusive rate on the frozen tier
  - any new false positive on a known-good target - a single one, no threshold

A recall drop warns rather than fails: a recall regression is usually a
deliberate precision trade, and failing it would push authors to over-report.
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import typer
import yaml

from core.assetgraph import seed_asset_graph
from core.authz import Scope
from core.context import ScanContext
from core.dns import DnsClient, MissingFixtureError, ReplayResolver
from core.measurement import (
    CaseScore,
    Expected,
    Gate,
    Observation,
    score_case,
    summarise,
)
from core.models import Asset, ScanResult
from core.registry import discover
from core.tls import MissingHandshakeError, ReplayTlsBackend, TlsClient

ROOT = Path(__file__).resolve().parents[1]
TARGETS_DIR = ROOT / "corpus" / "targets"
EXPECTED_DIR = ROOT / "corpus" / "expected"
RESULTS_DIR = ROOT / "corpus" / "results"
BASELINE = RESULTS_DIR / "baseline.json"
LATEST = RESULTS_DIR / "latest.json"

app = typer.Typer(add_completion=False)


@dataclass
class CaseOutcome:
    case_id: str
    tier: str
    score: CaseScore
    inconclusive_expected: bool
    inconclusive_delivered: bool
    errors: list[str]


def _load(path: Path) -> Any:
    return yaml.safe_load(path.read_text())


def _run_case(scanner_name: str, case: dict[str, Any]) -> ScanResult:
    scanner = discover().get(scanner_name)()
    target = Asset(**case["target"])
    fixtures = ROOT / case["fixtures"]
    ctx = ScanContext(
        dns=DnsClient(resolver=ReplayResolver(fixtures), resolvers=["1.1.1.1", "8.8.8.8"]),
        tls=TlsClient(scope=Scope.for_target(target), backend=ReplayTlsBackend(fixtures)),
        assets=seed_asset_graph(case.get("seed_assets", []) or []),
        progress=lambda message, fraction: None,
    )
    return scanner.run(target, case.get("mode", "light"), ctx)


def _score(result: ScanResult, expected: list[dict[str, str]]) -> CaseScore:
    return score_case(
        observations=[
            Observation(
                check_id=f.check_id,
                location=f.location,
                state=f.state,
                severity=f.severity,
                derivation=f.derivation,
            )
            for f in result.findings
        ],
        expected=[Expected(**e) for e in expected],
        checks_run=len(result.telemetry.checks_run),
    )


def run_scanner_corpus(
    scanner_name: str, targets_dir: Path | None = None, expected_dir: Path | None = None
) -> dict[str, Any]:
    definition = _load((targets_dir or TARGETS_DIR) / f"{scanner_name}.yaml")
    expected_by_case = _load((expected_dir or EXPECTED_DIR) / f"{scanner_name}.yaml") or {}
    gate = Gate(**definition["gate"])

    outcomes: list[CaseOutcome] = []
    expected_by_case_id: dict[str, list[dict[str, str]]] = {}
    for case in definition["cases"]:
        try:
            result = _run_case(scanner_name, case)
        except (MissingFixtureError, MissingHandshakeError) as exc:
            # The scanner now asks a question the frozen fixtures cannot
            # answer. That is a normal thing to happen while changing a
            # scanner, and it means "re-record", not "the scanner is broken".
            outcomes.append(
                CaseOutcome(
                    case_id=case["id"],
                    tier=case["tier"],
                    score=CaseScore(),
                    inconclusive_expected=False,
                    inconclusive_delivered=False,
                    errors=[f"fixtures do not cover this scanner version: {exc}"],
                )
            )
            continue
        expects_inconclusive = bool(case.get("expect_inconclusive"))
        expected_by_case_id[case["id"]] = expected_by_case.get(case["id"], []) or []
        score = _score(result, expected_by_case_id[case["id"]])
        delivered = any(f.state == "inconclusive" for f in result.findings)

        if expects_inconclusive:
            # Excluded from the rate: docs/10-measurement.md measures the
            # inconclusive rate where a definite answer is expected, and here
            # one is not. The case is asserted separately instead.
            score = CaseScore(
                tp=score.tp,
                fp=score.fp,
                fn=score.fn,
                suspected=score.suspected,
                inconclusive=0,
                checks_run=0,
            )

        outcomes.append(
            CaseOutcome(
                case_id=case["id"],
                tier=case["tier"],
                score=score,
                inconclusive_expected=expects_inconclusive,
                inconclusive_delivered=delivered,
                errors=[e.message for e in result.errors],
            )
        )

    by_tier: dict[str, list[CaseScore]] = {}
    for outcome in outcomes:
        by_tier.setdefault(outcome.tier, []).append(outcome.score)
    summaries = summarise(by_tier)

    overall = summarise({"all": [o.score for o in outcomes]})["all"]
    gate_result = gate.evaluate(overall)

    known_good_fps = sum(s.false_positives_on_known_good for s in summaries.values())

    unmet = [
        o.case_id for o in outcomes if o.inconclusive_expected and not o.inconclusive_delivered
    ]
    errored = [o.case_id for o in outcomes if o.errors]

    return {
        "scanner": scanner_name,
        "gate": {
            "precision": gate.precision,
            "recall": gate.recall,
            "inconclusive_max": gate.inconclusive_max,
            "recall_definition": gate.recall_definition,
            "recall_label": gate.recall_label,
        },
        "overall": overall.to_dict(),
        "tiers": {name: summary.to_dict() for name, summary in summaries.items()},
        "cases": [
            {
                "id": o.case_id,
                "tier": o.tier,
                "tp": o.score.tp,
                "fp": o.score.fp,
                "fn": o.score.fn,
                "inconclusive": o.score.inconclusive,
                "expected": expected_by_case_id.get(o.case_id, []),
                "expect_inconclusive": o.inconclusive_expected,
                "inconclusive_delivered": o.inconclusive_delivered,
                "errors": o.errors,
            }
            for o in outcomes
        ],
        "passed": gate_result.passed and not unmet and not errored and not known_good_fps,
        "reason": _reason(gate_result.reason, unmet, errored, known_good_fps),
        "false_positives_on_known_good": known_good_fps,
    }


def _reason(gate_reason: str, unmet: list[str], errored: list[str], known_good_fps: int = 0) -> str:
    parts = [] if gate_reason == "pass" else [gate_reason]
    if known_good_fps:
        parts.append(
            f"{known_good_fps} finding(s) on a known-good target, where anything "
            "reported is a false positive by definition"
        )
    if unmet:
        parts.append(f"cases that must be inconclusive were not: {', '.join(unmet)}")
    if errored:
        parts.append(
            f"cases that errored: {', '.join(errored)}. If the fixtures do not cover a "
            "query the scanner now makes, re-record them "
            "(uv run python -m corpus.generators.<scanner>)."
        )
    return "; ".join(parts) or "pass"


def _print_report(reports: list[dict[str, Any]]) -> None:
    header = (
        f"{'scanner':<10} {'checks':>7} {'TP':>4} {'FP':>4} {'FN':>4} "
        f"{'precision':>10} {'recall':>8} {'susp%':>7} {'inconc%':>8}  gate"
    )
    print(header)
    print("-" * len(header))
    for report in reports:
        overall = report["overall"]
        print(
            f"{report['scanner']:<10} {overall['checks_run']:>7} {overall['tp']:>4} "
            f"{overall['fp']:>4} {overall['fn']:>4} "
            f"{_fmt(overall['precision']):>10} {_fmt(overall['recall']):>8} "
            f"{overall['suspected_rate']:>6.1%} {overall['inconclusive_rate']:>7.1%}  "
            f"{'PASS' if report['passed'] else 'FAIL'}"
        )
        print(f"{'':<10} recall is {report['gate']['recall_label']}")
        if not report["passed"]:
            for line in report["reason"].split("; "):
                print(f"{'':<10} why: {line}")


def _fmt(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.3f}"


def _regressions(current: list[dict[str, Any]], baseline: list[dict[str, Any]]) -> list[str]:
    """What fails the build when compared against the committed baseline."""
    by_name = {report["scanner"]: report for report in baseline}
    problems: list[str] = []
    for report in current:
        name = report["scanner"]
        previous = by_name.get(name)
        if previous is None:
            continue
        now, before = report["overall"], previous["overall"]

        if (
            now["precision"] is not None
            and before["precision"] is not None
            and now["precision"] < before["precision"] - 1e-9
        ):
            problems.append(
                f"{name}: precision fell {before['precision']:.3f} -> {now['precision']:.3f}"
            )
        if now["inconclusive_rate"] > before["inconclusive_rate"] + 1e-9:
            problems.append(
                f"{name}: inconclusive rate rose "
                f"{before['inconclusive_rate']:.3f} -> {now['inconclusive_rate']:.3f}"
            )
        if report["false_positives_on_known_good"] > previous.get(
            "false_positives_on_known_good", 0
        ):
            problems.append(
                f"{name}: {report['false_positives_on_known_good']} false positive(s) on a "
                "known-good target. A single one fails the build."
            )
        if (
            now["recall"] is not None
            and before["recall"] is not None
            and now["recall"] < before["recall"] - 1e-9
        ):
            print(
                f"warning: {name}: recall fell {before['recall']:.3f} -> {now['recall']:.3f}",
                file=sys.stderr,
            )
    return problems


@app.command()
def main(
    scanner: str | None = typer.Option(None, "--scanner", help="Only this scanner"),
    check_baseline: bool = typer.Option(
        False, "--check-baseline", help="Fail on any regression against the committed baseline"
    ),
    update_baseline: bool = typer.Option(
        False, "--update-baseline", help="Rewrite the baseline from this run"
    ),
) -> None:
    names = [scanner] if scanner else sorted(p.stem for p in TARGETS_DIR.glob("*.yaml"))
    reports = [run_scanner_corpus(name) for name in names]

    _print_report(reports)

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    LATEST.write_text(json.dumps(reports, indent=2, sort_keys=True) + "\n")

    if update_baseline:
        BASELINE.write_text(json.dumps(reports, indent=2, sort_keys=True) + "\n")
        print(f"\nbaseline updated: {BASELINE}")
        return

    failed = [r for r in reports if not r["passed"]]
    problems: list[str] = []
    if check_baseline and BASELINE.exists():
        problems = _regressions(reports, json.loads(BASELINE.read_text()))

    if problems:
        print("\nRegressions against the baseline:", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
    if failed:
        print("\nScanners below their gate:", file=sys.stderr)
        for report in failed:
            print(f"  - {report['scanner']}: {report['reason']}", file=sys.stderr)

    if problems or failed:
        raise typer.Exit(1)


if __name__ == "__main__":
    app()
