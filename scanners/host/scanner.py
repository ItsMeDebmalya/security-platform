"""The `host` scanner: a validated agent snapshot becomes findings (spec 9, Tier-B slice).

Its relationship to the scanner is exactly `--replay`'s to a fixture directory: the snapshot IS
the recording. The platform never reaches into the host. A broken snapshot is a SCAN ERROR (a
fatal `ScanError` and no findings), never an inconclusive and never a clear. A snapshot that
reads but cannot answer a question yields an `inconclusive` finding for that check, naming why.

`state` is never set here: it is computed by `core/state.py` from the severity, the confidence
the engine combines and the independence classes of the detection methods.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from core.confidence import ConfidenceEngine, Signal
from core.context import ScanContext
from core.models import Asset, CheckRun, Finding, Mode, ScanError, ScanResult, Telemetry
from core.registry import register
from core.scanner import BaseScanner
from scanners.host import checks, reader
from scanners.host.reader import Snapshot, SnapshotError

NO_VERDICT_SIGNAL = Signal(
    method="snapshot_section",
    prior=0.5,
    likelihood_ratio=1.0,
    independence_class="snapshot",
    prior_justification="the snapshot could not answer this question, so nothing moves the prior",
)


@register
class HostScanner(BaseScanner):
    name = "host"
    version = "0.1.0"
    vantage = "agent"
    engagement = "defensive"
    supported_modes = frozenset({"light"})
    target_types = frozenset({"host"})
    takes_snapshot = True
    """`scan run` hands a scanner with this flag the `--snapshot` path (and refuses the flag
    for any other scanner)."""

    def __init__(self, snapshot_path: reader.SnapshotPath | None = None) -> None:
        self.snapshot_path = snapshot_path

    def requires_authorisation(self, mode: Mode) -> bool | None:
        """Reading a file the operator already holds sends nothing to any host."""
        return False

    def run(self, target: Asset, mode: Mode, ctx: ScanContext) -> ScanResult:
        self.validate(target, mode)
        if self.snapshot_path is None:
            return self._failed(target, mode, "input", "the host scanner needs --snapshot <file>")
        ctx.progress("reading the snapshot", 0.1)
        try:
            snap = reader.load_file(self.snapshot_path)
        except SnapshotError as exc:
            return self._failed(target, mode, "snapshot", str(exc))
        return self.assess(snap, target=target, mode=mode, ctx=ctx)

    def _failed(self, target: Asset, mode: Mode, stage: str, message: str) -> ScanResult:
        return ScanResult(
            scanner=self.name,
            scanner_version=self.version,
            target=target,
            mode=mode,
            errors=[ScanError(stage=stage, message=message, fatal=True)],
            finished_at=datetime.now(UTC),
        )

    def assess(
        self,
        snap: Snapshot,
        *,
        target: Asset | None = None,
        mode: Mode = "light",
        ctx: ScanContext | None = None,
    ) -> ScanResult:
        ctx = ctx or ScanContext()
        target = target or Asset(type="host", value=snap.hostname)
        errors: list[ScanError] = []
        if target.value != snap.hostname:
            errors.append(
                ScanError(
                    stage="snapshot",
                    message=(
                        f"the target is {target.value!r} but the snapshot was collected on "
                        f"{snap.hostname!r}; findings are filed under the target"
                    ),
                )
            )
        findings: list[Finding] = []
        runs: list[CheckRun] = []
        for check_id, check in checks.CHECKS.items():
            ctx.check_alive()
            verdict = checks.evaluate(check_id, snap)
            runs.append(CheckRun(check_id=check_id, outcome=verdict.outcome, location="$"))  # type: ignore[arg-type]
            if verdict.outcome != "clear":
                findings.append(self._finding(check, verdict, snap, target, ctx))
        ctx.progress("done", 1.0)
        cost = ctx.cost.snapshot()
        return ScanResult(
            scanner=self.name,
            scanner_version=self.version,
            target=target,
            mode=mode,
            findings=findings,
            errors=errors,
            telemetry=Telemetry(checks_run=runs, requests=cost.requests, wall_ms=cost.wall_ms),
            finished_at=datetime.now(UTC),
        )

    def _finding(
        self,
        check: checks.Check,
        verdict: checks.Verdict,
        snap: Snapshot,
        target: Asset,
        ctx: ScanContext,
    ) -> Finding:
        engine = ConfidenceEngine()
        reported = verdict.outcome == "reported"
        signals = (
            [
                Signal(
                    method=s.method,
                    prior=s.prior,
                    likelihood_ratio=s.likelihood_ratio,
                    independence_class=s.independence_class,
                    prior_justification=s.justification,
                )
                for s in check.signals
            ]
            if reported
            else [NO_VERDICT_SIGNAL]
        )
        result = engine.combine(signals)
        evidence = (
            [self._command_evidence(o, snap) for o in verdict.observations]
            if reported
            else [self._manifest_evidence(check, verdict, snap)]
        )
        now = datetime.now(UTC)
        extra: dict[str, Any] = {} if reported else {"no_verdict_reason": "blocked_prerequisite"}
        return Finding.create(
            org_id=ctx.org_id,
            scanner=self.name,
            scanner_version=self.version,
            vantage=self.vantage,
            engagement=self.engagement,
            check_id=check.check_id,
            title=check.title if reported else f"Could not assess: {check.title}",
            target=target,
            location="$",
            severity=check.severity,
            confidence=result.confidence,
            confidence_provisional=result.provisional,
            detection_methods=result.detection_methods,
            # No second method exists in the allowlist (spec 9), so validation cannot run.
            validation={"attempted": False, "outcome": "unavailable", "method": None},
            evidence=evidence,
            related_assets=[],
            description=verdict.description,
            impact=check.impact if reported else "Unknown until the snapshot can answer it.",
            remediation=check.remediation
            if reported
            else "Re-run the collector with the access this check needs (see the reason above).",
            references=list(check.references),
            first_seen=now,
            first_seen_scan_id=ctx.scan_id,
            last_seen=now,
            last_seen_scan_id=ctx.scan_id,
            cost=ctx.cost.snapshot(),
            **extra,
        )

    @staticmethod
    def _command_evidence(obs: checks.Observation, snap: Snapshot) -> dict[str, Any]:
        index = snap.receipt_index(obs.reason_id)
        assert index is not None  # _observation_blocker proved it before a verdict was reported
        command = snap.commands[index]
        return {
            "kind": "command_output",
            "label": obs.label,
            "captured_at": snap.collected_at,
            "control_rationale": obs.control_rationale,
            "data": {
                "argv": command["argv"],
                "exit_status": command["exit_status"],
                "output": obs.output,
                "output_selection": {
                    "method": obs.selection_method,
                    "detail": obs.selection_detail,
                    "captured_bytes": command.get("stdout_bytes", 0),
                    "truncated": command.get("stdout_truncated", False),
                },
                "receipt_ref": {"reason_id": obs.reason_id, "command_index": index},
                "collected_at": snap.collected_at,
                "host_ref": snap.host_ref,
            },
        }

    @staticmethod
    def _manifest_evidence(
        check: checks.Check, verdict: checks.Verdict, snap: Snapshot
    ) -> dict[str, Any]:
        """Evidence for a check that could not conclude: the manifest's own account.

        There is no command output to cite - that is why it is inconclusive - so this uses the
        evidence shape that carries only a label and a rationale (ADR-037's reserved
        `file_excerpt`), and says in words what it rests on."""
        return {
            "kind": "file_excerpt",
            "label": f"snapshot manifest and sections for {check.check_id}",
            "captured_at": snap.collected_at,
            "control_rationale": (
                "No reading was available to compare against expectation: " + verdict.reason
            ),
            "data": {},
        }
