"""The `scan` command.

Progress goes to stderr and results to stdout, so `scan run ... --format json`
pipes cleanly into anything.

Exit codes:
  0  the scan ran
  1  the scan could not run - unknown scanner, denied authorisation, a
     missing fixture on a replay run
  2  the scan ran and reported a finding at or above --fail-on
"""

from __future__ import annotations

import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast, get_args

import typer
from ulid import ULID

from core.authz import AuthorisationDeniedError, AuthorisedScope, Scope
from core.context import ScanContext
from core.dns import (
    DnsClient,
    MissingFixtureError,
    RecordingResolver,
    ReplayResolver,
    SystemResolver,
)
from core.http import HttpClient, OutOfScopeError, RecordingHttpBackend, ReplayHttpBackend
from core.models import Asset, AssetType, Mode, ScanResult
from core.ratelimit import RateLimiter
from core.registry import discover
from core.store import FindingStore, VerifyOutcome
from core.tls import RecordingTlsBackend, ReplayTlsBackend, SystemTlsBackend, TlsClient

VERIFY_BY = "scan verify"
"""`StatusChange.by` for transitions this command makes."""

NO_VERDICT_OUTCOMES = frozenset({"inconclusive", "suppressed", "error"})
"""CheckRun outcomes that mean the check ran but reached no verdict.

None of these may close a finding - only `outcome == "clear"` is a positive
observation that the problem is gone. See docs/03-roadmap.md 0b.8 and
ADR-022: absence of a verdict is not evidence of a fix.
"""

app = typer.Typer(add_completion=False, help="Run a scanner against a target.")

SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]
REPORTED_STATES = frozenset({"confirmed", "highly_likely"})
"""What counts as a claim we are making. docs/10-measurement.md."""

DEFAULT_RESOLVERS = ["1.1.1.1", "8.8.8.8"]
SCOPE_PATH = Path("config/authorised_scope.yaml")


def _progress(message: str, fraction: float) -> None:
    print(f"[{fraction:>5.0%}] {message}", file=sys.stderr)


@app.command("list")
def list_scanners(
    output_format: str = typer.Option("table", "--format", help="json or table"),
) -> None:
    """List registered scanners, their versions and supported modes."""
    described = discover().describe()
    if output_format == "json":
        typer.echo(json.dumps(described, indent=2))
        return
    typer.echo(f"{'name':<12} {'version':<10} {'modes':<24} target types")
    for entry in described:
        typer.echo(
            f"{entry['name']:<12} {entry['version']:<10} "
            f"{','.join(entry['modes']):<24} {','.join(entry['target_types'])}"
        )


@app.command("run")
def run(
    scanner_name: str = typer.Argument(..., metavar="SCANNER"),
    target: str = typer.Option(..., "--target", "-t"),
    mode: str = typer.Option("light", "--mode", "-m"),
    target_type: str = typer.Option("domain", "--target-type"),
    out: Path | None = typer.Option(None, "--out", "-o", help="Write the ScanResult here"),
    output_format: str = typer.Option("table", "--format", help="json or table"),
    record: Path | None = typer.Option(None, "--record", help="Record traffic into this directory"),
    replay: Path | None = typer.Option(
        None, "--replay", help="Replay from this directory, offline"
    ),
    fail_on: str | None = typer.Option(
        None, "--fail-on", help="Exit 2 on a reported finding at or above this severity"
    ),
    scope_file: Path = typer.Option(SCOPE_PATH, "--scope-file"),
    store: Path | None = typer.Option(
        None, "--store", help="Persist findings here, keyed on their deterministic id"
    ),
) -> None:
    """Run one scanner against one target."""
    try:
        result = _execute(
            scanner_name=scanner_name,
            target=Asset(type=_as_target_type(target_type), value=target),
            mode=mode,
            record=record,
            replay=replay,
            scope_file=scope_file,
        )
    except KeyError as exc:
        typer.echo(str(exc).strip('"'), err=False)
        raise typer.Exit(1) from None
    except AuthorisationDeniedError as exc:
        typer.echo(f"authorisation denied: {exc}")
        raise typer.Exit(1) from None
    except OutOfScopeError as exc:
        typer.echo(f"out of scope: {exc}")
        raise typer.Exit(1) from None
    except MissingFixtureError as exc:
        typer.echo(str(exc))
        raise typer.Exit(1) from None
    except ValueError as exc:
        typer.echo(f"error: {exc}")
        raise typer.Exit(1) from None

    payload = result.model_dump_json(indent=2)
    if out is not None:
        out.write_text(payload + "\n")
    if output_format == "json":
        typer.echo(payload)
    else:
        _print_table(result)

    if store is not None:
        with FindingStore(store) as fstore:
            fstore.ingest(result.findings)

    if fail_on and _breaches(result, fail_on):
        raise typer.Exit(2)


@app.command("verify")
def verify(
    finding_id: str = typer.Argument(..., metavar="FINDING_ID"),
    store: Path = typer.Option(..., "--store", help="Finding store the finding was persisted to"),
    replay: Path | None = typer.Option(
        None, "--replay", help="Replay from this directory, offline"
    ),
    scope_file: Path = typer.Option(SCOPE_PATH, "--scope-file"),
    output_format: str = typer.Option("table", "--format", help="json or table"),
) -> None:
    """Re-run the exact check that proved a stored finding.

    Closes the finding only on a positive, evidenced observation that the
    problem is gone (the check ran to completion and reported `clear`).
    Everything short of that - a timeout, a rate limit, a WAF block, an
    error, an `inconclusive` verdict, a missing prerequisite, or the check
    simply not running at all - leaves the finding open and says so.
    Closing on the *absence* of a fresh finding would mean a broken or
    blocked scanner reports every customer's problem as fixed; ADR-022 and
    docs/03-roadmap.md 0b.8 are explicit that this is the failure this
    command must never have.

    Free: verification never touches the cost meter beyond what the
    underlying scan itself already counts.
    """
    with FindingStore(store) as fstore:
        finding = fstore.get(finding_id, "org_internal")
        if finding is None:
            typer.echo(f"no stored finding {finding_id!r} in {store}")
            raise typer.Exit(1)

        scan_id = str(ULID())
        try:
            mode = _verify_mode(finding.scanner)
            result = _execute(
                scanner_name=finding.scanner,
                target=finding.target,
                mode=mode,
                record=None,
                replay=replay,
                scope_file=scope_file,
                scan_id=scan_id,
            )
        except KeyError as exc:
            typer.echo(str(exc).strip('"'))
            raise typer.Exit(1) from None
        except AuthorisationDeniedError as exc:
            typer.echo(f"authorisation denied: {exc}")
            raise typer.Exit(1) from None
        except OutOfScopeError as exc:
            typer.echo(f"out of scope: {exc}")
            raise typer.Exit(1) from None
        except MissingFixtureError as exc:
            typer.echo(str(exc))
            raise typer.Exit(1) from None
        except Exception as exc:  # see the docstring: never close on this
            outcome = _could_not_verify(
                finding, reason=f"the check could not run ({type(exc).__name__}: {exc})"
            )
            _print_verify(outcome, output_format=output_format)
            raise typer.Exit(1) from None

        outcome = _verify_outcome(fstore, finding, result, scan_id=scan_id)

    _print_verify(outcome, output_format=output_format)
    if outcome.action == "could_not_verify":
        raise typer.Exit(1)


def _verify_mode(scanner_name: str) -> Mode:
    """The mode a re-verify runs in: the scanner's fullest, so the check that
    proved the finding is included whatever mode it needs to run under."""
    scanner_cls = discover().get(scanner_name)
    candidates: tuple[Mode, ...] = ("deep", "standard", "light")
    for candidate in candidates:
        if candidate in scanner_cls.supported_modes:
            return candidate
    raise ValueError(f"{scanner_name} declares no supported modes")


def _resolve_check_run(result: ScanResult, finding: Any) -> Any | None:
    for check in result.telemetry.checks_run:
        if check.location == finding.location and finding.matches_stored_check_id(check.check_id):
            return check
    return None


def _could_not_verify(finding: Any, *, reason: str) -> VerifyOutcome:
    return VerifyOutcome(
        finding_id=finding.id,
        check_id=finding.check_id,
        action="could_not_verify",
        reason=reason,
        finding=finding,
    )


def _verify_outcome(
    fstore: FindingStore, finding: Any, result: ScanResult, *, scan_id: str
) -> VerifyOutcome:
    now = datetime.now(UTC)
    check = _resolve_check_run(result, finding)

    if check is None:
        return _could_not_verify(
            finding,
            reason=(
                f"check {finding.check_id!r} at {finding.location!r} did not run in this "
                "scan; the finding stays open"
            ),
        )

    if check.outcome in NO_VERDICT_OUTCOMES:
        return _could_not_verify(
            finding,
            reason=(
                f"the check ran but reached no verdict (outcome={check.outcome!r}); "
                "the finding stays open"
            ),
        )

    still_present = any(f.id == finding.id for f in result.findings)

    if check.outcome == "reported" and still_present:
        if finding.status == "closed":
            updated = fstore.transition(
                finding.id, finding.org_id, to="open", at=now, by=VERIFY_BY, scan_id=scan_id
            )
            return VerifyOutcome(
                finding.id, finding.check_id, "reopened", "the problem is present again", updated
            )
        updated = fstore.touch_last_seen(finding.id, finding.org_id, at=now, scan_id=scan_id)
        return VerifyOutcome(
            finding.id, finding.check_id, "unchanged", "the problem is still present", updated
        )

    if check.outcome == "clear":
        if finding.status != "open":
            return VerifyOutcome(
                finding.id,
                finding.check_id,
                "unchanged",
                f"already {finding.status}; nothing to do",
                finding,
            )
        updated = fstore.transition(
            finding.id, finding.org_id, to="closed", at=now, by=VERIFY_BY, scan_id=scan_id
        )
        return VerifyOutcome(
            finding.id,
            finding.check_id,
            "closed",
            "the check ran to completion and observed the problem is gone",
            updated,
        )

    # outcome == "reported" but this exact finding id is not among the fresh
    # findings: the check produced *something* at this location, but not the
    # finding we are verifying. That is not evidence either way.
    return _could_not_verify(
        finding,
        reason="the check reported a different finding at this location; unverified",
    )


def _print_verify(outcome: VerifyOutcome, *, output_format: str = "table") -> None:
    if output_format == "json":
        typer.echo(
            json.dumps(
                {
                    "finding_id": outcome.finding_id,
                    "check_id": outcome.check_id,
                    "action": outcome.action,
                    "reason": outcome.reason,
                    "status": outcome.finding.status,
                }
            )
        )
        return
    typer.echo(f"{outcome.check_id}: {outcome.action} - {outcome.reason}")
    typer.echo(f"status: {outcome.finding.status}")


def _execute(
    *,
    scanner_name: str,
    target: Asset,
    mode: str,
    record: Path | None,
    replay: Path | None,
    scope_file: Path,
    scan_id: str | None = None,
) -> ScanResult:
    registry = discover()
    scanner = registry.get(scanner_name)()

    scope = AuthorisedScope.load(scope_file)
    # docs/03-roadmap.md 0b.6: ask the scanner what its own checks declare
    # rather than trusting mode alone. `None` means "no declaration", which
    # falls back unchanged to the pre-0b.6 mode-based rule inside authorise().
    active = scanner.requires_authorisation(_as_mode(mode))
    passive = None if active is None else not active
    authz_ref = scope.require(target, mode=_as_mode(mode), passive=passive)

    resolver: Any
    tls_backend: Any
    http_backend: Any
    if replay is not None:
        resolver = ReplayResolver(replay)
        tls_backend = ReplayTlsBackend(replay)
        http_backend = ReplayHttpBackend(replay)
    elif record is not None:
        resolver = RecordingResolver(SystemResolver(DEFAULT_RESOLVERS), record)
        tls_backend = RecordingTlsBackend(record)
        http_backend = RecordingHttpBackend(record)
    else:
        resolver = SystemResolver(DEFAULT_RESOLVERS)
        tls_backend = SystemTlsBackend()
        http_backend = None  # HttpClient's own default: a live SystemHttpBackend

    # Two limiters, because they protect different things: the target host
    # is someone else's infrastructure, a public resolver is not.
    resolver_limit = RateLimiter.for_resolver()
    target_limit = RateLimiter.for_target()
    ctx = ScanContext(
        scan_id=scan_id or str(ULID()),
        org_id="org_internal",
        authz_ref=authz_ref,
        dns=DnsClient(resolver=resolver, resolvers=DEFAULT_RESOLVERS, ratelimit=resolver_limit),
        http=HttpClient(
            scope=Scope.for_target(target), ratelimit=target_limit, backend=http_backend
        ),
        tls=TlsClient(scope=Scope.for_target(target), backend=tls_backend, ratelimit=target_limit),
        scope=Scope.for_target(target),
        ratelimit=target_limit,
        progress=_progress,
    )
    return scanner.run(target, _as_mode(mode), ctx)


def _as_mode(mode: str) -> Mode:
    if mode not in get_args(Mode):
        raise ValueError(f"unknown mode {mode!r}; expected light, standard or deep")
    return cast(Mode, mode)


def _as_target_type(target_type: str) -> AssetType:
    if target_type not in get_args(AssetType):
        raise ValueError(
            f"unknown target type {target_type!r}; expected one of {', '.join(get_args(AssetType))}"
        )
    return cast(AssetType, target_type)


def _breaches(result: ScanResult, fail_on: str) -> bool:
    if fail_on not in SEVERITY_ORDER:
        raise ValueError(f"unknown severity {fail_on!r}")
    threshold = SEVERITY_ORDER.index(fail_on)
    return any(
        finding.state in REPORTED_STATES and SEVERITY_ORDER.index(finding.severity) >= threshold
        for finding in result.findings
    )


def _print_table(result: ScanResult) -> None:
    typer.echo(
        f"\n{result.scanner} {result.scanner_version} "
        f"{result.mode} {result.target.value} -> {result.outcome}"
    )
    if not result.findings:
        typer.echo("no findings")
    else:
        typer.echo(f"\n{'severity':<9} {'conf':<6} {'state':<14} {'check':<32} location")
        for finding in sorted(
            result.findings,
            key=lambda f: SEVERITY_ORDER.index(f.severity) * f.confidence,
            reverse=True,
        ):
            typer.echo(
                f"{finding.severity:<9} {finding.confidence:<6.2f} {finding.state:<14} "
                f"{finding.check_id:<32} {finding.location}"
            )
    ran = len(result.telemetry.checks_run)
    typer.echo(
        f"\n{ran} check(s) ran, {result.inconclusive_rate():.0%} inconclusive, "
        f"{result.telemetry.requests} request(s)"
    )
    for error in result.errors:
        typer.echo(f"error [{error.stage}]: {error.message}")


if __name__ == "__main__":
    app()
