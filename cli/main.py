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
from pathlib import Path
from typing import Any, cast, get_args

import typer

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
from core.tls import RecordingTlsBackend, ReplayTlsBackend, SystemTlsBackend, TlsClient

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

    if fail_on and _breaches(result, fail_on):
        raise typer.Exit(2)


def _execute(
    *,
    scanner_name: str,
    target: Asset,
    mode: str,
    record: Path | None,
    replay: Path | None,
    scope_file: Path,
) -> ScanResult:
    registry = discover()
    scanner = registry.get(scanner_name)()

    scope = AuthorisedScope.load(scope_file)
    authz_ref = scope.require(target, mode=_as_mode(mode))

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
