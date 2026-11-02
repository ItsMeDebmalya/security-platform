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
import threading
import traceback
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from types import TracebackType
from typing import Any, cast, get_args

import typer
from ulid import ULID

from cli.replay_counts import (
    Counts,
    counting_http_backend,
    counting_resolver,
    counting_tls_backend,
    divergence_note,
    read_manifest,
    write_manifest,
)
from core.addresses import AddressPolicy
from core.applicability import enforce
from core.assetgraph import AssetGraph, seed_asset_graph
from core.authz import AuthorisationDeniedError, AuthorisedScope, Scope
from core.context import ScanContext
from core.correlation import DEFAULT_PATH as RULES_DEFAULT_PATH
from core.correlation import CorrelationRulesError, correlate, load_composition_rules
from core.dns import (
    DnsClient,
    MissingFixtureError,
    RecordingResolver,
    ReplayResolver,
    Resolver,
    SystemResolver,
)
from core.http import HttpClient, OutOfScopeError, RecordingHttpBackend, ReplayHttpBackend
from core.models import Asset, AssetType, Mode, ScanResult
from core.ratelimit import RateLimiter
from core.redaction import redact_text
from core.registry import discover
from core.store import FindingStore, VerifyOutcome, is_read_only
from core.testssl import LiveTestsslClient, RecordingTestsslClient, ReplayTestsslClient
from core.tls import RecordingTlsBackend, ReplayTlsBackend, SystemTlsBackend, TlsClient

VERIFY_BY = "scan verify"
"""`StatusChange.by` for transitions this command makes."""

NO_VERDICT_OUTCOMES = frozenset({"inconclusive", "suppressed", "error", "not_applicable"})
"""CheckRun outcomes that mean the check ran but reached no verdict.

None of these may close a finding - only `outcome == "clear"` is a positive
observation that the problem is gone. See docs/03-roadmap.md 0b.8 and
ADR-022: absence of a verdict is not evidence of a fix.
"""

app = typer.Typer(
    add_completion=False,
    help="Run a scanner against a target.",
    # Uncaught exceptions go to `_redacting_excepthook`, not typer's printer:
    # an exception message can carry a response snippet (ADR-028).
    pretty_exceptions_enable=False,
)


def _echo(message: object = "", **kwargs: Any) -> None:
    """Everything the CLI prints goes through the redactor (ADR-028 clause 5).

    Token patterns and private-key blocks only: the output includes stored
    evidence, already redacted, whose public key material must stay intact.
    """
    typer.echo(redact_text(str(message), heuristics=False)[0], **kwargs)


def report_exception(exc: BaseException) -> None:
    """Print an exception as one redacted line on stderr."""
    text = f"{type(exc).__name__}: {exc}"
    print(redact_text(text)[0], file=sys.stderr)


def _redacting_excepthook(
    kind: type[BaseException], exc: BaseException, tb: TracebackType | None
) -> None:
    text = "".join(traceback.format_exception(kind, exc, tb))
    print(redact_text(text)[0], file=sys.stderr, end="")


def _redacting_thread_excepthook(args: threading.ExceptHookArgs) -> None:
    if args.exc_value is not None:
        _redacting_excepthook(args.exc_type, args.exc_value, args.exc_traceback)


sys.excepthook = _redacting_excepthook
threading.excepthook = _redacting_thread_excepthook

SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]
REPORTED_STATES = frozenset({"confirmed", "highly_likely"})
"""What counts as a claim we are making. docs/10-measurement.md."""

DEFAULT_RESOLVERS = ["1.1.1.1", "8.8.8.8"]
SCOPE_PATH = Path("config/authorised_scope.yaml")


def _progress(message: str, fraction: float) -> None:
    print(f"[{fraction:>5.0%}] {redact_text(message)[0]}", file=sys.stderr)


@app.command("list")
def list_scanners(
    output_format: str = typer.Option("table", "--format", help="json or table"),
) -> None:
    """List registered scanners, their versions and supported modes."""
    described = discover().describe()
    if output_format == "json":
        _echo(json.dumps(described, indent=2))
        return
    _echo(f"{'name':<12} {'version':<10} {'modes':<24} target types")
    for entry in described:
        _echo(
            f"{entry['name']:<12} {entry['version']:<10} "
            f"{','.join(entry['modes']):<24} {','.join(entry['target_types'])}"
        )


@app.command("run")
def run(
    scanner_name: str = typer.Argument(..., metavar="SCANNER"),
    target: str = typer.Option(..., "--target", "-t"),
    mode: str = typer.Option("light", "--mode", "-m"),
    target_type: str | None = typer.Option(
        None, "--target-type", help="Default: domain, or host for a scanner that reads a snapshot"
    ),
    snapshot: Path | None = typer.Option(
        None,
        "--snapshot",
        help="A host snapshot file to read (the host scanner; nothing is scanned)",
    ),
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
    if store is not None:
        _refuse_read_only_store(store, "scan run --store")
    counts = Counts()
    try:
        if target_type is None:
            reads_snapshot = getattr(discover().get(scanner_name), "takes_snapshot", False)
            target_type = "host" if reads_snapshot else "domain"
        result = _execute(
            scanner_name=scanner_name,
            target=Asset(type=_as_target_type(target_type), value=target),
            mode=mode,
            record=record,
            replay=replay,
            scope_file=scope_file,
            counts=counts,
            snapshot=snapshot,
        )
    except KeyError as exc:
        _echo(str(exc).strip('"'), err=False)
        raise typer.Exit(1) from None
    except AuthorisationDeniedError as exc:
        _echo(f"authorisation denied: {exc}")
        raise typer.Exit(1) from None
    except OutOfScopeError as exc:
        _echo(f"out of scope: {exc}")
        raise typer.Exit(1) from None
    except MissingFixtureError as exc:
        _echo(str(exc))
        raise typer.Exit(1) from None
    except ValueError as exc:
        _echo(f"error: {exc}")
        raise typer.Exit(1) from None

    # Re-validated at the storage boundary, so nothing mutated since it was built
    # reaches the file or the terminal unredacted (ADR-028; review of D21, 6).
    result = ScanResult.model_validate(result.model_dump())
    # D64: a recorded run writes down what it counted, by protocol, so its
    # replay can report both totals instead of quietly reporting a different
    # number for the same field.
    if record is not None:
        write_manifest(record, counts=counts, requests_counted=result.telemetry.requests)
    note = (
        divergence_note(
            replay_total=result.telemetry.requests,
            replay_counts=counts,
            manifest=read_manifest(replay),
        )
        if replay is not None
        else None
    )
    payload = result.model_dump_json(indent=2)
    if out is not None:
        out.write_text(payload + "\n")
    if output_format == "json":
        _echo(payload)
        # Said, not hidden - but on stderr, so a parser of this output is
        # unaffected. The manifest beside the fixtures is the machine-readable
        # record of the same fact.
        if note is not None:
            _echo(note, err=True)
    else:
        _print_table(result, requests_note=note)

    if store is not None:
        with FindingStore(store) as fstore:
            fstore.ingest(result.findings)

    # A scan of a recording that cannot be read did not run: exit 1, like any scan that could not
    # run. Only a snapshot scanner can end `errored` with nothing else to tell the caller.
    if result.outcome == "errored" and getattr(
        discover().get(scanner_name), "takes_snapshot", False
    ):
        raise typer.Exit(1)

    if fail_on and _breaches(result, fail_on):
        raise typer.Exit(2)


@app.command("correlate")
def correlate_cmd(
    results: list[Path] = typer.Option(
        ...,
        "--result",
        "-r",
        help="ScanResult JSON file(s) from earlier `scan run --out`, one run's worth",
    ),
    rules_file: Path = typer.Option(
        RULES_DEFAULT_PATH, "--rules", help="Composition rules file (config/composition_rules.yaml)"
    ),
    seed_assets: Path | None = typer.Option(
        None,
        "--seed-assets",
        help="JSON file of discovered assets to seed the asset graph (ADR-019 replay seam)",
    ),
    output_format: str = typer.Option("table", "--format", help="json or table"),
) -> None:
    """Run the correlation pass (ADR-022 'connect') over one or more scan
    results, emitting derived 'story' findings that chain related findings
    into one attack story. Runs after all scanners in a run have finished;
    this command is that step made runnable on its own, over saved results.
    """
    try:
        rules = load_composition_rules(rules_file)
    except CorrelationRulesError as exc:
        _echo(f"error: {exc}")
        raise typer.Exit(1) from None

    scan_results = [ScanResult.model_validate_json(p.read_text()) for p in results]
    if not scan_results:
        _echo("error: at least one --result is required")
        raise typer.Exit(1)

    all_findings = [finding for r in scan_results for finding in r.findings]
    primary_target = scan_results[0].target
    org_id = all_findings[0].org_id if all_findings else "org_internal"

    asset_graph: AssetGraph
    if seed_assets is not None:
        asset_graph = seed_asset_graph(json.loads(seed_assets.read_text()))
    else:
        asset_graph = AssetGraph()

    scan_id = str(ULID())
    stories = correlate(
        findings=all_findings,
        asset_graph=asset_graph,
        primary_target=primary_target,
        org_id=org_id,
        scan_id=scan_id,
        rules=rules,
    )

    if output_format == "json":
        _echo(json.dumps([s.model_dump(mode="json") for s in stories], indent=2))
        return

    _echo(
        f"\ncorrelated {len(all_findings)} finding(s) from {len(scan_results)} result(s) "
        f"against {len(rules)} rule(s)"
    )
    if not stories:
        _echo("no story findings")
    else:
        _echo(f"\n{'severity':<9} {'conf':<6} {'state':<14} {'check':<32} derived_from")
        for story in stories:
            _echo(
                f"{story.severity:<9} {story.confidence:<6.2f} {story.state:<14} "
                f"{story.check_id:<32} {story.derived_from}"
            )


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
    _refuse_read_only_store(store, "scan verify")
    with FindingStore(store) as fstore:
        finding = fstore.get(finding_id, "org_internal")
        if finding is None:
            _echo(f"no stored finding {finding_id!r} in {store}")
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
            _echo(str(exc).strip('"'))
            raise typer.Exit(1) from None
        except AuthorisationDeniedError as exc:
            _echo(f"authorisation denied: {exc}")
            raise typer.Exit(1) from None
        except OutOfScopeError as exc:
            _echo(f"out of scope: {exc}")
            raise typer.Exit(1) from None
        except MissingFixtureError as exc:
            _echo(str(exc))
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


def _refuse_read_only_store(store: Path, command: str) -> None:
    """Stop before scanning: these commands write their result to the store."""
    if is_read_only(store):
        _echo(
            f"{store} is read-only; {command} records its result there. Run it on a writable copy."
        )
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
        _echo(
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
    _echo(f"{outcome.check_id}: {outcome.action} - {outcome.reason}")
    _echo(f"status: {outcome.finding.status}")


def _execute(
    *,
    scanner_name: str,
    target: Asset,
    mode: str,
    record: Path | None,
    replay: Path | None,
    scope_file: Path,
    scan_id: str | None = None,
    address_policy: AddressPolicy | None = None,
    wrap_resolver: Callable[[Resolver], Resolver] | None = None,
    counts: Counts | None = None,
    snapshot: Path | None = None,
) -> ScanResult:
    """Build one scan's context and run it.

    `address_policy` and `wrap_resolver` exist for the lab entry point
    (`corpus/lab/scan.py`, ADR-036 decision 10) and nothing else. `scan run`
    never passes them, and a test reads every call to `_execute` in the source
    to keep it that way. They change only which non-global addresses the scan
    may reach and how lab names resolve; the authorisation check, the name
    scope, the kill switch, rate limits, cost and redaction below are the
    same for both callers.

    `counts` is filled in, if given, with what this run counted by protocol,
    which is how a recorded run and its replay can be compared rather than
    silently disagreeing about one total (D64, `cli/replay_counts.py`).
    """
    registry = discover()
    scanner_cls = registry.get(scanner_name)
    if snapshot is not None:
        # spec 9: the snapshot is the scanner's recording, as --replay's fixtures are. A scanner
        # that does not declare it reads one must not be handed a path it would ignore.
        if not getattr(scanner_cls, "takes_snapshot", False):
            raise ValueError(f"{scanner_name} does not take a snapshot; --snapshot is for host")
        scanner = scanner_cls(snapshot_path=snapshot)  # type: ignore[call-arg]
    else:
        scanner = scanner_cls()

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
    testssl_client: Any
    tally = counts if counts is not None else Counts()
    if replay is not None:
        resolver = counting_resolver(ReplayResolver(replay), tally)
        tls_backend = counting_tls_backend(ReplayTlsBackend(replay), tally)
        http_backend = counting_http_backend(ReplayHttpBackend(replay), tally)
        testssl_client = ReplayTestsslClient(replay)
    elif record is not None:
        live: Resolver = SystemResolver(DEFAULT_RESOLVERS)
        resolver = counting_resolver(
            RecordingResolver(wrap_resolver(live) if wrap_resolver else live, record), tally
        )
        tls_backend = counting_tls_backend(RecordingTlsBackend(record), tally)
        http_backend = counting_http_backend(RecordingHttpBackend(record), tally)
        testssl_client = RecordingTestsslClient(record)
    else:
        resolver = SystemResolver(DEFAULT_RESOLVERS)
        if wrap_resolver is not None:
            resolver = wrap_resolver(resolver)
        tls_backend = SystemTlsBackend()
        http_backend = None  # HttpClient's own default: a live SystemHttpBackend
        # D20: the one place a scan reaches the real testssl.sh subprocess.
        # Standard mode only pays for it - the TLS scanner's own mode gate
        # (`if self.mode == "standard"`) is what keeps Light free of the cost;
        # this client is wired unconditionally because it is only ever invoked
        # by a check declared `mode="standard"`. D59: `scan run` never gives it a
        # lab override, so for customers the four checks report "not run:
        # dedicated-address condition unproven". Only the lab entry point's
        # `address_policy` carries one, for inventory boxes (ADR-036 decision 10).
        # ScanContext hands the client this scan's resolver, scope, kill switch,
        # limiter and address policy.
        testssl_client = LiveTestsslClient()

    # Two limiters, because they protect different things: the target host
    # is someone else's infrastructure, a public resolver is not.
    resolver_limit = RateLimiter.for_resolver()
    target_limit = RateLimiter.for_target()
    ctx = ScanContext(
        scan_id=scan_id or str(ULID()),
        org_id="org_internal",
        authz_ref=authz_ref,
        dns=DnsClient(resolver=resolver, resolvers=DEFAULT_RESOLVERS, ratelimit=resolver_limit),
        # D54: scope and no-follow service hosts from one declaration (ADR-031).
        http=HttpClient.for_scan(
            target,
            service_hosts=scanner.service_hosts_for(target),
            ratelimit=target_limit,
            backend=http_backend,
        ),
        tls=TlsClient(scope=Scope.for_target(target), backend=tls_backend, ratelimit=target_limit),
        testssl=testssl_client,
        scope=Scope.for_target(target),
        ratelimit=target_limit,
        progress=_progress,
        addresses=address_policy or AddressPolicy(),
    )
    # ADR-032: a not_applicable reason the check did not declare fails here.
    return enforce(scanner.run(target, _as_mode(mode), ctx))


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


def _print_table(result: ScanResult, *, requests_note: str | None = None) -> None:
    _echo(
        f"\n{result.scanner} {result.scanner_version} "
        f"{result.mode} {result.target.value} -> {result.outcome}"
    )
    if not result.findings:
        _echo("no findings")
    else:
        _echo(f"\n{'severity':<9} {'conf':<6} {'state':<14} {'check':<32} location")
        for finding in sorted(
            result.findings,
            key=lambda f: SEVERITY_ORDER.index(f.severity) * f.confidence,
            reverse=True,
        ):
            _echo(
                f"{finding.severity:<9} {finding.confidence:<6.2f} {finding.state:<14} "
                f"{finding.check_id:<32} {finding.location}"
            )
    not_applicable = result.not_applicable_count()
    ran = len(result.telemetry.checks_run) - not_applicable
    requests = requests_note or f"{result.telemetry.requests} request(s)"
    _echo(
        f"\n{ran} check(s) ran, {result.inconclusive_rate():.0%} inconclusive, "
        f"{not_applicable} not applicable, {requests}"
    )
    for run in result.telemetry.checks_run:
        if run.outcome == "not_applicable":
            _echo(f"not applicable: {run.check_id} ({run.reason})")
    for error in result.errors:
        _echo(f"error [{error.stage}]: {error.message}")


if __name__ == "__main__":
    app()
