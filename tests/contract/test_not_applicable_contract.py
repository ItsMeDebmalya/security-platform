"""ADR-032: no check may use `not_applicable` with a reason it did not declare.

`not_applicable` leaves the inconclusive gate, so it must never be a way around
it. Each scanner declares, per check in its `CHECKS` table, which registered
reasons that check may give. The corpus half runs **every registered scanner**
that has a corpus; the second half proves the check bites.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from core.applicability import REASONS, declared_reasons, undeclared
from core.models import CheckRun
from core.registry import discover

ROOT = Path(__file__).resolve().parents[2]
TARGETS = ROOT / "corpus" / "targets"


def _declared(scanner: str) -> dict[str, frozenset[str]]:
    return declared_reasons(scanner)


def _cases() -> list[tuple[str, dict]]:
    cases = []
    for name in sorted(discover().names()):
        path = TARGETS / f"{name}.yaml"
        if path.exists():
            cases += [(name, case) for case in yaml.safe_load(path.read_text())["cases"]]
    return cases


CASES = _cases()


@pytest.mark.parametrize("scanner", sorted(discover().names()))
def test_every_declared_reason_is_registered(scanner):
    for check_id, reasons in _declared(scanner).items():
        assert reasons <= set(REASONS), f"{scanner}:{check_id} declares {reasons - set(REASONS)}"


@pytest.mark.parametrize(("scanner", "case"), CASES, ids=[f"{s}:{c['id']}" for s, c in CASES])
def test_no_corpus_case_uses_an_undeclared_reason(scanner, case):
    from cli.corpus import _run_case
    from core.http import MissingFixtureError

    try:
        result = _run_case(scanner, case)
    except MissingFixtureError:
        pytest.skip("fixtures do not cover this scanner version; make corpus reports it")

    assert undeclared(result.telemetry.checks_run, _declared(scanner)) == []


def test_the_contract_bites_on_a_reason_the_check_never_declared():
    runs = [CheckRun(check_id="dkim-missing", outcome="not_applicable", reason="special-use-name")]

    assert undeclared(runs, _declared("email")) == ["dkim-missing@$: special-use-name"]


def test_the_contract_accepts_a_declared_reason():
    runs = [CheckRun(check_id="x", outcome="not_applicable", reason="special-use-name")]

    assert undeclared(runs, {"x": frozenset({"special-use-name"})}) == []


# --- enforced at runtime, not only over the corpus (review of D28, finding 5) -------


def _result(scanner: str, run: CheckRun):
    from datetime import UTC, datetime

    from core.models import Asset, ScanResult, Telemetry

    return ScanResult(
        scanner=scanner,
        scanner_version="1.0.0",
        target=Asset(type="domain", value="x.test"),
        mode="light",
        findings=[],
        errors=[],
        telemetry=Telemetry(checks_run=[run]),
        finished_at=datetime.now(UTC),
    )


def test_enforce_refuses_a_reason_built_directly_on_any_code_path():
    from core.applicability import UndeclaredNotApplicableError, enforce

    run = CheckRun(check_id="dkim-missing", outcome="not_applicable", reason="special-use-name")
    with pytest.raises(UndeclaredNotApplicableError):
        enforce(_result("email", run))


def test_enforce_passes_a_declared_reason():
    from core.applicability import enforce

    run = CheckRun(check_id="domain-expiring", outcome="not_applicable", reason="special-use-name")
    assert enforce(_result("domscout", run)).scanner == "domscout"


def test_both_result_producers_call_enforce():
    import inspect

    import cli.corpus
    import cli.main

    assert "enforce(scanner.run(" in inspect.getsource(cli.corpus._run_case)
    assert "enforce(scanner.run(" in inspect.getsource(cli.main)


def test_the_corpus_harness_declares_service_hosts_to_the_http_client():
    """D54: replayed scans get the same no-follow guarantee as live ones."""
    from cli.corpus import _case_context

    (case,) = [c for s, c in CASES if s == "domscout" and c["id"] == "real-nixi"]
    scanner, target, ctx = _case_context("domscout", case)

    assert ctx.http._service_hosts == scanner.service_hosts_for(target)
    assert "rdap.nixiregistry.in" in ctx.http._service_hosts


def test_every_scan_client_is_built_with_for_scan():
    """Review of D54: scope and service hosts come from one declaration everywhere a
    scan's client is built, so they cannot be wired apart."""
    import inspect

    import cli.corpus
    import cli.main
    import corpus.generators.domscout

    for module in (cli.main, cli.corpus, corpus.generators.domscout):
        source = inspect.getsource(module)
        assert "HttpClient.for_scan(" in source
        assert "http=HttpClient(" not in source
