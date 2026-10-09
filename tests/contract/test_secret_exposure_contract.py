"""ADR-029 clause 6: a credential receipt on public content is always reported.

If any evidence item in a scan result carries a credential receipt for content
the target served, the result must also hold a finding that reports that
resource: `secret-exposed` (the core helper) or `web-secret-in-response`.

The corpus half runs **every registered scanner** that has a corpus, so a future
scanner is covered without being listed here. The fake-scanner half proves the
check bites: a scanner that captures a secret and forgets the helper fails it.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest
import yaml

from core.authz import Scope
from core.context import ScanContext
from core.evidence import capture_http_pair
from core.exposure import check_runs, secret_exposure_findings, unreported_exposures
from core.http import HttpClient
from core.models import Asset, CheckRun, Finding, Mode, ScanResult, Telemetry
from core.registry import discover
from core.scanner import BaseScanner
from tests.core.test_redaction import AWS
from tests.core.test_redaction_storage import _finding_kwargs

ROOT = Path(__file__).resolve().parents[2]
TARGETS = ROOT / "corpus" / "targets"


def _corpus_cases() -> list[tuple[str, dict]]:
    cases = []
    for name in sorted(discover().names()):
        path = TARGETS / f"{name}.yaml"
        if not path.exists():
            continue
        for case in yaml.safe_load(path.read_text())["cases"]:
            cases.append((name, case))
    return cases


CASES = _corpus_cases()


def test_every_registered_scanner_with_a_corpus_is_covered():
    covered = {name for name, _ in CASES}
    assert {"domscout", "email", "tls", "web"} <= covered


@pytest.mark.parametrize(("scanner", "case"), CASES, ids=[f"{s}:{c['id']}" for s, c in CASES])
def test_no_corpus_case_leaves_a_public_exposure_unreported(scanner, case):
    from cli.corpus import _run_case
    from core.http import MissingFixtureError

    try:
        result = _run_case(scanner, case)
    except MissingFixtureError:
        pytest.skip("fixtures do not cover this scanner version; make corpus reports it")

    assert unreported_exposures(result) == []


# --- the check bites ---------------------------------------------------------------


class _Forgetful(BaseScanner):
    """Captures a public page holding a credential and reports something else."""

    name = "forgetful"
    version = "1.0.0"
    supported_modes = frozenset({"light"})
    target_types = frozenset({"domain"})
    calls_helper = False

    def requires_authorisation(self, mode: Mode) -> bool:
        return False

    def run(self, target: Asset, mode: Mode, ctx: ScanContext) -> ScanResult:
        url = f"https://{target.value}/"
        captured = ctx.http.get(url).captured
        request = {"method": "GET", "url": url, "headers": {}}
        evidence = capture_http_pair(
            label="homepage",
            control_request=request,
            control_response=captured,
            test_request=request,
            test_response=captured,
        )
        findings = [
            Finding.create(
                **_finding_kwargs(
                    scanner=self.name,
                    check_id="some-other-check",
                    target=target.model_dump(),
                    evidence=[evidence.model_dump(mode="json")],
                )
            )
        ]
        runs = [CheckRun(check_id="some-other-check", location="$", outcome="reported")]
        if self.calls_helper:
            exposures = secret_exposure_findings(
                findings,
                scanner=self.name,
                scanner_version=self.version,
                target=target,
                org_id=ctx.org_id,
                scan_id=ctx.scan_id,
            )
            findings += exposures
            runs += check_runs(exposures)
        return ScanResult(
            scanner=self.name,
            scanner_version=self.version,
            target=target,
            mode=mode,
            findings=findings,
            errors=[],
            telemetry=Telemetry(checks_run=runs, suppressed=[]),
            finished_at=datetime.now(UTC),
        )


class _Careful(_Forgetful):
    name = "careful"
    calls_helper = True


def _run(scanner: BaseScanner) -> ScanResult:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=f"<p>key {AWS}</p>")

    scope = Scope(frozenset({"x.test"}))
    http = HttpClient(scope=scope, transport=httpx.MockTransport(handler))
    return scanner.run(Asset(type="domain", value="x.test"), "light", ScanContext(http=http))


def test_a_scanner_that_forgets_the_helper_fails_the_contract():
    unreported = unreported_exposures(_run(_Forgetful()))

    assert unreported == ["https://x.test/"]


def test_a_scanner_that_calls_the_helper_passes_the_contract():
    assert unreported_exposures(_run(_Careful())) == []


def test_web_secret_in_response_satisfies_the_contract_and_is_not_doubled():
    from tests.scanners.web.conftest import FakeSite
    from tests.scanners.web.test_web_scanner import HARDENED, hardened, run

    site = hardened(FakeSite())
    site.serve("https://x.test/", headers=HARDENED, body=f"<script>var k = '{AWS}';</script>")

    result = run(site)

    checks = [f.check_id for f in result.findings]
    assert "web-secret-in-response" in checks
    assert "secret-exposed" not in checks
    assert unreported_exposures(result) == []


@pytest.mark.parametrize(
    ("scanner", "case_id", "location"),
    [
        ("email", "secret-in-txt", "dns:corpus-secret.example/TXT"),
        ("domscout", "takeover-secret", "https://docs.corpus-takesecret.test/"),
    ],
)
def test_the_positive_corpus_cases_fire_secret_exposed(scanner, case_id, location):
    from cli.corpus import _run_case

    (case,) = [c for s, c in CASES if s == scanner and c["id"] == case_id]
    result = _run_case(scanner, case)

    exposed = [f for f in result.findings if f.check_id == "secret-exposed"]
    assert [f.location for f in exposed] == [location]
    assert "AKIAIOSFODNN7EXAMPLE" not in result.model_dump_json()
