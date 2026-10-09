"""A credential receipt on public content is a finding (ADR-029 clause 5).

ADR-028 removes a secret before anything is stored, and the evidence's
`redaction_receipts` say what kind went and from which part. When that part is
content the target served (a response's headers or body, or a DNS answer under
the target's name), the secret was public, and the customer needs to know.

`secret_exposure_findings` turns those receipts into one `secret-exposed`
finding per exposed resource, under the calling scanner's name. A scanner calls
it once, with the findings it has built. `web` does not, because
`web-secret-in-response` already reports the same thing.

`unreported_exposures` is the contract (ADR-029 clause 6): every exposed resource
in a scan result must be reported by one of the two checks.
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit

from core.confidence import ConfidenceEngine, Signal
from core.models import Asset, CheckRun, Finding, ScanResult

CHECK_ID = "secret-exposed"
REPORTING_CHECKS = frozenset({CHECK_ID, "web-secret-in-response"})

EXPOSURE_KINDS = frozenset(
    {"aws_access_key_id", "github_token", "slack_token", "private_key", "bearer_token"}
)
"""The redactor's kinds that are credentials, the same set as `web`'s. Excluded:
`google_api_key` (browser keys are public by design), the sensitive-header kinds (a
`Set-Cookie` header is normal), and `possible_key_material` (a heuristic cut, never
a verdict, ADR-028)."""

_SIGNAL = Signal(
    method="credential_pattern_in_public_content",
    prior=0.5,
    likelihood_ratio=30.0,
    independence_class="content_pattern",
    prior_justification=(
        "core's capture-time redactor matched a credential pattern in content the target "
        "served; patterns can match documentation examples, so the ratio is web's for the "
        "same signal (web-secret-in-response), below a header read"
    ),
)

TITLE = "A credential-shaped secret is served publicly"
IMPACT = "Anyone who can fetch this resource can copy the credential and use it."
REMEDIATION = (
    "Revoke and rotate the credential immediately, then remove it from where it is "
    "served. Removing it alone is not enough: assume it has been copied."
)


def _within(name: str, target: Asset) -> bool:
    """Is `name` (a host or a DNS name) the target's own, or under it?"""
    own = target.value.lower().rstrip(".")
    if target.type == "url":
        own = (urlsplit(target.value).hostname or own).lower()
    name = name.lower().rstrip(".")
    return name == own or name.endswith("." + own)


def _side_resource(item: Any, side: str, target: Asset) -> str | None:
    exchange = getattr(item, side, None)
    if exchange is None:
        return None
    if item.kind == "http_pair":
        url = exchange.request.url
        host = urlsplit(url).hostname
        return url if host and _within(host, target) else None
    if item.kind == "dns_answer":
        name = exchange.query.name
        return f"dns:{name}/{exchange.query.rrtype}" if _within(name, target) else None
    return None


def _public_part(item: Any, side: str) -> str | None:
    if item.kind == "http_pair":
        return f"{side}.response."
    if item.kind == "dns_answer":
        return f"{side}.answer"
    return None


def exposed_resources(
    item: Any, target: Asset, sides: Iterable[str] = ("control", "test")
) -> dict[str, set[str]]:
    """Resource -> credential kinds, for the public parts of one evidence item."""
    found: dict[str, set[str]] = {}
    for side in sides:
        part = _public_part(item, side)
        if part is None:
            continue
        kinds = {
            r.kind
            for r in getattr(item, "redaction_receipts", [])
            if r.kind in EXPOSURE_KINDS and r.where.startswith(part)
        }
        resource = _side_resource(item, side, target) if kinds else None
        if resource is not None:
            found.setdefault(resource, set()).update(kinds)
    return found


def reported_resources(findings: Iterable[Finding]) -> set[str]:
    """What the reporting checks already cover.

    A `secret-exposed` finding covers its location. `web-secret-in-response`
    covers the exposed resources on the *test* side of its evidence: its control
    is another page, which must be reported on its own account."""
    covered: set[str] = set()
    for finding in findings:
        if finding.check_id == CHECK_ID:
            covered.add(finding.location)
        elif finding.check_id in REPORTING_CHECKS:
            for item in finding.evidence:
                covered.update(exposed_resources(item, finding.target, sides=("test",)))
    return covered


def _all_exposures(findings: Iterable[Finding], target: Asset) -> dict[str, tuple[set[str], Any]]:
    out: dict[str, tuple[set[str], Any]] = {}
    for finding in findings:
        for item in finding.evidence:
            for resource, kinds in exposed_resources(item, target).items():
                known, first = out.get(resource, (set(), item))
                out[resource] = (known | kinds, first)
    return out


def secret_exposure_findings(
    findings: list[Finding],
    *,
    scanner: str,
    scanner_version: str,
    target: Asset,
    org_id: str,
    scan_id: str,
) -> list[Finding]:
    """One `secret-exposed` finding per exposed resource not already reported."""
    covered = reported_resources(findings)
    result = ConfidenceEngine().combine([_SIGNAL])
    now = datetime.now(UTC)
    out: list[Finding] = []
    for resource, (kinds, item) in sorted(_all_exposures(findings, target).items()):
        if resource in covered:
            continue
        names = ", ".join(sorted(kinds))
        out.append(
            Finding.create(
                org_id=org_id,
                scanner=scanner,
                scanner_version=scanner_version,
                check_id=CHECK_ID,
                title=TITLE,
                target=target,
                location=resource,
                severity="high",
                confidence=result.confidence,
                confidence_provisional=result.provisional,
                detection_methods=result.detection_methods,
                validation={"attempted": False, "outcome": "not_applicable"},
                evidence=[item],
                description=(
                    f"Text matching the credential pattern(s) {names} was served at "
                    f"{resource}. It was removed when captured and is not stored; the "
                    "evidence's redaction receipts show where it was."
                ),
                impact=IMPACT,
                remediation=REMEDIATION,
                taxonomy={"cwe": ["CWE-200"]},
                first_seen=now,
                first_seen_scan_id=scan_id,
                last_seen=now,
                last_seen_scan_id=scan_id,
            )
        )
    return out


def unreported_exposures(result: ScanResult) -> list[str]:
    """Exposed resources in `result` that no reporting check covers (the contract)."""
    exposed = _all_exposures(result.findings, result.target)
    return sorted(set(exposed) - reported_resources(result.findings))


def check_runs(exposures: Iterable[Finding]) -> list[CheckRun]:
    """The telemetry a caller adds with the findings: every finding's check ran."""
    return [CheckRun(check_id=CHECK_ID, location=f.location, outcome="reported") for f in exposures]
