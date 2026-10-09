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
from core.dns import DnsResponse
from core.models import Asset, CheckRun, Finding, ScanResult
from core.redaction import redact_text

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
            # It reported a credential at the page it tested. The page's own
            # receipts may be missing (a fixture recorded before ADR-029), so the
            # tested URL counts, not only a receipt on it.
            for item in finding.evidence:
                covered.update(exposed_resources(item, finding.target, sides=("test",)))
                if item.kind == "http_pair":
                    covered.add(item.test.request.url)
    return covered


class ExposureLog:
    """Every public capture a scan made, kept for one scan, in memory.

    Detection must not depend on an unrelated check keeping the evidence (review
    of ADR-029): a secret in the TXT record of an otherwise clean zone is cited
    by no finding. `ScanContext` wires this log into its HTTP and DNS clients, so
    it sees every response and every fresh DNS answer.

    It records only what is needed to report an exposure: the resource, the
    credential kinds, and how to build redacted evidence for it. A capture
    recorded before ADR-029 has no receipts, so its `redactions` kinds are used;
    a kind is enough to report, and no count is invented.
    """

    def __init__(self) -> None:
        self._seen: dict[str, tuple[set[str], Any]] = {}

    def observe_http(self, url: str, captured: dict[str, Any]) -> None:
        kinds = {
            str(r.get("kind"))
            for r in captured.get("redaction_receipts") or []
            if str(r.get("where", "")).startswith("response.")
        }
        if not captured.get("redaction_receipts"):
            # no receipts at all: a capture recorded before ADR-029
            kinds |= set(captured.get("redactions") or [])
        kinds &= EXPOSURE_KINDS
        if kinds:
            clean_url = redact_text(url)[0] or url
            self._add(clean_url, kinds, lambda: _http_evidence(clean_url, captured))

    def observe_dns(self, response: DnsResponse) -> None:
        kinds: set[str] = set()
        for record in response.records:
            kinds |= set(redact_text(record, heuristics=False)[1])
        kinds &= EXPOSURE_KINDS
        if kinds:
            resource = f"dns:{response.name}/{response.rrtype}"
            self._add(resource, kinds, lambda: _dns_evidence(response))

    def _add(self, resource: str, kinds: set[str], build: Any) -> None:
        known, first = self._seen.get(resource, (set(), build))
        self._seen[resource] = (known | kinds, first)

    def exposed(self, target: Asset) -> dict[str, tuple[set[str], Any]]:
        """Resource -> (kinds, evidence builder), for resources the target served."""
        out = {}
        for resource, entry in self._seen.items():
            name = (
                resource[4:].rsplit("/", 1)[0]
                if resource.startswith("dns:")
                else (urlsplit(resource).hostname or "")
            )
            if _within(name, target):
                out[resource] = entry
        return out


def _http_evidence(url: str, captured: dict[str, Any]) -> Any:
    from core.evidence import capture_http_pair

    request = {"method": "GET", "url": url, "headers": {}}
    return capture_http_pair(
        label=f"response from {url}",
        control_request=request,
        control_response=captured,
        test_request=request,
        test_response=captured,
        delta={"note": "one response; an exposure needs no control: it is what was served"},
    )


def _dns_evidence(response: DnsResponse) -> Any:
    from core.evidence import dns_evidence

    return dns_evidence(
        label=f"{response.rrtype} at {response.name}",
        test=response,
        control=None,
        control_rationale=(
            "an exposure needs no control: the record is what the zone publishes to anyone"
        ),
    )


def _all_exposures(
    findings: Iterable[Finding], target: Asset, log: ExposureLog | None = None
) -> dict[str, tuple[set[str], Any]]:
    out: dict[str, tuple[set[str], Any]] = {}
    if log is not None:
        for resource, (kinds, build) in log.exposed(target).items():
            out[resource] = (set(kinds), build)
    for finding in findings:
        for item in finding.evidence:
            for resource, kinds in exposed_resources(item, target).items():
                known, first = out.get(resource, (set(), item))
                out[resource] = (known | kinds, first)
    return out


def _evidence_of(first: Any) -> Any:
    return first() if callable(first) else first


def secret_exposure_findings(
    findings: list[Finding],
    *,
    scanner: str,
    scanner_version: str,
    target: Asset,
    org_id: str,
    scan_id: str,
    log: ExposureLog | None = None,
) -> list[Finding]:
    """One `secret-exposed` finding per exposed resource not already reported.

    Pass the context's `log` (`ctx.exposures`), so captures no finding cites are
    seen too."""
    covered = reported_resources(findings)
    result = ConfidenceEngine().combine([_SIGNAL])
    now = datetime.now(UTC)
    out: list[Finding] = []
    for resource, (kinds, item) in sorted(_all_exposures(findings, target, log).items()):
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
                evidence=[_evidence_of(item)],
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


def unreported_exposures(result: ScanResult, log: ExposureLog | None = None) -> list[str]:
    """Exposed resources that no reporting check covers (the contract).

    With the scan's `log`, every public capture counts, not only cited evidence."""
    exposed = _all_exposures(result.findings, result.target, log)
    return sorted(set(exposed) - reported_resources(result.findings))


def check_runs(exposures: Iterable[Finding]) -> list[CheckRun]:
    """The telemetry a caller adds with the findings: every finding's check ran."""
    return [CheckRun(check_id=CHECK_ID, location=f.location, outcome="reported") for f in exposures]
