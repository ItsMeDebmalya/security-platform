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

import hashlib
import json
from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit

from core.confidence import ConfidenceEngine, Signal
from core.dns import WILDCARD_PROBE_PREFIX, DnsResponse
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


def resource_url(url: str) -> str:
    """One spelling per resource: an empty path is `/`, scheme and host lowercase.

    The same page reached as `https://x.test` and cited as `https://x.test/` must
    be one exposure, not two (re-review of ADR-029)."""
    parts = urlsplit(url)
    path = parts.path or "/"
    query = f"?{parts.query}" if parts.query else ""
    return f"{parts.scheme.lower()}://{parts.netloc.lower()}{path}{query}"


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
        return resource_url(url) if host and _within(host, target) else None
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
            covered.add(
                resource_url(finding.location) if "://" in finding.location else finding.location
            )
        elif finding.check_id in REPORTING_CHECKS:
            # It reported a credential at the page it tested. The page's own
            # receipts may be missing (a fixture recorded before ADR-029), so the
            # tested URL counts, not only a receipt on it.
            for item in finding.evidence:
                covered.update(exposed_resources(item, finding.target, sides=("test",)))
                if item.kind == "http_pair":
                    covered.add(resource_url(item.test.request.url))
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
        self._content: dict[str, set[str]] = {}
        """DNS resource -> digests of every record set it served, across resolvers
        (D52). In memory for this scan only, never stored: it only tells identical
        content apart. A name that served two different record sets is never folded
        (review of D52, finding 1)."""

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
            clean_url = resource_url(redact_text(url)[0] or url)
            self._add(clean_url, kinds, lambda: _http_evidence(clean_url, captured))

    def observe_dns(self, response: DnsResponse) -> None:
        kinds: set[str] = set()
        for record in response.records:
            kinds |= set(redact_text(record, heuristics=False)[1])
        kinds &= EXPOSURE_KINDS
        if kinds:
            resource = f"dns:{response.name}/{response.rrtype}"
            self._add(resource, kinds, lambda: _dns_evidence(response))
            # JSON, so two records and one record holding a newline never collide
            # (review of D52, finding 5).
            digest = hashlib.sha256(json.dumps(sorted(response.records)).encode()).hexdigest()
            self._content.setdefault(resource, set()).add(digest)

    def wildcard_sources(self, resources: Iterable[str]) -> dict[str, str]:
        """Resource -> the wildcard record that served it (D52), for DNS resources
        whose content a random probe name was also served.

        The probe name cannot exist, so an answer there comes from a wildcard
        `*.<parent>`. A name under that parent with the same record set was served
        by the same wildcard (or by an identical record nobody can tell apart from
        it in DNS). The parent's own answer is never folded in: a wildcard does not
        match its owner (RFC 4592)."""
        by_content: dict[tuple[str, str], list[str]] = {}
        for resource in resources:
            digests = self._content.get(resource, set())
            # A name whose answers differed (two resolvers, a record mid-rotation)
            # is reported on its own, never folded.
            if len(digests) == 1:
                rrtype = resource.rsplit("/", 1)[1]
                by_content.setdefault((rrtype, next(iter(digests))), []).append(resource)
        out: dict[str, str] = {}
        for (rrtype, _), group in by_content.items():
            names = {r: _dns_name(r) for r in group}
            parents = {
                n.split(".", 1)[1] for n in names.values() if n.startswith(WILDCARD_PROBE_PREFIX)
            }
            # Most specific wildcard first, so the result never depends on the
            # probes' random labels (review of D52, finding 4).
            for parent in sorted(parents, key=lambda p: (-p.count("."), p)):
                source = f"dns:*.{parent}/{rrtype}"
                for resource, name in names.items():
                    if name.endswith("." + parent):
                        out.setdefault(resource, source)
        return out

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


def _dns_name(resource: str) -> str:
    return resource[4:].rsplit("/", 1)[0].lower()


def _fold_wildcards(
    exposures: dict[str, tuple[set[str], Any]], log: ExposureLog | None
) -> dict[str, tuple[set[str], Any, list[str]]]:
    """D52: resources served by one wildcard record become that record.

    Location -> (kinds, evidence, the names it was seen at; empty when not folded).
    The wildcard's evidence is the probe's answer, which is what proves it."""
    sources = log.wildcard_sources(exposures) if log is not None else {}
    out: dict[str, tuple[set[str], Any, list[str]]] = {}
    for resource, (kinds, item) in exposures.items():
        source = sources.get(resource)
        if source is None:
            out[resource] = (set(kinds), item, [])
            continue
        known, first, names = out.get(source, (set(), None, []))
        if _dns_name(resource).startswith(WILDCARD_PROBE_PREFIX):
            first = item
        out[source] = (known | kinds, first if first is not None else item, [*names, resource])
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
    # With the log, report from it alone: it saw each capture under the URL that
    # served it, where cited evidence knows only the URL the scanner requested
    # (a redirect's final page would be reported twice). Without it, use the
    # cited evidence.
    source = (
        _all_exposures([], target, log) if log is not None else _all_exposures(findings, target)
    )
    result = ConfidenceEngine().combine([_SIGNAL])
    now = datetime.now(UTC)
    out: list[Finding] = []
    for resource, (kinds, item, seen_at) in sorted(_fold_wildcards(source, log).items()):
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
                description=_description(names, resource, seen_at),
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


def _description(kinds: str, resource: str, seen_at: list[str]) -> str:
    """What was observed, and no more (review of D52, findings 2 and 3)."""
    stored = (
        "It was removed when captured and is not stored; the evidence's redaction receipts "
        "show where it was."
    )
    if not seen_at:
        return f"Text matching the credential pattern(s) {kinds} was served at {resource}. {stored}"
    named = sorted(
        {_dns_name(r) for r in seen_at if not _dns_name(r).startswith(WILDCARD_PROBE_PREFIX)}
    )
    record = resource[4:]
    count = f"{len(seen_at)} name" + ("" if len(seen_at) == 1 else "s")
    where = (
        f"seen at {count}: {', '.join(named)}, and a random name that cannot exist"
        if named
        else "seen only at a random name that cannot exist"
    )
    identical = (
        " Each listed name returned identical content, either from the wildcard or from an "
        "identical record of its own."
        if named
        else ""
    )
    return (
        f"Text matching the credential pattern(s) {kinds} is published in a wildcard DNS "
        f"record, {record}, {where}. The random name is what proves a wildcard: any name "
        f"under it without records of its own is served this record.{identical} {stored}"
    )


def unreported_exposures(result: ScanResult, log: ExposureLog | None = None) -> list[str]:
    """Exposed resources that no reporting check covers (the contract).

    With the scan's `log`, every public capture counts, not only cited evidence. A
    resource folded into a wildcard record (D52) is covered by that record's finding."""
    exposed = _all_exposures(result.findings, result.target, log)
    sources = log.wildcard_sources(exposed) if log is not None else {}
    covered = reported_resources(result.findings)
    return sorted(r for r in exposed if r not in covered and sources.get(r) not in covered)


def check_runs(exposures: Iterable[Finding]) -> list[CheckRun]:
    """The telemetry a caller adds with the findings: every finding's check ran."""
    return [CheckRun(check_id=CHECK_ID, location=f.location, outcome="reported") for f in exposures]
