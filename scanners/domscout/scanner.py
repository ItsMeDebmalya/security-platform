"""The DomScout Scanner — subdomain enumeration and domain posture, Light only.

Pure DNS, Certificate Transparency and RDAP: every check queries a public
service for itself (a CT log, authoritative DNS, a registry's RDAP record),
never the target's own infrastructure beyond ordinary DNS resolution. That is
why every check in `scanners/domscout/checks.py` is declared passive.

Orchestration mirrors `scanners/email/scanner.py`'s shape: a `_Scan` class
gathers observations once, then judges them, emitting findings through
`Finding.create` with `state` always derived, never hand-set.

Two disciplines this module exists to hold, both from the task brief and
docs/10-measurement.md:

- **A wildcard is checked before anything is concluded from a name
  resolving.** A CT-log name that only "resolves" because the zone answers
  every A/CNAME lookup is not a discovery — it is not contributed to the
  asset graph, and it does not appear in the `dns-records` finding's
  resolved-subdomain list.
- **Every source fails independently.** crt.sh being unreachable makes
  `subdomains-ct-log` inconclusive; it does not stop DNSSEC or RDAP from
  running. The same for RDAP and the takeover HTTP fetch.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, date, datetime
from typing import Any
from urllib.parse import urlsplit

from core.applicability import not_applicable
from core.assetgraph import DiscoveredAsset
from core.confidence import ConfidenceEngine, Signal
from core.context import ScanContext
from core.dns import DnsClient, DnsResponse
from core.evidence import capture_http_pair, dns_evidence
from core.exposure import check_runs as exposure_check_runs
from core.exposure import secret_exposure_findings
from core.http import CapturedResponse, HttpClient
from core.models import Asset, CheckRun, Finding, Mode, ScanResult, Telemetry
from core.registry import register
from core.scanner import BaseScanner
from core.tls import a_label
from scanners.domscout import ct, dnssec, rdap_bootstrap, rdapp, takeover
from scanners.domscout.checks import (
    CHECKS,
    CT_LOG,
    DNS_RESOLUTION,
    HTTP_FINGERPRINT,
    RDAP,
    SERVICE_HOSTS,
    Check,
)
from scanners.domscout.checks import requires_authorisation as _requires_authorisation
from scanners.domscout.takeover import TakeoverFingerprint

NO_VERDICT_FOR_RCODE = {
    "SERVFAIL": "servfail",
    "TIMEOUT": "timeout",
    "REFUSED": "blocked_prerequisite",
}


@register
class DomscoutScanner(BaseScanner):
    name = "domscout"
    version = "1.3.1"
    supported_modes = frozenset({"light"})
    target_types = frozenset({"domain"})
    service_hosts = SERVICE_HOSTS

    @classmethod
    def service_hosts_for(cls, target: Asset) -> frozenset[str]:
        """crt.sh, plus only the RDAP server of the target's own registry (ADR-031)."""
        url = rdap_bootstrap.rdap_url(target.value)
        host = urlsplit(url).hostname if url else None
        return cls.service_hosts | ({host} if host else set())

    def requires_authorisation(self, mode: Mode) -> bool:
        return _requires_authorisation(mode)

    def run(self, target: Asset, mode: Mode, ctx: ScanContext) -> ScanResult:
        self.validate(target, mode)
        dns = ctx.dns
        assert isinstance(dns, DnsClient), "domscout needs a DNS client from the context"
        http = ctx.http
        assert isinstance(http, HttpClient), "domscout needs an HTTP client from the context"
        return _Scan(self, target, mode, ctx, dns, http).execute()


@dataclass
class _Resolved:
    """The A/AAAA/CNAME answers for one name."""

    a: DnsResponse
    aaaa: DnsResponse
    cname: DnsResponse


class _Scan:
    """One run against one domain. Gathers observations once, then judges them."""

    def __init__(
        self,
        scanner: DomscoutScanner,
        target: Asset,
        mode: Mode,
        ctx: ScanContext,
        dns: DnsClient,
        http: HttpClient,
    ) -> None:
        self.scanner = scanner
        self.target = target
        self.domain = target.value.strip().lower().rstrip(".")
        self.mode = mode
        self.ctx = ctx
        self.dns = dns
        self.http = http
        self.findings: list[Finding] = []
        self.checks: list[CheckRun] = []
        self.engine = ConfidenceEngine()

    # --- orchestration -------------------------------------------------

    def execute(self) -> ScanResult:
        self.ctx.progress("checking the zone for wildcards", 0.05)
        self.ctx.check_alive()
        self.a_wildcard = self.dns.has_wildcard(self.domain, "A")
        self.a_wildcard_probe = self.dns.wildcard_probe(self.domain, "A")
        self.cname_wildcard = self.dns.has_wildcard(self.domain, "CNAME")
        self.cname_wildcard_probe = self.dns.wildcard_probe(self.domain, "CNAME")

        self.ctx.progress("seeding candidates from Certificate Transparency", 0.15)
        candidates = self._fetch_ct_candidates()

        self.ctx.progress("resolving the apex and its candidates", 0.35)
        self.resolved: dict[str, _Resolved] = {}
        for name in [self.domain, *candidates]:
            self.ctx.check_alive()
            self.resolved[name] = _Resolved(
                a=self.dns.query(name, "A"),
                aaaa=self.dns.query(name, "AAAA"),
                cname=self.dns.query(name, "CNAME"),
            )
        self.apex_mx = self.dns.query(self.domain, "MX")
        self.apex_ns = self.dns.query(self.domain, "NS")
        self.apex_txt = self.dns.query(self.domain, "TXT")
        self.apex_soa = self.dns.query(self.domain, "SOA")

        self._check_dns_records(candidates)

        self.ctx.progress("checking DNSSEC delegation", 0.6)
        self._check_dnssec()

        self.ctx.progress("checking domain registration lifecycle", 0.75)
        self._check_expiry()

        self.ctx.progress("checking for dangling subdomains", 0.9)
        self._check_takeover(candidates)

        # ADR-029: a credential receipt on content the target served is a finding.
        exposures = secret_exposure_findings(
            self.findings,
            scanner=self.scanner.name,
            scanner_version=self.scanner.version,
            target=self.target,
            org_id=self.ctx.org_id,
            scan_id=self.ctx.scan_id,
            log=self.ctx.exposures,
        )
        self.findings.extend(exposures)
        self.checks.extend(exposure_check_runs(exposures))

        self.ctx.progress("done", 1.0)
        cost = self.ctx.cost.snapshot()
        return ScanResult(
            scanner=self.scanner.name,
            scanner_version=self.scanner.version,
            target=self.target,
            mode=self.mode,
            findings=self.findings,
            errors=[],
            telemetry=Telemetry(
                checks_run=self.checks, requests=cost.requests, wall_ms=cost.wall_ms
            ),
            finished_at=datetime.now(UTC),
        )

    # --- crt.sh seeding --------------------------------------------------

    def _crtsh_url(self, pattern: str) -> str:
        return f"https://crt.sh/?q={pattern}&output=json"

    def _fetch_ct_candidates(self) -> list[str]:
        self.ctx.check_alive()
        test_url = self._crtsh_url(f"%25.{self.domain}")
        control_url = self._crtsh_url(self.domain)
        try:
            test_response = self.http.get(test_url)
            control_response = self.http.get(control_url)
        except Exception as exc:
            self._inconclusive_http(
                "subdomains-ct-log",
                label=f"crt.sh search for %.{self.domain}",
                request={"method": "GET", "url": test_url},
                description=(
                    f"crt.sh could not be queried for subdomains of {self.domain}: "
                    f"{type(exc).__name__}: {exc}. This does not show the domain has no "
                    "subdomains — only that this source could not be read."
                ),
                reason="blocked_prerequisite",
            )
            return []

        if test_response.status_code == 429 or test_response.status_code >= 500:
            self._inconclusive_http(
                "subdomains-ct-log",
                label=f"crt.sh search for %.{self.domain}",
                request={"method": "GET", "url": test_url},
                response=test_response,
                description=(
                    f"crt.sh returned HTTP {test_response.status_code} for the subdomain "
                    f"search on {self.domain}. This does not show the domain has no "
                    "subdomains — only that this source could not be read."
                ),
                reason=(
                    "rate_limited" if test_response.status_code == 429 else "blocked_prerequisite"
                ),
            )
            return []

        try:
            candidates = ct.parse_crtsh(test_response.text, self.domain)
        except (ValueError, TypeError):
            self._inconclusive_http(
                "subdomains-ct-log",
                label=f"crt.sh search for %.{self.domain}",
                request={"method": "GET", "url": test_url},
                response=test_response,
                description=(
                    f"crt.sh returned a response for {self.domain} that could not be parsed "
                    "as the expected JSON list. This does not show the domain has no "
                    "subdomains — only that this source could not be read."
                ),
                reason="ambiguous_response",
            )
            return []

        evidence = [
            capture_http_pair(
                label=f"crt.sh search for %.{self.domain}",
                control_request={"method": "GET", "url": control_url},
                control_response=_as_raw(control_response),
                test_request={"method": "GET", "url": test_url},
                test_response=_as_raw(test_response),
                delta={"control": "bare apex query", "test": "wildcard subdomain query"},
            )
        ]
        if not candidates:
            self._clear("subdomains-ct-log")
            return []

        self._emit_reported(
            check=CHECKS["subdomains-ct-log"],
            independence_class=CT_LOG,
            location="$",
            evidence=evidence,
            description=(
                f"Certificate Transparency logs record {len(candidates)} name(s) under "
                f"{self.domain} that have had a certificate issued: {', '.join(candidates)}."
            ),
            impact=(
                "These names are a public inventory of this domain's attack surface, "
                "visible to anyone who queries the same logs."
            ),
            remediation=(
                "No action is required for a name that is deliberately public. Retire the "
                "DNS record for any name here that no longer corresponds to a live service, "
                "so it does not become a takeover target."
            ),
            analysis={"candidates": candidates},
        )
        return candidates

    # --- dns-records ------------------------------------------------------

    def _check_dns_records(self, candidates: list[str]) -> None:
        apex = self.resolved[self.domain]
        if not apex.a.is_definite():
            self._inconclusive(
                "dns-records",
                answer=apex.a,
                description=(
                    f"The A lookup for {self.domain} returned {apex.a.rcode}, so we cannot "
                    "enumerate this domain's DNS records or its resolving subdomains. That is "
                    "not the same as there being none."
                ),
            )
            return

        self.resolved_subdomains: list[str] = []
        related: list[dict[str, str]] = []
        for name in candidates:
            info = self.resolved[name]
            if self._is_wildcard_shadow(info):
                continue
            # A CNAME's *target* is a relationship, not a scannable asset of
            # ours (we never scan a third party's host). But the source name is
            # a live subdomain under this domain if it resolves — found by the
            # live cross-check (2026-09-03): dropping CNAME'd names lost
            # www/accounts/... from real infrastructure. So the target is
            # recorded as `related`, and the name itself is still contributed
            # below whenever it resolves to an address, whether directly or by
            # following the CNAME. A dangling CNAME (target NXDOMAIN) has no
            # address, so it is correctly not contributed and is left to the
            # takeover check.
            if info.cname.is_definite() and info.cname.records:
                target = info.cname.records[0].strip().rstrip(".").lower()
                if not ct.is_within_apex(target, self.domain):
                    related.append({"type": "domain", "value": target, "relation": "cname_target"})
            has_address = (info.a.is_definite() and info.a.records) or (
                info.aaaa.is_definite() and info.aaaa.records
            )
            if has_address:
                self.resolved_subdomains.append(name)

        for mx in self.apex_mx.records if self.apex_mx.is_definite() else []:
            target = mx.split()[-1].strip().rstrip(".").lower()
            if target and target != ".":
                related.append({"type": "domain", "value": target, "relation": "mail_exchange"})

        evidence = [
            dns_evidence(
                label=f"A at {self.domain} and its candidate subdomains",
                test=apex.a,
                control=self.a_wildcard_probe,
                control_rationale=self._wildcard_rationale(self.a_wildcard_probe),
                analysis={
                    "resolved_subdomains": self.resolved_subdomains,
                    "ns": self.apex_ns.records if self.apex_ns.is_definite() else [],
                    "mx": self.apex_mx.records if self.apex_mx.is_definite() else [],
                    "soa": self.apex_soa.records if self.apex_soa.is_definite() else [],
                },
            )
        ]

        if not self.resolved_subdomains:
            self._clear("dns-records")
            return

        finding = self._emit_reported(
            check=CHECKS["dns-records"],
            independence_class=DNS_RESOLUTION,
            location="$",
            evidence=evidence,
            description=(
                f"{len(self.resolved_subdomains)} subdomain(s) of {self.domain} resolve to an "
                f"address: {', '.join(self.resolved_subdomains)}."
            ),
            impact=(
                "Each of these is a live host under this domain's name, and each is part of "
                "the domain's attack surface."
            ),
            remediation=(
                "Confirm every resolving subdomain is still in active use. Remove the DNS "
                "record for any that is not, before it becomes a target for takeover."
            ),
            related_assets=related,
        )
        for name in self.resolved_subdomains:
            self.ctx.assets.contribute(
                DiscoveredAsset(
                    asset=Asset(type="domain", value=name),
                    discovered_by=self.scanner.name,
                    evidence=finding.id,
                    check_id="dns-records",
                )
            )

    def _is_wildcard_shadow(self, info: _Resolved) -> bool:
        """Whether this name only "resolves" because the zone answers every name.

        Compares against the wildcard probe's own answer, taken at the same
        rrtype. A candidate whose records differ from the wildcard's is a
        real observation even in a wildcard zone.
        """
        if not self.a_wildcard:
            return False
        probe = self.a_wildcard_probe
        if probe is None or not probe.records:
            return False
        return sorted(info.a.records) == sorted(probe.records) and bool(info.a.records)

    # --- DNSSEC -------------------------------------------------------------

    def _zone_apex(self) -> tuple[str | None, DnsResponse | None]:
        """The zone `self.domain` belongs to: the nearest name, itself or above,
        that holds a SOA record. Returns (apex, None), or (None, the answer that
        stopped the walk).

        D53: DS records exist only at delegations, so a name inside a signed
        zone has none of its own. A name with a CNAME is never an apex (a CNAME
        cannot sit beside a SOA), and dnspython follows the CNAME, so its SOA
        answer would be the target zone's."""
        labels = self.domain.split(".")
        for i in range(len(labels)):
            name = ".".join(labels[i:])
            own = name == self.domain
            cname = self.resolved[name].cname if own else self.dns.query(name, "CNAME")
            if not cname.is_definite():
                return None, cname
            if cname.records:
                continue
            soa = self.apex_soa if own else self.dns.query(name, "SOA")
            if not soa.is_definite():
                return None, soa
            if soa.records:
                return name, None
        return None, None

    def _check_dnssec(self) -> None:
        zone, stopped = self._zone_apex()
        if zone is None:
            stopped = stopped or self.apex_soa
            self._inconclusive(
                "dnssec-status",
                answer=stopped,
                description=(
                    f"The zone {self.domain} belongs to could not be found: the "
                    f"{stopped.rrtype} lookup for {stopped.name} did not return a definite "
                    "answer, so DNSSEC delegation state could not be determined."
                ),
            )
            return
        # How the finding names what was judged: the target, or the zone it is in.
        subject = (
            self.domain if zone == self.domain else f"{self.domain} is in the zone {zone}, which"
        )

        ds = self.dns.query(zone, "DS")
        dnskey = self.dns.query(zone, "DNSKEY")
        state = dnssec.dnssec_state(ds, dnskey)

        evidence = [
            dns_evidence(
                label=f"DS at {zone}, DNSKEY at {zone}",
                test=ds,
                control=dnskey,
                control_rationale=(
                    "the child zone's own DNSKEY answer, read alongside the parent's DS record "
                    "— a secure delegation requires both to agree"
                ),
                analysis={"ds": ds.records, "dnskey": dnskey.records, "state": state},
            )
        ]

        if state == "inconclusive":
            self._inconclusive(
                "dnssec-status",
                answer=ds if not ds.is_definite() else dnskey,
                description=(
                    f"The DS or DNSKEY lookup for {zone} did not return a definite "
                    "answer, so DNSSEC delegation state could not be determined."
                ),
            )
            return

        if state == "signed":
            self._clear("dnssec-status")
            return

        # Independent second-resolver re-query: a zone that reads the same
        # unsigned/bogus state through a second resolver is confirmed, not
        # merely suspected — the one domscout finding that earns a validated
        # claim (the email pattern). A resolver that strips DNSSEC records
        # would disagree here, which is exactly what validation is for.
        validation = self._validate_dnssec(state, zone)

        description = {
            "insecure": (
                f"{subject} publishes no DS record at the parent and no DNSKEY at the "
                "child — the zone is not signed with DNSSEC."
            ),
            "bogus": (
                (f"{self.domain} is in the zone {zone}. " if zone != self.domain else "")
                + f"The parent zone delegates trust to a DS record for {zone}, but the "
                "zone serves no DNSKEY — a broken delegation, not merely an unsigned zone."
            ),
        }[state]

        self._emit_reported(
            check=CHECKS["dnssec-status"],
            independence_class=DNS_RESOLUTION,
            location="$",
            evidence=evidence,
            description=description,
            impact=(
                "Without DNSSEC, a resolver has no way to detect a forged or tampered answer "
                "for this zone; a network attacker able to spoof responses can redirect "
                "traffic silently."
                if state == "insecure"
                else (
                    "A validating resolver treats every answer for this zone as bogus and "
                    "returns SERVFAIL, which can make the domain and its subdomains "
                    "unreachable for a growing share of resolvers."
                )
            ),
            remediation=(
                "Enable DNSSEC signing with your DNS provider and publish the resulting DS "
                "record with your registrar."
                if state == "insecure"
                else (
                    "Either publish a DNSKEY that matches the DS record at the parent, or "
                    "remove the DS record until signing is correctly configured."
                )
            ),
            validation=validation,
        )

    def _validate_dnssec(self, state: str, zone: str) -> dict[str, Any]:
        """Re-query DS/DNSKEY through an independent resolver.

        Passed only when the second resolver reaches the same reported state.
        Unavailable (never failed silently) when no second resolver is
        configured — validation that cannot run says so, it does not pretend.
        """
        second = self.dns.second_resolver()
        if second is None:
            return {
                "attempted": False,
                "outcome": "unavailable",
                "method": "second_resolver_dnssec",
            }
        ds = self.dns.query(zone, "DS", resolver=second)
        dnskey = self.dns.query(zone, "DNSKEY", resolver=second)
        agreed = dnssec.dnssec_state(ds, dnskey) == state
        return {
            "attempted": True,
            "outcome": "passed" if agreed else "failed",
            "method": "second_resolver_dnssec",
        }

    # --- RDAP expiry ----------------------------------------------------

    def _check_expiry(self) -> None:
        # Operator ruling 2026-10-10, ADR-032: a special-use name has no registry,
        # so expiry does not apply. Said so explicitly, never a silent pass.
        if rdap_bootstrap.is_special_use(self.domain):
            for check_id in ("domain-expiring", "domain-expired"):
                self.checks.append(
                    not_applicable(
                        check_id,
                        "special-use-name",
                        declared=CHECKS[check_id].not_applicable_reasons,
                    )
                )
            return

        url = rdap_bootstrap.rdap_url(self.domain)
        if url is None:
            published = rdap_bootstrap.bootstrap().publication.date().isoformat()
            self._inconclusive_http(
                "domain-expiring",
                label=f"IANA RDAP bootstrap (vendored, published {published}) for {self.domain}",
                request={"method": "GET", "url": "https://data.iana.org/rdap/dns.json"},
                description=(
                    f"IANA's RDAP bootstrap (published {published}) lists no RDAP server for "
                    f"{self.domain}'s top-level domain (RFC 9224 §7), so registration expiry "
                    "could not be read. This scan does not use WHOIS."
                ),
                reason="blocked_prerequisite",
            )
            self._not_applicable("domain-expired")
            return

        host = urlsplit(url).hostname
        label = f"RDAP record for {self.domain} from {host}"
        try:
            test_response = self.http.get(url)
            control_response = self.http.get(url)
        except Exception as exc:
            self._inconclusive_http(
                "domain-expiring",
                label=label,
                request={"method": "GET", "url": url},
                description=(
                    f"The registry's RDAP server ({host}) could not be reached for "
                    f"{self.domain}: {type(exc).__name__}: {exc}."
                ),
                reason="blocked_prerequisite",
            )
            self._not_applicable("domain-expired")
            return

        # ADR-031 clause 5: a redirect is reported as what happened, never parsed.
        if 300 <= test_response.status_code < 400:
            location = test_response.headers.get("location", "")
            elsewhere = urlsplit(location).hostname or location or "an unnamed location"
            self._inconclusive_http(
                "domain-expiring",
                label=label,
                request={"method": "GET", "url": url},
                response=test_response,
                description=(
                    f"The registry's RDAP server ({host}) redirected to {elsewhere}, which "
                    "this scan may not contact, so expiry was not read."
                ),
                reason="blocked_prerequisite",
            )
            self._not_applicable("domain-expired")
            return

        # Registries differ for a name they do not hold (seen 2026-10-10 for a
        # subdomain): Verisign answers 404, PIR 400.
        if test_response.status_code in (400, 404):
            self._inconclusive_http(
                "domain-expiring",
                label=label,
                request={"method": "GET", "url": url},
                response=test_response,
                description=(
                    f"The registry's RDAP server ({host}) has no registration for "
                    f"{self.domain} (HTTP {test_response.status_code}). If it is a subdomain, "
                    "the registered domain above it is what expires; finding that needs the "
                    "Public Suffix List, which this scan does not use yet (D49)."
                ),
                reason="blocked_prerequisite",
            )
            self._not_applicable("domain-expired")
            return

        if test_response.status_code == 429 or test_response.status_code >= 400:
            self._inconclusive_http(
                "domain-expiring",
                label=label,
                request={"method": "GET", "url": url},
                response=test_response,
                description=(
                    f"The registry's RDAP server ({host}) returned HTTP "
                    f"{test_response.status_code} for {self.domain}."
                ),
                reason=(
                    "rate_limited" if test_response.status_code == 429 else "blocked_prerequisite"
                ),
            )
            self._not_applicable("domain-expired")
            return

        info = rdapp.parse_rdap(test_response.text)
        today = datetime.now(UTC).date()
        verdict = rdapp.expiry_verdict(info, today)

        # The record names what it is about. NIXI answers any name under a
        # registered domain with that domain's record (seen 2026-10-10), so a
        # date is reported under the name the registry gave, and only when that
        # name is the target or an ancestor of it. Anything else is not ours.
        queried = a_label(self.domain) or self.domain
        registered = info.name or queried
        if registered != queried and not queried.endswith("." + registered):
            self._inconclusive_http(
                "domain-expiring",
                label=label,
                request={"method": "GET", "url": url},
                response=test_response,
                description=(
                    f"The registry's RDAP server ({host}) answered the query for "
                    f"{self.domain} with the record for {registered}, which is neither that "
                    "name nor above it, so no expiry is attributed to it."
                ),
                reason="ambiguous_response",
            )
            self._not_applicable("domain-expired")
            return
        subject = (
            self.domain
            if registered == queried
            else f"{registered} (the registered domain above {self.domain}, as the registry's "
            "record names it)"
        )

        evidence = [
            capture_http_pair(
                label=label,
                control_request={"method": "GET", "url": url},
                control_response=_as_raw(control_response),
                test_request={"method": "GET", "url": url},
                test_response=_as_raw(test_response),
                delta={},
            )
        ]
        attestation = (
            "This is a single-source attestation — the registry's own RDAP record, read "
            "twice — not corroborated by a second, independent registry."
        )

        if verdict == "unknown":
            self._inconclusive_http(
                "domain-expiring",
                label=label,
                request={"method": "GET", "url": url},
                response=test_response,
                description=(
                    f"The RDAP record for {self.domain} from the registry ({host}) carries no "
                    "expiration event, so registration expiry could not be read."
                ),
                reason="ambiguous_response",
            )
            self._not_applicable("domain-expired")
            return

        if verdict == "ok":
            self._clear("domain-expiring")
            self._clear("domain-expired")
            return

        if verdict == "expiring":
            assert info.expiry is not None
            self._emit_reported(
                check=CHECKS["domain-expiring"],
                independence_class=RDAP,
                location="$",
                evidence=evidence,
                description=(
                    f"{subject}: the registration expires on {info.expiry.isoformat()}, "
                    f"within {rdapp.EXPIRING_WITHIN_DAYS} days. {attestation}"
                ),
                impact=(
                    "An expired domain can be re-registered by anyone, who then controls DNS, "
                    "email and any service running under the name."
                ),
                remediation="Renew the domain registration before its expiry date.",
                materialises_at=info.expiry,
                materialises_reason="the registry's own RDAP record states this expiration date",
            )
            self._clear("domain-expired")
            return

        assert info.expiry is not None
        self._emit_reported(
            check=CHECKS["domain-expired"],
            independence_class=RDAP,
            location="$",
            evidence=evidence,
            description=(
                f"{subject}: the registration expired on {info.expiry.isoformat()}. {attestation}"
            ),
            impact=(
                "The domain is available for anyone to re-register, taking control of DNS, "
                "email and any service running under the name."
            ),
            remediation="Renew the domain registration immediately.",
        )
        self._clear("domain-expiring")

    # --- takeover ---------------------------------------------------------

    def _check_takeover(self, candidates: list[str]) -> None:
        # Baseline: the check ran and found nothing, revised below if a match is confirmed.
        self._clear("subdomain-takeover")
        for name in candidates:
            info = self.resolved[name]
            if not (info.cname.is_definite() and info.cname.records):
                continue
            target = info.cname.records[0].strip().rstrip(".").lower()
            fp = takeover.match_cname(target)
            if fp is None:
                continue
            self.ctx.check_alive()
            self._evaluate_takeover(name, target, fp)

    def _evaluate_takeover(self, name: str, target: str, fp: TakeoverFingerprint) -> None:
        target_a = self.dns.query(target, "A")
        if not target_a.is_definite():
            self._inconclusive(
                "subdomain-takeover",
                answer=target_a,
                description=(
                    f"{name} has a CNAME to {target}, matching the {fp.name} takeover "
                    f"pattern, but the A lookup for {target} returned {target_a.rcode} — "
                    "whether it is dangling could not be determined."
                ),
                location=name,
            )
            return
        cname_nxdomain = target_a.rcode == "NXDOMAIN"

        # A fingerprint's HTTP need is a fact about *this evaluation*, not a
        # fixed attribute of the class — ask it with no response first.
        needs_http = fp.evaluate(cname_nxdomain, None).needs_http

        http_response: CapturedResponse | None = None
        # D31: plain http, because for a custom domain the provider's certificate
        # does not cover the name and the unclaimed page is never reached over https
        url = f"{fp.scheme}://{name}/"
        if needs_http:
            try:
                http_response = self.http.get(url)
            except Exception as exc:
                self._inconclusive_http(
                    "subdomain-takeover",
                    label=f"HTTP fetch of {name}",
                    request={"method": "GET", "url": url},
                    description=(
                        f"{name} has a CNAME to {target}, matching the {fp.name} takeover "
                        f"pattern, but the response body could not be fetched: "
                        f"{type(exc).__name__}: {exc}. A failed GET is never taken as proof "
                        "of takeover."
                    ),
                    reason="blocked_prerequisite",
                    location=name,
                )
                return

        result = fp.evaluate(cname_nxdomain, http_response)
        if not result.matched:
            self._clear("subdomain-takeover", location=name)
            return

        evidence: list[Any]
        if needs_http and http_response is not None:
            second = self.http.get(url)
            evidence = [
                capture_http_pair(
                    label=f"HTTP fetch of {name}",
                    control_request={"method": "GET", "url": url},
                    control_response=_as_raw(second),
                    test_request={"method": "GET", "url": url},
                    test_response=_as_raw(http_response),
                    delta={"detail": result.detail},
                )
            ]
        else:
            evidence = [
                dns_evidence(
                    label=f"CNAME at {name}, A at {target}",
                    test=self.resolved[name].cname,
                    control=target_a,
                    control_rationale=(
                        "an independent A-record lookup of the CNAME target, confirming it "
                        "does not resolve"
                    ),
                )
            ]

        self._emit_reported(
            check=CHECKS["subdomain-takeover"],
            independence_class=HTTP_FINGERPRINT,
            location=name,
            evidence=evidence,
            description=(
                f"{name} has a CNAME to {target}, which matches the {fp.name} takeover "
                f"pattern: {result.detail}."
            ),
            impact=(
                f"Anyone able to claim the underlying {fp.service} resource can serve content "
                f"from {name}, which still carries this domain's name and any trust that "
                "implies."
            ),
            remediation=(
                f"Remove the DNS record for {name} if it is no longer in use, or reclaim the "
                f"{fp.service} resource it points to."
            ),
            references=[fp.source],
        )

    # --- emitting -----------------------------------------------------------

    def _emit_reported(
        self,
        *,
        check: Check,
        independence_class: str,
        location: str,
        evidence: list[Any],
        description: str,
        impact: str,
        remediation: str,
        analysis: dict[str, Any] | None = None,
        related_assets: list[dict[str, str]] | None = None,
        materialises_at: date | None = None,
        materialises_reason: str | None = None,
        references: list[str] | None = None,
        validation: dict[str, Any] | None = None,
    ) -> Finding:
        del analysis  # carried on the evidence's own `analysis` field, not here
        result = self.engine.combine(
            [
                Signal(
                    method=f"domscout_{check.check_id.replace('-', '_')}",
                    prior=0.5,
                    likelihood_ratio=check.likelihood_ratio,
                    independence_class=independence_class,
                    prior_justification=check.justification,
                )
            ]
        )
        now = datetime.now(UTC)
        finding = Finding.create(
            org_id=self.ctx.org_id,
            scanner=self.scanner.name,
            scanner_version=self.scanner.version,
            check_id=check.check_id,
            title=check.title,
            target=self.target,
            location=location,
            severity=check.severity,
            confidence=result.confidence,
            confidence_provisional=result.provisional,
            detection_methods=result.detection_methods,
            validation=validation or {"attempted": False, "outcome": "not_applicable"},
            evidence=evidence,
            related_assets=related_assets or [],
            description=description,
            impact=impact,
            remediation=remediation,
            references=references or [],
            taxonomy={},
            first_seen=now,
            first_seen_scan_id=self.ctx.scan_id,
            last_seen=now,
            last_seen_scan_id=self.ctx.scan_id,
            cost=self.ctx.cost.snapshot(),
            materialises_at=materialises_at,
            materialises_reason=materialises_reason,
        )
        self.findings.append(finding)
        self.checks.append(CheckRun(check_id=check.check_id, location=location, outcome="reported"))
        return finding

    def _inconclusive(
        self,
        check_id: str,
        *,
        answer: DnsResponse,
        description: str,
        location: str = "$",
    ) -> None:
        check = CHECKS[check_id]
        class_by_check = {
            "subdomains-ct-log": CT_LOG,
            "dns-records": DNS_RESOLUTION,
            "dnssec-status": DNS_RESOLUTION,
            "domain-expiring": RDAP,
            "domain-expired": RDAP,
            "subdomain-takeover": HTTP_FINGERPRINT,
        }
        result = self.engine.combine(
            [
                Signal(
                    method=f"domscout_{check_id.replace('-', '_')}",
                    prior=0.5,
                    likelihood_ratio=1.0,
                    independence_class=class_by_check[check_id],
                    prior_justification=(
                        "the lookup produced no usable answer, so nothing moves the prior"
                    ),
                )
            ]
        )
        evidence = [
            dns_evidence(
                label=f"{answer.rrtype} at {answer.name}",
                test=answer,
                control=None,
                control_rationale="no control is possible: the lookup itself did not succeed",
            )
        ]
        now = datetime.now(UTC)
        finding = Finding.create(
            org_id=self.ctx.org_id,
            scanner=self.scanner.name,
            scanner_version=self.scanner.version,
            check_id=check_id,
            title=check.title,
            target=self.target,
            location=location,
            severity=check.severity,
            confidence=result.confidence,
            confidence_provisional=result.provisional,
            no_verdict_reason=NO_VERDICT_FOR_RCODE.get(answer.rcode, "blocked_prerequisite"),
            detection_methods=result.detection_methods,
            validation={"attempted": False, "outcome": "unavailable"},
            evidence=evidence,
            description=description,
            impact="Unknown until the lookup succeeds.",
            remediation=(
                "Re-run the scan. A persistent failure usually means a broken delegation or a "
                "DNSSEC validation problem on the authoritative nameservers."
            ),
            references=[],
            taxonomy={},
            first_seen=now,
            first_seen_scan_id=self.ctx.scan_id,
            last_seen=now,
            last_seen_scan_id=self.ctx.scan_id,
            cost=self.ctx.cost.snapshot(),
        )
        self.findings.append(finding)
        self.checks.append(CheckRun(check_id=check_id, location=location, outcome="inconclusive"))

    def _inconclusive_http(
        self,
        check_id: str,
        *,
        label: str,
        request: dict[str, Any],
        description: str,
        reason: str,
        response: CapturedResponse | None = None,
        location: str = "$",
    ) -> None:
        check = CHECKS[check_id]
        class_by_check = {
            "subdomains-ct-log": CT_LOG,
            "domain-expiring": RDAP,
            "domain-expired": RDAP,
            "subdomain-takeover": HTTP_FINGERPRINT,
        }
        result = self.engine.combine(
            [
                Signal(
                    method=f"domscout_{check_id.replace('-', '_')}",
                    prior=0.5,
                    likelihood_ratio=1.0,
                    independence_class=class_by_check[check_id],
                    prior_justification=(
                        "the request produced no usable answer, so nothing moves the prior"
                    ),
                )
            ]
        )
        test_response_raw = (
            _as_raw(response)
            if response is not None
            else {
                "status": 0,
                "headers": {},
                "body": None,
                "elapsed_ms": 0,
            }
        )
        evidence = [
            capture_http_pair(
                label=label,
                control_request=request,
                control_response=test_response_raw,
                test_request=request,
                test_response=test_response_raw,
                delta={},
            )
        ]
        no_verdict_reason = {
            "rate_limited": "rate_limited",
            "blocked_prerequisite": "blocked_prerequisite",
            "ambiguous_response": "ambiguous_response",
        }.get(reason, "blocked_prerequisite")
        now = datetime.now(UTC)
        finding = Finding.create(
            org_id=self.ctx.org_id,
            scanner=self.scanner.name,
            scanner_version=self.scanner.version,
            check_id=check_id,
            title=check.title,
            target=self.target,
            location=location,
            severity=check.severity,
            confidence=result.confidence,
            confidence_provisional=result.provisional,
            no_verdict_reason=no_verdict_reason,
            detection_methods=result.detection_methods,
            validation={"attempted": False, "outcome": "unavailable"},
            evidence=evidence,
            description=description,
            impact="Unknown until the request succeeds.",
            remediation=(
                "Re-run the scan; a persistent failure suggests the source is down or blocking us."
            ),
            references=[],
            taxonomy={},
            first_seen=now,
            first_seen_scan_id=self.ctx.scan_id,
            last_seen=now,
            last_seen_scan_id=self.ctx.scan_id,
            cost=self.ctx.cost.snapshot(),
        )
        self.findings.append(finding)
        self.checks.append(CheckRun(check_id=check_id, location=location, outcome="inconclusive"))

    def _clear(self, check_id: str, *, location: str = "$") -> None:
        self.checks.append(CheckRun(check_id=check_id, location=location, outcome="clear"))

    def _not_applicable(self, check_id: str) -> None:
        """A check that did not run because its prerequisite never resolved.

        Not recorded in `checks_run` at all — see the identical helper and
        rationale in `scanners/email/scanner.py`.
        """

    def _wildcard_rationale(self, probe: DnsResponse | None) -> str:
        if probe is None:
            return "the wildcard probe did not return a definite answer"
        return (
            "a random-label A probe in the same zone; without it a wildcard would make every "
            "name under this domain appear to resolve"
        )


def _as_raw(response: CapturedResponse) -> dict[str, Any]:
    return {
        "method": "GET",
        "url": response.url,
        "status": response.status_code,
        "headers": dict(response.headers),
        "body": response.text,
        "elapsed_ms": response.captured.get("elapsed_ms"),
        # ADR-029: the capture's receipts, so live and replay record the same
        "redaction_receipts": response.captured.get("redaction_receipts", []),
    }
