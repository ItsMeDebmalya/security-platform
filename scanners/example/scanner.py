"""A deliberately trivial scanner: does this domain resolve to an A record?

It exists to exercise the whole loop end to end - registry, context, DNS
client, evidence, confidence, state derivation, schema validation, CLI output
and corpus scoring - so that adding a real scanner is a matter of writing
checks rather than rediscovering the plumbing.

It is also the smallest honest demonstration of the three result shapes:

- a domain that resolves      -> no finding, and the check recorded as `clear`
- a domain with no A record   -> a finding, validated by an independent
                                 resolver before it can reach `confirmed`
- a lookup that SERVFAILs     -> `inconclusive`, never "the record is missing"
"""

from __future__ import annotations

from datetime import UTC, datetime

from core.confidence import ConfidenceEngine, Signal
from core.context import ScanContext
from core.dns import DnsClient, DnsResponse
from core.evidence import dns_evidence
from core.models import Asset, CheckOutcome, CheckRun, Finding, Mode, ScanResult, Telemetry
from core.registry import register
from core.scanner import BaseScanner

CHECK_ID = "example-a-record-missing"

NO_VERDICT_REASONS = {
    "SERVFAIL": "servfail",
    "TIMEOUT": "timeout",
    "REFUSED": "blocked_prerequisite",
}

DETECTION_PRIOR = 0.5
"""Hand-assigned. An A-record lookup is as likely to be right as wrong before we
look, and nothing about the domain shifts that prior. Provisional until Phase 4."""

DETECTION_LR = 40.0
"""A definite NODATA/NXDOMAIN from a resolver is strong evidence: the only common
way it misleads is a wildcard zone or a broken resolver, and both are checked."""


@register
class ExampleScanner(BaseScanner):
    name = "example"
    version = "1.0.0"
    vantage = "external_unauthenticated"
    engagement = "defensive"
    supported_modes = frozenset({"light", "standard"})
    target_types = frozenset({"domain"})

    def run(self, target: Asset, mode: Mode, ctx: ScanContext) -> ScanResult:
        self.validate(target, mode)
        dns = ctx.dns
        assert isinstance(dns, DnsClient), "the example scanner needs a DNS client from the context"

        ctx.progress("checking for a wildcard in the zone", 0.2)
        ctx.check_alive()
        wildcard = dns.has_wildcard(target.value, "A")
        probe = dns.wildcard_probe(target.value, "A")

        ctx.progress("looking up the A record", 0.6)
        ctx.check_alive()
        answer = dns.query(target.value, "A")

        findings: list[Finding] = []
        outcome: CheckOutcome
        if not answer.is_definite():
            findings.append(self._inconclusive(target, answer, probe, ctx))
            outcome = "inconclusive"
        elif answer.records:
            outcome = "clear"
        else:
            findings.append(self._missing(target, answer, probe, wildcard, dns, ctx))
            outcome = "reported"

        ctx.progress("done", 1.0)
        cost = ctx.cost.snapshot()
        return ScanResult(
            scanner=self.name,
            scanner_version=self.version,
            target=target,
            mode=mode,
            findings=findings,
            errors=[],
            telemetry=Telemetry(
                checks_run=[CheckRun(check_id=CHECK_ID, location="$", outcome=outcome)],
                requests=cost.requests,
                wall_ms=cost.wall_ms,
            ),
            finished_at=datetime.now(UTC),
        )

    # --- the two outcomes that produce a finding ---------------------------

    def _missing(
        self,
        target: Asset,
        answer: DnsResponse,
        probe: DnsResponse | None,
        wildcard: bool | None,
        dns: DnsClient,
        ctx: ScanContext,
    ) -> Finding:
        engine = ConfidenceEngine()
        result = engine.combine(
            [
                Signal(
                    method="dns_a_lookup",
                    prior=DETECTION_PRIOR,
                    likelihood_ratio=DETECTION_LR,
                    independence_class="dns",
                    prior_justification=(
                        "a definite answer from a resolver, with the zone checked for a "
                        "wildcard first; provisional until Phase 4"
                    ),
                )
            ]
        )
        validation, second = self._validate(target, dns)

        evidence = [
            dns_evidence(
                label=f"A lookup for {target.value}",
                test=answer,
                control=probe,
                control_rationale=(
                    "a random-label probe in the same zone; without it a wildcard would "
                    "make every lookup look successful"
                    if probe is not None
                    else "the wildcard probe did not return a definite answer"
                ),
            )
        ]
        if second is not None:
            evidence.append(
                dns_evidence(
                    label=f"independent re-query via {second.resolver}",
                    test=second,
                    control=None,
                    control_rationale=(
                        "the control for this re-query is the first resolver's answer, "
                        "captured in the evidence above"
                    ),
                )
            )

        return Finding.create(
            org_id=ctx.org_id,
            scanner=self.name,
            scanner_version=self.version,
            vantage=self.vantage,
            engagement=self.engagement,
            check_id=CHECK_ID,
            title=f"{target.value} has no A record",
            target=target,
            location="$",
            severity="low",
            confidence=engine.calibrate(
                result.confidence, scanner=self.name, method="dns_a_lookup"
            ),
            confidence_provisional=result.provisional,
            detection_methods=result.detection_methods,
            validation=validation,
            evidence=evidence,
            related_assets=[{"type": "domain", "value": target.value, "relation": "observed_on"}],
            description=(
                f"A lookups for {target.value} returned {answer.rcode} with no addresses. "
                f"The zone was checked for a wildcard first ({'present' if wildcard else 'none'}), "
                "so this is not an artefact of a catch-all record."
            ),
            impact=(
                "Nothing resolves this name to an address, so any service expected to "
                "answer on it is unreachable by name."
            ),
            remediation=(
                f"Publish an A or AAAA record for {target.value} pointing at the host that "
                "should serve it, or remove references to the name if it is retired."
            ),
            references=["https://www.rfc-editor.org/rfc/rfc1035"],
            first_seen=datetime.now(UTC),
            first_seen_scan_id=ctx.scan_id,
            last_seen=datetime.now(UTC),
            last_seen_scan_id=ctx.scan_id,
            cost=ctx.cost.snapshot(),
        )

    def _inconclusive(
        self,
        target: Asset,
        answer: DnsResponse,
        probe: DnsResponse | None,
        ctx: ScanContext,
    ) -> Finding:
        """The lookup ran and told us nothing. That is a result, not an error."""
        engine = ConfidenceEngine()
        result = engine.combine(
            [
                Signal(
                    method="dns_a_lookup",
                    prior=DETECTION_PRIOR,
                    likelihood_ratio=1.0,
                    independence_class="dns",
                    prior_justification=(
                        "the lookup returned no usable answer, so nothing moves the prior"
                    ),
                )
            ]
        )
        return Finding.create(
            org_id=ctx.org_id,
            scanner=self.name,
            scanner_version=self.version,
            vantage=self.vantage,
            engagement=self.engagement,
            check_id=CHECK_ID,
            title=f"Could not determine whether {target.value} has an A record",
            target=target,
            location="$",
            severity="low",
            confidence=result.confidence,
            confidence_provisional=result.provisional,
            no_verdict_reason=NO_VERDICT_REASONS.get(answer.rcode, "ambiguous_response"),
            detection_methods=result.detection_methods,
            validation={"attempted": False, "outcome": "unavailable", "method": None},
            evidence=[
                dns_evidence(
                    label=f"A lookup for {target.value} returned {answer.rcode}",
                    test=answer,
                    control=probe,
                    control_rationale=(
                        "the wildcard probe, for comparison with the failed lookup"
                        if probe is not None
                        else "no control was obtainable; the resolver answered neither query"
                    ),
                )
            ],
            description=(
                f"The A lookup for {target.value} returned {answer.rcode}. That is not the "
                "same as the record being absent, and we do not report it as such."
            ),
            impact="Unknown until the lookup succeeds.",
            remediation=(
                "Re-run the scan. If it persists, check the authoritative nameservers for "
                f"{target.value} - a persistent SERVFAIL usually means a broken delegation "
                "or a DNSSEC validation failure."
            ),
            first_seen=datetime.now(UTC),
            first_seen_scan_id=ctx.scan_id,
            last_seen=datetime.now(UTC),
            last_seen_scan_id=ctx.scan_id,
            cost=ctx.cost.snapshot(),
        )

    @staticmethod
    def _validate(target: Asset, dns: DnsClient) -> tuple[dict[str, object], DnsResponse | None]:
        """Re-test through a second resolver.

        A different resolver is a genuinely independent observation of the same
        fact: it defends against a stale cache or a single broken upstream,
        which is how this check actually goes wrong. Where no second resolver
        is configured the outcome is `unavailable` - validation that could not
        run never pretends to have passed.
        """
        second = dns.second_resolver()
        if second is None:
            return {
                "attempted": False,
                "outcome": "unavailable",
                "method": "independent_resolver",
            }, None

        answer = dns.query(target.value, "A", resolver=second)
        if not answer.is_definite():
            return {
                "attempted": True,
                "outcome": "unavailable",
                "method": "independent_resolver",
            }, answer
        agreed = not answer.records
        return {
            "attempted": True,
            "outcome": "passed" if agreed else "failed",
            "method": "independent_resolver",
        }, answer
