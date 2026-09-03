"""The check catalogue: severity, prior, and why the prior is what it is.

Every entry here is a promise made in docs/10-measurement.md - a detection
does not ship without a stated `independence_class` and a hand-assigned prior
with a written justification. Keeping them in one table makes it obvious when
one is missing, and it is the list the calibration buckets will be fitted
against in Phase 4.

All six checks are Light: enumeration and posture read from public services
(Certificate Transparency logs, authoritative DNS, RDAP) that this scanner
queries for itself - never a connection to the target's own infrastructure.
That is why every one of them is passive.
"""

from __future__ import annotations

from dataclasses import dataclass

from core.authz import checks_require_authorisation
from core.models import Mode

CT_LOG = "ct_log"
"""A name observed in a public Certificate Transparency log - a third party's
record of a certificate having been issued, not anything we asked the target
for."""

DNS_RESOLUTION = "dns_resolution"
"""An authoritative DNS answer this scanner queried for itself. The same
channel the email scanner reads, and independent of CT_LOG and RDAP for the
same reason: different infrastructure, different way of being wrong."""

RDAP = "rdap"
"""A registry's own record of a domain's lifecycle, read from the RDAP
service that succeeded WHOIS. Independent of DNS: a domain can resolve while
its registration has lapsed, and vice versa during grace periods."""

HTTP_FINGERPRINT = "http_fingerprint"
"""A response fingerprint read from a CNAME target believed to host nothing -
the standard subdomain-takeover signal. Independent of the DNS_RESOLUTION
class even though it starts from a DNS answer: the fingerprint is a
observation about a different party's server, not about the DNS itself."""


@dataclass(frozen=True)
class Check:
    check_id: str
    title: str
    severity: str
    likelihood_ratio: float
    justification: str
    passive: bool
    """docs/03-roadmap.md 0b.6: the ownership gate enforces this declaration
    directly, regardless of `mode` - see `core.authz.checks_require_authorisation`.
    No default, deliberately: a check with no opinion here fails to
    construct rather than reading as passive by omission."""
    mode: str = "light"


CHECKS: dict[str, Check] = {
    c.check_id: c
    for c in [
        # Every check below reads a public service this scanner queries for
        # itself - a CT log, authoritative DNS, or RDAP - never a request to
        # the target's own infrastructure. All are passive, all Light.
        Check(
            check_id="subdomains-ct-log",
            title="Subdomains discovered via Certificate Transparency logs",
            severity="info",
            likelihood_ratio=40.0,
            justification=(
                "a name appearing in a public CT log is a direct third-party record of a "
                "certificate having been issued for it, not an inference"
            ),
            passive=True,
        ),
        Check(
            check_id="dns-records",
            title="DNS records observed for this domain and its subdomains",
            severity="info",
            likelihood_ratio=40.0,
            justification=(
                "an authoritative DNS answer we queried for ourselves is a direct observation"
            ),
            passive=True,
        ),
        Check(
            check_id="dnssec-status",
            title="DNSSEC is not fully deployed",
            severity="low",
            likelihood_ratio=30.0,
            justification=(
                "the presence of DS and RRSIG records is read directly from authoritative "
                "answers, but a resolver that strips them looks identical to a zone that "
                "never signed, so the ratio is below a plain record absence"
            ),
            passive=True,
        ),
        Check(
            check_id="domain-expiring",
            title="Domain registration expires soon",
            severity="medium",
            likelihood_ratio=40.0,
            justification="the expiry date is read directly from the registry's own RDAP record",
            passive=True,
        ),
        Check(
            check_id="domain-expired",
            title="Domain registration has expired",
            severity="high",
            likelihood_ratio=40.0,
            justification=(
                "an expiry date in the past, read directly from the registry's own RDAP "
                "record, is unambiguous"
            ),
            passive=True,
        ),
        Check(
            check_id="subdomain-takeover",
            title="Subdomain points to a service that could be claimed by another party",
            severity="high",
            likelihood_ratio=25.0,
            justification=(
                "a dangling CNAME plus a fingerprint matching a known takeover pattern is "
                "strong evidence, but fingerprint databases go stale and a provider can "
                "change its unclaimed-response page, so the ratio sits below a direct "
                "record read"
            ),
            passive=True,
        ),
    ]
}

ENUMERATION_CHECK_IDS = frozenset({"subdomains-ct-log", "dns-records"})
"""The two checks that build the subdomain inventory the other four check
IDs above reason about, rather than reporting a posture finding themselves."""

SERVICE_HOSTS = frozenset({"crt.sh", "rdap.org"})
"""The public services this scanner talks to, beyond the target's own
authoritative DNS - declared on `BaseScanner.service_hosts` so the outbound
scope check permits them without treating them as part of the target's own
scope (docs/03-roadmap.md 0b.6)."""


def requires_authorisation(mode: Mode) -> bool:
    """Whether this scanner's checks need a valid authorisation record in `mode`.

    Every check above is declared `passive=True` - this scanner queries only
    public services (CT logs, authoritative DNS, RDAP), never the target's
    own infrastructure - so this always returns False today. It is not
    hand-set to False, though: it is computed from the catalogue so that a
    genuinely active check added later flips this automatically instead of
    requiring someone to remember a second place.
    """
    return checks_require_authorisation(CHECKS.values(), mode=mode)
