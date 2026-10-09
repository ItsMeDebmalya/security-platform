"""The check catalogue: severity, prior, and why the prior is what it is.

Every entry here is a promise made in docs/10-measurement.md - a detection
does not ship without a stated `independence_class` and a hand-assigned prior
with a written justification. Keeping them in one table makes it obvious when
one is missing, and it is the list the calibration buckets will be fitted
against in Phase 4.

Priors are all 0.5. Before we look at a domain we have no information about
whether it is misconfigured, and inventing an informative prior would be
pretending to knowledge we do not have. The evidence does the work, through
the likelihood ratio.
"""

from __future__ import annotations

from dataclasses import dataclass

from core.authz import checks_require_authorisation
from core.models import Mode

DNS_CLASS = "dns"
"""Every check in this scanner observes the same channel: authoritative DNS.

Stated once, plainly, because it has a consequence: two email checks agreeing
is one signal restated, not corroboration. That is why findings here reach
`confirmed` through independent re-query and validation rather than by piling
up agreeing checks.
"""


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
        # Every check below reads only the authoritative DNS answers this
        # scanner queried for itself - no SMTP connection, no HTTP request,
        # nothing sent to the target's own infrastructure. All are passive.
        Check(
            check_id="spf-missing",
            title="No SPF record published",
            severity="medium",
            likelihood_ratio=40.0,
            justification=(
                "a definite TXT answer containing no v=spf1 term is a direct observation; "
                "the failure modes are a broken resolver and a masked record, and both are checked"
            ),
            passive=True,
        ),
        Check(
            check_id="spf-invalid",
            title="SPF record is not valid",
            severity="medium",
            likelihood_ratio=30.0,
            justification=(
                "RFC 7208 syntax is unambiguous, but real-world records use extensions we may "
                "not know, so the ratio is below that of a plain absence"
            ),
            passive=True,
        ),
        Check(
            check_id="spf-multiple-records",
            title="More than one SPF record published",
            severity="medium",
            likelihood_ratio=40.0,
            justification="counting records at one name leaves no room for interpretation",
            passive=True,
        ),
        Check(
            check_id="spf-too-permissive",
            title="SPF policy permits any sender",
            severity="high",
            likelihood_ratio=40.0,
            justification="the qualifier on the all mechanism is read directly from the record",
            passive=True,
            mode="standard",
        ),
        Check(
            check_id="spf-lookup-limit",
            title="SPF exceeds the 10 DNS lookup limit",
            severity="high",
            likelihood_ratio=25.0,
            justification=(
                "the count is computed from records we fetched ourselves, but include chains "
                "change often and a chain we could not finish walking returns inconclusive"
            ),
            passive=True,
            mode="standard",
        ),
        Check(
            check_id="dmarc-missing",
            title="No DMARC record published",
            severity="high",
            likelihood_ratio=40.0,
            justification=(
                "a definite TXT answer at _dmarc with no v=DMARC1 term is a direct observation"
            ),
            passive=True,
        ),
        Check(
            check_id="dmarc-invalid",
            title="DMARC record would be ignored by receivers",
            severity="high",
            likelihood_ratio=30.0,
            justification=(
                "RFC 7489 ordering rules are explicit, though receiver implementations vary in "
                "how strictly they enforce them"
            ),
            passive=True,
        ),
        Check(
            check_id="dmarc-policy-none",
            title="DMARC policy is set to 'none'",
            severity="medium",
            likelihood_ratio=40.0,
            justification="the p= tag is read directly from a record that parsed",
            passive=True,
        ),
        Check(
            check_id="dmarc-pct-partial",
            title="DMARC policy is applied to only part of the mail stream",
            severity="medium",
            likelihood_ratio=40.0,
            justification="the pct= tag is read directly from a record that parsed",
            passive=True,
            mode="standard",
        ),
        Check(
            check_id="dmarc-obsolete-tags",
            title="DMARC record uses tags removed by RFC 9989",
            severity="low",
            likelihood_ratio=40.0,
            justification=(
                "the tag names are read directly from a record that parsed, and the list of "
                "removed tags is RFC 9989 Appendix C.5.2"
            ),
            passive=True,
            mode="standard",
        ),
        Check(
            check_id="dmarc-test-mode",
            title="DMARC policy is in test mode (t=y)",
            severity="medium",
            likelihood_ratio=4.0,
            justification=(
                "t=y is read directly, but only RFC 9989 receivers act on it; RFC 7489 "
                "receivers apply the policy as written, so the effect is receiver-dependent"
            ),
            passive=True,
        ),
        Check(
            check_id="dmarc-np-weaker",
            title="DMARC np= is weaker than the subdomain policy",
            severity="low",
            likelihood_ratio=4.0,
            justification=(
                "np= is read directly, but only RFC 9989 receivers act on it, so the effect is "
                "receiver-dependent"
            ),
            passive=True,
            mode="standard",
        ),
        Check(
            check_id="dmarc-no-rua",
            title="DMARC has no reporting address",
            severity="low",
            likelihood_ratio=40.0,
            justification="the absence of a rua= tag in a parsed record is unambiguous",
            passive=True,
            mode="standard",
        ),
        Check(
            check_id="dmarc-alignment",
            title="DMARC uses relaxed alignment",
            severity="info",
            likelihood_ratio=40.0,
            justification="the adkim= and aspf= tags are read directly, and default to relaxed",
            passive=True,
            mode="standard",
        ),
        Check(
            check_id="mx-missing",
            title="No MX records published",
            severity="medium",
            likelihood_ratio=40.0,
            justification="a definite empty MX answer is a direct observation",
            passive=True,
        ),
        Check(
            check_id="dkim-missing",
            title="No DKIM key found",
            severity="medium",
            likelihood_ratio=40.0,
            justification=(
                "selectors cannot be enumerated, so this check reaches a verdict only when a "
                "key is found; a failed search is inconclusive by construction"
            ),
            passive=True,
        ),
        Check(
            check_id="dkim-weak-key",
            title="DKIM key is below 2048 bits",
            # low: at 1024 bits the key meets RFC 8301's minimum. A key below
            # that minimum is raised to medium where it is reported.
            severity="low",
            likelihood_ratio=30.0,
            justification=(
                "the modulus length is measured from the key itself; every common selector is "
                "read, but a domain may publish others we cannot find"
            ),
            passive=True,
            mode="standard",
        ),
        Check(
            check_id="mta-sts-missing",
            title="No MTA-STS policy published",
            severity="low",
            likelihood_ratio=40.0,
            justification=(
                "a definite TXT answer at _mta-sts with no v=STSv1 term is direct observation"
            ),
            passive=True,
            mode="standard",
        ),
        Check(
            check_id="tls-rpt-missing",
            title="No SMTP TLS reporting configured",
            severity="low",
            likelihood_ratio=40.0,
            justification=(
                "a definite TXT answer at _smtp._tls with no v=TLSRPTv1 term is direct observation"
            ),
            passive=True,
            mode="standard",
        ),
        Check(
            check_id="spoofing-possible",
            title="Mail can be sent as this domain",
            severity="high",
            likelihood_ratio=25.0,
            justification=(
                "this is a simulation of a receiver's decision from records we read, not an "
                "observation of a receiver actually making it; the ratio is lower to say so"
            ),
            passive=True,
        ),
    ]
}


def requires_authorisation(mode: Mode) -> bool:
    """Whether this scanner's checks need a valid authorisation record in `mode`.

    Every check above is declared `passive=True` - this scanner queries only
    public authoritative DNS, never the target's own infrastructure - so
    this always returns False today. It is not hand-set to False, though:
    it is computed from the catalogue so that adding a genuinely active
    email check (D4's `open-relay` needs an SMTP connection) flips this
    automatically instead of requiring someone to remember a second place.
    """
    return checks_require_authorisation(CHECKS.values(), mode=mode)


COMMON_SELECTORS = (
    "selector1",
    "selector2",
    "google",
    "default",
    "dkim",
    "mail",
    "k1",
    "k2",
    "s1",
    "s2",
    "smtp",
    "mandrill",
    "everlytickey1",
    "zoho",
    "protonmail",
    "fm1",
    "sig1",
)
"""Selectors we can guess.

This list is the whole reason `dkim-missing` cannot be a confident finding.
DKIM selectors are chosen freely by the sender and there is no way to
enumerate them; not finding one of these proves nothing. The list is here to
find a key when we can, not to conclude anything when we cannot.
"""
