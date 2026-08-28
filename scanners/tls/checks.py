"""The TLS check catalogue: severity, prior, and why the prior is what it is.

Every entry is a promise from docs/10-measurement.md — no detection ships
without a stated `independence_class` and a hand-assigned prior with a written
justification.

Unlike the email scanner, this one observes **two** independent channels, and
that is worth being precise about because it decides what can reach
`confirmed`:

- `certificate` — what the server presented, parsed by us
- `trust_path` — what a strictly-configured client concluded about it

An expired certificate is visible in both: we read the date, and OpenSSL
refuses the chain. Those are genuinely independent observations of one fact —
different code, different failure modes — so they corroborate. A finding
resting on only one of them cannot exceed `suspected` without validation, and
that is the correct outcome rather than a limitation.
"""

from __future__ import annotations

from dataclasses import dataclass

from core.authz import checks_require_authorisation
from core.models import Mode

CERTIFICATE = "certificate"
"""We parsed the certificate the server sent and read a field from it."""

TRUST_PATH = "trust_path"
"""A strict client tried to build a path to a trusted root and told us what it
made of the attempt. Independent of our parsing: different implementation,
different trust store, different way of being wrong."""

NEGOTIATION = "negotiation"
"""What the server agreed to speak. Observed by attempting a handshake pinned
to one protocol version, not inferred from anything it advertises."""


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
        # --- Light ---------------------------------------------------------
        # docs/03-roadmap.md 0b.6: passive is what an ordinary client does -
        # one normal connection, nothing the target would not serve to any
        # visitor. Active is deliberately abnormal input: offering obsolete
        # protocols or a restricted/weak cipher list to see what a server
        # will accept, not what it would ordinarily negotiate.
        #
        # `self.observation` (scanners/tls/scanner.py `_Scan.execute`) is
        # one handshake made with `core.tls`'s permissive client context -
        # `PERMISSIVE_CIPHERS = "ALL:@SECLEVEL=0"`, deliberately offering
        # every cipher including weak and legacy ones, needed so an obsolete
        # or misconfigured server can be observed at all rather than just
        # refusing the connection outright.
        #
        # For a check that reads only the *certificate* the server presented
        # on that handshake - dates, subject/issuer, trust-path verdict, key
        # size, signature algorithm, the SCT extension - the permissive
        # offer changes nothing about the result: any ordinary visitor's
        # browser is served the identical certificate bytes regardless of
        # which cipher list it offered. Those checks are passive.
        #
        # `tls-weak-cipher` and `tls-no-forward-secrecy` instead read the
        # *cipher the server negotiated* from that same handshake - and the
        # abnormally permissive offer is exactly what makes that answer
        # meaningful: it is asking "will you agree to something weak if
        # allowed", not observing what an ordinary client would get. That
        # is the deliberately-abnormal-input case, so both are active
        # despite sharing the connection with the passive checks above.
        # `tls-protocol-obsolete` opens *further*, separate handshakes each
        # pinned to one specific old protocol version
        # (`self.tls.probe_protocols`) purely to see whether the server will
        # still speak it - unambiguously active.
        Check(
            check_id="tls-no-handshake",
            title="No TLS connection could be established",
            severity="medium",
            likelihood_ratio=1.0,
            justification=(
                "nothing was observed, so nothing moves the prior; this exists to say so "
                "out loud rather than to claim anything"
            ),
            passive=True,
        ),
        Check(
            check_id="tls-cert-expired",
            title="Certificate has expired",
            severity="critical",
            likelihood_ratio=60.0,
            justification=(
                "a date in the past, read from the certificate and independently "
                "confirmed by the trust path; there is no ambiguity in either"
            ),
            passive=True,
        ),
        Check(
            check_id="tls-cert-expiring-soon",
            title="Certificate expires soon",
            severity="medium",
            likelihood_ratio=60.0,
            justification="arithmetic on a date we parsed; nothing to interpret",
            passive=True,
        ),
        Check(
            check_id="tls-cert-not-yet-valid",
            title="Certificate is not valid yet",
            severity="high",
            likelihood_ratio=60.0,
            justification="as above, in the other direction; usually a clock or a rollout error",
            passive=True,
        ),
        Check(
            check_id="tls-hostname-mismatch",
            title="Certificate does not cover this hostname",
            severity="high",
            likelihood_ratio=30.0,
            justification=(
                "RFC 6125 matching is well defined, but wildcard and SAN handling is "
                "where implementations differ, so this sits below a plain date check"
            ),
            passive=True,
        ),
        Check(
            check_id="tls-cert-self-signed",
            title="Certificate is self-signed",
            severity="high",
            likelihood_ratio=50.0,
            justification=(
                "subject equals issuer in the certificate, and the trust path says the "
                "same; two independent readings of one fact"
            ),
            passive=True,
        ),
        Check(
            check_id="tls-untrusted-root",
            title="Certificate chain ends at an untrusted root",
            severity="high",
            likelihood_ratio=50.0,
            justification=(
                "the chain is complete and terminates in a root the trust store does not "
                "carry; that is a direct observation from path building, not an inference"
            ),
            passive=True,
        ),
        Check(
            check_id="tls-chain-incomplete",
            title="Certificate chain cannot be built",
            severity="medium",
            likelihood_ratio=20.0,
            justification=(
                "we cannot distinguish a server omitting its intermediates from an issuer "
                "our trust store does not carry; both are real problems for a visitor, but "
                "the cause is genuinely ambiguous, so the ratio is low"
            ),
            passive=True,
        ),
        # --- Standard ------------------------------------------------------
        Check(
            check_id="tls-protocol-obsolete",
            title="Server still offers an obsolete TLS version",
            severity="high",
            likelihood_ratio=50.0,
            justification=(
                "a completed handshake pinned to that version is the server doing it, "
                "not advertising it"
            ),
            passive=False,
            mode="standard",
        ),
        Check(
            check_id="tls-weak-key",
            title="Certificate key is below 2048 bits",
            severity="high",
            likelihood_ratio=60.0,
            justification="the modulus length is measured from the key itself",
            passive=True,
            mode="standard",
        ),
        Check(
            check_id="tls-weak-signature",
            title="Certificate uses a deprecated signature algorithm",
            severity="high",
            likelihood_ratio=60.0,
            justification="the algorithm is named in the certificate; nothing is inferred",
            passive=True,
            mode="standard",
        ),
        Check(
            check_id="tls-weak-cipher",
            title="Server negotiated a weak cipher",
            severity="high",
            likelihood_ratio=40.0,
            justification=(
                "the negotiated suite is what the server chose when offered everything; "
                "a different client offering less might get a better one, which is why "
                "this is not as strong as a certificate field"
            ),
            passive=False,
            mode="standard",
        ),
        Check(
            check_id="tls-no-forward-secrecy",
            title="Negotiated cipher provides no forward secrecy",
            severity="medium",
            likelihood_ratio=40.0,
            justification="key exchange is named in the cipher suite we negotiated",
            passive=False,
            mode="standard",
        ),
        Check(
            check_id="tls-no-certificate-transparency",
            title="Certificate carries no Certificate Transparency proof",
            severity="info",
            likelihood_ratio=30.0,
            justification=(
                "the SCT extension is either present or not, but its absence is normal "
                "for private and internal certificates, so this is informational"
            ),
            passive=True,
            mode="standard",
        ),
    ]
}


def requires_authorisation(mode: Mode) -> bool:
    """Whether this scanner's checks need a valid authorisation record in `mode`.

    Every Light-tier check is declared `passive=True` - each reads only what
    an ordinary client's handshake already sees, exactly like a browser
    visiting the site - so this returns False in `light` mode, matching
    docs/00-context.md's product-wide contract: Light needs no permission
    and "may be pointed at anything" (docs/13-test-targets.md).

    Standard adds three checks that force deliberately abnormal input to see
    what a server will accept rather than what it ordinarily would -
    `tls-protocol-obsolete` (separate handshakes pinned to old protocol
    versions), `tls-weak-cipher` and `tls-no-forward-secrecy` (both read the
    cipher negotiated when the client deliberately offered weak and legacy
    suites, `core.tls.PERMISSIVE_CIPHERS`). Those three are `passive=False`,
    so this returns True in `standard` mode even though the other three
    Standard checks (`tls-weak-key`, `tls-weak-signature`,
    `tls-no-certificate-transparency` - all read straight off the
    certificate) are themselves passive. That split - some Standard checks
    passive, some not - is 0b.6 working as intended, the same shape as
    email's Standard checks all being passive.

    Computed from the catalogue, not hand-set, so reclassifying a check
    here is the only place that has to change.
    """
    return checks_require_authorisation(CHECKS.values(), mode=mode)


MIN_KEY_BITS = 2048
EXPIRY_WARNING_DAYS = 30
EXPIRY_URGENT_DAYS = 7

OBSOLETE_PROTOCOLS = ("TLSv1", "TLSv1.1")
"""Deprecated by RFC 8996. Browsers removed support in 2020."""

DEPRECATED_SIGNATURES = ("md5", "sha1")

WEAK_CIPHER_MARKERS = ("RC4", "DES", "3DES", "NULL", "EXPORT", "MD5", "anon")
"""Substrings that mark a suite as broken or export-grade. Deliberately blunt:
a suite containing any of these has no defensible use in 2026."""

FORWARD_SECRECY_MARKERS = ("ECDHE", "DHE", "TLS_AES", "TLS_CHACHA")
"""TLS 1.3 suites are all forward-secret and do not name their key exchange,
hence the TLS_ prefixes."""

# OpenSSL verification codes we map to specific findings. Anything else becomes
# a generic untrusted-chain result rather than a guess.
VERIFY_SELF_SIGNED = {18}
"""DEPTH_ZERO_SELF_SIGNED_CERT - the *leaf* signs for itself."""

VERIFY_UNTRUSTED_ROOT = {19}
"""SELF_SIGNED_CERT_IN_CHAIN - the chain is complete and ends at a root we do
not trust. Every root is self-signed, so this code says nothing about the leaf.
Found live: untrusted-root.badssl.com was reported as a self-signed certificate
when its subject and issuer plainly differ."""
VERIFY_NO_ISSUER = {2, 20, 21}
VERIFY_EXPIRED = {10}
VERIFY_NOT_YET_VALID = {9}
