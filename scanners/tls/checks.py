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

EXTERNAL_PROBE = "external_probe"
"""D20: testssl.sh completing its own handshake against the same server,
using its own bundled OpenSSL build and its own socket code. Independent of
`NEGOTIATION` in the sense the confidence engine cares about - different
implementation, different process, different failure modes - even though
both are "the server agreed to a handshake". It is not `CERTIFICATE` or
`TRUST_PATH` either: nothing here reads or verifies a certificate. A new,
named class rather than reusing `NEGOTIATION` because collapsing them would
let a testssl-detected RC4 offer and our own weak-cipher negotiation
corroborate each other in `ConfidenceEngine.combine()`, when in fact they can
disagree - RC4 is compiled out of our engine's OpenSSL 3.5, so our engine
structurally cannot make the observation testssl just made. Treating "we
didn't look" and "we looked and disagree" as the same signal would be wrong."""


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
            passive=True,
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
            passive=True,
            mode="standard",
        ),
        Check(
            check_id="tls-no-forward-secrecy",
            title="Negotiated cipher provides no forward secrecy",
            severity="medium",
            likelihood_ratio=40.0,
            justification="key exchange is named in the cipher suite we negotiated",
            passive=True,
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
        # --- Legacy ciphers, via the testssl.sh runtime wrap (D20) ----------
        # ADR-016's reserved per-check reversal: our own engine's OpenSSL 3.5
        # cannot negotiate any of these four families - verified as
        # "No cipher can be selected" - so `core/testssl.py` shells out to
        # testssl.sh's own bundled OpenSSL, Standard mode only. Reading what a
        # server offers is ordinary negotiation (ADR-023), so these stay
        # passive despite running a second tool to observe it.
        Check(
            check_id="tls-vuln-rc4",
            title="Server offers the RC4 stream cipher",
            severity="high",
            likelihood_ratio=60.0,
            justification=(
                "testssl.sh completed a real handshake negotiating an RC4 suite against "
                "this server; a direct observation of what the server offered, not an "
                "inference from a version string or a banner"
            ),
            passive=True,
            mode="standard",
        ),
        Check(
            check_id="tls-vuln-sweet32",
            title="Server offers 3DES / 64-bit-block ciphers (SWEET32)",
            severity="medium",
            likelihood_ratio=50.0,
            justification=(
                "testssl.sh completed a handshake negotiating a 64-bit-block suite; a "
                "direct negotiation result. Rated below RC4 because a SWEET32 attack "
                "needs a very long-lived connection carrying attacker-influenced "
                "plaintext, a harder bar to clear in practice than RC4's outright break"
            ),
            passive=True,
            mode="standard",
        ),
        Check(
            check_id="tls-vuln-freak",
            title="Server offers export-grade RSA (FREAK)",
            severity="critical",
            likelihood_ratio=50.0,
            justification=(
                "testssl.sh completed a handshake negotiating an export-grade RSA suite; "
                "a direct negotiation result. Rated critical because a successful FREAK "
                "downgrade recovers the session key via a factorable 512-bit RSA modulus, "
                "not merely a weakened cipher"
            ),
            passive=True,
            mode="standard",
        ),
        Check(
            check_id="tls-vuln-logjam",
            title="Server offers export-grade or weak Diffie-Hellman (LOGJAM)",
            severity="critical",
            likelihood_ratio=50.0,
            justification=(
                "testssl.sh read the server's DH group directly off the handshake - "
                "either an export-grade cipher or (as with a fixed 512-bit group) the "
                "negotiated parameters themselves; a direct observation, not inferred"
            ),
            passive=True,
            mode="standard",
        ),
        # --- Derived (ADR-018) ----------------------------------------------
        Check(
            check_id="tls-vuln-beast",
            title="Server permits the TLS configuration BEAST exploits",
            severity="medium",
            likelihood_ratio=1.0,
            justification=(
                "this is a derived finding (ADR-018): its confidence is inherited from "
                "the tls-protocol-obsolete finding it builds on, via "
                "ConfidenceEngine.inherit(), never recomputed through combine(). This "
                "likelihood ratio is a neutral placeholder (LR=1.0, contributes no shift) "
                "kept so the detection_methods entry stays schema-honest rather than "
                "inventing a fake signal to push arithmetic through the evidence engine"
            ),
            passive=True,
            mode="standard",
        ),
    ]
}


def requires_authorisation(mode: Mode) -> bool:
    """Whether this scanner's checks need a valid authorisation record in `mode`.

    **Every TLS check is `passive=True`, so this returns False in every mode.**
    TLS analysis is an ordinary client negotiating a connection and reading
    what the server presents - a certificate, a protocol version, a cipher
    choice. None of it changes state, and every credible tool in the market
    (SSL Labs, SSL.org, Mozilla Observatory, testssl.sh) enumerates protocols
    and ciphers against any host, unauthenticated and free. See ADR-023.

    This reverses the 0b.6 first cut, which classified `tls-protocol-obsolete`,
    `tls-weak-cipher` and `tls-no-forward-secrecy` as active because they offer
    obsolete versions or a legacy cipher list (`core.tls.PERMISSIVE_CIPHERS`)
    to see what the server accepts. That reasoning conflated *abnormal* with
    *harmful*: offering an old protocol in a ClientHello is a normal
    negotiation the server freely accepts or refuses, not the malformed input
    ADR-004 forbids (Heartbleed, ROBOT). The distinction ADR-023 draws is
    exactly that line - complete handshakes are passive; malformed or
    exploit-adjacent probes are active, and we do not send those at all.

    The active path is still real and still tested (`TestChecksRequire-
    Authorisation` with synthetic checks); its first live consumer is the
    Website Scanner's payload-sending checks, not this tool. Computed from the
    catalogue, not hand-set, so a future active check is the only thing that
    would flip this.
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

CBC_EXCLUDED_MARKERS = ("GCM", "CCM", "CHACHA20", "POLY1305", "RC4", "NULL")
"""AEAD and stream markers - anything carrying one of these is not CBC mode."""


def is_cbc_cipher(cipher: str) -> bool:
    """Whether a negotiated suite is CBC-mode, for the BEAST inference.

    No AEAD suite exists for TLS 1.0/1.1 - GCM/CCM/ChaCha20-Poly1305 all
    require TLS 1.2, and this is only ever consulted against a handshake
    pinned to TLS 1.0 or 1.1 (`OBSOLETE_PROTOCOLS`). RC4 is compiled out of
    OpenSSL 3 (D18/ledger) and excluded here for the same reason it is
    excluded everywhere else: if it ever reappears, it is a stream cipher,
    not CBC, and BEAST does not apply to it.
    """
    upper = cipher.upper()
    return not any(marker in upper for marker in CBC_EXCLUDED_MARKERS)


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
