"""The SSL/TLS Analyzer.

One handshake tells us most of what we need; a second, made by a strictly
configured client, tells us what a browser would make of it. Those two are
independent observations of the same server — different code, different trust
store, different ways of being wrong — which is why a finding here can reach
`highly_likely` where an email finding needs an extra resolver to get there.

Three things this scanner is careful about:

- **An unreachable host proves nothing about its TLS.** Every check reads
  `is_definite()` and emits `inconclusive` rather than a confident absence.
  A firewall is not a finding.
- **OpenSSL reports only its first objection.** A certificate that is expired
  *and* self-signed comes back as "self-signed" alone, so expiry is read from
  the certificate we parsed rather than inferred from the verdict.
- **One problem, one finding.** An expired certificate is not also reported as
  expiring soon, and a self-signed one is not also reported as an unbuildable
  chain — the chain is unbuildable *because* it is self-signed, and saying so
  twice is noise dressed as thoroughness.

Not here, and not silently: HSTS needs an HTTP response header and therefore
HTTP record/replay (ledger D2/D10), and the A+ to F grade is deferred (D9).
"""

from __future__ import annotations

from datetime import UTC, datetime
from urllib.parse import urlsplit

from core.confidence import ConfidenceEngine, Signal
from core.context import ScanContext
from core.evidence import tls_evidence
from core.models import Asset, CheckOutcome, CheckRun, Finding, Mode, ScanResult, Telemetry
from core.registry import register
from core.scanner import BaseScanner
from core.tls import DEFAULT_PORT, TlsClient, TlsObservation
from scanners.tls.checks import (
    CERTIFICATE,
    CHECKS,
    DEPRECATED_SIGNATURES,
    EXPIRY_URGENT_DAYS,
    EXPIRY_WARNING_DAYS,
    FORWARD_SECRECY_MARKERS,
    MIN_KEY_BITS,
    NEGOTIATION,
    OBSOLETE_PROTOCOLS,
    TRUST_PATH,
    VERIFY_EXPIRED,
    VERIFY_NO_ISSUER,
    VERIFY_NOT_YET_VALID,
    VERIFY_SELF_SIGNED,
    VERIFY_UNTRUSTED_ROOT,
    WEAK_CIPHER_MARKERS,
    Check,
)

NO_VERDICT_FOR_ERROR = {
    "timeout": "timeout",
    "connect_error": "blocked_prerequisite",
    "tls_error": "ambiguous_response",
}

_REFERENCES = {
    "tls-cert-expired": ["https://www.rfc-editor.org/rfc/rfc5280"],
    "tls-cert-expiring-soon": ["https://www.rfc-editor.org/rfc/rfc5280"],
    "tls-cert-not-yet-valid": ["https://www.rfc-editor.org/rfc/rfc5280"],
    "tls-hostname-mismatch": ["https://www.rfc-editor.org/rfc/rfc6125"],
    "tls-cert-self-signed": ["https://www.rfc-editor.org/rfc/rfc5280"],
    "tls-chain-incomplete": ["https://www.rfc-editor.org/rfc/rfc5246#section-7.4.2"],
    "tls-protocol-obsolete": ["https://www.rfc-editor.org/rfc/rfc8996"],
    "tls-weak-key": [
        "https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r5.pdf"
    ],
    "tls-weak-signature": ["https://www.rfc-editor.org/rfc/rfc9155"],
    "tls-weak-cipher": ["https://www.rfc-editor.org/rfc/rfc7525"],
    "tls-no-forward-secrecy": ["https://www.rfc-editor.org/rfc/rfc7525#section-6.3"],
    "tls-no-certificate-transparency": ["https://www.rfc-editor.org/rfc/rfc6962"],
}


@register
class TlsScanner(BaseScanner):
    name = "tls"
    version = "1.0.0"
    supported_modes = frozenset({"light", "standard"})
    target_types = frozenset({"domain", "url", "ip"})

    def run(self, target: Asset, mode: Mode, ctx: ScanContext) -> ScanResult:
        self.validate(target, mode)
        tls = ctx.tls
        assert isinstance(tls, TlsClient), "the tls scanner needs a TLS client from the context"
        return _Scan(self, target, mode, ctx, tls).execute()


def _endpoint(target: Asset) -> tuple[str, int]:
    """Host and port to connect to, however the target was expressed.

    The scheme decides, not the declared target type. The CLI defaults
    `--target-type` to `domain`, so `scan run tls --target https://example.com`
    arrives here as a domain whose value is a URL - which is what most people
    will type. Trusting the declared type over the obvious scheme turned the
    host into the literal string "https://example.com" and made every check
    inconclusive, on a site with nothing wrong with it.
    """
    value = target.value
    if "://" in value:
        parts = urlsplit(value)
        return (parts.hostname or value), (parts.port or DEFAULT_PORT)
    if ":" in value and not value.startswith("["):
        host, _, port = value.rpartition(":")
        if port.isdigit():
            return host, int(port)
    return value, DEFAULT_PORT


class _Scan:
    def __init__(
        self, scanner: TlsScanner, target: Asset, mode: Mode, ctx: ScanContext, tls: TlsClient
    ) -> None:
        self.scanner = scanner
        self.target = target
        self.mode = mode
        self.ctx = ctx
        self.tls = tls
        self.host, self.port = _endpoint(target)
        self.findings: list[Finding] = []
        self.checks: list[CheckRun] = []
        self.engine = ConfidenceEngine()

    # --- orchestration ------------------------------------------------------

    def execute(self) -> ScanResult:
        self.ctx.progress(f"connecting to {self.host}:{self.port}", 0.2)
        self.ctx.check_alive()
        self.observation = self.tls.inspect(self.host, self.port, servername=self.host)

        if not self.observation.is_definite():
            self._all_inconclusive()
            return self._result()

        self.now = self.observation.observed_at
        self.cert = self.observation.certificate
        assert self.cert is not None

        self.ctx.progress("checking the certificate", 0.5)
        self._check_validity_dates()
        self._check_identity()
        self._check_trust_path()

        if self.mode != "light":
            self.ctx.progress("enumerating protocols", 0.75)
            self.ctx.check_alive()
            self.protocols = self.tls.supported_protocols(
                self.host, self.port, servername=self.host
            )
            self._check_protocols()
            self._check_certificate_strength()
            self._check_negotiated_suite()

        self.ctx.progress("done", 1.0)
        return self._result()

    def _result(self) -> ScanResult:
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

    def _all_inconclusive(self) -> None:
        """The server did not complete a handshake. That is not a TLS finding."""
        reason = "blocked_prerequisite"
        for prefix, mapped in NO_VERDICT_FOR_ERROR.items():
            if (self.observation.error or "").startswith(prefix):
                reason = mapped
                break

        for check_id, check in CHECKS.items():
            if check.mode == "standard" and self.mode == "light":
                continue
            self._emit(
                check,
                no_verdict_reason=reason,
                description=(
                    f"No TLS handshake could be completed with {self.host}:{self.port} "
                    f"({self.observation.error}). Nothing can be concluded about this "
                    "server's TLS configuration, and we do not report an unreachable "
                    "service as a well-configured one."
                ),
                impact="Unknown until a handshake succeeds.",
                remediation=(
                    f"Confirm that {self.host} is listening on port {self.port} and that a "
                    "firewall is not refusing the connection, then re-run the scan."
                ),
                signals=[self._signal(check, CERTIFICATE, 1.0)],
            )
            self.checks.append(
                CheckRun(check_id=check_id, location=self._location(), outcome="inconclusive")
            )

    # --- checks -------------------------------------------------------------

    def _check_validity_dates(self) -> None:
        assert self.cert is not None
        days = self.cert.days_until_expiry(now=self.now)

        if self.cert.is_expired(now=self.now):
            self._report(
                "tls-cert-expired",
                description=(
                    f"The certificate for {self.host} expired on "
                    f"{self.cert.not_after.date().isoformat()}, {abs(days)} days ago."
                ),
                impact=(
                    "Browsers refuse the connection and show a full-page security warning. "
                    "For most visitors the site is simply unreachable."
                ),
                remediation=(
                    "Renew the certificate and deploy it now. Then automate renewal - an "
                    "expiry reaching production means nothing was watching the date, and "
                    "the next one will arrive the same way."
                ),
                signals=self._date_signals("tls-cert-expired", VERIFY_EXPIRED),
            )
            self._clear("tls-cert-expiring-soon")
        elif days <= EXPIRY_WARNING_DAYS:
            urgent = days <= EXPIRY_URGENT_DAYS
            self._report(
                "tls-cert-expiring-soon",
                severity="high" if urgent else None,
                description=(
                    f"The certificate for {self.host} expires in {days} days, on "
                    f"{self.cert.not_after.date().isoformat()}."
                ),
                impact=(
                    "Once it expires every visitor sees a full-page security warning."
                    + (" At this range there is no margin for a failed renewal." if urgent else "")
                ),
                remediation=(
                    "Renew now rather than at the deadline, and check that automatic renewal "
                    "is actually running - most expiries are a renewal job that has been "
                    "failing quietly for weeks."
                ),
                signals=[self._signal(CHECKS["tls-cert-expiring-soon"], CERTIFICATE)],
            )
            self._clear("tls-cert-expired")
        else:
            self._clear("tls-cert-expired")
            self._clear("tls-cert-expiring-soon")

        if self.cert.not_yet_valid(now=self.now):
            self._report(
                "tls-cert-not-yet-valid",
                description=(
                    f"The certificate for {self.host} is not valid until "
                    f"{self.cert.not_before.date().isoformat()}."
                ),
                impact=(
                    "Browsers reject it exactly as they would an expired one. This is usually "
                    "a certificate deployed ahead of its start date, or a clock that is wrong."
                ),
                remediation=(
                    "Check the system clock on the server first, since a skewed clock produces "
                    "this and a great deal else. If the clock is right, wait for the start date "
                    "or reissue with one that has passed."
                ),
                signals=self._date_signals("tls-cert-not-yet-valid", VERIFY_NOT_YET_VALID),
            )
        else:
            self._clear("tls-cert-not-yet-valid")

    def _date_signals(self, check_id: str, codes: set[int]) -> list[Signal]:
        """Our own reading of the date, plus the trust path's if it agrees.

        The trust path only mentions dates once nothing more serious is in the
        way, so its agreement is a bonus rather than a requirement.
        """
        check = CHECKS[check_id]
        signals = [self._signal(check, CERTIFICATE)]
        if self.observation.verify_code in codes:
            signals.append(self._signal(check, TRUST_PATH, ratio=20.0))
        return signals

    def _check_identity(self) -> None:
        assert self.cert is not None
        if self.observation.hostname_matches is False:
            names = ", ".join(self.cert.sans) or self.cert.subject_cn or "none"
            self._report(
                "tls-hostname-mismatch",
                description=(
                    f"The certificate presented for {self.host} does not cover that name. "
                    f"It is valid for: {names}."
                ),
                impact=(
                    "Browsers refuse the connection with a security warning naming the wrong "
                    "site. It is also what a visitor would see during an interception attempt, "
                    "so the warning is doing its job and cannot be waved away."
                ),
                remediation=(
                    f"Reissue the certificate with {self.host} in its subjectAltName list, or "
                    "point this name at the host that already serves a certificate covering it."
                ),
                signals=self._hostname_signals(),
            )
        else:
            self._clear("tls-hostname-mismatch")

    def _hostname_signals(self) -> list[Signal]:
        """Our RFC 6125 matcher, plus OpenSSL's if it reached a verdict.

        Two independent implementations of the same rule. Where they disagree
        the finding stays at one signal, which is the correct outcome: a
        disagreement about name matching means one of us has a bug, and that is
        not the moment to sound confident.
        """
        check = CHECKS["tls-hostname-mismatch"]
        signals = [self._signal(check, CERTIFICATE)]
        if self.observation.openssl_hostname_match is False:
            signals.append(self._signal(check, TRUST_PATH, ratio=30.0))
        return signals

    def _check_trust_path(self) -> None:
        assert self.cert is not None
        code = self.observation.verify_code

        if self.cert.self_signed or code in VERIFY_SELF_SIGNED:
            self._report(
                "tls-cert-self-signed",
                description=(
                    f"The certificate for {self.host} is self-signed: it vouches for itself "
                    "rather than being issued by a certificate authority."
                    + (
                        f' A strict client agreed: "{self.observation.verify_message}".'
                        if self.observation.verify_message
                        else ""
                    )
                ),
                impact=(
                    "Every browser shows a full-page security warning, and a visitor who "
                    "clicks through has no way to tell your certificate from an attacker's."
                ),
                remediation=(
                    "Obtain a certificate from a public certificate authority - Let's Encrypt "
                    "issues them free and automates renewal. If this host is genuinely internal, "
                    "issue from your own CA and distribute that CA to the machines that use it."
                ),
                signals=[
                    self._signal(CHECKS["tls-cert-self-signed"], CERTIFICATE),
                    self._signal(CHECKS["tls-cert-self-signed"], TRUST_PATH),
                ],
            )
            # The chain is unbuildable *because* it is self-signed. Reporting
            # both would be one problem wearing two hats.
            self._clear("tls-chain-incomplete")
            self._clear("tls-untrusted-root")
            return

        self._clear("tls-cert-self-signed")

        if code in VERIFY_UNTRUSTED_ROOT:
            self._report(
                "tls-untrusted-root",
                description=(
                    f"{self.host} presents a complete certificate chain, but it ends at a "
                    "root certificate authority that public trust stores do not carry"
                    + (
                        f' ("{self.observation.verify_message}").'
                        if self.observation.verify_message
                        else "."
                    )
                    + f" The certificate itself was issued by {self.cert.issuer_cn or 'that root'}"
                    ", so this is a private or internal authority rather than a self-signed"
                    " certificate."
                ),
                impact=(
                    "Every browser that has not been given this root shows a full-page "
                    "security warning. If the host is internal and the root is distributed to "
                    "company machines, this is working as intended; if it is public-facing, it "
                    "is indistinguishable from an interception attempt."
                ),
                remediation=(
                    "For a public-facing host, replace this with a certificate from a publicly "
                    "trusted authority - Let's Encrypt issues them free. For an internal host, "
                    "confirm the root really is distributed to every client that needs it, "
                    "including mobile devices and CI runners, which are usually the ones missed."
                ),
                signals=[self._signal(CHECKS["tls-untrusted-root"], TRUST_PATH)],
            )
            self._clear("tls-chain-incomplete")
            return

        self._clear("tls-untrusted-root")

        if code in VERIFY_NO_ISSUER:
            self._report(
                "tls-chain-incomplete",
                description=(
                    f"A trusted path to {self.host}'s certificate could not be built: "
                    f'"{self.observation.verify_message}". Either the server is not sending '
                    "its intermediate certificates, or its issuer is not one we trust. We "
                    "cannot tell which from the outside, and both break some visitors."
                ),
                impact=(
                    "Clients that fetch missing intermediates themselves will work; those that "
                    "do not - many mobile apps, command-line tools and older browsers - will "
                    "fail. That produces the worst kind of bug report: it works for most people."
                ),
                remediation=(
                    "Serve the full chain. Your certificate authority provides a bundle "
                    "containing the intermediates; configure the server to send it alongside "
                    "the leaf certificate, then re-test."
                ),
                signals=[self._signal(CHECKS["tls-chain-incomplete"], TRUST_PATH)],
            )
        else:
            self._clear("tls-chain-incomplete")

    def _check_protocols(self) -> None:
        offered = [name for name in OBSOLETE_PROTOCOLS if self.protocols.get(name)]
        current = [
            name for name, ok in self.protocols.items() if ok and name not in OBSOLETE_PROTOCOLS
        ]

        if not offered:
            self._clear("tls-protocol-obsolete")
            return

        control: TlsObservation | None = None
        if current:
            control = self.observation

        self._report(
            "tls-protocol-obsolete",
            description=(
                f"{self.host}:{self.port} completed a handshake using {', '.join(offered)}, "
                "deprecated by RFC 8996 and removed from every major browser in 2020."
                + (f" It also offers {', '.join(current)}." if current else "")
            ),
            impact=(
                "These versions have known weaknesses and no longer receive attention. Keeping "
                "them enabled mainly serves clients that are themselves unpatched, while "
                "leaving the connection open to downgrade."
            ),
            remediation=(
                "Set the server's minimum protocol version to TLS 1.2. Check your traffic logs "
                "for genuine older clients first - usually there are none, and the ones there "
                "are turn out to be monitoring you control."
            ),
            signals=[self._signal(CHECKS["tls-protocol-obsolete"], NEGOTIATION)],
            compared_with=control,
        )

    def _check_certificate_strength(self) -> None:
        assert self.cert is not None
        bits = self.cert.key_bits

        if bits is not None and self.cert.key_type == "rsa" and bits < MIN_KEY_BITS:
            self._report(
                "tls-weak-key",
                description=(
                    f"The certificate for {self.host} uses a {bits}-bit RSA key. "
                    f"{MIN_KEY_BITS} bits is the minimum in current use."
                ),
                impact=(
                    "A key this size is within reach of a well-resourced attacker, who could "
                    "then impersonate this site convincingly enough to pass every check a "
                    "browser makes."
                ),
                remediation=(
                    f"Reissue with a {MIN_KEY_BITS}-bit RSA key, or a 256-bit elliptic curve "
                    "key which is stronger and faster. Both are a reissue, not a migration."
                ),
                signals=[self._signal(CHECKS["tls-weak-key"], CERTIFICATE)],
            )
        else:
            self._clear("tls-weak-key")

        signature = (self.cert.signature_algorithm or "").lower()
        if signature in DEPRECATED_SIGNATURES:
            self._report(
                "tls-weak-signature",
                description=(
                    f"The certificate for {self.host} is signed with {signature}, which is "
                    "no longer considered safe against collision attacks."
                ),
                impact=(
                    "A collision lets an attacker construct a second certificate carrying the "
                    "same signature, which is the whole basis on which a browser trusts this one."
                ),
                remediation=(
                    "Reissue the certificate with a SHA-256 signature. Any public certificate "
                    "authority does this by default; a signature this old means the certificate "
                    "was issued internally, so the internal CA needs its defaults changed too."
                ),
                signals=[self._signal(CHECKS["tls-weak-signature"], CERTIFICATE)],
            )
        else:
            self._clear("tls-weak-signature")

        if not self.cert.has_sct:
            self._report(
                "tls-no-certificate-transparency",
                description=(
                    f"The certificate for {self.host} carries no Certificate Transparency "
                    "proof. Public certificate authorities have embedded these since 2018, so "
                    "this is expected for an internal or self-signed certificate and unusual "
                    "for a public one."
                ),
                impact=(
                    "Without a CT proof there is no public log entry recording that this "
                    "certificate was issued, so a mis-issuance for your domain would be "
                    "harder to notice. Chrome requires CT for publicly trusted certificates."
                ),
                remediation=(
                    "No action if this certificate is internal by design. If it is meant to be "
                    "publicly trusted, reissue it from a CA that logs to Certificate "
                    "Transparency - which in practice is all of them."
                ),
                signals=[self._signal(CHECKS["tls-no-certificate-transparency"], CERTIFICATE)],
            )
        else:
            self._clear("tls-no-certificate-transparency")

    def _check_negotiated_suite(self) -> None:
        cipher = self.observation.cipher or ""

        if any(marker in cipher.upper() for marker in WEAK_CIPHER_MARKERS):
            self._report(
                "tls-weak-cipher",
                description=(
                    f"{self.host}:{self.port} negotiated {cipher}, which relies on an algorithm "
                    "that is broken or deliberately weakened."
                ),
                impact=(
                    "Traffic encrypted with this suite should be treated as readable by anyone "
                    "who captures it."
                ),
                remediation=(
                    "Remove RC4, DES, 3DES, export and NULL suites from the server's cipher "
                    "list. Most servers inherit these from a configuration copied years ago; "
                    "adopting a current recommended cipher list removes all of them at once."
                ),
                signals=[self._signal(CHECKS["tls-weak-cipher"], NEGOTIATION)],
            )
        else:
            self._clear("tls-weak-cipher")

        if cipher and not any(marker in cipher.upper() for marker in FORWARD_SECRECY_MARKERS):
            self._report(
                "tls-no-forward-secrecy",
                description=(
                    f"{self.host}:{self.port} negotiated {cipher}, which does not provide "
                    "forward secrecy."
                ),
                impact=(
                    "Anyone who records this traffic today and later obtains the server's "
                    "private key can decrypt all of it retrospectively. Forward secrecy is "
                    "what makes a stolen key a future problem rather than a past one."
                ),
                remediation=(
                    "Prefer ECDHE key exchange in the server's cipher list, or enable TLS 1.3, "
                    "where every suite is forward-secret and the choice disappears."
                ),
                signals=[self._signal(CHECKS["tls-no-forward-secrecy"], NEGOTIATION)],
            )
        else:
            self._clear("tls-no-forward-secrecy")

    # --- emitting -----------------------------------------------------------

    def _location(self) -> str:
        return f"{self.host}:{self.port}"

    def _signal(self, check: Check, independence_class: str, ratio: float | None = None) -> Signal:
        return Signal(
            method=f"tls_{independence_class}",
            prior=0.5,
            likelihood_ratio=ratio or check.likelihood_ratio,
            independence_class=independence_class,
            prior_justification=check.justification,
        )

    def _report(
        self,
        check_id: str,
        *,
        description: str,
        impact: str,
        remediation: str,
        signals: list[Signal],
        severity: str | None = None,
        compared_with: TlsObservation | None = None,
    ) -> None:
        check = CHECKS[check_id]
        self._emit(
            check,
            description=description,
            impact=impact,
            remediation=remediation,
            signals=signals,
            severity=severity,
            compared_with=compared_with,
        )
        outcome: CheckOutcome = "reported"
        self.checks.append(CheckRun(check_id=check_id, location=self._location(), outcome=outcome))

    def _emit(
        self,
        check: Check,
        *,
        description: str,
        impact: str,
        remediation: str,
        signals: list[Signal],
        severity: str | None = None,
        compared_with: TlsObservation | None = None,
        no_verdict_reason: str | None = None,
    ) -> None:
        result = self.engine.combine(signals)
        now = datetime.now(UTC)

        evidence = [
            tls_evidence(
                label=f"TLS handshake with {self._location()}",
                observation=self.observation,
                compared_with=compared_with,
            )
        ]

        self.findings.append(
            Finding.create(
                org_id=self.ctx.org_id,
                scanner=self.scanner.name,
                scanner_version=self.scanner.version,
                check_id=check.check_id,
                title=check.title,
                target=self.target,
                location=self._location(),
                severity=severity or check.severity,
                confidence=result.confidence,
                confidence_provisional=result.provisional,
                no_verdict_reason=no_verdict_reason,
                detection_methods=result.detection_methods,
                validation={"attempted": False, "outcome": "not_applicable", "method": None},
                evidence=evidence,
                related_assets=[{"type": "domain", "value": self.host, "relation": "observed_on"}],
                description=description,
                impact=impact,
                remediation=remediation,
                references=_REFERENCES.get(check.check_id, []),
                taxonomy={"cwe": ["CWE-295"]},
                first_seen=now,
                first_seen_scan_id=self.ctx.scan_id,
                last_seen=now,
                last_seen_scan_id=self.ctx.scan_id,
                cost=self.ctx.cost.snapshot(),
            )
        )

    def _clear(self, check_id: str) -> None:
        self.checks.append(CheckRun(check_id=check_id, location=self._location(), outcome="clear"))
