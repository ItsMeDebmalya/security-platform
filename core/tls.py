"""The one TLS client.

Scanners never open their own sockets. Everything goes through here, so scope
enforcement, the kill switch, cost accounting and the rate limit are
guarantees rather than habits.

**Two contexts, and the difference matters.**

`_observing_context()` is deliberately permissive: security level 0, every
protocol back to SSLv3, no certificate verification. That is not carelessness.
A client carrying the normal safety floor *refuses to complete a handshake*
with a server running TLS 1.0 — and those servers are exactly what this
scanner exists to find. A scanner that inherits the floor reports "connection
failed" for every insecure server and looks like it is working.

`_verifying_context()` is the opposite: the real trust store, real path
building. It answers "would a browser trust this?" and, when the answer is no,
hands back OpenSSL's own reason.

Running both against one server *is* the control-vs-test pair the finding
contract requires, and it comes free with the design rather than being
reconstructed afterwards.

**The rule that comes with the permissive context** (docs/06-guidelines.md):
it observes, it never fetches. It accepts forged and expired certificates by
design, so reusing it to retrieve content silently disables HTTPS for that
request.

One thing Python 3.12 cannot give us: the certificate chain.
`get_unverified_chain()` arrived in 3.13. Chain completeness — a server that
forgets to send its intermediates, working in some clients and failing in
others — is detected behaviourally instead, by whether the verifying context
can build a path. That measures what a user experiences rather than what the
bytes contain, so it is the better check regardless.
"""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import re
import socket
import ssl
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import ExtensionOID, NameOID

from core.authz import Scope
from core.cost import CostMeter
from core.http import OutOfScopeError
from core.killswitch import KillSwitch

DEFAULT_PORT = 443
DEFAULT_TIMEOUT_S = 10.0

PROTOCOLS: dict[str, ssl.TLSVersion] = {
    "TLSv1": ssl.TLSVersion.TLSv1,
    "TLSv1.1": ssl.TLSVersion.TLSv1_1,
    "TLSv1.2": ssl.TLSVersion.TLSv1_2,
    "TLSv1.3": ssl.TLSVersion.TLSv1_3,
}
"""What we enumerate in Standard mode. SSLv3 is omitted deliberately: OpenSSL 3
is usually built without it, so "not supported" would report our own build
rather than the target's, and a finding about ourselves is worse than none."""

PERMISSIVE_CIPHERS = "ALL:@SECLEVEL=0"
_SAFE = re.compile(r"[^a-z0-9._-]")


class MissingHandshakeError(LookupError):
    """A replay run asked for a handshake that was never recorded."""


# --- what we learned --------------------------------------------------------


@dataclass(frozen=True)
class CertificateInfo:
    subject: str
    issuer: str
    serial: str
    not_before: dt.datetime
    not_after: dt.datetime
    sans: list[str]
    key_type: str
    key_bits: int | None
    signature_algorithm: str | None
    self_signed: bool
    has_sct: bool
    fingerprint_sha256: str
    subject_cn: str | None = None
    issuer_cn: str | None = None

    def days_until_expiry(self, now: dt.datetime | None = None) -> int:
        """Whole days left. Negative once expired.

        `now` exists so a replayed handshake is judged against when it was
        recorded. Without it every frozen fixture would quietly become an
        expiry finding as it aged, and the corpus would rot untouched.
        """
        moment = now or dt.datetime.now(dt.UTC)
        return (self.not_after - moment).days

    def is_expired(self, now: dt.datetime | None = None) -> bool:
        return (now or dt.datetime.now(dt.UTC)) > self.not_after

    def not_yet_valid(self, now: dt.datetime | None = None) -> bool:
        return (now or dt.datetime.now(dt.UTC)) < self.not_before

    def covers_hostname(self, hostname: str) -> bool:
        """RFC 6125 name matching, including single-label wildcards.

        `*.example.test` covers `api.example.test` and covers neither
        `a.b.example.test` nor the bare `example.test`.
        """
        names = list(self.sans) or ([self.subject_cn] if self.subject_cn else [])
        host = hostname.lower().rstrip(".")
        for raw in names:
            name = raw.lower().rstrip(".")
            if name == host:
                return True
            if name.startswith("*."):
                suffix = name[2:]
                if not host.endswith("." + suffix):
                    continue
                label = host[: -(len(suffix) + 1)]
                if label and "." not in label:
                    return True
        return False

    def to_dict(self) -> dict[str, Any]:
        return {
            "subject": self.subject,
            "subject_cn": self.subject_cn,
            "issuer": self.issuer,
            "issuer_cn": self.issuer_cn,
            "serial": self.serial,
            "not_before": self.not_before.isoformat(),
            "not_after": self.not_after.isoformat(),
            "sans": list(self.sans),
            "key_type": self.key_type,
            "key_bits": self.key_bits,
            "signature_algorithm": self.signature_algorithm,
            "self_signed": self.self_signed,
            "has_sct": self.has_sct,
            "fingerprint_sha256": self.fingerprint_sha256,
        }


@dataclass(frozen=True)
class TlsObservation:
    host: str
    port: int
    servername: str | None
    reachable: bool
    observed_at: dt.datetime
    error: str | None = None
    protocol: str | None = None
    cipher: str | None = None
    cipher_bits: int | None = None
    certificate: CertificateInfo | None = None
    trusted: bool = False
    verify_code: int | None = None
    verify_message: str | None = None
    openssl_hostname_match: bool | None = None
    elapsed_ms: int = 0

    @property
    def hostname_matches(self) -> bool | None:
        if self.certificate is None or self.servername is None:
            return None
        return self.certificate.covers_hostname(self.servername)

    def is_definite(self) -> bool:
        """Whether this observation supports a conclusion.

        An unreachable host is not evidence of anything about its TLS; it is
        `inconclusive`, exactly as a SERVFAIL is for DNS.
        """
        return self.reachable and self.certificate is not None

    def to_dict(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "port": self.port,
            "servername": self.servername,
            "reachable": self.reachable,
            "observed_at": self.observed_at.isoformat(),
            "error": self.error,
            "protocol": self.protocol,
            "cipher": self.cipher,
            "cipher_bits": self.cipher_bits,
            "trusted": self.trusted,
            "verify_code": self.verify_code,
            "verify_message": self.verify_message,
            "hostname_matches": self.hostname_matches,
            "openssl_hostname_match": self.openssl_hostname_match,
            "certificate": self.certificate.to_dict() if self.certificate else None,
        }


@dataclass(frozen=True)
class RawHandshake:
    """What a backend returns: the wire facts, before we interpret them."""

    reachable: bool
    observed_at: dt.datetime
    error: str | None = None
    protocol: str | None = None
    cipher: str | None = None
    cipher_bits: int | None = None
    peer_der: bytes | None = None
    trusted: bool = False
    verify_code: int | None = None
    verify_message: str | None = None
    openssl_hostname_match: bool | None = None
    elapsed_ms: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "reachable": self.reachable,
            "observed_at": self.observed_at.isoformat(),
            "error": self.error,
            "protocol": self.protocol,
            "cipher": self.cipher,
            "cipher_bits": self.cipher_bits,
            "peer_der_b64": base64.b64encode(self.peer_der).decode() if self.peer_der else None,
            "trusted": self.trusted,
            "verify_code": self.verify_code,
            "verify_message": self.verify_message,
            "openssl_hostname_match": self.openssl_hostname_match,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RawHandshake:
        der = data.get("peer_der_b64")
        return cls(
            reachable=data["reachable"],
            observed_at=dt.datetime.fromisoformat(data["observed_at"]),
            error=data.get("error"),
            protocol=data.get("protocol"),
            cipher=data.get("cipher"),
            cipher_bits=data.get("cipher_bits"),
            peer_der=base64.b64decode(der) if der else None,
            trusted=data.get("trusted", False),
            verify_code=data.get("verify_code"),
            verify_message=data.get("verify_message"),
            openssl_hostname_match=data.get("openssl_hostname_match"),
        )


# --- backends ---------------------------------------------------------------


class TlsBackend(Protocol):
    def handshake(
        self,
        host: str,
        port: int,
        servername: str | None,
        *,
        min_version: ssl.TLSVersion | None = None,
        max_version: ssl.TLSVersion | None = None,
        trust_anchor: str | None = None,
        timeout_s: float = DEFAULT_TIMEOUT_S,
    ) -> RawHandshake: ...


def _observing_context(
    min_version: ssl.TLSVersion | None, max_version: ssl.TLSVersion | None
) -> ssl.SSLContext:
    """A client that will talk to anything, so that anything can be reported.

    OBSERVATION ONLY. This context accepts forged and expired certificates by
    design; never use it to fetch content.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.set_ciphers(PERMISSIVE_CIPHERS)
    context.minimum_version = min_version or ssl.TLSVersion.TLSv1
    if max_version is not None:
        context.maximum_version = max_version
    return context


def _verifying_context(trust_anchor: str | None) -> ssl.SSLContext:
    """A client that behaves like a browser, to answer "would this be trusted?".

    Hostname checking is left off on purpose: we match names ourselves from the
    SANs so that an untrusted chain does not mask a name mismatch. OpenSSL
    reports only its first objection, and we want both answers.
    """
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_REQUIRED
    if trust_anchor:
        context.load_verify_locations(cafile=trust_anchor)
    return context


class SystemTlsBackend:
    """Real sockets. Constructed by the CLI or the worker, never by a scanner."""

    def handshake(
        self,
        host: str,
        port: int,
        servername: str | None,
        *,
        min_version: ssl.TLSVersion | None = None,
        max_version: ssl.TLSVersion | None = None,
        trust_anchor: str | None = None,
        timeout_s: float = DEFAULT_TIMEOUT_S,
    ) -> RawHandshake:
        started = time.monotonic()
        observed_at = dt.datetime.now(dt.UTC)

        try:
            with socket.create_connection((host, port), timeout=timeout_s) as raw:
                context = _observing_context(min_version, max_version)
                with context.wrap_socket(raw, server_hostname=servername or host) as tls:
                    der = tls.getpeercert(binary_form=True)
                    cipher = tls.cipher()
                    protocol = tls.version()
        except TimeoutError:
            return RawHandshake(
                reachable=False,
                observed_at=observed_at,
                error="timeout",
                elapsed_ms=int((time.monotonic() - started) * 1000),
            )
        except ssl.SSLError as exc:
            return RawHandshake(
                reachable=False,
                observed_at=observed_at,
                error=f"tls_error:{getattr(exc, 'reason', None) or exc}",
                elapsed_ms=int((time.monotonic() - started) * 1000),
            )
        except OSError as exc:
            return RawHandshake(
                reachable=False,
                observed_at=observed_at,
                error=f"connect_error:{exc.strerror or exc}",
                elapsed_ms=int((time.monotonic() - started) * 1000),
            )

        trusted, code, message = self._verify(host, port, servername, trust_anchor, timeout_s)
        hostname_match = self._verify_hostname(host, port, servername, der, trust_anchor, timeout_s)
        return RawHandshake(
            reachable=True,
            observed_at=observed_at,
            protocol=protocol,
            cipher=cipher[0] if cipher else None,
            cipher_bits=cipher[2] if cipher else None,
            peer_der=der,
            trusted=trusted,
            verify_code=code,
            verify_message=message,
            openssl_hostname_match=hostname_match,
            elapsed_ms=int((time.monotonic() - started) * 1000),
        )

    @staticmethod
    def _verify_hostname(
        host: str,
        port: int,
        servername: str | None,
        der: bytes | None,
        trust_anchor: str | None,
        timeout_s: float,
    ) -> bool | None:
        """Ask OpenSSL whether the certificate covers the name, independently.

        The trick is to trust the system store *and* the server's own leaf.
        Trust is then satisfied either way - through the real chain for a
        publicly issued certificate, or through the leaf itself for a
        self-signed one - so the only thing OpenSSL can still object to is the
        hostname. Anchoring on the leaf alone was not enough: a real chain
        needs its issuer, so wrong.host.badssl.com produced no verdict at all
        until the system store was included.

        That verdict is a genuinely independent implementation of RFC 6125
        against our own, so a hostname finding rests on two readings rather
        than one, and a bug in our wildcard handling shows up as a
        disagreement rather than a silent wrong answer.
        """
        if der is None or servername is None:
            return None

        pem = ssl.DER_cert_to_PEM_cert(der)
        try:
            with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as handle:
                handle.write(pem)
                anchor = handle.name
        except OSError:  # pragma: no cover - defensive
            return None

        try:
            context = ssl.create_default_context()
            context.load_verify_locations(cafile=anchor)
            if trust_anchor:
                # A privately issued certificate needs its own CA here too, or
                # trust fails first and OpenSSL never reaches the hostname.
                context.load_verify_locations(cafile=trust_anchor)
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED
            with (
                socket.create_connection((host, port), timeout=timeout_s) as raw,
                context.wrap_socket(raw, server_hostname=servername),
            ):
                return True
        except ssl.SSLCertVerificationError as exc:
            message = (exc.verify_message or str(exc)).lower()
            if "hostname mismatch" in message or "doesn't match" in message:
                return False
            # Some other objection got in first; no independent verdict here.
            return None
        except (ssl.SSLError, OSError):
            return None
        finally:
            Path(anchor).unlink(missing_ok=True)

    @staticmethod
    def _verify(
        host: str, port: int, servername: str | None, trust_anchor: str | None, timeout_s: float
    ) -> tuple[bool, int | None, str | None]:
        try:
            with socket.create_connection((host, port), timeout=timeout_s) as raw:
                context = _verifying_context(trust_anchor)
                with context.wrap_socket(raw, server_hostname=servername or host):
                    return True, None, None
        except ssl.SSLCertVerificationError as exc:
            return False, exc.verify_code, exc.verify_message
        except ssl.SSLError as exc:
            return False, None, str(getattr(exc, "reason", None) or exc)
        except OSError as exc:
            return False, None, f"connect_error:{exc.strerror or exc}"


def _fixture_name(host: str, port: int, servername: str | None, version: str) -> str:
    key = f"{host}|{port}|{servername or ''}|{version}"
    digest = hashlib.sha256(key.encode()).hexdigest()[:10]
    safe = _SAFE.sub("_", f"{servername or host}".lower())
    return f"{safe}.{port}.{version}.{digest}.json"


class RecordingTlsBackend:
    """Wraps a backend and freezes every handshake for later replay."""

    def __init__(self, directory: str | Path, inner: TlsBackend | None = None) -> None:
        self._dir = Path(directory)
        self._dir.mkdir(parents=True, exist_ok=True)
        self._inner = inner or SystemTlsBackend()

    def handshake(
        self, host: str, port: int, servername: str | None, **kwargs: Any
    ) -> RawHandshake:
        result = self._inner.handshake(host, port, servername, **kwargs)
        version = _version_label(kwargs.get("min_version"), kwargs.get("max_version"))
        path = self._dir / _fixture_name(host, port, servername, version)
        path.write_text(json.dumps(result.to_dict(), indent=2, sort_keys=True) + "\n")
        return result


class ReplayTlsBackend:
    """Serves frozen handshakes and never opens a socket."""

    def __init__(self, directory: str | Path) -> None:
        self._dir = Path(directory)

    def handshake(
        self, host: str, port: int, servername: str | None, **kwargs: Any
    ) -> RawHandshake:
        version = _version_label(kwargs.get("min_version"), kwargs.get("max_version"))
        path = self._dir / _fixture_name(host, port, servername, version)
        if not path.exists():
            raise MissingHandshakeError(
                f"no recorded handshake for {servername or host}:{port} ({version}) in "
                f"{self._dir}. Record it with --record before replaying; a replay run never "
                "falls back to the wire."
            )
        return RawHandshake.from_dict(json.loads(path.read_text()))


def _version_label(min_version: ssl.TLSVersion | None, max_version: ssl.TLSVersion | None) -> str:
    if min_version is not None and min_version == max_version:
        return min_version.name
    return "any"


# --- the client -------------------------------------------------------------


@dataclass
class TlsClient:
    scope: Scope
    backend: TlsBackend = field(default_factory=SystemTlsBackend)
    trust_anchor: str | None = None
    timeout_s: float = DEFAULT_TIMEOUT_S
    cost: CostMeter | None = None
    killswitch: KillSwitch | None = None
    ratelimit: Any = None
    scan_id: str = "local"
    org_id: str = "org_internal"

    def inspect(
        self, host: str, port: int = DEFAULT_PORT, *, servername: str | None = None
    ) -> TlsObservation:
        """Observe a server's TLS, and separately ask whether it would be trusted."""
        raw = self._handshake(host, port, servername)
        return self._interpret(host, port, servername, raw)

    def probe_protocols(
        self, host: str, port: int = DEFAULT_PORT, *, servername: str | None = None
    ) -> dict[str, TlsObservation]:
        """One handshake per protocol version, each pinned to exactly that version.

        Returns the observations rather than booleans, because a finding about
        an obsolete protocol needs the obsolete handshake as its evidence. The
        earlier version returned only `True`/`False`, so the finding said "this
        server completed a handshake using TLS 1.0" while its evidence showed a
        TLS 1.3 handshake - a claim absent from its own evidence.
        """
        observations: dict[str, TlsObservation] = {}
        for label, version in PROTOCOLS.items():
            raw = self._handshake(host, port, servername, min_version=version, max_version=version)
            observations[label] = self._interpret(host, port, servername, raw)
        return observations

    def supported_protocols(
        self, host: str, port: int = DEFAULT_PORT, *, servername: str | None = None
    ) -> dict[str, bool]:
        """Which protocol versions the server will actually negotiate.

        Anything the server refuses is a `False`, which is the honest answer
        even when the refusal is the server protecting itself.
        """
        return {
            label: observation.reachable
            for label, observation in self.probe_protocols(
                host, port, servername=servername
            ).items()
        }

    def _handshake(
        self,
        host: str,
        port: int,
        servername: str | None,
        *,
        min_version: ssl.TLSVersion | None = None,
        max_version: ssl.TLSVersion | None = None,
    ) -> RawHandshake:
        if not self.scope.permits(host):
            raise OutOfScopeError(
                f"{host} is outside the scope of this scan; TLS connections to third "
                "parties are never made"
            )
        if self.killswitch is not None:
            self.killswitch.check(scan_id=self.scan_id, org_id=self.org_id)
        if self.ratelimit is not None:
            self.ratelimit.acquire(host)

        raw = self.backend.handshake(
            host,
            port,
            servername,
            min_version=min_version,
            max_version=max_version,
            trust_anchor=self.trust_anchor,
            timeout_s=self.timeout_s,
        )
        if self.cost is not None:
            self.cost.record_request()
        return raw

    @staticmethod
    def _interpret(
        host: str, port: int, servername: str | None, raw: RawHandshake
    ) -> TlsObservation:
        certificate = _parse_certificate(raw.peer_der) if raw.peer_der else None
        return TlsObservation(
            host=host,
            port=port,
            servername=servername,
            reachable=raw.reachable,
            observed_at=raw.observed_at,
            error=raw.error,
            protocol=raw.protocol,
            cipher=raw.cipher,
            cipher_bits=raw.cipher_bits,
            certificate=certificate,
            trusted=raw.trusted,
            verify_code=raw.verify_code,
            verify_message=raw.verify_message,
            openssl_hostname_match=raw.openssl_hostname_match,
            elapsed_ms=raw.elapsed_ms,
        )


# --- certificate parsing ----------------------------------------------------


def _common_name(name: x509.Name) -> str | None:
    values = name.get_attributes_for_oid(NameOID.COMMON_NAME)
    return str(values[0].value) if values else None


def _parse_certificate(der: bytes) -> CertificateInfo:
    cert = x509.load_der_x509_certificate(der)

    try:
        extension = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        san = extension.value
        assert isinstance(san, x509.SubjectAlternativeName)
        sans = san.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        sans = []

    public_key = cert.public_key()
    key_bits = getattr(public_key, "key_size", None)
    key_type = type(public_key).__name__.replace("PublicKey", "").replace("_", "").lower()
    for known in ("rsa", "ec", "ed25519", "ed448", "dsa"):
        if known in key_type:
            key_type = known
            break

    try:
        signature_algorithm = (
            cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else None
        )
    except Exception:  # pragma: no cover - exotic algorithms
        signature_algorithm = None

    has_sct = False
    for oid in (
        getattr(ExtensionOID, "SIGNED_CERTIFICATE_TIMESTAMPS", None),
        getattr(ExtensionOID, "PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS", None),
    ):
        if oid is None:
            continue
        try:
            cert.extensions.get_extension_for_oid(oid)
            has_sct = True
            break
        except x509.ExtensionNotFound:
            continue

    return CertificateInfo(
        subject=cert.subject.rfc4514_string(),
        subject_cn=_common_name(cert.subject),
        issuer=cert.issuer.rfc4514_string(),
        issuer_cn=_common_name(cert.issuer),
        serial=format(cert.serial_number, "x"),
        not_before=cert.not_valid_before_utc,
        not_after=cert.not_valid_after_utc,
        sans=list(sans),
        key_type=key_type,
        key_bits=key_bits,
        signature_algorithm=signature_algorithm,
        self_signed=cert.subject == cert.issuer,
        has_sct=has_sct,
        fingerprint_sha256=cert.fingerprint(hashes.SHA256()).hex(),
    )
