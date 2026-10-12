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

**D17.** OpenSSL reports only its first objection, so a certificate that is
both expired and served without its intermediates verifies as "certificate
has expired" and chain-incompleteness never surfaces. When the ordinary
verify fails, a second verifying handshake is made with `NO_CHECK_TIME` set,
asking "ignoring expiry, does the chain build to a trusted root?"
independently of the date verdict. Still behavioural, still no
`get_unverified_chain()` — just a second path-building attempt with one
variable removed.

**D60: the address checked is the address connected to** (ADR-036).
`TlsClient` resolves the host once per handshake through the scan's
`DnsClient`, checks every address with `core.addresses`, and hands the
backend the checked literals. `SystemTlsBackend` connects only to those, and
every connection of one handshake (the observation, the verification, the
hostname check, the D17 re-verify) goes to the same address, with the name
as SNI. It never passes a name to `socket.create_connection`, so the
operating system's resolver is never asked and cannot answer differently.
A refused name is a `RawHandshake` with `error="address_refused:..."` and no
connection at all.
"""

from __future__ import annotations

import base64
import datetime as dt
import ipaddress
import socket
import ssl
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

import idna
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import ExtensionOID, NameOID

from core.addresses import AddressPolicy, AddressRefusedError, AddressUnresolvedError
from core.authz import Scope
from core.cost import CostMeter
from core.http import OutOfScopeError
from core.killswitch import KillSwitch
from core.replay import (
    FixtureStore,
    MissingFixtureError,
    fixture_digest,
    fixture_filename,
    missing_fixture_message,
    sanitize_filename_part,
)

MissingHandshakeError = MissingFixtureError
"""Kept as its own name for readability at call sites and backward-compatible
imports (`from core.tls import MissingHandshakeError`); it is the same
exception type as every other protocol's missing-fixture error, on purpose,
so a caller can catch one type regardless of which client raised it."""

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

NO_CHECK_TIME = 0x200000
"""OpenSSL's `X509_V_FLAG_NO_CHECK_TIME`. Python's `ssl.VerifyFlags` does not
expose it (checked directly on 3.13.15: `VERIFY_DEFAULT`,
`VERIFY_CRL_CHECK_LEAF`, `VERIFY_CRL_CHECK_CHAIN`, `VERIFY_X509_STRICT`,
`VERIFY_ALLOW_PROXY_CERTS`, `VERIFY_X509_TRUSTED_FIRST`,
`VERIFY_X509_PARTIAL_CHAIN` - no sibling for time), but `SSLContext.verify_flags`
accepts and ORs in a raw integer, and OpenSSL honours it. Used for D17
(docs/14-progress-ledger.md): the verifying handshake reports only its first
objection, so a certificate that is both expired and served without its
intermediates comes back as "certificate has expired" and chain-incompleteness
is masked. Verifying a second time with this flag set answers "ignoring
expiry, does the chain build to a trusted root?" independently of the date
verdict."""


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
    ip_sans: list[str] = field(default_factory=list)
    """subjectAltName iPAddress entries (D48 review): an IP target is matched by
    address against these, never against a DNS name or the Common Name."""

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
        """RFC 9525 name matching (§6.3), including single-label wildcards.

        `*.example.test` covers `api.example.test` and covers neither
        `a.b.example.test` nor the bare `example.test`.

        Only subjectAltName DNS names count. RFC 9525 §2: "The Common Name RDN
        MUST NOT be used to identify a service". RFC 6125, which it obsoletes,
        allowed falling back to the CN when there were no SANs; this did, until
        D48, and so missed mismatches that current clients reject.
        """
        host = hostname.strip().rstrip(".")
        try:
            # brackets and an IPv6 zone id are not part of the address octets
            address = ipaddress.ip_address(host.strip("[]").split("%", 1)[0])
        except ValueError:
            address = None
        if address is not None:
            # RFC 9525 §6.4: an IP reference identity matches an iPAddress SAN,
            # by address. It is never compared with a DNS name or the CN.
            return any(_same_address(address, ip) for ip in self.ip_sans)
        names = list(self.sans)
        encoded = a_label(host)
        if encoded is None:
            return False
        host = encoded
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
            "ip_sans": list(self.ip_sans),
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
    verify_code_no_time: int | None = None
    verify_message_no_time: str | None = None
    """D17: the trust-path verdict from a second verifying handshake that
    ignores certificate validity dates (see `NO_CHECK_TIME`). `None` when the
    probe was not run - it is only meaningful, and only attempted, when the
    ordinary verify already failed, since a trusted chain has nothing left to
    unmask."""
    address: str | None = None
    """D60: the checked address every connection went to; `None` on a
    fixture recorded before D60, or when nothing was connected to."""

    @property
    def hostname_matches(self) -> bool | None:
        if self.certificate is None or self.servername is None:
            return None
        if a_label(self.servername) is None:
            return None  # not a valid name (ADR-030): no verdict
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
            "verify_code_no_time": self.verify_code_no_time,
            "verify_message_no_time": self.verify_message_no_time,
            **({"address": self.address} if self.address is not None else {}),
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
    verify_code_no_time: int | None = None
    verify_message_no_time: str | None = None
    address: str | None = None
    """D60: the checked address connected to (absent from older fixtures)."""

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
            "verify_code_no_time": self.verify_code_no_time,
            "verify_message_no_time": self.verify_message_no_time,
            **({"address": self.address} if self.address is not None else {}),
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
            verify_code_no_time=data.get("verify_code_no_time"),
            verify_message_no_time=data.get("verify_message_no_time"),
            address=data.get("address"),
        )


# --- backends ---------------------------------------------------------------


class TlsBackend(Protocol):
    """`connects` says whether `handshake` opens sockets. One that does is
    handed `addresses`, the checked literals, and connects only to them (D60)."""

    connects: bool

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
    """Real sockets. Constructed by the CLI or the worker, never by a scanner.

    D60: connects only to the checked `addresses` it is handed, never to a
    name. The first address that accepts the observing connection is used for
    every later connection of the same handshake, so the trust verdicts are
    about the server that was observed."""

    connects = True

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
        addresses: tuple[str, ...] | None = None,
    ) -> RawHandshake:
        if not addresses:
            raise ValueError(
                "the live TLS backend connects only to a checked address; "
                "TlsClient resolves and checks the host first (D60)"
            )
        started = time.monotonic()
        observed_at = dt.datetime.now(dt.UTC)
        address = addresses[0]

        try:
            raw, address = _connect_first(addresses, port, timeout_s)
            with raw:
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

        trusted, code, message = self._verify(
            host, address, port, servername, trust_anchor, timeout_s
        )
        hostname_match = self._verify_hostname(
            address, port, servername, der, trust_anchor, timeout_s
        )

        code_no_time: int | None = None
        message_no_time: str | None = None
        if not trusted:
            # D17: only worth asking when the ordinary verify already failed -
            # a trusted chain has nothing left to unmask, and skipping it here
            # is what keeps every already-passing corpus case's fixtures
            # unchanged.
            _, code_no_time, message_no_time = self._verify(
                host, address, port, servername, trust_anchor, timeout_s, no_check_time=True
            )

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
            verify_code_no_time=code_no_time,
            verify_message_no_time=message_no_time,
            address=address,
        )

    @staticmethod
    def _verify_hostname(
        address: str,
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

        That verdict is a separate implementation of RFC 9525 matching from our
        own, so a hostname finding rests on two readings rather
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
            # D48: no Common Name fallback, as RFC 9525 §2 requires. Python
            # defaults this to True, which made OpenSSL's reading share our old
            # blind spot, so the two readings agreed on a wrong answer (D38).
            context.hostname_checks_common_name = False
            context.verify_mode = ssl.CERT_REQUIRED
            with (
                socket.create_connection((address, port), timeout=timeout_s) as raw,
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
        host: str,
        address: str,
        port: int,
        servername: str | None,
        trust_anchor: str | None,
        timeout_s: float,
        *,
        no_check_time: bool = False,
    ) -> tuple[bool, int | None, str | None]:
        try:
            with socket.create_connection((address, port), timeout=timeout_s) as raw:
                context = _verifying_context(trust_anchor)
                if no_check_time:
                    context.verify_flags |= NO_CHECK_TIME
                with context.wrap_socket(raw, server_hostname=servername or host):
                    return True, None, None
        except ssl.SSLCertVerificationError as exc:
            return False, exc.verify_code, exc.verify_message
        except ssl.SSLError as exc:
            return False, None, str(getattr(exc, "reason", None) or exc)
        except OSError as exc:
            return False, None, f"connect_error:{exc.strerror or exc}"


POLICY_ERRORS = ("address_refused:", "address_unresolved:", "address_lookup_failed:")
"""D60: a handshake the address policy stopped before any socket was opened."""


def _stopped_by_policy(raw: RawHandshake) -> bool:
    return raw.error is not None and raw.error.startswith(POLICY_ERRORS)


def _connect_first(
    addresses: tuple[str, ...], port: int, timeout_s: float
) -> tuple[socket.socket, str]:
    """A connection to the first checked address that accepts one, and which it was.

    Only literals reach `socket.create_connection`, so the system resolver is
    never consulted (D60)."""
    last: OSError | None = None
    for address in addresses:
        try:
            return socket.create_connection((address, port), timeout=timeout_s), address
        except OSError as exc:
            last = exc
    assert last is not None
    raise last


def _fixture_name(host: str, port: int, servername: str | None, version: str) -> str:
    key = f"{host}|{port}|{servername or ''}|{version}"
    stem = sanitize_filename_part(servername or host)
    return fixture_filename(stem, str(port), version, digest=fixture_digest(key, length=10))


class RecordingTlsBackend:
    """Wraps a backend and freezes every handshake for later replay."""

    def __init__(self, directory: str | Path, inner: TlsBackend | None = None) -> None:
        self._store = FixtureStore(Path(directory))
        self._inner = inner or SystemTlsBackend()

    @property
    def connects(self) -> bool:
        # Silence means connecting, through a wrapper too (fail closed).
        return bool(getattr(self._inner, "connects", True))

    def handshake(
        self, host: str, port: int, servername: str | None, **kwargs: Any
    ) -> RawHandshake:
        result = self._inner.handshake(host, port, servername, **kwargs)
        self.record(
            host, port, servername, result, kwargs.get("min_version"), kwargs.get("max_version")
        )
        return result

    def record(
        self,
        host: str,
        port: int,
        servername: str | None,
        result: RawHandshake,
        min_version: ssl.TLSVersion | None,
        max_version: ssl.TLSVersion | None,
    ) -> None:
        """Freeze one handshake."""
        version = _version_label(min_version, max_version)
        self._store.write(_fixture_name(host, port, servername, version), result.to_dict())

    def record_refusal(
        self,
        host: str,
        port: int,
        servername: str | None,
        refused: RawHandshake,
        min_version: ssl.TLSVersion | None,
        max_version: ssl.TLSVersion | None,
    ) -> None:
        """D60: freeze a handshake the address policy stopped before any socket,
        so its replay stops it too."""
        self.record(host, port, servername, refused, min_version, max_version)


class ReplayTlsBackend:
    """Serves frozen handshakes and never opens a socket."""

    connects = False

    def __init__(self, directory: str | Path) -> None:
        self._store = FixtureStore(Path(directory))

    def handshake(
        self, host: str, port: int, servername: str | None, **kwargs: Any
    ) -> RawHandshake:
        version = _version_label(kwargs.get("min_version"), kwargs.get("max_version"))
        data = self._store.read(_fixture_name(host, port, servername, version))
        if data is None:
            raise MissingHandshakeError(
                missing_fixture_message(
                    kind="handshake",
                    subject=f"{servername or host}:{port} ({version})",
                    directory=self._store.directory,
                )
            )
        return RawHandshake.from_dict(data)


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
    dns: Any = None
    """The scan's `DnsClient`, wired in by `ScanContext` (D60)."""
    addresses: AddressPolicy | None = None
    """The scan's `AddressPolicy`, wired in by `ScanContext`; a client never
    given one uses the default, which has no override (D60)."""

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
        # ADR-030: the A-label a browser would send, so the SNI and the name
        # OpenSSL checks are the browser's, not Python's IDNA 2003 encoding.
        wire_name = (a_label(servername) or servername) if servername else servername
        pinned: dict[str, Any] = {}
        # Fail closed: a backend that does not say it opens no socket is pinned.
        if getattr(self.backend, "connects", True):
            # D60: one lookup, through the scan's resolver; only checked
            # literals go down to the socket.
            policy = self.addresses or AddressPolicy()
            error: str | None = None
            try:
                pinned["addresses"] = policy.pin(a_label(host) or host, self.dns).addresses
            except AddressRefusedError as exc:
                error = f"address_refused:{exc.summary}"
            except AddressUnresolvedError as exc:
                prefix = "address_lookup_failed" if exc.lookup_failed else "address_unresolved"
                error = f"{prefix}:{exc}"
            if error is not None:
                refused = RawHandshake(
                    reachable=False, observed_at=dt.datetime.now(dt.UTC), error=error
                )
                # A recording keeps the refusal, so its replay says the same
                # (review of D60, round 1). Nothing was connected to.
                record = getattr(self.backend, "record_refusal", None)
                if record is not None:
                    record(host, port, wire_name, refused, min_version, max_version)
                return refused
        if self.ratelimit is not None:
            self.ratelimit.acquire(host)

        raw = self.backend.handshake(
            host,
            port,
            wire_name,
            min_version=min_version,
            max_version=max_version,
            trust_anchor=self.trust_anchor,
            timeout_s=self.timeout_s,
            **pinned,
        )
        # A refusal opens no socket, live or replayed, so it costs no request
        # (review of D60, round 2).
        if self.cost is not None and not _stopped_by_policy(raw):
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
            verify_code_no_time=raw.verify_code_no_time,
            verify_message_no_time=raw.verify_message_no_time,
            address=raw.address,
        )


# --- certificate parsing ----------------------------------------------------


def _common_name(name: x509.Name) -> str | None:
    values = name.get_attributes_for_oid(NameOID.COMMON_NAME)
    return str(values[0].value) if values else None


def a_label(hostname: str) -> str | None:
    """The name as a browser encodes it for DNS and for certificate matching (ADR-030).

    UTS-46 processing, non-transitional, as the WHATWG URL Standard's
    domain-to-ASCII specifies: `faß.de` is `xn--fa-hia.de`, not IDNA 2003's
    `fass.de`. An ASCII name is only lowercased. `None` when the name does not
    encode (a joiner where CONTEXTJ forbids it, say): it is not a valid name, so
    no reading may judge it.
    """
    name = hostname.strip().rstrip(".")
    if name.isascii():
        return name.lower()
    try:
        return idna.encode(name, uts46=True).decode("ascii")
    except (idna.IDNAError, UnicodeError):
        return None


def _same_address(address: ipaddress.IPv4Address | ipaddress.IPv6Address, raw: str) -> bool:
    try:
        return ipaddress.ip_address(raw) == address
    except ValueError:
        return False


def _parse_certificate(der: bytes) -> CertificateInfo:
    cert = x509.load_der_x509_certificate(der)

    try:
        extension = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        san = extension.value
        assert isinstance(san, x509.SubjectAlternativeName)
        sans = san.get_values_for_type(x509.DNSName)
        ip_sans = [str(ip) for ip in san.get_values_for_type(x509.IPAddress)]
    except x509.ExtensionNotFound:
        sans = []
        ip_sans = []

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
        ip_sans=ip_sans,
        key_type=key_type,
        key_bits=key_bits,
        signature_algorithm=signature_algorithm,
        self_signed=cert.subject == cert.issuer,
        has_sct=has_sct,
        fingerprint_sha256=cert.fingerprint(hashes.SHA256()).hex(),
    )
