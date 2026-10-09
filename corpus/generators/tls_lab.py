"""A local TLS laboratory: mint certificates with known defects, serve them.

This is the ground truth for Tool 2. badssl.com does the same job and does it
well, but it needs a clone, a hosts file and a trust anchor; this needs
nothing, runs in-process, and lets us author a defect that badssl does not
happen to cover.

Every server binds to 127.0.0.1 on an ephemeral port. Nothing here listens
beyond loopback and nothing survives the process that started it.

Two OpenSSL behaviours to know, both discovered the hard way:

- OpenSSL 3.0 refuses to *serve* a 1024-bit key at its default security level
  (`EE_KEY_TOO_SMALL`), so the lab's server contexts run at `@SECLEVEL=0`.
  Without that we cannot even stand up the weak-key case we need to detect.
- The same applies to the client. A scanner that refuses to complete a
  handshake with a weak server cannot report on it, which is why
  `core/tls.py` probes permissively and judges afterwards.
"""

from __future__ import annotations

import datetime as dt
import socket
import ssl
import subprocess
import tempfile
import threading
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

DAY = dt.timedelta(days=1)


@dataclass(frozen=True)
class Minted:
    cert_path: Path
    key_path: Path
    certificate: x509.Certificate


def mint(
    directory: Path,
    stem: str,
    *,
    common_name: str,
    sans: list[str] | None = None,
    not_before_days: int = -30,
    not_after_days: int = 365,
    key_bits: int = 2048,
    key_type: str = "rsa",
    digest: str = "sha256",
    issuer_cn: str | None = None,
    issuer_key: object | None = None,
    is_ca: bool = False,
    omit_san: bool = False,
) -> Minted:
    """Create a certificate with exactly the defect you ask for.

    `omit_san=True` gives a certificate with no subjectAltName extension at all,
    so only its Common Name names a host (D48: RFC 9525 forbids matching that).

    `not_after_days` in the past gives an expired certificate; a small positive
    number gives one expiring soon. `key_bits=1024` gives a weak key.
    `digest="sha1"` gives a deprecated signature.
    """
    if key_type == "ec":
        key: object = ec.generate_private_key(ec.SECP256R1())
    else:
        key = rsa.generate_private_key(public_exponent=65537, key_size=key_bits)

    now = dt.datetime.now(dt.UTC)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn or common_name)])

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())  # type: ignore[union-attr]
        .serial_number(x509.random_serial_number())
        .not_valid_before(now + not_before_days * DAY)
        .not_valid_after(now + not_after_days * DAY)
    )
    if not omit_san:
        builder = builder.add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName(name) for name in (sans if sans is not None else [common_name])]
            ),
            critical=False,
        )
    builder = builder.add_extension(
        x509.SubjectKeyIdentifier.from_public_key(key.public_key()),  # type: ignore[union-attr]
        critical=False,
    ).add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(
            issuer_key.public_key() if issuer_key is not None else key.public_key()  # type: ignore[union-attr]
        ),
        critical=False,
    )

    if is_ca:
        # Without basicConstraints CA:TRUE, OpenSSL will not use this
        # certificate to sign anything, and path building fails with "unable to
        # get local issuer" rather than reaching the leaf. That silently turned
        # every corpus case into an untrusted-chain case.
        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True
        ).add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )

    if digest == "sha1":
        # `cryptography` 50 removed SHA-1 signing entirely, which is the right
        # default and unhelpful when the whole point is to produce a
        # deprecated signature to detect. The openssl CLI still obliges.
        return _mint_sha1_via_openssl(
            directory, stem, common_name=common_name, sans=sans, days=max(not_after_days, 1)
        )

    algorithm = hashes.SHA256()
    signing_key = issuer_key or key
    certificate = builder.sign(signing_key, algorithm)  # type: ignore[arg-type]

    directory.mkdir(parents=True, exist_ok=True)
    cert_path = directory / f"{stem}.pem"
    key_path = directory / f"{stem}.key"
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(  # type: ignore[union-attr]
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    return Minted(cert_path, key_path, certificate)


def _mint_sha1_via_openssl(
    directory: Path, stem: str, *, common_name: str, sans: list[str] | None, days: int
) -> Minted:
    """A SHA-1 signed certificate, via the openssl binary.

    Dev-time fixture generation only - openssl is not a runtime dependency of
    any scanner, and nothing here ships.
    """
    directory.mkdir(parents=True, exist_ok=True)
    cert_path = directory / f"{stem}.pem"
    key_path = directory / f"{stem}.key"
    names = ",".join(f"DNS:{n}" for n in (sans if sans is not None else [common_name]))
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-keyout",
            str(key_path),
            "-out",
            str(cert_path),
            "-days",
            str(days),
            "-nodes",
            "-sha1",
            "-subj",
            f"/CN={common_name}",
            "-addext",
            f"subjectAltName={names}",
        ],
        check=True,
        capture_output=True,
    )
    certificate = x509.load_pem_x509_certificate(cert_path.read_bytes())
    return Minted(cert_path, key_path, certificate)


def mint_chain(
    directory: Path, stem: str, *, common_name: str, sans: list[str] | None = None, **leaf_kwargs
) -> tuple[Minted, Minted, Path]:
    """A self-signed CA and a leaf it issued, plus a combined chain file.

    Serving the combined file makes the server send its own root, which is what
    an untrusted-root configuration looks like on the wire: the chain is
    complete and terminates somewhere the client has never heard of. That is a
    different problem from a self-signed leaf and gets a different finding.
    """
    from cryptography.hazmat.primitives.asymmetric import rsa as _rsa

    ca_key = _rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca = mint(
        directory, f"{stem}-ca", common_name=f"{common_name} Test Root", key_bits=2048, is_ca=True
    )

    leaf = mint(
        directory,
        f"{stem}-leaf",
        common_name=common_name,
        sans=sans,
        issuer_cn=ca.certificate.subject.rfc4514_string().split("CN=")[-1],
        issuer_key=_load_key(ca.key_path),
        **leaf_kwargs,
    )

    chain_path = directory / f"{stem}-chain.pem"
    chain_path.write_bytes(leaf.cert_path.read_bytes() + ca.cert_path.read_bytes())
    del ca_key
    return ca, leaf, chain_path


def mint_three_level(
    directory: Path, stem: str, *, common_name: str, sans: list[str] | None = None, **leaf_kwargs
) -> tuple[Minted, Minted, Minted, Path]:
    """A trusted root, an intermediate it signed, and a leaf under that.

    Serving the leaf alone while trusting only the root is what an incomplete
    chain actually is: the verifier holds the root, the server never sent the
    intermediate, and the gap in the middle cannot be bridged. A two-level
    chain cannot express this - if the signer is the trusted root, no
    intermediate is needed and the path builds fine.

    `leaf_kwargs` (e.g. `not_before_days`/`not_after_days`) pass through to
    the leaf only, so D17's corpus case can mint a leaf that is *both*
    expired and missing its intermediate.
    """
    root = mint(directory, f"{stem}-root", common_name=f"{common_name} Test Root", is_ca=True)
    intermediate = mint(
        directory,
        f"{stem}-int",
        common_name=f"{common_name} Test Intermediate",
        is_ca=True,
        issuer_cn=f"{common_name} Test Root",
        issuer_key=_load_key(root.key_path),
    )
    leaf = mint(
        directory,
        f"{stem}-leaf",
        common_name=common_name,
        sans=sans,
        issuer_cn=f"{common_name} Test Intermediate",
        issuer_key=_load_key(intermediate.key_path),
        **leaf_kwargs,
    )
    full = directory / f"{stem}-full.pem"
    full.write_bytes(leaf.cert_path.read_bytes() + intermediate.cert_path.read_bytes())
    return root, intermediate, leaf, full


def _load_key(path: Path) -> object:
    from cryptography.hazmat.primitives.serialization import load_pem_private_key

    return load_pem_private_key(path.read_bytes(), password=None)


class LabServer:
    """A TLS server on loopback, serving one certificate."""

    def __init__(
        self,
        minted: Minted,
        *,
        max_version: ssl.TLSVersion | None = None,
        min_version: ssl.TLSVersion | None = None,
        ciphers: str = "ALL:@SECLEVEL=0",
        chain_file: Path | None = None,
        port: int = 0,
    ) -> None:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.set_ciphers(ciphers)
        # A fresh context's default minimum_version rose from
        # MINIMUM_SUPPORTED to TLSv1.2 once this lab moved onto an OpenSSL
        # build new enough to default there (see docs/14-progress-ledger.md,
        # 2026-08-28). This lab exists to offer obsolete protocols on
        # purpose, so it always lowers the floor back down unless the caller
        # asks for something else - otherwise a server meant to offer TLS 1.0
        # silently stops offering it, and "max_version=TLSv1" on top of the
        # new default leaves an empty [min, max] range with nothing to
        # negotiate at all.
        context.minimum_version = min_version if min_version is not None else ssl.TLSVersion.TLSv1
        if max_version is not None:
            context.maximum_version = max_version
        context.load_cert_chain(chain_file or minted.cert_path, minted.key_path)

        self._context = context
        self._socket = socket.socket()
        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # Port 0 gives an ephemeral port, which is right for tests. The corpus
        # generator pins one instead: a recorded handshake is keyed on host,
        # port and servername, so an ephemeral port would make every fixture
        # unreplayable the moment it was regenerated.
        self._socket.bind(("127.0.0.1", port))
        self._socket.listen(8)
        self.port: int = self._socket.getsockname()[1]
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                raw, _ = self._socket.accept()
            except OSError:
                return
            try:
                self._context.wrap_socket(raw, server_side=True).close()
            except (ssl.SSLError, OSError):
                with suppress(OSError):
                    raw.close()

    def close(self) -> None:
        self._stop.set()
        with suppress(OSError):
            self._socket.close()


@contextmanager
def lab_server(**mint_kwargs: object) -> Iterator[LabServer]:
    """Mint a certificate and serve it, cleaning up afterwards.

    Server-only keyword arguments (`max_version`, `min_version`, `ciphers`) are
    passed through to LabServer; everything else describes the certificate.
    """
    server_keys = {"max_version", "min_version", "ciphers"}
    server_kwargs = {k: v for k, v in mint_kwargs.items() if k in server_keys}
    cert_kwargs = {k: v for k, v in mint_kwargs.items() if k not in server_keys}

    with tempfile.TemporaryDirectory() as tmp:
        minted = mint(Path(tmp), "lab", **cert_kwargs)  # type: ignore[arg-type]
        server = LabServer(minted, **server_kwargs)  # type: ignore[arg-type]
        try:
            yield server
        finally:
            server.close()
