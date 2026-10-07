"""Record the frozen HTTP fixtures for the web (Tool 4a) corpus from the local lab.

    make web-lab-up                                  # certs + containers
    uv run python -m corpus.generators.web record    # record every case

Every case is recorded by running the scanner itself through a recording
backend, so what is frozen is exactly what the scanner asks for. Requests for
<case>.web.test are routed to the lab on 127.0.0.1 with the original Host and
SNI, and the recorded URL is the original one, so replay needs no DNS.
"""

from __future__ import annotations

import datetime as dt
import shutil
import ssl
import sys
from pathlib import Path
from typing import Any

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from core.authz import Scope
from core.context import ScanContext
from core.http import DEFAULT_USER_AGENT, HttpClient, RawHttpResponse, RecordingHttpBackend
from core.models import Asset
from scanners.web import WebScanner

ROOT = Path(__file__).resolve().parents[2]
CERTS = ROOT / "corpus" / "lab" / "web" / "certs"
FIXTURES = ROOT / "corpus" / "fixtures" / "web"
HTTP_PORT, HTTPS_PORT = 18080, 18443
CASES = (
    "known-good",
    "bare",
    "hsts-weak",
    "csp-weak",
    "csp-meta",
    "listing",
    "mixed-sri",
    "secret",
    "eol",
    "django-debug",
    "pytrace",
)


def mint() -> None:
    """A throwaway lab CA and a *.web.test leaf. Python 3.13's default
    VERIFY_X509_STRICT needs the key-identifier extensions, so both are set."""
    CERTS.mkdir(parents=True, exist_ok=True)
    now = dt.datetime.now(dt.UTC)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Security-Platform web lab CA")])
    ca = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), False)
        .sign(ca_key, hashes.SHA256())
    )
    leaf = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "*.web.test")]))
        .issuer_name(ca_name)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=825))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("*.web.test")]), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(leaf_key.public_key()), False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), False
        )
        .sign(ca_key, hashes.SHA256())
    )
    pem = serialization.Encoding.PEM
    (CERTS / "ca.crt").write_bytes(ca.public_bytes(pem))
    (CERTS / "web-lab.crt").write_bytes(leaf.public_bytes(pem))
    (CERTS / "web-lab.key").write_bytes(
        leaf_key.private_bytes(
            pem, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()
        )
    )


class LabBackend:
    """Routes <case>.web.test to the lab, keeping the original URL in the response."""

    def __init__(self, ca: Path) -> None:
        context = ssl.create_default_context(cafile=str(ca))
        self._client = httpx.Client(verify=context, follow_redirects=False, timeout=10.0)

    def send(self, method: str, url: str, *, body_cap: int, **kwargs: Any) -> RawHttpResponse:
        del body_cap
        original = httpx.URL(url)
        port = HTTPS_PORT if original.scheme == "https" else HTTP_PORT
        routed = original.copy_with(host="127.0.0.1", port=port)
        response = self._client.request(
            method,
            routed,
            headers={"Host": original.host, "User-Agent": DEFAULT_USER_AGENT},
            extensions={"sni_hostname": original.host},
        )
        return RawHttpResponse(
            status_code=response.status_code,
            headers=dict(response.headers),
            text=response.text,
            url=url,
            elapsed_ms=int(response.elapsed.total_seconds() * 1000),
        )


def record() -> None:
    ca = CERTS / "ca.crt"
    if not ca.exists():
        sys.exit("no lab CA - run `make web-lab-up` first")
    backend = LabBackend(ca)
    for case in CASES:
        host = f"{case}.web.test"
        directory = FIXTURES / case
        shutil.rmtree(directory, ignore_errors=True)
        directory.mkdir(parents=True)
        scope = Scope(frozenset({host}))
        ctx = ScanContext(
            http=HttpClient(scope=scope, backend=RecordingHttpBackend(directory, backend)),
            scope=scope,
            progress=lambda message, fraction: None,
        )
        result = WebScanner().run(Asset(type="domain", value=host), "light", ctx)
        claims = sorted(
            f"{f.check_id}@{f.location}"
            for f in result.findings
            if f.state in ("confirmed", "highly_likely")
        )
        others = sorted(
            f"{f.check_id}:{f.state}"
            for f in result.findings
            if f.state not in ("confirmed", "highly_likely", "informational")
        )
        print(f"{case}: claims={claims} other={others}")


if __name__ == "__main__":
    {"certs": mint, "record": record}[sys.argv[1] if len(sys.argv) > 1 else "record"]()
