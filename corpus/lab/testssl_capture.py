"""LAB ONLY, NOT A CI GATE: what the narrowed testssl.sh run actually sends (D56).

Runs the production invocation (`core.testssl._run_raw`, through
`guard_invocation`) against an **ordinary** local TLS server, through a
recording TCP proxy, and checks two things:

1. every client-side byte on every connection fits
   `corpus.lab.tls_capture.analyse`'s allowlist of an ordinary handshake;
2. the server received at most one HTTP request, and it was a `GET`
   (testssl.sh's service detection).

It also checks the report still carries the four ids the checks read.

    tools/fetch-testssl.sh                                # once
    uv run python -m corpus.lab.testssl_capture

Exit status 0 when clean, 1 otherwise. It needs the pinned testssl.sh binary
and takes a minute or two, so it runs when the lab is up, never in CI. CI is
gated by the argument allowlist tests in `tests/core/test_testssl.py` and the
analyser tests in `tests/corpus/test_tls_capture.py`.

**What this proves, and what it does not** (ADR-023, D56 amendment): it
shows positive behaviour only. Against a normal server the narrowed run
sends only handshakes plus one ordinary GET. It cannot show that the old
`--vulnerable` invocation would have failed it: it was never run against
`--vulnerable`, by choice, and most of what that suite sends is outside
what the analyser inspects. A provoking server would supply only part of
that evidence (a heartbeat-enabled one would draw the Heartbleed probe,
whose record type the analyser flags), and we do not build one, by choice.
The server here is the system's own modern
OpenSSL with default settings. **Do not replace it with a deliberately
vulnerable one:** no vulnerable crypto infrastructure was built for this, by
choice, and none should be added.
"""

from __future__ import annotations

import contextlib
import datetime
import socket
import ssl
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import ClassVar

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from core.testssl import CHECK_TO_TESTSSL_ID, _parse, _run_raw, available
from corpus.lab.tls_capture import Chunk, analyse

HOST = "127.0.0.1"


def _self_signed(directory: Path) -> tuple[Path, Path]:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_path, key_path = directory / "cert.pem", directory / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return cert_path, key_path


class _Handler(BaseHTTPRequestHandler):
    requests: ClassVar[list[str]] = []

    def do_GET(self) -> None:
        self._answer()

    def do_HEAD(self) -> None:
        self._answer()

    def do_POST(self) -> None:
        self._answer()

    def _answer(self) -> None:
        _Handler.requests.append(f"{self.command} {self.path}")
        body = b"ok\n"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        pass


class _TlsServer(ThreadingHTTPServer):
    """An ordinary HTTPS server: default `ssl` settings, nothing weakened.
    A handshake it refuses is logged by `ssl` and ignored here."""

    daemon_threads = True

    def __init__(self, context: ssl.SSLContext) -> None:
        super().__init__((HOST, 0), _Handler)
        self.context = context

    def get_request(self) -> tuple[socket.socket, object]:
        sock, addr = super().get_request()
        return self.context.wrap_socket(sock, server_side=True), addr

    def handle_error(self, request: object, client_address: object) -> None:
        pass


class _RecordingProxy:
    def __init__(self, upstream_port: int) -> None:
        self.upstream_port = upstream_port
        self.chunks: list[Chunk] = []
        self._lock = threading.Lock()
        self._listener = socket.create_server((HOST, 0))
        self.port = self._listener.getsockname()[1]
        self._next = 0

    def serve(self) -> None:
        while True:
            try:
                client, _ = self._listener.accept()
            except OSError:
                return
            conn, self._next = self._next, self._next + 1
            upstream = socket.create_connection((HOST, self.upstream_port))
            for src, dst, direction in ((client, upstream, "client"), (upstream, client, "server")):
                threading.Thread(
                    target=self._pump, args=(conn, src, dst, direction), daemon=True
                ).start()

    def _pump(self, conn: int, src: socket.socket, dst: socket.socket, direction: str) -> None:
        try:
            while data := src.recv(65536):
                with self._lock:
                    self.chunks.append(Chunk(conn, direction, data))  # type: ignore[arg-type]
                dst.sendall(data)
        except OSError:
            pass
        finally:
            for sock in (src, dst):
                with contextlib.suppress(OSError):
                    sock.shutdown(socket.SHUT_RDWR)

    def close(self) -> None:
        self._listener.close()


def main() -> int:
    if not available():
        print("testssl.sh is not installed: run tools/fetch-testssl.sh first", file=sys.stderr)
        return 2

    with tempfile.TemporaryDirectory() as tmp:
        cert, key = _self_signed(Path(tmp))
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(cert, key)
        server = _TlsServer(context)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        proxy = _RecordingProxy(server.server_address[1])
        threading.Thread(target=proxy.serve, daemon=True).start()

        try:
            report = _run_raw(HOST, proxy.port, timeout_s=300)
        finally:
            proxy.close()
            server.shutdown()

    with proxy._lock:
        chunks = list(proxy.chunks)
    violations = analyse(chunks)
    connections = len({c.connection for c in chunks})
    client_bytes = sum(len(c.data) for c in chunks if c.direction == "client")
    found = set(_parse(report))
    wanted = set(CHECK_TO_TESTSSL_ID.values())
    requests = list(_Handler.requests)

    print(f"connections: {connections}  client bytes: {client_bytes}")
    print(f"HTTP requests seen by the server: {requests}")
    print(f"testssl ids in report: {sorted(found)} (want {sorted(wanted)})")
    for v in violations:
        print(f"VIOLATION conn={v.connection} {v.rule}: {v.detail}")

    ok = (
        not violations
        and len(requests) <= 1
        and all(r.startswith("GET ") for r in requests)
        and found == wanted
    )
    print("CLEAN" if ok else "NOT CLEAN")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
