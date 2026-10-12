"""An allowlist of what an ordinary TLS client sends, applied to a capture (D56).

`analyse` reads the bytes a recording proxy saw, connection by connection,
and flags anything the **client** sent outside the shape of an ordinary
handshake:

- **record types:** only ChangeCipherSpec (20), Alert (21), Handshake (22)
  and ApplicationData (23), plus an SSLv2-format ClientHello as the first
  record of a connection (testssl.sh's legacy-cipher tests send these, and
  ADR-023 classes them as passive);
- **the first record** is a ClientHello;
- **one handshake per connection:** one ClientHello, or two when the server
  answered the first with a TLS 1.3 HelloRetryRequest;
- **at most one ChangeCipherSpec** per connection;
- **after application data begins,** only application data and alerts.

It is deliberately **not** an attack-pattern detector (ADR-023, D56
amendment). It does not know what any probe looks like; it knows what
normal looks like and flags everything else, so within what it inspects
(record types, their order, and handshake type bytes) it also catches a
deviation nobody anticipated. After the first violation in a direction it
stops reading that direction rather than guess at framing.

What it does not inspect, stated plainly: the contents of encrypted records
(so a second handshake inside encryption before any application data
passes); the contents of an allowed plaintext handshake message beyond its
type byte (so a well-ordered message with malformed contents passes); and a
single ChangeCipherSpec sent early but before application data. Two
legitimate shapes testssl.sh does not send are flagged falsely: a
ClientHello split across records whose continuation begins with 0x01, and
0-RTT early data followed by a HelloRetryRequest.

The primary proof that we send only what we declare is the argument
allowlist and runtime guard in `core/testssl.py`; this analyser is the
positive check on a real run (`corpus/lab/testssl_capture.py`).

The server's stream is read only to recognise a HelloRetryRequest. The claim
is about what we send.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Literal

ALLOWED_RECORD_TYPES = frozenset({20, 21, 22, 23})
_CHANGE_CIPHER_SPEC, _ALERT, _HANDSHAKE, _APPLICATION_DATA = 20, 21, 22, 23
_AFTER_APPLICATION_DATA = frozenset({_ALERT, _APPLICATION_DATA})
_CLIENT_HELLO, _SERVER_HELLO = 1, 2
_SSLV2_CLIENT_HELLO = 1

HELLO_RETRY_REQUEST_RANDOM = bytes.fromhex(
    "cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c"
)
"""RFC 8446 section 4.1.3: a ServerHello with this random is a
HelloRetryRequest, after which the client legitimately sends a second
ClientHello."""

Direction = Literal["client", "server"]


@dataclass(frozen=True)
class Chunk:
    """One read from one side of one proxied connection, in arrival order."""

    connection: int
    direction: Direction
    data: bytes


@dataclass(frozen=True)
class Violation:
    connection: int
    rule: str
    detail: str


@dataclass
class _Client:
    buffer: bytearray = field(default_factory=bytearray)
    records: int = 0
    client_hellos: int = 0
    change_cipher_specs: int = 0
    application_data: bool = False
    stopped: bool = False


@dataclass
class _Server:
    buffer: bytearray = field(default_factory=bytearray)
    encrypted: bool = False
    stopped: bool = False


@dataclass
class _Connection:
    client: _Client = field(default_factory=_Client)
    server: _Server = field(default_factory=_Server)
    retries_granted: int = 0


def _next_record(buffer: bytearray, *, first: bool) -> tuple[int | None, bytes] | None:
    """Pop one record. Returns (content type, payload), with type None for an
    SSLv2-format record, or None if the record is not complete yet."""
    if first and buffer and buffer[0] & 0x80:
        if len(buffer) < 2:
            return None
        length = ((buffer[0] & 0x7F) << 8) | buffer[1]
        if len(buffer) < 2 + length:
            return None
        payload = bytes(buffer[2 : 2 + length])
        del buffer[: 2 + length]
        return None, payload
    if len(buffer) < 5:
        return None
    length = int.from_bytes(buffer[3:5], "big")
    if len(buffer) < 5 + length:
        return None
    content_type, payload = buffer[0], bytes(buffer[5 : 5 + length])
    del buffer[: 5 + length]
    return content_type, payload


def _client(state: _Connection, conn: int, data: bytes) -> list[Violation]:
    client = state.client
    if client.stopped:
        return []
    client.buffer.extend(data)
    violations: list[Violation] = []

    def stop(rule: str, detail: str) -> None:
        violations.append(Violation(conn, rule, detail))
        client.stopped = True

    while not client.stopped:
        if client.records > 0 and client.buffer and client.buffer[0] not in ALLOWED_RECORD_TYPES:
            stop("record-type-not-allowed", f"content type {client.buffer[0]}")
            break
        popped = _next_record(client.buffer, first=client.records == 0)
        if popped is None:
            break
        content_type, payload = popped
        client.records += 1

        if client.records == 1:
            if content_type is None:
                if payload[:1] != bytes([_SSLV2_CLIENT_HELLO]):
                    stop("first-record-not-client-hello", "SSLv2-format record is not a hello")
                else:
                    client.client_hellos += 1
                continue
            if content_type != _HANDSHAKE or payload[:1] != bytes([_CLIENT_HELLO]):
                stop("first-record-not-client-hello", f"content type {content_type}")
                continue
            client.client_hellos += 1
            continue

        if client.application_data and content_type not in _AFTER_APPLICATION_DATA:
            stop("after-application-data", f"content type {content_type}")
            continue
        if content_type == _APPLICATION_DATA:
            client.application_data = True
        elif content_type == _CHANGE_CIPHER_SPEC:
            client.change_cipher_specs += 1
            if client.change_cipher_specs > 1:
                stop("more-than-one-change-cipher-spec", "second ChangeCipherSpec")
        elif content_type == _HANDSHAKE and payload[:1] == bytes([_CLIENT_HELLO]):
            plaintext = client.change_cipher_specs == 0 or state.retries_granted > 0
            if plaintext:
                client.client_hellos += 1
                if client.client_hellos > 1 + state.retries_granted:
                    stop("more-than-one-handshake", f"ClientHello #{client.client_hellos}")
    return violations


def _server(state: _Connection, data: bytes) -> None:
    server = state.server
    if server.stopped:
        return
    server.buffer.extend(data)
    while True:
        popped = _next_record(server.buffer, first=False)
        if popped is None:
            return
        content_type, payload = popped
        if content_type not in ALLOWED_RECORD_TYPES:
            server.stopped = True
            return
        if content_type in (_CHANGE_CIPHER_SPEC, _APPLICATION_DATA):
            server.encrypted = True
        if content_type != _HANDSHAKE or server.encrypted:
            continue
        if payload[:1] == bytes([_SERVER_HELLO]) and payload[6:38] == HELLO_RETRY_REQUEST_RANDOM:
            state.retries_granted = 1


def analyse(chunks: Iterable[Chunk]) -> list[Violation]:
    """Every client-side departure from an ordinary handshake, in order."""
    connections: dict[int, _Connection] = defaultdict(_Connection)
    violations: list[Violation] = []
    for chunk in chunks:
        state = connections[chunk.connection]
        if chunk.direction == "client":
            violations.extend(_client(state, chunk.connection, chunk.data))
        else:
            _server(state, chunk.data)
    for conn, state in connections.items():
        if state.client.buffer and not state.client.stopped:
            violations.append(
                Violation(conn, "unparsed-bytes", f"{len(state.client.buffer)} bytes left over")
            )
    return violations


__all__ = ["ALLOWED_RECORD_TYPES", "HELLO_RETRY_REQUEST_RANDOM", "Chunk", "Violation", "analyse"]
