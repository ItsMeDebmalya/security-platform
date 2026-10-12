"""D56: the capture analyser is an allowlist of what a normal TLS client sends.

`corpus.lab.tls_capture.analyse` reads the bytes a recording proxy saw on each
connection and flags anything the client sent that falls outside the shape of
an ordinary handshake. It is deliberately **not** an attack-pattern detector
(ADR-023, D56 amendment): it lists what normal looks like and flags
everything else.

These tests run in CI. The record bytes below are built from the record
header layout alone, with opaque payloads. The analyser's rule is "flag any
record type not on the list", so one off-list type proves the rule for every
off-list type; the same holds for each shape rule.
"""

from __future__ import annotations

import pytest

from corpus.lab.tls_capture import (
    ALLOWED_RECORD_TYPES,
    HELLO_RETRY_REQUEST_RANDOM,
    Chunk,
    analyse,
)

CHANGE_CIPHER_SPEC, ALERT, HANDSHAKE, APPLICATION_DATA = 20, 21, 22, 23
CLIENT_HELLO, SERVER_HELLO, CLIENT_KEY_EXCHANGE = 1, 2, 16
OFF_LIST_TYPE = 99
"""Unassigned in the IANA TLS ContentType registry. Any type outside the
allowlist would do; the rule under test does not distinguish between them."""


def record(content_type: int, payload: bytes, version: bytes = b"\x03\x03") -> bytes:
    return bytes([content_type]) + version + len(payload).to_bytes(2, "big") + payload


def handshake(msg_type: int, body: bytes) -> bytes:
    return bytes([msg_type]) + len(body).to_bytes(3, "big") + body


def client_hello() -> bytes:
    return record(HANDSHAKE, handshake(CLIENT_HELLO, b"\x03\x03" + bytes(32) + b"\x00"))


def server_hello(random: bytes = b"\x11" * 32) -> bytes:
    return record(HANDSHAKE, handshake(SERVER_HELLO, b"\x03\x03" + random + b"\x00"))


def opaque(content_type: int, size: int = 24) -> bytes:
    return record(content_type, b"\xaa" * size)


def ccs() -> bytes:
    return record(CHANGE_CIPHER_SPEC, b"\x01")


def sslv2_client_hello() -> bytes:
    body = bytes([1]) + b"\x00\x02" + b"\x00\x03" + b"\x00\x00" + b"\x00\x10" + bytes(19)
    return bytes([0x80 | (len(body) >> 8), len(body) & 0xFF]) + body


def c(data: bytes, conn: int = 0) -> Chunk:
    return Chunk(connection=conn, direction="client", data=data)


def s(data: bytes, conn: int = 0) -> Chunk:
    return Chunk(connection=conn, direction="server", data=data)


def rules(chunks: list[Chunk]) -> list[str]:
    return [v.rule for v in analyse(chunks)]


# --- what normal looks like: no violations ----------------------------------


def test_the_allowlist_is_the_four_ordinary_record_types() -> None:
    assert frozenset({20, 21, 22, 23}) == ALLOWED_RECORD_TYPES


def test_a_tls12_shaped_connection_passes() -> None:
    chunks = [
        c(client_hello()),
        s(server_hello() + opaque(HANDSHAKE)),
        c(record(HANDSHAKE, handshake(CLIENT_KEY_EXCHANGE, bytes(10))) + ccs() + opaque(HANDSHAKE)),
        s(ccs() + opaque(HANDSHAKE)),
        c(opaque(APPLICATION_DATA)),
        s(opaque(APPLICATION_DATA)),
        c(opaque(ALERT, 2)),
    ]
    assert analyse(chunks) == []


def test_a_tls13_shaped_connection_with_compatibility_ccs_passes() -> None:
    chunks = [
        c(client_hello()),
        s(server_hello() + ccs() + opaque(APPLICATION_DATA)),
        c(ccs() + opaque(APPLICATION_DATA)),
        c(opaque(APPLICATION_DATA)),
        s(opaque(APPLICATION_DATA)),
    ]
    assert analyse(chunks) == []


def test_a_second_client_hello_after_a_hello_retry_request_passes() -> None:
    chunks = [
        c(client_hello()),
        s(server_hello(HELLO_RETRY_REQUEST_RANDOM) + ccs()),
        c(ccs() + client_hello()),
        s(server_hello() + opaque(APPLICATION_DATA)),
        c(opaque(APPLICATION_DATA)),
    ]
    assert analyse(chunks) == []


def test_an_sslv2_format_client_hello_as_the_first_record_passes() -> None:
    assert analyse([c(sslv2_client_hello())]) == []


def test_a_handshake_refused_with_an_alert_passes() -> None:
    assert analyse([c(client_hello()), s(opaque(ALERT, 2))]) == []


def test_records_split_across_reads_are_reassembled() -> None:
    stream = client_hello() + ccs() + opaque(APPLICATION_DATA)
    chunks = [c(stream[i : i + 3]) for i in range(0, len(stream), 3)]
    assert analyse(chunks) == []


def test_a_connection_on_which_the_client_sent_nothing_passes() -> None:
    assert analyse([s(opaque(ALERT, 2))]) == []


def test_connections_are_judged_independently() -> None:
    chunks = [c(client_hello(), conn=0), c(client_hello(), conn=1)]
    assert analyse(chunks) == []


# --- everything else is flagged ---------------------------------------------


def test_a_record_type_outside_the_allowlist_is_flagged() -> None:
    chunks = [c(client_hello()), c(opaque(OFF_LIST_TYPE))]
    assert rules(chunks) == ["record-type-not-allowed"]


def test_a_handshake_record_after_application_data_is_flagged() -> None:
    chunks = [c(client_hello()), c(ccs() + opaque(APPLICATION_DATA)), c(opaque(HANDSHAKE))]
    assert rules(chunks) == ["after-application-data"]


def test_a_change_cipher_spec_after_application_data_is_flagged() -> None:
    chunks = [c(client_hello()), c(opaque(APPLICATION_DATA)), c(ccs())]
    assert "after-application-data" in rules(chunks)


def test_a_second_client_hello_without_a_retry_request_is_flagged() -> None:
    chunks = [c(client_hello()), s(server_hello()), c(client_hello())]
    assert rules(chunks) == ["more-than-one-handshake"]


def test_a_second_change_cipher_spec_is_flagged() -> None:
    chunks = [c(client_hello()), c(ccs()), c(ccs())]
    assert rules(chunks) == ["more-than-one-change-cipher-spec"]


@pytest.mark.parametrize(
    "first",
    [
        pytest.param(ccs(), id="change-cipher-spec"),
        pytest.param(opaque(APPLICATION_DATA), id="application-data"),
        pytest.param(opaque(HANDSHAKE), id="handshake-that-is-not-a-client-hello"),
    ],
)
def test_a_connection_that_does_not_open_with_a_client_hello_is_flagged(first: bytes) -> None:
    assert "first-record-not-client-hello" in rules([c(first)])


def test_an_sslv2_format_record_after_the_first_is_flagged() -> None:
    chunks = [c(client_hello()), c(sslv2_client_hello())]
    assert "record-type-not-allowed" in rules(chunks)


def test_a_truncated_record_at_close_is_flagged() -> None:
    """Bytes the analyser could not frame are not assumed to be normal."""
    assert rules([c(client_hello()[:-3])]) == ["unparsed-bytes"]


def test_after_a_violation_the_rest_of_that_direction_is_not_trusted() -> None:
    """Once framing is off-list, later bytes can't be framed reliably; the
    analyser reports the first violation and stops reading that direction,
    rather than guessing."""
    chunks = [c(client_hello()), c(opaque(OFF_LIST_TYPE) + opaque(OFF_LIST_TYPE))]
    assert rules(chunks) == ["record-type-not-allowed"]


def test_off_list_bytes_from_the_server_are_not_our_traffic() -> None:
    """The claim is about what we send. The server's stream is read only to
    see a HelloRetryRequest."""
    chunks = [c(client_hello()), s(opaque(OFF_LIST_TYPE))]
    assert analyse(chunks) == []


def test_a_violation_names_its_connection() -> None:
    chunks = [
        c(client_hello(), conn=0),
        c(client_hello(), conn=7),
        c(opaque(OFF_LIST_TYPE), conn=7),
    ]
    (violation,) = analyse(chunks)
    assert violation.connection == 7
