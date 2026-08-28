"""The generic record/replay layer that DNS, TLS and HTTP build on."""

from __future__ import annotations

from core.replay import (
    FixtureStore,
    MissingFixtureError,
    fixture_digest,
    fixture_filename,
    missing_fixture_message,
    sanitize_filename_part,
)


def test_sanitize_filename_part_lowercases_and_replaces_unsafe_characters():
    assert sanitize_filename_part("Example.COM/../weird name") == "example.com_.._weird_name"


def test_fixture_digest_is_stable_and_key_sensitive():
    assert fixture_digest("a|b|c") == fixture_digest("a|b|c")
    assert fixture_digest("a|b|c") != fixture_digest("a|b|d")


def test_fixture_filename_preserves_tag_case_exactly():
    # DNS and TLS committed fixtures already disagree on case ("TXT" vs
    # "TLSv1_2"); this function must never normalise it, or every committed
    # fixture under corpus/fixtures/ would need renaming.
    name = fixture_filename("example.com", "TXT", digest="abc123")
    assert name == "example.com.TXT.abc123.json"
    name = fixture_filename("localhost", "14400", "any", digest="def456")
    assert name == "localhost.14400.any.def456.json"


def test_a_fixture_store_round_trips_a_payload(tmp_path):
    store = FixtureStore(tmp_path / "fixtures")
    store.write("a.json", {"x": 1})

    assert store.read("a.json") == {"x": 1}


def test_a_fixture_store_read_of_a_missing_file_is_none_not_an_exception(tmp_path):
    store = FixtureStore(tmp_path)

    assert store.read("never-written.json") is None


def test_the_missing_fixture_message_names_the_kind_subject_and_directory(tmp_path):
    message = missing_fixture_message(kind="answer", subject="example.com TXT", directory=tmp_path)

    assert "answer" in message
    assert "example.com TXT" in message
    assert str(tmp_path) in message
    assert "--record" in message


def test_missing_fixture_error_is_the_one_type_every_protocol_raises():
    # DNS, TLS and HTTP each import this exact class (TLS re-exports it under
    # its own historical name, `MissingHandshakeError`) so a caller can catch
    # one error type regardless of which client raised it.
    from core.dns import MissingFixtureError as DnsError
    from core.http import MissingFixtureError as HttpError
    from core.tls import MissingHandshakeError as TlsError

    assert DnsError is MissingFixtureError
    assert HttpError is MissingFixtureError
    assert TlsError is MissingFixtureError
